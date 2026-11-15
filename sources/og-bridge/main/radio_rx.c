#include "fwog_main.h"
#include "radio_rx.h"
#include <string.h>

typedef struct {
    cc1101_t chip;
    bool configured, active;
    uint8_t modulation;
    uint32_t hz, deadline, started, samples, bytes, overflows, io_errors;
} receiver_t;
static receiver_t receivers[2];
static uint32_t next_poll;

void radio_rx_init(void) {
    cc1101_bus_init(1000000);
    /* Preserve the legacy application's ordinal mapping explicitly:
       radio 1 = CS1 GPIO18, radio 2 = CS0 GPIO5 (not silkscreen numbering). */
    cc1101_bind(&receivers[0].chip, CC1101_RADIO_CS1);
    cc1101_bind(&receivers[1].chip, CC1101_RADIO_CS0);
    /* The RF chips need not reset with MAIN. Stop any receive session
       inherited from an earlier firmware run before accepting commands. */
    for (unsigned i = 0; i < 2; ++i)
        if (!cc1101_idle(&receivers[i].chip)) receivers[i].io_errors++;
}

static uint32_t actual_frequency(cc1101_t *chip, bool *ok) {
    uint8_t f[3];
    if (!cc1101_read_burst(chip, CC1101_REG_FREQ2, f, 3)) { *ok = false; return 0; }
    uint32_t word = ((uint32_t)f[0] << 16) | ((uint32_t)f[1] << 8) | f[2];
    return (uint32_t)(((uint64_t)word * CC1101_CRYSTAL_HZ) / 65536u);
}

static bool configure(receiver_t *r, const radio_request_t *q) {
    bool ok = cc1101_bringup(&r->chip);
    ok = ok && cc1101_idle(&r->chip);
    ok = ok && cc1101_set_frequency(&r->chip, q->frequency_hz);
    cc1101_modulation_t mod = q->modulation == 0 ? CC1101_MOD_ASK :
                             q->modulation == 1 ? CC1101_MOD_2FSK : CC1101_MOD_GFSK;
    ok = ok && cc1101_set_modulation(&r->chip, mod);
    ok = ok && cc1101_set_data_rate(&r->chip, 4.8f);
    ok = ok && cc1101_set_deviation(&r->chip, 20.0f);
    ok = ok && cc1101_set_rx_bandwidth(&r->chip, 203.125f);
    ok = ok && cc1101_set_sync_mode(&r->chip, 0);
    ok = ok && cc1101_set_crc(&r->chip, false);
    ok = ok && cc1101_set_white_data(&r->chip, false);
    ok = ok && cc1101_set_append_status(&r->chip, false);
    ok = ok && cc1101_set_length_config(&r->chip, 2); /* infinite raw RX */
    /* RX_OFF_MODE=RX, TX_OFF_MODE=IDLE; no automatic RX->TX transition. */
    ok = ok && cc1101_write_reg(&r->chip, CC1101_REG_MCSM1, 0x0c);
    ok = ok && cc1101_flush_rx(&r->chip);
    ok = ok && cc1101_rx(&r->chip);
    r->configured = ok;
    r->hz = ok ? q->frequency_hz : 0;
    r->modulation = q->modulation;
    return ok;
}

void radio_rx_request(const radio_request_t *q) {
    radio_response_t s = {.type = RADIO_RESPONSE, .seq = q->seq, .op = q->op, .radio = q->radio};
    if (q->radio < 1 || q->radio > 2 || q->op < RADIO_STATUS || q->op > RADIO_STOP) {
        fwog_link_uart_send_frame(&s, sizeof(s)); return;
    }
    receiver_t *r = &receivers[q->radio - 1];
    bool ok = true;
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (q->op == RADIO_START) {
        if (!cc1101_freq_in_band(q->frequency_hz) || q->modulation > 2 ||
            q->duration_ms < 1000 || q->duration_ms > 30000) ok = false;
        else {
            r->active = false;
            ok = configure(r, q);
            r->active = ok;
            r->deadline = now + q->duration_ms;
            r->started = now;
            if (!ok) { cc1101_idle(&r->chip); r->io_errors++; }
        }
    } else if (q->op == RADIO_STOP) {
        ok = cc1101_idle(&r->chip);
        r->active = false;
        if (!ok) r->io_errors++;
    }
    ok = cc1101_read_status(&r->chip, CC1101_STATUS_PARTNUM, &s.part) && ok;
    ok = cc1101_read_status(&r->chip, CC1101_STATUS_VERSION, &s.version) && ok;
    ok = cc1101_read_status(&r->chip, CC1101_STATUS_MARCSTATE, &s.marcstate) && ok;
    s.actual_hz = actual_frequency(&r->chip, &ok);
    uint8_t rssi;
    bool rssi_ok = cc1101_read_status(&r->chip, CC1101_STATUS_RSSI, &rssi);
    s.rssi_dbm = rssi_ok ? cc1101_rssi_dbm((int8_t)rssi) : 0;
    s.rssi_valid = rssi_ok && r->active && now - r->started >= 10;
    s.ok = ok && s.part == 0 && s.version == 0x14;
    s.requested_hz = r->hz; s.active = r->active; s.modulation = r->modulation;
    s.cs_pin = r->chip.cs_pin; s.configured = r->configured;
    s.samples = r->samples; s.bytes = r->bytes; s.overflows = r->overflows; s.io_errors = r->io_errors;
    fwog_link_uart_send_frame(&s, sizeof(s));
}

void radio_rx_poll(void) {
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if ((int32_t)(now - next_poll) < 0) return;
    next_poll = now + 10;
    for (unsigned i = 0; i < 2; ++i) {
        receiver_t *r = &receivers[i];
        if (!r->active) continue;
        if ((int32_t)(now - r->deadline) >= 0) {
            if (!cc1101_idle(&r->chip)) r->io_errors++;
            r->active = false; continue;
        }
        radio_event_t e = {.type = RADIO_EVENT, .radio = i + 1, .uptime_ms = now};
        uint8_t rssi = 0;
        int available = cc1101_rx_bytes_available(&r->chip);
        /* TI SWRS061I section 20: require two matching RXBYTES reads. */
        for (unsigned retry = 0; retry < 8 && available >= 0; ++retry) {
            int again = cc1101_rx_bytes_available(&r->chip);
            if (again == available) break;
            available = retry == 7 ? -1 : again;
        }
        bool ok = available >= 0 && cc1101_read_status(&r->chip, CC1101_STATUS_RSSI, &rssi);
        ok = cc1101_read_status(&r->chip, CC1101_STATUS_MARCSTATE, &e.marcstate) && ok;
        if (!ok) { r->io_errors++; r->active = false; cc1101_idle(&r->chip); continue; }
        e.rssi_dbm = cc1101_rssi_dbm((int8_t)rssi);
        e.rssi_valid = now - r->started >= 10;
        if (available & 0x80) {
            r->overflows++;
            if (!(cc1101_flush_rx(&r->chip) && cc1101_rx(&r->chip))) {
                r->io_errors++; r->active = false;
            }
        } else {
            /* Leave one byte in FIFO to avoid the documented last-byte race
               while the CC1101 can still be writing its FIFO. */
            unsigned n = (unsigned)available > 1 ? (unsigned)available - 1 : 0;
            if (n > sizeof(e.data)) n = sizeof(e.data);
            if (n && !cc1101_read_burst(&r->chip, CC1101_RXFIFO, e.data, (uint8_t)n)) {
                r->io_errors++; continue;
            }
            e.length = n; r->bytes += n;
        }
        r->samples++;
        fwog_link_uart_send_frame(&e, sizeof(e));
    }
}
