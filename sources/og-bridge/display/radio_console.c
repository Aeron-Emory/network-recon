#include "fwog_display.h"
#include "radio_protocol.h"
#include "radio_console.h"
#include "tusb.h"
#include <stdio.h>
#include <string.h>
static char input[100];
static unsigned used;
static bool discard;
static uint32_t output_drops;
uint32_t radio_console_drops(void) { return output_drops; }

void control_write(const char *text) {
    size_t len = strlen(text);
    /* A stalled host must not block power polling or the UART0 receiver. */
    if (tud_cdc_connected() && tud_cdc_write_available() >= len)
        tud_cdc_write(text, len);
    else if (tud_cdc_connected()) output_drops++;
}
static void error(unsigned seq, const char *reason) {
    char line[100];
    snprintf(line, sizeof(line), "RADIO_ERROR seq=%u code=%s\n", seq, reason);
    control_write(line);
}
static void command(void) {
    unsigned seq, op, index, mod;
    unsigned long hz, duration;
    char extra;
    if (sscanf(input, "radio %u %u %u %lu %lu %u %c", &seq, &op, &index,
               &hz, &duration, &mod, &extra) != 6 || seq > 255 || index < 1 || index > 2 ||
        op < RADIO_STATUS || op > RADIO_STOP || mod > 2) {
        error(0, "invalid_command"); return;
    }
    if ((op == RADIO_START && (!radio_frequency_valid(hz) || duration < 1000 || duration > 30000)) ||
        (op != RADIO_START && (hz || duration || mod))) {
        error(seq, "invalid_parameters"); return;
    }
    if (op == RADIO_START) {
        fwog_ant_t path = hz < 349000000 ? FWOG_ANT_200MHZ :
                          hz < 465000000 ? FWOG_ANT_400MHZ : FWOG_ANT_900MHZ;
        const fwog_ioexp_cfg_t *cfg = fwog_ioexp_link_cfg();
        if (!fwog_ioexp_link_set_antennas(index == 1 ? path : cfg->radio1_ant,
                                         index == 2 ? path : cfg->radio2_ant)) {
            error(seq, "antenna_write_failed"); return;
        }
    }
    radio_request_t q = {.type = RADIO_REQUEST, .seq = seq, .op = op, .radio = index,
                         .frequency_hz = hz, .duration_ms = duration, .modulation = mod};
    uint8_t wire[sizeof(q) + FWOG_LINK_OVERHEAD];
    size_t n = fwog_link_encode(wire, sizeof(wire), &q, sizeof(q));
    absolute_time_t deadline = make_timeout_time_ms(2);
    for (size_t i = 0; i < n;) {
        if (uart_is_writable(FWOG_LINK_UART)) uart_get_hw(FWOG_LINK_UART)->dr = wire[i++];
        else if (time_reached(deadline)) { error(seq, "main_link_timeout"); return; }
    }
}
void radio_console_poll(void) {
    for (unsigned i = 0; i < 128 && tud_cdc_available(); ++i) {
        int ch = tud_cdc_read_char();
        if (ch < 0 || ch == '\r') continue;
        if (ch == '\n') {
            if (discard) error(0, "line_too_long");
            else if (used) { input[used] = 0; command(); }
            used = 0; discard = false;
        } else if (ch >= 32 && ch < 127 && !discard && used < sizeof(input) - 1) input[used++] = ch;
        else discard = true;
    }
}
bool radio_console_frame(const uint8_t *data, size_t len) {
    char line[360];
    if (len == sizeof(radio_response_t) && data[0] == RADIO_RESPONSE) {
        radio_response_t s; memcpy(&s, data, sizeof(s));
        snprintf(line, sizeof(line),
                 "RADIO seq=%u op=%u radio=%u ok=%u part=%u version=%u marc=%u hz=%lu actual=%lu active=%u mod=%u cs=%u configured=%u rssi=%d valid=%u samples=%lu bytes=%lu overflows=%lu io_errors=%lu\n",
                 s.seq, s.op, s.radio, s.ok, s.part, s.version, s.marcstate,
                 (unsigned long)s.requested_hz, (unsigned long)s.actual_hz,
                 s.active, s.modulation, s.cs_pin, s.configured, s.rssi_dbm, s.rssi_valid,
                 (unsigned long)s.samples, (unsigned long)s.bytes,
                 (unsigned long)s.overflows, (unsigned long)s.io_errors);
        control_write(line); return true;
    }
    if (len == sizeof(radio_event_t) && data[0] == RADIO_EVENT) {
        radio_event_t e; memcpy(&e, data, sizeof(e));
        if (e.length > sizeof(e.data)) return true;
        char hex[65];
        for (unsigned i = 0; i < e.length; ++i) snprintf(hex + i * 2, 3, "%02x", e.data[i]);
        hex[e.length * 2] = 0;
        snprintf(line, sizeof(line), "RADIO_RX radio=%u ms=%lu rssi=%d valid=%u marc=%u data=%s\n",
                 e.radio, (unsigned long)e.uptime_ms, e.rssi_dbm, e.rssi_valid, e.marcstate,
                 e.length ? hex : "-");
        control_write(line); return true;
    }
    return false;
}
