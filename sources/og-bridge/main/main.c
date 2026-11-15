#include "fwog_main.h"
#include "status.h"
#include "radio_rx.h"
#include "pico/stdio_usb.h"
#include <string.h>
#include "hardware/irq.h"
#include "hardware/gpio.h"
#include "hardware/sync.h"
#include "tusb.h"
FWOG_WATCHDOG_DEFAULT();

#define RX_SIZE (128u * 1024u)
#define RX_MASK (RX_SIZE - 1u)
static uint8_t ring[RX_SIZE];
static volatile uint32_t head, tail;
static volatile uint32_t received, drops, errors, high_water;
static fwog_link_rx_t control_rx;

static void uart_rx_irq(void) {
    while (uart_is_readable(uart1)) {
        uint32_t word = uart_get_hw(uart1)->dr;
        received++;
        if (word & 0xf00u) errors++;
        uint32_t used = head - tail;
        if (used == RX_SIZE) { drops++; continue; }
        ring[head & RX_MASK] = (uint8_t)word;
        __dmb();
        head++;
        if (used + 1u > high_water) high_water = used + 1u;
    }
    /* Clear sticky receive errors after draining their flagged data. */
    uart_get_hw(uart1)->rsr = 0;
}

int main(void) {
    board_init();
    fwog_display_result_t display = fwog_display_update_run();
    /* The display application needs a moment after RUN to initialize I2C. */
    for (unsigned i = 0; i < 200; ++i) {
        board_watchdog_kick(); tud_task(); sleep_ms(1);
    }
    fwog_io_cfg_t cfg;
    fwog_io_cfg_default(&cfg);
    fwog_io_result_t io = fwog_io_dir_apply(&cfg);
    bool ready = (io == FWOG_IO_OK);
    if (ready) {
        uart_init(uart1, 460800);
        uart_set_format(uart1, 8, 1, UART_PARITY_NONE);
        uart_set_hw_flow(uart1, false, false);
        uart_set_fifo_enabled(uart1, true);
        gpio_set_function(PIN_IO_UART_TX, GPIO_FUNC_UART);
        gpio_set_function(PIN_IO_UART_RX, GPIO_FUNC_UART);
        irq_set_exclusive_handler(UART1_IRQ, uart_rx_irq);
        irq_set_priority(UART1_IRQ, 0);
        irq_set_enabled(UART1_IRQ, true);
        uart_set_irqs_enabled(uart1, true, false);
    }
    /* Suppress even BSP driver diagnostics on the binary USB stream. */
    stdio_set_driver_enabled(&stdio_usb, false);
    radio_rx_init();
    fwog_link_rx_init(&control_rx);
    uint32_t usb_tx = 0, uart_tx = 0, disconnected = 0;
    uint8_t tx[1024];
    uint32_t tx_len = 0, tx_pos = 0;
    absolute_time_t report = make_timeout_time_ms(1000);
    while (true) {
        board_watchdog_kick();
        tud_task();
        uint8_t b;
        while (fwog_link_uart_read(&b)) {
            size_t len = 0;
            if (fwog_link_rx_byte(&control_rx, b, &len) && len == sizeof(radio_request_t) &&
                control_rx.buf[0] == RADIO_REQUEST) {
                radio_request_t request;
                memcpy(&request, control_rx.buf, sizeof(request));
                radio_rx_request(&request);
            }
        }
        radio_rx_poll();
        if (ready) {
            while (tx_pos < tx_len && uart_is_writable(uart1)) {
                uart_get_hw(uart1)->dr = tx[tx_pos++]; uart_tx++;
            }
            if (tx_pos == tx_len) {
                tx_pos = 0;
                tx_len = tud_cdc_read(tx, sizeof(tx));
            }
            if (tud_cdc_connected()) {
                uint32_t n = head - tail;
                __dmb();
                uint32_t contiguous = RX_SIZE - (tail & RX_MASK);
                if (n > contiguous) n = contiguous;
                uint32_t available = tud_cdc_write_available();
                if (n > available) n = available;
                if (n) {
                    uint32_t sent = tud_cdc_write(ring + (tail & RX_MASK), n);
                    __dmb(); tail += sent; usb_tx += sent;
                }
                tud_cdc_write_flush();
            } else {
                uint32_t saved = save_and_disable_interrupts();
                disconnected += head - tail; tail = head;
                restore_interrupts(saved);
            }
        }
        if (time_reached(report)) {
            report = make_timeout_time_ms(1000);
            bridge_status_t s = {
                .type = 0x40, .ready = ready,
                .display_result = display, .io_result = io,
                .uptime_ms = to_ms_since_boot(get_absolute_time()),
                .uart_rx = received, .usb_tx = usb_tx, .uart_tx = uart_tx,
                .ring_drops = drops, .uart_errors = errors,
                .disconnected_drops = disconnected,
                .queued = head - tail, .high_water = high_water
            };
            (void)fwog_link_uart_send_frame(&s, sizeof(s));
        }
        tight_loop_contents();
    }
}
