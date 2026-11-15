#include "fwog_display.h"
#include "status.h"
#include "radio_console.h"
#include "pico/stdio_usb.h"
#include "tusb.h"
#include <string.h>
FWOG_POWER_DEFAULT();
static fwog_link_rx_t rx;
static bridge_status_t status;

int main(void) {
    board_init();
    stdio_set_driver_enabled(&stdio_usb, false);
    bool link = fwog_link_uart_init(FWOG_LINK_BAUD);
    fwog_link_rx_init(&rx);
    (void)ws2812_init(pio0, 0);
    st7789_init_begin();
    absolute_time_t lcd_limit = make_timeout_time_ms(500);
    bool lcd_started = false;
    absolute_time_t report = make_timeout_time_ms(1000);
    while (true) {
        tud_task();
        radio_console_poll();
        fwog_power_poll(to_ms_since_boot(get_absolute_time()));
        if (!time_reached(lcd_limit)) st7789_init_step();
        if (st7789_ready() && !lcd_started) {
            st7789_clear(0); lcd_started = true;
            board_backlight(180);
        }
        uint8_t b;
        while (link && fwog_link_uart_read(&b)) {
            size_t n = 0;
            if (fwog_link_rx_byte(&rx, b, &n)) {
                if (n == sizeof(status) && rx.buf[0] == 0x40)
                    memcpy(&status, rx.buf, n);
                else if (!radio_console_frame(rx.buf, n))
                    (void)fwog_ioexp_link_handle(rx.buf, n);
            }
        }
        if (time_reached(report)) {
            report = make_timeout_time_ms(1000);
            if (st7789_ready() && !st7789_busy()) {
                lcd_text_draw_padded(4, 16, "Bottlenose bridge", 20, 2, 0xffff, 0);
                lcd_text_draw_padded(4, 48, status.ready ? "USB on OG: ready" : "Setup failed", 20, 2, 0x07e0, 0);
                lcd_text_draw_padded(4, 90, "Wi-Fi / BLE / PCAP", 20, 2, 0xffff, 0);
                lcd_text_draw_padded(4, 120, "Sub-GHz RX: COM9", 20, 2, 0xffff, 0);
                lcd_text_draw_padded(4, 180, "Red 6s: power off", 20, 2, 0xffff, 0);
            }
            char line[300];
            snprintf(line, sizeof(line), "BNBRIDGE ready=%u display=%u io=%u ms=%lu rx=%lu usb=%lu tx=%lu drops=%lu errors=%lu disconnected=%lu queued=%lu high=%lu control_drops=%lu\n",
                 status.ready, status.display_result, status.io_result,
                 (unsigned long)status.uptime_ms, (unsigned long)status.uart_rx,
                 (unsigned long)status.usb_tx, (unsigned long)status.uart_tx,
                 (unsigned long)status.ring_drops, (unsigned long)status.uart_errors,
                 (unsigned long)status.disconnected_drops,
                 (unsigned long)status.queued, (unsigned long)status.high_water,
                 (unsigned long)radio_console_drops());
            control_write(line);
        }
        tud_cdc_write_flush();
        sleep_us(100);
    }
}
