#ifndef BNBRIDGE_STATUS_H
#define BNBRIDGE_STATUS_H
#include <stdint.h>
/* Private inter-CPU message, never inserted into the capture stream. */
typedef struct {
    uint8_t type; /* 0x40 */
    uint8_t ready;
    uint8_t display_result;
    uint8_t io_result;
    uint32_t uptime_ms;
    uint32_t uart_rx;
    uint32_t usb_tx;
    uint32_t uart_tx;
    uint32_t ring_drops;
    uint32_t uart_errors;
    uint32_t disconnected_drops;
    uint32_t queued;
    uint32_t high_water;
} bridge_status_t;
#endif
