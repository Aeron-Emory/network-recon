#ifndef BNBRIDGE_RADIO_PROTOCOL_H
#define BNBRIDGE_RADIO_PROTOCOL_H
#include <stdint.h>
#include <stdbool.h>
static inline bool radio_frequency_valid(uint32_t hz) {
    return (hz >= 300000000u && hz <= 348000000u) ||
           (hz >= 387000000u && hz <= 464000000u) ||
           (hz >= 779000000u && hz <= 928000000u);
}
#define RADIO_REQUEST 0x41u
#define RADIO_RESPONSE 0x42u
#define RADIO_EVENT 0x43u
#define RADIO_STATUS 1u
#define RADIO_START 2u
#define RADIO_STOP 3u
typedef struct {
    uint8_t type, seq, op, radio;
    uint32_t frequency_hz, duration_ms;
    uint8_t modulation, reserved[3];
} radio_request_t;
_Static_assert(sizeof(radio_request_t) == 16, "radio request layout");
typedef struct {
    uint8_t type, seq, op, radio;
    uint8_t ok, part, version, marcstate;
    uint32_t requested_hz, actual_hz;
    uint8_t active, modulation, cs_pin, configured;
    int16_t rssi_dbm;
    uint8_t rssi_valid, reserved;
    uint32_t samples, bytes, overflows, io_errors;
} radio_response_t;
_Static_assert(sizeof(radio_response_t) == 40, "radio response layout");
typedef struct {
    uint8_t type, radio, length, rssi_valid;
    uint32_t uptime_ms;
    int16_t rssi_dbm;
    uint8_t marcstate, reserved;
    uint8_t data[32];
} radio_event_t;
_Static_assert(sizeof(radio_event_t) == 44, "radio event layout");
#endif
