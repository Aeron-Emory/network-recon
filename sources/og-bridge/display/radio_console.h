#ifndef BNBRIDGE_RADIO_CONSOLE_H
#define BNBRIDGE_RADIO_CONSOLE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
void control_write(const char *text);
void radio_console_poll(void);
bool radio_console_frame(const uint8_t *data, size_t len);
uint32_t radio_console_drops(void);
#endif
