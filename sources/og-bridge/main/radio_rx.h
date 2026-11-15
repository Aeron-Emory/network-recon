#ifndef BNBRIDGE_RADIO_RX_H
#define BNBRIDGE_RADIO_RX_H
#include "radio_protocol.h"
void radio_rx_init(void);
void radio_rx_request(const radio_request_t *request);
void radio_rx_poll(void);
#endif
