#pragma once
#include <stdint.h>
#include "lwip/ip_addr.h"

typedef struct {
    ip4_addr_t ip;
    ip4_addr_t gw;
    ip4_addr_t mask;
    ip4_addr_t dns1;
    ip4_addr_t dns2;
    uint16_t   udp_port;
} net_config_t;

extern net_config_t NET;
extern volatile int eth_up;

void globals_init(void);


typedef enum { ST_UNKNOWN=0, ST_OK, ST_WARN, ST_ERR } state_t;

typedef struct {
    const char* anchor;   // "A1" stb.
    uint8_t     id;
    float       last_meas_s;
    float       last_volt;
    state_t     state;
} status_t;

extern status_t g_status;
