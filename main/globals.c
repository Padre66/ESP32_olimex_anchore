#include "globals.h"
#include "lwip/ip4_addr.h"

net_config_t NET;
volatile int eth_up = 0;

void globals_init(void)
{
    IP4_ADDR(&NET.ip,   192,168,0,191);
    IP4_ADDR(&NET.gw,   192,168,0,1);
    IP4_ADDR(&NET.mask, 255,255,255,0);
    IP4_ADDR(&NET.dns1, 1,1,1,1);
    IP4_ADDR(&NET.dns2, 8,8,8,8);
    NET.udp_port = 12345;
}

status_t g_status = { "A1", 1, 0.0f, 0.0f, ST_UNKNOWN };