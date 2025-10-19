#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Értesítés a bejövő BLE értesítésekről (DATA/CFG), from_cfg==true ha CFG karakterisztika
typedef void (*ble_notify_cb_t)(const uint8_t* data, uint16_t len, bool from_cfg);

/* Callback minden NOTIFY-ra.
 * from_cfg=true: CFG karakterisztika (ACK / HB TLV / STATE)
 * from_cfg=false: DATA karakterisztika (UWBPacket 20 bájt) */
typedef void (*ble_notify_cb_t)(const uint8_t* data, uint16_t len, bool from_cfg);

/* Indítás: BLE stack, GAP scan, automatikus connect név alapján.
 * name_filter == NULL vagy "" esetén bármire csatlakozik, ami UWB service-t hirdet. */
esp_err_t ble_start(const char* name_filter, ble_notify_cb_t cb);

/* GET kérés: ver=1, cmd=0x02, req_id=BE; a szerver CURRENT(+DEFAULTS) TLV-eket és ACK-ot NOTIFY-ol. */
esp_err_t ble_send_get(uint16_t req_id);

/* SET kérés: ver=1, cmd=0x01, req_id=BE, majd TLV lista (tlv_buf=[t,l,val..]...) */
esp_err_t ble_send_set(uint16_t req_id, const uint8_t* tlv_buf, uint16_t tlv_len);

#ifdef __cplusplus
}
#endif

