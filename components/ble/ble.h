#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ble_notify_cb_t)(const uint8_t* data, uint16_t len, bool from_cfg);

esp_err_t ble_start(const char* name_filter, ble_notify_cb_t cb);
esp_err_t ble_send_get(uint16_t req_id);
esp_err_t ble_send_set(uint16_t req_id, const uint8_t* tlv_buf, uint16_t tlv_len);
void ble_register_notify_cb(ble_notify_cb_t cb);

#ifdef __cplusplus
}
#endif
