#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void pp_log_data(const uint8_t* data, uint16_t len);

void pp_log_cfg(const uint8_t* data, uint16_t len,
                const char* (*tlv_name)(uint8_t),
                uint16_t (*rd16be)(const uint8_t*),
                uint32_t (*rd32be)(const uint8_t*));

#ifdef __cplusplus
}
#endif
