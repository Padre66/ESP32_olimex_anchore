#include <stdio.h>
#include "esp_log.h"
#include "pretty_print.h"
#include <inttypes.h>

static const char* TAG_BLE = "BLE";
static const char* TAG_CFG = "CFG";
static const char* TAG_DAT = "DATA";

static inline uint32_t rd32le(const uint8_t* p){
    return ((uint32_t)p[0]) | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint64_t rd40le(const uint8_t* p){   // 5 B little-endian
    return ((uint64_t)p[0]) |
           ((uint64_t)p[1]<<8) |
           ((uint64_t)p[2]<<16) |
           ((uint64_t)p[3]<<24) |
           ((uint64_t)p[4]<<32);
}

// pretty_print.c
void pp_log_cfg(const uint8_t* d, uint16_t n,
                const char* (*tlv_name)(uint8_t),
                uint16_t (*rd16be)(const uint8_t*),
                uint32_t (*rd32be)(const uint8_t*))
{
    // HB fast-path: [01 01 <st>] [02 04 <up:BE32>] [03 02 <sync_ms:BE16>]  => 13 B
    if (n == 13 && d[0]==0x01 && d[1]==0x01 && d[3]==0x02 && d[4]==0x04 && d[9]==0x03 && d[10]==0x02) {
        uint8_t  st   = d[2];
        uint32_t up   = rd32be(&d[5]);
        uint16_t sync = rd16be(&d[11]);
        ESP_LOGI("CFG", "HB st=0x%02X up=%" PRIu32 " sync_ms=%u", st, up, (unsigned)sync);
        return;
    }

    // ACK
    if(n==6 && d[0]==1 && d[1]==0x81){
        ESP_LOGI("CFG","ACK req=%u status=0x%02X applied=%u",
                 (unsigned)rd16be(&d[2]), d[4], d[5]);
        return;
    }
    // STATE
    if(n==17 && d[0]==1 && d[1]==0x90){
        ESP_LOGI("CFG","STATE st=0x%02X sync_ms=%u up=%" PRIu32 " net=%u zone=0x%04X anc=0x%08" PRIX32,
                 d[2], (unsigned)rd16be(&d[3]), (uint32_t)rd32be(&d[5]),
                 (unsigned)rd16be(&d[9]), (unsigned)rd16be(&d[11]),
                 (uint32_t)rd32be(&d[13]));
        return;
    }

    // TLV stream
    uint16_t i=0;
    while(i+2<=n){
        uint8_t t=d[i++], l=d[i++];
        if(i+l>n){ ESP_LOGW("CFG","TLV overflow t=0x%02X l=%u",t,(unsigned)l); break; }
        const uint8_t* v=&d[i];
        const char* nm = tlv_name? tlv_name(t):"TLV";

        switch (t) {
          case 0x00: if(l==1) ESP_LOGI("CFG","%s=%u", nm, v[0]); break;
          case 0x01: if(l==1) ESP_LOGI("CFG","%s=0x%02X", nm, v[0]); break;
          case 0x02: if(l==4) ESP_LOGI("CFG","%s=%" PRIu32, nm, (uint32_t)rd32be(v)); break;
          case 0x03: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x10: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x11: if(l==2) ESP_LOGI("CFG","%s=0x%04X", nm, (unsigned)rd16be(v)); break;
          case 0x12: if(l==4) ESP_LOGI("CFG","%s=0x%08" PRIX32, nm, (uint32_t)rd32be(v)); break;
          case 0x13: if(l==4) ESP_LOGI("CFG","%s=%" PRId32, nm, (int32_t) rd32be(v)); break;
          case 0x14: if(l==4) ESP_LOGI("CFG","%s=%" PRId32, nm, (int32_t) rd32be(v)); break;
          case 0x16: if(l==4) ESP_LOGI("CFG","%s=%" PRId32, nm, (int32_t) rd32be(v)); break; // BIAS_TICKS
          case 0x1F: if(l==1) ESP_LOGI("CFG","%s=%u", nm, v[0]); break;
          case 0x20: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x30: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x31: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x32: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x33: if(l==1) ESP_LOGI("CFG","%s=%u", nm, v[0]); break;
          case 0x34: if(l==1) ESP_LOGI("CFG","%s=%u", nm, v[0]); break;
          case 0x35: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x36: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x37: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x38: if(l==2) ESP_LOGI("CFG","%s=%u", nm, (unsigned)rd16be(v)); break;
          case 0x39: if(l==1) ESP_LOGI("CFG","%s=%u", nm, v[0]); break;
          default: {
            char hex[128]; size_t o=0;
            for(uint8_t k=0;k<l && o+3<sizeof(hex);k++) o += snprintf(hex+o,sizeof(hex)-o,"%02X ",v[k]);
            if(o) hex[o-1]=0;
            ESP_LOGI("CFG","%s[len=%u]: %s", nm, (unsigned)l, hex);
          } break;
        }
        i+=l;
    }
}

void pp_log_data(const uint8_t* d, uint16_t n)
{
    if (n!=20 || d[0]!=0xAB){ /* hexdump fallback ... */ return; }

    uint8_t  version  = d[1];
    uint8_t  sync_seq = d[2];
    uint8_t  tag_seq  = d[3];
    uint32_t anchor_id= rd32le(&d[4]);
    uint32_t tag_id   = rd32le(&d[8]);
    uint64_t ts_40    = rd40le(&d[12]);   // 40 bit érvényes, LE

    ESP_LOGI("DATA",
        "VER=%u SYNC=%u TAGSEQ=%u ANCHOR_ID=0x%08" PRIX32
        " TAG_ID=0x%08" PRIX32 " TIMESTAMP=%" PRIu64 " (0x%010" PRIX64 ")",
        version, sync_seq, tag_seq, anchor_id, tag_id, ts_40, ts_40);
}