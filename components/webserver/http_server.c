// http_server.c
#include "esp_http_server.h"
#include "cJSON.h"
#include "ble.h"        // ble_send_get, ble_register_notify_cb
#include "freertos/semphr.h"

static SemaphoreHandle_t s_sem_ack, s_sem_tlv;
static volatile uint16_t s_last_req = 0;
static volatile uint8_t  s_ack_status = 0;
static volatile uint8_t  s_applied = 0;

// ide gyűjtjük a TLV-ket
static struct {
    uint16_t network_id, zone_id, hb_ms, phy_sfdto;
    uint32_t anchor_id;
    int32_t  tx_ant_dly, rx_ant_dly, bias_ticks;
    uint8_t  log_level, phy_ch;
    bool     have[11];
} s_cfg;

static void on_ble_notify(const uint8_t* p, uint16_t n, bool from_cfg)
{
    if(!from_cfg || !p || n<1) return;

    // ACK: [1,0x81,req_hi,req_lo,status,applied]
    if(n==6 && p[0]==1 && p[1]==0x81){
        s_ack_status = p[4];
        s_applied    = p[5];
        xSemaphoreGive(s_sem_ack);
        return;
    }

    // TLV blokkok
    const uint8_t* q=p; uint16_t r=n; bool first=true;
    while(r>=2){
        uint8_t t=q[0], l=q[1]; q+=2; r-=2;
        if(r<l) break;
        if(first && t==0x00){ first=false; q+=l; r-=l; continue; } // T_VER skip

        switch(t){
            case 0x10: if(l==2){ s_cfg.network_id=(q[0]<<8)|q[1]; s_cfg.have[0]=true; } break;
            case 0x11: if(l==2){ s_cfg.zone_id   =(q[0]<<8)|q[1]; s_cfg.have[1]=true; } break;
            case 0x12: if(l==4){ s_cfg.anchor_id =(q[0]<<24)|(q[1]<<16)|(q[2]<<8)|q[3]; s_cfg.have[2]=true; } break;
            case 0x20: if(l==2){ s_cfg.hb_ms     =(q[0]<<8)|q[1]; s_cfg.have[3]=true; } break;
            case 0x1F: if(l==1){ s_cfg.log_level = q[0];           s_cfg.have[4]=true; } break;
            case 0x13: if(l==4){ s_cfg.tx_ant_dly=(int32_t)((q[0]<<24)|(q[1]<<16)|(q[2]<<8)|q[3]); s_cfg.have[5]=true; } break;
            case 0x14: if(l==4){ s_cfg.rx_ant_dly=(int32_t)((q[0]<<24)|(q[1]<<16)|(q[2]<<8)|q[3]); s_cfg.have[6]=true; } break;
            case 0x16: if(l==4){ s_cfg.bias_ticks=(int32_t)((q[0]<<24)|(q[1]<<16)|(q[2]<<8)|q[3]); s_cfg.have[7]=true; } break;
            case 0x40: if(l==1){ s_cfg.phy_ch     = q[0];           s_cfg.have[8]=true; } break;
            case 0x49: if(l==2){ s_cfg.phy_sfdto  =(q[0]<<8)|q[1]; s_cfg.have[9]=true; } break;
            default: break;
        }
        q+=l; r-=l;
    }

    // Heuriszta: ha sok mező bejött, engedjük tovább a HTTP választ
    if(s_cfg.have[0] || s_cfg.have[2] || s_cfg.have[3]) xSemaphoreGive(s_sem_tlv);
}

static esp_err_t dwm_get_handler(httpd_req_t* req)
{
    // init
    memset(&s_cfg, 0, sizeof(s_cfg));
    if(!s_sem_ack) s_sem_ack = xSemaphoreCreateBinary();
    if(!s_sem_tlv) s_sem_tlv = xSemaphoreCreateBinary();

    // BLE GET
    s_last_req++;
    ble_send_get(s_last_req);

    // ACK várakozás
    if(xSemaphoreTake(s_sem_ack, pdMS_TO_TICKS(1500))!=pdTRUE){
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "ACK timeout");
        return ESP_FAIL;
    }

    // TLV gyűjtés
    xSemaphoreTake(s_sem_tlv, 0); // ürítés
    (void)xSemaphoreTake(s_sem_tlv, pdMS_TO_TICKS(1200)); // első blokkig
    vTaskDelay(pdMS_TO_TICKS(200)); // kicsi puffer az extra blokkoknak

    // JSON
    cJSON* j=cJSON_CreateObject();
    if(s_cfg.have[0]) cJSON_AddNumberToObject(j,"NETWORK_ID", s_cfg.network_id);
    if(s_cfg.have[1]) cJSON_AddNumberToObject(j,"ZONE_ID",    s_cfg.zone_id);
    if(s_cfg.have[2]) cJSON_AddStringToObject(j,"ANCHOR_ID",  (char[]){0}); // hex formátum:
    {
        char hex[11]; snprintf(hex,sizeof hex,"0x%08X", s_cfg.anchor_id);
        cJSON_ReplaceItemInObject(j,"ANCHOR_ID", cJSON_CreateString(hex));
    }
    if(s_cfg.have[3]) cJSON_AddNumberToObject(j,"HB_MS",      s_cfg.hb_ms);
    if(s_cfg.have[4]) cJSON_AddNumberToObject(j,"LOG_LEVEL",  s_cfg.log_level);
    if(s_cfg.have[5]) cJSON_AddNumberToObject(j,"TX_ANT_DLY", s_cfg.tx_ant_dly);
    if(s_cfg.have[6]) cJSON_AddNumberToObject(j,"RX_ANT_DLY", s_cfg.rx_ant_dly);
    if(s_cfg.have[7]) cJSON_AddNumberToObject(j,"BIAS_TICKS", s_cfg.bias_ticks);
    if(s_cfg.have[8]) cJSON_AddNumberToObject(j,"PHY_CH",     s_cfg.phy_ch);
    if(s_cfg.have[9]) cJSON_AddNumberToObject(j,"PHY_SFDTO",  s_cfg.phy_sfdto);

    char* out=cJSON_PrintUnformatted(j);
    httpd_resp_set_type(req,"application/json");
    httpd_resp_sendstr(req,out?out:"{}");
    free(out); cJSON_Delete(j);
    return ESP_OK;
}

void http_register_routes(httpd_handle_t h)
{
    static httpd_uri_t u={
        .uri="/api/dwm_get", .method=HTTP_GET, .handler=dwm_get_handler
    };
    httpd_register_uri_handler(h,&u);
}

void ble_http_bridge_init(void){
    ble_register_notify_cb(on_ble_notify);
}
