// components/ble/ble.c — ESP-IDF v5.4, Bluedroid GATTC kliens UWB CFG/DATA-hoz
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatt_common_api.h"

#include "ble.h"   // ble_start / ble_send_get / ble_send_set

/* ====== Állapot ====== */
static const char* TAG = "BLE_CLI";

static esp_gatt_if_t g_gattc_if = 0xFE;
static uint16_t      g_conn_id  = 0xFFFF;
static esp_bd_addr_t g_peer_bda = {0};
static esp_ble_addr_type_t g_peer_addr_type = BLE_ADDR_TYPE_PUBLIC;
static bool          g_connected = false;

static uint16_t g_start_handle=0, g_end_handle=0;
static uint16_t g_data_h=0, g_cfg_h=0;
static uint16_t g_data_ccc_h=0, g_cfg_ccc_h=0;

static ble_notify_cb_t g_cb = NULL;
static char g_name_filter[32] = {0};
static bool g_connecting = false;

/* ====== UWB UUID-k ======
 * Service:  12345678-1234-5678-1234-1234567890AB
 * DATA:     ABCDEF01-1234-5678-1234-1234567890AB
 * CFG:      ABCDEF02-1234-5678-1234-1234567890AB
 *
 * IDF belső (LSB) sorrend + védelemként BE sorrend is elfogadva.
 */

/* ---- SCAN állapot ---- */
static bool s_params_set = false, s_scan_active = false;
static bool s_scan_pending = false;   /* ÚJ: start kérve, START_COMPLETE-re várunk */

static esp_ble_scan_params_t s_scan_params = {
    .scan_type              = BLE_SCAN_TYPE_ACTIVE,
    .own_addr_type          = BLE_ADDR_TYPE_PUBLIC,
    .scan_filter_policy     = BLE_SCAN_FILTER_ALLOW_ALL,
    .scan_interval          = 0x50,
    .scan_window            = 0x30,
    .scan_duplicate         = BLE_SCAN_DUPLICATE_DISABLE
};

/* ---- SCAN/CONNECT sorosítás + védett hívások (elődeklaráció) ---- */
static esp_err_t start_scan_safe(uint32_t dur_sec);
static esp_err_t gattc_open_safe(esp_gatt_if_t ifx, const esp_bd_addr_t addr, esp_ble_addr_type_t type);

static const uint8_t UWB_SVC_UUID_128[16]  = { 0xAB,0x90,0x78,0x56,0x34,0x12,0x34,0x12,0x78,0x56,0x34,0x12,0x78,0x56,0x34,0x12 };
static const uint8_t UWB_SVC_UUID_128_BE[16]= { 0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78,0x12,0x34,0x12,0x34,0x56,0x78,0x90,0xAB };
static const uint8_t UWB_DATA_UUID_128[16] = { 0xAB,0x90,0x78,0x56,0x34,0x12,0x34,0x12,0x78,0x56,0x34,0x12,0x01,0xEF,0xCD,0xAB };
static const uint8_t UWB_CFG_UUID_128[16]  = { 0xAB,0x90,0x78,0x56,0x34,0x12,0x34,0x12,0x78,0x56,0x34,0x12,0x02,0xEF,0xCD,0xAB };

static esp_bt_uuid_t uuid16(uint16_t u){ esp_bt_uuid_t x={.len=ESP_UUID_LEN_16,.uuid.uuid16=u}; return x; }
static esp_bt_uuid_t uuid128(const uint8_t u[16]){ esp_bt_uuid_t x={.len=ESP_UUID_LEN_128}; memcpy(x.uuid.uuid128,u,16); return x; }

// ---- SCAN/CONNECT sorosítás + védett hívások ----
static esp_err_t start_scan_safe(uint32_t dur_sec);
static esp_err_t gattc_open_safe(esp_gatt_if_t ifx, const esp_bd_addr_t addr, esp_ble_addr_type_t type);

static esp_err_t start_scan_safe(uint32_t dur_sec)
{
    if (g_connecting) return ESP_ERR_INVALID_STATE;

    if (!s_params_set) {
        /* Paramok még nincsenek beállítva → most kérjük be.
           A START a SET_COMPLETE eseményben történik. */
        return esp_ble_gap_set_scan_params(&s_scan_params);
    }

    /* Már fut vagy épp indul → ne indítsuk újra. */
    if (s_scan_active || s_scan_pending) {
        return ESP_ERR_INVALID_STATE;
    }

    /* Ha biztosan fut, állítsuk meg, majd indulunk. */
    if (s_scan_active) {
        esp_ble_gap_stop_scanning();
        /* STOP_COMPLETE-ben s_scan_active = false lesz. Várakozás nem kell. */
    }

    esp_err_t er = esp_ble_gap_start_scanning(dur_sec);
    if (er == ESP_OK) {
        s_scan_pending = true;   /* START kérve, még nem aktív */
    }
    return er;
}

static esp_err_t gattc_open_safe(esp_gatt_if_t ifx, const esp_bd_addr_t addr, esp_ble_addr_type_t type)
{
    if (s_scan_active) esp_ble_gap_stop_scanning();
    if (g_connecting)  return ESP_ERR_INVALID_STATE;
    g_connecting = true;
    esp_err_t er = esp_ble_gattc_open(ifx, (uint8_t*)addr, type, true);
    if (er != ESP_OK) g_connecting = false;   /* ha azonnal hibázik, engedjük újrapróbálni */
    return er;
}

/* publikus cb-regisztráció */
void ble_register_notify_cb(ble_notify_cb_t cb){ g_cb = cb; }

/* ====== Segédek ====== */
static bool adv_name_match(const uint8_t* adv, uint8_t len, const char* filter){
    if(!filter || !filter[0]) return true;
    uint8_t nlen=0; const uint8_t* name = esp_ble_resolve_adv_data((uint8_t*)adv, ESP_BLE_AD_TYPE_NAME_CMPL, &nlen);
    if(name && nlen && nlen == strlen(filter) && memcmp(name, filter, nlen)==0) return true;
    name = esp_ble_resolve_adv_data((uint8_t*)adv, ESP_BLE_AD_TYPE_NAME_SHORT, &nlen);
    return (name && nlen && nlen == strlen(filter) && memcmp(name, filter, nlen)==0);
}

static void reset_gatt_state(void){
    g_start_handle=g_end_handle=0;
    g_data_h=g_cfg_h=0;
    g_data_ccc_h=g_cfg_ccc_h=0;
}

/* ====== GAP ====== */
static void gap_cb(esp_gap_ble_cb_event_t e, esp_ble_gap_cb_param_t* p);

static void start_scan(void){
    esp_err_t er = start_scan_safe(0);
    ESP_LOGI(TAG, "scan start (safe) rc=0x%x", er);
}

/* ====== GATTC ====== */
static void gattc_cb(esp_gattc_cb_event_t e, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t* p);

/* ====== Publikus API ====== */
esp_err_t ble_start(const char* name_filter, ble_notify_cb_t cb)
{
    if (name_filter) {
        strncpy(g_name_filter, name_filter, sizeof(g_name_filter)-1);
        g_name_filter[sizeof(g_name_filter)-1]=0;
    } else {
        g_name_filter[0]=0;
    }
    g_cb = cb;

    esp_err_t er;
    if ((er = nvs_flash_init()) == ESP_ERR_NVS_NO_FREE_PAGES || er == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    // BLE-only mód + Classic BT memória felszabadítás
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
    ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));

    ESP_ERROR_CHECK(esp_bluedroid_init());
    ESP_ERROR_CHECK(esp_bluedroid_enable());

    ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_cb));
    ESP_ERROR_CHECK(esp_ble_gattc_register_callback(gattc_cb));
    ESP_ERROR_CHECK(esp_ble_gattc_app_register(0));

    return ESP_OK;
}

/* ====== GAP CB ====== */
static void gap_cb(esp_gap_ble_cb_event_t e, esp_ble_gap_cb_param_t* p)
{
    switch (e) {
    case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
        s_params_set = (p->scan_param_cmpl.status == ESP_BT_STATUS_SUCCESS);
        if (s_params_set) start_scan_safe(0);
        break;

    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
        if (p->scan_start_cmpl.status == ESP_BT_STATUS_SUCCESS) {
            s_scan_active  = true;
        } else {
            s_scan_active  = false;
        }
        s_scan_pending = false;   /* start kísérlet lezárult */
        ESP_LOGI(TAG, "scan start complete, status=0x%x", p->scan_start_cmpl.status);
        break;

    case ESP_GAP_BLE_SCAN_RESULT_EVT: {
        const esp_ble_gap_cb_param_t* sr = p;
        if (sr->scan_rst.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT) {
            if (!g_connecting && adv_name_match(sr->scan_rst.ble_adv, sr->scan_rst.adv_data_len, g_name_filter)) {
                memcpy(g_peer_bda, p->scan_rst.bda, 6);
                g_peer_addr_type = p->scan_rst.ble_addr_type;
                gattc_open_safe(g_gattc_if, g_peer_bda, g_peer_addr_type);
            }
        }
        break;
    }

    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
        s_scan_active  = false;
        s_scan_pending = false;   /* biztosan nincs folyamatban indítás */
        break;

    default:
        break;
    }
}

/* ====== CCC write ====== */
static void enable_ccc(uint16_t ccc_handle){
    uint8_t val[2] = {0x01, 0x00}; // notifications
    esp_ble_gattc_write_char_descr(g_gattc_if, g_conn_id, ccc_handle,
                                   sizeof(val), val,
                                   ESP_GATT_WRITE_TYPE_RSP,
                                   ESP_GATT_AUTH_REQ_NONE);
}

/* ====== GATTC CB ====== */
static void gattc_cb(esp_gattc_cb_event_t e, esp_gatt_if_t gattc_if, esp_ble_gattc_cb_param_t* p)
{
    if (e == ESP_GATTC_REG_EVT) {
        g_gattc_if = gattc_if;
        esp_ble_gatt_set_local_mtu(247);
        start_scan();
        return;
    }

    switch (e) {
    case ESP_GATTC_OPEN_EVT:
        if (p->open.status == ESP_GATT_OK) {
            g_connecting = false;
            g_conn_id = p->open.conn_id;
            g_connected = true;
            reset_gatt_state();
            ESP_LOGI(TAG, "connected, conn_id=%u", g_conn_id);
            esp_ble_gattc_send_mtu_req(g_gattc_if, g_conn_id);
            // Szolgáltatás-keresés szűrő NÉLKÜL, később UUID-egyeztetés
            esp_ble_gattc_search_service(g_gattc_if, g_conn_id, NULL);
        } else {
            ESP_LOGW(TAG, "open failed 0x%x; restart scan", p->open.status);
            g_connecting = false;
            vTaskDelay(pdMS_TO_TICKS(200));
            start_scan_safe(0);
        }
        break;

    case ESP_GATTC_CFG_MTU_EVT:
        ESP_LOGI(TAG, "ATT_MTU=%u", p->cfg_mtu.mtu);
        break;

    case ESP_GATTC_SEARCH_RES_EVT:
        if (p->search_res.srvc_id.uuid.len == ESP_UUID_LEN_128) {
            const uint8_t* u = p->search_res.srvc_id.uuid.uuid.uuid128;
            if (memcmp(u, UWB_SVC_UUID_128, 16)==0 || memcmp(u, UWB_SVC_UUID_128_BE, 16)==0) {
                g_start_handle = p->search_res.start_handle;
                g_end_handle   = p->search_res.end_handle;
                ESP_LOGI(TAG, "svc found: 0x%04X..0x%04X", g_start_handle, g_end_handle);
            }
        }
        break;

    case ESP_GATTC_SEARCH_CMPL_EVT: {
        if (!g_start_handle || !g_end_handle){
            // Fallback: teljes tartomány
            g_start_handle = 0x0001; g_end_handle = 0xFFFF;
            ESP_LOGW(TAG, "service not found by UUID, fallback range 0x%04X..0x%04X",
                     g_start_handle, g_end_handle);
        }

        bool have_data=false, have_cfg=false;

        // 1) UUID alapján
        {
            esp_gattc_char_elem_t chr[1]; uint16_t count=1;
            esp_bt_uuid_t cu = uuid128(UWB_DATA_UUID_128);
            if (esp_ble_gattc_get_char_by_uuid(g_gattc_if, g_conn_id,
                    g_start_handle, g_end_handle, cu, chr, &count) == ESP_GATT_OK && count) {
                g_data_h = chr[0].char_handle; have_data=true;
                ESP_LOGI(TAG, "DATA char=0x%04X", g_data_h);
            }
        }
        {
            esp_gattc_char_elem_t chr[1]; uint16_t count=1;
            esp_bt_uuid_t cu = uuid128(UWB_CFG_UUID_128);
            if (esp_ble_gattc_get_char_by_uuid(g_gattc_if, g_conn_id,
                    g_start_handle, g_end_handle, cu, chr, &count) == ESP_GATT_OK && count) {
                g_cfg_h = chr[0].char_handle; have_cfg=true;
                //ESP_LOGI(TAG, "CFG  char=0x%04X", g_cfg_h);
            }
        }

        // 2) Fallback: összes char, tulajdonság alapján
        if (!have_data || !have_cfg){
            uint16_t count=0;
            if (esp_ble_gattc_get_attr_count(g_gattc_if, g_conn_id, ESP_GATT_DB_CHARACTERISTIC,
                    g_start_handle, g_end_handle, 0, &count)==ESP_GATT_OK && count){
                esp_gattc_char_elem_t* list = calloc(count, sizeof(*list));
                if (list && esp_ble_gattc_get_all_char(g_gattc_if, g_conn_id,
                        g_start_handle, g_end_handle, list, &count, 0)==ESP_GATT_OK){
                    for (int i=0;i<count;i++){
                        uint8_t p = list[i].properties;
                        if (p & ESP_GATT_CHAR_PROP_BIT_NOTIFY){
                            if (!have_data && (p & ESP_GATT_CHAR_PROP_BIT_READ)){
                                g_data_h = list[i].char_handle; have_data=true;
                                ESP_LOGI(TAG,"DATA char(enum)=0x%04X", g_data_h);
                            } else if (!have_cfg && ((p & ESP_GATT_CHAR_PROP_BIT_WRITE) || (p & ESP_GATT_CHAR_PROP_BIT_WRITE_NR))){
                                g_cfg_h = list[i].char_handle; have_cfg=true;
                                //ESP_LOGI(TAG,"CFG  char(enum)=0x%04X", g_cfg_h);
                            }
                        }
                    }
                }
                free(list);
            }
        }

        // 3) CCC-k + feliratkozás
        if (g_data_h){
            esp_gattc_descr_elem_t dsc[1]; uint16_t count=1;
            if (esp_ble_gattc_get_descr_by_char_handle(g_gattc_if, g_conn_id, g_data_h,
                    uuid16(ESP_GATT_UUID_CHAR_CLIENT_CONFIG), dsc, &count)==ESP_GATT_OK && count) {
                g_data_ccc_h = dsc[0].handle;
                esp_ble_gattc_register_for_notify(g_gattc_if, g_peer_bda, g_data_h);
                enable_ccc(g_data_ccc_h);
            }
        }
        if (g_cfg_h){
            esp_gattc_descr_elem_t dsc[1]; uint16_t count=1;
            if (esp_ble_gattc_get_descr_by_char_handle(g_gattc_if, g_conn_id, g_cfg_h,
                    uuid16(ESP_GATT_UUID_CHAR_CLIENT_CONFIG), dsc, &count)==ESP_GATT_OK && count) {
                g_cfg_ccc_h = dsc[0].handle;
                esp_ble_gattc_register_for_notify(g_gattc_if, g_peer_bda, g_cfg_h);
                enable_ccc(g_cfg_ccc_h);
            }
        }

        if (!g_data_h || !g_cfg_h){
            ESP_LOGW(TAG, "char lookup incomplete; disconnect");
            esp_ble_gattc_close(g_gattc_if, g_conn_id);
        }
        break;
    }

    case ESP_GATTC_NOTIFY_EVT: {
        bool from_cfg = (p->notify.handle == g_cfg_h);
        if (g_cb) g_cb(p->notify.value, p->notify.value_len, from_cfg);
        break;
    }

    case ESP_GATTC_WRITE_DESCR_EVT:
        ESP_LOGI(TAG, "CCC write 0x%04X rc=0x%x", p->write.handle, p->write.status);
        break;

    case ESP_GATTC_WRITE_CHAR_EVT:
        ESP_LOGI(TAG, "WRITE char 0x%04X rc=0x%x", p->write.handle, p->write.status);
        break;

    case ESP_GATTC_CLOSE_EVT:
    case ESP_GATTC_DISCONNECT_EVT:
        ESP_LOGW(TAG, "disconnected; reason=0x%x", p->disconnect.reason);
        g_connected = false;
        g_connecting = false;
        reset_gatt_state();
        vTaskDelay(pdMS_TO_TICKS(100));
        start_scan_safe(0);
        break;

    default:
        break;
    }
}

/* ====== SET/GET küldők ====== */
static inline uint16_t max_write_payload(void){ return 240; /* MTU 247 - 7 */ }

esp_err_t ble_send_get(uint16_t req_id)
{
    if (!g_connected || !g_cfg_h) return ESP_ERR_INVALID_STATE;
    uint8_t pkt[5] = {1, 0x02, (uint8_t)(req_id>>8), (uint8_t)req_id, 0};
    esp_err_t er = esp_ble_gattc_write_char(g_gattc_if, g_conn_id, g_cfg_h,
                                            sizeof(pkt), pkt,
                                            ESP_GATT_WRITE_TYPE_RSP,
                                            ESP_GATT_AUTH_REQ_NONE);
    //ESP_LOGI(TAG, "SEND GET req=0x%04X -> 0x%x", req_id, er);
    return er;
}

esp_err_t ble_send_set(uint16_t req_id, const uint8_t* tlv, uint16_t len)
{
    if (!g_connected || !g_cfg_h) return ESP_ERR_INVALID_STATE;
    if (len > max_write_payload()) return ESP_ERR_INVALID_SIZE;

    uint8_t hdr[5] = {1, 0x01, (uint8_t)(req_id>>8), (uint8_t)req_id, 0xFF /* n_tlv (nem kötelező) */};
    uint16_t total = sizeof(hdr) + len;

    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return ESP_ERR_NO_MEM;
    memcpy(buf, hdr, 5);
    if (tlv && len) memcpy(buf+5, tlv, len);

    esp_err_t er = esp_ble_gattc_write_char(g_gattc_if, g_conn_id, g_cfg_h,
                                            total, buf,
                                            ESP_GATT_WRITE_TYPE_RSP,
                                            ESP_GATT_AUTH_REQ_NONE);
    free(buf);
    ESP_LOGI(TAG, "SEND SET req=0x%04X len=%u -> 0x%x", req_id, len, er);
    return er;
}
