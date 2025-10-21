// components/webserver/webserver.cpp — ESP-IDF v5.3.x
// Auth (login + SID cookie), Basic Auth fallback, DWM TLV GET diagnosztikával.

#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "mbedtls/base64.h"
#include "webserver.hpp"
#include "globals.h"
#include "ble.h"

static const char* TAG = "WEB";

/* ================= HTTPD handle ================= */
static httpd_handle_t s_http = NULL;

/* ================= Users + Sessions ================= */
struct User { const char* u; const char* p; user_role_t r; };
static const User kUsers[] = {
    {"diag","diag",ROLE_DIAG},
    {"admin","admin",ROLE_BLE},
    {"root","root",ROLE_ROOT},
    {nullptr,nullptr,ROLE_NONE}
};
struct Session { char sid[33]; user_role_t role; uint32_t exp_s; };
static Session g_sess[8]; // kevés is elég

static void mk_sid(char out[33]){
    for(int i=0;i<32;i++){ uint8_t b = esp_random() & 0x0F; out[i] = "0123456789abcdef"[b]; }
    out[32] = 0;
}
static user_role_t check_user(const char* u, const char* pw){
    for (auto& x: kUsers) if (x.u && strcmp(u,x.u)==0 && strcmp(pw,x.p)==0) return x.r;
    return ROLE_NONE;
}

/* ---------- Basic Auth decode ---------- */
static bool decode_basic(const char* h, std::string& u, std::string& p){
    if (!h) return false;
    const char* pref = "Basic ";
    if (strncmp(h, pref, 6) != 0) return false;
    const char* b64 = h + 6;
    size_t olen=0;
    (void)mbedtls_base64_decode(nullptr,0,&olen,(const unsigned char*)b64,strlen(b64));
    std::vector<unsigned char> buf(olen+1);
    if (mbedtls_base64_decode(buf.data(),olen,&olen,(const unsigned char*)b64,strlen(b64))!=0) return false;
    buf[olen]=0;
    char* sep = (char*)strchr((char*)buf.data(),':'); if(!sep) return false;
    *sep=0; u.assign((char*)buf.data()); p.assign(sep+1); return true;
}
static bool decode_basic_hdr(httpd_req_t* req, std::string& u, std::string& p){
    size_t len=httpd_req_get_hdr_value_len(req,"Authorization"); if(!len) return false;
    std::vector<char> auth(len+1);
    if(httpd_req_get_hdr_value_str(req,"Authorization",auth.data(),auth.size())!=ESP_OK) return false;
    return decode_basic(auth.data(), u, p);
}

/* ---------- Cookie (SID) ellenőrzés ---------- */
static user_role_t role_from_cookie(httpd_req_t* req){
    size_t n=httpd_req_get_hdr_value_len(req,"Cookie"); if(!n) return ROLE_NONE;
    std::vector<char> ck(n+1);
    if(httpd_req_get_hdr_value_str(req,"Cookie",ck.data(),ck.size())!=ESP_OK) return ROLE_NONE;
    const char* m=strstr(ck.data(),"SID="); if(!m) return ROLE_NONE; m+=4;
    char sid[33]={0}; int i=0; while(*m && *m!=';' && i<32) sid[i++]=*m++;
    uint32_t now=(uint32_t)(esp_timer_get_time()/1000000ULL);
    for(auto& s: g_sess) if(s.sid[0] && strcmp(s.sid,sid)==0 && s.exp_s>now) return s.role;
    return ROLE_NONE;
}
static user_role_t role_from_auth(httpd_req_t* req){
    user_role_t r = role_from_cookie(req);
    if (r != ROLE_NONE) return r;
    std::string u,p; if(!decode_basic_hdr(req,u,p)) return ROLE_NONE;
    return check_user(u.c_str(), p.c_str());
}
static bool require_role(httpd_req_t* req, user_role_t need){
    user_role_t r=role_from_auth(req);
    if(r<need){
        if (strncmp(req->uri,"/api/",5)==0 || strncmp(req->uri,"/auth/",6)==0){
            httpd_resp_set_status(req,"401 Unauthorized"); httpd_resp_sendstr(req,"");
        } else {
            httpd_resp_set_status(req,"302 Found"); httpd_resp_set_hdr(req,"Location","/login"); httpd_resp_sendstr(req,"");
        }
        return false;
    }
    return true;
}

/* ================= Static file helper ================= */
static esp_err_t send_file(httpd_req_t* req, const char* path, const char* ctype){
    FILE* f=fopen(path,"rb");
    if(!f){ httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"Not found"); return ESP_FAIL; }
    httpd_resp_set_type(req, ctype);
    char buf[1024]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0){
        if(httpd_resp_send_chunk(req,buf,n)!=ESP_OK){ fclose(f); httpd_resp_sendstr_chunk(req,NULL); return ESP_FAIL; }
    }
    fclose(f); httpd_resp_sendstr_chunk(req,NULL); return ESP_OK;
}

/* ================= Pages ================= */
static esp_err_t login_get(httpd_req_t* r){ return send_file(r,"/spiffs/login.html","text/html"); }
static esp_err_t diag_get (httpd_req_t* r){ if(!require_role(r,ROLE_DIAG))return ESP_FAIL; return send_file(r,"/spiffs/diag.html","text/html"); }
static esp_err_t ble_get  (httpd_req_t* r){ if(!require_role(r,ROLE_BLE ))return ESP_FAIL; return send_file(r,"/spiffs/ble.html","text/html"); }
static esp_err_t admin_get(httpd_req_t* r){ if(!require_role(r,ROLE_ROOT))return ESP_FAIL; return send_file(r,"/spiffs/admin.html","text/html"); }
static esp_err_t super_user_get(httpd_req_t* r){ if(!require_role(r,ROLE_BLE))return ESP_FAIL; return send_file(r,"/spiffs/super_user.html","text/html"); }

/* ================= /auth/login =================
   Body: {"user":"admin","pass":"admin"}
   Siker: Set-Cookie: SID=...; Path=/; HttpOnly; Max-Age=86400
*/
static esp_err_t auth_login_post(httpd_req_t* req){
    int len=req->content_len; if(len<=0) return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"empty");
    std::vector<char> body(len+1,0); int off=0;
    while(off<len){ int r=httpd_req_recv(req,body.data()+off,len-off); if(r<=0) return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"recv"); off+=r; }

    auto getstr=[&](const char* key)->std::string{
        const char* k=strstr(body.data(),key); if(!k) return {};
        k=strchr(k,':'); if(!k) return {}; k++;
        while(*k==' '||*k=='\"') ++k;
        const char* e=k; while(*e && *e!='\"' && *e!=',' && *e!='}') ++e;
        return std::string(k,e-k);
    };
    std::string u=getstr("\"user\""); std::string p=getstr("\"pass\"");
    user_role_t r=check_user(u.c_str(),p.c_str());
    if(r==ROLE_NONE) return httpd_resp_send_err(req,HTTPD_401_UNAUTHORIZED,"bad creds");

    // session mentés
    char sid[33]; mk_sid(sid);
    uint32_t now=(uint32_t)(esp_timer_get_time()/1000000ULL);
    // első szabad slot
    int idx=0; for(int i=0;i<(int)(sizeof(g_sess)/sizeof(g_sess[0]));++i){ if(g_sess[i].sid[0]==0){ idx=i; break; } }
    memset(&g_sess[idx],0,sizeof(g_sess[0]));
    strncpy(g_sess[idx].sid,sid,sizeof(g_sess[0].sid)-1);
    g_sess[idx].role=r; g_sess[idx].exp_s=now+86400;

    std::string cookie = std::string("SID=")+sid+"; Path=/; HttpOnly; Max-Age=86400";
    httpd_resp_set_hdr(req,"Set-Cookie",cookie.c_str());
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_sendstr(req,"{\"ok\":true}\n");
}

/* ================= ESP config tükör az UI-hoz ================= */
struct EspCfg {
    uint16_t NETWORK_ID = 1;
    uint16_t ZONE_ID    = 0x5A31;
    uint32_t ANCHOR_ID  = 0x00000001;
    uint16_t HB_MS      = 10000;
    uint8_t  LOG_LEVEL  = 1;
    int32_t  TX_ANT_DLY = 0;
    int32_t  RX_ANT_DLY = 0;
    int32_t  BIAS_TICKS = 0;
    uint8_t  PHY_CH     = 9;
    uint16_t PHY_SFDTO  = 248;
} g_cfg;

static void json_cfg_print(char* buf, size_t sz, const EspCfg& c){
    snprintf(buf, sz,
      "{"
      "\"NETWORK_ID\":%u,"
      "\"ZONE_ID\":\"0x%04X\","
      "\"ANCHOR_ID\":\"0x%08X\","
      "\"HB_MS\":%u,"
      "\"LOG_LEVEL\":%u,"
      "\"TX_ANT_DLY\":%d,"
      "\"RX_ANT_DLY\":%d,"
      "\"BIAS_TICKS\":%d,"
      "\"PHY_CH\":%u,"
      "\"PHY_SFDTO\":%u"
      "}\n",
      (unsigned)c.NETWORK_ID,(unsigned)c.ZONE_ID,(unsigned)c.ANCHOR_ID,
      (unsigned)c.HB_MS,(unsigned)c.LOG_LEVEL,
      (int)c.TX_ANT_DLY,(int)c.RX_ANT_DLY,(int)c.BIAS_TICKS,
      (unsigned)c.PHY_CH,(unsigned)c.PHY_SFDTO);
}
static bool find_key(const char* body, const char* key, const char** val_start){
    const char* p=strstr(body,key); if(!p) return false;
    p=strchr(p,':'); if(!p) return false; p++;
    while(*p==' '||*p=='\"'){ if(*p=='\"'){ *val_start=p; return true; } ++p; }
    *val_start=p; return true;
}
static bool parse_u32(const char* body, const char* key, uint32_t& out){
    const char* v=nullptr; if(!find_key(body,key,&v)) return false; char* end=nullptr;
    if(*v=='\"') out=strtoul(v+1,&end,16); else out=strtoul(v,&end,10); return true;
}
static bool parse_i32(const char* body, const char* key, int32_t& out){
    const char* v=nullptr; if(!find_key(body,key,&v)) return false; char* end=nullptr;
    if(*v=='\"') out=(int32_t)strtol(v+1,&end,16); else out=(int32_t)strtol(v,&end,10); return true;
}
static bool parse_u16(const char* body, const char* key, uint16_t& out){ uint32_t t; if(!parse_u32(body,key,t)) return false; out=(uint16_t)t; return true; }
static bool parse_u8 (const char* body, const char* key, uint8_t&  out){ uint32_t t; if(!parse_u32(body,key,t)) return false; out=(uint8_t)t;  return true; }

static esp_err_t api_config_get(httpd_req_t* req){
    if(!require_role(req, ROLE_BLE)) return ESP_FAIL;
    char buf[256]; json_cfg_print(buf,sizeof(buf),g_cfg);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req, buf, strlen(buf));
}
static esp_err_t api_config_post(httpd_req_t* req){
    if(!require_role(req, ROLE_BLE)) return ESP_FAIL;
    int len=req->content_len; if(len<=0) return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"empty");
    std::vector<char> body(len+1,0); int off=0;
    while(off<len){ int r=httpd_req_recv(req,body.data()+off,len-off); if(r<=0) return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"recv"); off+=r; }
    parse_u16(body.data(),"\"NETWORK_ID\"",g_cfg.NETWORK_ID);
    parse_u16(body.data(),"\"ZONE_ID\""   ,g_cfg.ZONE_ID);
    { uint32_t t; if(parse_u32(body.data(),"\"ANCHOR_ID\"",t)) g_cfg.ANCHOR_ID=t; }
    parse_u16(body.data(),"\"HB_MS\""     ,g_cfg.HB_MS);
    parse_u8 (body.data(),"\"LOG_LEVEL\"" ,g_cfg.LOG_LEVEL);
    parse_i32(body.data(),"\"TX_ANT_DLY\"",g_cfg.TX_ANT_DLY);
    parse_i32(body.data(),"\"RX_ANT_DLY\"",g_cfg.RX_ANT_DLY);
    parse_i32(body.data(),"\"BIAS_TICKS\"",g_cfg.BIAS_TICKS);
    parse_u8 (body.data(),"\"PHY_CH\""    ,g_cfg.PHY_CH);
    parse_u16(body.data(),"\"PHY_SFDTO\"" ,g_cfg.PHY_SFDTO);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_sendstr(req,"{\"ok\":true}\n");
}

/* ================= /api/status ================= */
static esp_err_t api_status_get(httpd_req_t* req){
    const char* st = (g_status.state==ST_OK?"ok":g_status.state==ST_WARN?"warn":g_status.state==ST_ERR?"err":"off");
    char buf[128];
    int n=snprintf(buf,sizeof(buf),
        "{\"anchor\":\"%s\",\"id\":%u,\"last_s\":%.2f,\"last_v\":%.2f,\"state\":\"%s\"}\n",
        g_status.anchor,g_status.id,g_status.last_meas_s,g_status.last_volt,st);
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req,buf,n);
}

/* ================= BLE notify + TLV GET diagnosztika ================= */
static volatile bool     s_ack_seen     = false;
static uint64_t          s_last_tlv_us  = 0;
static std::vector<uint8_t> s_bytes;
struct Frame { bool from_cfg; uint16_t len; };
static std::vector<Frame> s_frames;

static inline uint16_t rd16be(const uint8_t* p){ return (uint16_t)p[0]<<8 | p[1]; }
static inline uint32_t rd32be(const uint8_t* p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

static void on_ble_notify(const uint8_t* p, uint16_t n, bool from_cfg){
    if(!p || n==0) return;
    if(n==6 && p[0]==1 && p[1]==0x81){ s_ack_seen=true; return; }       // ACK
    if(n>=2 && p[0]==1 && p[1]==0x90) return;                            // STATE → eldob
    s_frames.push_back(Frame{from_cfg,n});
    s_bytes.insert(s_bytes.end(),p,p+n);
    s_last_tlv_us = esp_timer_get_time();
    // napló rövid hexdump
    char line[192]; int wp=0;
    wp+=snprintf(line+wp,sizeof(line)-wp,"[%s] len=%u: ",from_cfg?"CFG":"DATA",(unsigned)n);
    for (int i=0;i<n && wp<(int)sizeof(line)-3;i++) wp+=snprintf(line+wp,sizeof(line)-wp,"%02X ",p[i]);
    ESP_LOGI(TAG,"%s",line);
}

static esp_err_t api_dwm_get(httpd_req_t* req){
    if(!require_role(req, ROLE_BLE)) return ESP_FAIL;

    s_ack_seen=false; s_last_tlv_us=0; s_bytes.clear(); s_frames.clear();
    static uint16_t s_req=1; s_req++; (void)ble_send_get(s_req);

    const uint64_t t0=esp_timer_get_time();
    while(!s_ack_seen && (esp_timer_get_time()-t0)<800000ULL) vTaskDelay(pdMS_TO_TICKS(10));
    const uint64_t t1=esp_timer_get_time();
    for(;;){
        uint64_t now=esp_timer_get_time();
        if(s_last_tlv_us && (now-s_last_tlv_us)>200000ULL) break;
        if((now-t1)>1500000ULL) break;
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    // TLV → JSON + RAW_HEX, FRAMES
    char json[2048]; size_t wp=0; bool first=true;
    auto add=[&](const char* k, const char* v){ wp+=snprintf(json+wp,sizeof(json)-wp,"%s\"%s\":%s",first?"":",",k,v); first=false; };
    wp+=snprintf(json+wp,sizeof(json)-wp,"{");

    size_t off=0, alen=s_bytes.size();
    if(alen>=2 && s_bytes[0]==0x00){ uint8_t l=s_bytes[1]; if(alen>=2+l) off=2+l; } // VER skip

    auto name_of=[](uint8_t t)->const char*{
        switch(t){
            case 0x10: return "NETWORK_ID"; case 0x11: return "ZONE_ID";
            case 0x12: return "ANCHOR_ID";  case 0x13: return "TX_ANT_DLY";
            case 0x14: return "RX_ANT_DLY"; case 0x16: return "BIAS_TICKS";
            case 0x1F: return "LOG_LEVEL";  case 0x20: return "HB_MS";
            case 0x40: return "PHY_CH";     case 0x49: return "PHY_SFDTO";
            default:   return nullptr;
        }
    };

    while(off+2<=alen){
        uint8_t t=s_bytes[off], l=s_bytes[off+1]; off+=2;
        if(off+l>alen) break;
        const uint8_t* v=&s_bytes[off]; off+=l;
        const char* nm=name_of(t); if(!nm) continue;
        char vb[32];
        if(l==1) snprintf(vb,sizeof(vb),"%u",(unsigned)v[0]);
        else if(l==2) snprintf(vb,sizeof(vb),"%u",(unsigned)rd16be(v));
        else if(l==4) snprintf(vb,sizeof(vb),"\"0x%08" PRIX32 "\"", rd32be(v));
        else continue;
        add(nm,vb);
    }

    // RAW_HEX
    {
        std::string hex; hex.reserve(alen*3);
        for(size_t i=0;i<alen;i++){ char b[4]; snprintf(b,sizeof(b),"%02X ",s_bytes[i]); hex+=b; }
        if(!hex.empty()) hex.pop_back();
        char b[1024]; snprintf(b,sizeof(b),"\"%s\"",hex.c_str());
        add("RAW_HEX",b);
    }
    // FRAMES
    {
        std::string fr="[";
        for(size_t i=0;i<s_frames.size();i++){
            char b[32]; snprintf(b,sizeof(b),"%s[\"%s\",%u]",i?",":"",s_frames[i].from_cfg?"CFG":"DATA",(unsigned)s_frames[i].len);
            fr+=b;
        }
        fr+="]";
        add("FRAMES",fr.c_str());
    }

    wp+=snprintf(json+wp,sizeof(json)-wp,"}\n");
    httpd_resp_set_type(req,"application/json");
    return httpd_resp_send(req,json,wp);
}

/* ================= Server start/stop ================= */
esp_err_t webserver_start(){
    if (s_http) return ESP_OK;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 16;
    ESP_ERROR_CHECK(httpd_start(&s_http, &cfg));

    ble_register_notify_cb(on_ble_notify);

    httpd_uri_t u{};

    u.method=HTTP_GET;
    u.uri="/login";            u.handler=login_get;        httpd_register_uri_handler(s_http,&u);
    u.uri="/diag";             u.handler=diag_get;         httpd_register_uri_handler(s_http,&u);
    u.uri="/ble-data";         u.handler=ble_get;          httpd_register_uri_handler(s_http,&u);
    u.uri="/admin";            u.handler=admin_get;        httpd_register_uri_handler(s_http,&u);
    u.uri="/super_user.html";  u.handler=super_user_get;   httpd_register_uri_handler(s_http,&u);

    u.uri="/api/status";       u.handler=api_status_get;   httpd_register_uri_handler(s_http,&u);

    httpd_uri_t dwm_get{};  dwm_get.method=HTTP_GET;  dwm_get.uri="/api/dwm_get";  dwm_get.handler=api_dwm_get;
    httpd_register_uri_handler(s_http,&dwm_get);

    httpd_uri_t get_cfg{};  get_cfg.method=HTTP_GET;  get_cfg.uri="/api/config";   get_cfg.handler=api_config_get;
    httpd_register_uri_handler(s_http,&get_cfg);

    httpd_uri_t post_cfg{}; post_cfg.method=HTTP_POST; post_cfg.uri="/api/config"; post_cfg.handler=api_config_post;
    httpd_register_uri_handler(s_http,&post_cfg);

    httpd_uri_t auth{};     auth.method=HTTP_POST;    auth.uri="/auth/login";     auth.handler=auth_login_post;
    httpd_register_uri_handler(s_http,&auth);

    // Root és catch-all → login
    httpd_uri_t root{}; root.method=HTTP_GET; root.uri="/";  root.handler=login_get; httpd_register_uri_handler(s_http,&root);
    httpd_uri_t any{};  any .method=HTTP_GET; any .uri="/*"; any .handler=login_get; httpd_register_uri_handler(s_http,&any);

    ESP_LOGI(TAG,"webserver started");
    return ESP_OK;
}
esp_err_t webserver_stop(){
    if(!s_http) return ESP_OK;
    httpd_stop(s_http); s_http=NULL; return ESP_OK;
}
