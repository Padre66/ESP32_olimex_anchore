#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include "esp_http_server.h"
#include "esp_log.h"
#include "globals.h"
#include "mbedtls/base64.h"
#include "webserver.hpp"
#include "esp_timer.h"
#include "esp_system.h"


// prototípusok
static bool decode_basic(const char* h, std::string& u, std::string& p);
static user_role_t role_from_auth(httpd_req_t* req);
static bool require_role(httpd_req_t* req, user_role_t need);
static esp_err_t send_file(httpd_req_t* req, const char* path, const char* ctype);

static esp_err_t root_get(httpd_req_t* r);
static esp_err_t diag_get(httpd_req_t* r);
static esp_err_t ble_get (httpd_req_t* r);
static esp_err_t admin_get(httpd_req_t* r);
static esp_err_t login_get(httpd_req_t* r);

static esp_err_t super_user_get(httpd_req_t* r);
static esp_err_t api_status_get(httpd_req_t* req);
static esp_err_t api_config_get(httpd_req_t* req);
static esp_err_t api_config_post(httpd_req_t* req);

static const char* TAG = "WEB";
static httpd_handle_t s=NULL;

struct User { const char* u; const char* p; user_role_t r; };
static User users[] = {
  {"diag","diag",ROLE_DIAG},
  {"admin","admin",ROLE_BLE},
  {"root","root",ROLE_ROOT},
  {nullptr,nullptr,ROLE_NONE}
};
static const char* uri_for_role(user_role_t r){
  switch(r){
    case ROLE_ROOT: return "/admin";
    case ROLE_BLE:  return "/super_user.html";  // táblázatos ESP+DWM UI
    case ROLE_DIAG: return "/diag";
    default:        return "/login";
  }
}
struct Session { char sid[33]; user_role_t role; uint32_t exp_s; };
static Session g_sess[4];  // kicsi, elég
static void mk_sid(char out[33]){ for(int i=0;i<32;i++){ uint8_t b = esp_random() & 0x0F; out[i] = "0123456789abcdef"[b]; } out[32]=0; }
static user_role_t check_user(const char* u, const char* p){
  for (auto& x : users) {
    if (x.u && strcmp(u, x.u) == 0 && strcmp(p, x.p) == 0) {
      return x.r;
    }
  }
  return ROLE_NONE;
}

static user_role_t role_from_cookie(httpd_req_t* req){
  size_t n = httpd_req_get_hdr_value_len(req,"Cookie");
  if(!n) return ROLE_NONE;
  std::vector<char> ck(n+1);
  if(httpd_req_get_hdr_value_str(req,"Cookie",ck.data(),ck.size())!=ESP_OK) return ROLE_NONE;

  const char* m = strstr(ck.data(),"SID=");
  if(!m) return ROLE_NONE;
  m += 4;
  char sid[33]={0};
  int i=0;
  while(*m && *m!=';' && i<32){ sid[i++]=*m++; }

  uint32_t now = (uint32_t)(esp_timer_get_time()/1000000ULL);

  for(auto& s: g_sess){
    if(s.sid[0] && strcmp(s.sid,sid)==0 && s.exp_s>now) return s.role;
  }
  return ROLE_NONE;
}

static esp_err_t auth_login_post(httpd_req_t* req){
  int len=req->content_len; if(len<=0) return httpd_resp_send_err(req,HTTPD_400_BAD_REQUEST,"empty");
  std::vector<char> body(len+1,0);
  int off=0; while(off<len){ int r=httpd_req_recv(req,body.data()+off,len-off); if(r<=0) return httpd_resp_send_err(req,HTTPD_500_INTERNAL_SERVER_ERROR,"recv"); off+=r; }

  auto getstr=[&](const char* key)->std::string{
    const char* k=strstr(body.data(),key); if(!k) return {};
    k=strchr(k,':'); if(!k) return {}; k++;
    while(*k==' '||*k=='\"') ++k;
    const char* e=k; while(*e && *e!='\"' && *e!=',' && *e!='}') ++e;
    return std::string(k, e-k);
  };

  std::string u = getstr("\"user\"");
  std::string p = getstr("\"pass\"");
  user_role_t r = check_user(u.c_str(), p.c_str());
  if(r==ROLE_NONE) return httpd_resp_send_err(req,HTTPD_401_UNAUTHORIZED,"bad creds");

  char sid[33]; mk_sid(sid);
  uint32_t now = (uint32_t)(esp_timer_get_time()/1000000ULL);

  g_sess[0] = Session{};                 // teljes init
  strncpy(g_sess[0].sid, sid, sizeof(g_sess[0].sid));
  g_sess[0].role = r;
  g_sess[0].exp_s = now + 86400;

  std::string cookie = std::string("SID=") + sid + "; Path=/; HttpOnly; Max-Age=86400";
  httpd_resp_set_hdr(req,"Set-Cookie", cookie.c_str());

  httpd_resp_set_type(req,"application/json");
  return httpd_resp_sendstr(req,"{\"ok\":true}\n");
}


// Egyszerű, ESP-n tárolt config-tükör (a front-end kulcsneveivel)
struct EspCfg {
  uint16_t NETWORK_ID = 1;
  uint16_t ZONE_ID    = 0x5A31;   // 'Z1'
  uint32_t ANCHOR_ID  = 0x00000001;
  uint16_t HB_MS      = 10000;
  uint8_t  LOG_LEVEL  = 1;
  int32_t  TX_ANT_DLY = 0;
  int32_t  RX_ANT_DLY = 0;
  int32_t  BIAS_TICKS = 0;
  uint8_t  PHY_CH     = 9;
  uint16_t PHY_SFDTO  = 248;      // példa
} g_cfg;

static user_role_t role_from_auth(httpd_req_t* req){
  user_role_t r = role_from_cookie(req); if(r!=ROLE_NONE) return r;  // új
  size_t len=httpd_req_get_hdr_value_len(req,"Authorization");
  if(len==0) return ROLE_NONE;
  std::vector<char> auth(len+1);
  if(httpd_req_get_hdr_value_str(req,"Authorization",auth.data(),auth.size())!=ESP_OK) return ROLE_NONE;
  std::string u,p; if(!decode_basic(auth.data(),u,p)) return ROLE_NONE;
  for(auto& x: users) if(x.u && u==x.u && p==x.p) return x.r;
  return ROLE_NONE;
}


// kis helper a JSON íráshoz (hexeket 0x… formában adjuk vissza)
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
    (unsigned)c.NETWORK_ID, (unsigned)c.ZONE_ID, (unsigned)c.ANCHOR_ID,
    (unsigned)c.HB_MS, (unsigned)c.LOG_LEVEL,
    (int)c.TX_ANT_DLY, (int)c.RX_ANT_DLY, (int)c.BIAS_TICKS,
    (unsigned)c.PHY_CH, (unsigned)c.PHY_SFDTO);
}
static esp_err_t api_config_get(httpd_req_t* req)      // :contentReference[oaicite:1]{index=1}
{
  if(!require_role(req, ROLE_BLE)) return ESP_FAIL;
  char buf[256];
  json_cfg_print(buf, sizeof(buf), g_cfg);
  httpd_resp_set_type(req, "application/json");
  return httpd_resp_send(req, buf, strlen(buf));
}


// primitív JSON mező-kinyerők (\"KEY\": <number> | \"0x..\" )
static bool find_key(const char* body, const char* key, const char** val_start){
  const char* p = strstr(body, key);
  if(!p) return false;
  p = strchr(p, ':'); if(!p) return false;
  p++; while(*p==' '||*p=='\"') { if(*p=='\"'){ *val_start = p; return true; } ++p; }
  *val_start = p; return true;
}
static bool parse_u32(const char* body, const char* key, uint32_t& out){
  const char* v=nullptr; if(!find_key(body, key, &v)) return false;
  if(*v=='\"'){ // "0x...."
    char* end=nullptr; out = strtoul(v+1, &end, 16);
  }else{
    char* end=nullptr; out = strtoul(v, &end, 10);
  }
  return true;
}
static bool parse_i32(const char* body, const char* key, int32_t& out){
  const char* v=nullptr; if(!find_key(body, key, &v)) return false;
  char* end=nullptr;
  if(*v=='\"'){ out = (int32_t)strtol(v+1, &end, 16); }
  else        { out = (int32_t)strtol(v,   &end, 10); }
  return true;
}
static bool parse_u16(const char* body, const char* key, uint16_t& out){
  uint32_t tmp; if(!parse_u32(body,key,tmp)) return false; out=(uint16_t)tmp; return true;
}
static bool parse_u8 (const char* body, const char* key, uint8_t&  out){
  uint32_t tmp; if(!parse_u32(body,key,tmp)) return false; out=(uint8_t)tmp;  return true;
}

// --- új: /api/config POST
static esp_err_t api_config_post(httpd_req_t* req)
{
  if(!require_role(req, ROLE_BLE)) return ESP_FAIL;

  // body beolvasás
  int len = req->content_len; if(len<=0) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty");
  std::vector<char> body(len+1, 0);
  int off=0, rcv=0;
  while(off<len){
    rcv = httpd_req_recv(req, body.data()+off, len-off);
    if(rcv<=0) return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "recv");
    off += rcv;
  }

  // mezők részleges frissítése (csak ami benne van)
  parse_u16(body.data(), "\"NETWORK_ID\"", g_cfg.NETWORK_ID);
  parse_u16(body.data(), "\"ZONE_ID\"",    g_cfg.ZONE_ID);
  { uint32_t t; if(parse_u32(body.data(), "\"ANCHOR_ID\"", t)) g_cfg.ANCHOR_ID=t; }
  parse_u16(body.data(), "\"HB_MS\"",      g_cfg.HB_MS);
  parse_u8 (body.data(), "\"LOG_LEVEL\"",  g_cfg.LOG_LEVEL);
  parse_i32(body.data(), "\"TX_ANT_DLY\"", g_cfg.TX_ANT_DLY);
  parse_i32(body.data(), "\"RX_ANT_DLY\"", g_cfg.RX_ANT_DLY);
  parse_i32(body.data(), "\"BIAS_TICKS\"", g_cfg.BIAS_TICKS);
  parse_u8 (body.data(), "\"PHY_CH\"",     g_cfg.PHY_CH);
  parse_u16(body.data(), "\"PHY_SFDTO\"",  g_cfg.PHY_SFDTO);

  // válasz
  httpd_resp_set_type(req, "application/json");
  return httpd_resp_sendstr(req, "{\"ok\":true}\n");
}

static const char* state_str(state_t s){
    switch (s) {
        case ST_OK:   return "ok";
        case ST_WARN: return "warn";
        case ST_ERR:  return "err";
        default:      return "off";
    }
}

static esp_err_t api_status_get(httpd_req_t* req)
{
    char buf[128];
    int n = snprintf(buf, sizeof(buf),
                     "{\"anchor\":\"%s\",\"id\":%u,\"last_s\":%.2f,\"last_v\":%.2f,\"state\":\"%s\"}\n",
                     g_status.anchor, g_status.id, g_status.last_meas_s, g_status.last_volt,
                     state_str(g_status.state));
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, buf, n);
}

static bool decode_basic(const char* h, std::string& u, std::string& p){
  if(!h) return false;
  const char* pref="Basic ";
  if(strncmp(h,pref,6)!=0) return false;
  const char* b64=h+6;
  size_t olen=0;
  (void)mbedtls_base64_decode(nullptr,0,&olen,(const unsigned char*)b64,strlen(b64));
  std::vector<unsigned char> buf(olen+1);
  if(mbedtls_base64_decode(buf.data(),olen,&olen,(const unsigned char*)b64,strlen(b64))!=0) return false;
  buf[olen]=0;
  char* sep=(char*)strchr((char*)buf.data(),':'); if(!sep) return false;
  *sep=0; u.assign((char*)buf.data()); p.assign(sep+1); return true;
}
static bool require_role(httpd_req_t* req, user_role_t need){
  user_role_t r=role_from_auth(req);
  if(r<need){
    if (strncmp(req->uri,"/api/",5)==0 || strncmp(req->uri,"/auth/",6)==0){
      httpd_resp_set_status(req,"401 Unauthorized");
      httpd_resp_sendstr(req,"");
    } else {
      httpd_resp_set_status(req,"302 Found");
      httpd_resp_set_hdr(req,"Location","/login");
      httpd_resp_sendstr(req,"");
    }
    return false;
  }
  return true;
}

static esp_err_t send_file(httpd_req_t* req, const char* path, const char* ctype){
  FILE* f = fopen(path,"rb");
  if(!f){ httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"Not found"); return ESP_FAIL; }
  httpd_resp_set_type(req, ctype);
  char buf[1024];
  size_t n;
  while((n=fread(buf,1,sizeof(buf),f))>0){
    if(httpd_resp_send_chunk(req, buf, n)!=ESP_OK){ fclose(f); httpd_resp_sendstr_chunk(req, NULL); return ESP_FAIL; }
  }
  fclose(f);
  httpd_resp_sendstr_chunk(req, NULL);
  return ESP_OK;
}

// --- root_get: teljes csere ---
static esp_err_t root_get(httpd_req_t* req)
{
  // ha már van Basic Auth, küldd a szerephez illő oldalra
  user_role_t cur = role_from_auth(req);
  if (cur != ROLE_NONE) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", uri_for_role(cur));
    return httpd_resp_sendstr(req, "");
  }

  // közvetlen védett HTML kérés esetén is tereld loginra
  if (strcmp(req->uri, "/super_user.html") == 0 ||
      strcmp(req->uri, "/admin") == 0 ||
      strcmp(req->uri, "/diag") == 0) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/login");
    return httpd_resp_sendstr(req, "");
  }

  // statikus fájlok kiszolgálása
  char path[256];
  const char* prefix = "/spiffs";
  if (strcmp(req->uri, "/") == 0) {
    snprintf(path, sizeof(path), "%s/login.html", prefix);
  } else {
    size_t pre_len = strlen(prefix);
    size_t uri_len = strlen(req->uri);
    if (pre_len + uri_len >= sizeof(path)) {
      return httpd_resp_send_err(req, HTTPD_414_URI_TOO_LONG, "URI too long");
    }
    memcpy(path, prefix, pre_len);
    memcpy(path + pre_len, req->uri, uri_len);
    path[pre_len + uri_len] = '\0';
  }

  FILE* f = fopen(path, "rb");
  if (!f) {
    httpd_resp_set_status(req, "404 Not Found");
    return httpd_resp_sendstr(req, "Not found");
  }

  const char* ct = "text/plain";
  const char* ext = strrchr(path, '.');
  if (ext) {
    if (!strcmp(ext, ".html")) ct = "text/html";
    else if (!strcmp(ext, ".css")) ct = "text/css";
    else if (!strcmp(ext, ".js")) ct = "application/javascript";
    else if (!strcmp(ext, ".png")) ct = "image/png";
    else if (!strcmp(ext, ".jpg") || !strcmp(ext, ".jpeg")) ct = "image/jpeg";
    else if (!strcmp(ext, ".svg")) ct = "image/svg+xml";
  }
  httpd_resp_set_type(req, ct);

  char buf[1024]; size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    if (httpd_resp_send_chunk(req, buf, n) != ESP_OK) {
      fclose(f);
      httpd_resp_send_chunk(req, NULL, 0);
      return ESP_FAIL;
    }
  }
  fclose(f);
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}


static esp_err_t super_user_get(httpd_req_t* r){
  if(!require_role(r, ROLE_BLE)) return ESP_FAIL;
  return send_file(r, "/spiffs/super_user.html", "text/html");
}

static esp_err_t diag_get(httpd_req_t* r){
  if(!require_role(r, ROLE_DIAG)) return ESP_FAIL;
  return send_file(r, "/spiffs/diag.html", "text/html");
}

static esp_err_t ble_get(httpd_req_t* r){
  if(!require_role(r, ROLE_BLE)) return ESP_FAIL;
  return send_file(r, "/spiffs/ble.html", "text/html");
}

static esp_err_t admin_get(httpd_req_t* r){
  if(!require_role(r, ROLE_ROOT)) return ESP_FAIL;
  return send_file(r, "/spiffs/admin.html", "text/html");
}


static esp_err_t login_get(httpd_req_t *req) {
    return send_file(req, "/spiffs/login.html", "text/html");
}

esp_err_t webserver_start()
{
    if (s) return ESP_OK;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.uri_match_fn = httpd_uri_match_wildcard;
    cfg.max_uri_handlers = 16;
    ESP_ERROR_CHECK(httpd_start(&s, &cfg));

    httpd_uri_t u{};

    // ---- SPECIFIKUS OLDALAK (előbb)
    u.method = HTTP_GET;

    u.uri = "/login";      u.handler = login_get;       httpd_register_uri_handler(s, &u);
    u.uri = "/diag";       u.handler = diag_get;        httpd_register_uri_handler(s, &u);
    u.uri = "/ble-data";   u.handler = ble_get;         httpd_register_uri_handler(s, &u);
    u.uri = "/admin";      u.handler = admin_get;       httpd_register_uri_handler(s, &u);
    u.uri = "/super_user.html"; u.handler = super_user_get;  httpd_register_uri_handler(s, &u);

    // ---- API-k
    u.uri = "/api/status"; u.handler = api_status_get;  httpd_register_uri_handler(s, &u);

    httpd_uri_t auth{};
    auth.method = HTTP_POST; auth.uri="/auth/login"; auth.handler=auth_login_post;
    httpd_register_uri_handler(s,&auth);

    httpd_uri_t get_cfg{};
    get_cfg.method = HTTP_GET;
    get_cfg.uri = "/api/config";
    get_cfg.handler = api_config_get;
    httpd_register_uri_handler(s, &get_cfg);

    httpd_uri_t post_cfg{};
    post_cfg.method = HTTP_POST;
    post_cfg.uri = "/api/config";
    post_cfg.handler = api_config_post;
    httpd_register_uri_handler(s, &post_cfg);

    // ---- ROOT "/" külön, mert "/*" nem illeszkedik rá
    httpd_uri_t u_root{};
    u_root.method  = HTTP_GET;
    u_root.uri     = "/";
    u_root.handler = root_get;
    httpd_register_uri_handler(s, &u_root);

    // ---- CATCH-ALL VÉGÜL
    httpd_uri_t w{};
    w.method = HTTP_GET;
    w.uri = "/*";
    w.handler = root_get;
    httpd_register_uri_handler(s, &w);

    ESP_LOGI(TAG, "webserver started");
    return ESP_OK;
}


esp_err_t webserver_stop()
{
    if (!s) return ESP_OK;
    httpd_stop(s);
    s = NULL;
    return ESP_OK;
}
