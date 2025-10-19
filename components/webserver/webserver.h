#pragma once
#include "esp_err.h"

typedef enum {
    ROLE_NONE = 0,
    ROLE_DIAG = 1,
    ROLE_BLE  = 2,
    ROLE_ROOT = 3
} user_role_t;

esp_err_t webserver_start(void);
esp_err_t webserver_stop(void);

/* segédfüggvény a szerep lekérdezéséhez (pl. main vagy BLE hívhatja) */
user_role_t webserver_role_from_basic_auth(const char* auth_header);
