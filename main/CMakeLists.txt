idf_component_register(
    SRCS "main.c" "globals.c"
    INCLUDE_DIRS "."
    REQUIRES webserver ble ethernet nvs_flash esp_netif esp_event
)
