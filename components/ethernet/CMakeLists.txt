idf_component_register(
    SRCS "ethernet.c"
    INCLUDE_DIRS "."
    REQUIRES esp_eth esp_netif nvs_flash driver esp_event log freertos
    PRIV_REQUIRES main
)
