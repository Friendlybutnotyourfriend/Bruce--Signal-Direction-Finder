#pragma once
using esp_err_t = int;
constexpr esp_err_t ESP_OK = 0;
constexpr esp_err_t ESP_ERR_NOT_FOUND = 0x105;
enum esp_bt_controller_status_t {
    ESP_BT_CONTROLLER_STATUS_IDLE,
    ESP_BT_CONTROLLER_STATUS_INITED,
    ESP_BT_CONTROLLER_STATUS_ENABLED
};
enum esp_bt_mode_t { ESP_BT_MODE_BLE = 1, ESP_BT_MODE_CLASSIC_BT = 2, ESP_BT_MODE_BTDM = 3 };
esp_bt_controller_status_t esp_bt_controller_get_status();
esp_err_t esp_bt_controller_mem_release(esp_bt_mode_t mode);
