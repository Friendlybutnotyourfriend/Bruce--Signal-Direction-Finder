#include <cassert>
#include <cstdio>
#include <esp_bt.h>
#include "core/radio_mem.h"

FakeWifi WiFi;
FakeSerial Serial;
bool wifiConnected = false;
static size_t largest;
static size_t classicGain;
static size_t wifiGain;
static unsigned releaseCalls;
static unsigned disconnectCalls;
static esp_bt_controller_status_t controller;

size_t heap_caps_get_largest_free_block(unsigned caps) {
    assert(caps == MALLOC_CAP_DMA);
    return largest;
}

esp_bt_controller_status_t esp_bt_controller_get_status() { return controller; }

esp_err_t esp_bt_controller_mem_release(esp_bt_mode_t mode) {
    assert(controller == ESP_BT_CONTROLLER_STATUS_IDLE);
    assert(mode == ESP_BT_MODE_CLASSIC_BT); // Releasing BLE would prevent the next scan.
    ++releaseCalls;
    if (classicGain == 0) return ESP_ERR_NOT_FOUND;
    largest += classicGain;
    classicGain = 0;
    return ESP_OK;
}

void wifiDisconnect() {
    ++disconnectCalls;
    largest += wifiGain;
    WiFi.currentMode = WIFI_MODE_NULL;
    wifiConnected = false;
}

static void reset(size_t bytes) {
    largest = bytes;
    classicGain = wifiGain = 0;
    releaseCalls = disconnectCalls = 0;
    controller = ESP_BT_CONTROLLER_STATUS_IDLE;
    WiFi.currentMode = WIFI_MODE_NULL;
    wifiConnected = false;
}

int main() {
    static_assert(RADIO_BLE_MIN_DMA_BLOCK == 48 * 1024, "Keep the BLE safety margin");
    static_assert(RADIO_WIFI_MIN_DMA_BLOCK == 15 * 1024, "Keep the Wi-Fi safety margin");

    reset(32 * 1024);
    classicGain = 17 * 1024;
#if defined(FENRIR_EBYTE) && defined(CONFIG_IDF_TARGET_ESP32)
    assert(radioHasMemForBle());
    assert(releaseCalls == 1);
    // NimBLE and subsequent scans may repeat an already-completed release.
    assert(radioHasMemForBle());
    assert(largest == 49 * 1024);
#else
    assert(!radioHasMemForBle());
    assert(releaseCalls == 0);
#endif

    reset(32 * 1024);
    assert(!radioHasMemForBle()); // No reclaimable memory: still refuse safely.

    reset(64 * 1024);
    controller = ESP_BT_CONTROLLER_STATUS_ENABLED;
    assert(radioHasMemForBle());
    assert(releaseCalls == 0);

    reset(32 * 1024);
    controller = ESP_BT_CONTROLLER_STATUS_INITED;
    assert(!radioHasMemForBle());
    assert(releaseCalls == 0);

    reset(32 * 1024);
    WiFi.currentMode = 1;
    wifiGain = 16 * 1024;
    assert(radioHasMemForBle());
    assert(disconnectCalls == 1);

    reset(16 * 1024);
    assert(radioHasMemForWifi());
    assert(releaseCalls == 0);
    std::puts("Radio memory regressions passed");
}
