#include "antenna_id.h"

#include "core/display.h"
#include "core/settings.h"
#include "core/wifi/wifi_common.h"
#include "globals.h"
#include "modules/ble/ble_common.h"

#include <NimBLEDevice.h>
#include <WiFi.h>
#include <algorithm>

namespace {

constexpr uint8_t WIFI_PASSES = 3;
constexpr uint8_t BLE_PASSES = 3;
constexpr uint8_t WIFI_CHANNELS = 13;
constexpr uint8_t WIFI_GROUPS = 3;
constexpr uint8_t MAX_IDENTITIES = 64;
constexpr uint32_t BLE_SCAN_MS = 4000;
constexpr int RSSI_FLOOR = -105;
constexpr int MIN_WIFI_RSSI = -95;
constexpr int MIN_BLE_RSSI = -95;

struct WifiGroupDefinition {
    const char *label;
    uint8_t firstChannel;
    uint8_t lastChannel;
};

constexpr WifiGroupDefinition WIFI_GROUP_DEFS[WIFI_GROUPS] = {
    {"LOW  1-4",  1,  4},
    {"MID  5-9",  5,  9},
    {"HIGH 10-13", 10, 13},
};

struct WifiGroupResult {
    int peakRssi = RSSI_FLOOR;
    uint8_t peakChannel = 0;
    uint8_t passesSeen = 0;
    uint16_t observations = 0;
};

struct WifiResult {
    WifiGroupResult groups[WIFI_GROUPS];
    int peakRssi = RSSI_FLOOR;
    uint8_t peakChannel = 0;
    uint8_t passesSeen = 0;
    uint8_t uniqueNetworks = 0;
    uint16_t observations = 0;
    int score = 0;
    bool evidence = false;
};

struct BleResult {
    int peakRssi = RSSI_FLOOR;
    int medianRssi = RSSI_FLOOR;
    uint8_t passesSeen = 0;
    uint8_t uniqueDevices = 0;
    uint16_t observations = 0;
    int score = 0;
    bool evidence = false;
};

int clampInt(int value, int lower, int upper) {
    if (value < lower) return lower;
    if (value > upper) return upper;
    return value;
}

int median(int *values, uint8_t count) {
    std::sort(values, values + count);
    return values[count / 2];
}

bool escapePressed() { return check(EscPress); }

void drawHeader(const char *subtitle) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(1);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString("MAKO ANTENNA ID", 4, 3);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString(subtitle, 4, 16);
}

bool waitForStart() {
    drawHeader("ESP32-S3 2.4 GHz survey");
    tft.setTextColor(TFT_LIGHTGREY, bruceConfig.bgColor);
    tft.drawString("Uses ESP32 WiFi/BLE antenna path", 4, 34);
    tft.drawString("T-Embed: attach to S3 U.FL path", 4, 47);
    tft.drawString("WiFi connection will be closed", 4, 60);
    tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
    tft.drawString("Not the CC1101 SMA - not SWR", 4, 78);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString("SEL: start     ESC: back", 4, tftHeight - 13);

    while (true) {
        if (escapePressed()) return false;
        if (check(SelPress)) return true;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

void drawProgress(const char *radio, uint8_t pass, const char *detail) {
    drawHeader("ESP32-S3 2.4 GHz survey");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Radio: " + String(radio), 4, 36);
    tft.drawString("Pass: " + String(pass + 1) + " / 3", 4, 52);
    tft.drawString(detail, 4, 68);

    const int totalSteps = WIFI_PASSES + BLE_PASSES;
    const int completed = String(radio) == "WiFi" ? pass : WIFI_PASSES + pass;
    const int width = tftWidth - 8;
    const int fillWidth = completed * width / totalSteps;
    tft.drawRect(4, tftHeight - 26, width, 9, TFT_DARKGREY);
    if (fillWidth > 2) tft.fillRect(5, tftHeight - 25, fillWidth - 2, 7, bruceConfig.priColor);
}

uint64_t bssidKey(const uint8_t *bssid) {
    if (!bssid) return 0;
    uint64_t key = 0;
    for (uint8_t i = 0; i < 6; i++) key = (key << 8) | bssid[i];
    return key;
}

bool addUniqueBssid(uint64_t key, uint64_t identities[MAX_IDENTITIES], uint8_t &count) {
    if (key == 0) return false;
    for (uint8_t i = 0; i < count; i++) {
        if (identities[i] == key) return false;
    }
    if (count >= MAX_IDENTITIES) return false;
    identities[count++] = key;
    return true;
}

bool addUniqueAddress(const String &address, String identities[MAX_IDENTITIES], uint8_t &count) {
    for (uint8_t i = 0; i < count; i++) {
        if (identities[i] == address) return false;
    }
    if (count >= MAX_IDENTITIES) return false;
    identities[count++] = address;
    return true;
}

uint16_t channelFrequency(uint8_t channel) {
    return 2407 + channel * 5;
}

WifiResult runWifiSurvey() {
    WifiResult result;
    int passPeak[WIFI_PASSES][WIFI_CHANNELS + 1];
    uint16_t channelObservations[WIFI_CHANNELS + 1] = {};
    uint64_t identities[MAX_IDENTITIES] = {};
    uint8_t identityCount = 0;

    for (uint8_t pass = 0; pass < WIFI_PASSES; pass++) {
        for (uint8_t channel = 0; channel <= WIFI_CHANNELS; channel++) {
            passPeak[pass][channel] = RSSI_FLOOR;
        }
    }

    stopBLEStack();
    ensureWifiPlatform();
    if (WiFi.isConnected()) WiFi.disconnect(false, false);
    WiFi.mode(WIFI_STA);
    vTaskDelay(pdMS_TO_TICKS(100));

    for (uint8_t pass = 0; pass < WIFI_PASSES; pass++) {
        if (escapePressed()) break;
        drawProgress("WiFi", pass, "Scanning channels 1-13");

        const int networkCount = WiFi.scanNetworks(false, true);
        for (int i = 0; i < networkCount; i++) {
            const int channel = WiFi.channel(i);
            if (channel < 1 || channel > WIFI_CHANNELS) continue;

            const int rssi = WiFi.RSSI(i);
            if (rssi > passPeak[pass][channel]) passPeak[pass][channel] = rssi;
            channelObservations[channel]++;
            result.observations++;
            addUniqueBssid(bssidKey(WiFi.BSSID(i)), identities, identityCount);
        }
        WiFi.scanDelete();
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    result.uniqueNetworks = identityCount;
    for (uint8_t groupIndex = 0; groupIndex < WIFI_GROUPS; groupIndex++) {
        const WifiGroupDefinition &definition = WIFI_GROUP_DEFS[groupIndex];
        WifiGroupResult &group = result.groups[groupIndex];

        for (uint8_t channel = definition.firstChannel; channel <= definition.lastChannel; channel++) {
            int values[WIFI_PASSES];
            uint8_t passesSeen = 0;
            for (uint8_t pass = 0; pass < WIFI_PASSES; pass++) {
                values[pass] = passPeak[pass][channel];
                if (values[pass] > RSSI_FLOOR) passesSeen++;
            }
            const int channelPeak = median(values, WIFI_PASSES);
            if (channelPeak > group.peakRssi) {
                group.peakRssi = channelPeak;
                group.peakChannel = channel;
                group.passesSeen = passesSeen;
            }
            group.observations += channelObservations[channel];
        }

        if (group.peakRssi > result.peakRssi) {
            result.peakRssi = group.peakRssi;
            result.peakChannel = group.peakChannel;
            result.passesSeen = group.passesSeen;
        }
    }

    const int strength = clampInt(result.peakRssi - RSSI_FLOOR, 0, 60);
    result.score = clampInt(strength + result.uniqueNetworks * 4 + result.passesSeen * 8, 0, 100);
    result.evidence =
        result.peakRssi >= MIN_WIFI_RSSI && result.passesSeen >= 2 && result.uniqueNetworks > 0;

    wifiDisconnect();
    return result;
}

BleResult runBleSurvey() {
    BleResult result;
    int passPeak[BLE_PASSES];
    int passMedian[BLE_PASSES];
    String identities[MAX_IDENTITIES];
    uint8_t identityCount = 0;

    for (uint8_t pass = 0; pass < BLE_PASSES; pass++) {
        passPeak[pass] = RSSI_FLOOR;
        passMedian[pass] = RSSI_FLOOR;
    }

    wifiDisconnect();
    stopBLEStack();
    NimBLEDevice::init("Mako-Antenna-ID");
    NimBLEScan *scanner = NimBLEDevice::getScan();
    scanner->setActiveScan(false);
    scanner->setInterval(160);
    scanner->setWindow(120);

    for (uint8_t pass = 0; pass < BLE_PASSES; pass++) {
        if (escapePressed()) break;
        drawProgress("BLE", pass, "Passive advertisement scan");

        NimBLEScanResults devices = scanner->getResults(BLE_SCAN_MS, false);
        int rssiValues[MAX_IDENTITIES];
        uint8_t rssiCount = 0;

        for (int i = 0; i < devices.getCount(); i++) {
            const NimBLEAdvertisedDevice *device = devices.getDevice(i);
            if (!device) continue;

            const int rssi = device->getRSSI();
            if (rssi > passPeak[pass]) passPeak[pass] = rssi;
            if (rssiCount < MAX_IDENTITIES) rssiValues[rssiCount++] = rssi;
            result.observations++;
            addUniqueAddress(device->getAddress().toString().c_str(), identities, identityCount);
        }

        if (rssiCount > 0) {
            passMedian[pass] = median(rssiValues, rssiCount);
            result.passesSeen++;
        }
        scanner->clearResults();
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    result.uniqueDevices = identityCount;
    result.peakRssi = median(passPeak, BLE_PASSES);
    result.medianRssi = median(passMedian, BLE_PASSES);

    const int strength = clampInt(result.peakRssi - RSSI_FLOOR, 0, 60);
    result.score = clampInt(strength + result.uniqueDevices * 3 + result.passesSeen * 8, 0, 100);
    result.evidence =
        result.peakRssi >= MIN_BLE_RSSI && result.passesSeen >= 2 && result.uniqueDevices > 0;

    scanner->stop();
    scanner->clearResults();
    NimBLEDevice::deinit(true);
    BLEConnected = false;
    return result;
}

uint16_t resultColor(bool evidence, int score) {
    if (!evidence) return TFT_DARKGREY;
    if (score >= 70) return TFT_GREEN;
    if (score >= 40) return TFT_YELLOW;
    return TFT_ORANGE;
}

void drawWifiGroup(const WifiGroupDefinition &definition, const WifiGroupResult &result, int y) {
    tft.setTextColor(result.peakChannel ? TFT_WHITE : TFT_DARKGREY, bruceConfig.bgColor);
    tft.drawString(definition.label, 4, y);

    String detail = "no repeatable AP";
    if (result.peakChannel) {
        detail = "ch" + String(result.peakChannel) + " " + String(result.peakRssi) + "dBm";
        detail += " x" + String(result.passesSeen);
    }
    tft.drawString(detail, 96, y);
}

void drawResults(const WifiResult &wifi, const BleResult &ble) {
    drawHeader("ESP32-S3 2.4 GHz result");

    String classification;
    if (wifi.evidence && ble.evidence) classification = "2.4G RESPONSE: WIFI + BLE";
    else if (wifi.evidence) classification = "2.4G RESPONSE: WIFI";
    else if (ble.evidence) classification = "2.4G RESPONSE: BLE";
    else classification = "INCONCLUSIVE - LOW 2.4G EVIDENCE";

    tft.setTextColor((wifi.evidence || ble.evidence) ? TFT_WHITE : TFT_YELLOW, bruceConfig.bgColor);
    tft.drawString(classification, 4, 31);

    for (uint8_t i = 0; i < WIFI_GROUPS; i++) {
        drawWifiGroup(WIFI_GROUP_DEFS[i], wifi.groups[i], 50 + i * 17);
    }

    tft.setTextColor(resultColor(wifi.evidence, wifi.score), bruceConfig.bgColor);
    String wifiLine = "WiFi " + String(wifi.uniqueNetworks) + " IDs " + String(wifi.score) + "%";
    if (wifi.peakChannel) {
        wifiLine += " peak " + String(channelFrequency(wifi.peakChannel)) + "MHz";
    }
    tft.drawString(wifiLine, 4, 104);

    tft.setTextColor(resultColor(ble.evidence, ble.score), bruceConfig.bgColor);
    const String bleLine =
        "BLE " + String(ble.uniqueDevices) + " IDs " + String(ble.peakRssi) + "dBm " + String(ble.score) + "%";
    tft.drawString(bleLine, 4, 119);

    tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
    tft.drawString("Ambient response - AP layout affects result", 4, 136);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString("SEL: rescan     ESC: back", 4, tftHeight - 13);
}

void printResults(const WifiResult &wifi, const BleResult &ble) {
    Serial.println("[ANTENNA_ID_24] wifi_group,peak_channel,peak_mhz,peak_dbm,passes,observations");
    for (uint8_t i = 0; i < WIFI_GROUPS; i++) {
        const WifiGroupResult &group = wifi.groups[i];
        Serial.printf(
            "[ANTENNA_ID_24] %s,%u,%u,%d,%u,%u\n",
            WIFI_GROUP_DEFS[i].label,
            group.peakChannel,
            group.peakChannel ? channelFrequency(group.peakChannel) : 0,
            group.peakRssi,
            group.passesSeen,
            group.observations
        );
    }
    Serial.printf(
        "[ANTENNA_ID_24] wifi_summary,%u,%u,%d,%u,%u,%u,%d,%s\n",
        wifi.peakChannel,
        wifi.peakChannel ? channelFrequency(wifi.peakChannel) : 0,
        wifi.peakRssi,
        wifi.passesSeen,
        wifi.observations,
        wifi.uniqueNetworks,
        wifi.score,
        wifi.evidence ? "yes" : "no"
    );
    Serial.printf(
        "[ANTENNA_ID_24] ble_summary,%d,%d,%u,%u,%u,%d,%s\n",
        ble.peakRssi,
        ble.medianRssi,
        ble.passesSeen,
        ble.observations,
        ble.uniqueDevices,
        ble.score,
        ble.evidence ? "yes" : "no"
    );
}

} // namespace

void rf_antenna_id_24ghz() {
#if !defined(LITE_VERSION)
    if (!waitForStart()) return;

    while (true) {
        const WifiResult wifi = runWifiSurvey();
        if (escapePressed()) {
            wifiDisconnect();
            return;
        }

        const BleResult ble = runBleSurvey();
        if (escapePressed()) return;

        printResults(wifi, ble);
        drawResults(wifi, ble);

        while (true) {
            if (escapePressed()) return;
            if (check(SelPress)) break;
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }
#else
    displayError("Not available on Launcher version", true);
#endif
}
