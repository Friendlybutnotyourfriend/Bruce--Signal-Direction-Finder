#include "ble_solo_df.h"

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_common.h"
#include <globals.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <string>
#include <vector>

namespace {

constexpr uint32_t DISCOVERY_TIME_MS = 5000;
constexpr uint32_t LOST_TARGET_MS = 3000;
constexpr size_t MEDIAN_WINDOW_SIZE = 7;

struct BleDfTarget {
    String name;
    String address;
    int rssi = -127;
};

struct TrackerState {
    int rawRssi = -127;
    float fastRssi = -127.0f;
    float stableRssi = -127.0f;
    float bestRssi = -127.0f;
    float trend = 0.0f;
    float jitter = 0.0f;
    uint32_t samples = 0;
    uint32_t lastSeenMs = 0;
    bool initialized = false;
};

class MedianWindow {
public:
    void reset() {
        _values.fill(-127);
        _count = 0;
        _index = 0;
    }

    void add(int value) {
        _values[_index] = value;
        _index = (_index + 1) % MEDIAN_WINDOW_SIZE;
        if (_count < MEDIAN_WINDOW_SIZE) _count++;
    }

    float median() const {
        if (_count == 0) return -127.0f;

        std::array<int, MEDIAN_WINDOW_SIZE> sorted = _values;
        std::sort(sorted.begin(), sorted.begin() + _count);

        if (_count % 2 == 1) return static_cast<float>(sorted[_count / 2]);
        return (sorted[_count / 2 - 1] + sorted[_count / 2]) / 2.0f;
    }

private:
    std::array<int, MEDIAN_WINDOW_SIZE> _values{};
    size_t _count = 0;
    size_t _index = 0;
};

portMUX_TYPE trackerMux = portMUX_INITIALIZER_UNLOCKED;
TrackerState trackerState;
MedianWindow medianWindow;
std::string trackedAddress;

void resetTrackerState() {
    portENTER_CRITICAL(&trackerMux);
    trackerState = TrackerState{};
    portEXIT_CRITICAL(&trackerMux);
    medianWindow.reset();
}

TrackerState getTrackerSnapshot() {
    TrackerState snapshot;
    portENTER_CRITICAL(&trackerMux);
    snapshot = trackerState;
    portEXIT_CRITICAL(&trackerMux);
    return snapshot;
}

void resetPeak() {
    portENTER_CRITICAL(&trackerMux);
    if (trackerState.initialized) {
        trackerState.bestRssi = trackerState.stableRssi;
        trackerState.fastRssi = trackerState.stableRssi;
        trackerState.trend = 0.0f;
    }
    portEXIT_CRITICAL(&trackerMux);
}

class BleDfScanCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *advertisedDevice) override {
        if (advertisedDevice == nullptr) return;
        if (advertisedDevice->getAddress().toString() != trackedAddress) return;

        const int rawRssi = advertisedDevice->getRSSI();
        medianWindow.add(rawRssi);
        const float medianRssi = medianWindow.median();

        portENTER_CRITICAL(&trackerMux);
        if (!trackerState.initialized) {
            trackerState.rawRssi = rawRssi;
            trackerState.fastRssi = medianRssi;
            trackerState.stableRssi = medianRssi;
            trackerState.bestRssi = medianRssi;
            trackerState.trend = 0.0f;
            trackerState.jitter = 0.0f;
            trackerState.samples = 1;
            trackerState.lastSeenMs = millis();
            trackerState.initialized = true;
            portEXIT_CRITICAL(&trackerMux);
            return;
        }

        constexpr float FAST_ALPHA = 0.45f;
        constexpr float STABLE_ALPHA = 0.14f;
        constexpr float JITTER_ALPHA = 0.18f;

        trackerState.rawRssi = rawRssi;
        trackerState.fastRssi += FAST_ALPHA * (medianRssi - trackerState.fastRssi);
        trackerState.stableRssi += STABLE_ALPHA * (medianRssi - trackerState.stableRssi);
        trackerState.trend = trackerState.fastRssi - trackerState.stableRssi;
        trackerState.jitter +=
            JITTER_ALPHA * (fabsf(static_cast<float>(rawRssi) - trackerState.fastRssi) - trackerState.jitter);
        trackerState.bestRssi = std::max(trackerState.bestRssi, trackerState.stableRssi);
        trackerState.samples++;
        trackerState.lastSeenMs = millis();
        portEXIT_CRITICAL(&trackerMux);
    }
};

BleDfScanCallbacks bleDfCallbacks;

int signalBarPixels(float rssi, int width) {
    const float bounded = std::max(-100.0f, std::min(-35.0f, rssi));
    return static_cast<int>(((bounded + 100.0f) / 65.0f) * width);
}

String trendLabel(const TrackerState &state) {
    if (!state.initialized) return "SEARCHING";
    if (millis() - state.lastSeenMs > LOST_TARGET_MS) return "TARGET LOST";
    if (state.trend >= 3.0f) return "WARMER";
    if (state.trend <= -3.0f) return "COLDER";
    return "STEADY";
}

uint16_t trendColor(const TrackerState &state) {
    if (!state.initialized || millis() - state.lastSeenMs > LOST_TARGET_MS) return TFT_RED;
    if (state.trend >= 3.0f) return TFT_GREEN;
    if (state.trend <= -3.0f) return TFT_ORANGE;
    return bruceConfig.priColor;
}

int confidenceScore(const TrackerState &state) {
    if (!state.initialized) return 0;

    int score = std::min(75, static_cast<int>(state.samples * 3));
    score += std::max(0, 20 - static_cast<int>(state.jitter * 4.0f));

    const uint32_t age = millis() - state.lastSeenMs;
    if (age > 500) score -= static_cast<int>((age - 500) / 75);

    return std::max(0, std::min(100, score));
}

String compactTargetLabel(const BleDfTarget &target) {
    String label = target.name;
    if (label.isEmpty()) label = target.address;

    const int maxChars = std::max(10, (tftWidth / (LW * FM)) - 8);
    if (label.length() > static_cast<unsigned int>(maxChars)) label = label.substring(0, maxChars - 1) + "~";
    return label;
}

void drawTrackerScreen(const BleDfTarget &target, const TrackerState &state) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.drawCentreString("BLE SOLO DF", tftWidth / 2, 29, 1);

    const String targetLabel = compactTargetLabel(target);
    tft.drawCentreString(targetLabel, tftWidth / 2, 44, 1);

    const int raw = state.initialized ? state.rawRssi : -127;
    const int stable = state.initialized ? static_cast<int>(roundf(state.stableRssi)) : -127;
    const int best = state.initialized ? static_cast<int>(roundf(state.bestRssi)) : -127;

    tft.setTextSize(FM);
    tft.drawString("RAW " + String(raw), 13, 61, 1);
    tft.drawCentreString("AVG " + String(stable), tftWidth / 2, 61, 1);
    tft.drawRightString("BEST " + String(best), tftWidth - 13, 61, 1);

    const int barX = 14;
    const int barY = 84;
    const int barW = tftWidth - 28;
    const int barH = 18;
    tft.drawRect(barX, barY, barW, barH, bruceConfig.priColor);

    if (state.initialized) {
        const int fillW = std::max(0, std::min(barW - 4, signalBarPixels(state.stableRssi, barW - 4)));
        if (fillW > 0) tft.fillRect(barX + 2, barY + 2, fillW, barH - 4, trendColor(state));
    }

    tft.setTextSize(FM);
    tft.setTextColor(trendColor(state), bruceConfig.bgColor);
    tft.drawCentreString(trendLabel(state), tftWidth / 2, 108, 1);

    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    const String stats = "d " + String(state.trend, 1) + "  conf " + String(confidenceScore(state)) +
                         "%  n " + String(state.samples);
    tft.drawCentreString(stats, tftWidth / 2, 130, 1);

    const String footer = String(BTN_ALIAS) + " reset peak   Esc back";
    tft.drawCentreString(footer, tftWidth / 2, tftHeight - 14, 1);
    drawStatusBar();
}

void trackBleTarget(const BleDfTarget &target) {
    displayTextLine("Starting BLE tracker...");

    ble_scan_setup();
    if (pBLEScan == nullptr) {
        displayError("BLE scanner unavailable", true);
        return;
    }

    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&bleDfCallbacks, true);

    trackedAddress = target.address.c_str();
    resetTrackerState();

    if (!pBLEScan->start(0, false, true)) {
        pBLEScan->setScanCallbacks(nullptr, false);
        pBLEScan->setMaxResults(0xFF);
        displayError("Unable to start BLE scan", true);
        stopBLEStack();
        return;
    }

    uint32_t lastDrawMs = 0;
    while (!check(EscPress)) {
        if (check(SelPress)) resetPeak();

        const uint32_t now = millis();
        if (now - lastDrawMs >= 120) {
            drawTrackerScreen(target, getTrackerSnapshot());
            lastDrawMs = now;
        }
        delay(10);
    }

    if (pBLEScan != nullptr) {
        pBLEScan->stop();
        pBLEScan->setScanCallbacks(nullptr, false);
        pBLEScan->setMaxResults(0xFF);
        pBLEScan->clearResults();
    }
    stopBLEStack();
}

std::vector<BleDfTarget> discoverBleTargets() {
    std::vector<BleDfTarget> targets;

    displayTextLine("Scanning BLE targets...");
    ble_scan_setup();
    if (pBLEScan == nullptr) return targets;

    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setMaxResults(80);
    pBLEScan->setActiveScan(true);

    BLEScanResults foundDevices = pBLEScan->getResults(DISCOVERY_TIME_MS, false);
    targets.reserve(foundDevices.getCount());

    for (int i = 0; i < foundDevices.getCount(); i++) {
        const NimBLEAdvertisedDevice *device = foundDevices.getDevice(i);
        if (device == nullptr) continue;

        BleDfTarget target;
        target.name = device->getName().c_str();
        target.address = device->getAddress().toString().c_str();
        target.rssi = device->getRSSI();
        targets.push_back(target);
    }

    std::sort(targets.begin(), targets.end(), [](const BleDfTarget &a, const BleDfTarget &b) {
        return a.rssi > b.rssi;
    });

    pBLEScan->clearResults();
    return targets;
}

} // namespace

void bleSoloDf() {
    std::vector<BleDfTarget> targets = discoverBleTargets();

    if (targets.empty()) {
        displayWarning("No BLE advertisers found", true);
        stopBLEStack();
        return;
    }

    options.clear();
    const size_t maxTargets = std::min<size_t>(targets.size(), 60);
    for (size_t i = 0; i < maxTargets; i++) {
        const BleDfTarget target = targets[i];
        String label = target.name;
        if (label.isEmpty()) label = target.address;
        label += "  " + String(target.rssi);

        options.emplace_back(label, [target]() { trackBleTarget(target); });
    }

    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_REGULAR, "Select BLE target", 0, false);
    options.clear();
    stopBLEStack();
}
