#include "antenna_id.h"

#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "globals.h"
#include "rf_utils.h"

#include <algorithm>

namespace {

constexpr uint8_t PASSES = 3;
constexpr uint8_t SAMPLES_PER_POINT = 5;
constexpr uint16_t SETTLE_MS = 8;
constexpr int RSSI_MIN = -105;
constexpr int RSSI_MAX = -35;
constexpr int MIN_PROMINENCE_DB = 4;
constexpr int MIN_EVIDENCE_RSSI = -100;

constexpr float BAND_315[] = {300.0f, 305.0f, 310.0f, 315.0f, 320.0f, 330.0f, 340.0f, 348.0f};
constexpr float BAND_433[] = {
    387.0f, 400.0f, 410.0f, 418.0f, 425.0f, 430.0f, 433.92f, 438.0f, 445.0f, 458.0f, 464.0f
};
constexpr float BAND_900[] = {
    779.0f, 800.0f, 820.0f, 850.0f, 868.3f, 880.0f, 900.0f, 915.0f, 925.0f, 928.0f
};

struct BandDefinition {
    const char *label;
    const float *frequencies;
    uint8_t count;
};

constexpr BandDefinition BANDS[] = {
    {"300-348", BAND_315, static_cast<uint8_t>(sizeof(BAND_315) / sizeof(BAND_315[0]))},
    {"387-464", BAND_433, static_cast<uint8_t>(sizeof(BAND_433) / sizeof(BAND_433[0]))},
    {"779-928", BAND_900, static_cast<uint8_t>(sizeof(BAND_900) / sizeof(BAND_900[0]))},
};

constexpr uint8_t BAND_COUNT = sizeof(BANDS) / sizeof(BANDS[0]);
constexpr uint8_t MAX_POINTS = sizeof(BAND_433) / sizeof(BAND_433[0]);
constexpr uint16_t TOTAL_POINTS_PER_PASS =
    (sizeof(BAND_315) + sizeof(BAND_433) + sizeof(BAND_900)) / sizeof(float);

struct BandResult {
    int peakRssi = RSSI_MIN;
    int baselineRssi = RSSI_MIN;
    int prominence = 0;
    int repeatSpread = 99;
    int score = 0;
    float peakFrequency = 0.0f;
    bool evidence = false;
};

int median(int *values, uint8_t count) {
    std::sort(values, values + count);
    return values[count / 2];
}

int clampInt(int value, int lower, int upper) {
    if (value < lower) return lower;
    if (value > upper) return upper;
    return value;
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

bool waitForSubGhzStart() {
    drawHeader("CC1101 receive-only survey");
    tft.setTextColor(TFT_LIGHTGREY, bruceConfig.bgColor);
    tft.drawString("Attach antenna to CC1101 SMA", 4, 34);
    tft.drawString("Keep unit still during scan", 4, 47);
    tft.drawString("Known nearby source improves ID", 4, 60);
    tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
    tft.drawString("Ambient result - not SWR/VSWR", 4, 78);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString("SEL: start     ESC: back", 4, tftHeight - 13);

    while (true) {
        if (escapePressed()) return false;
        if (check(SelPress)) return true;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

int samplePoint(float frequency) {
    setMHZ(frequency);
    vTaskDelay(pdMS_TO_TICKS(SETTLE_MS));

    int samples[SAMPLES_PER_POINT];
    for (uint8_t i = 0; i < SAMPLES_PER_POINT; i++) {
        samples[i] = ELECHOUSE_cc1101.getRssi();
        // Some boards share SPI between the radio and display.
        tft.drawPixel(0, 0, bruceConfig.bgColor);
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    return median(samples, SAMPLES_PER_POINT);
}

void drawScanProgress(
    const BandDefinition &band, uint8_t pass, float frequency, uint16_t completed, uint16_t total
) {
    drawHeader("CC1101 ambient sweep");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString("Range: " + String(band.label) + " MHz", 4, 34);
    tft.drawString("Pass: " + String(pass + 1) + " / " + String(PASSES), 4, 47);
    tft.drawString("Frequency: " + String(frequency, 2) + " MHz", 4, 60);

    const int x = 4;
    const int y = tftHeight - 26;
    const int width = tftWidth - 8;
    const int progress = total > 0 ? (completed * width) / total : 0;
    tft.drawRect(x, y, width, 9, TFT_DARKGREY);
    if (progress > 2) tft.fillRect(x + 1, y + 1, progress - 2, 7, bruceConfig.priColor);
}

BandResult analyseBand(
    const BandDefinition &band, int passRssi[PASSES][MAX_POINTS], int aggregate[MAX_POINTS]
) {
    BandResult result;

    for (uint8_t point = 0; point < band.count; point++) {
        int values[PASSES];
        for (uint8_t pass = 0; pass < PASSES; pass++) values[pass] = passRssi[pass][point];
        aggregate[point] = median(values, PASSES);
        if (aggregate[point] > result.peakRssi) {
            result.peakRssi = aggregate[point];
            result.peakFrequency = band.frequencies[point];
        }
    }

    int baselineValues[MAX_POINTS];
    for (uint8_t point = 0; point < band.count; point++) baselineValues[point] = aggregate[point];
    result.baselineRssi = median(baselineValues, band.count);
    result.prominence = result.peakRssi - result.baselineRssi;

    int lowestPassPeak = 127;
    int highestPassPeak = -127;
    for (uint8_t pass = 0; pass < PASSES; pass++) {
        int passPeak = -127;
        for (uint8_t point = 0; point < band.count; point++) {
            if (passRssi[pass][point] > passPeak) passPeak = passRssi[pass][point];
        }
        if (passPeak < lowestPassPeak) lowestPassPeak = passPeak;
        if (passPeak > highestPassPeak) highestPassPeak = passPeak;
    }
    result.repeatSpread = highestPassPeak - lowestPassPeak;

    const int strength = clampInt(result.peakRssi - MIN_EVIDENCE_RSSI, 0, 30);
    result.score = clampInt(result.prominence * 6 + strength * 2 - result.repeatSpread * 3, 0, 100);
    result.evidence =
        result.peakRssi >= MIN_EVIDENCE_RSSI && result.prominence >= MIN_PROMINENCE_DB &&
        result.repeatSpread <= 12;

    return result;
}

String likelyBandName(uint8_t bandIndex, float peakFrequency) {
    if (bandIndex == 0) {
        if (peakFrequency >= 307.0f && peakFrequency <= 323.0f) return "315 MHz";
        return "300-348 MHz";
    }
    if (bandIndex == 1) {
        if (peakFrequency >= 425.0f && peakFrequency <= 445.0f) return "433 MHz";
        return "387-464 MHz";
    }
    if (peakFrequency >= 855.0f && peakFrequency < 890.0f) return "868 MHz";
    if (peakFrequency >= 890.0f) return "915 MHz";
    return "779-928 MHz";
}

uint16_t scoreColor(const BandResult &result) {
    if (!result.evidence) return TFT_DARKGREY;
    if (result.score >= 70) return TFT_GREEN;
    if (result.score >= 40) return TFT_YELLOW;
    return TFT_ORANGE;
}

void drawBandRow(const BandDefinition &band, const BandResult &result, int y) {
    const int labelWidth = 54;
    const int rightWidth = 112;
    const int barX = labelWidth;
    int barWidth = tftWidth - labelWidth - rightWidth;
    if (barWidth < 20) barWidth = 20;
    const int normalized = clampInt(result.peakRssi, RSSI_MIN, RSSI_MAX);
    const int fillWidth = (normalized - RSSI_MIN) * barWidth / (RSSI_MAX - RSSI_MIN);
    const uint16_t color = scoreColor(result);

    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString(band.label, 4, y);
    tft.drawRect(barX, y + 1, barWidth, 7, TFT_DARKGREY);
    if (fillWidth > 1) tft.fillRect(barX + 1, y + 2, fillWidth - 1, 5, color);

    tft.setTextColor(result.evidence ? TFT_LIGHTGREY : TFT_DARKGREY, bruceConfig.bgColor);
    const String stats =
        String(result.peakRssi) + "dBm +" + String(result.prominence) + "dB " + String(result.score) + "%";
    tft.drawString(stats, barX + barWidth + 5, y);
}

void drawResults(const BandResult results[BAND_COUNT]) {
    drawHeader("CC1101 survey result");

    uint8_t strongest = 0;
    uint8_t evidenceCount = 0;
    for (uint8_t i = 0; i < BAND_COUNT; i++) {
        if (results[i].evidence) evidenceCount++;
        if (results[i].score > results[strongest].score) strongest = i;
    }

    tft.setTextColor(evidenceCount == 0 ? TFT_YELLOW : TFT_WHITE, bruceConfig.bgColor);
    String classification;
    if (evidenceCount == 0) {
        classification = "INCONCLUSIVE - LOW RF EVIDENCE";
    } else if (evidenceCount > 1) {
        classification = "POSSIBLE MULTI-BAND RESPONSE";
    } else {
        classification = "LIKELY " + likelyBandName(strongest, results[strongest].peakFrequency);
    }
    tft.drawString(classification, 4, 31);

    for (uint8_t i = 0; i < BAND_COUNT; i++) drawBandRow(BANDS[i], results[i], 50 + i * 22);

    tft.setTextColor(TFT_LIGHTGREY, bruceConfig.bgColor);
    if (evidenceCount > 0) {
        String peak = "Peak " + String(results[strongest].peakFrequency, 2) + " MHz";
        peak += " spread " + String(results[strongest].repeatSpread) + " dB";
        tft.drawString(peak, 4, 119);
    } else {
        tft.drawString("Try a nearby known transmitter", 4, 119);
    }

    tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
    tft.drawString("Observed response only - not resonance", 4, 134);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString("SEL: rescan     ESC: back", 4, tftHeight - 13);
}

void printResults(const BandResult results[BAND_COUNT]) {
    Serial.println("[ANTENNA_ID] band,peak_mhz,peak_dbm,baseline_dbm,prominence_db,spread_db,score,evidence");
    for (uint8_t i = 0; i < BAND_COUNT; i++) {
        Serial.printf(
            "[ANTENNA_ID] %s,%.2f,%d,%d,%d,%d,%d,%s\n",
            BANDS[i].label,
            results[i].peakFrequency,
            results[i].peakRssi,
            results[i].baselineRssi,
            results[i].prominence,
            results[i].repeatSpread,
            results[i].score,
            results[i].evidence ? "yes" : "no"
        );
    }
}

bool runSurvey(BandResult results[BAND_COUNT]) {
    if (!initRfModule("rx", BAND_315[0])) {
        displayError("Unable to start CC1101", true);
        return false;
    }

    uint16_t completed = 0;
    const uint16_t total = TOTAL_POINTS_PER_PASS * PASSES;

    for (uint8_t bandIndex = 0; bandIndex < BAND_COUNT; bandIndex++) {
        const BandDefinition &band = BANDS[bandIndex];
        int passRssi[PASSES][MAX_POINTS] = {};
        int aggregate[MAX_POINTS] = {};

        for (uint8_t pass = 0; pass < PASSES; pass++) {
            for (uint8_t point = 0; point < band.count; point++) {
                if (escapePressed()) {
                    deinitRfModule();
                    return false;
                }
                drawScanProgress(band, pass, band.frequencies[point], completed, total);
                passRssi[pass][point] = samplePoint(band.frequencies[point]);
                completed++;
            }
        }
        results[bandIndex] = analyseBand(band, passRssi, aggregate);
    }

    deinitRfModule();
    printResults(results);
    return true;
}

} // namespace

void rf_antenna_id() {
#if !defined(LITE_VERSION)
    int selectedAction = 0;
    options = {
        {"Sub-GHz CC1101", [&selectedAction]() { selectedAction = 1; }},
        {"2.4G WiFi/BLE",  [&selectedAction]() { selectedAction = 2; }},
        {"Back",           [&selectedAction]() { selectedAction = 3; }},
    };
    loopOptions(options, MENU_TYPE_SUBMENU, "Antenna ID");
    options.clear();

    if (selectedAction == 1) rf_antenna_id_subghz();
    else if (selectedAction == 2) rf_antenna_id_24ghz();
#else
    displayError("Not available on Launcher version", true);
#endif
}

void rf_antenna_id_subghz() {
#if !defined(LITE_VERSION)
    if (bruceConfigPins.rfModule != CC1101_SPI_MODULE) {
        displayError("Sub-GHz ID requires CC1101", true);
        return;
    }

    if (!waitForSubGhzStart()) return;

    while (true) {
        BandResult results[BAND_COUNT];
        if (!runSurvey(results)) return;
        drawResults(results);

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
