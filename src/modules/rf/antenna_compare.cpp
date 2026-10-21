#include "antenna_id.h"
#include "rf_utils.h"
#include "core/display.h"
#include "core/utils.h"
#include "core/mykeyboard.h"
#include "core/sd_functions.h"
#include "modules/ble/ble_common.h"
#include "modules/df/recon_core.h"
#include <globals.h>
#include <algorithm>
#include <cmath>

namespace {
constexpr unsigned COUNT = 24;
int samples[3][COUNT];
portMUX_TYPE sampleMux = portMUX_INITIALIZER_UNLOCKED;
unsigned received = 0;
char beacon[18]{};
uint8_t beaconType = 0;
uint32_t previousSample = 0;
class ReferenceCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *d) override {
        if (!d || d->getAdvType() == 4 || d->getAddressType() != beaconType || d->getAddress().toString() != beacon) return;
        portENTER_CRITICAL(&sampleMux);
        const uint32_t now = millis();
        if (received < COUNT && now - previousSample >= 100) {
            samples[0][received++] = d->getRSSI(); previousSample = now;
        }
        portEXIT_CRITICAL(&sampleMux);
    }
} referenceCallbacks;
void header(const String &title) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(1);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString(title, 4, 4);
}
bool prompt(const char *phase, bool ble) {
    header(String("A/B/A: ") + phase);
    tft.drawString(ble ? "ESP32 BLE antenna path (not SMA)" : "CC1101 SMA receive path", 4, 24);
    tft.drawString("Keep source, power, position fixed", 4, 41);
    tft.drawString("Keep orientation and cable fixed", 4, 55);
    tft.drawString("Change only the antenna under test", 4, 69);
    tft.drawString(ble ? "Same selected beacon; address locked" : "Use a steady source at selected MHz", 4, 85);
    tft.drawString("Reference -> candidate -> reference", 4, 101);
    tft.drawString("SEL sample / ESC cancel", 4, tftHeight - 14);
    while (!check(EscPress)) {
        if (check(SelPress)) return true;
        delay(20);
    }
    return false;
}
bool measure(unsigned phase, bool ble, float frequency) {
    int captured[COUNT]{};
    if (ble) {
        pBLEScan->stop(); pBLEScan->clearResults();
        portENTER_CRITICAL(&sampleMux); received = 0; previousSample = millis() - 100; portEXIT_CRITICAL(&sampleMux);
        pBLEScan->setScanCallbacks(&referenceCallbacks, true);
        pBLEScan->setMaxResults(0); pBLEScan->setActiveScan(false);
        if (!pBLEScan->start(0, false, true)) return false;
    } else if (!initRfModule("rx", frequency)) return false;
    const uint32_t start = millis();
    unsigned count = 0;
    bool cancelled = false;
    while (count < COUNT && millis() - start < 45000) {
        if (check(EscPress)) { cancelled = true; break; }
        if (ble) {
            portENTER_CRITICAL(&sampleMux); count = received; portEXIT_CRITICAL(&sampleMux);
        } else {
            captured[count++] = ELECHOUSE_cc1101.getRssi();
        }
        header("Measuring " + String(count) + "/24");
        tft.drawString("Keep everything still", 4, 40);
        tft.drawString("ESC cancels without saving", 4, 60);
        delay(ble ? 30 : 150);
    }
    if (ble) {
        pBLEScan->stop(); pBLEScan->setScanCallbacks(nullptr, false);
        // Callback uses phase-zero scratch; save all phases separately below.
        std::copy(samples[0], samples[0] + COUNT, captured);
    } else deinitRfModule();
    if (cancelled) return false;
    if (count != COUNT) { displayWarning("Too few beacon packets; retry", true); return false; }
    std::copy(captured, captured + COUNT, samples[phase]);
    return true;
}
float median(const int *p) {
    int v[COUNT]; std::copy(p, p + COUNT, v); std::sort(v, v + COUNT);
    return (v[11] + v[12]) / 2.f;
}
float spread(const int *p) {
    int v[COUNT]; std::copy(p, p + COUNT, v); std::sort(v, v + COUNT);
    return (v[21] - v[2]) / 2.f;
}
String safeName(String s) {
    String result;
    for (unsigned i = 0; i < s.length() && result.length() < 24; ++i) {
        const char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') result += c;
    }
    return result.isEmpty() ? "antenna" : result;
}
}

void rf_antenna_compare(bool ble) {
    float frequency = 0;
    if (ble) {
        ble_scan_setup();
        if (!pBLEScan) return;
        pBLEScan->setActiveScan(false); pBLEScan->setMaxResults(40);
        displayTextLine("Choose a fixed BLE reference beacon");
        const auto devices = pBLEScan->getResults(5000, false);
        std::vector<Option> choices;
        bool selected = false;
        for (int i = 0; i < devices.getCount(); ++i) {
            const auto *device = devices.getDevice(i);
            if (!device) continue;
            const std::string address = device->getAddress().toString();
            const uint8_t type = device->getAddressType();
            choices.emplace_back(String(address.c_str()) + " " + String(device->getRSSI()), [&, address, type]() {
                std::strncpy(beacon, address.c_str(), 17); beaconType = type; selected = true;
            });
        }
        loopOptions(choices, MENU_TYPE_REGULAR, "Reference beacon", 0, false);
        pBLEScan->clearResults();
        if (!selected) { stopBLEStack(); return; }
    } else {
        if (bruceConfigPins.rfModule != CC1101_SPI_MODULE) { displayError("Requires CC1101", true); return; }
        const String text = num_keyboard("433.92", 9, "Source frequency MHz");
        frequency = text.toFloat();
        if (!((frequency >= 300 && frequency <= 348) || (frequency >= 387 && frequency <= 464) || (frequency >= 779 && frequency <= 928))) {
            displayWarning("Unsupported CC1101 band", true); return;
        }
    }
    const String name = safeName(keyboard("antenna", 24, "Candidate profile name"));
    int before[COUNT], candidate[COUNT], after[COUNT];
    const char *phases[] = {"REFERENCE before", "CANDIDATE", "REFERENCE after"};
    for (unsigned i = 0; i < 3; ++i) {
        if (!prompt(phases[i], ble) || !measure(i, ble, frequency)) {
            if (ble) stopBLEStack();
            return;
        }
        // Dedicated copies protect the reference from the BLE callback scratch.
        std::copy(samples[i], samples[i] + COUNT, i == 0 ? before : i == 1 ? candidate : after);
    }
    if (ble) stopBLEStack();
    const float a = median(before), b = median(candidate), c = median(after);
    const auto result = recon::compareAntenna(a, b, c, std::max({spread(before), spread(candidate), spread(after)}));
    bool saved = false;
    String path;
    if (setupSdCard() && (SD.exists("/AntennaProfiles") || SD.mkdir("/AntennaProfiles"))) {
        path = "/AntennaProfiles/" + name + (ble ? "-esp32-ble.csv" : "-cc1101.csv");
        const bool exists = SD.exists(path);
        File file = SD.open(path, FILE_APPEND);
        if (file) {
            bool ok = true;
            if (!exists) ok = file.println("uptime_ms,path,frequency_mhz,beacon,reference_before_dbm,candidate_dbm,reference_after_dbm,relative_db,drift_db,uncertainty_db,reliable") > 0;
            const String row = String(millis()) + "," + (ble ? "ESP32_BLE,2400-2483.5," : "CC1101," + String(frequency, 3) + ",") + (ble ? beacon : "") + "," + String(a, 1) + "," + String(b, 1) + "," + String(c, 1) + "," + String(result.delta, 1) + "," + String(result.drift, 1) + "," + String(result.uncertainty, 1) + "," + (result.reliable ? "true" : "false");
            saved = ok && file.println(row) == row.length() + 2;
            file.flush(); file.close();
        }
    }
    header("Antenna relative response / " + name);
    tft.drawString("Candidate " + String(result.delta, 1) + " dB vs reference", 4, 25);
    tft.drawString("Drift " + String(result.drift, 1) + " dB  spread +/-" + String(result.uncertainty, 1), 4, 41);
    tft.drawString(result.reliable ? "Repeatable in this setup" : "INCONCLUSIVE: drift/noise/level", 4, 57);
    tft.drawString("RSSI comparison; no gain/SWR claim", 4, 73);
    const int *traces[] = {before, candidate, after};
    const uint16_t colors[] = {TFT_BLUE, TFT_GREEN, TFT_ORANGE};
    for (unsigned t = 0; t < 3; ++t) for (unsigned i = 1; i < COUNT; ++i) {
        auto y = [](int v) { return 135 - (std::max(-105, std::min(-25, v)) + 105) / 2; };
        tft.drawLine(4 + (i-1) * (tftWidth-8) / 23, y(traces[t][i-1]), 4 + i * (tftWidth-8) / 23, y(traces[t][i]), colors[t]);
    }
    tft.drawString(saved ? "Saved profile / ESC back" : "Not saved (SD unavailable/full) / ESC", 4, tftHeight - 14);
    while (!check(EscPress) && !check(SelPress)) delay(20);
}

void rf_antenna_profiles() {
    if (!setupSdCard()) { displayWarning("Insert SD card", true); return; }
    const String path = loopSD(SD, true, "CSV", "/AntennaProfiles");
    if (path.isEmpty()) return;
    File file = SD.open(path, FILE_READ);
    if (!file) return;
    auto line = [&file]() {
        String value; bool overflow = false;
        while (file.available()) {
            const char c = file.read();
            if (c == '\n') break;
            if (value.length() < 512) value += c; else overflow = true;
        }
        value.trim(); return overflow ? String() : value;
    };
    const String heading = line();
    const bool vna = heading == "frequency_mhz,return_loss_db,vswr";
    if (!vna && !heading.startsWith("uptime_ms,path,frequency_mhz,beacon,")) {
        file.close(); displayWarning("Import VNA with recon_session.py", true); return;
    }
    struct Point { float frequency, value, spread; bool valid; };
    static Point points[128];
    unsigned count = 0, ignored = 0;
    String radio;
    while (file.available() && count < 128) {
        if (check(EscPress)) { file.close(); return; }
        const String text = line();
        String cells[11]; unsigned cell = 0;
        for (unsigned i = 0; i < text.length(); ++i) {
            if (text[i] == ',') { if (++cell >= 11) break; }
            else if (cell < 11) cells[cell] += text[i];
        }
        if (cell != (vna ? 2u : 10u)) { ++ignored; continue; }
        const auto number = [](const String &value, float &out) {
            char *end = nullptr; out = strtof(value.c_str(), &end);
            return end != value.c_str() && *end == 0 && std::isfinite(out);
        };
        Point point{};
        const bool pooledBle = !vna && cells[1] == "ESP32_BLE";
        if (pooledBle) point.frequency = 0;
        else if (!number(cells[vna ? 0 : 2], point.frequency) || point.frequency <= 0) { ++ignored; continue; }
        if (!number(cells[vna ? 1 : 7], point.value) || !number(cells[vna ? 2 : 9], point.spread)) { ++ignored; continue; }
        if (vna && (point.value <= 0 || point.spread < 1)) { ++ignored; continue; }
        if (!vna) {
            if (radio.isEmpty()) radio = cells[1];
            if (radio != cells[1]) { ++ignored; continue; }
            point.valid = cells[10] == "true";
        } else point.valid = true;
        points[count++] = point;
    }
    const bool capped = file.available();
    file.close();
    if (!count) { displayWarning("No valid profile points", true); return; }
    std::sort(points, points + count, [](const Point &a, const Point &b) { return a.frequency < b.frequency; });
    float lo = points[0].value, hi = lo;
    for (unsigned i = 1; i < count; ++i) { lo = std::min(lo, points[i].value); hi = std::max(hi, points[i].value); }
    if (hi - lo < 1) { lo -= .5f; hi += .5f; }
    unsigned selected = 0;
    while (!check(EscPress)) {
        header(vna ? "VNA S11 / imported calibration" : "PROFILE / " + radio);
        const auto &p = points[selected];
        tft.drawString(p.frequency ? String(p.frequency, 3) + " MHz" : "BLE advertising channels pooled", 4, 23);
        tft.drawString(vna ? "Return loss " + String(p.value, 2) + " dB  VSWR " + String(p.spread, 2) : "Relative " + String(p.value, 1) + " dB +/-" + String(p.spread, 1), 4, 38);
        tft.drawString(vna ? "S11 matching; not radiation gain" : p.valid ? "Repeatable setup" : "INCONCLUSIVE sample", 4, 53);
        for (unsigned i = 1; i < count; ++i) {
            const auto x = [&](unsigned n) { return points[count-1].frequency > points[0].frequency ? 6 + static_cast<int>((points[n].frequency-points[0].frequency)*(tftWidth-12)/(points[count-1].frequency-points[0].frequency)) : 6 + n*(tftWidth-12)/std::max(1u,count-1); };
            const auto y = [&](float value) { return 125 - static_cast<int>((value-lo)*50/(hi-lo)); };
            tft.drawLine(x(i-1), y(points[i-1].value), x(i), y(points[i].value), points[i].valid ? TFT_GREEN : TFT_YELLOW);
        }
        tft.drawString("Y " + String(lo,1) + ".." + String(hi,1) + " dB  " + String(selected+1) + "/" + String(count), 4, 133);
        tft.drawString(capped ? "128 point limit / ESC back" : ignored ? "Ignored " + String(ignored) + " invalid rows / ESC" : "Turn points / ESC back", 4, tftHeight-14);
        if (check(PrevPress)) selected = (selected + count - 1) % count;
        if (check(NextPress)) selected = (selected + 1) % count;
        delay(40);
    }
}
