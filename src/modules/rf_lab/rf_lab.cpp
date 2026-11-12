#include "rf_lab.h"
#include "core.h"
#include "core/display.h"
#include "core/sd_functions.h"
#include "modules/radio_control/radio_control.h"
#include "modules/rf/rf_utils.h"
#include <ArduinoJson.h>
#include <esp_system.h>
#include <esp_random.h>
#include <globals.h>
#include <memory>

namespace {
using RadioControl::ReceiveSettings;
ReceiveSettings selected;
int gateDbm = -85;
bool frequencySelected = false;
constexpr size_t CandidateCount = 18;
constexpr uint32_t DwellMs = 2000;
const char *modName(uint8_t m) { return m == 2 ? "OOK" : m == 0 ? "2FSK" : "GFSK"; }

void screen(const String &title, const String &a, const String &b = "", const String &c = "") {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(1);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString(title, 4, 3);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.drawString(a, 4, 23);
    tft.drawString(b, 4, 38);
    tft.drawString(c, 4, 53);
    tft.drawString("ESC: stop/back", 4, tftHeight - 14);
}

// One foreground RF tool owns the radio. Restore Bruce's configured receive defaults
// and idle on every exit; the persisted Radio Control profile is never modified.
class RadioSession {
    bool active = false;
public:
    bool begin(const ReceiveSettings &s) {
        if (!RadioControl::validReceiveSettings(s) || bruceConfigPins.rfModule != CC1101_SPI_MODULE) {
            displayError("CC1101 / valid band required", true);
            return false;
        }
        active = initRfModule("rx", s.frequencyMHz);
        if (!active) { deinitRfModule(); displayError("CC1101 unavailable", true); return false; }
        return RadioControl::applyReceiveSettings(s);
    }
    ~RadioSession() {
        if (active) {
            initRfModule("rx", bruceConfigPins.rfFreq);
            deinitRfModule();
        }
    }
};

// Hardware capture avoids a per-edge ISR storm. Fixed buffers bound RAM and capture
// truncation is reported instead of treating a full buffer as a complete frame.
class PulseCapture {
    rmt_channel_handle_t channel = nullptr;
    QueueHandle_t queue = nullptr;
    bool enabled = false;
    rmt_symbol_word_t symbols[128]{};
    static bool done(rmt_channel_handle_t, const rmt_rx_done_event_data_t *data, void *ctx) {
        auto self = static_cast<PulseCapture *>(ctx);
        BaseType_t wake = pdFALSE;
        xQueueSendFromISR(self->queue, data, &wake);
        return wake == pdTRUE;
    }
    bool arm() {
        rmt_receive_config_t cfg{};
        cfg.signal_range_min_ns = 20000;
        cfg.signal_range_max_ns = 12000000;
        return rmt_receive(channel, symbols, sizeof(symbols), &cfg) == ESP_OK;
    }
public:
    bool healthy = true;
    bool begin() {
        queue = xQueueCreate(1, sizeof(rmt_rx_done_event_data_t));
        if (!queue) return false;
        rmt_rx_channel_config_t cfg{};
        cfg.gpio_num = static_cast<gpio_num_t>(bruceConfigPins.CC1101_bus.io0);
        cfg.clk_src = RMT_CLK_SRC_DEFAULT;
        cfg.resolution_hz = 1000000;
        cfg.mem_block_symbols = 64;
        if (rmt_new_rx_channel(&cfg, &channel) != ESP_OK) return false;
        rmt_rx_event_callbacks_t callbacks{};
        callbacks.on_recv_done = done;
        if (rmt_rx_register_event_callbacks(channel, &callbacks, this) != ESP_OK) return false;
        if (rmt_enable(channel) != ESP_OK) return false;
        enabled = true;
        return arm();
    }
    bool poll(RfLab::Evidence &e, bool energy, int32_t *example, size_t &exampleSize) {
        rmt_rx_done_event_data_t result{};
        if (xQueueReceive(queue, &result, 0) != pdPASS) return false;
        if (energy && result.num_symbols >= 8) {
            if (result.num_symbols >= 128) ++e.clipped;
            else {
                const uint32_t before = e.pulses;
                for (size_t i = 0; i < result.num_symbols; ++i) {
                    e.pulse(symbols[i].duration0);
                    e.pulse(symbols[i].duration1);
                }
                if (e.pulses - before >= 16) {
                    ++e.frames;
                    if (!exampleSize) {
                        for (size_t i = 0; i < result.num_symbols && exampleSize + 2 <= 256; ++i) {
                            if (symbols[i].duration0)
                                example[exampleSize++] = symbols[i].level0 ? symbols[i].duration0 : -int(symbols[i].duration0);
                            if (symbols[i].duration1)
                                example[exampleSize++] = symbols[i].level1 ? symbols[i].duration1 : -int(symbols[i].duration1);
                        }
                    }
                }
            }
        }
        healthy = arm();
        return true;
    }
    ~PulseCapture() {
        if (enabled) rmt_disable(channel);
        if (channel) rmt_del_channel(channel);
        if (queue) vQueueDelete(queue);
    }
};

void settingsJson(JsonObject obj, const ReceiveSettings &s) {
    obj["frequency_mhz"] = s.frequencyMHz;
    obj["modulation_register"] = s.modulation;
    obj["modulation_candidate"] = modName(s.modulation);
    obj["requested_rate_kbaud"] = s.rateKBaud;
    obj["requested_rx_bandwidth_khz"] = s.bandwidthKHz;
}

bool writeJson(File &file, const JsonDocument &doc) {
    if (!file) return false;
    const size_t expected = measureJson(doc);
    const size_t written = serializeJson(doc, file);
    const size_t newline = file.print('\n');
    file.flush();
    return written == expected && newline == 1 && !file.getWriteError();
}

String sessionName(const char *prefix) {
    return String(prefix) + "-" + String(esp_random(), HEX) + ".jsonl";
}

void blackBox() {
    // Continuous logging uses SD only, avoiding repeated writes to internal flash.
    if (!setupSdCard()) { displayError("Black Box needs an SD card", true); return; }
    FS *fs = &SD;
    File log = createNewFile(fs, "/RF-Lab", sessionName("blackbox"));
    if (!log) { displayError("Cannot create event log", true); return; }
    RadioSession radio;
    if (!radio.begin(selected)) { log.close(); return; }
    delay(20);
    JsonDocument header;
    header["schema"] = "bruce.rf-blackbox.v1";
    header["clock"] = "uptime_ms; wraps at 2^32; not UTC";
    header["mode"] = "fixed_frequency_sampled_rssi";
    header["nominal_sample_ms"] = 20;
    header["learning_samples"] = RfLab::Detector::Learning;
    header["pre_samples"] = 64;
    header["post_samples"] = 32;
    header["limit_events"] = 100;
    header["notes"] = "RSSI only; no IQ or raw pulse prebuffer. Storage/UI cause gaps; timestamps are actual sample times.";
    settingsJson(header["receiver"].to<JsonObject>(), selected);
    if (!writeJson(log, header)) { displayError("SD write failed", true); return; }
    RfLab::Detector detector;
    RfLab::Ring<64> pre;
    std::array<RfLab::Sample, 96> event{};
    size_t eventSize = 0, remaining = 0;
    unsigned count = 0;
    uint32_t triggerMs = 0, lastSample = millis(), lastDraw = 0, previousSample = lastSample;
    uint32_t maxGap = 0;
    bool failed = false, cancelled = false, tracking = false;
    uint32_t activityStart = 0, lastAbove = 0, aboveSamples = 0;
    unsigned activityId = 0;
    int peak = -127;
    auto saveActivity = [&](bool partial) {
        JsonDocument doc;
        doc["activity_end_for_event"] = activityId;
        doc["trigger_ms"] = activityStart;
        doc["last_above_threshold_ms"] = lastAbove;
        doc["observed_span_ms"] = uint32_t(lastAbove - activityStart);
        doc["above_threshold_samples"] = aboveSamples;
        doc["peak_dbm"] = peak;
        doc["partial"] = partial;
        doc["note"] = "Sampled span, not continuous airtime; brief quiet gaps may be included";
        failed = failed || !writeJson(log, doc);
        tracking = false;
    };
    auto saveEvent = [&](bool partial) {
        JsonDocument doc;
        doc["event"] = ++count;
        doc["trigger_ms"] = triggerMs;
        doc["threshold_dbm"] = detector.threshold;
        doc["partial"] = partial;
        doc["max_observed_sample_gap_ms"] = maxGap;
        auto samples = doc["samples"].to<JsonArray>();
        for (size_t i = 0; i < eventSize; ++i) {
            auto row = samples.add<JsonArray>();
            row.add(event[i].ms); row.add(event[i].rssi);
        }
        failed = failed || !writeJson(log, doc);
        gateDbm = detector.threshold;
    };
    screen("RF BLACK BOX", "Learning quiet baseline...", "Fixed " + String(selected.frequencyMHz, 3) + " MHz");
    while (count < 100 && !failed) {
        if (check(EscPress)) { cancelled = true; break; }
        const uint32_t now = millis();
        if (uint32_t(now - lastSample) < 20) { delay(1); continue; }
        lastSample = now;
        maxGap = std::max(maxGap, uint32_t(now - previousSample)); previousSample = now;
        RfLab::Sample sample{now, static_cast<int16_t>(ELECHOUSE_cc1101.getRssi())};
        tft.drawPixel(0, 0, bruceConfig.bgColor);
        const bool trigger = detector.add(sample);
        if (tracking && sample.rssi >= detector.threshold) {
            lastAbove = now; ++aboveSamples; peak = std::max(peak, int(sample.rssi));
        }
        if (tracking && !detector.latched) saveActivity(false);
        // Preserve a fresh event even if the previous post-trigger window is not full.
        if (trigger && remaining) { saveEvent(true); remaining = 0; }
        if (remaining) {
            event[eventSize++] = sample;
            if (--remaining == 0) saveEvent(false);
        } else if (trigger && count < 100 && !failed) {
            eventSize = 0;
            for (size_t i = 0; i < pre.count; ++i) event[eventSize++] = pre.at(i);
            triggerMs = now;
            tracking = true; activityId = count + 1;
            activityStart = lastAbove = now; aboveSamples = 1; peak = sample.rssi;
            event[eventSize++] = sample;
            remaining = 31;
        }
        pre.push(sample);
        if (uint32_t(now - lastDraw) >= 500) {
            lastDraw = now;
            screen("RF BLACK BOX", String(selected.frequencyMHz, 3) + " MHz  " + String(sample.rssi) + " dBm",
                   detector.learned < RfLab::Detector::Learning ? "Learning baseline..." : "Trigger >= " + String(detector.threshold) + " dBm",
                   "Saved " + String(count) + "/100  gap " + String(maxGap) + "ms");
        }
    }
    if (remaining && !failed) saveEvent(true);
    if (tracking && !failed) saveActivity(true);
    JsonDocument end;
    end["end_ms"] = millis();
    end["reason"] = failed ? "write_error" : cancelled ? "user_stop" : "event_limit";
    end["events"] = count;
    end["max_observed_sample_gap_ms"] = maxGap;
    if (!failed) failed = !writeJson(log, end);
    log.close();
    if (failed) displayError("SD write failed; log incomplete", true);
    else displaySuccess("Saved in /RF-Lab", true);
}

struct Candidate {
    ReceiveSettings settings;
    RfLab::Evidence rounds[2];
    int score = 0;
    int32_t example[256]{};
    size_t exampleSize = 0;
};

bool collect(Candidate &c, unsigned round) {
    if (!RadioControl::applyReceiveSettings(c.settings)) return false;
    delay(20);
    PulseCapture capture;
    if (!capture.begin()) { displayError("RMT capture unavailable", true); return false; }
    const uint32_t start = millis();
    bool energy = false;
    uint32_t lastRssi = 0;
    while (uint32_t(millis() - start) < DwellMs) {
        if (check(EscPress)) return false;
        if (uint32_t(millis() - lastRssi) >= 5) {
            lastRssi = millis();
            energy = (ELECHOUSE_cc1101.getRssi() >= gateDbm) || energy;
            tft.drawPixel(0, 0, bruceConfig.bgColor);
        }
        if (capture.poll(c.rounds[round], energy, c.example, c.exampleSize)) energy = false;
        if (!capture.healthy) { displayError("RMT capture failed", true); return false; }
        delay(1);
    }
    return true;
}

void evidenceJson(JsonObject out, const RfLab::Evidence &e) {
    out["segments"] = e.frames;
    out["pulses"] = e.pulses;
    out["clipped_segments"] = e.clipped;
    auto bins = out["duration_histogram"].to<JsonArray>();
    for (auto value : e.bins) bins.add(value);
}

void saveCandidate(const Candidate &c) {
    FS *fs = nullptr;
    if (!getFsStorage(fs)) return;
    File f = createNewFile(fs, "/RF-Lab", sessionName("profile"));
    JsonDocument doc;
    doc["schema"] = "bruce.rx-profile.v1";
    doc["identification"] = "unknown; receiver candidate only";
    doc["score_is_probability"] = false;
    doc["heuristic_score"] = c.score;
    doc["gate_dbm"] = gateDbm;
    doc["dwell_per_round_ms"] = DwellMs;
    doc["rounds"] = 2;
    doc["capture"] = "1us RMT, 20us glitch filter, 12ms idle split; signed levels";
    doc["histogram"] = "32 bins; upper edge starts 25us, next=floor(edge*5/4)+1; 20<=pulse<12000us";
    doc["limitations"] = "No IQ, protocol or CRC validation. Energy gate polled every 5ms within capture segments. OOK/FSK/GFSK may remain ambiguous. Live repeated transmissions required.";
    settingsJson(doc["receiver"].to<JsonObject>(), c.settings);
    evidenceJson(doc["first_pass"].to<JsonObject>(), c.rounds[0]);
    evidenceJson(doc["second_pass"].to<JsonObject>(), c.rounds[1]);
    auto pulses = doc["example_pulses_us"].to<JsonArray>();
    for (size_t i = 0; i < c.exampleSize; ++i) pulses.add(c.example[i]);
    const bool ok = writeJson(f, doc);
    f.close();
    if (ok) displaySuccess("Profile saved in /RF-Lab", true);
    else displayError("Profile write failed", true);
}

void finder() {
    // Allocate on the heap, not the small Arduino loop task stack.
    std::unique_ptr<Candidate[]> candidates(new (std::nothrow) Candidate[CandidateCount]);
    if (!candidates) { displayError("Not enough RAM", true); return; }
    size_t n = 0;
    for (uint8_t mod : {uint8_t(2), uint8_t(0), uint8_t(1)})
        for (float rate : {1.2f, 4.8f, 9.6f})
            for (float bw : {58.0357f, 203.125f})
                candidates[n++].settings = {selected.frequencyMHz, mod, rate, bw};
    {
        RadioSession radio;
        if (!radio.begin(selected)) return;
        // Reverse the second pass to reduce order bias; changing/intermittent sources
        // still require a rerun. Never label this score as identification confidence.
        for (unsigned round = 0; round < 2; ++round) {
            for (size_t step = 0; step < n; ++step) {
                const size_t index = round == 0 ? step : n - 1 - step;
                auto &c = candidates[index];
                screen("RECEIVE PROFILE FINDER", "Repeat source throughout (~75s)",
                       "Pass " + String(round + 1) + "  " + String(step + 1) + "/18",
                       String(modName(c.settings.modulation)) + " " + String(c.settings.rateKBaud, 1) + "k  BW " + String(c.settings.bandwidthKHz, 0));
                if (!collect(c, round)) return;
            }
        }
    }
    for (size_t i = 0; i < n; ++i) candidates[i].score = RfLab::similarity(candidates[i].rounds[0], candidates[i].rounds[1]);
    std::sort(candidates.get(), candidates.get() + n, [](const Candidate &a, const Candidate &b) { return a.score > b.score; });
    if (!candidates[0].score) {
        displayWarning("Insufficient repeatable evidence", true);
        return;
    }
    while (true) {
        std::vector<Option> items;
        for (size_t i = 0; i < std::min(size_t(5), n); ++i) {
            if (!candidates[i].score) break;
            auto &c = candidates[i];
            String label = String(c.score) + " " + modName(c.settings.modulation) + " " + String(c.settings.rateKBaud, 1) + "k/" + String(c.settings.bandwidthKHz, 0);
            items.push_back({label, [&, i]() {
                auto &candidate = candidates[i];
                std::vector<Option> actions = {
                    {"Use for Black Box", [&]() { selected = candidate.settings; }},
                    {"Save profile + evidence", [&]() { saveCandidate(candidate); }},
                    {"Back", []() {}},
                };
                loopOptions(actions, MENU_TYPE_SUBMENU, "Candidate, NOT device ID");
            }});
        }
        items.push_back({"Back", []() {}});
        const int result = loopOptions(items, MENU_TYPE_SUBMENU, "Heuristic score, not %");
        if (result < 0 || result == int(items.size() - 1)) return;
    }
}

void loadProfile() {
    FS *fs = nullptr;
    if (!getFsStorage(fs)) return;
    String path = loopSD(*fs, true, "jsonl", "/RF-Lab");
    if (!path.length()) return;
    File file = fs->open(path, FILE_READ);
    if (!file || file.size() > 32768) { displayError("Invalid profile file", true); return; }
    JsonDocument doc;
    if (deserializeJson(doc, file) || doc["schema"].as<String>() != "bruce.rx-profile.v1") {
        displayError("Not an RX profile", true); return;
    }
    auto s = doc["receiver"];
    if (!s["frequency_mhz"].is<float>() || !s["modulation_register"].is<unsigned>() ||
        !s["requested_rate_kbaud"].is<float>() || !s["requested_rx_bandwidth_khz"].is<float>()) {
        displayError("Missing profile settings", true); return;
    }
    const unsigned mod = s["modulation_register"].as<unsigned>();
    ReceiveSettings value{s["frequency_mhz"].as<float>(), static_cast<uint8_t>(mod),
                          s["requested_rate_kbaud"].as<float>(), s["requested_rx_bandwidth_khz"].as<float>()};
    if (mod > 2 || !RadioControl::validReceiveSettings(value)) { displayError("Profile outside supported range", true); return; }
    selected = value;
    frequencySelected = true;
    displaySuccess("RX profile loaded", true);
}

void reviewEvents() {
    FS *fs = nullptr;
    if (!getFsStorage(fs)) return;
    String path = loopSD(*fs, true, "JSONL", "/RF-Lab");
    if (!path.length()) return;
    File file = fs->open(path, FILE_READ);
    if (!file || file.size() > 1024 * 1024) { displayError("Invalid event log", true); return; }
    // Read a bounded line: malformed files must not exhaust the ESP32 heap.
    auto readLine = [&file](String &line) {
        line = "";
        while (file.available()) {
            const char c = file.read();
            if (c == '\n') return true;
            if (line.length() >= 8192) return false;
            line += c;
        }
        return line.length() != 0;
    };
    String line;
    JsonDocument doc;
    if (!readLine(line) || deserializeJson(doc, line) ||
        doc["schema"].as<String>() != "bruce.rf-blackbox.v1") {
        displayError("Not a Black Box log", true); return;
    }
    ReceiveSettings settings;
    auto receiver = doc["receiver"];
    const unsigned mod = receiver["modulation_register"] | 255u;
    settings.frequencyMHz = receiver["frequency_mhz"] | 0.0f;
    settings.modulation = static_cast<uint8_t>(mod);
    settings.rateKBaud = receiver["requested_rate_kbaud"] | 0.0f;
    settings.bandwidthKHz = receiver["requested_rx_bandwidth_khz"] | 0.0f;
    if (mod > 2 || !RadioControl::validReceiveSettings(settings)) {
        displayError("Unsupported log receiver", true); return;
    }
    struct Event { uint32_t ms; int threshold; bool partial; };
    std::vector<Event> events;
    bool malformed = false;
    while (file.available()) {
        if (check(EscPress)) return;
        if (!readLine(line) || deserializeJson(doc, line)) { malformed = true; break; }
        if (!doc["event"].is<unsigned>()) continue;
        if (!doc["trigger_ms"].is<uint32_t>() || !doc["threshold_dbm"].is<int>()) {
            malformed = true; break;
        }
        const int threshold = doc["threshold_dbm"].as<int>();
        if (threshold < -127 || threshold > 0) { malformed = true; break; }
        if (events.size() == 8) events.erase(events.begin());
        events.push_back({doc["trigger_ms"].as<uint32_t>(), threshold, doc["partial"] | false});
        delay(1);
    }
    file.close();
    if (malformed) displayWarning("Log incomplete; showing valid events", true);
    if (events.empty()) { displayWarning("No saved events", true); return; }
    std::vector<Option> items;
    for (auto event : events) {
        items.push_back({String(event.ms) + "ms" + (event.partial ? " partial" : ""), [settings, event]() {
            selected = settings;
            gateDbm = event.threshold;
            std::vector<Option> actions = {
                {"Find profile LIVE (~75s)", finder},
                {"Monitor this frequency", blackBox},
                {"Back", []() {}},
            };
            loopOptions(actions, MENU_TYPE_SUBMENU, "Repeat signal required");
        }});
    }
    items.push_back({"Back", []() {}});
    loopOptions(items, MENU_TYPE_SUBMENU, "Last 8 events (uptime)");
}

void chooseFrequency() {
    std::vector<Option> items;
    for (float f : subghz_frequency_list) {
        ReceiveSettings checkSettings = selected; checkSettings.frequencyMHz = f;
        if (!RadioControl::validReceiveSettings(checkSettings)) continue;
        items.push_back({String(f, 3) + " MHz", [f]() { selected.frequencyMHz = f; frequencySelected = true; }});
    }
    loopOptions(items, MENU_TYPE_SUBMENU, "Monitor frequency");
}
} // namespace

void rfLabMenu() {
    if (!frequencySelected) {
        selected.frequencyMHz = bruceConfigPins.rfFreq;
        if (!RadioControl::validReceiveSettings(selected)) selected.frequencyMHz = 433.92f;
        frequencySelected = true;
    }
    while (true) {
        std::vector<Option> items = {
            {"Start Black Box (SD)", blackBox},
            {"Run Profile Finder", finder},
            {"Review events / Find profile", reviewEvents},
            {String("Frequency: ") + String(selected.frequencyMHz, 3), chooseFrequency},
            {String("Finder gate: ") + String(gateDbm) + " dBm", []() { gateDbm += 5; if (gateDbm > -30) gateDbm = -100; }},
            {"Load saved RX profile", loadProfile},
            {"Back", []() {}},
        };
        const int result = loopOptions(items, MENU_TYPE_SUBMENU, "RF Lab - CC1101 RX");
        if (result < 0 || result == int(items.size() - 1)) return;
    }
}
