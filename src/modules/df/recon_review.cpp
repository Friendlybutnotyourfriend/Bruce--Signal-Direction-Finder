#include "ble_recon_v3.h"
#include "recon_core.h"
#include "core/display.h"
#include "core/utils.h"
#include "core/sd_functions.h"
#include "modules/ble/ble_common.h"
#include <ArduinoJson.h>
#include <globals.h>

namespace {
recon::Association replayEngine; // Keep the multi-format model off the Arduino task stack.
struct Summary {
    char target[18]{};
    uint32_t reports = 0, selected = 0, handoffs = 0, dropped = 0, truncated = 0, errors = 0;
    uint32_t levels[128]{};
    bool footer = false;
    float median() const {
        uint32_t count = 0;
        if (!selected) return -127;
        for (unsigned i = 0; i < 128; ++i) { count += levels[i]; if (count > selected / 2) return static_cast<int>(i) - 127; }
        return -127;
    }
};
bool readRow(File &file, JsonDocument &row, bool &valid) {
    if (!file.available()) return false;
    char line[1100]; unsigned size = 0; bool overflow = false;
    while (file.available()) {
        const int c = file.read();
        if (c == '\n') break;
        if (size < sizeof(line) - 1) line[size++] = static_cast<char>(c);
        else overflow = true;
    }
    line[size] = 0;
    row.clear();
    valid = !overflow && !deserializeJson(row, line);
    return true;
}
void screen(const String &title, const std::vector<String> &lines) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextSize(1); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawString(title, 4, 5);
    int y = 26;
    for (const auto &line : lines) { if (y > tftHeight - 22) break; tft.drawString(line, 4, y); y += 14; }
    tft.drawString("SEL next / turn autoplay / ESC back", 4, tftHeight - 14);
}
bool packet(const JsonDocument &row, recon::Packet &p, uint8_t *bytes) {
    const char *address = row["address"] | "";
    const char *hex = row["payload"] | "";
    const size_t len = std::strlen(hex);
    if (std::strlen(address) != 17 || len > 512 || len % 2) return false;
    std::strncpy(p.address, address, 17);
    p.ms = row["ms"] | 0u; p.addressType = row["address_type"] | 0;
    p.rssi = row["rssi"] | -127;
    if (p.addressType > 3 || p.rssi < -127 || p.rssi > 20) return false;
    auto digit = [](char c) -> int { if (c >= '0' && c <= '9') return c-'0'; if (c >= 'a' && c <= 'f') return c-'a'+10; if (c >= 'A' && c <= 'F') return c-'A'+10; return -1; };
    for (size_t i = 0; i < len; i += 2) {
        const int a = digit(hex[i]), b = digit(hex[i+1]);
        if (a < 0 || b < 0) return false;
        bytes[i/2] = (a << 4) | b;
    }
    const unsigned adv = row["adv_len"] | 0;
    p.payload = bytes; p.length = adv ? std::min<size_t>(adv, len/2) : len/2;
    p.response = (row["adv_type"] | 0) == 4;
    p.truncated = (row["original_len"] | 0u) > len/2 || (row["data_status"] | 0) != 0;
    return true;
}
bool review(const String &path, bool replay, Summary &summary) {
    File file = SD.open(path, FILE_READ);
    if (!file) return false;
    JsonDocument row;
    bool valid, initialized = false, automatic = false, header = false;
    unsigned lines = 0;
    while (readRow(file, row, valid)) {
        if (check(EscPress)) { file.close(); return false; }
        if (++lines > 100000) { ++summary.errors; break; }
        if (!valid) { ++summary.errors; continue; }
        const String type = row["type"] | "";
        if (!header) {
            if (type != "header" || (row["schema"] | 0) != 1) { displayWarning("Unsupported session", true); return false; }
            std::strncpy(summary.target, row["target"] | "", 17); header = true;
            continue;
        }
        if (type == "footer") {
            summary.footer = true; summary.dropped = row["dropped"] | 0u;
            summary.truncated = row["truncated"] | 0u;
            if (row["write_error"] | false) ++summary.errors;
        }
        if (replay && initialized && type == "event") {
            const String kind = row["kind"] | "";
            const uint32_t time = (row["us"].as<uint64_t>() / 1000) & 0xffffffff;
            if (kind == "resume") replayEngine.resume(time);
            if (kind == "lock_toggle") replayEngine.lock(!replayEngine.status(time).locked);
            if (kind == "undo") replayEngine.undo(time);
        }
        if (type != "observation") continue;
        uint8_t bytes[256]; recon::Packet p;
        if (!packet(row, p, bytes)) { ++summary.errors; continue; }
        ++summary.reports;
        const unsigned recorded = row["decision"] | 0;
        if (recorded == 1 || recorded == 3) {
            ++summary.selected;
            ++summary.levels[std::max(0, std::min(127, p.rssi + 127))];
        }
        if (recorded == 3) ++summary.handoffs;
        if (!replay) { if (lines % 100 == 0) delay(1); continue; }
        if (!initialized) {
            if (std::strncmp(summary.target, p.address, 17)) continue;
            replayEngine.reset(p); initialized = true;
        }
        const auto decision = replayEngine.observe(p);
        if (decision == recon::Decision::Ignore) continue;
        const auto status = replayEngine.status(p.ms);
        screen("SESSION REPLAY / radios off", {
            String(p.ms) + " ms " + p.address, "RSSI " + String(p.rssi) + " dBm",
            "Decision " + String(static_cast<unsigned>(decision)) + " / recorded " + String(recorded),
            "Evidence " + String(status.score) + " hits " + String(status.hits),
            "Handoffs " + String(status.handoffs),
            automatic ? "Autoplay (turn to pause)" : "Paused (Select steps report)"
        });
        const uint32_t shown = millis();
        while (true) {
            if (check(EscPress)) { file.close(); return false; }
            if (check(NextPress) || check(PrevPress)) { automatic = !automatic; break; }
            if (check(SelPress) || (automatic && millis() - shown > 100)) break;
            delay(10);
        }
    }
    file.close();
    return header;
}
void showSummary(const Summary &a, const Summary *b = nullptr) {
    std::vector<String> lines;
    lines.push_back(String("A ") + a.target + " " + String(a.median(), 1) + " dBm");
    lines.push_back("A selected " + String(a.selected) + " total " + String(a.reports));
    lines.push_back("A drop " + String(a.dropped) + " trunc " + String(a.truncated) + " errors " + String(a.errors));
    if (!a.footer) lines.push_back("A INCOMPLETE / no footer");
    if (b) {
        lines.push_back(String("B ") + b->target + " " + String(b->median(), 1) + " dBm");
        lines.push_back("B selected " + String(b->selected) + " drop " + String(b->dropped));
        lines.push_back("B trunc " + String(b->truncated) + " errors " + String(b->errors));
        if (!b->footer) lines.push_back("B INCOMPLETE / no footer");
        lines.push_back(a.selected && b->selected ? "B-A median " + String(b->median()-a.median(),1) + " dB" : "Insufficient selected reports");
    }
    screen(b ? "COMPARE / recorded target hypotheses" : "SESSION SUMMARY", lines);
    while (!check(EscPress) && !check(SelPress)) delay(20);
}
}

void bleSessionReview() {
    stopBLEStack();
    if (!setupSdCard()) { displayWarning("Insert SD card", true); return; }
    int action = -1;
    std::vector<Option> choices = {
        {"Replay session", [&]() { action = 0; }},
        {"Compare two sessions", [&]() { action = 1; }},
        {"Session summary", [&]() { action = 2; }}
    };
    loopOptions(choices, MENU_TYPE_REGULAR, "Recorded BLE sessions", 0, false);
    if (action < 0) return;
    const String path = loopSD(SD, true, "JSONL", "/BruceRecon");
    if (path.isEmpty()) return;
    Summary a, b;
    if (!review(path, action == 0, a)) return;
    if (action == 1) {
        const String other = loopSD(SD, true, "JSONL", "/BruceRecon");
        if (other.isEmpty() || !review(other, false, b)) return;
        showSummary(a, &b);
    } else showSummary(a);
}
