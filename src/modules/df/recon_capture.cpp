#include "recon_capture.h"
#include "core/sd_functions.h"
#include <esp_timer.h>

namespace recon {
Capture capture;
void Capture::line(const String &text) {
    if (!file || file.println(text) != text.length() + 2) {
        failed = true;
        enabled = false;
    }
}
bool Capture::begin(const char *mode, const char *target) {
    end();
    failed = false;
    dropped = 0; truncated = 0; written = 0;
    if (!setupSdCard()) return false;
    if (!SD.exists("/BruceRecon") && !SD.mkdir("/BruceRecon")) return false;
    if (!queue) queue = xQueueCreate(32, sizeof(CaptureRow));
    if (!queue) return false;
    xQueueReset(queue);
    // Never overwrite a session, even after a reset with the same uptime.
    for (unsigned i = 1; i < 100000; ++i) {
        path = "/BruceRecon/session-" + String(i) + ".jsonl";
        if (!SD.exists(path)) break;
        path = "";
    }
    if (path.isEmpty()) return false;
    file = SD.open(path, FILE_WRITE);
    if (!file) return false;
    line(String("{\"type\":\"header\",\"schema\":1,\"firmware\":\"field-evolution-1\",\"mode\":\"") + mode +
         "\",\"target\":\"" + target + "\",\"clock\":\"monotonic_us\",\"payload_cap\":256}");
    enabled = !failed;
    lastFlush = millis();
    return enabled;
}
void Capture::push(const CaptureRow &row) {
    if (!enabled.load() || !queue) return;
    if (row.originalLength > row.length || row.dataStatus) ++truncated;
    if (xQueueSend(queue, &row, 0) != pdTRUE) ++dropped;
}
void Capture::drain(unsigned limit) {
    if (!queue || !file) return;
    CaptureRow row;
    while (limit-- && xQueueReceive(queue, &row, 0) == pdTRUE) {
        String out;
        out.reserve(900);
        char head[360];
        snprintf(head, sizeof(head),
            "{\"type\":\"observation\",\"us\":%llu,\"ms\":%lu,\"address\":\"%s\",\"address_type\":%u,\"rssi\":%d,\"mode\":%u,\"adv_type\":%u,\"adv_len\":%u,\"original_len\":%u,\"decision\":%u,\"score\":%u,\"sid\":%u,\"primary_phy\":%u,\"secondary_phy\":%u,\"data_status\":%u,\"payload\":\"",
            static_cast<unsigned long long>(row.us), static_cast<unsigned long>(row.ms), row.address,
            row.addressType, row.rssi, row.mode, row.advType, row.advLength, row.originalLength,
            row.decision, row.score, row.sid, row.primaryPhy, row.secondaryPhy, row.dataStatus);
        out += head;
        constexpr char hex[] = "0123456789abcdef";
        for (unsigned i = 0; i < row.length; ++i) { out += hex[row.payload[i] >> 4]; out += hex[row.payload[i] & 15]; }
        out += "\"}";
        line(out);
        if (failed) break;
        ++written;
    }
    if (millis() - lastFlush >= 1000) { file.flush(); lastFlush = millis(); }
}
void Capture::event(const char *kind, const char *detail) {
    if (!file) return;
    drain(32);
    // Internal event names only; escape user-visible text if callers later accept arbitrary input.
    String safe(detail);
    safe.replace("\\", "\\\\"); safe.replace("\"", "\\\""); safe.replace("\n", "\\n"); safe.replace("\r", "\\r");
    line(String("{\"type\":\"event\",\"us\":") + String(static_cast<unsigned long long>(esp_timer_get_time())) +
         ",\"kind\":\"" + kind + "\",\"detail\":\"" + safe + "\",\"dropped\":" + String(dropped.load()) + "}");
}
void Capture::end() {
    enabled = false;
    if (!file) return;
    drain(32);
    line(String("{\"type\":\"footer\",\"written\":") + written + ",\"dropped\":" + dropped.load() +
         ",\"truncated\":" + truncated.load() + ",\"write_error\":" + (failed ? "true" : "false") + "}");
    file.flush(); file.close();
}
String Capture::status() const {
    if (failed) return "SD WRITE ERROR";
    if (!enabled.load()) return "REC OFF / no SD";
    return "REC " + String(written) + " DROP " + String(dropped.load()) + " TRUNC " + String(truncated.load());
}
}
