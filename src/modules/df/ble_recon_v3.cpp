#include "ble_recon_v3.h"
#include "recon_core.h"
#include "recon_capture.h"
#include "modules/others/audio.h"
#include <esp_timer.h>

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_common.h"
#include <globals.h>
#include <NimBLERemoteDescriptor.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

namespace {

// Temporary hardware-test telemetry. Each caller owns its timer on its own task.
// ESP-IDF reports the task stack high-water mark in bytes.
void logReconMemory(const char *context, uint32_t &lastLog) {
    const uint32_t now = millis();
    if (static_cast<uint32_t>(now - lastLog) < 60000) return;
    lastLog = now;
    Serial.printf(
        "[BLE-RECON] %s uptime_ms=%lu free_heap=%lu largest_free_block=%lu stack_hwm_bytes=%lu\n",
        context,
        static_cast<unsigned long>(now),
        static_cast<unsigned long>(heap_caps_get_free_size(MALLOC_CAP_8BIT)),
        static_cast<unsigned long>(heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
        static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr))
    );
}

constexpr uint32_t DISCOVERY_MS = 5000;
constexpr size_t MAX_PAYLOAD = 256;
constexpr size_t MAX_RESPONSE = 128;
constexpr size_t MAX_NAME = 40;
constexpr size_t MAX_HISTORY = 8;
constexpr size_t MAX_LINES = 180;
constexpr size_t MAX_GATT_LINES = 220;
#if defined(CONFIG_BT_NIMBLE_EXT_ADV) && CONFIG_BT_NIMBLE_EXT_ADV
#define BLE_RECON_EXT_ADV 1
#endif
enum IdentitySource : uint8_t { ID_MAC = 0, ID_NAME = 1, ID_MFG = 2 };

struct BleObservation {
    char address[18]{};
    uint8_t addressType = 0;
    char name[MAX_NAME + 1]{};
    int rssi = -127;
    uint8_t advType = 0;
    bool connectable = false;
    bool scannable = false;
    uint8_t payload[MAX_PAYLOAD]{};
    uint16_t payloadLen = 0;
    uint16_t originalLen = 0;
    uint16_t advLen = 0;
    uint8_t response[MAX_RESPONSE]{};
    uint16_t responseLen = 0;
    uint16_t companyId = 0;
    uint16_t appearance = 0;
    bool hasAppearance = false;
    int8_t txPower = 0;
    bool hasTxPower = false;
    uint32_t fullHash = 0;
    uint32_t shapeHash = 0;
    uint32_t serviceHash = 0;
    bool hasFcf1 = false;
    uint8_t fcf1[32]{};
    uint8_t fcf1Len = 0;
#ifdef BLE_RECON_EXT_ADV
    bool legacy = true;
    uint8_t sid = 0xFF;
    uint8_t primaryPhy = 0;
    uint8_t secondaryPhy = 0;
    uint16_t periodicInterval = 0;
    uint8_t dataStatus = 0;
#endif
};
struct FingerprintModel {
    uint8_t baseline[MAX_PAYLOAD]{};
    uint8_t last[MAX_PAYLOAD]{};
    bool stable[MAX_PAYLOAD]{};
    uint16_t len = 0;
    uint32_t observations = 0;
    bool valid = false;
};
struct HunterState {
    BleObservation target;
    FingerprintModel model;
    char currentName[MAX_NAME + 1]{};
    char history[MAX_HISTORY][18]{};
    uint8_t historyCount = 0;
    uint8_t identitySource = ID_MAC;
    float fastRssi = -127;
    float stableRssi = -127;
    float bestRssi = -127;
    float trend = 0;
    float jitter = 0;
    float pps = 0;
    float gapEma = 0;
    uint32_t samples = 0;
    uint32_t lastSeen = 0;
    uint32_t lastPacket = 0;
    uint32_t rateStart = 0;
    uint32_t ratePackets = 0;
    uint32_t handoffNotice = 0;
    uint32_t reacquireNotice = 0;
    uint32_t offlineMs = 0;
    uint16_t handoffs = 0;
    uint16_t reacquisitions = 0;
    uint8_t lastHandoffScore = 0;
    bool initialized = false;
};
struct MutationModel {
    uint8_t baseline[MAX_PAYLOAD]{};
    uint8_t last[MAX_PAYLOAD]{};
    uint8_t changeHits[MAX_PAYLOAD]{};
    uint8_t counterHits[MAX_PAYLOAD]{};
    bool volatileMask[MAX_PAYLOAD]{};
    uint16_t len = 0;
    uint32_t observations = 0;
    uint32_t changes = 0;
    uint16_t lastChanged = 0;
    uint8_t lastDiff[MAX_PAYLOAD]{};
    uint16_t lastDiffLen = 0;
    bool valid = false;
};
struct Fcf1Tracker {
    bool seen = false;
    uint8_t payload[32]{};
    uint8_t len = 0;
    uint32_t firstSeen = 0;
    uint32_t lastSeen = 0;
    uint32_t count = 0;
    uint32_t macChanges = 0;
    uint32_t payloadChanges = 0;
    uint32_t correlated = 0;
    uint32_t macOnly = 0;
    uint32_t payloadOnly = 0;
    char currentAddress[18]{};
    char previousAddress[18]{};
    uint8_t addressType = 0;
};
struct SnifferState {
    BleObservation target;
    MutationModel mutation;
    Fcf1Tracker fcf1;
    uint32_t packets = 0;
    recon::Signature decoded;
    uint8_t fieldChanges = 0;
    uint32_t lastSeen = 0;
    uint32_t rateStart = 0;
    uint32_t ratePackets = 0;
    float pps = 0;
    float gapEma = 0;
    uint8_t response[MAX_RESPONSE]{};
    uint16_t responseLen = 0;
    uint32_t activeBursts = 0;
    uint32_t activeReports = 0;
    uint32_t activeResponses = 0;
    bool activeComplete = false;
    bool initialized = false;
};
struct GattResult {
    bool connected = false;
    bool discovered = false;
    String error;
    uint16_t services = 0;
    uint16_t characteristics = 0;
    uint16_t descriptors = 0;
    uint16_t readable = 0;
    uint16_t writable = 0;
    uint16_t notify = 0;
    uint16_t indicate = 0;
    std::vector<String> serviceLines;
    std::vector<String> tree;
    bool truncated = false;
};
class MedianWindow {
public:
    void reset() {
        values.fill(-127);
        count = index = 0;
    }
    void add(int v) {
        values[index] = v;
        index = (index + 1) % values.size();
        if (count < values.size()) count++;
    }
    float median() const {
        if (!count) return -127;
        auto s = values;
        std::sort(s.begin(), s.begin() + count);
        return (count & 1) ? static_cast<float>(s[count / 2]) : (s[count / 2 - 1] + s[count / 2]) / 2.0f;
    }

private:
    std::array<int, 7> values{};
    size_t count = 0, index = 0;
};
portMUX_TYPE reconMux = portMUX_INITIALIZER_UNLOCKED;
HunterState hunterState;
SnifferState snifferState;
MedianWindow medianWindow;
char selectedAddress[18]{};
bool activeBurst = false;
// UI snapshots stay off the Arduino task stack; callbacks update state under reconMux.
HunterState uiHunterSnap;
SnifferState uiSnifferSnap;
SnifferState uiFrozenSnap;
template <typename T> void reinit(T &x) {
    x.~T();
    new (&x) T();
}
void updateFingerprint(FingerprintModel &, const BleObservation &);
recon::Association association;
BleObservation previousTarget;
recon::Status associationStatus() {
    portENTER_CRITICAL(&reconMux);
    const auto status = association.status(millis());
    portEXIT_CRITICAL(&reconMux);
    return status;
}
recon::Packet packet(const BleObservation &o, uint32_t now) {
    recon::Packet p;
    p.ms = now;
    std::memcpy(p.address, o.address, 18);
    p.addressType = o.addressType;
    p.rssi = o.rssi;
    p.payload = o.payload;
    p.length = o.advLen ? o.advLen : o.payloadLen;
    p.response = o.advType == 4;
    p.truncated = o.originalLen > o.payloadLen;
#ifdef BLE_RECON_EXT_ADV
    p.truncated = p.truncated || o.dataStatus != 0;
#endif
    return p;
}
recon::Decision associate(const BleObservation &o, uint32_t now) {
    const auto p = packet(o, now);
    portENTER_CRITICAL(&reconMux);
    const auto result = association.observe(p);
    const auto state = association.status(now);
    const bool active = activeBurst;
    portEXIT_CRITICAL(&reconMux);
    recon::CaptureRow row;
    row.us = esp_timer_get_time(); row.ms = now;
    std::memcpy(row.address, o.address, 18);
    row.addressType = o.addressType; row.rssi = o.rssi;
    row.advType = o.advType; row.mode = active ? 1 : 0;
    row.length = o.payloadLen; row.originalLength = o.originalLen; row.advLength = o.advLen;
    row.decision = static_cast<uint8_t>(result); row.score = state.score;
    std::memcpy(row.payload, o.payload, o.payloadLen);
#ifdef BLE_RECON_EXT_ADV
    row.sid = o.sid; row.primaryPhy = o.primaryPhy; row.secondaryPhy = o.secondaryPhy; row.dataStatus = o.dataStatus;
#endif
    recon::capture.push(row);
    return result;
}
void resetAssociation(const BleObservation &o) {
    portENTER_CRITICAL(&reconMux);
    association.reset(packet(o, millis()));
    reinit(previousTarget);
    portEXIT_CRITICAL(&reconMux);
}
String matchStatus() {
    const auto a = associationStatus();
    if (a.ambiguous) return "AMBIGUOUS " + String(a.score) + "/100 " + String(a.hits) + " hits";
    if (millis() - a.lastSeen > a.timeout) return "LOST (wait " + String(a.timeout / 1000) + "s)";
    return a.locked ? "ADDRESS LOCKED" : a.tentative ? "STRONG MATCH - HYPOTHESIS" : "SELECTED ADDRESS";
}
void undoAssociation(bool hunter) {
    // Called only while scanning is stopped.
    if (!association.undo(millis()) || !previousTarget.address[0]) {
        displayWarning("No address change to undo", true); return;
    }
    if (hunter) {
        hunterState.target = previousTarget;
        std::strncpy(hunterState.currentName, previousTarget.name, MAX_NAME);
        reinit(hunterState.model); updateFingerprint(hunterState.model, previousTarget);
        hunterState.initialized = false;
        medianWindow.reset();
    } else {
        snifferState.target = previousTarget;
        reinit(snifferState.mutation);
    }
    std::memcpy(selectedAddress, previousTarget.address, 18);
    recon::capture.event("undo", previousTarget.address);
}
uint32_t fnv1a(const uint8_t *d, size_t n, uint32_t h = 2166136261UL) {
    for (size_t i = 0; i < n; i++) {
        h ^= d[i];
        h *= 16777619UL;
    }
    return h;
}
uint16_t le16(const uint8_t *p) { return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8); }
String hexBytes(const uint8_t *d, size_t n, size_t max = 32, bool spaces = false) {
    const size_t c = std::min(n, max);
    String o;
    o.reserve(c * (spaces ? 3 : 2) + 3);
    char b[4];
    for (size_t i = 0; i < c; i++) {
        std::snprintf(b, sizeof(b), spaces ? "%02X " : "%02X", d[i]);
        o += b;
    }
    if (spaces && !o.isEmpty()) o.remove(o.length() - 1);
    if (n > c) o += "..";
    return o;
}
String cleanText(const uint8_t *d, size_t n) {
    const size_t c = std::min(n, MAX_NAME);
    String o;
    o.reserve(c);
    for (size_t i = 0; i < c; i++) {
        if (d[i] == 0) break;
        o += (d[i] >= 0x20 && d[i] < 0x7F) ? static_cast<char>(d[i]) : '.';
    }
    o.trim();
    return o;
}
String cleanText(const std::string &s) {
    return cleanText(reinterpret_cast<const uint8_t *>(s.data()), s.size());
}
void copyAddress(char *d, const std::string &s) {
    std::memset(d, 0, 18);
    std::strncpy(d, s.c_str(), 17);
}
void copyName(char *d, const String &s) {
    std::memset(d, 0, MAX_NAME + 1);
    std::strncpy(d, s.c_str(), MAX_NAME);
}
String addressTypeName(uint8_t type, const char *address) {
    if (!address || !address[0]) return "UNKNOWN";
    NimBLEAddress a(std::string(address), type);
    if (a.isPublic()) return "PUBLIC";
    if (a.isRpa()) return "RPA";
    if (a.isNrpa()) return "NRPA";
    if (a.isStatic()) return "STATIC";
    return "RANDOM";
}
String addressTypeName(const BleObservation &o) { return addressTypeName(o.addressType, o.address); }
const char *companyName(uint16_t id) {
    switch (id) {
        case 0x0006: return "Microsoft";
        case 0x004C: return "Apple";
        case 0x0057: return "Harman";
        case 0x0075: return "Samsung";
        case 0x0087: return "Garmin";
        case 0x009E: return "Bose";
        case 0x00E0: return "Google";
        case 0x012D: return "Sony";
        case 0x0131: return "Cypress";
        case 0x0157: return "Xiaomi";
        case 0x0499: return "Ruuvi";
        default: return nullptr;
    }
}
const char *serviceName(uint16_t id) {
    switch (id) {
        case 0x1800: return "Generic Access";
        case 0x1801: return "Generic Attribute";
        case 0x180A: return "Device Information";
        case 0x180D: return "Heart Rate";
        case 0x180F: return "Battery";
        case 0x1812: return "HID";
        case 0x1816: return "Cycling Speed/Cadence";
        case 0x181A: return "Environmental Sensing";
        case 0x181D: return "Weight Scale";
        case 0xFE2C: return "Google Fast Pair";
        case 0xFEAA: return "Eddystone";
        case 0xFD6F: return "Exposure Notification";
        case 0xFCF1: return "Google Service (FCF1)";
        default: return nullptr;
    }
}
const char *characteristicName(uint16_t id) {
    switch (id) {
        case 0x2A00: return "Device Name";
        case 0x2A01: return "Appearance";
        case 0x2A19: return "Battery Level";
        case 0x2A24: return "Model Number";
        case 0x2A25: return "Serial Number";
        case 0x2A26: return "Firmware Revision";
        case 0x2A27: return "Hardware Revision";
        case 0x2A29: return "Manufacturer Name";
        case 0x2A37: return "Heart Rate Measurement";
        case 0x2A4D: return "HID Report";
        default: return nullptr;
    }
}
String uuid16Label(uint16_t id) {
    String s = "0x" + String(id, HEX);
    s.toUpperCase();
    if (const char *n = serviceName(id)) s += " " + String(n);
    return s;
}
String appearanceName(uint16_t a) {
    switch (a >> 6) {
        case 1: return "Phone";
        case 2: return "Computer";
        case 3: return "Watch";
        case 4: return "Clock";
        case 5: return "Display";
        case 6: return "Remote";
        case 8: return "Tag";
        case 9: return "Keyring";
        case 10: return "Media player";
        case 11: return "Barcode scanner";
        case 12: return "Thermometer";
        case 13: return "Heart-rate sensor";
        case 15: return "HID";
        case 18: return "Cycling sensor";
        case 49: return "Pulse oximeter";
        case 50: return "Weight scale";
        default: return "Unknown";
    }
}
String adTypeName(uint8_t t) {
    switch (t) {
        case 1: return "Flags";
        case 2: return "16-bit UUIDs (some)";
        case 3: return "16-bit UUIDs";
        case 4: return "32-bit UUIDs (some)";
        case 5: return "32-bit UUIDs";
        case 6: return "128-bit UUIDs (some)";
        case 7: return "128-bit UUIDs";
        case 8: return "Short name";
        case 9: return "Complete name";
        case 10: return "TX power";
        case 18: return "Connection interval";
        case 22: return "16-bit service data";
        case 25: return "Appearance";
        case 32: return "32-bit service data";
        case 33: return "128-bit service data";
        case 36: return "URI";
        case 255: return "Manufacturer data";
        default: return "Unknown field";
    }
}
void appendWrapped(std::vector<String> &lines, const String &text, size_t width = 28) {
    String s = text;
    s.trim();
    while (s.length() > width && lines.size() < MAX_LINES) {
        int p = width;
        while (p > 8 && s.charAt(p) != ' ') p--;
        if (p <= 8) p = width;
        lines.push_back(s.substring(0, p));
        s = s.substring(p);
        s.trim();
    }
    if (!s.isEmpty() && lines.size() < MAX_LINES) lines.push_back(s);
}

void parseAdFields(const uint8_t *payload, size_t length, std::vector<String> *lines, BleObservation *obs) {
    size_t off = 0;
    while (off < length) {
        const uint8_t fl = payload[off];
        if (!fl) break;
        const size_t end = off + static_cast<size_t>(fl) + 1;
        if (fl < 1 || end > length) {
            if (lines) appendWrapped(*lines, "MALFORMED field at byte " + String(off));
            break;
        }
        const uint8_t type = payload[off + 1];
        const uint8_t *data = payload + off + 2;
        const size_t dl = fl - 1;
        if (obs) {
            if ((type == 8 || type == 9) && dl && !obs->name[0]) copyName(obs->name, cleanText(data, dl));
            if (type == 25 && dl >= 2) {
                obs->appearance = le16(data);
                obs->hasAppearance = true;
            }
            if (type == 10 && dl) {
                obs->txPower = static_cast<int8_t>(data[0]);
                obs->hasTxPower = true;
            }
            if (type == 255 && dl >= 2 && !obs->companyId) obs->companyId = le16(data);
        }
        if (lines) {
            appendWrapped(*lines, "AD 0x" + String(type, HEX) + " " + String(adTypeName(type)));
            switch (type) {
                case 2:
                case 3:
                    for (size_t i = 0; i + 1 < dl; i += 2)
                        appendWrapped(*lines, "  UUID " + uuid16Label(le16(data + i)));
                    break;
                case 6:
                case 7: appendWrapped(*lines, "  UUID128: " + hexBytes(data, dl, 32, true)); break;
                case 8:
                case 9: appendWrapped(*lines, "  Name: " + cleanText(data, dl)); break;
                case 10:
                    if (dl)
                        appendWrapped(*lines, "  TX power: " + String(static_cast<int8_t>(data[0])) + " dBm");
                    break;
                case 18:
                    if (dl >= 4)
                        appendWrapped(
                            *lines,
                            "  Conn: " + String(le16(data) * 1.25f, 1) + "-" +
                                String(le16(data + 2) * 1.25f, 1) + " ms"
                        );
                    break;
                case 22:
                    if (dl >= 2) {
                        const uint16_t u = le16(data);
                        appendWrapped(*lines, "  Service: " + uuid16Label(u));
                        if (u == 0xFCF1)
                            appendWrapped(*lines, "  FCF1 payload: " + hexBytes(data + 2, dl - 2, 32, true));
                        else if (dl > 2)
                            appendWrapped(*lines, "  Data: " + hexBytes(data + 2, dl - 2, 32, true));
                    }
                    break;
                case 25:
                    if (dl >= 2) appendWrapped(*lines, "  Appearance: " + appearanceName(le16(data)));
                    break;
                case 32:
                    if (dl >= 4) appendWrapped(*lines, "  Service UUID32: " + hexBytes(data, 4, 4, true));
                    break;
                case 33:
                    if (dl >= 16) appendWrapped(*lines, "  Service UUID128: " + hexBytes(data, 16, 16, true));
                    break;
                case 36: appendWrapped(*lines, "  URI/data: " + hexBytes(data, dl, 32, true)); break;
                case 255:
                    if (dl >= 2)
                        appendWrapped(
                            *lines,
                            "  Company: " +
                                String(companyName(le16(data)) ? companyName(le16(data)) : "Unlisted") +
                                " (0x" + String(le16(data), HEX) + ")"
                        );
                    if (dl > 2) appendWrapped(*lines, "  Data: " + hexBytes(data + 2, dl - 2, 32, true));
                    break;
                default: appendWrapped(*lines, "  Data: " + hexBytes(data, dl, 32, true)); break;
            }
        }
        off = end;
    }
}

uint32_t shapeHash(const uint8_t *payload, size_t length) {
    uint32_t h = 2166136261UL;
    size_t off = 0;
    while (off < length) {
        const uint8_t fl = payload[off];
        if (!fl) break;
        const size_t end = off + static_cast<size_t>(fl) + 1;
        if (fl < 1 || end > length) break;
        const uint8_t type = payload[off + 1];
        h = fnv1a(&fl, 1, h);
        h = fnv1a(&type, 1, h);
        if (type == 255 && fl >= 3) h = fnv1a(payload + off + 2, std::min<size_t>(4, fl - 1), h);
        else if ((type >= 2 && type <= 7) || type == 22 || type == 32 || type == 33) {
            const size_t n =
                type == 22 ? std::min<size_t>(2, fl - 1) : std::min<size_t>(type == 32 ? 4 : 16, fl - 1);
            h = fnv1a(payload + off + 2, n, h);
        }
        off = end;
    }
    return h;
}

void fillObservation(const NimBLEAdvertisedDevice *device, BleObservation &o) {
    o = BleObservation{};
    if (!device) return;
    copyAddress(o.address, device->getAddress().toString());
    o.addressType = device->getAddressType();
    o.rssi = device->getRSSI();
    o.advType = device->getAdvType();
    o.connectable = device->isConnectable();
    o.scannable = device->isScannable();
    const std::vector<uint8_t> &p = device->getPayload();
    const size_t n = std::min(p.size(), MAX_PAYLOAD);
    o.payloadLen = n;
    o.originalLen = std::min<size_t>(p.size(), 65535);
    o.advLen = std::min<size_t>(device->getAdvLength(), n);
    if (n) std::memcpy(o.payload, p.data(), n);
    if (!p.empty()) o.fullHash = fnv1a(p.data(), p.size());
    if (n) o.shapeHash = shapeHash(o.payload, n);
    String name = cleanText(device->getName());
    if (!name.isEmpty()) copyName(o.name, name);
    parseAdFields(o.payload, o.payloadLen, nullptr, &o);
    if (device->haveManufacturerData()) {
        const std::string m = device->getManufacturerData();
        if (m.size() >= 2) o.companyId = le16(reinterpret_cast<const uint8_t *>(m.data()));
    }
    uint32_t sh = 2166136261UL;
    for (uint8_t i = 0; i < device->getServiceUUIDCount(); i++) {
        const std::string u = device->getServiceUUID(i).toString();
        sh = fnv1a(reinterpret_cast<const uint8_t *>(u.data()), u.size(), sh);
    }
    for (uint8_t i = 0; i < device->getServiceDataCount(); i++) {
        const std::string u = device->getServiceDataUUID(i).toString();
        const std::string d = device->getServiceData(i);
        sh = fnv1a(reinterpret_cast<const uint8_t *>(u.data()), u.size(), sh);
        const uint16_t dl = static_cast<uint16_t>(std::min<size_t>(d.size(), 0xFFFF));
        sh = fnv1a(reinterpret_cast<const uint8_t *>(&dl), sizeof(dl), sh);
        String us(u.c_str());
        us.toLowerCase();
        if (us == "fcf1" || us == "0000fcf1-0000-1000-8000-00805f9b34fb") {
            o.hasFcf1 = true;
            o.fcf1Len = std::min<size_t>(d.size(), sizeof(o.fcf1));
            if (o.fcf1Len) std::memcpy(o.fcf1, d.data(), o.fcf1Len);
        }
    }
    o.serviceHash = (device->getServiceUUIDCount() || device->getServiceDataCount()) ? sh : 0;
    o.hasTxPower = device->haveTXPower();
    o.txPower = o.hasTxPower ? device->getTXPower() : 0;
    o.hasAppearance = device->haveAppearance();
    o.appearance = o.hasAppearance ? device->getAppearance() : 0;
#ifdef BLE_RECON_EXT_ADV
    o.legacy = device->isLegacyAdvertisement();
    if (!o.legacy) {
        o.sid = device->getSetId();
        o.primaryPhy = device->getPrimaryPhy();
        o.secondaryPhy = device->getSecondaryPhy();
        o.periodicInterval = device->getPeriodicInterval();
        o.dataStatus = device->getDataStatus();
    }
#endif
}
String resolvedIdentity(const BleObservation &o, uint8_t &source) {
    if (o.name[0]) {
        source = ID_NAME;
        return String(o.name);
    }
    if (const char *m = companyName(o.companyId)) {
        source = ID_MFG;
        return String(m) + " device";
    }
    source = ID_MAC;
    return String();
}
void updateFingerprint(FingerprintModel &m, const BleObservation &o) {
    if (!o.payloadLen) return;
    if (!m.valid) {
        std::memcpy(m.baseline, o.payload, o.payloadLen);
        std::memcpy(m.last, o.payload, o.payloadLen);
        for (size_t i = 0; i < o.payloadLen; i++) m.stable[i] = true;
        m.len = o.payloadLen;
        m.observations = 1;
        m.valid = true;
        return;
    }
    const size_t n = std::min<size_t>(m.len, o.payloadLen);
    for (size_t i = 0; i < n; i++) {
        if (m.last[i] != o.payload[i]) m.stable[i] = false;
        m.last[i] = o.payload[i];
    }
    if (o.payloadLen > m.len) {
        for (size_t i = m.len; i < o.payloadLen; i++) {
            m.baseline[i] = o.payload[i];
            m.last[i] = o.payload[i];
            m.stable[i] = false;
        }
        m.len = o.payloadLen;
    }
    m.observations++;
}
void pushHistory(HunterState &s, const char *a) {
    if (!a || !a[0]) return;
    if (s.historyCount < MAX_HISTORY) {
        std::strncpy(s.history[s.historyCount], a, 17);
        s.history[s.historyCount++][17] = '\0';
        return;
    }
    for (size_t i = 1; i < MAX_HISTORY; i++) std::strncpy(s.history[i - 1], s.history[i], 17);
    std::strncpy(s.history[MAX_HISTORY - 1], a, 17);
    s.history[MAX_HISTORY - 1][17] = '\0';
}
class HunterCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device) return;
        BleObservation o;
        fillObservation(device, o);
        const uint32_t now = millis();
        const auto decision = associate(o, now);
        if (decision != recon::Decision::Current && decision != recon::Decision::Handoff) return;
        if (o.advType == 4) return;
        const auto match = associationStatus();
        medianWindow.add(o.rssi);
        const float med = medianWindow.median();
        portENTER_CRITICAL(&reconMux);
        auto &s = hunterState;
        const bool moved = decision == recon::Decision::Handoff;
        const bool lost = s.initialized && now - s.lastSeen > match.timeout;
        if (moved) {
            previousTarget = s.target;
            pushHistory(s, s.target.address);
            ++s.handoffs;
            s.lastHandoffScore = match.score;
            s.handoffNotice = now;
            reinit(s.model);
        }
        if (moved || lost || !s.initialized) {
            if (lost) { ++s.reacquisitions; s.offlineMs = now - s.lastSeen; s.reacquireNotice = now; }
            medianWindow.reset(); medianWindow.add(o.rssi);
            s.fastRssi = s.stableRssi = s.bestRssi = o.rssi;
            s.trend = s.jitter = 0; s.samples = 0;
        } else {
            s.fastRssi += .45f * (med - s.fastRssi);
            s.stableRssi += .14f * (med - s.stableRssi);
            s.trend = s.fastRssi - s.stableRssi;
            s.jitter += .18f * (fabsf(o.rssi - s.fastRssi) - s.jitter);
        }
        updateFingerprint(s.model, o);
        s.target = o;
        if (o.name[0]) { std::strncpy(s.currentName, o.name, MAX_NAME); s.identitySource = ID_NAME; }
        if (s.lastPacket && now - s.lastPacket < 60000)
            s.gapEma = s.gapEma == 0 ? now - s.lastPacket : s.gapEma + .18f * (now - s.lastPacket - s.gapEma);
        s.lastSeen = s.lastPacket = now;
        s.initialized = true; ++s.samples; ++s.ratePackets;
        s.bestRssi = std::max(s.bestRssi, s.stableRssi);
        if (now - s.rateStart >= 1000) {
            s.pps = s.ratePackets * 1000.f / (now - s.rateStart);
            s.ratePackets = 0; s.rateStart = now;
        }
        portEXIT_CRITICAL(&reconMux);
    }
};
HunterCallbacks hunterCallbacks;
void resetHunter(const BleObservation &t) {
    portENTER_CRITICAL(&reconMux);
    reinit(hunterState);
    hunterState.target = t;
    uint8_t src = ID_MAC;
    const String id = resolvedIdentity(t, src);
    if (!id.isEmpty()) copyName(hunterState.currentName, id);
    hunterState.identitySource = src;
    updateFingerprint(hunterState.model, t);
    std::strncpy(selectedAddress, t.address, 17);
    selectedAddress[17] = '\0';
    portEXIT_CRITICAL(&reconMux);
    medianWindow.reset();
}
void hunterSnapshot(HunterState &s) {
    portENTER_CRITICAL(&reconMux);
    s = hunterState;
    portEXIT_CRITICAL(&reconMux);
}
void drawHunterDetails(const HunterState &s) {
    std::vector<String> l;
    appendWrapped(l, "IDENTITY: " + String(s.currentName[0] ? s.currentName : "Unnamed"));
    appendWrapped(
        l,
        "SOURCE: " + String(
                         s.identitySource == ID_NAME  ? "ADVERTISED NAME"
                         : s.identitySource == ID_MFG ? "MANUFACTURER"
                                                      : "ADDRESS"
                     )
    );
    appendWrapped(l, "CURRENT: " + String(s.target.address));
    appendWrapped(l, "TYPE: " + addressTypeName(s.target));
    appendWrapped(l, "COMPANY: 0x" + String(s.target.companyId, HEX));
    appendWrapped(l, "SERVICE HASH: " + String(s.target.serviceHash, HEX));
    appendWrapped(l, "SHAPE HASH: " + String(s.target.shapeHash, HEX));
    appendWrapped(l, "PAYLOAD: " + String(s.target.payloadLen) + " bytes");
    size_t stable = 0;
    for (size_t i = 0; i < s.model.len; i++)
        if (s.model.stable[i]) stable++;
    appendWrapped(l, "RAW bytes stable: " + String(stable) + " volatile: " + String(s.model.len - stable));
    appendWrapped(l, "OBSERVATIONS: " + String(s.model.observations));
    appendWrapped(l, "ADDRESS HISTORY:");
    for (uint8_t i = 0; i < s.historyCount; i++)
        appendWrapped(l, String(i + 1) + ": " + String(s.history[i]));
    appendWrapped(l, matchStatus());
    appendWrapped(l, "Scores are evidence, not identity probability");
    appendWrapped(l, "FIELD ASSOCIATION / automatic changes reversible");
    appendWrapped(l, recon::capture.status());
    size_t scroll = 0;
    while (!check(EscPress)) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString("BLE HUNTER DETAILS", tftWidth / 2, 29, 1);
        const int first = 50, footer = tftHeight - 18, visible = (footer - first) / 12;
        if (scroll >= l.size()) scroll = l.empty() ? 0 : l.size() - 1;
        for (int r = 0; r < visible && scroll + r < l.size(); r++)
            tft.drawString(l[scroll + r], 8, first + r * 12, 1);
        if (check(PrevPress) && scroll) scroll--;
        if (check(NextPress)) scroll++;
        tft.drawCentreString("Turn scroll  Esc", tftWidth / 2, footer, 1);
        drawStatusBar();
        delay(20);
    }
}
bool startPassiveHunter() {
    if (!pBLEScan) return false;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
#ifdef BLE_RECON_EXT_ADV
    pBLEScan->setPhy(NimBLEScan::SCAN_ALL);
#endif
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&hunterCallbacks, true);
    return pBLEScan->start(0, false, true);
}
void huntTarget(const BleObservation &t) {
    ble_scan_setup();
    if (!pBLEScan) {
        displayError("BLE scanner unavailable", true);
        return;
    }
    resetHunter(t);
    resetAssociation(t);
    recon::capture.begin("hunter", t.address);
    if (!startPassiveHunter()) {
        recon::capture.end();
        stopBLEStack();
        displayError("Unable to start BLE scan", true);
        return;
    }
    uint32_t draw = 0;
    uint32_t lastLog = millis();
    uint32_t warmSince = 0, lastBeep = 0, lastSamples = 0;
    bool audio = false, haveCheckpoint = false;
    float checkpoint = 0;
    float trail[48]{};
    unsigned trailCount = 0;
    while (!check(EscPress)) {
        logReconMemory("HUNTER_UI", lastLog);
        recon::capture.drain();
        if (check(LongPress) || check(SelPress)) {
            pBLEScan->stop();
            recon::capture.event("pause", "hunter_menu");
            std::vector<Option> actions;
            int action = -1;
            actions.emplace_back("Details / evidence", [&]() { action = 0; });
            actions.emplace_back("Set location checkpoint", [&]() { action = 1; });
            actions.emplace_back(audio ? "Audio off" : "Audio on", [&]() { action = 2; });
            actions.emplace_back("Bookmark", [&]() { action = 3; });
            actions.emplace_back("Undo address change + lock", [&]() { action = 4; });
            actions.emplace_back("Toggle address lock", [&]() { action = 5; });
            actions.emplace_back(recon::capture.active() ? "Stop recording" : "Start recording", [&]() { action = 6; });
            loopOptions(actions, MENU_TYPE_REGULAR, "Hunter actions", 0, false);
            hunterSnapshot(uiHunterSnap);
            if (action == 0) drawHunterDetails(uiHunterSnap);
            if (action == 1) {
                const auto state = associationStatus();
                if (millis() - state.lastSeen <= state.timeout && uiHunterSnap.samples >= 3) {
                    checkpoint = uiHunterSnap.stableRssi; haveCheckpoint = true;
                    recon::capture.event("checkpoint", String(checkpoint, 1).c_str());
                } else displayWarning("Need fresh target samples", true);
            }
            if (action == 2) audio = !audio;
            if (action == 3) recon::capture.event("bookmark", "hunter");
            if (action == 4) { undoAssociation(true); haveCheckpoint = false; trailCount = 0; }
            if (action == 5) { association.lock(!associationStatus().locked); recon::capture.event("lock_toggle"); }
            if (action == 6) {
                if (recon::capture.active()) recon::capture.end();
                else recon::capture.begin("hunter", uiHunterSnap.target.address);
            }
            association.resume(millis());
            recon::capture.event("resume", "hunter_menu");
            if (!startPassiveHunter()) { displayError("Scan restart failed", true); break; }
            draw = 0; warmSince = 0;
            delay(100);
        }
        if (millis() - draw >= 250) {
            hunterSnapshot(uiHunterSnap);
            const HunterState &s = uiHunterSnap;
            tft.fillScreen(bruceConfig.bgColor);
            drawMainBorder(false);
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            tft.setTextSize(FP);
            const auto a = associationStatus();
            const uint32_t now = millis(), age = now - a.lastSeen;
            const bool fresh = age <= a.timeout;
            const bool unstable = s.jitter > 4 || fabsf(s.trend) < s.jitter;
            String direction = !fresh ? "TARGET LOST" : unstable ? "UNSTABLE" : s.trend > 2 ? "WARMER" : s.trend < -2 ? "COLDER" : "STEADY";
            tft.drawCentreString("BLE HUNTER / FIELD", tftWidth / 2, 26, 1);
            tft.drawCentreString(s.currentName[0] ? String(s.currentName) : String(s.target.address), tftWidth / 2, 38, 1);
            tft.drawCentreString(matchStatus(), tftWidth / 2, 50, 1);
            tft.setTextColor(!fresh ? TFT_RED : unstable ? TFT_YELLOW : bruceConfig.priColor, bruceConfig.bgColor);
            tft.drawCentreString(direction, tftWidth / 2, 64, 2);
            tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
            tft.drawString(String(s.stableRssi, 1) + " dBm  age " + String(age) + " ms", 10, 88, 1);
            tft.drawString(haveCheckpoint ? "Checkpoint " + String(s.stableRssi - checkpoint, 1) + " dB  jitter " + String(s.jitter, 1) : "Trend " + String(s.trend, 1) + " dB  jitter " + String(s.jitter, 1), 10, 100, 1);
            tft.drawString(recon::capture.status(), 10, 112, 1);
            if (s.samples != lastSamples && fresh) {
                lastSamples = s.samples;
                if (trailCount == 48) { for (unsigned i = 1; i < 48; ++i) trail[i-1] = trail[i]; --trailCount; }
                trail[trailCount++] = s.stableRssi;
            }
            for (unsigned i = 1; i < trailCount; ++i) {
                const auto y = [](float v) { return 145 - static_cast<int>((std::max(-100.f, std::min(-30.f, v)) + 100) * 20 / 70); };
                tft.drawLine(10 + (i-1) * (tftWidth-20) / 47, y(trail[i-1]), 10 + i * (tftWidth-20) / 47, y(trail[i]), fresh ? bruceConfig.priColor : TFT_DARKGREY);
            }
            if (fresh && !unstable && s.trend > 2 && s.samples >= 7) {
                if (!warmSince) warmSince = now;
                if (audio && now - warmSince >= 4000 && now - lastBeep >= 3000) {
                    recon::capture.drain(32); _tone(1200, 500); lastBeep = now;
                }
            } else warmSince = 0;
            tft.drawCentreString("Select actions  Esc back", tftWidth / 2, tftHeight - 14, 1);
            drawStatusBar();
            draw = millis();
        }
        delay(10);
    }
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    recon::capture.end();
    pBLEScan->setMaxResults(0xFF);
    pBLEScan->clearResults();
    stopBLEStack();
}
std::vector<BleObservation> discoverTargets(bool active) {
    std::vector<BleObservation> out;
    ble_scan_setup();
    if (!pBLEScan) return out;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(active);
#ifdef BLE_RECON_EXT_ADV
    pBLEScan->setPhy(NimBLEScan::SCAN_ALL);
#endif
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(80);
    displayTextLine(active ? "Scanning BLE advertisers..." : "Listening for BLE advertisers...");
    BLEScanResults results = pBLEScan->getResults(DISCOVERY_MS, false);
    out.reserve(std::min(results.getCount(), 60));
    for (int i = 0; i < results.getCount() && out.size() < 60; i++) {
        const NimBLEAdvertisedDevice *d = results.getDevice(i);
        if (!d) continue;
        BleObservation o;
        fillObservation(d, o);
        out.push_back(o);
    }
    std::sort(out.begin(), out.end(), [](const BleObservation &a, const BleObservation &b) {
        return a.rssi > b.rssi;
    });
    pBLEScan->clearResults();
    return out;
}
void updateMutation(MutationModel &m, const BleObservation &o) {
    if (!m.valid && !o.payloadLen) return;
    if (!m.valid) {
        std::memcpy(m.baseline, o.payload, o.payloadLen);
        std::memcpy(m.last, o.payload, o.payloadLen);
        m.len = o.payloadLen;
        m.observations = 1;
        m.valid = true;
        return;
    }
    const size_t n = std::min<size_t>(m.len, o.payloadLen);
    m.lastDiffLen = 0;
    m.lastChanged = 0;
    for (size_t i = 0; i < n; i++) {
        if (m.last[i] != o.payload[i]) {
            m.volatileMask[i] = true;
            if (m.changeHits[i] < 255) m.changeHits[i]++;
            if (static_cast<uint8_t>(m.last[i] + 1) == o.payload[i] && m.counterHits[i] < 255)
                m.counterHits[i]++;
            if (m.lastDiffLen < MAX_PAYLOAD) m.lastDiff[m.lastDiffLen++] = static_cast<uint8_t>(i);
            m.lastChanged++;
        }
        m.last[i] = o.payload[i];
    }
    const size_t high = std::max<size_t>(m.len, o.payloadLen);
    for (size_t i = n; i < high; ++i) {
        m.volatileMask[i] = true;
        if (m.lastDiffLen < MAX_PAYLOAD) m.lastDiff[m.lastDiffLen++] = static_cast<uint8_t>(i);
        ++m.lastChanged;
        if (i < o.payloadLen) m.last[i] = o.payload[i];
    }
    m.len = o.payloadLen;
    if (m.lastChanged) m.changes++;
    m.observations++;
}
void updateFcf1(Fcf1Tracker &f, const BleObservation &o, uint32_t now) {
    if (!o.hasFcf1) return;
    const bool mac = f.seen && std::strncmp(f.currentAddress, o.address, 17) != 0;
    const bool pay = f.seen && (f.len != o.fcf1Len || (f.len && std::memcmp(f.payload, o.fcf1, f.len) != 0));
    if (!f.seen) {
        f.seen = true;
        f.firstSeen = now;
    } else {
        if (mac) f.macChanges++;
        if (pay) f.payloadChanges++;
        if (mac && pay) f.correlated++;
        else if (mac) f.macOnly++;
        else if (pay) f.payloadOnly++;
    }
    if (mac) {
        std::strncpy(f.previousAddress, f.currentAddress, 17);
        f.previousAddress[17] = '\0';
    }
    std::strncpy(f.currentAddress, o.address, 17);
    f.currentAddress[17] = '\0';
    f.addressType = o.addressType;
    f.len = o.fcf1Len;
    if (f.len) std::memcpy(f.payload, o.fcf1, f.len);
    f.lastSeen = now;
    f.count++;
}
class SnifferCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device) return;
        static uint32_t lastLog = 0;
        logReconMemory("SNIFFER_HOST", lastLog);
        BleObservation o;
        fillObservation(device, o);
        const uint32_t now = millis();
        const bool scanResponse = o.advType == 4;
        const auto decision = associate(o, now);
        const bool selected = decision == recon::Decision::Current || decision == recon::Decision::Handoff;
        if (!selected) return;
        if (decision == recon::Decision::Handoff) {
            portENTER_CRITICAL(&reconMux);
            previousTarget = snifferState.target;
            std::memcpy(selectedAddress, o.address, 18);
            reinit(snifferState.mutation);
            portEXIT_CRITICAL(&reconMux);
        }

        portENTER_CRITICAL(&reconMux);
        if (!scanResponse) {
            const uint32_t previousSeen = snifferState.lastSeen;
            const auto decoded = recon::decode(o.payload, o.payloadLen);
            unsigned changes = 0;
            for (unsigned i = 0; i < decoded.count; ++i) {
                const auto &f = decoded.fields[i];
                bool equal = false;
                for (unsigned j = 0; j < snifferState.decoded.count; ++j) {
                    const auto &old = snifferState.decoded.fields[j];
                    if (f.key == old.key && f.len == old.len && std::memcmp(f.data, old.data, f.len) == 0) equal = true;
                }
                if (!equal) ++changes;
            }
            for (unsigned i = 0; i < snifferState.decoded.count; ++i) {
                bool found = false;
                for (unsigned j = 0; j < decoded.count; ++j)
                    if (snifferState.decoded.fields[i].key == decoded.fields[j].key) found = true;
                if (!found) ++changes;
            }
            snifferState.fieldChanges = changes;
            snifferState.decoded = decoded;
            updateMutation(snifferState.mutation, o);
            updateFcf1(snifferState.fcf1, o, now);
            snifferState.target = o;
            snifferState.packets++;
            snifferState.initialized = true;
            if (previousSeen && now - previousSeen < 60000) {
                const uint32_t gap = now - previousSeen;
                snifferState.gapEma = snifferState.gapEma <= 0.1f
                                          ? gap
                                          : snifferState.gapEma + 0.18f * (gap - snifferState.gapEma);
            }
            snifferState.lastSeen = now;
            if (!snifferState.rateStart) snifferState.rateStart = now;
            snifferState.ratePackets++;
            if (now - snifferState.rateStart >= 1000) {
                snifferState.pps = snifferState.ratePackets * 1000.0f / (now - snifferState.rateStart);
                snifferState.rateStart = now;
                snifferState.ratePackets = 0;
            }
        }
        const std::vector<uint8_t> &p = device->getPayload();
        const size_t adv = std::min<size_t>(device->getAdvLength(), p.size());
        if (scanResponse || (adv < p.size() && device->getAdvLength() > 0)) {
            const size_t start = scanResponse ? 0 : adv;
            const size_t n = std::min(p.size() - start, MAX_RESPONSE);
            std::memcpy(snifferState.response, p.data() + start, n);
            snifferState.responseLen = n;
            if (activeBurst) snifferState.activeResponses++;
        }
        if (activeBurst && device->isScannable()) snifferState.activeReports++;
        portEXIT_CRITICAL(&reconMux);
    }
};
SnifferCallbacks snifferCallbacks;
void snifferSnapshot(SnifferState &s) {
    portENTER_CRITICAL(&reconMux);
    s = snifferState;
    portEXIT_CRITICAL(&reconMux);
}
void resetSniffer(const BleObservation &o) {
    portENTER_CRITICAL(&reconMux);
    reinit(snifferState);
    snifferState.target = o;
    std::strncpy(selectedAddress, o.address, 17);
    selectedAddress[17] = '\0';
    portEXIT_CRITICAL(&reconMux);
}
String mutationClass(const MutationModel &m) {
    if (!m.len) return "NO PAYLOAD";
    if (!m.observations || !m.changes) return "NO MUTATION OBSERVED";
    size_t vol = 0, ctr = 0;
    for (size_t i = 0; i < m.len; i++) {
        if (m.volatileMask[i]) vol++;
        if (m.counterHits[i] >= 2) ctr++;
    }
    if (ctr) return "COUNTER-LIKE FIELD(S) DETECTED";
    return vol * 100 >= m.len * 60 ? "HIGH VOLATILITY / POSSIBLY ENCRYPTED"
                                   : "PARTIAL VOLATILITY / LIVE DATA";
}
void drawSniffer(const SnifferState &s, uint8_t view, size_t &scroll, bool frozen) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    const char *vn = view == 0   ? "PLAIN"
                     : view == 1 ? "AD FIELDS"
                     : view == 2 ? "RAW"
                     : view == 3 ? "MUTATION"
                                 : "ACTIVE";
    tft.drawCentreString(String("BLE SNIFFER - ") + vn, tftWidth / 2, 29, 1);
    tft.drawCentreString(
        s.target.name[0] ? String(s.target.name) : String(s.target.address), tftWidth / 2, 42, 1
    );
    const bool lost = s.initialized && millis() - s.lastSeen > associationStatus().timeout;
    tft.setTextColor(lost ? TFT_RED : bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString(
        lost ? String("TARGET QUIET") : String(s.target.rssi) + " dBm  " + String(s.packets) + " pkt",
        tftWidth / 2,
        54,
        1
    );
    std::vector<String> l;
    appendWrapped(l, matchStatus());
    appendWrapped(l, recon::capture.status());
    appendWrapped(l, "Decoded field changes: " + String(s.fieldChanges));
    appendWrapped(l, "Signature preview: first 24 bytes/field");

    if (view == 0) {
        appendWrapped(l, "Address: " + String(s.target.address));
        appendWrapped(l, "Type: " + addressTypeName(s.target));
        appendWrapped(l, s.target.connectable ? "Connectable" : "Not connectable");
        appendWrapped(l, s.target.scannable ? "Scannable" : "Non-scannable");
        appendWrapped(
            l,
            "Company: " +
                String(companyName(s.target.companyId) ? companyName(s.target.companyId) : "Unlisted") +
                " 0x" + String(s.target.companyId, HEX)
        );
        appendWrapped(l, "Payload: " + String(s.target.payloadLen) + " bytes");
        appendWrapped(l, "Rate: " + String(s.pps, 1) + "/s  gap " + String(s.gapEma, 0) + "ms");
        if (s.target.hasAppearance) appendWrapped(l, "Appearance: " + appearanceName(s.target.appearance));
        if (s.fcf1.seen) appendWrapped(l, "Google Service (FCF1) DETECTED");
#ifdef BLE_RECON_EXT_ADV
        appendWrapped(l, s.target.legacy ? "Legacy advertising" : "Extended advertising");
        if (!s.target.legacy) {
            appendWrapped(
                l,
                "SID " + String(s.target.sid) + " PHY " + String(s.target.primaryPhy) + "/" +
                    String(s.target.secondaryPhy)
            );
            appendWrapped(l, "Data status " + String(s.target.dataStatus));
            appendWrapped(
                l,
                s.target.periodicInterval
                    ? "Periodic interval: " + String(s.target.periodicInterval) + " units"
                    : "No periodic interval advertised"
            );
        }
#endif
    } else if (view == 1) {
        parseAdFields(s.target.payload, s.target.payloadLen, &l, nullptr);
        if (s.responseLen) {
            appendWrapped(l, "SCAN RESPONSE");
            parseAdFields(s.response, s.responseLen, &l, nullptr);
        }
    } else if (view == 2) {
        appendWrapped(l, "ADV PAYLOAD");
        for (size_t i = 0; i < s.target.payloadLen; i += 8)
            l.push_back(
                String(i, HEX) + ": " +
                hexBytes(s.target.payload + i, std::min<size_t>(8, s.target.payloadLen - i), 8, true)
            );
        if (s.responseLen) {
            appendWrapped(l, "SCAN RESPONSE");
            for (size_t i = 0; i < s.responseLen; i += 8)
                l.push_back(
                    String(i, HEX) + ": " +
                    hexBytes(s.response + i, std::min<size_t>(8, s.responseLen - i), 8, true)
                );
        }
    } else if (view == 3) {
        appendWrapped(l, mutationClass(s.mutation));
        appendWrapped(l, "Observations: " + String(s.mutation.observations));
        appendWrapped(l, "Payload changes: " + String(s.mutation.changes));
        appendWrapped(l, "Last changed bytes: " + String(s.mutation.lastChanged));
        appendWrapped(
            l, "Last diff offsets: " + hexBytes(s.mutation.lastDiff, s.mutation.lastDiffLen, 48, true)
        );
        size_t stable = 0, vol = 0, ctr = 0;
        for (size_t i = 0; i < s.mutation.len; i++) {
            if (s.mutation.volatileMask[i]) vol++;
            else stable++;
            if (s.mutation.counterHits[i] >= 2) ctr++;
        }
        appendWrapped(
            l, "Stable " + String(stable) + "  Volatile " + String(vol) + "  Counter-like " + String(ctr)
        );
        if (s.fcf1.seen) {
            appendWrapped(l, "--- GOOGLE SERVICE (FCF1) ---");
            appendWrapped(
                l,
                "Payload " + String(s.fcf1.len) + " bytes: " + hexBytes(s.fcf1.payload, s.fcf1.len, 32, true)
            );
            appendWrapped(
                l,
                "First " + String(s.fcf1.firstSeen / 1000) + "s  Last " + String(s.fcf1.lastSeen / 1000) +
                    "s  Count " + String(s.fcf1.count)
            );
            appendWrapped(
                l,
                "MAC changes " + String(s.fcf1.macChanges) + "  Payload changes " +
                    String(s.fcf1.payloadChanges)
            );
            appendWrapped(l, "Correlated MAC+payload " + String(s.fcf1.correlated));
            appendWrapped(
                l, "MAC-only " + String(s.fcf1.macOnly) + "  Payload-only " + String(s.fcf1.payloadOnly)
            );
            appendWrapped(
                l,
                "Current " + String(s.fcf1.currentAddress) + " " +
                    addressTypeName(s.fcf1.addressType, s.fcf1.currentAddress)
            );
            if (s.fcf1.previousAddress[0]) appendWrapped(l, "Previous " + String(s.fcf1.previousAddress));
        }
    } else {
        appendWrapped(l, s.activeComplete ? "Active scan complete" : "No active scan performed");
        appendWrapped(
            l, "Bursts " + String(s.activeBursts) + "  Scannable reports " + String(s.activeReports)
        );
        appendWrapped(l, "Scan responses " + String(s.activeResponses));
        if (s.responseLen) parseAdFields(s.response, s.responseLen, &l, nullptr);
    }
    const int first = 69, footer = tftHeight - 19, visible = (footer - first) / 12;
    if (scroll >= l.size()) scroll = l.empty() ? 0 : l.size() - 1;
    for (int r = 0; r < visible && scroll + r < l.size(); r++)
        tft.drawString(l[scroll + r], 8, first + r * 12, 1);
    if (scroll) tft.drawRightString("^", tftWidth - 7, first, 1);
    if (scroll + visible < l.size()) tft.drawRightString("v", tftWidth - 7, footer - 12, 1);
    tft.drawCentreString("Turn scroll  Hold actions", tftWidth / 2, footer, 1);
    drawStatusBar();
}
bool confirmAction(const String &title, const std::vector<String> &messages) {
    const uint32_t start = millis();
    while (true) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.drawCentreString(title, tftWidth / 2, 31, 1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        int y = 54;
        for (const String &m : messages) {
            tft.drawCentreString(m, tftWidth / 2, y, 1);
            y += 15;
        }
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.drawCentreString("Select: continue  Esc: cancel", tftWidth / 2, tftHeight - 21, 1);
        drawStatusBar();
        if (check(EscPress)) return false;
        if (millis() - start > 650 && check(SelPress)) return true;
        delay(25);
    }
}
bool startPassiveSniffer() {
    if (!pBLEScan) return false;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
#ifdef BLE_RECON_EXT_ADV
    pBLEScan->setPhy(NimBLEScan::SCAN_ALL);
#endif
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);
    return pBLEScan->start(0, false, true);
}
void runActiveScan() {
    if (!confirmAction(
            "ACTIVE SCAN - TRANSMITS",
            {"3-second scan-request burst",
             "Nearby scannable devices may receive requests",
             "No BLE connection is made"}
        ))
        return;
    pBLEScan->stop();
    pBLEScan->clearResults();
    portENTER_CRITICAL(&reconMux);
    snifferState.activeBursts++;
    snifferState.activeReports = 0;
    snifferState.activeResponses = 0;
    snifferState.responseLen = 0;
    activeBurst = true;
    portEXIT_CRITICAL(&reconMux);
    recon::capture.event("active_scan_start");
    pBLEScan->setActiveScan(true);
#ifdef BLE_RECON_EXT_ADV
    pBLEScan->setPhy(NimBLEScan::SCAN_ALL);
#endif
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);
    pBLEScan->start(0, false, true);
    const uint32_t start = millis();
    while (millis() - start < 3000) {
        recon::capture.drain();
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.drawCentreString("ACTIVE - TRANSMITTING", tftWidth / 2, 40, 1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString("BLE scan requests are on air", tftWidth / 2, 65, 1);
        tft.drawCentreString("Esc stops burst early", tftWidth / 2, tftHeight - 21, 1);
        drawStatusBar();
        if (check(EscPress)) break;
        delay(80);
    }
    pBLEScan->stop();
    portENTER_CRITICAL(&reconMux);
    activeBurst = false;
    snifferState.activeComplete = true;
    portEXIT_CRITICAL(&reconMux);
    recon::capture.event("active_scan_end");

}
String characteristicProperties(const NimBLERemoteCharacteristic *c) {
    String p;
    if (c->canRead()) p += "R ";
    if (c->canWrite()) p += "W ";
    if (c->canWriteNoResponse()) p += "WNR ";
    if (c->canNotify()) p += "N ";
    if (c->canIndicate()) p += "I ";
    p.trim();
    return p.isEmpty() ? "none" : p;
}
GattResult enumerateGatt(const BleObservation &t) {
    GattResult r;
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->clearResults();
    displayTextLine("Connecting for GATT map...");
    NimBLEClient *client = NimBLEDevice::createClient();
    if (!client) {
        r.error = "Could not create BLE client";
        return r;
    }
    client->setConnectTimeout(8000);
    client->setConnectRetries(0);
    client->setConnectionParams(12, 24, 0, 400);
    NimBLEAddress peer(std::string(t.address), t.addressType);
    if (!client->connect(peer, true, false, false)) {
        r.error = "Connection failed (error " + String(client->getLastError()) + ")";
        NimBLEDevice::deleteClient(client);
        return r;
    }
    r.connected = true;
    if (!client->discoverAttributes())
        r.error = "GATT discovery failed (error " + String(client->getLastError()) + ")";
    else {
        r.discovered = true;
        const auto &services = client->getServices(false);
        for (const NimBLERemoteService *s : services) {
            if (!s) continue;
            r.services++;
            const String u(s->getUUID().toString().c_str());
            r.serviceLines.push_back(u);
            if (r.tree.size() < MAX_GATT_LINES) r.tree.push_back("SERVICE " + u);
            const auto &chars = s->getCharacteristics(false);
            for (const NimBLERemoteCharacteristic *c : chars) {
                if (!c) continue;
                r.characteristics++;
                if (c->canRead()) r.readable++;
                if (c->canWrite() || c->canWriteNoResponse()) r.writable++;
                if (c->canNotify()) r.notify++;
                if (c->canIndicate()) r.indicate++;
                const String cu(c->getUUID().toString().c_str());
                if (r.tree.size() < MAX_GATT_LINES) {
                    r.tree.push_back("  CHAR " + cu);
                    r.tree.push_back("    PROPS " + characteristicProperties(c));
                } else r.truncated = true;
                const auto &ds = c->getDescriptors(false);
                for (const NimBLERemoteDescriptor *d : ds) {
                    if (!d) continue;
                    r.descriptors++;
                    if (r.tree.size() < MAX_GATT_LINES)
                        r.tree.push_back("    DESC " + String(d->getUUID().toString().c_str()));
                    else r.truncated = true;
                }
            }
        }
    }
    if (client->isConnected()) client->disconnect();
    delay(80);
    NimBLEDevice::deleteClient(client);
    return r;
}
void showGatt(const GattResult &r, const String &identity) {
    bool tech = false;
    size_t scroll = 0;
    while (!check(EscPress)) {
        std::vector<String> l;
        if (!r.connected) appendWrapped(l, r.error.isEmpty() ? "Connection failed" : r.error);
        else if (!r.discovered) appendWrapped(l, r.error.isEmpty() ? "GATT discovery failed" : r.error);
        else {
            appendWrapped(l, tech ? "STRUCTURE ONLY - NO VALUES READ" : "GATT mapped; disconnected");
            appendWrapped(
                l,
                String(r.services) + " services  " + String(r.characteristics) + " chars  " +
                    String(r.descriptors) + " desc"
            );
            appendWrapped(l, String(r.readable) + " readable  " + String(r.writable) + " writable");
            appendWrapped(l, String(r.notify) + " notify  " + String(r.indicate) + " indicate");
            if (tech)
                for (const String &x : r.tree) l.push_back(x);
            else
                for (const String &x : r.serviceLines) appendWrapped(l, "Service: " + x);
            if (r.truncated) appendWrapped(l, "Technical tree truncated");
        }
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString(tech ? "GATT TECHNICAL" : "GATT PLAIN", tftWidth / 2, 29, 1);
        tft.drawCentreString(identity, tftWidth / 2, 42, 1);
        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.drawCentreString("DISCONNECTED - NO VALUES", tftWidth / 2, 54, 1);
        const int first = 69, footer = tftHeight - 19, visible = (footer - first) / 12;
        if (scroll >= l.size()) scroll = l.empty() ? 0 : l.size() - 1;
        for (int row = 0; row < visible && scroll + row < l.size(); row++)
            tft.drawString(l[scroll + row], 8, first + row * 12, 1);
        if (check(PrevPress) && scroll) scroll--;
        if (check(NextPress)) scroll++;
        if (check(SelPress)) {
            tech = !tech;
            scroll = 0;
            delay(100);
        }
        tft.drawCentreString("Turn scroll  Select tree  Esc", tftWidth / 2, footer, 1);
        drawStatusBar();
        delay(20);
    }
}
void sniffTarget(const BleObservation &t) {
    ble_scan_setup();
    if (!pBLEScan) {
        displayError("BLE scanner unavailable", true);
        return;
    }
    resetSniffer(t);
    resetAssociation(t);
    recon::capture.begin("sniffer", t.address);
    if (!startPassiveSniffer()) {
        recon::capture.end();
        stopBLEStack();
        displayError("Unable to start BLE scan", true);
        return;
    }
    uint8_t view = 0;
    size_t scroll = 0;
    bool frozen = false;
    SnifferState &frozenState = uiFrozenSnap;
    reinit(frozenState);
    uint32_t draw = 0;
    uint32_t lastLog = millis();
    while (!check(EscPress)) {
        logReconMemory("SNIFFER_UI", lastLog);
        recon::capture.drain();
        if (check(PrevPress)) {
            if (scroll) scroll--;
            else view = (view + 4) % 5;
        }
        if (check(NextPress)) scroll++;
        if (check(LongPress) || check(SelPress)) {
            pBLEScan->stop();
            recon::capture.event("pause", "sniffer_menu");
            std::vector<Option> actions;
            int chosen = -1;
            actions.emplace_back("Active scan request (3s)", [&chosen]() { chosen = 0; });
            actions.emplace_back("Connect + map GATT", [&chosen]() { chosen = 1; });
            actions.emplace_back("Next view", [&chosen]() { chosen = 2; });
            actions.emplace_back(frozen ? "Unfreeze frame" : "Freeze frame", [&chosen]() { chosen = 3; });
            actions.emplace_back("Bookmark", [&chosen]() { chosen = 4; });
            actions.emplace_back("Undo address change + lock", [&chosen]() { chosen = 5; });
            actions.emplace_back("Toggle address lock", [&chosen]() { chosen = 6; });
            actions.emplace_back(recon::capture.active() ? "Stop recording" : "Start recording", [&chosen]() { chosen = 7; });
            loopOptions(actions, MENU_TYPE_REGULAR, "BLE Sniffer", 0, false);
            if (chosen == 0) {
                frozen = false;
                runActiveScan();
                view = 4;
                scroll = 0;
            } else if (chosen == 1) {
                frozen = false;
                snifferSnapshot(uiSnifferSnap);
                const SnifferState &s = uiSnifferSnap;
                if (!s.target.connectable) displayWarning("Target is not advertising connectable", true);
                else if (
                    confirmAction(
                        "CONNECT + MAP GATT",
                        {"Target will see a connection",
                         "Structure discovery only",
                         "NO READS / WRITES / SUBSCRIPTIONS"}
                    )
                ) {
                    const GattResult r = enumerateGatt(s.target);
                    showGatt(r, s.target.name[0] ? String(s.target.name) : String(s.target.address));

                }
            } else if (chosen == 2) {
                view = (view + 1) % 5;
                scroll = 0;
            } else if (chosen == 3) {
                frozen = !frozen;
                if (frozen) snifferSnapshot(frozenState);
            }
            if (chosen == 4) recon::capture.event("bookmark", "sniffer");
            if (chosen == 5) { undoAssociation(false); frozen = false; }
            if (chosen == 6) { association.lock(!associationStatus().locked); recon::capture.event("lock_toggle"); }
            if (chosen == 7) {
                if (recon::capture.active()) recon::capture.end();
                else recon::capture.begin("sniffer", snifferState.target.address);
            }
            association.resume(millis());
            recon::capture.event("resume", "sniffer_menu");
            if (!startPassiveSniffer()) { displayError("Scan restart failed", true); break; }
            delay(100);
        }
        if (millis() - draw >= (frozen ? 1000 : 300)) {
            if (!frozen) snifferSnapshot(uiSnifferSnap);
            drawSniffer(frozen ? frozenState : uiSnifferSnap, view, scroll, frozen);
            draw = millis();
        }
        delay(10);
    }
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    recon::capture.end();
    pBLEScan->setMaxResults(0xFF);
    pBLEScan->clearResults();
    stopBLEStack();
}
} // namespace

void bleHunterV3() {
    const std::vector<BleObservation> targets = discoverTargets(false);
    if (targets.empty()) {
        displayWarning("No BLE advertisers found", true);
        stopBLEStack();
        return;
    }
    options.clear();
    for (size_t i = 0; i < std::min<size_t>(targets.size(), 60); i++) {
        const BleObservation target = targets[i];
        String label = target.name[0] ? String(target.name) : String(target.address);
        if (target.name[0]) label += " [" + String(target.address).substring(12) + "]";
        label += " " + String(target.rssi);
        options.emplace_back(label, [target]() { huntTarget(target); });
    }
    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_REGULAR, "BLE Hunter target", 0, false);
    options.clear();
    stopBLEStack();
}
void bleSnifferV3() {
    const std::vector<BleObservation> targets = discoverTargets(false);
    if (targets.empty()) {
        displayWarning("No BLE advertisers found", true);
        stopBLEStack();
        return;
    }
    options.clear();
    for (size_t i = 0; i < std::min<size_t>(targets.size(), 60); i++) {
        const BleObservation target = targets[i];
        String label = target.name[0] ? String(target.name) : String(target.address);
        if (target.name[0]) label += " [" + String(target.address).substring(12) + "]";
        label += " " + String(target.rssi);
        options.emplace_back(label, [target]() { sniffTarget(target); });
    }
    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_REGULAR, "BLE Sniffer target", 0, false);
    options.clear();
    stopBLEStack();
}
