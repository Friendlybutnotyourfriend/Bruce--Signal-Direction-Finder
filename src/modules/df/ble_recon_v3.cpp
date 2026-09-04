#include "ble_recon_v3.h"

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_common.h"
#include <globals.h>
#include <NimBLERemoteDescriptor.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
constexpr uint32_t DISCOVERY_MS = 5000;
constexpr uint32_t LOST_MS = 3000;
constexpr uint32_t HANDOFF_ARM_MS = 900;
constexpr uint32_t HANDOFF_MAX_GAP_MS = 10000;
constexpr uint32_t CANDIDATE_STALE_MS = 2500;
constexpr uint32_t NOTICE_MS = 2500;
constexpr int HANDOFF_THRESHOLD = 78;
constexpr uint8_t HANDOFF_HITS = 3;
constexpr uint8_t HANDOFF_MARGIN = 10;
constexpr size_t MAX_PAYLOAD = 256;
constexpr size_t MAX_RESPONSE = 128;
constexpr size_t MAX_NAME = 40;
constexpr size_t MAX_CANDIDATES = 6;
constexpr size_t MAX_HISTORY = 8;
constexpr size_t MAX_LINES = 180;
constexpr size_t MAX_GATT_LINES = 220;

#if __has_include(<NimBLEExtAdvertising.h>)
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

struct Candidate {
    BleObservation obs;
    uint8_t score = 0;
    uint8_t hits = 0;
    uint32_t firstSeen = 0;
    uint32_t lastSeen = 0;
    bool valid = false;
};

struct HunterState {
    BleObservation target;
    FingerprintModel model;
    Candidate candidates[MAX_CANDIDATES];
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
    void reset() { values.fill(-127); count = index = 0; }
    void add(int value) { values[index] = value; index = (index + 1) % values.size(); if (count < values.size()) count++; }
    float median() const {
        if (!count) return -127;
        auto sorted = values;
        std::sort(sorted.begin(), sorted.begin() + count);
        return (count & 1) ? static_cast<float>(sorted[count / 2]) : (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0f;
    }
private:
    std::array<int, 7> values{};
    size_t count = 0;
    size_t index = 0;
};

portMUX_TYPE reconMux = portMUX_INITIALIZER_UNLOCKED;
HunterState hunterState;
SnifferState snifferState;
MedianWindow medianWindow;
char selectedAddress[18]{};
bool activeBurst = false;

uint32_t fnv1a(const uint8_t *data, size_t length, uint32_t seed = 2166136261UL) {
    uint32_t h = seed;
    for (size_t i = 0; i < length; i++) { h ^= data[i]; h *= 16777619UL; }
    return h;
}
uint16_t le16(const uint8_t *p) { return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8); }

String hexBytes(const uint8_t *data, size_t length, size_t maxBytes = 32, bool spaces = false) {
    const size_t n = std::min(length, maxBytes); String out; out.reserve(n * (spaces ? 3 : 2) + 3); char b[4];
    for (size_t i = 0; i < n; i++) { std::snprintf(b, sizeof(b), spaces ? "%02X " : "%02X", data[i]); out += b; }
    if (spaces && !out.isEmpty()) out.remove(out.length() - 1); if (length > n) out += ".."; return out;
}
String cleanText(const uint8_t *data, size_t length) {
    const size_t n = std::min(length, MAX_NAME); String out; out.reserve(n);
    for (size_t i = 0; i < n; i++) { if (data[i] == 0) break; out += (data[i] >= 0x20 && data[i] < 0x7F) ? static_cast<char>(data[i]) : '.'; }
    out.trim(); return out;
}
String cleanText(const std::string &s) { return cleanText(reinterpret_cast<const uint8_t *>(s.data()), s.size()); }
void copyAddress(char dst[18], const std::string &src) { std::memset(dst, 0, 18); std::strncpy(dst, src.c_str(), 17); }
void copyName(char dst[MAX_NAME + 1], const String &src) { std::memset(dst, 0, MAX_NAME + 1); std::strncpy(dst, src.c_str(), MAX_NAME); }

String addressTypeName(uint8_t type, const char *address) {
    if (!address || !address[0]) return "UNKNOWN";
    NimBLEAddress a(std::string(address), type);
    if (a.isPublic()) return "PUBLIC"; if (a.isRpa()) return "RPA"; if (a.isNrpa()) return "NRPA"; if (a.isStatic()) return "STATIC"; return "RANDOM";
}
String addressTypeName(const BleObservation &o) { return addressTypeName(o.addressType, o.address); }

const char *companyName(uint16_t id) {
    switch (id) {
        case 0x0006: return "Microsoft"; case 0x004C: return "Apple"; case 0x0057: return "Harman"; case 0x0075: return "Samsung";
        case 0x0087: return "Garmin"; case 0x009E: return "Bose"; case 0x00E0: return "Google"; case 0x012D: return "Sony";
        case 0x0131: return "Cypress"; case 0x0157: return "Xiaomi"; case 0x0499: return "Ruuvi"; default: return nullptr;
    }
}
const char *serviceName(uint16_t id) {
    switch (id) {
        case 0x1800: return "Generic Access"; case 0x1801: return "Generic Attribute"; case 0x180A: return "Device Information";
        case 0x180D: return "Heart Rate"; case 0x180F: return "Battery"; case 0x1812: return "HID"; case 0x1816: return "Cycling Speed/Cadence";
        case 0x181A: return "Environmental Sensing"; case 0x181D: return "Weight Scale"; case 0xFE2C: return "Google Fast Pair";
        case 0xFEAA: return "Eddystone"; case 0xFD6F: return "Exposure Notification"; case 0xFCF1: return "Google Service (FCF1)"; default: return nullptr;
    }
}
const char *characteristicName(uint16_t id) {
    switch (id) {
        case 0x2A00: return "Device Name"; case 0x2A01: return "Appearance"; case 0x2A19: return "Battery Level";
        case 0x2A24: return "Model Number"; case 0x2A25: return "Serial Number"; case 0x2A26: return "Firmware Revision";
        case 0x2A27: return "Hardware Revision"; case 0x2A29: return "Manufacturer Name"; case 0x2A37: return "Heart Rate Measurement";
        case 0x2A4D: return "HID Report"; default: return nullptr;
    }
}
String uuid16Label(uint16_t id) { String s = "0x" + String(id, HEX); s.toUpperCase(); if (const char *n = serviceName(id)) s += " " + String(n); return s; }
String appearanceName(uint16_t a) {
    switch (a >> 6) {
        case 1: return "Phone"; case 2: return "Computer"; case 3: return "Watch"; case 4: return "Clock"; case 5: return "Display";
        case 6: return "Remote"; case 8: return "Tag"; case 9: return "Keyring"; case 10: return "Media player"; case 11: return "Barcode scanner";
        case 12: return "Thermometer"; case 13: return "Heart-rate sensor"; case 15: return "HID"; case 18: return "Cycling sensor";
        case 49: return "Pulse oximeter"; case 50: return "Weight scale"; default: return "Unknown";
    }
}
String adTypeName(uint8_t t) {
    switch (t) {
        case 0x01: return "Flags"; case 0x02: return "16-bit UUIDs (some)"; case 0x03: return "16-bit UUIDs"; case 0x04: return "32-bit UUIDs (some)";
        case 0x05: return "32-bit UUIDs"; case 0x06: return "128-bit UUIDs (some)"; case 0x07: return "128-bit UUIDs"; case 0x08: return "Short name";
        case 0x09: return "Complete name"; case 0x0A: return "TX power"; case 0x12: return "Connection interval"; case 0x16: return "16-bit service data";
        case 0x19: return "Appearance"; case 0x20: return "32-bit service data"; case 0x21: return "128-bit service data"; case 0x24: return "URI";
        case 0xFF: return "Manufacturer data"; default: return "Unknown field";
    }
}

void appendWrapped(std::vector<String> &lines, const String &text, size_t width = 28) {
    String s = text; s.trim();
    while (s.length() > width && lines.size() < MAX_LINES) { int split = static_cast<int>(width); while (split > 8 && s.charAt(split) != ' ') split--; if (split <= 8) split = width; lines.push_back(s.substring(0, split)); s = s.substring(split); s.trim(); }
    if (!s.isEmpty() && lines.size() < MAX_LINES) lines.push_back(s);
}

void parseAdFields(const uint8_t *payload, size_t length, std::vector<String> *lines, BleObservation *obs) {
    size_t off = 0;
    while (off < length) {
        const uint8_t fl = payload[off]; if (!fl) break; const size_t end = off + static_cast<size_t>(fl) + 1;
        if (fl < 1 || end > length) { if (lines) appendWrapped(*lines, "MALFORMED field at byte " + String(off)); break; }
        const uint8_t type = payload[off + 1]; const uint8_t *data = payload + off + 2; const size_t dl = fl - 1;
        if (obs) {
            if ((type == 0x08 || type == 0x09) && dl && !obs->name[0]) copyName(obs->name, cleanText(data, dl));
            if (type == 0x19 && dl >= 2) { obs->appearance = le16(data); obs->hasAppearance = true; }
            if (type == 0x0A && dl) { obs->txPower = static_cast<int8_t>(data[0]); obs->hasTxPower = true; }
            if (type == 0xFF && dl >= 2 && !obs->companyId) obs->companyId = le16(data);
        }
        if (lines) {
            appendWrapped(*lines, "AD 0x" + String(type, HEX) + " " + String(adTypeName(type)));
            switch (type) {
                case 0x02: case 0x03: for (size_t i = 0; i + 1 < dl; i += 2) appendWrapped(*lines, "  UUID " + uuid16Label(le16(data + i))); break;
                case 0x06: case 0x07: appendWrapped(*lines, "  UUID128: " + hexBytes(data, dl, 32, true)); break;
                case 0x08: case 0x09: appendWrapped(*lines, "  Name: " + cleanText(data, dl)); break;
                case 0x0A: if (dl) appendWrapped(*lines, "  TX power: " + String(static_cast<int8_t>(data[0])) + " dBm"); break;
                case 0x12: if (dl >= 4) appendWrapped(*lines, "  Conn: " + String(le16(data) * 1.25f, 1) + "-" + String(le16(data + 2) * 1.25f, 1) + " ms"); break;
                case 0x16:
                    if (dl >= 2) { const uint16_t u = le16(data); appendWrapped(*lines, "  Service: " + uuid16Label(u)); if (u == 0xFCF1) appendWrapped(*lines, "  FCF1 payload: " + hexBytes(data + 2, dl - 2, 32, true)); else if (dl > 2) appendWrapped(*lines, "  Data: " + hexBytes(data + 2, dl - 2, 32, true)); }
                    break;
                case 0x19: if (dl >= 2) appendWrapped(*lines, "  Appearance: " + appearanceName(le16(data))); break;
                case 0x20: if (dl >= 4) appendWrapped(*lines, "  Service UUID32: " + hexBytes(data, 4, 4, true)); break;
                case 0x21: if (dl >= 16) appendWrapped(*lines, "  Service UUID128: " + hexBytes(data, 16, 16, true)); break;
                case 0x24: appendWrapped(*lines, "  URI/data: " + hexBytes(data, dl, 32, true)); break;
                case 0xFF:
                    if (dl >= 2) appendWrapped(*lines, "  Company: " + String(companyName(le16(data)) ? companyName(le16(data)) : "Unlisted") + " (0x" + String(le16(data), HEX) + ")");
                    if (dl > 2) appendWrapped(*lines, "  Data: " + hexBytes(data + 2, dl - 2, 32, true)); break;
                default: appendWrapped(*lines, "  Data: " + hexBytes(data, dl, 32, true)); break;
            }
        }
        off = end;
    }
}

uint32_t shapeHash(const uint8_t *payload, size_t length) {
    uint32_t h = 2166136261UL; size_t off = 0;
    while (off < length) {
        const uint8_t fl = payload[off]; if (!fl) break; const size_t end = off + static_cast<size_t>(fl) + 1; if (fl < 1 || end > length) break;
        const uint8_t type = payload[off + 1]; h = fnv1a(&fl, 1, h); h = fnv1a(&type, 1, h);
        if (type == 0xFF && fl >= 3) h = fnv1a(payload + off + 2, std::min<size_t>(4, fl - 1), h);
        else if ((type >= 0x02 && type <= 0x07) || type == 0x16 || type == 0x20 || type == 0x21) { const size_t n = type == 0x16 ? std::min<size_t>(2, fl - 1) : std::min<size_t>(type == 0x20 ? 4 : 16, fl - 1); h = fnv1a(payload + off + 2, n, h); }
        off = end;
    }
    return h;
}

void fillObservation(const NimBLEAdvertisedDevice *device, BleObservation &o) {
    o = BleObservation{}; if (!device) return; copyAddress(o.address, device->getAddress().toString()); o.addressType = device->getAddressType(); o.rssi = device->getRSSI(); o.advType = device->getAdvType(); o.connectable = device->isConnectable(); o.scannable = device->isScannable();
    const std::vector<uint8_t> &p = device->getPayload(); const size_t n = std::min(p.size(), MAX_PAYLOAD); o.payloadLen = n; o.advLen = std::min<size_t>(device->getAdvLength(), n); if (n) std::memcpy(o.payload, p.data(), n); if (!p.empty()) o.fullHash = fnv1a(p.data(), p.size()); if (n) o.shapeHash = shapeHash(o.payload, n);
    String name = cleanText(device->getName()); if (!name.isEmpty()) copyName(o.name, name); parseAdFields(o.payload, o.payloadLen, nullptr, &o);
    if (device->haveManufacturerData()) { const std::string m = device->getManufacturerData(); if (m.size() >= 2) o.companyId = le16(reinterpret_cast<const uint8_t *>(m.data())); }
    uint32_t sh = 2166136261UL;
    for (uint8_t i = 0; i < device->getServiceUUIDCount(); i++) { const std::string u = device->getServiceUUID(i).toString(); sh = fnv1a(reinterpret_cast<const uint8_t *>(u.data()), u.size(), sh); }
    for (uint8_t i = 0; i < device->getServiceDataCount(); i++) {
        const std::string u = device->getServiceDataUUID(i).toString(); const std::string d = device->getServiceData(i); sh = fnv1a(reinterpret_cast<const uint8_t *>(u.data()), u.size(), sh); const uint16_t dl = static_cast<uint16_t>(std::min<size_t>(d.size(), 0xFFFF)); sh = fnv1a(reinterpret_cast<const uint8_t *>(&dl), sizeof(dl), sh);
        String us(u.c_str()); us.toLowerCase(); if (us == "fcf1" || us == "0000fcf1-0000-1000-8000-00805f9b34fb") { o.hasFcf1 = true; o.fcf1Len = std::min<size_t>(d.size(), sizeof(o.fcf1)); if (o.fcf1Len) std::memcpy(o.fcf1, d.data(), o.fcf1Len); }
    }
    o.serviceHash = sh; o.hasTxPower = device->haveTXPower(); o.txPower = o.hasTxPower ? device->getTXPower() : 0; o.hasAppearance = device->haveAppearance(); o.appearance = o.hasAppearance ? device->getAppearance() : 0;
#ifdef BLE_RECON_EXT_ADV
    o.legacy = device->isLegacyAdvertisement(); if (!o.legacy) { o.sid = device->getSetId(); o.primaryPhy = device->getPrimaryPhy(); o.secondaryPhy = device->getSecondaryPhy(); o.periodicInterval = device->getPeriodicInterval(); o.dataStatus = device->getDataStatus(); }
#endif
}

String resolvedIdentity(const BleObservation &o, uint8_t &source) { if (o.name[0]) { source = ID_NAME; return String(o.name); } if (const char *m = companyName(o.companyId)) { source = ID_MFG; return String(m) + " device"; } source = ID_MAC; return String(); }

void updateFingerprint(FingerprintModel &m, const BleObservation &o) {
    if (!o.payloadLen) return;
    if (!m.valid) { std::memcpy(m.baseline, o.payload, o.payloadLen); std::memcpy(m.last, o.payload, o.payloadLen); for (size_t i = 0; i < o.payloadLen; i++) m.stable[i] = true; m.len = o.payloadLen; m.observations = 1; m.valid = true; return; }
    const size_t n = std::min<size_t>(m.len, o.payloadLen); for (size_t i = 0; i < n; i++) { if (m.last[i] != o.payload[i]) m.stable[i] = false; m.last[i] = o.payload[i]; }
    if (o.payloadLen > m.len) { for (size_t i = m.len; i < o.payloadLen; i++) { m.baseline[i] = o.payload[i]; m.last[i] = o.payload[i]; m.stable[i] = false; } m.len = o.payloadLen; }
    m.observations++;
}
int maskedSimilarity(const FingerprintModel &m, const BleObservation &o) {
    if (!m.valid || !o.payloadLen) return 0; const size_t n = std::min<size_t>(m.len, o.payloadLen); size_t stable = 0, equal = 0, rawEqual = 0;
    for (size_t i = 0; i < n; i++) { if (m.baseline[i] == o.payload[i]) rawEqual++; if (m.stable[i]) { stable++; if (m.baseline[i] == o.payload[i]) equal++; } }
    return stable >= 4 ? static_cast<int>(equal * 100 / stable) : (n ? static_cast<int>(rawEqual * 100 / n) : 0);
}
int nameScore(const char *a, const char *b) {
    if (!a || !b || !a[0] || !b[0]) return 0; String x(a), y(b); x.toLowerCase(); y.toLowerCase(); if (x == y) return 25; const size_t n = std::min(x.length(), y.length()); size_t same = 0; while (same < n && x.charAt(same) == y.charAt(same)) same++; return same >= 4 && same * 100 / n >= 70 ? 14 : 0;
}
int scoreCandidate(const HunterState &s, const BleObservation &o, uint32_t gap) {
    int identity = nameScore(s.currentName, o.name); if (s.target.companyId && s.target.companyId == o.companyId) identity += 10; if (s.target.hasAppearance && o.hasAppearance && s.target.appearance == o.appearance) identity += 5; identity = std::min(identity, 30);
    int structure = 0; if (s.target.serviceHash && s.target.serviceHash == o.serviceHash) structure += 14; if (s.target.shapeHash && s.target.shapeHash == o.shapeHash) structure += 6; if (s.target.advType == o.advType) structure += 2; if (s.target.addressType == o.addressType) structure += 2; if (s.target.payloadLen && s.target.payloadLen == o.payloadLen) structure += 2; structure = std::min(structure, 25);
    const int sim = maskedSimilarity(s.model, o); const int payload = sim >= 95 ? 25 : sim >= 85 ? 22 : sim >= 70 ? 17 : sim >= 55 ? 10 : sim >= 40 ? 5 : 0;
    const int rd = std::abs(static_cast<int>(roundf(s.stableRssi)) - o.rssi); const int radio = rd <= 5 ? 15 : rd <= 10 ? 11 : rd <= 18 ? 6 : rd <= 25 ? 2 : 0; const int timing = gap <= 2000 ? 5 : gap <= 5000 ? 3 : 1;
    return std::min(100, identity + structure + payload + radio + timing);
}
void clearCandidates(HunterState &s) { for (auto &c : s.candidates) c = Candidate{}; }
void pushHistory(HunterState &s, const char *address) { if (!address || !address[0]) return; if (s.historyCount < MAX_HISTORY) { std::strncpy(s.history[s.historyCount], address, 17); s.history[s.historyCount++][17] = '\0'; return; } for (size_t i = 1; i < MAX_HISTORY; i++) std::strncpy(s.history[i - 1], s.history[i], 17); std::strncpy(s.history[MAX_HISTORY - 1], address, 17); s.history[MAX_HISTORY - 1][17] = '\0'; }
int bestCandidate(const HunterState &s) { int best = -1; for (size_t i = 0; i < MAX_CANDIDATES; i++) if (s.candidates[i].valid && (best < 0 || s.candidates[i].score > s.candidates[best].score)) best = i; return best; }
int secondScore(const HunterState &s, int best) { int second = 0; for (size_t i = 0; i < MAX_CANDIDATES; i++) if (s.candidates[i].valid && static_cast<int>(i) != best) second = std::max(second, static_cast<int>(s.candidates[i].score)); return second; }
void acceptHandoff(HunterState &s, const Candidate &c, uint32_t now) { pushHistory(s, s.target.address); s.target = c.obs; uint8_t src = ID_MAC; const String id = resolvedIdentity(c.obs, src); if (!id.isEmpty()) { copyName(s.currentName, id); s.identitySource = src; } updateFingerprint(s.model, c.obs); s.handoffs++; s.lastHandoffScore = c.score; s.handoffNotice = now + NOTICE_MS; s.fastRssi = s.stableRssi = s.bestRssi = c.obs.rssi; s.trend = s.jitter = 0; s.samples = 1; s.lastSeen = s.lastPacket = now; s.rateStart = now; s.ratePackets = 1; s.pps = s.gapEma = 0; clearCandidates(s); }

class HunterCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device) return; BleObservation o; fillObservation(device, o); const uint32_t now = millis(); portENTER_CRITICAL(&reconMux); const bool current = std::strncmp(o.address, hunterState.target.address, 17) == 0; const HunterState snap = hunterState; portEXIT_CRITICAL(&reconMux);
        if (current) {
            const bool lost = snap.initialized && now - snap.lastSeen > LOST_MS; if (lost) medianWindow.reset(); medianWindow.add(o.rssi); const float med = medianWindow.median(); portENTER_CRITICAL(&reconMux); updateFingerprint(hunterState.model, o); hunterState.target = o; uint8_t src = ID_MAC; const String id = resolvedIdentity(o, src); if (!id.isEmpty() && src == ID_NAME) { copyName(hunterState.currentName, id); hunterState.identitySource = src; }
            if (lost) { hunterState.offlineMs = now - hunterState.lastSeen; hunterState.reacquisitions++; hunterState.reacquireNotice = now + NOTICE_MS; hunterState.fastRssi = hunterState.stableRssi = hunterState.bestRssi = med; hunterState.trend = hunterState.jitter = 0; hunterState.samples = 1; hunterState.lastSeen = hunterState.lastPacket = now; hunterState.rateStart = now; hunterState.ratePackets = 1; hunterState.pps = hunterState.gapEma = 0; portEXIT_CRITICAL(&reconMux); return; }
            if (hunterState.lastPacket) { const uint32_t gap = now - hunterState.lastPacket; if (gap < 60000) hunterState.gapEma = hunterState.gapEma <= 0.1f ? gap : hunterState.gapEma + 0.18f * (gap - hunterState.gapEma); }
            hunterState.lastPacket = now; hunterState.ratePackets++; if (now - hunterState.rateStart >= 1000) { hunterState.pps = hunterState.ratePackets * 1000.0f / (now - hunterState.rateStart); hunterState.rateStart = now; hunterState.ratePackets = 0; }
            if (!hunterState.initialized) { hunterState.fastRssi = hunterState.stableRssi = hunterState.bestRssi = med; hunterState.samples = 1; hunterState.lastSeen = now; hunterState.initialized = true; portEXIT_CRITICAL(&reconMux); return; }
            hunterState.fastRssi += 0.45f * (med - hunterState.fastRssi); hunterState.stableRssi += 0.14f * (med - hunterState.stableRssi); hunterState.trend = hunterState.fastRssi - hunterState.stableRssi; hunterState.jitter += 0.18f * (fabsf(static_cast<float>(o.rssi) - hunterState.fastRssi) - hunterState.jitter); if (hunterState.stableRssi > hunterState.bestRssi) hunterState.bestRssi = hunterState.stableRssi; hunterState.samples++; hunterState.lastSeen = now; clearCandidates(hunterState); portEXIT_CRITICAL(&reconMux); return;
        }
        if (!snap.initialized) return; const uint32_t gap = now - snap.lastSeen; if (gap < HANDOFF_ARM_MS || gap > HANDOFF_MAX_GAP_MS) return; const int score = scoreCandidate(snap, o, gap); if (score < 45) return;
        portENTER_CRITICAL(&reconMux); int slot = -1; for (size_t i = 0; i < MAX_CANDIDATES; i++) if (hunterState.candidates[i].valid && std::strncmp(hunterState.candidates[i].obs.address, o.address, 17) == 0) { slot = i; break; }
        if (slot < 0) for (size_t i = 0; i < MAX_CANDIDATES; i++) if (!hunterState.candidates[i].valid) { slot = i; break; }
        if (slot < 0) { int weak = 0; for (size_t i = 1; i < MAX_CANDIDATES; i++) if (hunterState.candidates[i].score < hunterState.candidates[weak].score) weak = i; if (score > hunterState.candidates[weak].score) slot = weak; }
        if (slot < 0) { portEXIT_CRITICAL(&reconMux); return; }
        Candidate &c = hunterState.candidates[slot]; if (!c.valid || now - c.lastSeen > CANDIDATE_STALE_MS) { c = Candidate{}; c.valid = true; c.firstSeen = now; } c.obs = o; c.score = score; c.hits = c.hits < 255 ? c.hits + 1 : 255; c.lastSeen = now;
        const int best = bestCandidate(hunterState), second = secondScore(hunterState, best); const bool dominant = best >= 0 && (second == 0 || hunterState.candidates[best].score - second >= HANDOFF_MARGIN); bool accepted = false; Candidate acceptedCandidate; if (best >= 0 && dominant && hunterState.candidates[best].score >= HANDOFF_THRESHOLD && hunterState.candidates[best].hits >= HANDOFF_HITS) { acceptedCandidate = hunterState.candidates[best]; acceptHandoff(hunterState, acceptedCandidate, now); accepted = true; }
        portEXIT_CRITICAL(&reconMux); if (accepted) { medianWindow.reset(); medianWindow.add(acceptedCandidate.obs.rssi); Serial.printf("[BLE-HUNTER] HANDOFF %s score=%u hits=%u gap=%lums\n", acceptedCandidate.obs.address, acceptedCandidate.score, acceptedCandidate.hits, static_cast<unsigned long>(gap)); }
    }
};
HunterCallbacks hunterCallbacks;

void resetHunter(const BleObservation &target) { portENTER_CRITICAL(&reconMux); hunterState = HunterState{}; hunterState.target = target; uint8_t src = ID_MAC; const String id = resolvedIdentity(target, src); if (!id.isEmpty()) copyName(hunterState.currentName, id); hunterState.identitySource = src; updateFingerprint(hunterState.model, target); std::strncpy(selectedAddress, target.address, 17); selectedAddress[17] = '\0'; portEXIT_CRITICAL(&reconMux); medianWindow.reset(); }
HunterState hunterSnapshot() { HunterState s; portENTER_CRITICAL(&reconMux); s = hunterState; portEXIT_CRITICAL(&reconMux); return s; }

void drawHunterDetails(const HunterState &s) {
    std::vector<String> lines; appendWrapped(lines, "IDENTITY: " + String(s.currentName[0] ? s.currentName : "Unnamed")); appendWrapped(lines, "SOURCE: " + String(s.identitySource == ID_NAME ? "ADVERTISED NAME" : s.identitySource == ID_MFG ? "MANUFACTURER" : "ADDRESS")); appendWrapped(lines, "CURRENT: " + String(s.target.address)); appendWrapped(lines, "TYPE: " + addressTypeName(s.target)); appendWrapped(lines, "COMPANY: 0x" + String(s.target.companyId, HEX)); appendWrapped(lines, "SERVICE HASH: " + String(s.target.serviceHash, HEX)); appendWrapped(lines, "SHAPE HASH: " + String(s.target.shapeHash, HEX)); appendWrapped(lines, "PAYLOAD: " + String(s.target.payloadLen) + " bytes"); size_t stable = 0; for (size_t i = 0; i < s.model.len; i++) if (s.model.stable[i]) stable++; appendWrapped(lines, "STABLE: " + String(stable) + "  VOLATILE: " + String(s.model.len - stable)); appendWrapped(lines, "OBSERVATIONS: " + String(s.model.observations)); appendWrapped(lines, "ADDRESS HISTORY:"); for (uint8_t i = 0; i < s.historyCount; i++) appendWrapped(lines, String(i + 1) + ": " + String(s.history[i])); appendWrapped(lines, "CANDIDATES:"); for (size_t i = 0; i < MAX_CANDIDATES; i++) if (s.candidates[i].valid) appendWrapped(lines, String(i + 1) + " " + String(s.candidates[i].obs.address) + " score=" + String(s.candidates[i].score) + " hits=" + String(s.candidates[i].hits));
    size_t scroll = 0; while (!check(EscPress)) { tft.fillScreen(bruceConfig.bgColor); drawMainBorder(false); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); tft.drawCentreString("BLE HUNTER DETAILS", tftWidth / 2, 29, 1); const int first = 50, footer = tftHeight - 18, visible = (footer - first) / 12; if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1; for (int r = 0; r < visible && scroll + r < lines.size(); r++) tft.drawString(lines[scroll + r], 8, first + r * 12, 1); if (check(PrevPress) && scroll) scroll--; if (check(NextPress)) scroll++; tft.drawCentreString("Turn scroll  Esc", tftWidth / 2, footer, 1); drawStatusBar(); delay(20); }
}
bool startPassiveHunter() { if (!pBLEScan) return false; pBLEScan->stop(); pBLEScan->clearResults(); pBLEScan->setActiveScan(false); pBLEScan->setInterval(SCAN_INT); pBLEScan->setWindow(SCAN_WINDOW); pBLEScan->setMaxResults(0); pBLEScan->setScanCallbacks(&hunterCallbacks, true); return pBLEScan->start(0, false, true); }
void huntTarget(const BleObservation &target) {
    ble_scan_setup(); if (!pBLEScan) { displayError("BLE scanner unavailable", true); return; } resetHunter(target); if (!startPassiveHunter()) { stopBLEStack(); displayError("Unable to start BLE scan", true); return; }
    uint32_t draw = 0; while (!check(EscPress)) { if (check(LongPress) || check(SelPress)) { drawHunterDetails(hunterSnapshot()); draw = 0; delay(100); } if (millis() - draw >= 250) { const HunterState s = hunterSnapshot(); tft.fillScreen(bruceConfig.bgColor); drawMainBorder(false); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); tft.setTextSize(FP); tft.drawCentreString("BLE HUNTER DF", tftWidth / 2, 29, 1); tft.drawCentreString(s.currentName[0] ? String(s.currentName) : String(s.target.address), tftWidth / 2, 42, 1); tft.drawCentreString(addressTypeName(s.target) + " " + String(s.target.address), tftWidth / 2, 54, 1); const uint32_t now = millis(); String status = now - s.handoffNotice < NOTICE_MS ? "HANDOFF " + String(s.lastHandoffScore) : now - s.reacquireNotice < NOTICE_MS ? "REACQUIRED " + String(s.offlineMs / 1000) + "s" : now - s.lastSeen > LOST_MS ? "TARGET LOST" : s.trend >= 3 ? "WARMER" : s.trend <= -3 ? "COLDER" : "STEADY"; tft.setTextColor(status.startsWith("TARGET") ? TFT_RED : bruceConfig.priColor, bruceConfig.bgColor); tft.drawCentreString(status, tftWidth / 2, 69, 1); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); tft.drawString("RSSI " + String(s.stableRssi, 1) + "  PEAK " + String(s.bestRssi, 1), 10, 88, 1); tft.drawString("TREND " + String(s.trend, 1) + "  JIT " + String(s.jitter, 1), 10, 101, 1); tft.drawString("RATE " + String(s.pps, 1) + "/s  GAP " + String(s.gapEma, 0) + "ms", 10, 114, 1); tft.drawString("HANDOFF " + String(s.handoffs) + "  REACQ " + String(s.reacquisitions), 10, 127, 1); tft.drawString("MATCH " + String(s.lastHandoffScore), 10, 140, 1); tft.drawCentreString("Hold details  Esc back", tftWidth / 2, tftHeight - 14, 1); drawStatusBar(); draw = millis(); } delay(10); }
    pBLEScan->stop(); pBLEScan->setScanCallbacks(nullptr, false); pBLEScan->setMaxResults(0xFF); pBLEScan->clearResults(); stopBLEStack();
}

std::vector<BleObservation> discoverTargets(bool active) {
    std::vector<BleObservation> out; ble_scan_setup(); if (!pBLEScan) return out; pBLEScan->stop(); pBLEScan->clearResults(); pBLEScan->setActiveScan(active); pBLEScan->setInterval(SCAN_INT); pBLEScan->setWindow(SCAN_WINDOW); pBLEScan->setMaxResults(80); displayTextLine(active ? "Scanning BLE advertisers..." : "Listening for BLE advertisers..."); BLEScanResults results = pBLEScan->getResults(DISCOVERY_MS, false); out.reserve(std::min(results.getCount(), 60)); for (int i = 0; i < results.getCount() && out.size() < 60; i++) { const NimBLEAdvertisedDevice *d = results.getDevice(i); if (!d) continue; BleObservation o; fillObservation(d, o); out.push_back(o); } std::sort(out.begin(), out.end(), [](const BleObservation &a, const BleObservation &b) { return a.rssi > b.rssi; }); pBLEScan->clearResults(); return out;
}

void updateMutation(MutationModel &m, const BleObservation &o) {
    if (!o.payloadLen) return;
    if (!m.valid) { std::memcpy(m.baseline, o.payload, o.payloadLen); std::memcpy(m.last, o.payload, o.payloadLen); m.len = o.payloadLen; m.observations = 1; m.valid = true; return; }
    const size_t n = std::min<size_t>(m.len, o.payloadLen); m.lastDiffLen = 0; m.lastChanged = 0;
    for (size_t i = 0; i < n; i++) {
        if (m.last[i] != o.payload[i]) { m.volatileMask[i] = true; if (m.changeHits[i] < 255) m.changeHits[i]++; if (static_cast<uint8_t>(m.last[i] + 1) == o.payload[i] && m.counterHits[i] < 255) m.counterHits[i]++; if (m.lastDiffLen < MAX_PAYLOAD) m.lastDiff[m.lastDiffLen++] = static_cast<uint8_t>(i); m.lastChanged++; }
        m.last[i] = o.payload[i];
    }
    if (m.lastChanged) m.changes++; m.observations++;
}

void updateFcf1(Fcf1Tracker &f, const BleObservation &o, uint32_t now) {
    if (!o.hasFcf1) return; const bool macChanged = f.seen && std::strncmp(f.currentAddress, o.address, 17) != 0; const bool payloadChanged = f.seen && (f.len != o.fcf1Len || (f.len && std::memcmp(f.payload, o.fcf1, f.len) != 0));
    if (!f.seen) { f.seen = true; f.firstSeen = now; } else { if (macChanged) f.macChanges++; if (payloadChanged) f.payloadChanges++; if (macChanged && payloadChanged) f.correlated++; else if (macChanged) f.macOnly++; else if (payloadChanged) f.payloadOnly++; }
    if (macChanged) { std::strncpy(f.previousAddress, f.currentAddress, 17); f.previousAddress[17] = '\0'; } std::strncpy(f.currentAddress, o.address, 17); f.currentAddress[17] = '\0'; f.addressType = o.addressType; f.len = o.fcf1Len; if (f.len) std::memcpy(f.payload, o.fcf1, f.len); f.lastSeen = now; f.count++;
}

class SnifferCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device) return; BleObservation o; fillObservation(device, o); const uint32_t now = millis(); const bool scanResponse = o.advType == 4;
        portENTER_CRITICAL(&reconMux); const bool same = std::strncmp(o.address, selectedAddress, 17) == 0; const SnifferState snap = snifferState; portEXIT_CRITICAL(&reconMux);
        bool selected = same;
        if (!selected && snap.initialized && now - snap.lastSeen > LOST_MS) {
            HunterState h; h.target = snap.target; h.model.valid = snap.mutation.valid; h.model.len = snap.mutation.len; h.model.observations = snap.mutation.observations; if (h.model.valid) { std::memcpy(h.model.baseline, snap.mutation.baseline, MAX_PAYLOAD); for (size_t i = 0; i < MAX_PAYLOAD; i++) h.model.stable[i] = !snap.mutation.volatileMask[i]; }
            selected = scoreCandidate(h, o, now - snap.lastSeen) >= HANDOFF_THRESHOLD;
            if (selected) { portENTER_CRITICAL(&reconMux); std::strncpy(selectedAddress, o.address, 17); selectedAddress[17] = '\0'; portEXIT_CRITICAL(&reconMux); }
        }
        if (!selected) return;
        portENTER_CRITICAL(&reconMux);
        if (!scanResponse) {
            const uint32_t previousSeen = snifferState.lastSeen; updateMutation(snifferState.mutation, o); updateFcf1(snifferState.fcf1, o, now); snifferState.target = o; snifferState.packets++; snifferState.initialized = true;
            if (previousSeen && now - previousSeen < 60000) { const uint32_t gap = now - previousSeen; snifferState.gapEma = snifferState.gapEma <= 0.1f ? gap : snifferState.gapEma + 0.18f * (gap - snifferState.gapEma); }
            snifferState.lastSeen = now; if (!snifferState.rateStart) snifferState.rateStart = now; snifferState.ratePackets++; if (now - snifferState.rateStart >= 1000) { snifferState.pps = snifferState.ratePackets * 1000.0f / (now - snifferState.rateStart); snifferState.rateStart = now; snifferState.ratePackets = 0; }
        }
        const std::vector<uint8_t> &p = device->getPayload(); const size_t adv = std::min<size_t>(device->getAdvLength(), p.size()); if (scanResponse || (adv < p.size() && device->getAdvLength() > 0)) { const size_t start = scanResponse ? 0 : adv; const size_t n = std::min(p.size() - start, MAX_RESPONSE); std::memcpy(snifferState.response, p.data() + start, n); snifferState.responseLen = n; if (activeBurst) snifferState.activeResponses++; }
        if (activeBurst && device->isScannable()) snifferState.activeReports++; portEXIT_CRITICAL(&reconMux);
    }
};
SnifferCallbacks snifferCallbacks;
SnifferState snifferSnapshot() { SnifferState s; portENTER_CRITICAL(&reconMux); s = snifferState; portEXIT_CRITICAL(&reconMux); return s; }
void resetSniffer(const BleObservation &o) { portENTER_CRITICAL(&reconMux); snifferState = SnifferState{}; snifferState.target = o; std::strncpy(selectedAddress, o.address, 17); selectedAddress[17] = '\0'; portEXIT_CRITICAL(&reconMux); }
String mutationClass(const MutationModel &m) { if (!m.observations || !m.changes) return "NO MUTATION OBSERVED"; size_t vol = 0, ctr = 0; for (size_t i = 0; i < m.len; i++) { if (m.volatileMask[i]) vol++; if (m.counterHits[i] >= 2) ctr++; } if (ctr) return "COUNTER-LIKE FIELD(S) DETECTED"; return vol * 100 >= m.len * 60 ? "HIGH VOLATILITY / POSSIBLY ENCRYPTED" : "PARTIAL VOLATILITY / LIVE DATA"; }

void drawSniffer(const SnifferState &s, uint8_t view, size_t &scroll, bool frozen) {
    tft.fillScreen(bruceConfig.bgColor); drawMainBorder(false); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); tft.setTextSize(FP); const char *vn = view == 0 ? "PLAIN" : view == 1 ? "AD FIELDS" : view == 2 ? "RAW" : view == 3 ? "MUTATION" : "ACTIVE"; tft.drawCentreString(String("BLE SNIFFER - ") + vn, tftWidth / 2, 29, 1); tft.drawCentreString(s.target.name[0] ? String(s.target.name) : String(s.target.address), tftWidth / 2, 42, 1); const bool lost = s.initialized && millis() - s.lastSeen > LOST_MS; tft.setTextColor(lost ? TFT_RED : bruceConfig.priColor, bruceConfig.bgColor); tft.drawCentreString(lost ? "TARGET QUIET" : String(s.target.rssi) + " dBm  " + String(s.packets) + " pkt", tftWidth / 2, 54, 1);
    std::vector<String> lines;
    if (view == 0) { appendWrapped(lines, "Address: " + String(s.target.address)); appendWrapped(lines, "Type: " + addressTypeName(s.target)); appendWrapped(lines, s.target.connectable ? "Connectable" : "Not connectable"); appendWrapped(lines, s.target.scannable ? "Scannable" : "Non-scannable"); appendWrapped(lines, "Company: " + String(companyName(s.target.companyId) ? companyName(s.target.companyId) : "Unlisted") + " 0x" + String(s.target.companyId, HEX)); appendWrapped(lines, "Payload: " + String(s.target.payloadLen) + " bytes"); appendWrapped(lines, "Rate: " + String(s.pps, 1) + "/s  gap " + String(s.gapEma, 0) + "ms"); if (s.target.hasAppearance) appendWrapped(lines, "Appearance: " + appearanceName(s.target.appearance)); if (s.fcf1.seen) appendWrapped(lines, "Google Service (FCF1) DETECTED");
#ifdef BLE_RECON_EXT_ADV
        appendWrapped(lines, s.target.legacy ? "Legacy advertising" : "Extended advertising"); if (!s.target.legacy) { appendWrapped(lines, "SID " + String(s.target.sid) + " PHY " + String(s.target.primaryPhy) + "/" + String(s.target.secondaryPhy)); appendWrapped(lines, "Data status " + String(s.target.dataStatus)); appendWrapped(lines, s.target.periodicInterval ? "Periodic interval: " + String(s.target.periodicInterval) + " units" : "No periodic interval advertised"); }
#endif
    } else if (view == 1) { parseAdFields(s.target.payload, s.target.payloadLen, &lines, nullptr); if (s.responseLen) { appendWrapped(lines, "SCAN RESPONSE"); parseAdFields(s.response, s.responseLen, &lines, nullptr); } }
    else if (view == 2) { appendWrapped(lines, "ADV PAYLOAD"); for (size_t i = 0; i < s.target.payloadLen; i += 8) lines.push_back(String(i, HEX) + ": " + hexBytes(s.target.payload + i, std::min<size_t>(8, s.target.payloadLen - i), 8, true)); if (s.responseLen) { appendWrapped(lines, "SCAN RESPONSE"); for (size_t i = 0; i < s.responseLen; i += 8) lines.push_back(String(i, HEX) + ": " + hexBytes(s.response + i, std::min<size_t>(8, s.responseLen - i), 8, true)); } }
    else if (view == 3) { appendWrapped(lines, mutationClass(s.mutation)); appendWrapped(lines, "Observations: " + String(s.mutation.observations)); appendWrapped(lines, "Payload changes: " + String(s.mutation.changes)); appendWrapped(lines, "Last changed bytes: " + String(s.mutation.lastChanged)); appendWrapped(lines, "Last diff offsets: " + hexBytes(s.mutation.lastDiff, s.mutation.lastDiffLen, 48, true)); size_t stable = 0, vol = 0, ctr = 0; for (size_t i = 0; i < s.mutation.len; i++) { if (s.mutation.volatileMask[i]) vol++; else stable++; if (s.mutation.counterHits[i] >= 2) ctr++; } appendWrapped(lines, "Stable " + String(stable) + "  Volatile " + String(vol) + "  Counter-like " + String(ctr)); if (s.fcf1.seen) { appendWrapped(lines, "--- GOOGLE SERVICE (FCF1) ---"); appendWrapped(lines, "Payload " + String(s.fcf1.len) + " bytes: " + hexBytes(s.fcf1.payload, s.fcf1.len, 32, true)); appendWrapped(lines, "First " + String(s.fcf1.firstSeen / 1000) + "s  Last " + String(s.fcf1.lastSeen / 1000) + "s  Count " + String(s.fcf1.count)); appendWrapped(lines, "MAC changes " + String(s.fcf1.macChanges) + "  Payload changes " + String(s.fcf1.payloadChanges)); appendWrapped(lines, "Correlated MAC+payload " + String(s.fcf1.correlated)); appendWrapped(lines, "MAC-only " + String(s.fcf1.macOnly) + "  Payload-only " + String(s.fcf1.payloadOnly)); appendWrapped(lines, "Current " + String(s.fcf1.currentAddress) + " " + addressTypeName(s.fcf1.addressType, s.fcf1.currentAddress)); if (s.fcf1.previousAddress[0]) appendWrapped(lines, "Previous " + String(s.fcf1.previousAddress)); } }
    else { appendWrapped(lines, s.activeComplete ? "Active scan complete" : "No active scan performed"); appendWrapped(lines, "Bursts " + String(s.activeBursts) + "  Scannable reports " + String(s.activeReports)); appendWrapped(lines, "Scan responses " + String(s.activeResponses)); if (s.responseLen) parseAdFields(s.response, s.responseLen, &lines, nullptr); }
    const int first = 69, footer = tftHeight - 19, visible = (footer - first) / 12; if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1; for (int r = 0; r < visible && scroll + r < lines.size(); r++) tft.drawString(lines[scroll + r], 8, first + r * 12, 1); if (scroll) tft.drawRightString("^", tftWidth - 7, first, 1); if (scroll + visible < lines.size()) tft.drawRightString("v", tftWidth - 7, footer - 12, 1); tft.drawCentreString("Turn scroll  Hold actions", tftWidth / 2, footer, 1); drawStatusBar();
}

bool confirmAction(const String &title, const std::vector<String> &messages) { const uint32_t start = millis(); while (true) { tft.fillScreen(bruceConfig.bgColor); drawMainBorder(false); tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor); tft.drawCentreString(title, tftWidth / 2, 31, 1); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); int y = 54; for (const String &m : messages) { tft.drawCentreString(m, tftWidth / 2, y, 1); y += 15; } tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor); tft.drawCentreString("Select: continue  Esc: cancel", tftWidth / 2, tftHeight - 21, 1); drawStatusBar(); if (check(EscPress)) return false; if (millis() - start > 650 && check(SelPress)) return true; delay(25); } }
bool startPassiveSniffer() { if (!pBLEScan) return false; pBLEScan->stop(); pBLEScan->clearResults(); pBLEScan->setActiveScan(false); pBLEScan->setInterval(SCAN_INT); pBLEScan->setWindow(SCAN_WINDOW); pBLEScan->setMaxResults(0); pBLEScan->setScanCallbacks(&snifferCallbacks, true); return pBLEScan->start(0, false, true); }
void runActiveScan() {
    if (!confirmAction("ACTIVE SCAN - TRANSMITS", {"3-second scan-request burst", "Nearby scannable devices may receive requests", "No BLE connection is made"})) return; pBLEScan->stop(); pBLEScan->clearResults(); portENTER_CRITICAL(&reconMux); snifferState.activeBursts++; snifferState.activeReports = 0; snifferState.activeResponses = 0; snifferState.responseLen = 0; activeBurst = true; portEXIT_CRITICAL(&reconMux);
    pBLEScan->setActiveScan(true); pBLEScan->setInterval(SCAN_INT); pBLEScan->setWindow(SCAN_WINDOW); pBLEScan->setMaxResults(0); pBLEScan->setScanCallbacks(&snifferCallbacks, true); pBLEScan->start(0, false, true); const uint32_t start = millis(); while (millis() - start < 3000) { tft.fillScreen(bruceConfig.bgColor); drawMainBorder(false); tft.setTextColor(TFT_RED, bruceConfig.bgColor); tft.drawCentreString("ACTIVE - TRANSMITTING", tftWidth / 2, 40, 1); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); tft.drawCentreString("BLE scan requests are on air", tftWidth / 2, 65, 1); tft.drawCentreString("Esc stops burst early", tftWidth / 2, tftHeight - 21, 1); drawStatusBar(); if (check(EscPress)) break; delay(80); }
    pBLEScan->stop(); portENTER_CRITICAL(&reconMux); activeBurst = false; snifferState.activeComplete = true; portEXIT_CRITICAL(&reconMux); startPassiveSniffer();
}
String characteristicProperties(const NimBLERemoteCharacteristic *c) { String p; if (c->canRead()) p += "R "; if (c->canWrite()) p += "W "; if (c->canWriteNoResponse()) p += "WNR "; if (c->canNotify()) p += "N "; if (c->canIndicate()) p += "I "; p.trim(); return p.isEmpty() ? "none" : p; }
GattResult enumerateGatt(const BleObservation &target) {
    GattResult r; pBLEScan->stop(); pBLEScan->setScanCallbacks(nullptr, false); pBLEScan->clearResults(); displayTextLine("Connecting for GATT map..."); NimBLEClient *client = NimBLEDevice::createClient(); if (!client) { r.error = "Could not create BLE client"; return r; } client->setConnectTimeout(8000); client->setConnectRetries(0); client->setConnectionParams(12, 24, 0, 400); NimBLEAddress peer(std::string(target.address), target.addressType);
    if (!client->connect(peer, true, false, false)) { r.error = "Connection failed (error " + String(client->getLastError()) + ")"; NimBLEDevice::deleteClient(client); return r; } r.connected = true;
    if (!client->discoverAttributes()) r.error = "GATT discovery failed (error " + String(client->getLastError()) + ")"; else { r.discovered = true; const auto &services = client->getServices(false); for (const NimBLERemoteService *s : services) { if (!s) continue; r.services++; const String u(s->getUUID().toString().c_str()); r.serviceLines.push_back(u); if (r.tree.size() < MAX_GATT_LINES) r.tree.push_back("SERVICE " + u); const auto &chars = s->getCharacteristics(false); for (const NimBLERemoteCharacteristic *c : chars) { if (!c) continue; r.characteristics++; if (c->canRead()) r.readable++; if (c->canWrite() || c->canWriteNoResponse()) r.writable++; if (c->canNotify()) r.notify++; if (c->canIndicate()) r.indicate++; const String cu(c->getUUID().toString().c_str()); if (r.tree.size() < MAX_GATT_LINES) { r.tree.push_back("  CHAR " + cu); r.tree.push_back("    PROPS " + characteristicProperties(c)); } else r.truncated = true; const auto &ds = c->getDescriptors(false); for (const NimBLERemoteDescriptor *d : ds) { if (!d) continue; r.descriptors++; if (r.tree.size() < MAX_GATT_LINES) r.tree.push_back("    DESC " + String(d->getUUID().toString().c_str())); else r.truncated = true; } } } }
    if (client->isConnected()) client->disconnect(); delay(80); NimBLEDevice::deleteClient(client); return r;
}
void showGatt(const GattResult &r, const String &identity) { bool tech = false; size_t scroll = 0; while (!check(EscPress)) { std::vector<String> lines; if (!r.connected) appendWrapped(lines, r.error.isEmpty() ? "Connection failed" : r.error); else if (!r.discovered) appendWrapped(lines, r.error.isEmpty() ? "GATT discovery failed" : r.error); else { appendWrapped(lines, tech ? "STRUCTURE ONLY - NO VALUES READ" : "GATT mapped; disconnected"); appendWrapped(lines, String(r.services) + " services  " + String(r.characteristics) + " chars  " + String(r.descriptors) + " desc"); appendWrapped(lines, String(r.readable) + " readable  " + String(r.writable) + " writable"); appendWrapped(lines, String(r.notify) + " notify  " + String(r.indicate) + " indicate"); if (tech) for (const String &x : r.tree) lines.push_back(x); else for (const String &x : r.serviceLines) appendWrapped(lines, "Service: " + x); if (r.truncated) appendWrapped(lines, "Technical tree truncated"); } tft.fillScreen(bruceConfig.bgColor); drawMainBorder(false); tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor); tft.drawCentreString(tech ? "GATT TECHNICAL" : "GATT PLAIN", tftWidth / 2, 29, 1); tft.drawCentreString(identity, tftWidth / 2, 42, 1); tft.setTextColor(TFT_GREEN, bruceConfig.bgColor); tft.drawCentreString("DISCONNECTED - NO VALUES", tftWidth / 2, 54, 1); const int first = 69, footer = tftHeight - 19, visible = (footer - first) / 12; if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1; for (int row = 0; row < visible && scroll + row < lines.size(); row++) tft.drawString(lines[scroll + row], 8, first + row * 12, 1); if (check(PrevPress) && scroll) scroll--; if (check(NextPress)) scroll++; if (check(SelPress)) { tech = !tech; scroll = 0; delay(100); } tft.drawCentreString("Turn scroll  Select tree  Esc", tftWidth / 2, footer, 1); drawStatusBar(); delay(20); } }

void sniffTarget(const BleObservation &target) {
    ble_scan_setup(); if (!pBLEScan) { displayError("BLE scanner unavailable", true); return; } resetSniffer(target); if (!startPassiveSniffer()) { stopBLEStack(); displayError("Unable to start BLE scan", true); return; }
    uint8_t view = 0; size_t scroll = 0; bool frozen = false; SnifferState frozenState; uint32_t draw = 0;
    while (!check(EscPress)) {
        if (check(PrevPress)) { if (scroll) scroll--; else view = (view + 4) % 5; } if (check(NextPress)) scroll++;
        if (check(LongPress) || check(SelPress)) { std::vector<Option> actions; int chosen = -1; actions.emplace_back("Active scan request (3s)", [&chosen]() { chosen = 0; }); actions.emplace_back("Connect + map GATT", [&chosen]() { chosen = 1; }); actions.emplace_back("Next view", [&chosen]() { chosen = 2; }); actions.emplace_back(frozen ? "Unfreeze frame" : "Freeze frame", [&chosen]() { chosen = 3; }); loopOptions(actions, MENU_TYPE_REGULAR, "BLE Sniffer", 0, false);
            if (chosen == 0) { frozen = false; runActiveScan(); view = 4; scroll = 0; } else if (chosen == 1) { frozen = false; const SnifferState s = snifferSnapshot(); if (!s.target.connectable) displayWarning("Target is not advertising connectable", true); else if (confirmAction("CONNECT + MAP GATT", {"Target will see a connection", "Structure discovery only", "NO READS / WRITES / SUBSCRIPTIONS"})) { const GattResult r = enumerateGatt(s.target); showGatt(r, s.target.name[0] ? String(s.target.name) : String(s.target.address)); startPassiveSniffer(); } } else if (chosen == 2) { view = (view + 1) % 5; scroll = 0; } else if (chosen == 3) { frozen = !frozen; if (frozen) frozenState = snifferSnapshot(); } delay(100); }
        if (millis() - draw >= (frozen ? 1000 : 300)) { drawSniffer(frozen ? frozenState : snifferSnapshot(), view, scroll, frozen); draw = millis(); } delay(10);
    }
    pBLEScan->stop(); pBLEScan->setScanCallbacks(nullptr, false); pBLEScan->setMaxResults(0xFF); pBLEScan->clearResults(); stopBLEStack();
}

} // namespace

void bleHunterV3() {
    const std::vector<BleObservation> targets = discoverTargets(false); if (targets.empty()) { displayWarning("No BLE advertisers found", true); stopBLEStack(); return; } options.clear();
    for (size_t i = 0; i < std::min<size_t>(targets.size(), 60); i++) { const BleObservation target = targets[i]; String label = target.name[0] ? String(target.name) : String(target.address); if (target.name[0]) label += " [" + String(target.address).substring(12) + "]"; label += " " + String(target.rssi); options.emplace_back(label, [target]() { huntTarget(target); }); }
    addOptionToMainMenu(); loopOptions(options, MENU_TYPE_REGULAR, "BLE Hunter target", 0, false); options.clear(); stopBLEStack();
}
void bleSnifferV3() {
    const std::vector<BleObservation> targets = discoverTargets(true); if (targets.empty()) { displayWarning("No BLE advertisers found", true); stopBLEStack(); return; } options.clear();
    for (size_t i = 0; i < std::min<size_t>(targets.size(), 60); i++) { const BleObservation target = targets[i]; String label = target.name[0] ? String(target.name) : String(target.address); if (target.name[0]) label += " [" + String(target.address).substring(12) + "]"; label += " " + String(target.rssi); options.emplace_back(label, [target]() { sniffTarget(target); }); }
    addOptionToMainMenu(); loopOptions(options, MENU_TYPE_REGULAR, "BLE Sniffer target", 0, false); options.clear(); stopBLEStack();
}
