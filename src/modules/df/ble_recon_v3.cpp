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

constexpr uint32_t DISCOVERY_TIME_MS = 5000;
constexpr uint32_t LOST_TARGET_MS = 3000;
constexpr uint32_t HANDOFF_ARM_MS = 900;
constexpr uint32_t HANDOFF_MAX_GAP_MS = 10000;
constexpr uint32_t HANDOFF_NOTICE_MS = 3000;
constexpr uint32_t REACQUIRE_NOTICE_MS = 2500;
constexpr uint32_t CANDIDATE_STALE_MS = 2500;
constexpr int HANDOFF_SCORE_THRESHOLD = 78;
constexpr uint8_t HANDOFF_HITS_REQUIRED = 3;
constexpr uint8_t HANDOFF_MARGIN_REQUIRED = 10;
constexpr size_t MEDIAN_WINDOW_SIZE = 7;
constexpr size_t MAX_PAYLOAD_BYTES = 256;
constexpr size_t MAX_SCAN_RESPONSE_BYTES = 128;
constexpr size_t MAX_NAME_BYTES = 40;
constexpr size_t MAX_CANDIDATES = 6;
constexpr size_t MAX_ADDRESS_HISTORY = 8;
constexpr size_t MAX_AD_LINES = 160;
constexpr size_t MAX_GATT_LINES = 220;
constexpr size_t MAX_MUTATION_EVENTS = 6;

#if __has_include(<NimBLEExtAdvertising.h>)
#define BLE_RECON_EXT_ADV 1
#endif

enum IdentitySource : uint8_t {
    ID_ADDRESS = 0,
    ID_ADVERTISED_NAME = 1,
    ID_MANUFACTURER = 2,
};

struct BleObservation {
    char address[18]{};
    uint8_t addressType = 0;
    char name[MAX_NAME_BYTES + 1]{};
    int rssi = -127;
    uint8_t advType = 0;
    bool connectable = false;
    bool scannable = false;
    uint8_t payload[MAX_PAYLOAD_BYTES]{};
    uint16_t payloadLen = 0;
    uint16_t advLen = 0;
    uint8_t scanResponse[MAX_SCAN_RESPONSE_BYTES]{};
    uint16_t scanResponseLen = 0;
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
    uint8_t baseline[MAX_PAYLOAD_BYTES]{};
    uint16_t baselineLen = 0;
    bool stable[MAX_PAYLOAD_BYTES]{};
    uint8_t last[MAX_PAYLOAD_BYTES]{};
    uint32_t observations = 0;
    bool valid = false;
};

struct HunterCandidate {
    BleObservation obs;
    uint8_t score = 0;
    uint8_t hits = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
    bool valid = false;
};

struct HunterState {
    BleObservation target;
    FingerprintModel model;
    float fastRssi = -127.0f;
    float stableRssi = -127.0f;
    float bestRssi = -127.0f;
    float trend = 0.0f;
    float jitter = 0.0f;
    float packetsPerSecond = 0.0f;
    float gapEmaMs = 0.0f;
    uint32_t samples = 0;
    uint32_t lastSeenMs = 0;
    uint32_t lastPacketMs = 0;
    uint32_t rateWindowStartMs = 0;
    uint32_t rateWindowPackets = 0;
    uint32_t handoffNoticeUntilMs = 0;
    uint32_t reacquireNoticeUntilMs = 0;
    uint32_t lastOfflineMs = 0;
    uint16_t handoffs = 0;
    uint16_t reacquisitions = 0;
    uint8_t lastHandoffScore = 0;
    uint8_t identitySource = ID_ADDRESS;
    char currentName[MAX_NAME_BYTES + 1]{};
    char addressHistory[MAX_ADDRESS_HISTORY][18]{};
    uint8_t addressHistoryCount = 0;
    HunterCandidate candidates[MAX_CANDIDATES];
    bool initialized = false;
};

struct MutationModel {
    uint8_t baseline[MAX_PAYLOAD_BYTES]{};
    uint8_t last[MAX_PAYLOAD_BYTES]{};
    uint8_t changeHits[MAX_PAYLOAD_BYTES]{};
    uint8_t counterHits[MAX_PAYLOAD_BYTES]{};
    bool volatileMask[MAX_PAYLOAD_BYTES]{};
    uint16_t baselineLen = 0;
    uint32_t observations = 0;
    uint32_t changes = 0;
    uint16_t lastChangedBytes = 0;
    uint8_t lastDiff[MAX_PAYLOAD_BYTES]{};
    uint16_t lastDiffLen = 0;
    bool valid = false;
};

struct Fcf1Tracker {
    bool seen = false;
    uint8_t payload[32]{};
    uint8_t len = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
    uint32_t count = 0;
    uint32_t macChanges = 0;
    uint32_t payloadChanges = 0;
    uint32_t correlatedChanges = 0;
    uint32_t macOnlyChanges = 0;
    uint32_t payloadOnlyChanges = 0;
    char currentAddress[18]{};
    char previousAddress[18]{};
    uint8_t addressType = 0;
};

struct SnifferState {
    BleObservation target;
    MutationModel mutation;
    Fcf1Tracker fcf1;
    uint32_t packets = 0;
    uint32_t lastSeenMs = 0;
    uint8_t scanResponse[MAX_SCAN_RESPONSE_BYTES]{};
    uint16_t scanResponseLen = 0;
    uint32_t activeBursts = 0;
    uint32_t activeReports = 0;
    uint32_t activeResponses = 0;
    float gapEmaMs = 0.0f;
    float packetsPerSecond = 0.0f;
    uint32_t rateWindowStartMs = 0;
    uint32_t rateWindowPackets = 0;
    uint32_t mutationEvents[MAX_MUTATION_EVENTS]{};
    uint8_t mutationEventCount = 0;
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
    uint16_t notifiable = 0;
    uint16_t indicatable = 0;
    std::vector<String> serviceSummaries;
    std::vector<String> technicalLines;
    bool truncated = false;
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
        if (_count & 1) return static_cast<float>(sorted[_count / 2]);
        return (sorted[_count / 2 - 1] + sorted[_count / 2]) / 2.0f;
    }
private:
    std::array<int, MEDIAN_WINDOW_SIZE> _values{};
    size_t _count = 0;
    size_t _index = 0;
};

portMUX_TYPE reconMux = portMUX_INITIALIZER_UNLOCKED;
HunterState hunterState;
SnifferState snifferState;
MedianWindow medianWindow;
char selectedAddress[18]{};
bool activeBurstCapture = false;

int clampInt(int value, int low, int high) {
    return value < low ? low : (value > high ? high : value);
}

float clampFloat(float value, float low, float high) {
    return value < low ? low : (value > high ? high : value);
}

uint32_t fnv1a(const uint8_t *data, size_t length, uint32_t seed = 2166136261UL) {
    uint32_t hash = seed;
    for (size_t i = 0; i < length; i++) {
        hash ^= data[i];
        hash *= 16777619UL;
    }
    return hash;
}

uint16_t readLe16(const uint8_t *data) {
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

void copyAddress(char destination[18], const std::string &source) {
    std::memset(destination, 0, 18);
    std::strncpy(destination, source.c_str(), 17);
}

void copyName(char destination[MAX_NAME_BYTES + 1], const String &source) {
    std::memset(destination, 0, MAX_NAME_BYTES + 1);
    std::strncpy(destination, source.c_str(), MAX_NAME_BYTES);
}

String cleanText(const uint8_t *data, size_t length) {
    if (!data || !length) return String();
    const size_t count = std::min(length, MAX_NAME_BYTES);
    String out;
    out.reserve(count);
    for (size_t i = 0; i < count; i++) {
        if (data[i] == 0) break;
        out += (data[i] >= 0x20 && data[i] < 0x7F) ? static_cast<char>(data[i]) : '.';
    }
    out.trim();
    return out;
}

String cleanText(const std::string &value) {
    return cleanText(reinterpret_cast<const uint8_t *>(value.data()), value.size());
}

String hexBytes(const uint8_t *data, size_t length, size_t maxBytes = 32, bool spaced = false) {
    String out;
    const size_t count = std::min(length, maxBytes);
    out.reserve(count * (spaced ? 3 : 2) + 3);
    char buf[4];
    for (size_t i = 0; i < count; i++) {
        std::snprintf(buf, sizeof(buf), spaced ? "%02X " : "%02X", data[i]);
        out += buf;
    }
    if (spaced && !out.isEmpty()) out.remove(out.length() - 1);
    if (length > count) out += "..";
    return out;
}

String addressTypeName(const NimBLEAddress &address) {
    if (address.isPublic()) return "PUBLIC";
    if (address.isRpa()) return "RPA";
    if (address.isNrpa()) return "NRPA";
    if (address.isStatic()) return "STATIC";
    return "RANDOM";
}

String addressTypeName(const BleObservation &obs) {
    NimBLEAddress address(std::string(obs.address), obs.addressType);
    return addressTypeName(address);
}

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

const char *serviceName(uint16_t uuid) {
    switch (uuid) {
        case 0x1800: return "Generic Access";
        case 0x1801: return "Generic Attribute";
        case 0x180A: return "Device Information";
        case 0x180D: return "Heart Rate";
        case 0x180F: return "Battery";
        case 0x1812: return "Human Interface Device";
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

const char *characteristicName(uint16_t uuid) {
    switch (uuid) {
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
        case 0x2A4E: return "HID Protocol Mode";
        default: return nullptr;
    }
}

const char *descriptorName(uint16_t uuid) {
    switch (uuid) {
        case 0x2900: return "Extended Properties";
        case 0x2901: return "User Description";
        case 0x2902: return "Client Configuration";
        case 0x2904: return "Presentation Format";
        default: return nullptr;
    }
}

String appearanceName(uint16_t appearance) {
    switch (appearance >> 6) {
        case 1: return "Phone";
        case 2: return "Computer";
        case 3: return "Watch";
        case 4: return "Clock";
        case 5: return "Display";
        case 6: return "Remote control";
        case 7: return "Eye glasses";
        case 8: return "Tag";
        case 9: return "Keyring";
        case 10: return "Media player";
        case 11: return "Barcode scanner";
        case 12: return "Thermometer";
        case 13: return "Heart-rate sensor";
        case 15: return "HID device";
        case 17: return "Running/walking sensor";
        case 18: return "Cycling sensor";
        case 49: return "Pulse oximeter";
        case 50: return "Weight scale";
        default: return "Unknown class";
    }
}

String adTypeName(uint8_t type) {
    switch (type) {
        case 0x01: return "Flags";
        case 0x02: return "16-bit UUIDs (some)";
        case 0x03: return "16-bit UUIDs";
        case 0x04: return "32-bit UUIDs (some)";
        case 0x05: return "32-bit UUIDs";
        case 0x06: return "128-bit UUIDs (some)";
        case 0x07: return "128-bit UUIDs";
        case 0x08: return "Short name";
        case 0x09: return "Complete name";
        case 0x0A: return "TX power";
        case 0x12: return "Connection interval";
        case 0x16: return "16-bit service data";
        case 0x19: return "Appearance";
        case 0x20: return "32-bit service data";
        case 0x21: return "128-bit service data";
        case 0x24: return "URI";
        case 0xFF: return "Manufacturer data";
        default: return "Unknown field";
    }
}

String uuid16Label(uint16_t uuid) {
    const char *name = serviceName(uuid);
    String out = "0x" + String(uuid, HEX);
    out.toUpperCase();
    if (name) out += " " + String(name);
    return out;
}

void appendWrapped(std::vector<String> &lines, const String &text, size_t width = 28) {
    String remaining = text;
    remaining.trim();
    while (remaining.length() > width) {
        int split = static_cast<int>(width);
        while (split > 8 && remaining.charAt(split) != ' ') split--;
        if (split <= 8) split = static_cast<int>(width);
        lines.push_back(remaining.substring(0, split));
        remaining = remaining.substring(split);
        remaining.trim();
        if (lines.size() >= MAX_AD_LINES) return;
    }
    if (!remaining.isEmpty() && lines.size() < MAX_AD_LINES) lines.push_back(remaining);
}

bool parseAdFields(const uint8_t *payload, size_t length, std::vector<String> *lines, BleObservation *obs) {
    if (!payload && length) return false;
    size_t offset = 0;
    bool valid = true;
    while (offset < length) {
        const uint8_t fieldLength = payload[offset];
        if (fieldLength == 0) break;
        const size_t end = offset + static_cast<size_t>(fieldLength) + 1;
        if (fieldLength < 1 || end > length) {
            valid = false;
            if (lines) appendWrapped(*lines, "MALFORMED field at byte " + String(offset));
            break;
        }
        const uint8_t type = payload[offset + 1];
        const uint8_t *data = payload + offset + 2;
        const size_t dataLen = fieldLength - 1;

        if (obs) {
            if ((type == 0x08 || type == 0x09) && dataLen && obs->name[0] == '\0')
                copyName(obs->name, cleanText(data, dataLen));
            if (type == 0x19 && dataLen >= 2) {
                obs->appearance = readLe16(data);
                obs->hasAppearance = true;
            }
            if (type == 0x0A && dataLen >= 1) {
                obs->txPower = static_cast<int8_t>(data[0]);
                obs->hasTxPower = true;
            }
            if (type == 0xFF && dataLen >= 2 && obs->companyId == 0)
                obs->companyId = readLe16(data);
        }

        if (lines) {
            appendWrapped(*lines, "AD 0x" + String(type, HEX) + " " + String(adTypeName(type)));
            switch (type) {
                case 0x01:
                    if (dataLen) {
                        String flags;
                        if (data[0] & 0x01) flags += "limited ";
                        if (data[0] & 0x02) flags += "general ";
                        if (data[0] & 0x04) flags += "LE-only ";
                        appendWrapped(*lines, "  Flags: " + (flags.isEmpty() ? String("none") : flags));
                    }
                    break;
                case 0x02:
                case 0x03:
                    for (size_t i = 0; i + 1 < dataLen; i += 2)
                        appendWrapped(*lines, "  UUID " + uuid16Label(readLe16(data + i)));
                    break;
                case 0x06:
                case 0x07:
                    appendWrapped(*lines, "  UUID128 bytes: " + hexBytes(data, dataLen, 32, true));
                    break;
                case 0x08:
                case 0x09:
                    appendWrapped(*lines, "  Name: " + cleanText(data, dataLen));
                    break;
                case 0x0A:
                    if (dataLen) appendWrapped(*lines, "  TX power: " + String(static_cast<int8_t>(data[0])) + " dBm");
                    break;
                case 0x12:
                    if (dataLen >= 4) appendWrapped(*lines, "  Conn: " + String(readLe16(data) * 1.25f, 1) + "-" +
                                                       String(readLe16(data + 2) * 1.25f, 1) + " ms");
                    break;
                case 0x16:
                    if (dataLen >= 2) {
                        const uint16_t uuid = readLe16(data);
                        appendWrapped(*lines, "  Service: " + uuid16Label(uuid));
                        if (uuid == 0xFCF1)
                            appendWrapped(*lines, "  Google Service (FCF1) payload: " + hexBytes(data + 2, dataLen - 2, 32, true));
                        else if (uuid == 0xFEAA && dataLen > 2)
                            appendWrapped(*lines, "  Eddystone frame: 0x" + String(data[2], HEX));
                        else if (dataLen > 2)
                            appendWrapped(*lines, "  Data: " + hexBytes(data + 2, dataLen - 2, 32, true));
                    }
                    break;
                case 0x19:
                    if (dataLen >= 2) appendWrapped(*lines, "  Appearance: " + appearanceName(readLe16(data)));
                    break;
                case 0x20:
                    if (dataLen >= 4) appendWrapped(*lines, "  32-bit service UUID: " + hexBytes(data, 4, 4, true));
                    break;
                case 0x21:
                    if (dataLen >= 16) appendWrapped(*lines, "  128-bit service UUID: " + hexBytes(data, 16, 16, true));
                    break;
                case 0x24:
                    appendWrapped(*lines, "  URI: " + cleanText(data, dataLen));
                    break;
                case 0xFF:
                    if (dataLen >= 2) {
                        const uint16_t company = readLe16(data);
                        const char *name = companyName(company);
                        appendWrapped(*lines, "  Company: " + String(name ? name : "Unlisted") +
                                                       " (0x" + String(company, HEX) + ")");
                        if (dataLen > 2) appendWrapped(*lines, "  Data: " + hexBytes(data + 2, dataLen - 2, 32, true));
                    }
                    break;
                default:
                    appendWrapped(*lines, "  Data: " + hexBytes(data, dataLen, 32, true));
                    break;
            }
        }
        offset = end;
        if (lines && lines->size() >= MAX_AD_LINES) break;
    }
    return valid;
}

uint32_t shapeHash(const uint8_t *payload, size_t length) {
    uint32_t hash = 2166136261UL;
    size_t offset = 0;
    while (offset < length) {
        const uint8_t fieldLength = payload[offset];
        if (fieldLength == 0) break;
        const size_t end = offset + static_cast<size_t>(fieldLength) + 1;
        if (fieldLength < 1 || end > length) break;
        const uint8_t type = payload[offset + 1];
        hash = fnv1a(&fieldLength, 1, hash);
        hash = fnv1a(&type, 1, hash);
        if (type == 0xFF && fieldLength >= 3) {
            const size_t stable = std::min<size_t>(4, fieldLength - 1);
            hash = fnv1a(payload + offset + 2, stable, hash);
        } else if ((type == 0x02 || type == 0x03 || type == 0x06 || type == 0x07) && fieldLength > 1) {
            hash = fnv1a(payload + offset + 2, fieldLength - 1, hash);
        } else if ((type == 0x16 || type == 0x20 || type == 0x21) && fieldLength > 1) {
            const size_t stable = std::min<size_t>(type == 0x16 ? 2 : (type == 0x20 ? 4 : 16), fieldLength - 1);
            hash = fnv1a(payload + offset + 2, stable, hash);
        }
        offset = end;
    }
    return hash;
}

void fillObservation(const NimBLEAdvertisedDevice *device, BleObservation &obs) {
    obs = BleObservation{};
    if (!device) return;
    copyAddress(obs.address, device->getAddress().toString());
    obs.addressType = device->getAddressType();
    obs.rssi = device->getRSSI();
    obs.advType = device->getAdvType();
    obs.connectable = device->isConnectable();
    obs.scannable = device->isScannable();

    const std::vector<uint8_t> &payload = device->getPayload();
    const size_t copyLen = std::min(payload.size(), MAX_PAYLOAD_BYTES);
    obs.payloadLen = static_cast<uint16_t>(copyLen);
    obs.advLen = static_cast<uint16_t>(std::min<size_t>(device->getAdvLength(), copyLen));
    if (copyLen) std::memcpy(obs.payload, payload.data(), copyLen);
    obs.fullHash = copyLen ? fnv1a(payload.data(), payload.size()) : 0;
    obs.shapeHash = copyLen ? shapeHash(payload.data(), copyLen) : 0;

    String name = cleanText(device->getName());
    if (!name.isEmpty()) copyName(obs.name, name);
    parseAdFields(obs.payload, obs.payloadLen, nullptr, &obs);

    if (device->haveManufacturerData()) {
        const std::string mfg = device->getManufacturerData();
        if (mfg.size() >= 2) obs.companyId = readLe16(reinterpret_cast<const uint8_t *>(mfg.data()));
    }

    uint32_t service = 2166136261UL;
    for (uint8_t i = 0; i < device->getServiceUUIDCount(); i++)
        service = fnv1a(reinterpret_cast<const uint8_t *>(device->getServiceUUID(i).toString().data()),
                        device->getServiceUUID(i).toString().size(), service);
    for (uint8_t i = 0; i < device->getServiceDataCount(); i++) {
        const std::string uuid = device->getServiceDataUUID(i).toString();
        const std::string data = device->getServiceData(i);
        service = fnv1a(reinterpret_cast<const uint8_t *>(uuid.data()), uuid.size(), service);
        const uint16_t len = static_cast<uint16_t>(std::min<size_t>(data.size(), 0xFFFF));
        service = fnv1a(reinterpret_cast<const uint8_t *>(&len), sizeof(len), service);
        String uuidText(uuid.c_str());
        uuidText.toLowerCase();
        if (uuidText == "fcf1" || uuidText == "0000fcf1-0000-1000-8000-00805f9b34fb") {
            obs.hasFcf1 = true;
            obs.fcf1Len = static_cast<uint8_t>(std::min<size_t>(data.size(), sizeof(obs.fcf1)));
            if (obs.fcf1Len) std::memcpy(obs.fcf1, data.data(), obs.fcf1Len);
        }
    }
    obs.serviceHash = service;
    obs.hasTxPower = device->haveTXPower();
    obs.txPower = obs.hasTxPower ? device->getTXPower() : 0;
    obs.hasAppearance = device->haveAppearance();
    obs.appearance = obs.hasAppearance ? device->getAppearance() : 0;
#ifdef BLE_RECON_EXT_ADV
    obs.legacy = device->isLegacyAdvertisement();
    if (!obs.legacy) {
        obs.sid = device->getSetId();
        obs.primaryPhy = device->getPrimaryPhy();
        obs.secondaryPhy = device->getSecondaryPhy();
        obs.periodicInterval = device->getPeriodicInterval();
        obs.dataStatus = device->getDataStatus();
    }
#endif
}

String resolvedIdentity(const BleObservation &obs, uint8_t &source) {
    if (obs.name[0]) {
        source = ID_ADVERTISED_NAME;
        return String(obs.name);
    }
    if (const char *company = companyName(obs.companyId)) {
        source = ID_MANUFACTURER;
        return String(company) + " device";
    }
    source = ID_ADDRESS;
    return String();
}

void updateFingerprintModel(FingerprintModel &model, const BleObservation &obs) {
    if (!obs.payloadLen) return;
    if (!model.valid) {
        std::memcpy(model.baseline, obs.payload, obs.payloadLen);
        std::memcpy(model.last, obs.payload, obs.payloadLen);
        for (size_t i = 0; i < obs.payloadLen; i++) model.stable[i] = true;
        model.baselineLen = obs.payloadLen;
        model.observations = 1;
        model.valid = true;
        return;
    }
    const size_t common = std::min<size_t>(model.baselineLen, obs.payloadLen);
    for (size_t i = 0; i < common; i++) {
        if (model.last[i] != obs.payload[i]) model.stable[i] = false;
        model.last[i] = obs.payload[i];
    }
    if (obs.payloadLen > model.baselineLen) {
        const size_t newEnd = std::min<size_t>(obs.payloadLen, MAX_PAYLOAD_BYTES);
        for (size_t i = model.baselineLen; i < newEnd; i++) {
            model.baseline[i] = obs.payload[i];
            model.last[i] = obs.payload[i];
            model.stable[i] = false;
        }
        model.baselineLen = static_cast<uint16_t>(newEnd);
    }
    model.observations++;
}

int maskedPayloadSimilarity(const FingerprintModel &model, const BleObservation &obs) {
    if (!model.valid || !obs.payloadLen) return 0;
    const size_t common = std::min<size_t>(model.baselineLen, obs.payloadLen);
    size_t stableCount = 0;
    size_t equal = 0;
    for (size_t i = 0; i < common; i++) {
        if (!model.stable[i]) continue;
        stableCount++;
        if (model.baseline[i] == obs.payload[i]) equal++;
    }
    if (stableCount >= 4) return static_cast<int>((equal * 100) / stableCount);
    size_t rawEqual = 0;
    for (size_t i = 0; i < common; i++) if (model.baseline[i] == obs.payload[i]) rawEqual++;
    return common ? static_cast<int>((rawEqual * 100) / common) : 0;
}

int nameSimilarity(const char *a, const char *b) {
    if (!a || !b || !a[0] || !b[0]) return 0;
    String sa(a), sb(b);
    sa.toLowerCase();
    sb.toLowerCase();
    if (sa == sb) return 25;
    const size_t common = std::min(sa.length(), sb.length());
    size_t same = 0;
    while (same < common && sa.charAt(same) == sb.charAt(same)) same++;
    if (same >= 4 && same * 100 / common >= 70) return 14;
    return 0;
}

int handoffScore(const HunterState &state, const BleObservation &candidate, uint32_t gapMs) {
    int identity = 0;
    identity += nameSimilarity(state.currentName, candidate.name);
    if (state.target.companyId && state.target.companyId == candidate.companyId) identity += 10;
    if (state.target.hasAppearance && candidate.hasAppearance && state.target.appearance == candidate.appearance) identity += 5;
    identity = clampInt(identity, 0, 30);

    int structure = 0;
    if (state.target.serviceHash && state.target.serviceHash == candidate.serviceHash) structure += 14;
    if (state.target.shapeHash && state.target.shapeHash == candidate.shapeHash) structure += 6;
    if (state.target.advType == candidate.advType) structure += 2;
    if (state.target.addressType == candidate.addressType) structure += 2;
    if (state.target.payloadLen && state.target.payloadLen == candidate.payloadLen) structure += 2;
    structure = clampInt(structure, 0, 25);

    int payload = 0;
    const int similarity = maskedPayloadSimilarity(state.model, candidate);
    if (similarity >= 95) payload = 25;
    else if (similarity >= 85) payload = 22;
    else if (similarity >= 70) payload = 17;
    else if (similarity >= 55) payload = 10;
    else if (similarity >= 40) payload = 5;
    payload = clampInt(payload, 0, 25);

    int radio = 0;
    const int rssiDiff = std::abs(static_cast<int>(roundf(state.stableRssi)) - candidate.rssi);
    if (rssiDiff <= 5) radio = 15;
    else if (rssiDiff <= 10) radio = 11;
    else if (rssiDiff <= 18) radio = 6;
    else if (rssiDiff <= 25) radio = 2;

    int timing = gapMs <= 2000 ? 5 : (gapMs <= 5000 ? 3 : 1);
    return clampInt(identity + structure + payload + radio + timing, 0, 100);
}

void resetHunterCandidates(HunterState &state) {
    for (auto &candidate : state.candidates) candidate = HunterCandidate{};
}

void pushAddressHistory(HunterState &state, const char *address) {
    if (!address || !address[0]) return;
    if (state.addressHistoryCount < MAX_ADDRESS_HISTORY) {
        std::strncpy(state.addressHistory[state.addressHistoryCount++], address, 17);
        state.addressHistory[state.addressHistoryCount - 1][17] = '\0';
        return;
    }
    for (size_t i = 1; i < MAX_ADDRESS_HISTORY; i++)
        std::strncpy(state.addressHistory[i - 1], state.addressHistory[i], 17);
    std::strncpy(state.addressHistory[MAX_ADDRESS_HISTORY - 1], address, 17);
    state.addressHistory[MAX_ADDRESS_HISTORY - 1][17] = '\0';
}

int bestCandidateIndex(const HunterState &state) {
    int best = -1;
    for (size_t i = 0; i < MAX_CANDIDATES; i++) {
        if (!state.candidates[i].valid) continue;
        if (best < 0 || state.candidates[i].score > state.candidates[best].score) best = static_cast<int>(i);
    }
    return best;
}

int secondCandidateScore(const HunterState &state, int bestIndex) {
    int second = 0;
    for (size_t i = 0; i < MAX_CANDIDATES; i++) {
        if (!state.candidates[i].valid || static_cast<int>(i) == bestIndex) continue;
        second = std::max(second, static_cast<int>(state.candidates[i].score));
    }
    return second;
}

void acceptHandoff(HunterState &state, const HunterCandidate &candidate, uint32_t now) {
    pushAddressHistory(state, state.target.address);
    state.target = candidate.obs;
    uint8_t source = ID_ADDRESS;
    const String identity = resolvedIdentity(candidate.obs, source);
    if (!identity.isEmpty()) {
        copyName(state.currentName, identity);
        state.identitySource = source;
    }
    updateFingerprintModel(state.model, candidate.obs);
    state.handoffs++;
    state.lastHandoffScore = candidate.score;
    state.handoffNoticeUntilMs = now + HANDOFF_NOTICE_MS;
    state.fastRssi = static_cast<float>(candidate.obs.rssi);
    state.stableRssi = static_cast<float>(candidate.obs.rssi);
    state.bestRssi = state.stableRssi;
    state.trend = 0;
    state.jitter = 0;
    state.samples = 1;
    state.lastSeenMs = now;
    state.lastPacketMs = now;
    state.rateWindowStartMs = now;
    state.rateWindowPackets = 1;
    state.packetsPerSecond = 0;
    state.gapEmaMs = 0;
    resetHunterCandidates(state);
}

class HunterCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device) return;
        BleObservation obs;
        fillObservation(device, obs);
        const uint32_t now = millis();

        portENTER_CRITICAL(&reconMux);
        const bool current = std::strncmp(obs.address, hunterState.target.address, 17) == 0;
        const HunterState snapshot = hunterState;
        portEXIT_CRITICAL(&reconMux);

        if (current) {
            const bool wasLost = snapshot.initialized && now - snapshot.lastSeenMs > LOST_TARGET_MS;
            if (wasLost) medianWindow.reset();
            medianWindow.add(obs.rssi);
            const float med = medianWindow.median();

            portENTER_CRITICAL(&reconMux);
            updateFingerprintModel(hunterState.model, obs);
            hunterState.target = obs;
            uint8_t source = ID_ADDRESS;
            const String identity = resolvedIdentity(obs, source);
            if (!identity.isEmpty() && source == ID_ADVERTISED_NAME) {
                copyName(hunterState.currentName, identity);
                hunterState.identitySource = source;
            }
            if (wasLost) {
                hunterState.lastOfflineMs = now - hunterState.lastSeenMs;
                hunterState.reacquisitions++;
                hunterState.reacquireNoticeUntilMs = now + REACQUIRE_NOTICE_MS;
                hunterState.fastRssi = med;
                hunterState.stableRssi = med;
                hunterState.bestRssi = med;
                hunterState.trend = 0;
                hunterState.jitter = 0;
                hunterState.samples = 1;
                hunterState.lastSeenMs = now;
                hunterState.lastPacketMs = now;
                hunterState.rateWindowStartMs = now;
                hunterState.rateWindowPackets = 1;
                hunterState.packetsPerSecond = 0;
                hunterState.gapEmaMs = 0;
                portEXIT_CRITICAL(&reconMux);
                return;
            }
            if (hunterState.lastPacketMs) {
                const uint32_t gap = now - hunterState.lastPacketMs;
                if (gap < 60000) {
                    if (hunterState.gapEmaMs <= 0.1f) hunterState.gapEmaMs = static_cast<float>(gap);
                    else hunterState.gapEmaMs += 0.18f * (static_cast<float>(gap) - hunterState.gapEmaMs);
                }
            }
            hunterState.lastPacketMs = now;
            hunterState.rateWindowPackets++;
            const uint32_t window = now - hunterState.rateWindowStartMs;
            if (window >= 1000) {
                hunterState.packetsPerSecond = hunterState.rateWindowPackets * 1000.0f / window;
                hunterState.rateWindowStartMs = now;
                hunterState.rateWindowPackets = 0;
            }
            if (!hunterState.initialized) {
                hunterState.fastRssi = med;
                hunterState.stableRssi = med;
                hunterState.bestRssi = med;
                hunterState.samples = 1;
                hunterState.lastSeenMs = now;
                hunterState.initialized = true;
                portEXIT_CRITICAL(&reconMux);
                return;
            }
            constexpr float FAST_ALPHA = 0.45f;
            constexpr float STABLE_ALPHA = 0.14f;
            constexpr float JITTER_ALPHA = 0.18f;
            hunterState.fastRssi += FAST_ALPHA * (med - hunterState.fastRssi);
            hunterState.stableRssi += STABLE_ALPHA * (med - hunterState.stableRssi);
            hunterState.trend = hunterState.fastRssi - hunterState.stableRssi;
            hunterState.jitter += JITTER_ALPHA * (fabsf(static_cast<float>(obs.rssi) - hunterState.fastRssi) - hunterState.jitter);
            if (hunterState.stableRssi > hunterState.bestRssi) hunterState.bestRssi = hunterState.stableRssi;
            hunterState.samples++;
            hunterState.lastSeenMs = now;
            resetHunterCandidates(hunterState);
            portEXIT_CRITICAL(&reconMux);
            return;
        }

        if (!snapshot.initialized) return;
        const uint32_t gap = now - snapshot.lastSeenMs;
        if (gap < HANDOFF_ARM_MS || gap > HANDOFF_MAX_GAP_MS) return;

        const int score = handoffScore(snapshot, obs, gap);
        if (score < 45) return;

        portENTER_CRITICAL(&reconMux);
        int slot = -1;
        for (size_t i = 0; i < MAX_CANDIDATES; i++) {
            if (hunterState.candidates[i].valid && std::strncmp(hunterState.candidates[i].obs.address, obs.address, 17) == 0) {
                slot = static_cast<int>(i);
                break;
            }
        }
        if (slot < 0) {
            for (size_t i = 0; i < MAX_CANDIDATES; i++) {
                if (!hunterState.candidates[i].valid) { slot = static_cast<int>(i); break; }
            }
        }
        if (slot < 0) {
            int weakest = 0;
            for (size_t i = 1; i < MAX_CANDIDATES; i++)
                if (hunterState.candidates[i].score < hunterState.candidates[weakest].score) weakest = static_cast<int>(i);
            if (score > hunterState.candidates[weakest].score) slot = weakest;
        }
        if (slot < 0) { portEXIT_CRITICAL(&reconMux); return; }

        HunterCandidate &candidate = hunterState.candidates[slot];
        if (!candidate.valid || now - candidate.lastSeenMs > CANDIDATE_STALE_MS) {
            candidate = HunterCandidate{};
            candidate.firstSeenMs = now;
            candidate.valid = true;
        }
        candidate.obs = obs;
        candidate.score = static_cast<uint8_t>(score);
        candidate.hits = candidate.hits < 255 ? candidate.hits + 1 : 255;
        candidate.lastSeenMs = now;

        const int best = bestCandidateIndex(hunterState);
        const int second = secondCandidateScore(hunterState, best);
        const bool dominant = best >= 0 && (second == 0 || hunterState.candidates[best].score - second >= HANDOFF_MARGIN_REQUIRED);
        bool accepted = false;
        HunterCandidate acceptedCandidate;
        if (best >= 0 && dominant && hunterState.candidates[best].score >= HANDOFF_SCORE_THRESHOLD &&
            hunterState.candidates[best].hits >= HANDOFF_HITS_REQUIRED) {
            acceptedCandidate = hunterState.candidates[best];
            acceptHandoff(hunterState, acceptedCandidate, now);
            accepted = true;
        }
        portEXIT_CRITICAL(&reconMux);

        if (accepted) {
            medianWindow.reset();
            medianWindow.add(acceptedCandidate.obs.rssi);
            Serial.printf("[BLE-HUNTER] HANDOFF -> %s score=%u hits=%u gap=%lums\n",
                          acceptedCandidate.obs.address, acceptedCandidate.score, acceptedCandidate.hits,
                          static_cast<unsigned long>(gap));
        }
    }
};

HunterCallbacks hunterCallbacks;

void resetHunter(const BleObservation &target) {
    portENTER_CRITICAL(&reconMux);
    hunterState = HunterState{};
    hunterState.target = target;
    uint8_t source = ID_ADDRESS;
    const String identity = resolvedIdentity(target, source);
    if (!identity.isEmpty()) copyName(hunterState.currentName, identity);
    hunterState.identitySource = source;
    updateFingerprintModel(hunterState.model, target);
    hunterState.initialized = false;
    resetHunterCandidates(hunterState);
    portEXIT_CRITICAL(&reconMux);
    medianWindow.reset();
}

HunterState hunterSnapshot() {
    HunterState snapshot;
    portENTER_CRITICAL(&reconMux);
    snapshot = hunterState;
    portEXIT_CRITICAL(&reconMux);
    return snapshot;
}

String hunterStatus(const HunterState &state) {
    const uint32_t now = millis();
    if (state.handoffNoticeUntilMs > now) return "HANDOFF " + String(state.lastHandoffScore);
    if (state.reacquireNoticeUntilMs > now) return "REACQUIRED " + String(state.lastOfflineMs / 1000) + "s";
    if (!state.initialized) return "SEARCHING";
    if (now - state.lastSeenMs > LOST_TARGET_MS) {
        const int best = bestCandidateIndex(state);
        if (best >= 0) return "CAND " + String(state.candidates[best].score) + " x" + String(state.candidates[best].hits);
        return "TARGET LOST";
    }
    if (state.trend >= 3.0f) return "WARMER";
    if (state.trend <= -3.0f) return "COLDER";
    return "STEADY";
}

void drawHunter(const HunterState &state) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.drawCentreString("BLE HUNTER DF", tftWidth / 2, 29, 1);
    String identity = state.currentName[0] ? String(state.currentName) : String(state.target.address);
    tft.drawCentreString(identity, tftWidth / 2, 42, 1);
    tft.drawCentreString(String(addressTypeName(state.target)) + "  " + state.target.address, tftWidth / 2, 54, 1);

    const String status = hunterStatus(state);
    const uint16_t statusColor = status.startsWith("WARMER") || status.startsWith("HANDOFF") || status.startsWith("REACQUIRED") ? TFT_GREEN :
                                 (status.startsWith("COLDER") ? TFT_YELLOW :
                                  (status.startsWith("TARGET") ? TFT_RED : bruceConfig.priColor));
    tft.setTextColor(statusColor, bruceConfig.bgColor);
    tft.drawCentreString(status, tftWidth / 2, 69, 1);

    const int x = 14, y = 88, w = tftWidth - 28, h = 18;
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawRect(x, y, w, h, bruceConfig.priColor);
    const float bounded = clampFloat(state.stableRssi, -100, -35);
    const int filled = static_cast<int>(((bounded + 100) / 65.0f) * (w - 2));
    if (filled > 0) tft.fillRect(x + 1, y + 1, filled, h - 2, bruceConfig.priColor);

    tft.drawString("RSSI " + String(state.stableRssi, 1) + " / " + String(state.bestRssi, 1), 12, 115, 1);
    tft.drawString("TREND " + String(state.trend, 1) + "  JIT " + String(state.jitter, 1), 12, 128, 1);
    tft.drawString("RATE " + String(state.packetsPerSecond, 1) + "/s  GAP " + String(state.gapEmaMs, 0) + "ms", 12, 141, 1);
    tft.drawString("HANDOFFS " + String(state.handoffs) + "  REACQ " + String(state.reacquisitions), 12, 154, 1);
    tft.drawString("MATCH " + String(state.lastHandoffScore), 12, 167, 1);

    if (state.addressHistoryCount) {
        tft.drawString("ADDR HISTORY", 12, 182, 1);
        const int rows = std::min<int>(3, state.addressHistoryCount);
        for (int i = 0; i < rows; i++) tft.drawString(String(i + 1) + ": " + String(state.addressHistory[state.addressHistoryCount - 1 - i]), 12, 195 + i * 11, 1);
    }
    tft.drawCentreString("Hold details  Esc back", tftWidth / 2, tftHeight - 14, 1);
    drawStatusBar();
}

void drawHunterDetails(const HunterState &state) {
    std::vector<String> lines;
    appendWrapped(lines, "IDENTITY: " + String(state.currentName[0] ? state.currentName : "Unnamed"));
    appendWrapped(lines, "SOURCE: " + String(state.identitySource == ID_ADVERTISED_NAME ? "ADVERTISED NAME" :
                                                 (state.identitySource == ID_MANUFACTURER ? "MANUFACTURER" : "ADDRESS")));
    appendWrapped(lines, "CURRENT: " + String(state.target.address));
    appendWrapped(lines, "ADDR TYPE: " + addressTypeName(state.target));
    appendWrapped(lines, "COMPANY: 0x" + String(state.target.companyId, HEX));
    appendWrapped(lines, "SERV HASH: " + String(state.target.serviceHash, HEX));
    appendWrapped(lines, "SHAPE HASH: " + String(state.target.shapeHash, HEX));
    appendWrapped(lines, "PAYLOAD: " + String(state.target.payloadLen) + " bytes");
    appendWrapped(lines, "STABLE BYTES: " + String([&]() { size_t n = 0; for (size_t i = 0; i < state.model.baselineLen; i++) if (state.model.stable[i]) n++; return n; }()));
    appendWrapped(lines, "VOLATILE BYTES: " + String([&]() { size_t n = 0; for (size_t i = 0; i < state.model.baselineLen; i++) if (!state.model.stable[i]) n++; return n; }()));
    appendWrapped(lines, "OBSERVATIONS: " + String(state.model.observations));
    appendWrapped(lines, "CANDIDATES:");
    for (size_t i = 0; i < MAX_CANDIDATES; i++) if (state.candidates[i].valid)
        appendWrapped(lines, String(i + 1) + " " + String(state.candidates[i].obs.address) + " score=" + String(state.candidates[i].score) + " hits=" + String(state.candidates[i].hits));
    size_t scroll = 0;
    while (!check(EscPress)) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString("BLE HUNTER DETAILS", tftWidth / 2, 29, 1);
        const int firstY = 50, footerY = tftHeight - 18, visible = (footerY - firstY) / 12;
        if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1;
        for (int row = 0; row < visible && scroll + row < lines.size(); row++) tft.drawString(lines[scroll + row], 8, firstY + row * 12, 1);
        if (check(PrevPress) && scroll) scroll--;
        if (check(NextPress)) scroll++;
        delay(20);
    }
}

std::vector<BleObservation> discoverObservations(bool active) {
    std::vector<BleObservation> targets;
    ble_scan_setup();
    if (!pBLEScan) return targets;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(active);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(80);
    displayTextLine(active ? "Scanning BLE advertisers..." : "Listening for BLE advertisers...");
    BLEScanResults results = pBLEScan->getResults(DISCOVERY_TIME_MS, false);
    const int count = results.getCount();
    targets.reserve(std::min(count, 60));
    for (int i = 0; i < count && targets.size() < 60; i++) {
        const NimBLEAdvertisedDevice *device = results.getDevice(i);
        if (!device) continue;
        BleObservation obs;
        fillObservation(device, obs);
        targets.push_back(obs);
    }
    std::sort(targets.begin(), targets.end(), [](const BleObservation &a, const BleObservation &b) { return a.rssi > b.rssi; });
    pBLEScan->clearResults();
    return targets;
}

bool startPassiveHunterScan() {
    if (!pBLEScan) return false;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&hunterCallbacks, true);
    return pBLEScan->start(0, false, true);
}

void huntTarget(const BleObservation &target) {
    ble_scan_setup();
    if (!pBLEScan) { displayError("BLE scanner unavailable", true); return; }
    resetHunter(target);
    if (!startPassiveHunterScan()) { stopBLEStack(); displayError("Unable to start BLE scan", true); return; }
    bool details = false;
    uint32_t lastDraw = 0;
    while (!check(EscPress)) {
        if (check(LongPress) || check(SelPress)) {
            details = true;
            drawHunterDetails(hunterSnapshot());
            details = false;
            lastDraw = 0;
            delay(100);
        }
        if (millis() - lastDraw >= 250) {
            drawHunter(hunterSnapshot());
            lastDraw = millis();
        }
        delay(10);
    }
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->setMaxResults(0xFF);
    pBLEScan->clearResults();
    stopBLEStack();
}

String signalMeaning(int rssi) {
    if (rssi >= -50) return "Very strong / likely close";
    if (rssi >= -65) return "Strong / likely nearby";
    if (rssi >= -78) return "Moderate";
    if (rssi >= -90) return "Weak / obstructed or distant";
    return "Very weak";
}

void updateMutation(MutationModel &model, const BleObservation &obs) {
    if (!obs.payloadLen) return;
    if (!model.valid) {
        std::memcpy(model.baseline, obs.payload, obs.payloadLen);
        std::memcpy(model.last, obs.payload, obs.payloadLen);
        model.baselineLen = obs.payloadLen;
        model.observations = 1;
        model.valid = true;
        return;
    }
    const size_t common = std::min<size_t>(model.baselineLen, obs.payloadLen);
    uint16_t changed = 0;
    model.lastDiffLen = 0;
    for (size_t i = 0; i < common; i++) {
        if (model.last[i] != obs.payload[i]) {
            model.volatileMask[i] = true;
            if (model.changeHits[i] < 255) model.changeHits[i]++;
            if (static_cast<uint8_t>(model.last[i] + 1) == obs.payload[i] && model.counterHits[i] < 255) model.counterHits[i]++;
            if (model.lastDiffLen < MAX_PAYLOAD_BYTES) model.lastDiff[model.lastDiffLen++] = static_cast<uint8_t>(i);
            changed++;
        }
        model.last[i] = obs.payload[i];
    }
    if (changed) model.changes++;
    model.lastChangedBytes = changed;
    model.observations++;
}

String mutationClass(const MutationModel &model) {
    if (!model.observations || !model.changes) return "NO MUTATION OBSERVED";
    size_t volatileBytes = 0, counterBytes = 0;
    for (size_t i = 0; i < model.baselineLen; i++) {
        if (model.volatileMask[i]) volatileBytes++;
        if (model.counterHits[i] >= 2) counterBytes++;
    }
    if (counterBytes) return "COUNTER-LIKE FIELD(S) DETECTED";
    if (volatileBytes * 100 >= model.baselineLen * 60) return "HIGH VOLATILITY / POSSIBLY ENCRYPTED";
    return "PARTIAL VOLATILITY / LIVE DATA";
}

void updateFcf1(Fcf1Tracker &tracker, const BleObservation &obs, uint32_t now) {
    if (!obs.hasFcf1) return;
    const bool macChanged = tracker.seen && std::strncmp(tracker.currentAddress, obs.address, 17) != 0;
    bool payloadChanged = false;
    if (tracker.seen && tracker.len != obs.fcf1Len) payloadChanged = true;
    if (tracker.seen && tracker.len == obs.fcf1Len && tracker.len && std::memcmp(tracker.payload, obs.fcf1, tracker.len) != 0) payloadChanged = true;

    if (!tracker.seen) {
        tracker.firstSeenMs = now;
        tracker.seen = true;
    } else {
        if (macChanged) tracker.macChanges++;
        if (payloadChanged) tracker.payloadChanges++;
        if (macChanged && payloadChanged) tracker.correlatedChanges++;
        else if (macChanged) tracker.macOnlyChanges++;
        else if (payloadChanged) tracker.payloadOnlyChanges++;
    }
    if (macChanged) {
        std::strncpy(tracker.previousAddress, tracker.currentAddress, 17);
        tracker.previousAddress[17] = '\0';
    }
    std::strncpy(tracker.currentAddress, obs.address, 17);
    tracker.currentAddress[17] = '\0';
    tracker.addressType = obs.addressType;
    tracker.len = obs.fcf1Len;
    if (tracker.len) std::memcpy(tracker.payload, obs.fcf1, tracker.len);
    tracker.lastSeenMs = now;
    tracker.count++;
}

class SnifferCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!device) return;
        BleObservation obs;
        fillObservation(device, obs);
        const uint32_t now = millis();

        portENTER_CRITICAL(&reconMux);
        bool selected = std::strncmp(obs.address, selectedAddress, 17) == 0;
        if (!selected && snifferState.initialized && now - snifferState.lastSeenMs > LOST_TARGET_MS) {
            HunterState temp;
            temp.target = snifferState.target;
            temp.model.valid = snifferState.mutation.valid;
            if (snifferState.mutation.valid) {
                std::memcpy(temp.model.baseline, snifferState.mutation.baseline, MAX_PAYLOAD_BYTES);
                std::memcpy(temp.model.last, snifferState.mutation.last, MAX_PAYLOAD_BYTES);
                for (size_t i = 0; i < MAX_PAYLOAD_BYTES; i++) temp.model.stable[i] = !snifferState.mutation.volatileMask[i];
                temp.model.baselineLen = snifferState.mutation.baselineLen;
            }
            selected = handoffScore(temp, obs, now - snifferState.lastSeenMs) >= HANDOFF_SCORE_THRESHOLD;
            if (selected) {
                std::strncpy(selectedAddress, obs.address, 17);
                selectedAddress[17] = '\0';
            }
        }
        portEXIT_CRITICAL(&reconMux);
        if (!selected) return;

        portENTER_CRITICAL(&reconMux);
        updateMutation(snifferState.mutation, obs);
        updateFcf1(snifferState.fcf1, obs, now);
        snifferState.target = obs;
        snifferState.packets++;
        snifferState.lastSeenMs = now;
        snifferState.initialized = true;
        if (snifferState.rateWindowStartMs == 0) snifferState.rateWindowStartMs = now;
        snifferState.rateWindowPackets++;
        const uint32_t window = now - snifferState.rateWindowStartMs;
        if (window >= 1000) {
            snifferState.packetsPerSecond = snifferState.rateWindowPackets * 1000.0f / window;
            snifferState.rateWindowStartMs = now;
            snifferState.rateWindowPackets = 0;
        }
        if (snifferState.lastSeenMs && snifferState.mutation.observations > 1) {
            const uint32_t gap = now - snifferState.lastSeenMs;
            if (gap < 60000) {
                if (snifferState.gapEmaMs <= 0.1f) snifferState.gapEmaMs = gap;
                else snifferState.gapEmaMs += 0.18f * (gap - snifferState.gapEmaMs);
            }
        }
        snifferState.scanResponseLen = 0;
        std::memset(snifferState.scanResponse, 0, sizeof(snifferState.scanResponse));
        if (device->getAdvType() == 4 || (device->getPayload().size() > device->getAdvLength() && device->getAdvLength() > 0)) {
            const std::vector<uint8_t> &payload = device->getPayload();
            const size_t start = std::min<size_t>(device->getAdvLength(), payload.size());
            if (start < payload.size()) {
                const size_t len = std::min(payload.size() - start, MAX_SCAN_RESPONSE_BYTES);
                std::memcpy(snifferState.scanResponse, payload.data() + start, len);
                snifferState.scanResponseLen = len;
                if (activeBurstCapture) snifferState.activeResponses++;
            }
        }
        if (activeBurstCapture && device->isScannable()) snifferState.activeReports++;
        portEXIT_CRITICAL(&reconMux);
    }
};

SnifferCallbacks snifferCallbacks;

void resetSniffer(const BleObservation &target) {
    portENTER_CRITICAL(&reconMux);
    snifferState = SnifferState{};
    snifferState.target = target;
    snifferState.lastSeenMs = millis();
    snifferState.initialized = false;
    std::strncpy(selectedAddress, target.address, 17);
    selectedAddress[17] = '\0';
    portEXIT_CRITICAL(&reconMux);
}

SnifferState snifferSnapshot() {
    SnifferState snapshot;
    portENTER_CRITICAL(&reconMux);
    snapshot = snifferState;
    portEXIT_CRITICAL(&reconMux);
    return snapshot;
}

void drawSniffer(const SnifferState &state, uint8_t view, size_t &scroll, bool frozen) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    const char *viewName = view == 0 ? "PLAIN" : (view == 1 ? "AD FIELDS" : (view == 2 ? "RAW" : (view == 3 ? "MUTATION" : "ACTIVE")));
    tft.drawCentreString(String("BLE SNIFFER - ") + viewName, tftWidth / 2, 29, 1);
    String identity = state.target.name[0] ? String(state.target.name) : String(state.target.address);
    tft.drawCentreString(identity, tftWidth / 2, 42, 1);
    const bool lost = state.initialized && millis() - state.lastSeenMs > LOST_TARGET_MS;
    String status = !state.initialized ? "LISTENING..." : (lost ? "TARGET QUIET" : String(state.target.rssi) + " dBm  " + String(state.packets) + " pkt");
    if (frozen) status = "FROZEN  " + status;
    tft.setTextColor(lost ? TFT_RED : (frozen ? TFT_YELLOW : bruceConfig.priColor), bruceConfig.bgColor);
    tft.drawCentreString(status, tftWidth / 2, 54, 1);

    std::vector<String> lines;
    if (view == 0) {
        appendWrapped(lines, state.target.name[0] ? String(state.target.name) : "Unnamed BLE device");
        appendWrapped(lines, "Address: " + String(state.target.address));
        appendWrapped(lines, "Address type: " + addressTypeName(state.target));
        appendWrapped(lines, state.connectable ? "Connectable" : "Not advertising connectable");
        appendWrapped(lines, state.target.scannable ? "Scannable" : "Non-scannable");
        appendWrapped(lines, signalMeaning(state.target.rssi) + " (" + String(state.target.rssi) + " dBm)");
        appendWrapped(lines, "Company: " + String(companyName(state.target.companyId) ? companyName(state.target.companyId) : "Unlisted") +
                               " 0x" + String(state.target.companyId, HEX));
        if (state.target.hasAppearance) appendWrapped(lines, "Appearance: " + appearanceName(state.target.appearance));
        if (state.target.hasTxPower) appendWrapped(lines, "TX power: " + String(state.target.txPower) + " dBm");
        appendWrapped(lines, "Payload: " + String(state.target.payloadLen) + " bytes");
#ifdef BLE_RECON_EXT_ADV
        appendWrapped(lines, state.target.legacy ? "Legacy advertising" : "Extended advertising");
        if (!state.target.legacy) {
            appendWrapped(lines, "SID " + String(state.target.sid) + "  PHY " + String(state.target.primaryPhy) + "/" + String(state.target.secondaryPhy));
            appendWrapped(lines, "Data status " + String(state.target.dataStatus));
            appendWrapped(lines, state.target.periodicInterval ? "Periodic interval: " + String(state.target.periodicInterval) + " units" : "No periodic interval advertised");
        }
#endif
        if (state.fcf1.seen) appendWrapped(lines, "Google Service (FCF1) detected");
    } else if (view == 1) {
        parseAdFields(state.target.payload, state.target.payloadLen, &lines, nullptr);
        if (state.target.scanResponseLen) {
            appendWrapped(lines, "SCAN RESPONSE");
            parseAdFields(state.target.scanResponse, state.target.scanResponseLen, &lines, nullptr);
        }
    } else if (view == 2) {
        appendWrapped(lines, "ADV PAYLOAD " + String(state.target.payloadLen) + " bytes");
        for (size_t i = 0; i < state.target.payloadLen; i += 8)
            lines.push_back(String(i, HEX) + ": " + hexBytes(state.target.payload + i, std::min<size_t>(8, state.target.payloadLen - i), 8, true));
        if (state.target.scanResponseLen) {
            appendWrapped(lines, "SCAN RESPONSE " + String(state.target.scanResponseLen) + " bytes");
            for (size_t i = 0; i < state.target.scanResponseLen; i += 8)
                lines.push_back(String(i, HEX) + ": " + hexBytes(state.target.scanResponse + i, std::min<size_t>(8, state.target.scanResponseLen - i), 8, true));
        }
    } else if (view == 3) {
        appendWrapped(lines, mutationClass(state.mutation));
        appendWrapped(lines, "Observations: " + String(state.mutation.observations));
        appendWrapped(lines, "Payload changes: " + String(state.mutation.changes));
        appendWrapped(lines, "Last changed bytes: " + String(state.mutation.lastChangedBytes));
        size_t stable = 0, volatileBytes = 0, counters = 0;
        for (size_t i = 0; i < state.mutation.baselineLen; i++) {
            if (state.mutation.volatileMask[i]) volatileBytes++; else stable++;
            if (state.mutation.counterHits[i] >= 2) counters++;
        }
        appendWrapped(lines, "Stable: " + String(stable) + "  Volatile: " + String(volatileBytes) + "  Counter-like: " + String(counters));
        appendWrapped(lines, "Last diff offsets: " + hexBytes(state.mutation.lastDiff, state.mutation.lastDiffLen, 48, true));
        if (state.fcf1.seen) {
            appendWrapped(lines, "--- GOOGLE FCF1 ---");
            appendWrapped(lines, "Payload: " + String(state.fcf1.len) + " bytes");
            appendWrapped(lines, hexBytes(state.fcf1.payload, state.fcf1.len, 32, true));
            appendWrapped(lines, "First seen: " + String(state.fcf1.firstSeenMs / 1000) + "s");
            appendWrapped(lines, "Last seen: " + String(state.fcf1.lastSeenMs / 1000) + "s");
            appendWrapped(lines, "Count: " + String(state.fcf1.count));
            appendWrapped(lines, "MAC changes: " + String(state.fcf1.macChanges) + "  Payload changes: " + String(state.fcf1.payloadChanges));
            appendWrapped(lines, "Correlated MAC+payload: " + String(state.fcf1.correlatedChanges));
            appendWrapped(lines, "MAC-only: " + String(state.fcf1.macOnlyChanges) + "  Payload-only: " + String(state.fcf1.payloadOnlyChanges));
            appendWrapped(lines, "Current: " + String(state.fcf1.currentAddress) + " " + String(addressTypeName(state.fcf1.addressType == 0 ? state.target : state.target)));
        }
    } else {
        appendWrapped(lines, state.activeComplete ? "Active scan complete" : "No active scan performed");
        appendWrapped(lines, "Active bursts: " + String(state.activeBursts));
        appendWrapped(lines, "Scannable reports: " + String(state.activeReports));
        appendWrapped(lines, "Scan responses: " + String(state.activeResponses));
        if (state.scanResponseLen) {
            appendWrapped(lines, "Response: " + String(state.scanResponseLen) + " bytes");
            parseAdFields(state.scanResponse, state.scanResponseLen, &lines, nullptr);
        } else appendWrapped(lines, "No scan-response payload captured");
    }

    const int lineHeight = 12, firstY = 69, footerY = tftHeight - 19;
    const int visible = (footerY - firstY) / lineHeight;
    if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1;
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    for (int row = 0; row < visible && scroll + row < lines.size(); row++) tft.drawString(lines[scroll + row], 8, firstY + row * lineHeight, 1);
    if (scroll) tft.drawRightString("^", tftWidth - 7, firstY, 1);
    if (scroll + visible < lines.size()) tft.drawRightString("v", tftWidth - 7, footerY - lineHeight, 1);
    tft.drawCentreString("Turn scroll  Hold actions", tftWidth / 2, footerY, 1);
    drawStatusBar();
}

bool confirmAction(const String &title, const std::vector<String> &messages) {
    const uint32_t opened = millis();
    while (true) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.drawCentreString(title, tftWidth / 2, 31, 1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        int y = 54;
        for (const String &message : messages) { tft.drawCentreString(message, tftWidth / 2, y, 1); y += 15; }
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.drawCentreString("Select: continue  Esc: cancel", tftWidth / 2, tftHeight - 21, 1);
        drawStatusBar();
        if (check(EscPress)) return false;
        if (millis() - opened > 650 && check(SelPress)) return true;
        delay(25);
    }
}

bool startPassiveSnifferScan() {
    if (!pBLEScan) return false;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);
    return pBLEScan->start(0, false, true);
}

void runActiveScan(SnifferState &state) {
    if (!confirmAction("ACTIVE SCAN - TRANSMITS", {"3-second scan-request burst", "Nearby scannable devices may receive requests", "No BLE connection is made"})) return;
    pBLEScan->stop();
    pBLEScan->clearResults();
    portENTER_CRITICAL(&reconMux);
    state.scanResponseLen = 0;
    state.activeReports = 0;
    state.activeResponses = 0;
    state.activeBursts++;
    activeBurstCapture = true;
    portEXIT_CRITICAL(&reconMux);

    // This is deliberately true: active scan actually sends scan requests.
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);
    const uint32_t start = millis();
    pBLEScan->start(0, false, true);
    while (millis() - start < 3000) {
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
    activeBurstCapture = false;
    state.activeComplete = true;
    portEXIT_CRITICAL(&reconMux);
    startPassiveSnifferScan();
}

String characteristicProperties(const NimBLERemoteCharacteristic *characteristic) {
    String properties;
    if (characteristic->canRead()) properties += "R ";
    if (characteristic->canWrite()) properties += "W ";
    if (characteristic->canWriteNoResponse()) properties += "WNR ";
    if (characteristic->canNotify()) properties += "N ";
    if (characteristic->canIndicate()) properties += "I ";
    properties.trim();
    return properties.isEmpty() ? "none declared" : properties;
}

GattResult enumerateGatt(const BleObservation &target) {
    GattResult result;
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->clearResults();
    displayTextLine("Connecting for GATT map...");
    NimBLEClient *client = NimBLEDevice::createClient();
    if (!client) { result.error = "Could not create BLE client"; return result; }
    client->setConnectTimeout(8000);
    client->setConnectRetries(0);
    client->setConnectionParams(12, 24, 0, 400);
    NimBLEAddress peer(std::string(target.address), target.addressType);
    if (!client->connect(peer, true, false, false)) {
        result.error = "Connection failed (error " + String(client->getLastError()) + ")";
        NimBLEDevice::deleteClient(client);
        return result;
    }
    result.connected = true;
    if (!client->discoverAttributes()) {
        result.error = "GATT discovery failed (error " + String(client->getLastError()) + ")";
    } else {
        result.discovered = true;
        const auto &services = client->getServices(false);
        for (const NimBLERemoteService *service : services) {
            if (!service) continue;
            result.services++;
            const String uuid(service->getUUID().toString().c_str());
            uint16_t shortUuid = 0;
            String label = uuid;
            if (uuid.length() == 36 && uuid.substring(0, 4) == "0000" && uuid.substring(8) == "-0000-1000-8000-00805f9b34fb") {
                shortUuid = static_cast<uint16_t>(strtoul(uuid.substring(4, 8).c_str(), nullptr, 16));
                label = uuid16Label(shortUuid);
            }
            result.serviceSummaries.push_back(label);
            if (result.technicalLines.size() < MAX_GATT_LINES) result.technicalLines.push_back("SERVICE " + label);
            const auto &characteristics = service->getCharacteristics(false);
            for (const NimBLERemoteCharacteristic *characteristic : characteristics) {
                if (!characteristic) continue;
                result.characteristics++;
                if (characteristic->canRead()) result.readable++;
                if (characteristic->canWrite() || characteristic->canWriteNoResponse()) result.writable++;
                if (characteristic->canNotify()) result.notifiable++;
                if (characteristic->canIndicate()) result.indicatable++;
                const String cuuid(characteristic->getUUID().toString().c_str());
                uint16_t cshort = 0;
                String clabel = cuuid;
                if (cuuid.length() == 36 && cuuid.substring(0, 4) == "0000" && cuuid.substring(8) == "-0000-1000-8000-00805f9b34fb") {
                    cshort = static_cast<uint16_t>(strtoul(cuuid.substring(4, 8).c_str(), nullptr, 16));
                    if (const char *known = characteristicName(cshort)) clabel = "0x" + String(cshort, HEX) + " " + String(known);
                }
                if (result.technicalLines.size() < MAX_GATT_LINES) {
                    result.technicalLines.push_back("  CHAR " + clabel);
                    result.technicalLines.push_back("    PROPS " + characteristicProperties(characteristic));
                } else result.truncated = true;
                const auto &descriptors = characteristic->getDescriptors(false);
                for (const NimBLERemoteDescriptor *descriptor : descriptors) {
                    if (!descriptor) continue;
                    result.descriptors++;
                    if (result.technicalLines.size() < MAX_GATT_LINES) result.technicalLines.push_back("    DESC " + String(descriptor->getUUID().toString().c_str()));
                    else result.truncated = true;
                }
            }
        }
    }
    if (client->isConnected()) client->disconnect();
    delay(80);
    NimBLEDevice::deleteClient(client);
    return result;
}

void showGatt(const GattResult &result, const String &identity) {
    bool technical = false;
    size_t scroll = 0;
    while (!check(EscPress)) {
        std::vector<String> lines;
        if (!result.connected) appendWrapped(lines, result.error.isEmpty() ? "Connection failed" : result.error);
        else if (!result.discovered) appendWrapped(lines, result.error.isEmpty() ? "GATT discovery failed" : result.error);
        else {
            appendWrapped(lines, technical ? "STRUCTURE ONLY - NO VALUES READ" : "GATT structure mapped; disconnected");
            appendWrapped(lines, String(result.services) + " services  " + String(result.characteristics) + " chars  " + String(result.descriptors) + " desc");
            appendWrapped(lines, String(result.readable) + " readable  " + String(result.writable) + " writable");
            appendWrapped(lines, String(result.notifiable) + " notify  " + String(result.indicatable) + " indicate");
            if (technical) for (const String &line : result.technicalLines) lines.push_back(line);
            else for (const String &service : result.serviceSummaries) appendWrapped(lines, "Service: " + service);
            if (result.truncated) appendWrapped(lines, "Technical tree truncated for memory safety");
        }
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString(technical ? "GATT TECHNICAL" : "GATT PLAIN", tftWidth / 2, 29, 1);
        tft.drawCentreString(identity, tftWidth / 2, 42, 1);
        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.drawCentreString("DISCONNECTED - NO VALUES", tftWidth / 2, 54, 1);
        const int firstY = 69, footerY = tftHeight - 19, visible = (footerY - firstY) / 12;
        if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1;
        for (int row = 0; row < visible && scroll + row < lines.size(); row++) tft.drawString(lines[scroll + row], 8, firstY + row * 12, 1);
        if (check(PrevPress) && scroll) scroll--;
        if (check(NextPress)) scroll++;
        if (check(SelPress)) { technical = !technical; scroll = 0; delay(100); }
        tft.drawCentreString("Turn scroll  Select plain/tree  Esc", tftWidth / 2, footerY, 1);
        drawStatusBar();
        delay(20);
    }
}

void sniffTarget(const BleObservation &target) {
    ble_scan_setup();
    if (!pBLEScan) { displayError("BLE scanner unavailable", true); return; }
    resetSniffer(target);
    if (!startPassiveSnifferScan()) { stopBLEStack(); displayError("Unable to start BLE scan", true); return; }
    uint8_t view = 0;
    size_t scroll = 0;
    bool frozen = false;
    SnifferState frozenState;
    uint32_t lastDraw = 0;
    while (!check(EscPress)) {
        if (check(PrevPress)) { if (scroll) scroll--; else view = (view + 4) % 5; }
        if (check(NextPress)) { scroll++; }
        if (check(LongPress) || check(SelPress)) {
            const bool action = confirmAction("SNIFFER ACTIONS", {"Active scan / GATT map / freeze", "Active scan transmits scan requests", "GATT connects only after confirmation"});
            if (action) {
                std::vector<Option> actions;
                int selected = -1;
                actions.emplace_back("Active scan request (3s)", [&selected]() { selected = 0; });
                actions.emplace_back("Connect + map GATT", [&selected]() { selected = 1; });
                actions.emplace_back("Next view", [&selected]() { selected = 2; });
                actions.emplace_back(frozen ? "Unfreeze frame" : "Freeze frame", [&selected]() { selected = 3; });
                loopOptions(actions, MENU_TYPE_REGULAR, "BLE Sniffer", 0, false);
                if (selected == 0) { frozen = false; SnifferState state = snifferSnapshot(); runActiveScan(state); }
                else if (selected == 1) {
                    frozen = false;
                    const SnifferState state = snifferSnapshot();
                    if (!state.target.connectable) displayWarning("Target is not advertising connectable", true);
                    else if (confirmAction("CONNECT + MAP GATT", {"Target will see a connection", "Structure discovery only", "NO READS / WRITES / SUBSCRIPTIONS"})) {
                        const GattResult result = enumerateGatt(state.target);
                        showGatt(result, state.target.name[0] ? String(state.target.name) : String(state.target.address));
                        startPassiveSnifferScan();
                    }
                } else if (selected == 2) { view = (view + 1) % 5; scroll = 0; }
                else if (selected == 3) { frozen = !frozen; if (frozen) frozenState = snifferSnapshot(); }
            }
            scroll = 0;
            delay(100);
        }
        if (millis() - lastDraw >= (frozen ? 1000 : 300)) {
            const SnifferState state = frozen ? frozenState : snifferSnapshot();
            drawSniffer(state, view, scroll, frozen);
            lastDraw = millis();
        }
        delay(10);
    }
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->setMaxResults(0xFF);
    pBLEScan->clearResults();
    stopBLEStack();
}

} // namespace

void bleHunterV3() {
    std::vector<BleObservation> targets = discoverObservations(false);
    if (targets.empty()) { displayWarning("No BLE advertisers found", true); stopBLEStack(); return; }
    options.clear();
    const size_t count = std::min<size_t>(targets.size(), 60);
    for (size_t i = 0; i < count; i++) {
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
    std::vector<BleObservation> targets = discoverObservations(true);
    if (targets.empty()) { displayWarning("No BLE advertisers found", true); stopBLEStack(); return; }
    options.clear();
    const size_t count = std::min<size_t>(targets.size(), 60);
    for (size_t i = 0; i < count; i++) {
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
