#include "ble_sniffer.h"

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_common.h"
#include <globals.h>
#include <NimBLERemoteDescriptor.h>

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t DISCOVERY_TIME_MS = 5000;
constexpr uint32_t LOST_DEVICE_MS = 4000;
constexpr uint32_t ACTIVE_SCAN_TIME_MS = 3000;
constexpr size_t MAX_PAYLOAD_BYTES = 96;
constexpr size_t MAX_NAME_BYTES = 40;
constexpr size_t MAX_GATT_LINES = 220;
constexpr uint8_t VIEW_PLAIN = 0;
constexpr uint8_t VIEW_FIELDS = 1;
constexpr uint8_t VIEW_RAW = 2;
constexpr uint8_t VIEW_ACTIVE = 3;
constexpr uint8_t VIEW_COUNT = 4;

struct SnifferTarget {
    String name;
    String address;
    int rssi = -127;
    uint16_t companyId = 0;
    uint8_t addressType = 0;
    bool connectable = false;
    bool scannable = false;
};

struct SnifferState {
    uint8_t payload[MAX_PAYLOAD_BYTES]{};
    uint8_t payloadLen = 0;
    char name[MAX_NAME_BYTES + 1]{};
    char address[18]{};
    int rssi = -127;
    int8_t txPower = 0;
    uint8_t addressType = 0;
    uint8_t advType = 0;
    uint32_t packets = 0;
    uint32_t payloadChanges = 0;
    uint32_t payloadHash = 0;
    uint32_t lastSeenMs = 0;
    uint8_t scanResponse[MAX_PAYLOAD_BYTES]{};
    uint8_t scanResponseLen = 0;
    uint32_t activeBursts = 0;
    uint32_t activeReports = 0;
    uint32_t activeResponses = 0;
    bool hasTxPower = false;
    bool connectable = false;
    bool scannable = false;
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

portMUX_TYPE snifferMux = portMUX_INITIALIZER_UNLOCKED;
SnifferState snifferState;
char selectedAddress[18]{};
bool activeBurstCapture = false;

uint16_t readLe16(const uint8_t *data) {
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

uint32_t fnv1a(const uint8_t *data, size_t length) {
    uint32_t hash = 2166136261UL;
    for (size_t i = 0; i < length; i++) {
        hash ^= data[i];
        hash *= 16777619UL;
    }
    return hash;
}

String cleanText(const uint8_t *data, size_t length) {
    String output;
    const size_t count = length < MAX_NAME_BYTES ? length : MAX_NAME_BYTES;
    output.reserve(count);
    for (size_t i = 0; i < count; i++) {
        const uint8_t value = data[i];
        if (value == 0) break;
        output += (value >= 0x20 && value < 0x7F) ? static_cast<char>(value) : '.';
    }
    output.trim();
    return output;
}

String cleanText(const std::string &value) {
    return cleanText(reinterpret_cast<const uint8_t *>(value.data()), value.size());
}

String bytesToHex(const uint8_t *data, size_t length, size_t maxBytes = 24, bool spaced = false) {
    String output;
    const size_t count = length < maxBytes ? length : maxBytes;
    output.reserve(count * (spaced ? 3 : 2) + 3);
    char byteText[4];
    for (size_t i = 0; i < count; i++) {
        std::snprintf(byteText, sizeof(byteText), spaced ? "%02X " : "%02X", data[i]);
        output += byteText;
    }
    if (spaced && !output.isEmpty()) output.remove(output.length() - 1);
    if (length > count) output += "..";
    return output;
}

const char *companyName(uint16_t companyId) {
    switch (companyId) {
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

bool uuid16FromText(String uuid, uint16_t &shortUuid) {
    uuid.toLowerCase();
    if (uuid.startsWith("0x")) uuid = uuid.substring(2);
    if (uuid.length() == 4) {
        shortUuid = static_cast<uint16_t>(strtoul(uuid.c_str(), nullptr, 16));
        return true;
    }
    if (uuid.length() == 36 && uuid.substring(0, 4) == "0000" &&
        uuid.substring(8) == "-0000-1000-8000-00805f9b34fb") {
        shortUuid = static_cast<uint16_t>(strtoul(uuid.substring(4, 8).c_str(), nullptr, 16));
        return true;
    }
    return false;
}

String friendlyUuid(const String &uuid, const char *(*lookup)(uint16_t)) {
    uint16_t shortUuid = 0;
    if (!uuid16FromText(uuid, shortUuid)) return uuid;
    const char *known = lookup(shortUuid);
    String output = "0x" + String(shortUuid, HEX);
    output.toUpperCase();
    if (known) output += " " + String(known);
    return output;
}

const char *appearanceName(uint16_t appearance) {
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
        case 14: return "Blood-pressure sensor";
        case 15: return "HID device";
        case 16: return "Glucose meter";
        case 17: return "Running/walking sensor";
        case 18: return "Cycling sensor";
        case 49: return "Pulse oximeter";
        case 50: return "Weight scale";
        default: return nullptr;
    }
}

const char *adTypeName(uint8_t type) {
    switch (type) {
        case 0x01: return "Flags";
        case 0x02: return "16-bit UUIDs (some)";
        case 0x03: return "16-bit UUIDs";
        case 0x04: return "32-bit UUIDs (some)";
        case 0x05: return "32-bit UUIDs";
        case 0x06: return "128-bit UUIDs (some)";
        case 0x07: return "128-bit UUIDs";
        case 0x08: return "Short name";
        case 0x09: return "Device name";
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

String localNameFromPayload(const uint8_t *payload, size_t length) {
    String shortName;
    size_t offset = 0;
    while (offset < length) {
        const uint8_t fieldLength = payload[offset];
        if (fieldLength == 0) break;
        const size_t end = offset + static_cast<size_t>(fieldLength) + 1;
        if (fieldLength < 1 || end > length) break;
        const uint8_t type = payload[offset + 1];
        if ((type == 0x08 || type == 0x09) && fieldLength > 1) {
            const String value = cleanText(payload + offset + 2, fieldLength - 1);
            if (!value.isEmpty()) {
                if (type == 0x09) return value;
                if (shortName.isEmpty()) shortName = value;
            }
        }
        offset = end;
    }
    return shortName;
}

uint16_t companyIdFromPayload(const uint8_t *payload, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        const uint8_t fieldLength = payload[offset];
        if (fieldLength == 0) break;
        const size_t end = offset + static_cast<size_t>(fieldLength) + 1;
        if (fieldLength < 1 || end > length) break;
        if (payload[offset + 1] == 0xFF && fieldLength >= 3) return readLe16(payload + offset + 2);
        offset = end;
    }
    return 0;
}

String advKind(uint8_t type) {
    switch (type) {
        case 0: return "Connectable advertisement";
        case 1: return "Directed connection request";
        case 2: return "Scannable advertisement";
        case 3: return "Broadcast only (not connectable)";
        case 4: return "Scan response";
        default: return "BLE advertisement type " + String(type);
    }
}

String signalMeaning(int rssi) {
    if (rssi >= -50) return "Very strong signal; probably close";
    if (rssi >= -65) return "Strong signal; likely nearby";
    if (rssi >= -78) return "Moderate signal";
    if (rssi >= -90) return "Weak signal; distant or obstructed";
    return "Very weak signal";
}

void appendWrapped(std::vector<String> &lines, const String &text, size_t width = 27) {
    String remaining = text;
    remaining.trim();
    while (remaining.length() > width) {
        int split = static_cast<int>(width);
        while (split > 8 && remaining.charAt(split) != ' ') split--;
        if (split <= 8) split = static_cast<int>(width);
        lines.push_back(remaining.substring(0, split));
        remaining = remaining.substring(split);
        remaining.trim();
    }
    if (!remaining.isEmpty()) lines.push_back(remaining);
}

void appendUuid16List(std::vector<String> &lines, const uint8_t *data, size_t length, const String &prefix) {
    for (size_t i = 0; i + 1 < length; i += 2) {
        const uint16_t uuid = readLe16(data + i);
        const char *known = serviceName(uuid);
        String value = prefix + " 0x" + String(uuid, HEX);
        if (known) value += " " + String(known);
        appendWrapped(lines, value);
    }
}

String decodeFlags(uint8_t flags) {
    std::vector<String> values;
    if (flags & 0x01) values.push_back("limited discoverable");
    if (flags & 0x02) values.push_back("general discoverable");
    if (flags & 0x04) values.push_back("no Classic Bluetooth");
    if (flags & 0x08) values.push_back("BLE + Classic controller");
    if (flags & 0x10) values.push_back("BLE + Classic host");
    if (values.empty()) return "No standard flags set";
    String output;
    for (size_t i = 0; i < values.size(); i++) {
        if (i) output += ", ";
        output += values[i];
    }
    return output;
}

String decodeEddystone(const uint8_t *data, size_t length) {
    if (length == 0) return "Eddystone service data";
    switch (data[0]) {
        case 0x00: return "Eddystone UID beacon";
        case 0x10: return "Eddystone URL beacon";
        case 0x20: return "Eddystone telemetry beacon";
        case 0x30: return "Eddystone rotating-ID beacon";
        default: return "Eddystone frame 0x" + String(data[0], HEX);
    }
}

void decodeManufacturer(std::vector<String> &lines, const uint8_t *data, size_t length, bool plain) {
    if (length < 2) {
        appendWrapped(lines, "Manufacturer field is too short");
        return;
    }

    const uint16_t companyId = readLe16(data);
    const char *company = companyName(companyId);
    String heading = company ? String(company) : "Unlisted manufacturer";
    heading += " (0x" + String(companyId, HEX) + ")";
    appendWrapped(lines, plain ? "Made/encoded by " + heading : "Manufacturer: " + heading);

    const uint8_t *body = data + 2;
    const size_t bodyLength = length - 2;
    if (companyId == 0x004C && bodyLength >= 2 && body[0] == 0x02 && body[1] == 0x15 && bodyLength >= 23) {
        appendWrapped(lines, "Format: Apple iBeacon");
        appendWrapped(lines, "UUID: " + bytesToHex(body + 2, 16, 16));
        appendWrapped(lines, "Major " + String((body[18] << 8) | body[19]) + ", minor " +
                                 String((body[20] << 8) | body[21]));
        appendWrapped(lines, "Calibrated power " + String(static_cast<int8_t>(body[22])) + " dBm");
    } else if (companyId == 0x004C && bodyLength > 0) {
        appendWrapped(lines, "Apple Continuity/proprietary message type 0x" + String(body[0], HEX));
    } else if (companyId == 0x0006) {
        appendWrapped(lines, "Microsoft proprietary BLE data");
    } else if (companyId == 0x00E0) {
        appendWrapped(lines, "Google proprietary BLE data");
    } else if (companyId == 0x0075) {
        appendWrapped(lines, "Samsung proprietary BLE data");
    }

    if (!plain && bodyLength > 0) appendWrapped(lines, "Data: " + bytesToHex(body, bodyLength, 28, true));
}

std::vector<String> decodeFields(const SnifferState &state, bool plain) {
    std::vector<String> lines;
    if (!state.initialized) {
        lines.push_back("Waiting for target...");
        return lines;
    }

    if (plain) {
        const String identity = state.name[0] ? String(state.name) : String("Unnamed BLE device");
        appendWrapped(lines, identity);
        appendWrapped(lines, advKind(state.advType));
        appendWrapped(lines, signalMeaning(state.rssi) + " (" + String(state.rssi) + " dBm)");
        appendWrapped(lines, state.addressType == 0 ? "Public device address" :
                                                     "Random/private address; it may rotate");
    }

    size_t offset = 0;
    bool sawManufacturer = false;
    bool sawUsefulField = false;
    while (offset < state.payloadLen) {
        const uint8_t fieldLength = state.payload[offset];
        if (fieldLength == 0) break;
        const size_t end = offset + static_cast<size_t>(fieldLength) + 1;
        if (fieldLength < 1 || end > state.payloadLen) {
            appendWrapped(lines, "Malformed/truncated field at byte " + String(offset));
            break;
        }

        const uint8_t type = state.payload[offset + 1];
        const uint8_t *data = state.payload + offset + 2;
        const size_t dataLength = fieldLength - 1;
        if (!plain) appendWrapped(lines, String(adTypeName(type)) + " [0x" + String(type, HEX) + "]");

        switch (type) {
            case 0x01:
                if (dataLength >= 1) appendWrapped(lines, (plain ? "Mode: " : "  ") + decodeFlags(data[0]));
                sawUsefulField = true;
                break;
            case 0x08:
            case 0x09:
                appendWrapped(lines, (plain ? "Advertised name: " : "  Value: ") + cleanText(data, dataLength));
                sawUsefulField = true;
                break;
            case 0x02:
            case 0x03:
                appendUuid16List(lines, data, dataLength, plain ? "Offers service" : "  UUID");
                sawUsefulField = true;
                break;
            case 0x0A:
                if (dataLength >= 1) {
                    appendWrapped(lines, String(plain ? "Radio reference power: " : "  Value: ") +
                                             String(static_cast<int8_t>(data[0])) + " dBm");
                }
                sawUsefulField = true;
                break;
            case 0x12:
                if (dataLength >= 4) {
                    const float minimumMs = readLe16(data) * 1.25f;
                    const float maximumMs = readLe16(data + 2) * 1.25f;
                    appendWrapped(lines, "Connection interval " + String(minimumMs, 1) + "-" +
                                             String(maximumMs, 1) + " ms");
                }
                sawUsefulField = true;
                break;
            case 0x16:
                if (dataLength >= 2) {
                    const uint16_t uuid = readLe16(data);
                    const char *known = serviceName(uuid);
                    String value = plain ? "Service data from " : "  UUID 0x" + String(uuid, HEX) + ": ";
                    value += known ? String(known) : ("service 0x" + String(uuid, HEX));
                    appendWrapped(lines, value);
                    if (uuid == 0xFEAA)
                        appendWrapped(lines, decodeEddystone(data + 2, dataLength - 2));
                    else if (uuid == 0xFE2C && dataLength >= 5)
                        appendWrapped(lines, "Fast Pair model ID " + bytesToHex(data + 2, 3, 3));
                    else if (uuid == 0xFD6F)
                        appendWrapped(lines, "Privacy-preserving proximity identifier");
                    else if (!plain && dataLength > 2)
                        appendWrapped(lines, "  Data: " + bytesToHex(data + 2, dataLength - 2, 26, true));
                }
                sawUsefulField = true;
                break;
            case 0x19:
                if (dataLength >= 2) {
                    const uint16_t appearance = readLe16(data);
                    const char *known = appearanceName(appearance);
                    appendWrapped(lines, String(plain ? "Device class: " : "  Value: ") +
                                             (known ? String(known) : ("code 0x" + String(appearance, HEX))));
                }
                sawUsefulField = true;
                break;
            case 0xFF:
                decodeManufacturer(lines, data, dataLength, plain);
                sawManufacturer = true;
                sawUsefulField = true;
                break;
            default:
                if (!plain) appendWrapped(lines, "  " + bytesToHex(data, dataLength, 28, true));
                break;
        }
        offset = end;
    }

    if (plain && !sawManufacturer) appendWrapped(lines, "No manufacturer identity advertised");
    if (plain && !sawUsefulField) appendWrapped(lines, "Payload is proprietary, encrypted, or not self-describing");
    if (plain && state.payloadChanges > 0) {
        appendWrapped(lines, "Payload changed " + String(state.payloadChanges) +
                                 " time(s); rotating identifiers or live values may be present");
    }
    return lines;
}

std::vector<String> rawLines(const SnifferState &state) {
    std::vector<String> lines;
    if (!state.initialized) {
        lines.push_back("Waiting for target...");
        return lines;
    }
    for (size_t offset = 0; offset < state.payloadLen; offset += 8) {
        const size_t count = (state.payloadLen - offset) < 8 ? (state.payloadLen - offset) : 8;
        char prefix[8];
        std::snprintf(prefix, sizeof(prefix), "%02X: ", static_cast<unsigned int>(offset));
        lines.push_back(String(prefix) + bytesToHex(state.payload + offset, count, count, true));
    }
    return lines;
}

std::vector<String> activeScanLines(const SnifferState &state) {
    std::vector<String> lines;
    if (!state.activeComplete) {
        appendWrapped(lines, "No active request made yet");
        appendWrapped(lines, "Hold for actions, then choose Active scan request");
        appendWrapped(lines, "The 3-second burst transmits BLE scan requests and then returns to passive listening");
        return lines;
    }

    appendWrapped(lines, "Active bursts: " + String(state.activeBursts));
    appendWrapped(lines, "Scannable reports seen: " + String(state.activeReports));
    appendWrapped(lines, "Scan responses received: " + String(state.activeResponses));
    if (state.scanResponseLen == 0) {
        appendWrapped(lines, state.scannable ? "No extra scan-response data returned" :
                                              "Target did not advertise as scannable");
        appendWrapped(lines, "This does not prove the device has no extra information");
        return lines;
    }

    appendWrapped(lines, "Extra response: " + String(state.scanResponseLen) + " byte(s)");
    SnifferState response = state;
    std::memset(response.payload, 0, sizeof(response.payload));
    std::memcpy(response.payload, state.scanResponse, state.scanResponseLen);
    response.payloadLen = state.scanResponseLen;
    response.payloadChanges = 0;
    response.advType = 4;
    std::vector<String> decoded = decodeFields(response, true);
    for (size_t i = 4; i < decoded.size(); i++) lines.push_back(decoded[i]);
    appendWrapped(lines, "Response bytes: " + bytesToHex(state.scanResponse, state.scanResponseLen, 28, true));
    return lines;
}

void copyAddress(char destination[18], const std::string &source) {
    std::memset(destination, 0, 18);
    std::strncpy(destination, source.c_str(), 17);
}

void copyName(char destination[MAX_NAME_BYTES + 1], const String &source) {
    std::memset(destination, 0, MAX_NAME_BYTES + 1);
    std::strncpy(destination, source.c_str(), MAX_NAME_BYTES);
}

void resetState(const SnifferTarget &target) {
    portENTER_CRITICAL(&snifferMux);
    snifferState = SnifferState{};
    activeBurstCapture = false;
    copyAddress(selectedAddress, std::string(target.address.c_str()));
    copyAddress(snifferState.address, std::string(target.address.c_str()));
    if (!target.name.isEmpty()) copyName(snifferState.name, target.name);
    snifferState.addressType = target.addressType;
    snifferState.connectable = target.connectable;
    snifferState.scannable = target.scannable;
    portEXIT_CRITICAL(&snifferMux);
}

SnifferState stateSnapshot() {
    SnifferState snapshot;
    portENTER_CRITICAL(&snifferMux);
    snapshot = snifferState;
    portEXIT_CRITICAL(&snifferMux);
    return snapshot;
}

class BleSnifferCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (device == nullptr) return;
        const std::string address = device->getAddress().toString();

        portENTER_CRITICAL(&snifferMux);
        const bool selected = std::strncmp(address.c_str(), selectedAddress, 17) == 0;
        portEXIT_CRITICAL(&snifferMux);
        if (!selected) return;

        const std::vector<uint8_t> &payload = device->getPayload();
        const size_t advertisedLength = std::min<size_t>(device->getAdvLength(), payload.size());
        const size_t payloadLength = advertisedLength < MAX_PAYLOAD_BYTES ? advertisedLength : MAX_PAYLOAD_BYTES;
        const size_t responseAvailable = payload.size() > advertisedLength ? payload.size() - advertisedLength : 0;
        const size_t responseLength = responseAvailable < MAX_PAYLOAD_BYTES ? responseAvailable : MAX_PAYLOAD_BYTES;
        const uint32_t hash = payloadLength ? fnv1a(payload.data(), payloadLength) : 0;
        String name = cleanText(device->getName());
        if (name.isEmpty() && payloadLength) name = localNameFromPayload(payload.data(), payloadLength);

        portENTER_CRITICAL(&snifferMux);
        if (snifferState.initialized && hash != 0 && snifferState.payloadHash != 0 && hash != snifferState.payloadHash) {
            snifferState.payloadChanges++;
        }
        std::memset(snifferState.payload, 0, MAX_PAYLOAD_BYTES);
        if (payloadLength) std::memcpy(snifferState.payload, payload.data(), payloadLength);
        snifferState.payloadLen = static_cast<uint8_t>(payloadLength);
        snifferState.payloadHash = hash;
        snifferState.rssi = device->getRSSI();
        snifferState.addressType = device->getAddressType();
        snifferState.advType = device->getAdvType();
        snifferState.hasTxPower = device->haveTXPower();
        snifferState.txPower = snifferState.hasTxPower ? device->getTXPower() : 0;
        snifferState.connectable = device->isConnectable();
        snifferState.scannable = device->isScannable();
        snifferState.lastSeenMs = millis();
        snifferState.packets++;
        snifferState.initialized = true;
        if (activeBurstCapture) {
            if (device->isScannable()) snifferState.activeReports++;
            if (responseLength > 0) {
                std::memset(snifferState.scanResponse, 0, MAX_PAYLOAD_BYTES);
                std::memcpy(snifferState.scanResponse, payload.data() + advertisedLength, responseLength);
                snifferState.scanResponseLen = static_cast<uint8_t>(responseLength);
                snifferState.activeResponses++;
            }
        }
        if (!name.isEmpty()) copyName(snifferState.name, name);
        portEXIT_CRITICAL(&snifferMux);
    }
};

BleSnifferCallbacks snifferCallbacks;

void drawSniffer(const SnifferState &state, uint8_t view, size_t &scroll, bool frozen) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);

    const char *viewName = view == VIEW_PLAIN   ? "PLAIN SPEAK" :
                           view == VIEW_FIELDS  ? "AD FIELDS" :
                           view == VIEW_RAW     ? "RAW BYTES" : "ACTIVE RESULT";
    tft.drawCentreString(String("BLE SNIFFER - ") + viewName, tftWidth / 2, 29, 1);

    String identity = state.name[0] ? String(state.name) : String(state.address);
    if (identity.isEmpty()) identity = "Waiting for target";
    tft.drawCentreString(identity, tftWidth / 2, 42, 1);

    const bool lost = state.initialized && millis() - state.lastSeenMs > LOST_DEVICE_MS;
    String status = state.initialized ? (String(state.rssi) + " dBm  pkt " + String(state.packets)) : "Listening...";
    if (lost) status = "TARGET QUIET " + String((millis() - state.lastSeenMs) / 1000) + "s";
    if (frozen) status = "FROZEN  " + status;
    tft.setTextColor(lost ? TFT_RED : (frozen ? TFT_YELLOW : bruceConfig.priColor), bruceConfig.bgColor);
    tft.drawCentreString(status, tftWidth / 2, 54, 1);

    std::vector<String> lines;
    if (view == VIEW_PLAIN)
        lines = decodeFields(state, true);
    else if (view == VIEW_FIELDS)
        lines = decodeFields(state, false);
    else if (view == VIEW_RAW)
        lines = rawLines(state);
    else
        lines = activeScanLines(state);

    const int lineHeight = 12;
    const int firstY = 69;
    const int footerY = tftHeight - 19;
    const int visible = (footerY - firstY) / lineHeight;
    if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1;

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    for (int row = 0; row < visible && scroll + row < lines.size(); row++) {
        tft.drawString(lines[scroll + row], 9, firstY + row * lineHeight, 1);
    }
    if (scroll > 0) tft.drawRightString("^", tftWidth - 7, firstY, 1);
    if (scroll + visible < lines.size()) tft.drawRightString("v", tftWidth - 7, footerY - lineHeight, 1);

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString("Turn scroll  Press view  Hold actions", tftWidth / 2, footerY, 1);
    drawStatusBar();
}

bool confirmRadioAction(const String &title, const std::vector<String> &messages) {
    const uint32_t openedAt = millis();
    while (true) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextSize(FP);
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.drawCentreString(title, tftWidth / 2, 31, 1);

        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        int y = 54;
        for (const String &message : messages) {
            tft.drawCentreString(message, tftWidth / 2, y, 1);
            y += 15;
        }
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.drawCentreString("Select: continue   Esc: cancel", tftWidth / 2, tftHeight - 21, 1);
        drawStatusBar();

        if (check(EscPress)) return false;
        if (millis() - openedAt > 650 && check(SelPress)) return true;
        delay(25);
    }
}

bool startPassiveTargetScan() {
    if (pBLEScan == nullptr) return false;
    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);
    return pBLEScan->start(0, false, true);
}

void runActiveScanBurst() {
    if (!confirmRadioAction(
            "ACTIVE SCAN - TRANSMITS",
            {"3-second scan-request burst", "Nearby scannable devices", "may receive requests", "No connection is made"}
        ))
        return;

    pBLEScan->stop();
    pBLEScan->clearResults();
    portENTER_CRITICAL(&snifferMux);
    snifferState.scanResponseLen = 0;
    std::memset(snifferState.scanResponse, 0, MAX_PAYLOAD_BYTES);
    snifferState.activeReports = 0;
    snifferState.activeResponses = 0;
    snifferState.activeComplete = false;
    snifferState.activeBursts++;
    activeBurstCapture = true;
    portEXIT_CRITICAL(&snifferMux);

    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);

    const bool started = pBLEScan->start(0, false, true);
    const uint32_t startedAt = millis();
    while (started && millis() - startedAt < ACTIVE_SCAN_TIME_MS) {
        const uint32_t remaining = (ACTIVE_SCAN_TIME_MS - (millis() - startedAt) + 999) / 1000;
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorder(false);
        tft.setTextSize(FP);
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.drawCentreString("ACTIVE - TRANSMITTING", tftWidth / 2, 40, 1);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString("BLE scan requests are on air", tftWidth / 2, 65, 1);
        tft.drawCentreString("Returning to passive in " + String(remaining) + "s", tftWidth / 2, 82, 1);
        tft.drawCentreString("Esc stops burst early", tftWidth / 2, tftHeight - 21, 1);
        drawStatusBar();
        if (check(EscPress)) break;
        delay(80);
    }

    pBLEScan->stop();
    portENTER_CRITICAL(&snifferMux);
    activeBurstCapture = false;
    snifferState.activeComplete = true;
    portEXIT_CRITICAL(&snifferMux);
    startPassiveTargetScan();
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

void addGattTechnicalLine(GattResult &result, const String &line) {
    if (result.technicalLines.size() < MAX_GATT_LINES)
        result.technicalLines.push_back(line);
    else
        result.truncated = true;
}

GattResult enumerateGatt(const SnifferTarget &target) {
    GattResult result;
    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->clearResults();

    displayTextLine("Connecting for GATT map...");
    NimBLEClient *client = NimBLEDevice::createClient();
    if (client == nullptr) {
        result.error = "Could not create BLE client";
        return result;
    }

    client->setConnectTimeout(8000);
    client->setConnectRetries(0);
    client->setConnectionParams(12, 24, 0, 400);
    const std::string address(target.address.c_str());
    const NimBLEAddress peer(address, target.addressType);
    if (!client->connect(peer, true, false, false)) {
        result.error = "Connection failed (error " + String(client->getLastError()) + ")";
        NimBLEDevice::deleteClient(client);
        return result;
    }

    result.connected = true;
    displayTextLine("Mapping GATT structure only...");
    if (!client->discoverAttributes()) {
        result.error = "GATT discovery failed (error " + String(client->getLastError()) + ")";
    } else {
        result.discovered = true;
        const std::vector<NimBLERemoteService *> &services = client->getServices(false);
        for (const NimBLERemoteService *service : services) {
            if (service == nullptr) continue;
            result.services++;
            const String serviceUuid(service->getUUID().toString().c_str());
            const String serviceLabel = friendlyUuid(serviceUuid, serviceName);
            result.serviceSummaries.push_back(serviceLabel);
            addGattTechnicalLine(result, "SERVICE " + serviceLabel);

            const std::vector<NimBLERemoteCharacteristic *> &characteristics =
                service->getCharacteristics(false);
            for (const NimBLERemoteCharacteristic *characteristic : characteristics) {
                if (characteristic == nullptr) continue;
                result.characteristics++;
                const bool canRead = characteristic->canRead();
                const bool canWrite = characteristic->canWrite() || characteristic->canWriteNoResponse();
                const bool canNotify = characteristic->canNotify();
                const bool canIndicate = characteristic->canIndicate();
                if (canRead) result.readable++;
                if (canWrite) result.writable++;
                if (canNotify) result.notifiable++;
                if (canIndicate) result.indicatable++;

                const String characteristicUuid(characteristic->getUUID().toString().c_str());
                addGattTechnicalLine(
                    result, "  CHAR " + friendlyUuid(characteristicUuid, characteristicName)
                );
                addGattTechnicalLine(result, "    PROPS " + characteristicProperties(characteristic));

                const std::vector<NimBLERemoteDescriptor *> &descriptors =
                    characteristic->getDescriptors(false);
                for (const NimBLERemoteDescriptor *descriptor : descriptors) {
                    if (descriptor == nullptr) continue;
                    result.descriptors++;
                    const String descriptorUuid(descriptor->getUUID().toString().c_str());
                    addGattTechnicalLine(
                        result, "    DESC " + friendlyUuid(descriptorUuid, descriptorName)
                    );
                }
            }
        }
    }

    if (client->isConnected()) client->disconnect();
    delay(80);
    NimBLEDevice::deleteClient(client);
    return result;
}

std::vector<String> gattPlainLines(const GattResult &result) {
    std::vector<String> lines;
    if (!result.connected) {
        appendWrapped(lines, result.error.isEmpty() ? "Connection failed" : result.error);
        appendWrapped(lines, "No GATT information collected");
        return lines;
    }
    if (!result.discovered) {
        appendWrapped(lines, result.error.isEmpty() ? "GATT discovery failed" : result.error);
        appendWrapped(lines, "Disconnected without reading values");
        return lines;
    }

    appendWrapped(lines, "Structure mapped, then disconnected");
    appendWrapped(lines, "No characteristic values read");
    appendWrapped(lines, "No writes or subscriptions made");
    appendWrapped(lines, String(result.services) + " services, " + String(result.characteristics) +
                             " characteristics, " + String(result.descriptors) + " descriptors");
    appendWrapped(lines, String(result.readable) + " declare read support");
    appendWrapped(lines, String(result.writable) + " declare write support");
    appendWrapped(lines, String(result.notifiable) + " notify, " + String(result.indicatable) + " indicate");
    if (result.writable > 0) {
        appendWrapped(lines, "Writable declarations mean control/config endpoints may exist; access control was not tested");
    }
    for (const String &service : result.serviceSummaries) appendWrapped(lines, "Service: " + service);
    if (result.truncated) appendWrapped(lines, "Technical tree truncated to protect memory");
    return lines;
}

void drawGattViewer(
    const GattResult &result, bool technical, size_t &scroll, const String &targetIdentity
) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);
    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.drawCentreString(technical ? "GATT TECHNICAL TREE" : "GATT PLAIN SPEAK", tftWidth / 2, 29, 1);
    tft.drawCentreString(targetIdentity, tftWidth / 2, 42, 1);
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.drawCentreString("DISCONNECTED - NO VALUES ACCESSED", tftWidth / 2, 54, 1);

    std::vector<String> lines = technical ? result.technicalLines : gattPlainLines(result);
    if (technical && lines.empty()) lines.push_back(result.error.isEmpty() ? "No GATT tree" : result.error);
    const int lineHeight = 12;
    const int firstY = 69;
    const int footerY = tftHeight - 19;
    const int visible = (footerY - firstY) / lineHeight;
    if (scroll >= lines.size()) scroll = lines.empty() ? 0 : lines.size() - 1;
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    for (int row = 0; row < visible && scroll + row < lines.size(); row++) {
        tft.drawString(lines[scroll + row], 9, firstY + row * lineHeight, 1);
    }
    if (scroll > 0) tft.drawRightString("^", tftWidth - 7, firstY, 1);
    if (scroll + visible < lines.size()) tft.drawRightString("v", tftWidth - 7, footerY - lineHeight, 1);
    tft.drawCentreString("Turn scroll  Press plain/tree  Esc back", tftWidth / 2, footerY, 1);
    drawStatusBar();
}

void showGattResult(const GattResult &result, const SnifferTarget &target) {
    bool technical = false;
    size_t scroll = 0;
    bool redraw = true;
    while (!check(EscPress)) {
        if (check(PrevPress)) {
            if (scroll > 0) scroll--;
            redraw = true;
            delay(70);
        } else if (check(NextPress)) {
            scroll++;
            redraw = true;
            delay(70);
        } else if (check(SelPress)) {
            technical = !technical;
            scroll = 0;
            redraw = true;
            delay(100);
        }
        if (redraw) {
            drawGattViewer(result, technical, scroll, target.name.isEmpty() ? target.address : target.name);
            redraw = false;
        }
        delay(10);
    }
}

enum SnifferAction { ACTION_NONE, ACTION_ACTIVE_SCAN, ACTION_GATT, ACTION_FREEZE };

SnifferAction chooseSnifferAction(bool frozen) {
    SnifferAction chosen = ACTION_NONE;
    std::vector<Option> actions;
    actions.emplace_back("Active scan request (3s)", [&chosen]() { chosen = ACTION_ACTIVE_SCAN; });
    actions.emplace_back("Connect + map GATT", [&chosen]() { chosen = ACTION_GATT; });
    actions.emplace_back(frozen ? "Unfreeze frame" : "Freeze frame", [&chosen]() { chosen = ACTION_FREEZE; });
    loopOptions(actions, MENU_TYPE_REGULAR, "BLE Sniffer actions", 0, false);
    return chosen;
}

void sniffTarget(const SnifferTarget &target) {
    displayTextLine("Starting BLE sniffer...");
    ble_scan_setup();
    if (pBLEScan == nullptr) {
        displayError("BLE scanner unavailable", true);
        return;
    }

    pBLEScan->stop();
    pBLEScan->clearResults();
    resetState(target);

    if (!startPassiveTargetScan()) {
        pBLEScan->setScanCallbacks(nullptr, false);
        pBLEScan->setMaxResults(0xFF);
        displayError("Unable to start BLE scan", true);
        stopBLEStack();
        return;
    }

    uint8_t view = VIEW_PLAIN;
    size_t scroll = 0;
    bool frozen = false;
    SnifferState frozenState;
    uint32_t lastDrawMs = 0;
    bool redraw = true;

    while (!check(EscPress)) {
        if (check(PrevPress)) {
            if (scroll > 0) scroll--;
            redraw = true;
            delay(70);
        } else if (check(NextPress)) {
            scroll++;
            redraw = true;
            delay(70);
        } else if (check(LongPress)) {
            const SnifferAction action = chooseSnifferAction(frozen);
            if (action == ACTION_ACTIVE_SCAN) {
                frozen = false;
                runActiveScanBurst();
                view = VIEW_ACTIVE;
                scroll = 0;
            } else if (action == ACTION_GATT) {
                frozen = false;
                if (!target.connectable) {
                    displayWarning("Target is not advertising as connectable", true);
                } else if (confirmRadioAction(
                               "CONNECT + MAP GATT",
                               {"Target will see a connection", "Discovers structure only", "NO VALUE READS",
                                "NO WRITES OR SUBSCRIPTIONS"}
                           )) {
                    const GattResult result = enumerateGatt(target);
                    showGattResult(result, target);
                    if (!startPassiveTargetScan()) displayWarning("Passive scan restart failed", true);
                }
                scroll = 0;
            } else if (action == ACTION_FREEZE) {
                frozen = !frozen;
                if (frozen) frozenState = stateSnapshot();
            }
            redraw = true;
            delay(100);
        } else if (check(SelPress)) {
            view = (view + 1) % VIEW_COUNT;
            scroll = 0;
            redraw = true;
            delay(100);
        }

        const uint32_t now = millis();
        if (redraw || (!frozen && now - lastDrawMs >= 300) || (frozen && now - lastDrawMs >= 1000)) {
            const SnifferState snapshot = frozen ? frozenState : stateSnapshot();
            drawSniffer(snapshot, view, scroll, frozen);
            lastDrawMs = now;
            redraw = false;
        }
        delay(10);
    }

    pBLEScan->stop();
    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->setMaxResults(0xFF);
    pBLEScan->clearResults();
    stopBLEStack();
}

std::vector<SnifferTarget> discoverTargets() {
    std::vector<SnifferTarget> targets;
    displayTextLine("Scanning BLE advertisers...");
    ble_scan_setup();
    if (pBLEScan == nullptr) return targets;

    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setMaxResults(80);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);

    BLEScanResults results = pBLEScan->getResults(DISCOVERY_TIME_MS, false);
    targets.reserve(results.getCount());
    for (int i = 0; i < results.getCount(); i++) {
        const NimBLEAdvertisedDevice *device = results.getDevice(i);
        if (device == nullptr) continue;

        SnifferTarget target;
        target.address = device->getAddress().toString().c_str();
        target.rssi = device->getRSSI();
        target.addressType = device->getAddressType();
        target.connectable = device->isConnectable();
        target.scannable = device->isScannable();
        const std::vector<uint8_t> &payload = device->getPayload();
        target.name = cleanText(device->getName());
        if (target.name.isEmpty() && !payload.empty()) target.name = localNameFromPayload(payload.data(), payload.size());
        if (!payload.empty()) target.companyId = companyIdFromPayload(payload.data(), payload.size());
        if (target.name.isEmpty()) {
            const char *company = companyName(target.companyId);
            if (company) target.name = String(company) + " device";
        }
        targets.push_back(target);
    }

    std::sort(targets.begin(), targets.end(), [](const SnifferTarget &a, const SnifferTarget &b) {
        return a.rssi > b.rssi;
    });
    pBLEScan->clearResults();
    return targets;
}

} // namespace

void bleSniffer() {
    std::vector<SnifferTarget> targets = discoverTargets();
    if (targets.empty()) {
        displayWarning("No BLE advertisers found", true);
        stopBLEStack();
        return;
    }

    options.clear();
    const size_t maxTargets = targets.size() < 60 ? targets.size() : 60;
    for (size_t i = 0; i < maxTargets; i++) {
        const SnifferTarget target = targets[i];
        String label = target.name.isEmpty() ? target.address : target.name;
        if (!target.name.isEmpty() && target.address.length() >= 5) {
            label += " [" + target.address.substring(target.address.length() - 5) + "]";
        }
        label += " " + String(target.rssi);
        options.emplace_back(label, [target]() { sniffTarget(target); });
    }

    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_REGULAR, "BLE Sniffer target", 0, false);
    options.clear();
    stopBLEStack();
}
