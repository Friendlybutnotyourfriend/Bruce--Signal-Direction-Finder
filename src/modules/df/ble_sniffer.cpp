#include "ble_sniffer.h"

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_common.h"
#include <globals.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t DISCOVERY_TIME_MS = 5000;
constexpr uint32_t LOST_DEVICE_MS = 4000;
constexpr size_t MAX_PAYLOAD_BYTES = 96;
constexpr size_t MAX_NAME_BYTES = 40;
constexpr uint8_t VIEW_PLAIN = 0;
constexpr uint8_t VIEW_FIELDS = 1;
constexpr uint8_t VIEW_RAW = 2;
constexpr uint8_t VIEW_COUNT = 3;

struct SnifferTarget {
    String name;
    String address;
    int rssi = -127;
    uint16_t companyId = 0;
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
    bool hasTxPower = false;
    bool initialized = false;
};

portMUX_TYPE snifferMux = portMUX_INITIALIZER_UNLOCKED;
SnifferState snifferState;
char selectedAddress[18]{};

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
    copyAddress(selectedAddress, std::string(target.address.c_str()));
    copyAddress(snifferState.address, std::string(target.address.c_str()));
    if (!target.name.isEmpty()) copyName(snifferState.name, target.name);
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
        const size_t payloadLength = payload.size() < MAX_PAYLOAD_BYTES ? payload.size() : MAX_PAYLOAD_BYTES;
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
        snifferState.lastSeenMs = millis();
        snifferState.packets++;
        snifferState.initialized = true;
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

    const char *viewName = view == VIEW_PLAIN ? "PLAIN SPEAK" : (view == VIEW_FIELDS ? "AD FIELDS" : "RAW BYTES");
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
    else
        lines = rawLines(state);

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
    tft.drawCentreString("Turn scroll  Press view  Hold freeze", tftWidth / 2, footerY, 1);
    drawStatusBar();
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
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&snifferCallbacks, true);
    resetState(target);

    if (!pBLEScan->start(0, false, true)) {
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
            frozen = !frozen;
            if (frozen) frozenState = stateSnapshot();
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
