#include "ble_solo_df.h"

#include "core/display.h"
#include "core/utils.h"
#include "modules/ble/ble_common.h"
#include <globals.h>

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
constexpr uint32_t CANDIDATE_STALE_MS = 2200;
constexpr int HANDOFF_SCORE_THRESHOLD = 78;
constexpr uint8_t HANDOFF_HITS_REQUIRED = 3;
constexpr size_t MEDIAN_WINDOW_SIZE = 7;
constexpr size_t MAX_PAYLOAD_BYTES = 64;
constexpr size_t MAX_MANUFACTURER_BYTES = 40;
constexpr size_t MAX_IDENTITY_BYTES = 40;

enum BleIdentitySource : uint8_t {
    BLE_ID_ADDRESS = 0,
    BLE_ID_ADVERTISED_NAME = 1,
    BLE_ID_MANUFACTURER = 2,
};

uint32_t fnv1a(const uint8_t *data, size_t length, uint32_t seed = 2166136261UL) {
    uint32_t hash = seed;
    for (size_t i = 0; i < length; i++) {
        hash ^= data[i];
        hash *= 16777619UL;
    }
    return hash;
}

uint32_t fnv1aString(const std::string &value, uint32_t seed = 2166136261UL) {
    return fnv1a(reinterpret_cast<const uint8_t *>(value.data()), value.size(), seed);
}

struct BleFingerprint {
    uint8_t payload[MAX_PAYLOAD_BYTES]{};
    uint8_t payloadLen = 0;
    uint8_t manufacturer[MAX_MANUFACTURER_BYTES]{};
    uint8_t manufacturerLen = 0;
    uint16_t companyId = 0;
    uint8_t addressType = 0;
    uint8_t advType = 0;
    int8_t txPower = 0;
    bool hasTxPower = false;
    uint32_t fullHash = 0;
    uint32_t shapeHash = 0;
    uint32_t serviceHash = 0;
};

struct BleDfTarget {
    String name;
    String address;
    int rssi = -127;
    uint8_t identitySource = BLE_ID_ADDRESS;
    BleFingerprint fingerprint;
};

struct TrackerState {
    int rawRssi = -127;
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
    uint32_t macFirstSeenMs = 0;
    uint32_t handoffNoticeUntilMs = 0;
    uint32_t reacquireNoticeUntilMs = 0;
    uint32_t lastOfflineMs = 0;
    uint16_t handoffs = 0;
    uint16_t reacquisitions = 0;
    uint8_t lastHandoffScore = 0;
    uint8_t candidateScore = 0;
    uint8_t candidateHits = 0;
    uint8_t identitySource = BLE_ID_ADDRESS;
    char currentName[MAX_IDENTITY_BYTES + 1]{};
    char currentAddress[18]{};
    char previousAddress[18]{};
    char candidateAddress[18]{};
    bool initialized = false;
};

struct CandidateState {
    BleFingerprint fingerprint;
    char name[MAX_IDENTITY_BYTES + 1]{};
    char address[18]{};
    int rssi = -127;
    uint8_t identitySource = BLE_ID_ADDRESS;
    uint8_t score = 0;
    uint8_t hits = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
};

struct TrackerSnapshot {
    TrackerState state;
    BleFingerprint fingerprint;
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

        if (_count % 2 == 1) return static_cast<float>(sorted[_count / 2]);
        return (sorted[_count / 2 - 1] + sorted[_count / 2]) / 2.0f;
    }

private:
    std::array<int, MEDIAN_WINDOW_SIZE> _values{};
    size_t _count = 0;
    size_t _index = 0;
};

portMUX_TYPE trackerMux = portMUX_INITIALIZER_UNLOCKED;
TrackerState trackerState;
CandidateState candidateState;
BleFingerprint trackedFingerprint;
MedianWindow medianWindow;
char trackedAddress[18]{};

int clampInt(int value, int low, int high) {
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

float clampFloat(float value, float low, float high) {
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

void copyAddress(char destination[18], const std::string &source) {
    std::memset(destination, 0, 18);
    std::strncpy(destination, source.c_str(), 17);
}

void copyIdentity(char destination[MAX_IDENTITY_BYTES + 1], const String &source) {
    std::memset(destination, 0, MAX_IDENTITY_BYTES + 1);
    std::strncpy(destination, source.c_str(), MAX_IDENTITY_BYTES);
}

String cleanIdentity(const uint8_t *data, size_t length) {
    if (data == nullptr || length == 0) return String();

    String cleaned;
    const size_t count = length < MAX_IDENTITY_BYTES ? length : MAX_IDENTITY_BYTES;
    cleaned.reserve(count);
    for (size_t i = 0; i < count; i++) {
        const uint8_t value = data[i];
        if (value == 0) break;
        if (value < 0x20 || value == 0x7F)
            cleaned += ' ';
        else
            cleaned += static_cast<char>(value);
    }
    cleaned.trim();
    return cleaned;
}

String cleanIdentity(const std::string &value) {
    return cleanIdentity(reinterpret_cast<const uint8_t *>(value.data()), value.size());
}

String localNameFromPayload(const std::vector<uint8_t> &payload) {
    String shortenedName;
    size_t offset = 0;

    while (offset < payload.size()) {
        const uint8_t fieldLength = payload[offset];
        if (fieldLength == 0) break;
        const size_t fieldEnd = offset + static_cast<size_t>(fieldLength) + 1;
        if (fieldLength < 1 || fieldEnd > payload.size()) break;

        const uint8_t type = payload[offset + 1];
        if ((type == 0x08 || type == 0x09) && fieldLength > 1) {
            const String candidate = cleanIdentity(payload.data() + offset + 2, fieldLength - 1);
            if (!candidate.isEmpty()) {
                if (type == 0x09) return candidate;
                if (shortenedName.isEmpty()) shortenedName = candidate;
            }
        }
        offset = fieldEnd;
    }
    return shortenedName;
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
        default: return nullptr;
    }
}

const char *identitySourceTag(uint8_t source) {
    switch (source) {
        case BLE_ID_ADVERTISED_NAME: return "ADV";
        case BLE_ID_MANUFACTURER: return "MFG";
        default: return "MAC";
    }
}

String resolveDeviceIdentity(const NimBLEAdvertisedDevice *device, const BleFingerprint &fingerprint, uint8_t &source) {
    source = BLE_ID_ADDRESS;
    if (device == nullptr) return String();

    String name = cleanIdentity(device->getName());
    if (name.isEmpty()) name = localNameFromPayload(device->getPayload());
    if (!name.isEmpty()) {
        source = BLE_ID_ADVERTISED_NAME;
        return name;
    }

    const char *company = companyName(fingerprint.companyId);
    if (company != nullptr) {
        source = BLE_ID_MANUFACTURER;
        return String(company) + " device";
    }

    return String();
}

uint32_t calculateShapeHash(const uint8_t *payload, size_t length) {
    uint32_t hash = 2166136261UL;
    size_t offset = 0;

    while (offset < length) {
        const uint8_t fieldLength = payload[offset];
        if (fieldLength == 0) break;
        if (offset + fieldLength >= length + 1) break;

        const uint8_t type = payload[offset + 1];
        hash = fnv1a(&fieldLength, 1, hash);
        hash = fnv1a(&type, 1, hash);

        // Preserve protocol identifiers while ignoring most rotating/encrypted data.
        if (type == 0xFF && fieldLength >= 4) {
            const size_t bytesToHash = fieldLength >= 5 ? 4 : fieldLength - 1;
            hash = fnv1a(payload + offset + 2, bytesToHash, hash);
        } else if ((type == 0x02 || type == 0x03 || type == 0x06 || type == 0x07) && fieldLength > 1) {
            hash = fnv1a(payload + offset + 2, fieldLength - 1, hash);
        }

        offset += static_cast<size_t>(fieldLength) + 1;
    }

    return hash;
}

BleFingerprint fingerprintFromDevice(const NimBLEAdvertisedDevice *device) {
    BleFingerprint fingerprint;
    if (device == nullptr) return fingerprint;

    fingerprint.addressType = device->getAddressType();
    fingerprint.advType = device->getAdvType();
    fingerprint.hasTxPower = device->haveTXPower();
    fingerprint.txPower = fingerprint.hasTxPower ? device->getTXPower() : 0;

    const std::vector<uint8_t> &payload = device->getPayload();
    fingerprint.payloadLen = static_cast<uint8_t>(payload.size() < MAX_PAYLOAD_BYTES ? payload.size() : MAX_PAYLOAD_BYTES);
    if (fingerprint.payloadLen > 0) {
        std::memcpy(fingerprint.payload, payload.data(), fingerprint.payloadLen);
        fingerprint.fullHash = fnv1a(fingerprint.payload, fingerprint.payloadLen);
        fingerprint.shapeHash = calculateShapeHash(fingerprint.payload, fingerprint.payloadLen);
    }

    if (device->haveManufacturerData()) {
        const std::string manufacturer = device->getManufacturerData();
        fingerprint.manufacturerLen = static_cast<uint8_t>(
            manufacturer.size() < MAX_MANUFACTURER_BYTES ? manufacturer.size() : MAX_MANUFACTURER_BYTES
        );
        if (fingerprint.manufacturerLen > 0) {
            std::memcpy(fingerprint.manufacturer, manufacturer.data(), fingerprint.manufacturerLen);
        }
        if (manufacturer.size() >= 2) {
            fingerprint.companyId = static_cast<uint16_t>(static_cast<uint8_t>(manufacturer[0])) |
                                    (static_cast<uint16_t>(static_cast<uint8_t>(manufacturer[1])) << 8);
        }
    }

    uint32_t serviceHash = 2166136261UL;
    for (uint8_t i = 0; i < device->getServiceUUIDCount(); i++) {
        serviceHash = fnv1aString(device->getServiceUUID(i).toString(), serviceHash);
    }
    for (uint8_t i = 0; i < device->getServiceDataCount(); i++) {
        serviceHash = fnv1aString(device->getServiceDataUUID(i).toString(), serviceHash);
        const std::string serviceData = device->getServiceData(i);
        const uint8_t dataLength = static_cast<uint8_t>(serviceData.size() > 255 ? 255 : serviceData.size());
        serviceHash = fnv1a(&dataLength, 1, serviceHash);
    }
    fingerprint.serviceHash = serviceHash;

    return fingerprint;
}

int payloadSimilarity(const BleFingerprint &a, const BleFingerprint &b) {
    if (a.payloadLen == 0 || b.payloadLen == 0) return 0;
    const size_t common = a.payloadLen < b.payloadLen ? a.payloadLen : b.payloadLen;
    if (common == 0) return 0;

    size_t equal = 0;
    for (size_t i = 0; i < common; i++) {
        if (a.payload[i] == b.payload[i]) equal++;
    }
    return static_cast<int>((equal * 100) / common);
}

int fingerprintScore(
    const BleFingerprint &reference, const BleFingerprint &candidate, int referenceRssi, int candidateRssi,
    uint32_t transitionMs
) {
    int score = 0;

    if (reference.shapeHash != 0 && reference.shapeHash == candidate.shapeHash) score += 25;
    if (reference.companyId != 0 && reference.companyId == candidate.companyId) score += 20;
    if (reference.manufacturerLen == candidate.manufacturerLen && reference.manufacturerLen > 0) score += 10;

    if (reference.manufacturerLen >= 3 && candidate.manufacturerLen >= 3 &&
        reference.manufacturer[0] == candidate.manufacturer[0] &&
        reference.manufacturer[1] == candidate.manufacturer[1] &&
        reference.manufacturer[2] == candidate.manufacturer[2]) {
        score += 10;
    }

    if (reference.serviceHash != 0 && reference.serviceHash == candidate.serviceHash) score += 8;
    if (reference.advType == candidate.advType) score += 4;
    if (reference.addressType == candidate.addressType) score += 3;
    if (reference.payloadLen == candidate.payloadLen && reference.payloadLen > 0) score += 7;

    if (reference.hasTxPower == candidate.hasTxPower) {
        score += 2;
        if (reference.hasTxPower && std::abs(reference.txPower - candidate.txPower) <= 2) score += 3;
    }

    const int similarity = payloadSimilarity(reference, candidate);
    if (similarity >= 85)
        score += 15;
    else if (similarity >= 65)
        score += 10;
    else if (similarity >= 45)
        score += 5;

    const int rssiDifference = std::abs(referenceRssi - candidateRssi);
    if (rssiDifference <= 5)
        score += 10;
    else if (rssiDifference <= 10)
        score += 6;
    else if (rssiDifference <= 18)
        score += 3;

    if (transitionMs <= 2000)
        score += 10;
    else if (transitionMs <= 5000)
        score += 6;
    else if (transitionMs <= HANDOFF_MAX_GAP_MS)
        score += 3;

    return clampInt(score, 0, 100);
}

String bytesToHex(const uint8_t *data, size_t length, size_t maxBytes = 16) {
    String output;
    const size_t count = length < maxBytes ? length : maxBytes;
    output.reserve(count * 2 + 2);
    char byteText[3];
    for (size_t i = 0; i < count; i++) {
        std::snprintf(byteText, sizeof(byteText), "%02X", data[i]);
        output += byteText;
    }
    if (length > count) output += "..";
    return output;
}

String formatAge(uint32_t ageMs) {
    const uint32_t totalSeconds = ageMs / 1000;
    const uint32_t minutes = totalSeconds / 60;
    const uint32_t seconds = totalSeconds % 60;
    char text[12];
    std::snprintf(text, sizeof(text), "%02lu:%02lu", static_cast<unsigned long>(minutes), static_cast<unsigned long>(seconds));
    return String(text);
}

void resetCandidateLocked() {
    candidateState = CandidateState{};
    trackerState.candidateScore = 0;
    trackerState.candidateHits = 0;
    trackerState.candidateAddress[0] = '\0';
}

void resetTrackerState(const BleDfTarget &target) {
    portENTER_CRITICAL(&trackerMux);
    trackerState = TrackerState{};
    trackedFingerprint = target.fingerprint;
    copyAddress(trackerState.currentAddress, target.address.c_str());
    copyAddress(trackedAddress, target.address.c_str());
    if (!target.name.isEmpty()) copyIdentity(trackerState.currentName, target.name);
    trackerState.identitySource = target.identitySource;
    trackerState.macFirstSeenMs = millis();
    trackerState.rateWindowStartMs = millis();
    resetCandidateLocked();
    portEXIT_CRITICAL(&trackerMux);
    medianWindow.reset();
}

TrackerSnapshot getTrackerSnapshot() {
    TrackerSnapshot snapshot;
    portENTER_CRITICAL(&trackerMux);
    snapshot.state = trackerState;
    snapshot.fingerprint = trackedFingerprint;
    portEXIT_CRITICAL(&trackerMux);
    return snapshot;
}

void resetPeak() {
    portENTER_CRITICAL(&trackerMux);
    if (trackerState.initialized) {
        trackerState.bestRssi = trackerState.stableRssi;
        trackerState.fastRssi = trackerState.stableRssi;
        trackerState.trend = 0.0f;
    }
    portEXIT_CRITICAL(&trackerMux);
}

void updateCadenceLocked(uint32_t seenAtMs) {
    if (trackerState.lastPacketMs != 0) {
        const uint32_t gapMs = seenAtMs - trackerState.lastPacketMs;
        if (gapMs < 60000) {
            if (trackerState.gapEmaMs <= 0.1f)
                trackerState.gapEmaMs = static_cast<float>(gapMs);
            else
                trackerState.gapEmaMs += 0.18f * (static_cast<float>(gapMs) - trackerState.gapEmaMs);
        }
    }
    trackerState.lastPacketMs = seenAtMs;

    if (trackerState.rateWindowStartMs == 0) trackerState.rateWindowStartMs = seenAtMs;
    trackerState.rateWindowPackets++;
    const uint32_t windowMs = seenAtMs - trackerState.rateWindowStartMs;
    if (windowMs >= 1000) {
        trackerState.packetsPerSecond = (trackerState.rateWindowPackets * 1000.0f) / static_cast<float>(windowMs);
        trackerState.rateWindowStartMs = seenAtMs;
        trackerState.rateWindowPackets = 0;
    }
}

void printFingerprint(const char *prefix, const char *address, const BleFingerprint &fingerprint) {
    Serial.printf(
        "[DF] %s addr=%s company=%04X shape=%08lX full=%08lX payloadLen=%u mfgLen=%u payload=%s\n",
        prefix,
        address,
        fingerprint.companyId,
        static_cast<unsigned long>(fingerprint.shapeHash),
        static_cast<unsigned long>(fingerprint.fullHash),
        fingerprint.payloadLen,
        fingerprint.manufacturerLen,
        bytesToHex(fingerprint.payload, fingerprint.payloadLen, 24).c_str()
    );
}

void acceptHandoffLocked(const CandidateState &candidate, uint32_t seenAtMs) {
    std::strncpy(trackerState.previousAddress, trackerState.currentAddress, 17);
    trackerState.previousAddress[17] = '\0';
    std::strncpy(trackerState.currentAddress, candidate.address, 17);
    trackerState.currentAddress[17] = '\0';
    std::strncpy(trackedAddress, candidate.address, 17);
    trackedAddress[17] = '\0';

    // Preserve a strong advertised identity across privacy-address rotations. Only
    // replace it when the successor actually advertises a name, or if we had none.
    if (candidate.name[0] != '\0' &&
        (candidate.identitySource == BLE_ID_ADVERTISED_NAME || trackerState.currentName[0] == '\0')) {
        std::strncpy(trackerState.currentName, candidate.name, MAX_IDENTITY_BYTES);
        trackerState.currentName[MAX_IDENTITY_BYTES] = '\0';
        trackerState.identitySource = candidate.identitySource;
    }

    trackedFingerprint = candidate.fingerprint;
    trackerState.handoffs++;
    trackerState.lastHandoffScore = candidate.score;
    trackerState.handoffNoticeUntilMs = seenAtMs + HANDOFF_NOTICE_MS;
    trackerState.macFirstSeenMs = seenAtMs;
    trackerState.rawRssi = candidate.rssi;
    trackerState.fastRssi = static_cast<float>(candidate.rssi);
    trackerState.stableRssi = static_cast<float>(candidate.rssi);
    trackerState.bestRssi = static_cast<float>(candidate.rssi);
    trackerState.trend = 0.0f;
    trackerState.jitter = 0.0f;
    trackerState.samples = 1;
    trackerState.lastSeenMs = seenAtMs;
    trackerState.lastPacketMs = seenAtMs;
    trackerState.rateWindowStartMs = seenAtMs;
    trackerState.rateWindowPackets = 1;
    trackerState.packetsPerSecond = 0.0f;
    trackerState.gapEmaMs = 0.0f;
    resetCandidateLocked();
}

class BleDfScanCallbacks : public NimBLEScanCallbacks {
public:
    void onResult(const NimBLEAdvertisedDevice *advertisedDevice) override {
        if (advertisedDevice == nullptr) return;

        const std::string address = advertisedDevice->getAddress().toString();
        const int rawRssi = advertisedDevice->getRSSI();
        const uint32_t seenAtMs = millis();

        bool isCurrentTarget = false;
        portENTER_CRITICAL(&trackerMux);
        isCurrentTarget = std::strncmp(address.c_str(), trackedAddress, 17) == 0;
        portEXIT_CRITICAL(&trackerMux);

        if (isCurrentTarget) {
            bool wasLost = false;
            portENTER_CRITICAL(&trackerMux);
            wasLost = trackerState.initialized && seenAtMs - trackerState.lastSeenMs > LOST_TARGET_MS;
            portEXIT_CRITICAL(&trackerMux);

            // Do not blend fresh measurements with samples from before an outage.
            // A stale median/EMA makes a returning target look continuously tracked
            // and can produce a false WARMER/COLDER cue.
            if (wasLost) medianWindow.reset();
            medianWindow.add(rawRssi);
            const float medianRssi = medianWindow.median();
            const BleFingerprint currentFingerprint = fingerprintFromDevice(advertisedDevice);
            uint8_t seenIdentitySource = BLE_ID_ADDRESS;
            const String seenIdentity = resolveDeviceIdentity(advertisedDevice, currentFingerprint, seenIdentitySource);

            portENTER_CRITICAL(&trackerMux);
            trackedFingerprint = currentFingerprint;
            if (!seenIdentity.isEmpty() && seenIdentitySource == BLE_ID_ADVERTISED_NAME) {
                copyIdentity(trackerState.currentName, seenIdentity);
                trackerState.identitySource = BLE_ID_ADVERTISED_NAME;
            }
            resetCandidateLocked();

            if (wasLost) {
                const uint32_t offlineMs = seenAtMs - trackerState.lastSeenMs;
                trackerState.lastOfflineMs = offlineMs;
                trackerState.reacquireNoticeUntilMs = seenAtMs + REACQUIRE_NOTICE_MS;
                if (trackerState.reacquisitions < 0xFFFFu) trackerState.reacquisitions++;
                trackerState.rawRssi = rawRssi;
                trackerState.fastRssi = medianRssi;
                trackerState.stableRssi = medianRssi;
                trackerState.bestRssi = medianRssi;
                trackerState.trend = 0.0f;
                trackerState.jitter = 0.0f;
                trackerState.samples = 1;
                trackerState.lastSeenMs = seenAtMs;
                trackerState.lastPacketMs = seenAtMs;
                trackerState.rateWindowStartMs = seenAtMs;
                trackerState.rateWindowPackets = 1;
                trackerState.packetsPerSecond = 0.0f;
                portEXIT_CRITICAL(&trackerMux);
                Serial.printf(
                    "[DF] REACQUIRED %s after %lums rssi=%d\n",
                    address.c_str(),
                    static_cast<unsigned long>(offlineMs),
                    rawRssi
                );
                return;
            }

            updateCadenceLocked(seenAtMs);

            if (!trackerState.initialized) {
                trackerState.rawRssi = rawRssi;
                trackerState.fastRssi = medianRssi;
                trackerState.stableRssi = medianRssi;
                trackerState.bestRssi = medianRssi;
                trackerState.trend = 0.0f;
                trackerState.jitter = 0.0f;
                trackerState.samples = 1;
                trackerState.lastSeenMs = seenAtMs;
                trackerState.initialized = true;
                portEXIT_CRITICAL(&trackerMux);
                printFingerprint("target", address.c_str(), currentFingerprint);
                return;
            }

            constexpr float FAST_ALPHA = 0.45f;
            constexpr float STABLE_ALPHA = 0.14f;
            constexpr float JITTER_ALPHA = 0.18f;

            trackerState.rawRssi = rawRssi;
            trackerState.fastRssi += FAST_ALPHA * (medianRssi - trackerState.fastRssi);
            trackerState.stableRssi += STABLE_ALPHA * (medianRssi - trackerState.stableRssi);
            trackerState.trend = trackerState.fastRssi - trackerState.stableRssi;
            trackerState.jitter +=
                JITTER_ALPHA * (fabsf(static_cast<float>(rawRssi) - trackerState.fastRssi) - trackerState.jitter);
            if (trackerState.stableRssi > trackerState.bestRssi) trackerState.bestRssi = trackerState.stableRssi;
            trackerState.samples++;
            trackerState.lastSeenMs = seenAtMs;
            portEXIT_CRITICAL(&trackerMux);
            return;
        }

        TrackerState stateSnapshot;
        BleFingerprint referenceFingerprint;
        portENTER_CRITICAL(&trackerMux);
        stateSnapshot = trackerState;
        referenceFingerprint = trackedFingerprint;
        portEXIT_CRITICAL(&trackerMux);

        if (!stateSnapshot.initialized) return;
        const uint32_t transitionMs = seenAtMs - stateSnapshot.lastSeenMs;
        if (transitionMs < HANDOFF_ARM_MS || transitionMs > HANDOFF_MAX_GAP_MS) return;

        const BleFingerprint candidateFingerprint = fingerprintFromDevice(advertisedDevice);
        uint8_t candidateIdentitySource = BLE_ID_ADDRESS;
        const String candidateIdentity = resolveDeviceIdentity(advertisedDevice, candidateFingerprint, candidateIdentitySource);
        const int score = fingerprintScore(
            referenceFingerprint,
            candidateFingerprint,
            static_cast<int>(roundf(stateSnapshot.stableRssi)),
            rawRssi,
            transitionMs
        );
        if (score < 55) return;

        bool accepted = false;
        CandidateState acceptedCandidate;

        portENTER_CRITICAL(&trackerMux);
        const bool sameCandidate = std::strncmp(candidateState.address, address.c_str(), 17) == 0;
        const bool staleCandidate = candidateState.lastSeenMs != 0 && seenAtMs - candidateState.lastSeenMs > CANDIDATE_STALE_MS;

        if (!sameCandidate || staleCandidate) {
            candidateState = CandidateState{};
            copyAddress(candidateState.address, address);
            candidateState.firstSeenMs = seenAtMs;
        }

        candidateState.fingerprint = candidateFingerprint;
        candidateState.rssi = rawRssi;
        candidateState.identitySource = candidateIdentitySource;
        if (!candidateIdentity.isEmpty()) copyIdentity(candidateState.name, candidateIdentity);
        candidateState.score = static_cast<uint8_t>(score);
        candidateState.lastSeenMs = seenAtMs;
        if (candidateState.hits < 255) candidateState.hits++;

        trackerState.candidateScore = candidateState.score;
        trackerState.candidateHits = candidateState.hits;
        std::strncpy(trackerState.candidateAddress, candidateState.address, 17);
        trackerState.candidateAddress[17] = '\0';

        if (candidateState.score >= HANDOFF_SCORE_THRESHOLD && candidateState.hits >= HANDOFF_HITS_REQUIRED) {
            acceptedCandidate = candidateState;
            acceptHandoffLocked(candidateState, seenAtMs);
            accepted = true;
        }
        portEXIT_CRITICAL(&trackerMux);

        if (accepted) {
            medianWindow.reset();
            medianWindow.add(rawRssi);
            Serial.printf(
                "[DF] HANDOFF %s -> %s score=%u gap=%lums rssi=%d\n",
                stateSnapshot.currentAddress,
                acceptedCandidate.address,
                acceptedCandidate.score,
                static_cast<unsigned long>(transitionMs),
                rawRssi
            );
            printFingerprint("successor", acceptedCandidate.address, acceptedCandidate.fingerprint);
        }
    }
};

BleDfScanCallbacks bleDfCallbacks;

int signalBarPixels(float rssi, int width) {
    const float bounded = clampFloat(rssi, -100.0f, -35.0f);
    return static_cast<int>(((bounded + 100.0f) / 65.0f) * width);
}

String trackerStatusLabel(const TrackerState &state) {
    const uint32_t now = millis();
    if (state.handoffNoticeUntilMs > now) return "HANDOFF " + String(state.lastHandoffScore) + "%";
    if (state.reacquireNoticeUntilMs > now) return "REACQUIRED " + String(state.lastOfflineMs / 1000) + "s";
    if (!state.initialized) return "SEARCHING";
    if (now - state.lastSeenMs > LOST_TARGET_MS) {
        if (state.candidateHits > 0) return "CAND " + String(state.candidateScore) + "% x" + String(state.candidateHits);
        return "TARGET LOST";
    }
    if (state.trend >= 3.0f) return "WARMER";
    if (state.trend <= -3.0f) return "COLDER";
    return "STEADY";
}

uint16_t trackerStatusColor(const TrackerState &state) {
    const uint32_t now = millis();
    if (state.handoffNoticeUntilMs > now) return TFT_GREEN;
    if (state.reacquireNoticeUntilMs > now) return TFT_GREEN;
    if (!state.initialized) return TFT_RED;
    if (now - state.lastSeenMs > LOST_TARGET_MS) return state.candidateHits > 0 ? TFT_YELLOW : TFT_RED;
    if (state.trend >= 3.0f) return TFT_GREEN;
    if (state.trend <= -3.0f) return TFT_YELLOW;
    return bruceConfig.priColor;
}

int confidenceScore(const TrackerState &state) {
    if (!state.initialized) return 0;

    int sampleScore = static_cast<int>(state.samples * 3);
    if (sampleScore > 75) sampleScore = 75;

    int stabilityScore = 20 - static_cast<int>(state.jitter * 4.0f);
    if (stabilityScore < 0) stabilityScore = 0;

    int score = sampleScore + stabilityScore;
    const uint32_t age = millis() - state.lastSeenMs;
    if (age > 500) score -= static_cast<int>((age - 500) / 75);

    return clampInt(score, 0, 100);
}

void drawTrackerFrame() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);

    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    tft.drawCentreString("BLE HUNTER DF", tftWidth / 2, 29, 1);

    tft.drawString("RAW", 13, 58, 1);
    tft.drawCentreString("AVG", tftWidth / 2, 58, 1);
    tft.drawRightString("BEST", tftWidth - 13, 58, 1);

    const int barX = 14;
    const int barY = 88;
    const int barW = tftWidth - 28;
    const int barH = 18;
    tft.drawRect(barX, barY, barW, barH, bruceConfig.priColor);

    const String footer = String(BTN_ALIAS) + " peak  Hold details  Esc back";
    tft.drawCentreString(footer, tftWidth / 2, tftHeight - 14, 1);
    drawStatusBar();
}

void drawTrackerValues(const TrackerSnapshot &snapshot) {
    const TrackerState &state = snapshot.state;
    const int raw = state.initialized ? state.rawRssi : -127;
    const int stable = state.initialized ? static_cast<int>(roundf(state.stableRssi)) : -127;
    const int best = state.initialized ? static_cast<int>(roundf(state.bestRssi)) : -127;

    tft.fillRect(8, 42, tftWidth - 16, 14, bruceConfig.bgColor);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);
    String identity = state.currentName[0] ? String(state.currentName) : String(state.currentAddress);
    if (state.identitySource == BLE_ID_MANUFACTURER) identity += " [MFG]";
    tft.drawCentreString(identity, tftWidth / 2, 43, 1);

    tft.setTextSize(FM);
    tft.fillRect(8, 69, tftWidth - 16, 17, bruceConfig.bgColor);
    tft.drawString(String(raw), 13, 69, 1);
    tft.drawCentreString(String(stable), tftWidth / 2, 69, 1);
    tft.drawRightString(String(best), tftWidth - 13, 69, 1);

    const int barX = 16;
    const int barY = 90;
    const int barW = tftWidth - 32;
    const int barH = 14;
    tft.fillRect(barX, barY, barW, barH, bruceConfig.bgColor);
    if (state.initialized) {
        const int fillW = clampInt(signalBarPixels(state.stableRssi, barW), 0, barW);
        if (fillW > 0) tft.fillRect(barX, barY, fillW, barH, trackerStatusColor(state));
    }

    tft.fillRect(8, 109, tftWidth - 16, 40, bruceConfig.bgColor);
    tft.setTextSize(FM);
    tft.setTextColor(trackerStatusColor(state), bruceConfig.bgColor);
    tft.drawCentreString(trackerStatusLabel(state), tftWidth / 2, 110, 1);

    float displayedRate = state.packetsPerSecond;
    if (state.lastSeenMs == 0 || millis() - state.lastSeenMs > 1800) displayedRate = 0.0f;

    tft.setTextSize(FP);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    const String stats = "d" + String(state.trend, 1) + " c" + String(confidenceScore(state)) + " p" +
                         String(displayedRate, 1) + " H" + String(state.handoffs);
    tft.drawCentreString(stats, tftWidth / 2, 132, 1);

    const String age = "MAC " + formatAge(millis() - state.macFirstSeenMs) + " gap " +
                       String(static_cast<int>(roundf(state.gapEmaMs))) + "ms";
    tft.drawCentreString(age, tftWidth / 2, 144, 1);
}

void drawFingerprintDetails(const TrackerSnapshot &snapshot) {
    const TrackerState &state = snapshot.state;
    const BleFingerprint &fingerprint = snapshot.fingerprint;

    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorder(false);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    tft.setTextSize(FP);

    tft.drawCentreString("BLE IDENTITY", tftWidth / 2, 29, 1);
    const String identity = state.currentName[0] ? String(state.currentName) : String("Unknown BLE");
    tft.drawString("Name " + identity + " [" + identitySourceTag(state.identitySource) + "]", 10, 45, 1);
    tft.drawString("MAC  " + String(state.currentAddress), 10, 58, 1);
    tft.drawString("Prev " + String(state.previousAddress[0] ? state.previousAddress : "-"), 10, 71, 1);
    const char *company = companyName(fingerprint.companyId);
    const String companyText = company ? String(company) : ("0x" + String(fingerprint.companyId, HEX));
    tft.drawString("Mfg  " + companyText, 10, 84, 1);
    tft.drawString("Shape " + String(fingerprint.shapeHash, HEX), 10, 97, 1);
    tft.drawString("Len " + String(fingerprint.payloadLen) + "  Mfg " + String(fingerprint.manufacturerLen) +
                       "  Type " + String(fingerprint.advType),
                   10,
                   110,
                   1);
    tft.drawString("ADV " + bytesToHex(fingerprint.payload, fingerprint.payloadLen, 20), 10, 123, 1);
    tft.drawString("MFG " + bytesToHex(fingerprint.manufacturer, fingerprint.manufacturerLen, 20), 10, 136, 1);
    tft.drawString("Rate " + String(state.packetsPerSecond, 2) + "/s  Handoffs " + String(state.handoffs), 10, 149, 1);

    drawStatusBar();
}

void trackBleTarget(const BleDfTarget &target) {
    displayTextLine("Starting BLE Hunter tracker...");

    ble_scan_setup();
    if (pBLEScan == nullptr) {
        displayError("BLE scanner unavailable", true);
        return;
    }

    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(false);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);
    pBLEScan->setMaxResults(0);
    pBLEScan->setScanCallbacks(&bleDfCallbacks, true);

    resetTrackerState(target);
    printFingerprint("selected", target.address.c_str(), target.fingerprint);

    if (!pBLEScan->start(0, false, true)) {
        pBLEScan->setScanCallbacks(nullptr, false);
        pBLEScan->setMaxResults(0xFF);
        displayError("Unable to start BLE scan", true);
        stopBLEStack();
        return;
    }

    bool detailsMode = false;
    drawTrackerFrame();
    uint32_t lastDrawMs = 0;

    while (!check(EscPress)) {
        if (check(LongPress)) {
            detailsMode = !detailsMode;
            if (!detailsMode) drawTrackerFrame();
            delay(100);
        } else if (check(SelPress)) {
            if (detailsMode) {
                detailsMode = false;
                drawTrackerFrame();
            } else {
                resetPeak();
            }
        }

        const uint32_t now = millis();
        const uint32_t refreshMs = detailsMode ? 300 : 120;
        if (now - lastDrawMs >= refreshMs) {
            const TrackerSnapshot snapshot = getTrackerSnapshot();
            if (detailsMode)
                drawFingerprintDetails(snapshot);
            else
                drawTrackerValues(snapshot);
            lastDrawMs = now;
        }
        delay(10);
    }

    if (pBLEScan != nullptr) {
        pBLEScan->stop();
        pBLEScan->setScanCallbacks(nullptr, false);
        pBLEScan->setMaxResults(0xFF);
        pBLEScan->clearResults();
    }
    stopBLEStack();
}

std::vector<BleDfTarget> discoverBleTargets() {
    std::vector<BleDfTarget> targets;

    displayTextLine("Scanning BLE targets...");
    ble_scan_setup();
    if (pBLEScan == nullptr) return targets;

    pBLEScan->stop();
    pBLEScan->clearResults();
    pBLEScan->setMaxResults(80);
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(SCAN_INT);
    pBLEScan->setWindow(SCAN_WINDOW);

    BLEScanResults foundDevices = pBLEScan->getResults(DISCOVERY_TIME_MS, false);
    targets.reserve(foundDevices.getCount());

    for (int i = 0; i < foundDevices.getCount(); i++) {
        const NimBLEAdvertisedDevice *device = foundDevices.getDevice(i);
        if (device == nullptr) continue;

        BleDfTarget target;
        target.address = device->getAddress().toString().c_str();
        target.rssi = device->getRSSI();
        target.fingerprint = fingerprintFromDevice(device);
        target.name = resolveDeviceIdentity(device, target.fingerprint, target.identitySource);
        targets.push_back(target);
    }

    std::sort(targets.begin(), targets.end(), [](const BleDfTarget &a, const BleDfTarget &b) {
        return a.rssi > b.rssi;
    });

    pBLEScan->clearResults();
    return targets;
}

} // namespace

void bleSoloDf() {
    std::vector<BleDfTarget> targets = discoverBleTargets();

    if (targets.empty()) {
        displayWarning("No BLE advertisers found", true);
        stopBLEStack();
        return;
    }

    options.clear();
    const size_t maxTargets = targets.size() < 60 ? targets.size() : 60;
    for (size_t i = 0; i < maxTargets; i++) {
        const BleDfTarget target = targets[i];
        String label = target.name;
        if (label.isEmpty()) {
            label = target.address;
        } else {
            if (target.identitySource == BLE_ID_MANUFACTURER) label += " [MFG]";
            if (target.address.length() >= 5) label += " [" + target.address.substring(target.address.length() - 5) + "]";
        }
        label += " " + String(target.rssi);

        options.emplace_back(label, [target]() { trackBleTarget(target); });
    }

    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_REGULAR, "Select BLE target", 0, false);
    options.clear();
    stopBLEStack();
}
