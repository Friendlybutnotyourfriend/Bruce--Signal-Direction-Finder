#pragma once
// Host-testable scoring for Sentinel. No Arduino, Wi-Fi, or BLE stack types.
// A finding is a radio pattern. It is never an identification of a person.

#include <stddef.h>
#include <stdint.h>

namespace sentinel {

enum class Severity : uint8_t { None = 0, Info = 1, Low = 2, Medium = 3, High = 4 };

enum class Kind : uint8_t {
    Deauth = 0,
    BeaconFlood,
    EvilTwin,
    KarmaProbe,
    BleSpam,
    HidGatt,
    Tracker,
    Note,
    Count
};

enum class WifiSecurity : uint8_t { Unknown = 0, Open, Wep, Wpa, Wpa2, Wpa3, Mixed };

// Bits. One advertisement can match only one of these in practice.
enum BleFamily : uint8_t {
    BleNone = 0,
    AppleContinuity = 1 << 0,
    FastPair = 1 << 1,
    SwiftPair = 1 << 2,
    SamsungEasySetup = 1 << 3
};

enum class TrackerFamily : uint8_t { None = 0, AppleFindMy, SamsungSmartTag, Tile, GoogleFindMyDevice };

struct Thresholds {
    uint16_t deauth_low_locked = 8;
    uint16_t deauth_med_locked = 25;
    uint16_t deauth_high_locked = 60;
    uint16_t deauth_low_hop = 3;
    uint16_t deauth_med_hop = 8;
    uint16_t deauth_high_hop = 20;

    uint16_t beacon_unique_info = 20;
    uint16_t beacon_unique_low = 30;
    uint16_t beacon_unique_med = 60;
    uint16_t beacon_unique_high = 120;
    uint8_t beacon_once_pct = 70;

    uint8_t karma_low = 2;
    uint8_t karma_med = 4;
    uint8_t karma_high = 8;
    uint8_t karma_unbeaconed_min = 3;

    uint16_t ble_ads_info = 15;
    uint16_t ble_ads_low = 8;
    uint16_t ble_ads_med = 20;
    uint16_t ble_ads_high = 40;
    uint8_t ble_addrs_low = 3;
    uint8_t ble_addrs_med = 5;
    uint8_t ble_addrs_high = 8;
    // Same idea as beacon_once_pct: a flood is addresses heard once.
    // Repeating addresses are a crowd, not a spam burst.
    uint8_t ble_once_pct = 70;

    uint8_t hid_new_low = 1;
    uint8_t hid_new_med = 4;

    uint8_t tracker_checkpoints_med = 2;
    uint8_t tracker_checkpoints_high = 3;
    uint32_t tracker_persist_ms = 10u * 60u * 1000u;
};

struct BeaconStats {
    uint16_t unique_ssids;
    uint16_t once_only;
};

struct KarmaInput {
    bool saw_beacon;
    bool beacon_hidden;
    uint8_t distinct_probe_ssids;
    uint8_t probe_ssids_other; // probe names that differ from a non-empty beacon name
};

struct BleMarks {
    uint8_t spam_mask;
    TrackerFamily tracker;
    bool hid;
};

struct LogIdentity {
    const char *board;
    const char *firmware;
    const char *git;
};

Severity score_deauth(uint16_t frames_per_second, bool channel_locked, Thresholds t = Thresholds());
Severity score_beacon_flood(BeaconStats stats, Thresholds t = Thresholds());
Severity score_evil_twin(uint8_t bssid_count, bool known_security_differs, bool open_versus_encrypted);
Severity score_karma(KarmaInput in, Thresholds t = Thresholds());
// once_only is how many of unique_addrs were heard a single time in the window.
Severity score_ble_spam(
    uint16_t ads_per_second, uint8_t unique_addrs, uint8_t once_only, Thresholds t = Thresholds()
);
Severity score_new_hid(uint8_t new_hid_addresses, Thresholds t = Thresholds());
Severity score_tracker(uint8_t user_checkpoints, uint32_t duration_ms, Thresholds t = Thresholds());

const char *severity_name(Severity severity);
const char *kind_name(Kind kind);
const char *summary_for(Kind kind, Severity severity);
const char *explanation_for(Kind kind, Severity severity);
const char *security_name(WifiSecurity security);
const char *ble_family_name(uint8_t family_bit);
const char *tracker_family_name(TrackerFamily family);

// capability bit 0x0010 is the privacy bit. ies_truncated is true when the
// caller could not see the end of the information elements.
WifiSecurity
classify_wifi_security(uint16_t capability, const uint8_t *ies, size_t ie_len, bool ies_truncated);

// True when an SSID element is present, including a hidden (empty) SSID.
bool extract_ssid(const uint8_t *ies, size_t ie_len, char *ssid, size_t ssid_cap, uint8_t *out_len);

// Promiscuous sig_len counts the 4-byte frame check sequence. Tag walking must
// not treat those bytes as an information element.
size_t mgmt_len_without_fcs(uint16_t sig_len);

struct WifiTagParse {
    bool has_ssid;
    uint8_t ssid_len;
    char ssid[33];
    WifiSecurity security;
    bool truncated;
};

// frame_len is the management frame without the FCS. SSID and RSN are read
// from the whole tag list, not from a fixed prefix.
WifiTagParse parse_mgmt_tags(const uint8_t *frame, size_t frame_len);

// Among used slots whose checkpoint bits are 0, the one with the greatest
// age (now - first_ms). Returns -1 when every used slot is marked or none are used.
// HID slots pass bits of all zeros, so the oldest HID slot is eligible.
int oldest_unmarked_slot(
    const uint8_t *used, const uint8_t *bits, const uint32_t *first_ms, int count, uint32_t now
);

// Classify the first advertising-data bytes. Does not interpret identity fields.
BleMarks classify_ble_ad(const uint8_t *ad, size_t len);

int format_session_header(char *out, size_t cap, const LogIdentity &id);
int format_event_json(
    char *out, size_t cap, uint32_t t_ms, const char *wall, Kind kind, Severity severity, const char *summary,
    const char *detail, uint32_t drops
);

} // namespace sentinel
