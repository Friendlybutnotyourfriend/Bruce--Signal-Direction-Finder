#include "sentinel_score.h"

#include <stdio.h>
#include <string.h>

namespace sentinel {
namespace {

bool append_text(char *out, size_t cap, size_t *used, const char *text) {
    if (text == nullptr) text = "";
    size_t n = strlen(text);
    if (*used + n + 1 > cap) return false;
    memcpy(out + *used, text, n);
    *used += n;
    out[*used] = '\0';
    return true;
}

bool append_json_string(char *out, size_t cap, size_t *used, const char *text) {
    if (text == nullptr) text = "";
    if (!append_text(out, cap, used, "\"")) return false;
    for (size_t i = 0; text[i] != '\0'; i++) {
        unsigned char c = (unsigned char)text[i];
        char tmp[8];
        const char *piece = tmp;
        if (c == '"' || c == '\\') {
            tmp[0] = '\\';
            tmp[1] = (char)c;
            tmp[2] = '\0';
        } else if (c < 0x20 || c > 0x7e) {
            tmp[0] = '?';
            tmp[1] = '\0';
        } else {
            tmp[0] = (char)c;
            tmp[1] = '\0';
        }
        if (!append_text(out, cap, used, piece)) return false;
    }
    return append_text(out, cap, used, "\"");
}

void note_akm(uint8_t suite_type, bool *psk, bool *sae, bool *owe) {
    if (suite_type == 2 || suite_type == 6) *psk = true;
    if (suite_type == 8 || suite_type == 9) *sae = true;
    if (suite_type == 18) *owe = true;
}

void parse_rsn_akm(const uint8_t *body, uint8_t len, bool *psk, bool *sae, bool *owe) {
    if (len < 8) return;
    size_t off = 2 + 4; // version + group cipher
    if (off + 2 > len) return;
    uint16_t pair_count = (uint16_t)body[off] | ((uint16_t)body[off + 1] << 8);
    off += 2;
    if (pair_count > 8) return;
    if (off + (size_t)pair_count * 4 > len) return;
    off += (size_t)pair_count * 4;
    if (off + 2 > len) return;
    uint16_t akm_count = (uint16_t)body[off] | ((uint16_t)body[off + 1] << 8);
    off += 2;
    if (akm_count > 8) return;
    for (uint16_t i = 0; i < akm_count; i++) {
        if (off + 4 > len) return;
        const uint8_t *suite = body + off;
        off += 4;
        if (suite[0] == 0x00 && suite[1] == 0x0f && suite[2] == 0xac) note_akm(suite[3], psk, sae, owe);
    }
}

bool uuid16_is(const uint8_t *p, uint16_t uuid) {
    return p[0] == (uint8_t)(uuid & 0xff) && p[1] == (uint8_t)(uuid >> 8);
}

} // namespace

Severity score_deauth(uint16_t frames_per_second, bool channel_locked, Thresholds t) {
    uint16_t low = channel_locked ? t.deauth_low_locked : t.deauth_low_hop;
    uint16_t med = channel_locked ? t.deauth_med_locked : t.deauth_med_hop;
    uint16_t high = channel_locked ? t.deauth_high_locked : t.deauth_high_hop;
    if (frames_per_second >= high) return Severity::High;
    if (frames_per_second >= med) return Severity::Medium;
    if (frames_per_second >= low) return Severity::Low;
    return Severity::None;
}

Severity score_beacon_flood(BeaconStats stats, Thresholds t) {
    if (stats.unique_ssids == 0) return Severity::None;
    uint16_t once = stats.once_only;
    if (once > stats.unique_ssids) once = stats.unique_ssids;
    uint16_t once_pct = (uint16_t)((once * 100u) / stats.unique_ssids);
    bool flood_shape = once_pct >= t.beacon_once_pct;
    if (!flood_shape) {
        if (stats.unique_ssids >= t.beacon_unique_info) return Severity::Info;
        return Severity::None;
    }
    if (stats.unique_ssids >= t.beacon_unique_high) return Severity::High;
    if (stats.unique_ssids >= t.beacon_unique_med) return Severity::Medium;
    if (stats.unique_ssids >= t.beacon_unique_low) return Severity::Low;
    if (stats.unique_ssids >= t.beacon_unique_info) return Severity::Info;
    return Severity::None;
}

Severity score_evil_twin(uint8_t bssid_count, bool known_security_differs, bool open_versus_encrypted) {
    if (bssid_count < 2) return Severity::None;
    if (open_versus_encrypted) return Severity::High;
    if (known_security_differs) return Severity::Medium;
    return Severity::Info;
}

Severity score_karma(KarmaInput in, Thresholds t) {
    uint8_t extras = 0;
    if (in.saw_beacon && !in.beacon_hidden) {
        extras = in.probe_ssids_other;
    } else if (in.saw_beacon && in.beacon_hidden) {
        extras = in.distinct_probe_ssids > 0 ? (uint8_t)(in.distinct_probe_ssids - 1) : 0;
    } else if (in.distinct_probe_ssids >= t.karma_unbeaconed_min) {
        extras = in.distinct_probe_ssids;
    }
    if (extras >= t.karma_high) return Severity::High;
    if (extras >= t.karma_med) return Severity::Medium;
    if (extras >= t.karma_low) return Severity::Low;
    return Severity::None;
}

Severity score_ble_spam(uint16_t ads_per_second, uint8_t unique_addrs, uint8_t once_only, Thresholds t) {
    if (unique_addrs == 0) return Severity::None;
    if (once_only > unique_addrs) once_only = unique_addrs;
    uint16_t once_pct = (uint16_t)((once_only * 100u) / unique_addrs);
    bool spam_shape = once_pct >= t.ble_once_pct;
    if (!spam_shape) {
        if (ads_per_second >= t.ble_ads_info) return Severity::Info;
        return Severity::None;
    }
    if (unique_addrs >= t.ble_addrs_high && ads_per_second >= t.ble_ads_high) return Severity::High;
    if (unique_addrs >= t.ble_addrs_med && ads_per_second >= t.ble_ads_med) return Severity::Medium;
    if (unique_addrs >= t.ble_addrs_low && ads_per_second >= t.ble_ads_low) return Severity::Low;
    if (unique_addrs < t.ble_addrs_low && ads_per_second >= t.ble_ads_info) return Severity::Info;
    return Severity::None;
}

Severity score_new_hid(uint8_t new_hid_addresses, Thresholds t) {
    if (new_hid_addresses >= t.hid_new_med) return Severity::Medium;
    if (new_hid_addresses >= t.hid_new_low) return Severity::Low;
    return Severity::None;
}

Severity score_tracker(uint8_t user_checkpoints, uint32_t duration_ms, Thresholds t) {
    if (user_checkpoints >= t.tracker_checkpoints_high) return Severity::High;
    if (user_checkpoints >= t.tracker_checkpoints_med) return Severity::Medium;
    if (duration_ms >= t.tracker_persist_ms) return Severity::Low;
    return Severity::None;
}

const char *severity_name(Severity severity) {
    switch (severity) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::None: break;
    }
    return "none";
}

const char *kind_name(Kind kind) {
    switch (kind) {
        case Kind::Deauth: return "deauth";
        case Kind::BeaconFlood: return "beacon_flood";
        case Kind::EvilTwin: return "evil_twin";
        case Kind::KarmaProbe: return "karma_probe";
        case Kind::BleSpam: return "ble_spam";
        case Kind::HidGatt: return "hid_gatt";
        case Kind::Tracker: return "tracker";
        case Kind::Note: return "note";
        case Kind::Count: break;
    }
    return "note";
}

const char *summary_for(Kind kind, Severity severity) {
    switch (kind) {
        case Kind::Deauth: return "Deauth/disassoc rate";
        case Kind::BeaconFlood:
            return severity == Severity::Info ? "Busy air, names repeating" : "Beacon flood pattern";
        case Kind::EvilTwin: return "Same name, different access point";
        case Kind::KarmaProbe: return "Karma-style probe responses";
        case Kind::BleSpam:
            return severity == Severity::Info ? "Elevated popup-family traffic" : "Advertisement spam family";
        case Kind::HidGatt: return "New HID-over-GATT advertisement";
        case Kind::Tracker: return "Tracker-family sightings";
        case Kind::Note: return "Session note";
        case Kind::Count: break;
    }
    return "Sentinel note";
}

const char *explanation_for(Kind kind, Severity severity) {
    if (severity == Severity::None) return "";
    switch (kind) {
        case Kind::Deauth:
            return "Deauthentication or disassociation frames naming one access point were elevated. "
                   "The count is only what this radio heard on the channel it was tuned to. "
                   "Rate uses time enabled on that channel, not unseen airtime. Sentinel did not send these frames.";
        case Kind::BeaconFlood:
            if (severity == Severity::Info) {
                return "Many network names were repeating. That looks like a busy place, not a one-shot "
                       "beacon flood.";
            }
            return "Many network names were heard only once in a second. Ordinary access points repeat "
                   "their name. This is a beacon-flood pattern, not an identification.";
        case Kind::EvilTwin:
            if (severity == Severity::High) {
                return "The same network name was advertised as open and as encrypted. That pattern is "
                       "seen with evil-twin setups and with captive portals. It does not say who is "
                       "transmitting.";
            }
            if (severity == Severity::Medium) {
                return "The same network name was advertised with more than one security class. This is "
                       "a pattern, not an identification.";
            }
            return "The same network name was heard from more than one access point. A normal multi-AP "
                   "network does this too. This is a pattern, not an identification.";
        case Kind::KarmaProbe:
            return "One access point answered for several different network names. That is a karma-style "
                   "pattern. Some devices do this without being a portal. Sentinel did not answer any "
                   "probe.";
        case Kind::BleSpam:
            if (severity == Severity::Info) {
                return "Elevated popup-family traffic, with repeated or few addresses. Ordinary phones "
                       "and repeated-address floods can both do this. Rate alone cannot distinguish them.";
            }
            return "Elevated advertisements from a known popup family (Apple continuity, Fast Pair, Swift "
                   "Pair, or Samsung EasySetup) came from several addresses that were each heard once. "
                   "Family evidence only, not a device identity.";
        case Kind::HidGatt:
            return "A new address advertised the HID-over-GATT service. Keyboards, mice, and BadBLE-style "
                   "devices all advertise this service. Sentinel did not connect.";
        case Kind::Tracker:
            return "Tracker-family advertisement seen over time or across marked checkpoints. This does "
                   "not establish ownership or that anyone is following you. Rotating addresses may be missed.";
        case Kind::Note: return "Session bookkeeping. No radio pattern is claimed by this line.";
        case Kind::Count: break;
    }
    return "";
}

const char *security_name(WifiSecurity security) {
    switch (security) {
        case WifiSecurity::Open: return "open";
        case WifiSecurity::Wep: return "wep";
        case WifiSecurity::Wpa: return "wpa";
        case WifiSecurity::Wpa2: return "wpa2";
        case WifiSecurity::Wpa3: return "wpa3";
        case WifiSecurity::Mixed: return "mixed";
        case WifiSecurity::Unknown: break;
    }
    return "unknown";
}

const char *ble_family_name(uint8_t family_bit) {
    if (family_bit & AppleContinuity) return "apple_continuity";
    if (family_bit & FastPair) return "fast_pair";
    if (family_bit & SwiftPair) return "swift_pair";
    if (family_bit & SamsungEasySetup) return "samsung_easysetup";
    return "none";
}

const char *tracker_family_name(TrackerFamily family) {
    switch (family) {
        case TrackerFamily::AppleFindMy: return "apple_findmy";
        case TrackerFamily::SamsungSmartTag: return "samsung_smarttag";
        case TrackerFamily::Tile: return "tile";
        case TrackerFamily::GoogleFindMyDevice: return "google_findmy_device";
        case TrackerFamily::None: break;
    }
    return "none";
}

WifiSecurity
classify_wifi_security(uint16_t capability, const uint8_t *ies, size_t ie_len, bool ies_truncated) {
    const bool privacy = (capability & 0x0010) != 0;
    bool saw_wpa = false;
    bool saw_rsn = false;
    bool saw_psk = false;
    bool saw_sae = false;
    bool saw_owe = false;
    bool truncated = ies_truncated;
    const uint8_t *p = ies;
    const uint8_t *end = (ies == nullptr) ? nullptr : ies + ie_len;

    while (p != nullptr && p + 2 <= end) {
        uint8_t id = p[0];
        uint8_t len = p[1];
        if (p + 2 + len > end) {
            truncated = true;
            break;
        }
        const uint8_t *body = p + 2;
        if (id == 48) {
            saw_rsn = true;
            parse_rsn_akm(body, len, &saw_psk, &saw_sae, &saw_owe);
        } else if (id == 221 && len >= 4 && body[0] == 0x00 && body[1] == 0x50 && body[2] == 0xf2 &&
                   body[3] == 0x01) {
            saw_wpa = true;
        }
        p += 2 + len;
    }

    if (saw_sae && saw_psk) return WifiSecurity::Mixed;
    if (saw_owe || saw_sae) return WifiSecurity::Wpa3;
    if (saw_rsn && saw_wpa) return WifiSecurity::Mixed;
    if (saw_rsn) return WifiSecurity::Wpa2;
    if (saw_wpa) return WifiSecurity::Wpa;
    if (privacy && truncated) return WifiSecurity::Unknown;
    if (privacy) return WifiSecurity::Wep;
    return WifiSecurity::Open;
}

size_t mgmt_len_without_fcs(uint16_t sig_len) {
    if (sig_len >= 4) return (size_t)sig_len - 4;
    return sig_len;
}

WifiTagParse parse_mgmt_tags(const uint8_t *frame, size_t frame_len) {
    WifiTagParse parsed;
    memset(&parsed, 0, sizeof(parsed));
    parsed.security = WifiSecurity::Unknown;
    if (frame == nullptr || frame_len < 36) return parsed;
    uint16_t capability = (uint16_t)frame[34] | ((uint16_t)frame[35] << 8);
    const uint8_t *ies = frame + 36;
    size_t ie_len = frame_len - 36;
    uint8_t ssid_len = 0;
    parsed.has_ssid = extract_ssid(ies, ie_len, parsed.ssid, sizeof(parsed.ssid), &ssid_len);
    parsed.ssid_len = ssid_len;
    bool truncated = false;
    const uint8_t *p = ies;
    const uint8_t *end = ies + ie_len;
    while (p < end) {
        if (p + 2 > end) {
            truncated = true;
            break;
        }
        uint8_t len = p[1];
        if (p + 2 + (size_t)len > end) {
            truncated = true;
            break;
        }
        p += 2 + (size_t)len;
    }
    parsed.truncated = truncated;
    parsed.security = classify_wifi_security(capability, ies, ie_len, truncated);
    return parsed;
}

int oldest_unmarked_slot(
    const uint8_t *used, const uint8_t *bits, const uint32_t *first_ms, int count, uint32_t now
) {
    if (used == nullptr || bits == nullptr || first_ms == nullptr || count <= 0) return -1;
    int best = -1;
    uint32_t best_age = 0;
    for (int i = 0; i < count; i++) {
        if (!used[i] || bits[i] != 0) continue;
        uint32_t age = now - first_ms[i];
        if (best < 0 || age > best_age) {
            best = i;
            best_age = age;
        }
    }
    return best;
}

bool extract_ssid(const uint8_t *ies, size_t ie_len, char *ssid, size_t ssid_cap, uint8_t *out_len) {
    if (out_len != nullptr) *out_len = 0;
    if (ssid != nullptr && ssid_cap > 0) ssid[0] = '\0';
    if (ies == nullptr || ssid == nullptr || ssid_cap < 2) return false;
    const uint8_t *p = ies;
    const uint8_t *end = ies + ie_len;
    while (p + 2 <= end) {
        uint8_t id = p[0];
        uint8_t len = p[1];
        if (p + 2 + len > end) return false;
        if (id == 0) {
            uint8_t n = len > 32 ? 32 : len;
            if ((size_t)n + 1 > ssid_cap) n = (uint8_t)(ssid_cap - 1);
            memcpy(ssid, p + 2, n);
            ssid[n] = '\0';
            if (out_len != nullptr) *out_len = n;
            return true;
        }
        p += 2 + (size_t)len;
    }
    return false;
}

BleMarks classify_ble_ad(const uint8_t *ad, size_t len) {
    BleMarks marks;
    marks.spam_mask = BleNone;
    marks.tracker = TrackerFamily::None;
    marks.hid = false;
    if (ad == nullptr) return marks;

    size_t i = 0;
    while (i + 1 < len) {
        uint8_t field_len = ad[i];
        if (field_len == 0) break;
        if (i + 1 + field_len > len) break;
        uint8_t type = ad[i + 1];
        const uint8_t *data = ad + i + 2;
        uint8_t data_len = (uint8_t)(field_len - 1);

        if ((type == 0x02 || type == 0x03) && data_len >= 2) {
            for (uint8_t u = 0; u + 1 < data_len; u = (uint8_t)(u + 2)) {
                if (uuid16_is(data + u, 0x1812)) marks.hid = true;
                if (uuid16_is(data + u, 0xfd5a)) marks.tracker = TrackerFamily::SamsungSmartTag;
                if (uuid16_is(data + u, 0xfeed)) marks.tracker = TrackerFamily::Tile;
            }
        } else if (type == 0x16 && data_len >= 2 && uuid16_is(data, 0xfe2c)) {
            const uint8_t *payload = data + 2;
            uint8_t payload_len = (uint8_t)(data_len - 2);
            // Find My Device Network advertisements use frame type 0x40 and are
            // longer than the 3-byte model-id popup. A 3-byte model id is the
            // Fast Pair popup shape, also used by real accessories.
            if (payload_len >= 4 && payload[0] == 0x40) {
                marks.tracker = TrackerFamily::GoogleFindMyDevice;
            } else if (payload_len >= 3) {
                marks.spam_mask = (uint8_t)(marks.spam_mask | FastPair);
            }
        } else if (type == 0xff && data_len >= 2) {
            uint16_t company = (uint16_t)data[0] | ((uint16_t)data[1] << 8);
            const uint8_t *payload = data + 2;
            uint8_t payload_len = (uint8_t)(data_len - 2);
            if (company == 0x004c && payload_len >= 1) {
                if (payload[0] == 0x12) marks.tracker = TrackerFamily::AppleFindMy;
                else if (payload[0] == 0x07 || payload[0] == 0x0f || payload[0] == 0x10)
                    marks.spam_mask = (uint8_t)(marks.spam_mask | AppleContinuity);
            } else if (company == 0x0006 && payload_len >= 3 && payload[0] == 0x03 && payload[1] == 0x00 &&
                       payload[2] == 0x80) {
                marks.spam_mask = (uint8_t)(marks.spam_mask | SwiftPair);
            } else if (company == 0x0075 && payload_len >= 1 && (payload[0] == 0x42 || payload[0] == 0x01)) {
                marks.spam_mask = (uint8_t)(marks.spam_mask | SamsungEasySetup);
            }
        }
        i += 1 + (size_t)field_len;
    }
    return marks;
}

int format_session_header(char *out, size_t cap, const LogIdentity &id) {
    if (out == nullptr || cap == 0) return -1;
    const char *board = id.board != nullptr ? id.board : "unknown";
    const char *firmware = id.firmware != nullptr ? id.firmware : "unknown";
    const char *git = id.git != nullptr ? id.git : "unknown";
    int n = snprintf(
        out,
        cap,
        "# sentinel-session 1\n"
        "# claim: pattern evidence for awareness and training. This file does not identify an attacker "
        "or a person.\n"
        "# board: %s\n"
        "# firmware: %s\n"
        "# git: %s\n"
        "# radio: 2.4 GHz. One channel and one radio mode at a time.\n"
        "# schema: jsonl. Lines starting with # are comments. Each other line is one JSON object.\n"
        "# fields: t_ms (millis since boot), wall (clock if set, else empty), kind, severity, summary, "
        "detail, drops.\n"
        "# kind: deauth | beacon_flood | evil_twin | karma_probe | ble_spam | hid_gatt | tracker | note\n"
        "# severity: info | low | medium | high\n"
        "# detail is bounded. Advertisement payloads and probe names are not stored.\n"
        "# drops counts frames the queue could not accept. Those frames were not scored.\n"
        "# caps: SSID hashes 128 per second, BSSID table 24, probe names 8 per BSSID, "
        "BLE addresses 24 per second, HID baseline 24, trackers 16, checkpoints 8, "
        "file 262144 bytes. SSID hashes stop at the cap. A full tracker table replaces the oldest "
        "slot that has no checkpoint mark; a marked tracker is kept. The HID table replaces its oldest "
        "slot. BLE spam severity needs addresses heard once; repeating addresses are busy air.\n",
        board,
        firmware,
        git
    );
    if (n < 0 || (size_t)n >= cap) return -1;
    return n;
}

int format_event_json(
    char *out, size_t cap, uint32_t t_ms, const char *wall, Kind kind, Severity severity, const char *summary,
    const char *detail, uint32_t drops
) {
    if (out == nullptr || cap == 0) return -1;
    char head[96];
    int hn = snprintf(
        head,
        sizeof(head),
        "{\"t_ms\":%lu,\"wall\":",
        (unsigned long)t_ms
    );
    if (hn < 0 || (size_t)hn >= sizeof(head)) return -1;
    size_t used = 0;
    out[0] = '\0';
    if (!append_text(out, cap, &used, head)) return -1;
    if (!append_json_string(out, cap, &used, wall)) return -1;
    char mid[96];
    int mn = snprintf(
        mid,
        sizeof(mid),
        ",\"kind\":\"%s\",\"severity\":\"%s\",\"summary\":",
        kind_name(kind),
        severity_name(severity)
    );
    if (mn < 0 || (size_t)mn >= sizeof(mid)) return -1;
    if (!append_text(out, cap, &used, mid)) return -1;
    if (!append_json_string(out, cap, &used, summary)) return -1;
    if (!append_text(out, cap, &used, ",\"detail\":")) return -1;
    if (!append_json_string(out, cap, &used, detail)) return -1;
    char tail[40];
    int tn = snprintf(tail, sizeof(tail), ",\"drops\":%lu}\n", (unsigned long)drops);
    if (tn < 0 || (size_t)tn >= sizeof(tail)) return -1;
    if (!append_text(out, cap, &used, tail)) return -1;
    return (int)used;
}

} // namespace sentinel
