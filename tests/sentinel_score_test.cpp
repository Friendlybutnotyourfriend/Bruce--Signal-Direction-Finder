#include "sentinel_score.h"

#include <stdio.h>
#include <string.h>

static int g_fails = 0;

static void expect(bool cond, const char *expr, int line) {
    if (cond) return;
    fprintf(stderr, "FAIL %s:%d %s\n", "sentinel_score_test.cpp", line, expr);
    g_fails++;
}

#define EXPECT(c) expect((c), #c, __LINE__)

static bool has_ci(const char *hay, const char *needle) {
    if (hay == nullptr || needle == nullptr) return false;
    size_t n = strlen(needle);
    if (n == 0) return true;
    for (size_t i = 0; hay[i] != '\0'; i++) {
        size_t j = 0;
        while (j < n) {
            char a = hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a == '\0' || a != b) break;
            j++;
        }
        if (j == n) return true;
    }
    return false;
}

static void expect_language(const char *text) {
    EXPECT(text != nullptr);
    EXPECT(!has_ci(text, "attacker identified"));
    EXPECT(!has_ci(text, "attacker"));
    EXPECT(!has_ci(text, "person identified"));
}

static uint8_t rsn_psk(uint8_t akm_type, uint8_t *out) {
    uint8_t ie[] = {48, 20, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
                    0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, akm_type, 0x00, 0x00};
    memcpy(out, ie, sizeof(ie));
    return (uint8_t)sizeof(ie);
}

int main() {
    using namespace sentinel;

    EXPECT(score_deauth(0, true) == Severity::None);
    EXPECT(score_deauth(7, true) == Severity::None);
    EXPECT(score_deauth(8, true) == Severity::Low);
    EXPECT(score_deauth(25, true) == Severity::Medium);
    EXPECT(score_deauth(60, true) == Severity::High);
    EXPECT(score_deauth(7, false) == Severity::Low);
    EXPECT(score_deauth(2, false) == Severity::None);
    EXPECT(score_deauth(8, false) == Severity::Medium);
    EXPECT(score_deauth(20, false) == Severity::High);
    EXPECT(score_deauth(19, false) == Severity::Medium);

    BeaconStats busy;
    busy.unique_ssids = 40;
    busy.once_only = 4;
    EXPECT(score_beacon_flood(busy) == Severity::Info);

    BeaconStats quiet;
    quiet.unique_ssids = 10;
    quiet.once_only = 10;
    EXPECT(score_beacon_flood(quiet) == Severity::None);

    BeaconStats low_flood;
    low_flood.unique_ssids = 40;
    low_flood.once_only = 35;
    EXPECT(score_beacon_flood(low_flood) == Severity::Low);

    BeaconStats med_flood;
    med_flood.unique_ssids = 80;
    med_flood.once_only = 70;
    EXPECT(score_beacon_flood(med_flood) == Severity::Medium);

    BeaconStats high_flood;
    high_flood.unique_ssids = 130;
    high_flood.once_only = 120;
    EXPECT(score_beacon_flood(high_flood) == Severity::High);

    BeaconStats repeating_crowd;
    repeating_crowd.unique_ssids = 130;
    repeating_crowd.once_only = 10;
    EXPECT(score_beacon_flood(repeating_crowd) == Severity::Info);

    EXPECT(score_evil_twin(1, true, true) == Severity::None);
    EXPECT(score_evil_twin(2, false, false) == Severity::Info);
    EXPECT(score_evil_twin(3, true, false) == Severity::Medium);
    EXPECT(score_evil_twin(2, true, true) == Severity::High);

    KarmaInput own_name = {true, false, 1, 0};
    EXPECT(score_karma(own_name) == Severity::None);

    KarmaInput hidden_one = {true, true, 1, 1};
    EXPECT(score_karma(hidden_one) == Severity::None);

    KarmaInput hidden_many = {true, true, 5, 5};
    EXPECT(score_karma(hidden_many) == Severity::Medium);

    KarmaInput extras = {true, false, 3, 2};
    EXPECT(score_karma(extras) == Severity::Low);

    KarmaInput no_beacon_two = {false, false, 2, 2};
    EXPECT(score_karma(no_beacon_two) == Severity::None);

    KarmaInput no_beacon_many = {false, false, 8, 8};
    EXPECT(score_karma(no_beacon_many) == Severity::High);

    // Third argument is addresses heard once. These cases are one-shot addresses.
    EXPECT(score_ble_spam(50, 1, 1) == Severity::Info);
    EXPECT(score_ble_spam(50, 2, 2) == Severity::Info);
    EXPECT(score_ble_spam(8, 3, 3) == Severity::Low);
    EXPECT(score_ble_spam(20, 5, 5) == Severity::Medium);
    EXPECT(score_ble_spam(40, 8, 8) == Severity::High);
    EXPECT(score_ble_spam(7, 10, 10) == Severity::None);
    EXPECT(score_ble_spam(40, 4, 4) == Severity::Low);
    // Eight phones repeating Nearby Info is a crowd, not a flood.
    EXPECT(score_ble_spam(50, 8, 0) == Severity::Info);
    EXPECT(score_ble_spam(40, 8, 2) == Severity::Info);
    EXPECT(score_ble_spam(40, 8, 6) == Severity::High);
    EXPECT(score_ble_spam(10, 8, 0) == Severity::None);

    EXPECT(score_new_hid(0) == Severity::None);
    EXPECT(score_new_hid(1) == Severity::Low);
    EXPECT(score_new_hid(4) == Severity::Medium);

    EXPECT(score_tracker(0, 1000) == Severity::None);
    EXPECT(score_tracker(1, 1000) == Severity::None);
    EXPECT(score_tracker(1, 10u * 60u * 1000u) == Severity::Low);
    EXPECT(score_tracker(2, 1000) == Severity::Medium);
    EXPECT(score_tracker(3, 1000) == Severity::High);

    uint8_t ie[32];
    uint8_t n = rsn_psk(2, ie);
    EXPECT(classify_wifi_security(0x0011, ie, n, false) == WifiSecurity::Wpa2);
    n = rsn_psk(8, ie);
    EXPECT(classify_wifi_security(0x0011, ie, n, false) == WifiSecurity::Wpa3);
    EXPECT(classify_wifi_security(0x0001, nullptr, 0, false) == WifiSecurity::Open);
    EXPECT(classify_wifi_security(0x0011, nullptr, 0, false) == WifiSecurity::Wep);
    EXPECT(classify_wifi_security(0x0011, nullptr, 0, true) == WifiSecurity::Unknown);

    uint8_t wpa_ie[] = {221, 4, 0x00, 0x50, 0xf2, 0x01};
    EXPECT(classify_wifi_security(0x0011, wpa_ie, sizeof(wpa_ie), false) == WifiSecurity::Wpa);

    uint8_t ssid_ie[] = {0, 4, 'C', 'a', 'f', 'e', 1, 1, 0x82};
    char ssid[33];
    uint8_t ssid_len = 99;
    EXPECT(extract_ssid(ssid_ie, sizeof(ssid_ie), ssid, sizeof(ssid), &ssid_len));
    EXPECT(ssid_len == 4);
    EXPECT(strcmp(ssid, "Cafe") == 0);
    uint8_t hidden[] = {0, 0};
    EXPECT(extract_ssid(hidden, sizeof(hidden), ssid, sizeof(ssid), &ssid_len));
    EXPECT(ssid_len == 0);

    uint8_t apple[] = {0x05, 0xff, 0x4c, 0x00, 0x07, 0x19};
    BleMarks apple_marks = classify_ble_ad(apple, sizeof(apple));
    EXPECT(apple_marks.spam_mask & AppleContinuity);
    EXPECT(apple_marks.tracker == TrackerFamily::None);

    uint8_t findmy[] = {0x05, 0xff, 0x4c, 0x00, 0x12, 0x19};
    BleMarks find_marks = classify_ble_ad(findmy, sizeof(findmy));
    EXPECT(find_marks.tracker == TrackerFamily::AppleFindMy);
    EXPECT(find_marks.spam_mask == BleNone);

    uint8_t fast[] = {0x06, 0x16, 0x2c, 0xfe, 0x00, 0x01, 0xf0};
    BleMarks fast_marks = classify_ble_ad(fast, sizeof(fast));
    EXPECT(fast_marks.spam_mask & FastPair);
    EXPECT(fast_marks.tracker == TrackerFamily::None);

    uint8_t fmdn[] = {0x08, 0x16, 0x2c, 0xfe, 0x40, 0x01, 0x02, 0x03, 0x04};
    BleMarks fmdn_marks = classify_ble_ad(fmdn, sizeof(fmdn));
    EXPECT(fmdn_marks.tracker == TrackerFamily::GoogleFindMyDevice);
    EXPECT((fmdn_marks.spam_mask & FastPair) == 0);

    uint8_t swift[] = {0x07, 0xff, 0x06, 0x00, 0x03, 0x00, 0x80, 'A'};
    EXPECT(classify_ble_ad(swift, sizeof(swift)).spam_mask & SwiftPair);
    uint8_t ms_other[] = {0x04, 0xff, 0x06, 0x00, 0x01};
    EXPECT(classify_ble_ad(ms_other, sizeof(ms_other)).spam_mask == BleNone);

    uint8_t buds[] = {0x05, 0xff, 0x75, 0x00, 0x42, 0x09};
    EXPECT(classify_ble_ad(buds, sizeof(buds)).spam_mask & SamsungEasySetup);
    uint8_t samsung_other[] = {0x05, 0xff, 0x75, 0x00, 0x99, 0x00};
    EXPECT(classify_ble_ad(samsung_other, sizeof(samsung_other)).spam_mask == BleNone);

    uint8_t hid[] = {0x03, 0x03, 0x12, 0x18};
    BleMarks hid_marks = classify_ble_ad(hid, sizeof(hid));
    EXPECT(hid_marks.hid);
    EXPECT(!hid_marks.spam_mask);

    uint8_t tag[] = {0x03, 0x03, 0x5a, 0xfd};
    EXPECT(classify_ble_ad(tag, sizeof(tag)).tracker == TrackerFamily::SamsungSmartTag);
    uint8_t tile[] = {0x03, 0x03, 0xed, 0xfe};
    EXPECT(classify_ble_ad(tile, sizeof(tile)).tracker == TrackerFamily::Tile);

    uint8_t used[4] = {1, 1, 1, 0};
    uint8_t bits[4] = {0, 1, 0, 0};
    uint32_t first_ms[4] = {100, 1, 400, 0};
    EXPECT(oldest_unmarked_slot(used, bits, first_ms, 4, 1000) == 0);
    bits[0] = 1;
    EXPECT(oldest_unmarked_slot(used, bits, first_ms, 4, 1000) == 2);
    bits[2] = 3;
    EXPECT(oldest_unmarked_slot(used, bits, first_ms, 4, 1000) == -1);
    uint8_t hid_used[3] = {1, 1, 1};
    uint8_t hid_bits[3] = {0, 0, 0};
    uint32_t hid_first[3] = {50, 20, 80};
    EXPECT(oldest_unmarked_slot(hid_used, hid_bits, hid_first, 3, 100) == 1);
    EXPECT(oldest_unmarked_slot(nullptr, hid_bits, hid_first, 3, 100) == -1);

    EXPECT(mgmt_len_without_fcs(40) == 36);
    EXPECT(mgmt_len_without_fcs(3) == 3);
    uint8_t short_frame[40];
    memset(short_frame, 0, sizeof(short_frame));
    short_frame[0] = 0x80;
    short_frame[34] = 0x01;
    short_frame[36] = 0;
    short_frame[37] = 2;
    short_frame[38] = 'F';
    short_frame[39] = 'A';
    WifiTagParse fcs_kept = parse_mgmt_tags(short_frame, 40);
    EXPECT(fcs_kept.has_ssid);
    EXPECT(fcs_kept.ssid_len == 2);
    EXPECT(strcmp(fcs_kept.ssid, "FA") == 0);
    WifiTagParse fcs_dropped = parse_mgmt_tags(short_frame, mgmt_len_without_fcs(40));
    EXPECT(!fcs_dropped.has_ssid);
    EXPECT(fcs_dropped.ssid_len == 0);

    uint8_t beacon[160];
    memset(beacon, 0, sizeof(beacon));
    beacon[0] = 0x80;
    beacon[34] = 0x11;
    beacon[35] = 0x00;
    size_t at = 36;
    beacon[at++] = 0;
    beacon[at++] = 32;
    memset(beacon + at, 'A', 32);
    at += 32;
    beacon[at++] = 7;
    beacon[at++] = 6;
    memcpy(beacon + at, "US ", 3);
    beacon[at + 3] = 1;
    beacon[at + 4] = 11;
    beacon[at + 5] = 20;
    at += 6;
    beacon[at++] = 1;
    beacon[at++] = 26;
    at += 26;
    uint8_t rsn[32];
    uint8_t rsn_n = rsn_psk(2, rsn);
    EXPECT(at == 36 + 70);
    memcpy(beacon + at, rsn, rsn_n);
    at += rsn_n;
    WifiTagParse full = parse_mgmt_tags(beacon, at);
    EXPECT(full.has_ssid);
    EXPECT(full.ssid_len == 32);
    EXPECT(strcmp(full.ssid, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0);
    EXPECT(full.security == WifiSecurity::Wpa2);
    EXPECT(!full.truncated);
    const uint8_t *ies = beacon + 36;
    EXPECT(classify_wifi_security(0x0011, ies, 80, false) == WifiSecurity::Unknown ||
           classify_wifi_security(0x0011, ies, 80, true) == WifiSecurity::Unknown);
    EXPECT(classify_wifi_security(0x0011, ies, 80, true) == WifiSecurity::Unknown);

    for (int k = 0; k < (int)Kind::Count; k++) {
        for (int s = 0; s <= (int)Severity::High; s++) {
            expect_language(summary_for((Kind)k, (Severity)s));
            expect_language(explanation_for((Kind)k, (Severity)s));
            if ((Severity)s == Severity::None) EXPECT(explanation_for((Kind)k, (Severity)s)[0] == '\0');
            else EXPECT(explanation_for((Kind)k, (Severity)s)[0] != '\0');
        }
    }

    LogIdentity id;
    id.board = "M5Stack Cardputer";
    id.firmware = "1.16.1";
    id.git = "test";
    char header[1600];
    int hn = format_session_header(header, sizeof(header), id);
    EXPECT(hn > 0);
    EXPECT(strstr(header, "sentinel-session 1") != nullptr);
    EXPECT(strstr(header, "M5Stack Cardputer") != nullptr);
    EXPECT(strstr(header, "1.16.1") != nullptr);
    EXPECT(strstr(header, "does not identify an attacker") != nullptr);
    EXPECT(!has_ci(header, "attacker identified"));
    EXPECT(strstr(header, "beacon_flood") != nullptr);
    EXPECT(strstr(header, "karma_probe") != nullptr);
    EXPECT(strstr(header, "hid_gatt") != nullptr);

    char line[512];
    int ln = format_event_json(
        line,
        sizeof(line),
        1234,
        "2026-08-11T12:00:00",
        Kind::Deauth,
        Severity::High,
        "Deauth/disassoc rate",
        "bssid=AA:BB:CC:DD:EE:FF observed=60/s",
        2
    );
    EXPECT(ln > 0);
    EXPECT(line[ln - 1] == '\n');
    EXPECT(strstr(line, "\"t_ms\":1234") != nullptr);
    EXPECT(strstr(line, "\"kind\":\"deauth\"") != nullptr);
    EXPECT(strstr(line, "\"severity\":\"high\"") != nullptr);
    EXPECT(strstr(line, "\"drops\":2") != nullptr);
    EXPECT(strstr(line, "payload") == nullptr);
    EXPECT(!has_ci(line, "attacker"));

    ln = format_event_json(line, sizeof(line), 1, "", Kind::Note, Severity::Info, "say \"hi\"", "a\\b", 0);
    EXPECT(ln > 0);
    EXPECT(strstr(line, "say \\\"hi\\\"") != nullptr);
    EXPECT(strstr(line, "a\\\\b") != nullptr);

    char tiny[8];
    EXPECT(format_event_json(tiny, sizeof(tiny), 1, "", Kind::Note, Severity::Info, "x", "y", 0) < 0);

    if (g_fails == 0) {
        printf("sentinel score tests passed\n");
        return 0;
    }
    fprintf(stderr, "%d failure(s)\n", g_fails);
    return 1;
}
