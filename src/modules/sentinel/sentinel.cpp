#if !defined(LITE_VERSION)
// Sentinel: 2.4 GHz defensive detection. It listens and logs patterns.
// It does not transmit deauth, spam, exploits, or jamming.
//
// Wi-Fi promiscuous and NimBLE callbacks only enqueue a small note. The Wi-Fi
// callback parses SSID and RSN itself so a long beacon is not cut at 80 bytes.
// A worker task owns the tables and the score. The UI task draws and writes the
// SD log, because on many boards the display and the card share one SPI bus.

#include "sentinel.h"

#include "sentinel_score.h"

#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/radio_mem.h"
#include "core/scrollableTextArea.h"
#include "core/wifi/wifi_common.h"
#include "modules/ble/ble_common.h"
#include "modules/wifi/channel_analyzer.h"
#include "modules/wifi/jam_detect.h"

#include <NimBLEDevice.h>
#include <SD.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include "core/lazy_ram.h"
#include <nvs_flash.h>
#include <stdio.h>
#include <string.h>
#include <vector>

namespace {

constexpr size_t kMaxLogBytes = 262144;
constexpr int kBssidCap = 24;
constexpr int kGroupCap = 16;
constexpr int kBeaconCap = 128;
constexpr int kProbeCap = 8;
constexpr int kSpamCap = 24;
constexpr int kHidCap = 24;
constexpr int kTrackerCap = 16;
constexpr int kSavedCap = 12;
constexpr int kPendingCap = 8;
constexpr uint32_t kFreshMs = 60000;
constexpr uint32_t kTrackerHereMs = 30000;
constexpr uint32_t kMarkWindowMs = 120000;
constexpr uint32_t kBaselineMs = 20000;
constexpr uint32_t kWifiSliceMs = 8000;
constexpr uint32_t kBleSliceMs = 6000;
constexpr uint32_t kHopMs = 180;

enum class WatchMode : uint8_t { Wifi, Ble, Both };

struct WifiNote {
    uint8_t subtype;
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint8_t has_fixed;
    uint8_t has_ssid;
    uint8_t ssid_len;
    uint8_t ie_truncated;
    uint8_t security;
    uint16_t capability;
    char ssid[33];
};

struct BleNote {
    uint8_t addr[6];
    int8_t rssi;
    uint8_t ad_len;
    uint8_t ad[31];
};

struct BssidSlot {
    bool used;
    uint8_t bssid[6];
    char beacon_ssid[33];
    uint8_t beacon_ssid_len;
    bool saw_beacon;
    bool beacon_hidden;
    sentinel::WifiSecurity security;
    bool security_known;
    uint32_t probe_hash[kProbeCap];
    uint8_t probe_n;
    uint8_t probe_other;
    bool probe_capped;
    uint16_t deauth;
    uint32_t last_ms;
    uint8_t channel;
};

struct SsidGroup {
    bool used;
    uint32_t hash;
    char ssid[33];
    uint8_t ssid_len;
    uint8_t n;
    uint8_t bssid[4][6];
    sentinel::WifiSecurity sec[4];
    bool sec_known[4];
    uint32_t last_ms[4];
};

struct BeaconHit {
    uint32_t hash;
    uint8_t count;
};

struct SpamAddr {
    uint8_t addr[6];
    uint8_t mask;
    uint8_t hits;
};

struct HidSlot {
    bool used;
    uint8_t addr[6];
    bool baseline;
    bool counted;
    uint32_t first_ms;
};

struct TrackerSlot {
    bool used;
    uint8_t addr[6];
    sentinel::TrackerFamily family;
    uint32_t first_ms;
    uint32_t last_ms;
    uint8_t bits;
    sentinel::Severity last_sev;
};

struct Cool {
    bool used;
    sentinel::Kind kind;
    uint32_t key;
    sentinel::Severity sev;
    uint32_t last_ms;
};

struct Saved {
    uint32_t t_ms;
    sentinel::Kind kind;
    sentinel::Severity sev;
    char summary[72];
    char detail[96];
};

struct Live {
    sentinel::Severity sev;
    char summary[72];
    char explanation[240];
    char finding[3][72];
    uint8_t finding_n;
    uint16_t deauth_top;
    uint16_t beacon_unique;
    uint32_t wifi_drops;
    uint32_t ble_drops;
    uint8_t checkpoint;
    bool table_full;
    bool beacon_capped;
    bool baseline_done;
};

// Not static DRAM. See lazy_ram.h. Indexed like the old arrays via the
// reference helpers below, so sizeof(g_bssid) stays the full table.
static BssidSlot *mem_bssid = nullptr;
static SsidGroup *mem_group = nullptr;
static BeaconHit *mem_beacon = nullptr;
static Saved *mem_saved = nullptr;
static Saved *mem_pending = nullptr;
static Live *mem_live = nullptr;

static bool ensureSentinelRam() {
    if (mem_bssid && mem_group && mem_beacon && mem_saved && mem_pending && mem_live) return true;
    if (!lazyRamArray(mem_bssid, static_cast<size_t>(kBssidCap))) return false;
    if (!lazyRamArray(mem_group, static_cast<size_t>(kGroupCap))) return false;
    if (!lazyRamArray(mem_beacon, static_cast<size_t>(kBeaconCap))) return false;
    if (!lazyRamArray(mem_saved, static_cast<size_t>(kSavedCap))) return false;
    if (!lazyRamArray(mem_pending, static_cast<size_t>(kPendingCap))) return false;
    if (!lazyRam(mem_live)) return false;
    return true;
}

static BssidSlot (&bssidArr())[kBssidCap] {
    return *reinterpret_cast<BssidSlot (*)[kBssidCap]>(mem_bssid);
}
static SsidGroup (&groupArr())[kGroupCap] {
    return *reinterpret_cast<SsidGroup (*)[kGroupCap]>(mem_group);
}
static BeaconHit (&beaconArr())[kBeaconCap] {
    return *reinterpret_cast<BeaconHit (*)[kBeaconCap]>(mem_beacon);
}
static Saved (&savedArr())[kSavedCap] {
    return *reinterpret_cast<Saved (*)[kSavedCap]>(mem_saved);
}
static Saved (&pendingArr())[kPendingCap] {
    return *reinterpret_cast<Saved (*)[kPendingCap]>(mem_pending);
}
#define g_bssid bssidArr()
#define g_group groupArr()
#define g_beacon beaconArr()
#define g_saved savedArr()
#define g_pending pendingArr()
#define g_live (*mem_live)

int g_beacon_n = 0;
bool g_beacon_capped = false;
SpamAddr g_spam[kSpamCap];
uint8_t g_spam_n = 0;
uint16_t g_spam_ads[4] = {0, 0, 0, 0};
uint8_t g_spam_unique[4] = {0, 0, 0, 0};
HidSlot g_hid[kHidCap];
uint8_t g_hid_new = 0;
bool g_hid_full = false;
TrackerSlot g_track[kTrackerCap];
bool g_track_full = false;
Cool g_cool[16];
uint8_t g_saved_count = 0;
uint8_t g_saved_next = 0;
uint8_t g_pending_n = 0;
uint32_t g_window_start = 0;
uint32_t g_ble_listen_ms = 0;
bool g_baseline_done = false;
uint8_t g_checkpoint = 0;
uint32_t g_logged_drops = 0;

QueueHandle_t g_wifi_q = nullptr;
QueueHandle_t g_ble_q = nullptr;
SemaphoreHandle_t g_mu = nullptr;
TaskHandle_t g_worker_handle = nullptr;
volatile bool g_worker_run = false;
volatile bool g_wifi_capture = false;
volatile bool g_ble_capture = false;
volatile bool g_ble_active = false;
volatile bool g_reset_window = false;
volatile bool g_mark_checkpoint = false;
volatile bool g_locked = false;
volatile uint8_t g_ui_channel = 1;
volatile uint32_t g_wifi_drops = 0;
volatile uint32_t g_ble_drops = 0;

File g_log;
size_t g_log_bytes = 0;
bool g_log_capped = false;
bool g_sd_log = true;
char g_log_path[80] = {0};

const uint8_t kChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
const uint8_t kFamilyBit[] = {
    sentinel::AppleContinuity, sentinel::FastPair, sentinel::SwiftPair, sentinel::SamsungEasySetup
};

class SentinelScanCallbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *device) override {
        if (!g_ble_capture || device == nullptr || g_ble_q == nullptr) return;
        BleNote note;
        memset(&note, 0, sizeof(note));
        const uint8_t *addr = device->getAddress().getVal();
        if (addr != nullptr) memcpy(note.addr, addr, 6);
        note.rssi = device->getRSSI();
        const std::vector<uint8_t> &payload = device->getPayload();
        size_t n = payload.size();
        if (n > sizeof(note.ad)) n = sizeof(note.ad);
        if (n > 0) memcpy(note.ad, payload.data(), n);
        note.ad_len = (uint8_t)n;
        if (xQueueSend(g_ble_q, &note, 0) != pdTRUE) g_ble_drops = g_ble_drops + 1;
    }
};

SentinelScanCallbacks g_ble_cb;

uint32_t hash_bytes(const uint8_t *data, uint8_t len) {
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h == 0 ? 1u : h;
}

uint32_t hash_mac(const uint8_t *mac) { return hash_bytes(mac, 6); }

void fmt_mac(char *out, size_t n, const uint8_t *mac) {
    snprintf(
        out,
        n,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
}

void copy_sanitized(char *dst, size_t cap, const char *src, uint8_t len) {
    if (cap == 0) return;
    size_t n = len;
    if (n + 1 > cap) n = cap - 1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c >= 0x20 && c <= 0x7e) ? (char)c : '?';
    }
    dst[n] = '\0';
}

bool mac_eq(const uint8_t *a, const uint8_t *b) { return memcmp(a, b, 6) == 0; }

bool mac_zero(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0) return false;
    }
    return true;
}

uint8_t popcount(uint8_t v) {
    uint8_t n = 0;
    while (v) {
        n = (uint8_t)(n + (v & 1));
        v = (uint8_t)(v >> 1);
    }
    return n;
}

int sev_rank(sentinel::Severity sev) { return (int)sev; }

uint32_t g_latch_ms = 0;
bool g_raised_this_tick = false;

void latch(sentinel::Severity sev, sentinel::Kind kind) {
    if (sev == sentinel::Severity::None) return;
    uint32_t now = millis();
    if (sev_rank(sev) < sev_rank(g_live.sev) && (uint32_t)(now - g_latch_ms) < 5000) return;
    g_live.sev = sev;
    g_latch_ms = now;
    snprintf(g_live.summary, sizeof(g_live.summary), "%s", sentinel::summary_for(kind, sev));
    snprintf(g_live.explanation, sizeof(g_live.explanation), "%s", sentinel::explanation_for(kind, sev));
}

void remember(const Saved &item) {
    g_saved[g_saved_next] = item;
    g_saved_next = (uint8_t)((g_saved_next + 1) % kSavedCap);
    if (g_saved_count < kSavedCap) g_saved_count++;
    uint8_t shown = g_saved_count < 3 ? g_saved_count : 3;
    g_live.finding_n = shown;
    for (uint8_t i = 0; i < shown; i++) {
        uint8_t idx = (uint8_t)((g_saved_next + kSavedCap - 1 - i) % kSavedCap);
        snprintf(g_live.finding[i], sizeof(g_live.finding[i]), "%s", g_saved[idx].summary);
    }
}

void raise_finding(sentinel::Kind kind, sentinel::Severity sev, uint32_t key, const char *detail) {
    if (sev == sentinel::Severity::None) return;
    uint32_t now = millis();
    uint32_t cool_ms = 10000;
    if (sev == sentinel::Severity::Low) cool_ms = 60000;
    if (sev == sentinel::Severity::Info) cool_ms = 30000;
    if (kind == sentinel::Kind::Note) cool_ms = 5000;
    for (int i = 0; i < 16; i++) {
        if (!g_cool[i].used || g_cool[i].kind != kind || g_cool[i].key != key) continue;
        bool higher = sev_rank(sev) > sev_rank(g_cool[i].sev);
        if (!higher && (uint32_t)(now - g_cool[i].last_ms) < cool_ms) return;
        g_cool[i].sev = sev;
        g_cool[i].last_ms = now;
        goto store;
    }
    for (int i = 0; i < 16; i++) {
        if (g_cool[i].used) continue;
        g_cool[i].used = true;
        g_cool[i].kind = kind;
        g_cool[i].key = key;
        g_cool[i].sev = sev;
        g_cool[i].last_ms = now;
        break;
    }
store:
    Saved item;
    memset(&item, 0, sizeof(item));
    item.t_ms = now;
    item.kind = kind;
    item.sev = sev;
    snprintf(item.summary, sizeof(item.summary), "%s", sentinel::summary_for(kind, sev));
    snprintf(item.detail, sizeof(item.detail), "%s", detail != nullptr ? detail : "");
    remember(item);
    if (g_pending_n < kPendingCap) g_pending[g_pending_n++] = item;
    if (kind != sentinel::Kind::Note) {
        g_raised_this_tick = true;
        latch(sev, kind);
    }
}

BssidSlot *find_bssid(const uint8_t *mac, bool create) {
    for (int i = 0; i < kBssidCap; i++) {
        if (g_bssid[i].used && mac_eq(g_bssid[i].bssid, mac)) return &g_bssid[i];
    }
    if (!create) return nullptr;
    for (int i = 0; i < kBssidCap; i++) {
        if (g_bssid[i].used) continue;
        memset(&g_bssid[i], 0, sizeof(g_bssid[i]));
        g_bssid[i].used = true;
        memcpy(g_bssid[i].bssid, mac, 6);
        return &g_bssid[i];
    }
    g_live.table_full = true;
    return nullptr;
}

void touch_group(const char *ssid, uint8_t ssid_len, const uint8_t *bssid, sentinel::WifiSecurity sec, bool known) {
    if (ssid_len == 0) return;
    uint32_t h = hash_bytes((const uint8_t *)ssid, ssid_len);
    uint32_t now = millis();
    SsidGroup *slot = nullptr;
    for (int i = 0; i < kGroupCap; i++) {
        if (!g_group[i].used || g_group[i].hash != h || g_group[i].ssid_len != ssid_len) continue;
        if (memcmp(g_group[i].ssid, ssid, ssid_len) != 0) continue;
        slot = &g_group[i];
        break;
    }
    if (slot == nullptr) {
        for (int i = 0; i < kGroupCap; i++) {
            if (g_group[i].used) continue;
            slot = &g_group[i];
            memset(slot, 0, sizeof(*slot));
            slot->used = true;
            slot->hash = h;
            slot->ssid_len = ssid_len;
            memcpy(slot->ssid, ssid, ssid_len);
            break;
        }
    }
    if (slot == nullptr) {
        g_live.table_full = true;
        return;
    }
    for (uint8_t i = 0; i < slot->n; i++) {
        if (!mac_eq(slot->bssid[i], bssid)) continue;
        slot->last_ms[i] = now;
        if (known) {
            slot->sec[i] = sec;
            slot->sec_known[i] = true;
        }
        return;
    }
    if (slot->n >= 4) return;
    memcpy(slot->bssid[slot->n], bssid, 6);
    slot->sec[slot->n] = sec;
    slot->sec_known[slot->n] = known;
    slot->last_ms[slot->n] = now;
    slot->n++;
}

void note_beacon_ssid(uint32_t h) {
    for (int i = 0; i < g_beacon_n; i++) {
        if (g_beacon[i].hash != h) continue;
        if (g_beacon[i].count < 255) g_beacon[i].count++;
        return;
    }
    if (g_beacon_n >= kBeaconCap) {
        g_beacon_capped = true;
        return;
    }
    g_beacon[g_beacon_n].hash = h;
    g_beacon[g_beacon_n].count = 1;
    g_beacon_n++;
}

void recompute_probe_other(BssidSlot *slot, uint32_t beacon_hash) {
    slot->probe_other = 0;
    if (!slot->saw_beacon || slot->beacon_hidden) return;
    for (uint8_t i = 0; i < slot->probe_n; i++) {
        if (slot->probe_hash[i] != beacon_hash) slot->probe_other++;
    }
}

void note_probe(BssidSlot *slot, uint32_t h) {
    for (uint8_t i = 0; i < slot->probe_n; i++) {
        if (slot->probe_hash[i] == h) return;
    }
    if (slot->probe_n >= kProbeCap) {
        slot->probe_capped = true;
        return;
    }
    slot->probe_hash[slot->probe_n++] = h;
    if (slot->saw_beacon && !slot->beacon_hidden) {
        uint32_t beacon_hash = hash_bytes((const uint8_t *)slot->beacon_ssid, slot->beacon_ssid_len);
        if (h != beacon_hash) slot->probe_other++;
    }
}

void handle_wifi(const WifiNote &note) {
    if (mac_zero(note.bssid)) return;
    BssidSlot *slot = find_bssid(note.bssid, true);
    if (slot == nullptr) return;
    slot->last_ms = millis();
    slot->channel = note.channel;
    if (note.subtype == 0x0c || note.subtype == 0x0a) {
        if (slot->deauth < 65535) slot->deauth++;
        return;
    }
    if (!note.has_fixed) return;
    char ssid[33];
    uint8_t ssid_len = note.ssid_len;
    bool have_ssid = note.has_ssid != 0;
    if (ssid_len > 32) ssid_len = 32;
    memcpy(ssid, note.ssid, ssid_len);
    ssid[ssid_len] = '\0';
    sentinel::WifiSecurity sec = (sentinel::WifiSecurity)note.security;
    bool known = sec != sentinel::WifiSecurity::Unknown;
    if (note.subtype == 0x08) {
        slot->saw_beacon = true;
        if (have_ssid) {
            slot->beacon_hidden = ssid_len == 0;
            slot->beacon_ssid_len = ssid_len;
            memcpy(slot->beacon_ssid, ssid, ssid_len);
            slot->beacon_ssid[ssid_len] = '\0';
            if (ssid_len > 0) {
                uint32_t h = hash_bytes((const uint8_t *)ssid, ssid_len);
                note_beacon_ssid(h);
                recompute_probe_other(slot, h);
                touch_group(ssid, ssid_len, note.bssid, sec, known);
            }
        }
        if (known) {
            slot->security = sec;
            slot->security_known = true;
        }
        return;
    }
    if (note.subtype == 0x05 && have_ssid && ssid_len > 0) {
        note_probe(slot, hash_bytes((const uint8_t *)ssid, ssid_len));
    }
}

void note_spam(const uint8_t *addr, uint8_t mask) {
    int found = -1;
    for (uint8_t i = 0; i < g_spam_n; i++) {
        if (!mac_eq(g_spam[i].addr, addr)) continue;
        found = (int)i;
        break;
    }
    if (found >= 0) {
        if (g_spam[found].hits < 255) g_spam[found].hits++;
    } else if (g_spam_n < kSpamCap) {
        memcpy(g_spam[g_spam_n].addr, addr, 6);
        g_spam[g_spam_n].mask = 0;
        g_spam[g_spam_n].hits = 1;
        found = (int)g_spam_n;
        g_spam_n++;
    } else {
        return;
    }
    for (int b = 0; b < 4; b++) {
        uint8_t bit = kFamilyBit[b];
        if ((mask & bit) == 0) continue;
        if (g_spam_ads[b] < 65535) g_spam_ads[b]++;
        if ((g_spam[found].mask & bit) != 0) continue;
        g_spam[found].mask = (uint8_t)(g_spam[found].mask | bit);
        if (g_spam_unique[b] < 255) g_spam_unique[b]++;
    }
}

int hid_evict_slot(uint32_t now) {
    uint8_t used[kHidCap];
    uint8_t bits[kHidCap];
    uint32_t first_ms[kHidCap];
    for (int i = 0; i < kHidCap; i++) {
        used[i] = g_hid[i].used ? 1 : 0;
        bits[i] = 0;
        first_ms[i] = g_hid[i].first_ms;
    }
    return sentinel::oldest_unmarked_slot(used, bits, first_ms, kHidCap, now);
}

int tracker_evict_slot(uint32_t now) {
    uint8_t used[kTrackerCap];
    uint8_t bits[kTrackerCap];
    uint32_t first_ms[kTrackerCap];
    for (int i = 0; i < kTrackerCap; i++) {
        used[i] = g_track[i].used ? 1 : 0;
        bits[i] = g_track[i].bits;
        first_ms[i] = g_track[i].first_ms;
    }
    return sentinel::oldest_unmarked_slot(used, bits, first_ms, kTrackerCap, now);
}

void fill_hid_slot(int slot, const uint8_t *addr, uint32_t now) {
    memset(&g_hid[slot], 0, sizeof(g_hid[slot]));
    g_hid[slot].used = true;
    memcpy(g_hid[slot].addr, addr, 6);
    g_hid[slot].first_ms = now;
    g_hid[slot].baseline = !g_baseline_done;
    g_hid[slot].counted = false;
    if (g_baseline_done) {
        g_hid[slot].counted = true;
        if (g_hid_new < 255) g_hid_new++;
    }
}

void note_hid(const uint8_t *addr) {
    uint32_t now = millis();
    for (int i = 0; i < kHidCap; i++) {
        if (!g_hid[i].used || !mac_eq(g_hid[i].addr, addr)) continue;
        if (g_hid[i].baseline || g_hid[i].counted) return;
        g_hid[i].counted = true;
        if (g_hid_new < 255) g_hid_new++;
        return;
    }
    for (int i = 0; i < kHidCap; i++) {
        if (g_hid[i].used) continue;
        fill_hid_slot(i, addr, now);
        g_hid_full = false;
        return;
    }
    int slot = hid_evict_slot(now);
    if (slot < 0) {
        g_hid_full = true;
        g_live.table_full = true;
        return;
    }
    fill_hid_slot(slot, addr, now);
    g_hid_full = false;
}

void fill_tracker_slot(int slot, const uint8_t *addr, sentinel::TrackerFamily family, uint32_t now) {
    memset(&g_track[slot], 0, sizeof(g_track[slot]));
    g_track[slot].used = true;
    memcpy(g_track[slot].addr, addr, 6);
    g_track[slot].family = family;
    g_track[slot].first_ms = now;
    g_track[slot].last_ms = now;
    g_track[slot].last_sev = sentinel::Severity::None;
    if (g_checkpoint > 0) g_track[slot].bits = (uint8_t)(1u << (g_checkpoint - 1));
}

void note_tracker(const uint8_t *addr, sentinel::TrackerFamily family) {
    uint32_t now = millis();
    for (int i = 0; i < kTrackerCap; i++) {
        if (!g_track[i].used || !mac_eq(g_track[i].addr, addr)) continue;
        g_track[i].last_ms = now;
        g_track[i].family = family;
        if (g_checkpoint > 0) g_track[i].bits = (uint8_t)(g_track[i].bits | (1u << (g_checkpoint - 1)));
        return;
    }
    for (int i = 0; i < kTrackerCap; i++) {
        if (g_track[i].used) continue;
        fill_tracker_slot(i, addr, family, now);
        g_track_full = false;
        return;
    }
    int slot = tracker_evict_slot(now);
    if (slot < 0) {
        g_track_full = true;
        g_live.table_full = true;
        return;
    }
    fill_tracker_slot(slot, addr, family, now);
    g_track_full = false;
}

void handle_ble(const BleNote &note) {
    if (mac_zero(note.addr)) return;
    sentinel::BleMarks marks = sentinel::classify_ble_ad(note.ad, note.ad_len);
    if (marks.spam_mask != 0) note_spam(note.addr, marks.spam_mask);
    if (marks.hid) note_hid(note.addr);
    if (marks.tracker != sentinel::TrackerFamily::None) note_tracker(note.addr, marks.tracker);
}

void apply_checkpoint_mark() {
    if (!g_mark_checkpoint) return;
    g_mark_checkpoint = false;
    if (g_checkpoint >= 8) return;
    g_checkpoint++;
    uint8_t bit = (uint8_t)(1u << (g_checkpoint - 1));
    uint32_t now = millis();
    for (int i = 0; i < kTrackerCap; i++) {
        if (!g_track[i].used) continue;
        if ((uint32_t)(now - g_track[i].last_ms) <= kMarkWindowMs) g_track[i].bits = (uint8_t)(g_track[i].bits | bit);
    }
    g_live.checkpoint = g_checkpoint;
}

void score_tick(uint32_t now) {
    g_raised_this_tick = false;
    apply_checkpoint_mark();
    if (g_reset_window) {
        g_reset_window = false;
        for (int i = 0; i < kBssidCap; i++) g_bssid[i].deauth = 0;
        g_beacon_n = 0;
        g_beacon_capped = false;
        g_spam_n = 0;
        g_hid_new = 0;
        memset(g_spam_ads, 0, sizeof(g_spam_ads));
        memset(g_spam_unique, 0, sizeof(g_spam_unique));
        for (int i = 0; i < kHidCap; i++) g_hid[i].counted = false;
        g_window_start = now;
        return;
    }
    uint32_t elapsed = (uint32_t)(now - g_window_start);
    if (elapsed < 800) return;
    if (g_ble_active) {
        g_ble_listen_ms += elapsed;
        if (g_ble_listen_ms >= kBaselineMs) g_baseline_done = true;
    }
    g_live.baseline_done = g_baseline_done;
    g_live.checkpoint = g_checkpoint;
    g_live.wifi_drops = g_wifi_drops;
    g_live.ble_drops = g_ble_drops;
    g_live.beacon_capped = g_beacon_capped;

    bool locked = g_locked && !g_ble_active;
    uint16_t top = 0;
    for (int i = 0; i < kBssidCap; i++) {
        if (!g_bssid[i].used || g_bssid[i].deauth == 0) continue;
        uint32_t per_s = (uint32_t)g_bssid[i].deauth * 1000u / elapsed;
        if (per_s > 65535) per_s = 65535;
        if ((uint16_t)per_s > top) top = (uint16_t)per_s;
        sentinel::Severity sev = sentinel::score_deauth((uint16_t)per_s, locked);
        char mac[18];
        char detail[96];
        fmt_mac(mac, sizeof(mac), g_bssid[i].bssid);
        snprintf(
            detail,
            sizeof(detail),
            "bssid=%s ch=%u observed=%lu/s hopping=%s",
            mac,
            g_bssid[i].channel,
            (unsigned long)per_s,
            locked ? "no" : "yes"
        );
        raise_finding(sentinel::Kind::Deauth, sev, hash_mac(g_bssid[i].bssid), detail);
        g_bssid[i].deauth = 0;
    }
    g_live.deauth_top = top;

    sentinel::BeaconStats stats;
    stats.unique_ssids = (uint16_t)g_beacon_n;
    stats.once_only = 0;
    for (int i = 0; i < g_beacon_n; i++) {
        if (g_beacon[i].count == 1) stats.once_only++;
    }
    g_live.beacon_unique = stats.unique_ssids;
    sentinel::Severity flood = sentinel::score_beacon_flood(stats);
    char flood_detail[96];
    snprintf(
        flood_detail,
        sizeof(flood_detail),
        "unique=%u once=%u capped=%s",
        stats.unique_ssids,
        stats.once_only,
        g_beacon_capped ? "yes" : "no"
    );
    raise_finding(sentinel::Kind::BeaconFlood, flood, 1, flood_detail);
    g_beacon_n = 0;
    g_beacon_capped = false;

    for (int i = 0; i < kGroupCap; i++) {
        if (!g_group[i].used) continue;
        uint8_t fresh = 0;
        bool saw_open = false;
        bool saw_enc = false;
        bool differ = false;
        bool have = false;
        sentinel::WifiSecurity first = sentinel::WifiSecurity::Unknown;
        for (uint8_t b = 0; b < g_group[i].n; b++) {
            if ((uint32_t)(now - g_group[i].last_ms[b]) > kFreshMs) continue;
            fresh++;
            if (!g_group[i].sec_known[b]) continue;
            if (g_group[i].sec[b] == sentinel::WifiSecurity::Open) saw_open = true;
            else saw_enc = true;
            if (!have) {
                first = g_group[i].sec[b];
                have = true;
            } else if (g_group[i].sec[b] != first) {
                differ = true;
            }
        }
        sentinel::Severity sev = sentinel::score_evil_twin(fresh, differ, saw_open && saw_enc);
        char name[33];
        char detail[96];
        copy_sanitized(name, sizeof(name), g_group[i].ssid, g_group[i].ssid_len);
        snprintf(detail, sizeof(detail), "ssid=%s bssids=%u", name, fresh);
        raise_finding(sentinel::Kind::EvilTwin, sev, g_group[i].hash, detail);
    }

    for (int i = 0; i < kBssidCap; i++) {
        if (!g_bssid[i].used) continue;
        if ((uint32_t)(now - g_bssid[i].last_ms) > kFreshMs) continue;
        sentinel::KarmaInput in;
        in.saw_beacon = g_bssid[i].saw_beacon;
        in.beacon_hidden = g_bssid[i].beacon_hidden;
        in.distinct_probe_ssids = g_bssid[i].probe_n;
        in.probe_ssids_other = g_bssid[i].probe_other;
        if (g_bssid[i].probe_capped && in.probe_ssids_other < kProbeCap) in.probe_ssids_other = kProbeCap;
        sentinel::Severity sev = sentinel::score_karma(in);
        char mac[18];
        char detail[96];
        fmt_mac(mac, sizeof(mac), g_bssid[i].bssid);
        if (g_bssid[i].probe_capped) {
            snprintf(detail, sizeof(detail), "bssid=%s extra_names>=%u", mac, kProbeCap);
        } else {
            uint8_t extras = 0;
            if (in.saw_beacon && !in.beacon_hidden) extras = in.probe_ssids_other;
            else if (in.saw_beacon && in.beacon_hidden && in.distinct_probe_ssids > 0)
                extras = (uint8_t)(in.distinct_probe_ssids - 1);
            else if (!in.saw_beacon && in.distinct_probe_ssids >= 3) extras = in.distinct_probe_ssids;
            snprintf(detail, sizeof(detail), "bssid=%s extra_names=%u", mac, extras);
        }
        raise_finding(sentinel::Kind::KarmaProbe, sev, hash_mac(g_bssid[i].bssid) ^ 0x9e3779b9u, detail);
    }

    for (int b = 0; b < 4; b++) {
        uint32_t ads = (uint32_t)g_spam_ads[b] * 1000u / elapsed;
        if (ads > 65535) ads = 65535;
        uint8_t once = 0;
        uint8_t bit = kFamilyBit[b];
        for (uint8_t i = 0; i < g_spam_n; i++) {
            if ((g_spam[i].mask & bit) != 0 && g_spam[i].hits == 1) once++;
        }
        sentinel::Severity sev = sentinel::score_ble_spam((uint16_t)ads, g_spam_unique[b], once);
        char detail[96];
        snprintf(
            detail,
            sizeof(detail),
            "family=%s ads=%lu/s addrs=%u once=%u",
            sentinel::ble_family_name(kFamilyBit[b]),
            (unsigned long)ads,
            g_spam_unique[b],
            once
        );
        raise_finding(sentinel::Kind::BleSpam, sev, (uint32_t)kFamilyBit[b], detail);
    }
    g_spam_n = 0;
    memset(g_spam_ads, 0, sizeof(g_spam_ads));
    memset(g_spam_unique, 0, sizeof(g_spam_unique));

    if (g_baseline_done) {
        sentinel::Severity sev = sentinel::score_new_hid(g_hid_new);
        char detail[96];
        snprintf(detail, sizeof(detail), "new_addrs=%u baseline_s=20", g_hid_new);
        raise_finding(sentinel::Kind::HidGatt, sev, 2, detail);
    }
    g_hid_new = 0;
    for (int i = 0; i < kHidCap; i++) g_hid[i].counted = false;

    for (int i = 0; i < kTrackerCap; i++) {
        if (!g_track[i].used) continue;
        if ((uint32_t)(now - g_track[i].last_ms) > kTrackerHereMs) continue;
        uint32_t age = (uint32_t)(now - g_track[i].first_ms);
        uint8_t marks = popcount(g_track[i].bits);
        sentinel::Severity sev = sentinel::score_tracker(marks, age);
        if (sev_rank(sev) > sev_rank(g_track[i].last_sev)) g_track[i].last_sev = sev;
        char mac[18];
        char detail[96];
        fmt_mac(mac, sizeof(mac), g_track[i].addr);
        snprintf(
            detail,
            sizeof(detail),
            "family=%s addr=%s checkpoints=%u age_s=%lu",
            sentinel::tracker_family_name(g_track[i].family),
            mac,
            marks,
            (unsigned long)(age / 1000u)
        );
        raise_finding(sentinel::Kind::Tracker, sev, hash_mac(g_track[i].addr), detail);
    }

    uint32_t drops = g_wifi_drops + g_ble_drops;
    if (drops > g_logged_drops) {
        char detail[96];
        snprintf(
            detail,
            sizeof(detail),
            "wifi_queue_drops=%lu ble_queue_drops=%lu",
            (unsigned long)g_wifi_drops,
            (unsigned long)g_ble_drops
        );
        raise_finding(sentinel::Kind::Note, sentinel::Severity::Info, 3, detail);
        g_logged_drops = drops;
    }

    if (!g_raised_this_tick && g_live.sev != sentinel::Severity::None && (uint32_t)(now - g_latch_ms) > 5000) {
        g_live.sev = sentinel::Severity::None;
        snprintf(g_live.summary, sizeof(g_live.summary), "%s", "Listening");
        snprintf(
            g_live.explanation,
            sizeof(g_live.explanation),
            "%s",
            "No pattern is over the threshold. That is not a clean bill of health."
        );
    }
    g_window_start = now;
}

void worker_task(void *arg) {
    (void)arg;
    if (!ensureSentinelRam()) {
        g_worker_run = false;
        vTaskDelete(nullptr);
        return;
    }
    WifiNote wifi;
    BleNote ble;
    while (g_worker_run) {
        bool got = false;
        if (g_wifi_q != nullptr && xQueueReceive(g_wifi_q, &wifi, 0) == pdTRUE) {
            got = true;
            if (g_mu != nullptr && xSemaphoreTake(g_mu, pdMS_TO_TICKS(20)) == pdTRUE) {
                handle_wifi(wifi);
                xSemaphoreGive(g_mu);
            }
        }
        if (g_ble_q != nullptr && xQueueReceive(g_ble_q, &ble, 0) == pdTRUE) {
            got = true;
            if (g_mu != nullptr && xSemaphoreTake(g_mu, pdMS_TO_TICKS(20)) == pdTRUE) {
                handle_ble(ble);
                xSemaphoreGive(g_mu);
            }
        }
        uint32_t now = millis();
        if (g_window_start == 0 || (uint32_t)(now - g_window_start) >= 1000) {
            if (g_mu != nullptr && xSemaphoreTake(g_mu, pdMS_TO_TICKS(50)) == pdTRUE) {
                score_tick(now);
                xSemaphoreGive(g_mu);
            }
        }
        if (!got) vTaskDelay(pdMS_TO_TICKS(10));
    }
    g_worker_handle = nullptr;
    vTaskDelete(nullptr);
}

void wifi_rx(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_wifi_capture || buf == nullptr || g_wifi_q == nullptr) return;
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t sig = pkt->rx_ctrl.sig_len;
    size_t frame_len = sentinel::mgmt_len_without_fcs(sig);
    if (frame_len < 24) return;
    if (frame_len > 512) frame_len = 512;
    const uint8_t *frame = pkt->payload;
    uint16_t fc = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    uint8_t ftype = (uint8_t)((fc >> 2) & 0x3);
    uint8_t fsub = (uint8_t)((fc >> 4) & 0xf);
    if (ftype != 0) return;
    bool deauth = fsub == 0x0c || fsub == 0x0a;
    bool beacon = fsub == 0x08;
    bool probe = fsub == 0x05;
    if (!deauth && !beacon && !probe) return;

    WifiNote note;
    memset(&note, 0, sizeof(note));
    note.subtype = fsub;
    memcpy(note.bssid, frame + 16, 6);
    note.rssi = pkt->rx_ctrl.rssi;
    uint8_t channel = (uint8_t)pkt->rx_ctrl.channel;
    if (channel < 1 || channel > 14) channel = g_ui_channel;
    note.channel = channel;
    if ((beacon || probe) && frame_len >= 36) {
        note.has_fixed = 1;
        note.capability = (uint16_t)frame[34] | ((uint16_t)frame[35] << 8);
        sentinel::WifiTagParse parsed = sentinel::parse_mgmt_tags(frame, frame_len);
        note.has_ssid = parsed.has_ssid ? 1 : 0;
        note.ssid_len = parsed.ssid_len;
        memcpy(note.ssid, parsed.ssid, sizeof(note.ssid));
        note.security = (uint8_t)parsed.security;
        note.ie_truncated = parsed.truncated ? 1 : 0;
    }
    if (xQueueSend(g_wifi_q, &note, 0) != pdTRUE) g_wifi_drops = g_wifi_drops + 1;
}

void session_reset() {
    memset(g_bssid, 0, sizeof(g_bssid));
    memset(g_group, 0, sizeof(g_group));
    memset(g_beacon, 0, sizeof(g_beacon));
    memset(g_spam, 0, sizeof(g_spam));
    memset(g_hid, 0, sizeof(g_hid));
    memset(g_track, 0, sizeof(g_track));
    memset(g_cool, 0, sizeof(g_cool));
    memset(g_saved, 0, sizeof(g_saved));
    memset(g_pending, 0, sizeof(g_pending));
    memset(&g_live, 0, sizeof(g_live));
    snprintf(g_live.summary, sizeof(g_live.summary), "%s", "Listening");
    snprintf(
        g_live.explanation,
        sizeof(g_live.explanation),
        "%s",
        "No pattern is over the threshold. That is not a clean bill of health."
    );
    g_beacon_n = 0;
    g_beacon_capped = false;
    g_spam_n = 0;
    g_hid_new = 0;
    g_hid_full = false;
    g_track_full = false;
    g_saved_count = 0;
    g_saved_next = 0;
    g_pending_n = 0;
    g_window_start = millis();
    g_ble_listen_ms = 0;
    g_baseline_done = false;
    g_checkpoint = 0;
    g_logged_drops = 0;
    g_wifi_drops = 0;
    g_ble_drops = 0;
    g_locked = false;
    g_ui_channel = 1;
    g_mark_checkpoint = false;
    g_reset_window = false;
    g_latch_ms = 0;
    g_raised_this_tick = false;
    memset(g_spam_ads, 0, sizeof(g_spam_ads));
    memset(g_spam_unique, 0, sizeof(g_spam_unique));
}

void wall_now(char *out, size_t n) {
    if (out == nullptr || n == 0) return;
    out[0] = '\0';
    if (!clock_set) return;
    struct tm stamp = rtc.getTimeStruct();
    if (stamp.tm_year + 1900 < 2024) return;
    snprintf(
        out,
        n,
        "%04d-%02d-%02dT%02d:%02d:%02d",
        stamp.tm_year + 1900,
        stamp.tm_mon + 1,
        stamp.tm_mday,
        stamp.tm_hour,
        stamp.tm_min,
        stamp.tm_sec
    );
}

bool write_log_bytes(const char *text, size_t n) {
    if (!g_log || text == nullptr || n == 0 || g_log_capped) return false;
    if (g_log_bytes + n > kMaxLogBytes) {
        g_log_capped = true;
        const char *cap =
            "{\"t_ms\":0,\"wall\":\"\",\"kind\":\"note\",\"severity\":\"info\",\"summary\":\"Log capped\","
            "\"detail\":\"file limit 262144 bytes\",\"drops\":0}\n";
        size_t cn = strlen(cap);
        if (g_log_bytes + cn <= kMaxLogBytes) {
            g_log.write((const uint8_t *)cap, cn);
            g_log_bytes += cn;
            g_log.flush();
        }
        return false;
    }
    size_t wrote = g_log.write((const uint8_t *)text, n);
    g_log_bytes += wrote;
    g_log.flush();
    return wrote == n;
}

void open_log(WatchMode mode) {
    g_log_path[0] = '\0';
    g_log_bytes = 0;
    g_log_capped = false;
    if (!g_sd_log || !sdcardMounted) return;
    if (!SD.exists("/Bruce")) SD.mkdir("/Bruce");
    if (!SD.exists("/Bruce/Sentinel")) SD.mkdir("/Bruce/Sentinel");
    char stamp[32];
    wall_now(stamp, sizeof(stamp));
    if (stamp[0] != '\0') {
        for (char *p = stamp; *p != '\0'; p++) {
            if (*p == ':') *p = '-';
        }
        snprintf(
            g_log_path,
            sizeof(g_log_path),
            "/Bruce/Sentinel/sentinel_%s_%lu.jsonl",
            stamp,
            (unsigned long)millis()
        );
    } else {
        snprintf(g_log_path, sizeof(g_log_path), "/Bruce/Sentinel/sentinel_boot%lu.jsonl", (unsigned long)millis());
    }
    g_log = SD.open(g_log_path, FILE_WRITE);
    if (!g_log) {
        g_log_path[0] = '\0';
        return;
    }
    sentinel::LogIdentity id;
#ifndef DEVICE_NAME
    id.board = "unknown-board";
#else
    id.board = DEVICE_NAME;
#endif
    id.firmware = BRUCE_VERSION;
    id.git = GIT_COMMIT_HASH;
    // Stack, not BSS. A static 2KB buffer pushed the no-PSRAM ESP32 (E32R28T)
    // over its DRAM limit. The formatted header is about 1.2KB.
    char header[1600];
    int n = sentinel::format_session_header(header, sizeof(header), id);
    if (n > 0) write_log_bytes(header, (size_t)n);
    char wall[24];
    wall_now(wall, sizeof(wall));
    const char *mode_name = mode == WatchMode::Wifi ? "wifi" : mode == WatchMode::Ble ? "ble" : "alternate";
    char detail[96];
    snprintf(detail, sizeof(detail), "mode=%s passive_ble=1", mode_name);
    char line[320];
    int ln = sentinel::format_event_json(
        line,
        sizeof(line),
        millis(),
        wall,
        sentinel::Kind::Note,
        sentinel::Severity::Info,
        "Session started",
        detail,
        0
    );
    if (ln > 0) write_log_bytes(line, (size_t)ln);
    Serial.printf("[Sentinel] log %s\n", g_log_path);
}

void drain_logs() {
    Saved pending[kPendingCap];
    uint8_t n = 0;
    if (g_mu == nullptr || xSemaphoreTake(g_mu, pdMS_TO_TICKS(20)) != pdTRUE) return;
    n = g_pending_n;
    if (n > kPendingCap) n = kPendingCap;
    memcpy(pending, g_pending, n * sizeof(Saved));
    g_pending_n = 0;
    xSemaphoreGive(g_mu);
    if (!g_log) return;
    char wall[24];
    wall_now(wall, sizeof(wall));
    uint32_t drops = g_wifi_drops + g_ble_drops;
    for (uint8_t i = 0; i < n; i++) {
        char line[320];
        int ln = sentinel::format_event_json(
            line,
            sizeof(line),
            pending[i].t_ms,
            wall,
            pending[i].kind,
            pending[i].sev,
            pending[i].summary,
            pending[i].detail,
            drops
        );
        if (ln > 0) write_log_bytes(line, (size_t)ln);
    }
}

void close_log() {
    if (g_log) {
        g_log.flush();
        g_log.close();
    }
}

bool start_wifi() {
    if (!radioHasMemForWifi()) {
        displayError("Not enough RAM for monitor mode", true);
        return false;
    }
    ensureWifiPlatform();
    nvs_flash_init();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK && err != ESP_ERR_WIFI_INIT_STATE) {
        Serial.printf("[Sentinel] wifi_init: %s\n", esp_err_to_name(err));
    }
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    err = esp_wifi_start();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        Serial.printf("[Sentinel] wifi_start: %s\n", esp_err_to_name(err));
    }
    esp_wifi_disconnect();
    wifi_promiscuous_filter_t filt = {};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wifi_rx);
    err = esp_wifi_set_promiscuous(true);
    bool on = false;
    esp_wifi_get_promiscuous(&on);
    if (err != ESP_OK || !on) {
        displayError("Monitor mode refused on this radio", true);
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        esp_wifi_set_promiscuous(false);
        esp_wifi_stop();
        wifiDisconnect();
        return false;
    }
    if (g_ui_channel < 1 || g_ui_channel > 11) g_ui_channel = 1;
    esp_wifi_set_channel(g_ui_channel, WIFI_SECOND_CHAN_NONE);
    g_wifi_capture = true;
    g_reset_window = true;
    return true;
}

void stop_wifi() {
    g_wifi_capture = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    esp_wifi_stop();
    wifiDisconnect();
}

bool start_ble() {
    if (!ble_scan_setup() || pBLEScan == nullptr) {
        displayError("BLE scan did not start", true);
        return false;
    }
    pBLEScan->setActiveScan(false);
    pBLEScan->setDuplicateFilter(0);
    pBLEScan->setScanCallbacks(&g_ble_cb, true);
    pBLEScan->clearResults();
    g_ble_capture = true;
    g_ble_active = true;
    g_reset_window = true;
    bool started = pBLEScan->start(0, false);
    if (!started) started = pBLEScan->start(10000, false);
    if (!started) {
        g_ble_capture = false;
        g_ble_active = false;
        displayError("BLE scan did not start", true);
        stopBLEStack();
        return false;
    }
    return true;
}

void stop_ble() {
    g_ble_capture = false;
    g_ble_active = false;
    if (pBLEScan != nullptr) {
        pBLEScan->stop();
        pBLEScan->clearResults();
    }
    stopBLEStack();
}

bool start_worker() {
    if (g_mu == nullptr) g_mu = xSemaphoreCreateMutex();
    g_wifi_q = xQueueCreate(32, sizeof(WifiNote));
    g_ble_q = xQueueCreate(32, sizeof(BleNote));
    if (g_mu == nullptr || g_wifi_q == nullptr || g_ble_q == nullptr) {
        displayError("Sentinel queue failed", true);
        return false;
    }
    g_worker_run = true;
    if (xTaskCreate(worker_task, "sentinel", 4096, nullptr, 1, &g_worker_handle) != pdPASS) {
        g_worker_run = false;
        displayError("Sentinel worker failed", true);
        return false;
    }
    return true;
}

void stop_worker() {
    g_wifi_capture = false;
    g_ble_capture = false;
    g_worker_run = false;
    for (int i = 0; i < 50 && g_worker_handle != nullptr; i++) vTaskDelay(pdMS_TO_TICKS(10));
    if (g_wifi_q != nullptr) {
        vQueueDelete(g_wifi_q);
        g_wifi_q = nullptr;
    }
    if (g_ble_q != nullptr) {
        vQueueDelete(g_ble_q);
        g_ble_q = nullptr;
    }
}

int wrap_text(const char *text, int cpl, char lines[][48], int max_lines) {
    if (cpl > 47) cpl = 47;
    if (cpl < 12) cpl = 12;
    int count = 0;
    const char *p = text != nullptr ? text : "";
    while (*p && count < max_lines) {
        while (*p == ' ') p++;
        if (*p == '\0') break;
        int take = 0;
        int last_space = -1;
        while (p[take] != '\0' && take < cpl) {
            if (p[take] == ' ') last_space = take;
            take++;
        }
        int cut = take;
        if (p[take] != '\0' && last_space > cpl / 3) cut = last_space;
        memcpy(lines[count], p, (size_t)cut);
        lines[count][cut] = '\0';
        p += cut;
        count++;
    }
    return count;
}

void draw_watch(WatchMode mode, bool wifi_on, bool ble_on, bool switching) {
    Live live;
    memset(&live, 0, sizeof(live));
    if (g_mu != nullptr && xSemaphoreTake(g_mu, pdMS_TO_TICKS(30)) == pdTRUE) {
        live = g_live;
        live.wifi_drops = g_wifi_drops;
        live.ble_drops = g_ble_drops;
        xSemaphoreGive(g_mu);
    }
    drawMainBorder(true);
    tft.setTextSize(FP);
    int top = 28;
    int bottom = tftHeight - 12;
    uint16_t bg = TFT_DARKGREEN;
    uint16_t fg = TFT_WHITE;
    const char *sev = "LISTEN";
    if (switching) {
        bg = TFT_DARKGREY;
        sev = "SWITCH";
    } else if (live.sev == sentinel::Severity::High) {
        bg = TFT_RED;
        sev = "HIGH";
    } else if (live.sev == sentinel::Severity::Medium) {
        bg = TFT_ORANGE;
        fg = TFT_BLACK;
        sev = "MEDIUM";
    } else if (live.sev == sentinel::Severity::Low) {
        bg = TFT_YELLOW;
        fg = TFT_BLACK;
        sev = "LOW";
    } else if (live.sev == sentinel::Severity::Info) {
        bg = TFT_BLUE;
        sev = "INFO";
    }
    tft.fillRect(8, top, tftWidth - 16, 14, bg);
    tft.setTextColor(fg, bg);
    char banner[48];
    snprintf(banner, sizeof(banner), "%s %s", sev, switching ? "radio changing" : live.summary);
    int cpl = (tftWidth - 16) / (LW * FP);
    if (cpl < 12) cpl = 12;
    if ((int)strlen(banner) > cpl) banner[cpl] = '\0';
    tft.drawString(banner, 10, top + 3, 1);

    int y = top + 16;
    int room = (bottom - y) / (LH * FP);
    if (room < 4) room = 4;
    int expl_lines = room >= 8 ? 3 : 2;
    char wrapped[4][48];
    const char *expl = switching ? "Wi-Fi and BLE share this radio. Nothing is heard while the stack changes."
                                  : live.explanation;
    int nlines = wrap_text(expl, cpl, wrapped, expl_lines);
    tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
    for (int i = 0; i < nlines && y < bottom - (LH * FP); i++) {
        tft.drawString(wrapped[i], 8, y, 1);
        y += LH * FP;
    }

    char status[48];
    if (switching) {
        snprintf(status, sizeof(status), "switching");
    } else if (wifi_on) {
        snprintf(status, sizeof(status), "WiFi ch%u %s", g_ui_channel, g_locked ? "locked" : "hop");
    } else if (ble_on) {
        snprintf(
            status, sizeof(status), "BLE %s cp%u", live.baseline_done ? "ready" : "baseline", live.checkpoint
        );
    } else {
        snprintf(status, sizeof(status), "radio off");
    }
    int used = (int)strlen(status);
    if (live.wifi_drops + live.ble_drops > 0 && used < 32) {
        snprintf(
            status + used,
            sizeof(status) - (size_t)used,
            " drop%lu",
            (unsigned long)(live.wifi_drops + live.ble_drops)
        );
    }
    if ((int)strlen(status) > cpl) status[cpl] = '\0';
    tft.drawString(status, 8, y, 1);
    y += LH * FP;

    int find_room = (bottom - y) / (LH * FP) - 1;
    if (find_room < 0) find_room = 0;
    if (find_room > live.finding_n) find_room = live.finding_n;
    for (int i = 0; i < find_room; i++) {
        char row[48];
        snprintf(row, sizeof(row), "%s", live.finding[i]);
        if ((int)strlen(row) > cpl) row[cpl] = '\0';
        tft.drawString(row, 8, y, 1);
        y += LH * FP;
    }

    static const char *hints[] = {
        "2.4 GHz only. 5 GHz is not swept.",
        "Hopping under-counts. Lock a channel.",
        "Wi-Fi and BLE share this radio.",
        "A finding is a pattern, not an ID.",
        "Queue drops are counted.",
#if defined(CONFIG_IDF_TARGET_ESP32C5)
        "C5 monitor mode can hear 5 GHz. This watch stays on 2.4.",
#endif
    };
    const char *hint = hints[(millis() / 4000) % (sizeof(hints) / sizeof(hints[0]))];
    if (live.table_full) hint = "A table is full. Extra devices unscored.";
    if (!wifi_on && !ble_on) hint = "This radio is not in a listen mode.";
    char hint_buf[48];
    snprintf(hint_buf, sizeof(hint_buf), "%s", hint);
    if ((int)strlen(hint_buf) > cpl) hint_buf[cpl] = '\0';
    if (y <= bottom - (LH * FP)) tft.drawString(hint_buf, 8, bottom - (LH * FP), 1);

    const char *foot = "ESC exit  SEL checkpoint";
    if (mode == WatchMode::Wifi) foot = "ESC exit  SEL hop  UP/DN ch";
    tft.fillRect(0, tftHeight - 12, tftWidth, 12, bruceConfig.bgColor);
    tft.drawString(foot, 8, tftHeight - 11, 1);
}

void handle_buttons(WatchMode mode, bool wifi_on) {
    if (mode != WatchMode::Ble && wifi_on) {
        if (check(UpPress)) {
            g_locked = true;
            if (g_ui_channel < 11) g_ui_channel = (uint8_t)(g_ui_channel + 1);
            esp_wifi_set_channel(g_ui_channel, WIFI_SECOND_CHAN_NONE);
        }
        if (check(DownPress)) {
            g_locked = true;
            if (g_ui_channel > 1) g_ui_channel = (uint8_t)(g_ui_channel - 1);
            esp_wifi_set_channel(g_ui_channel, WIFI_SECOND_CHAN_NONE);
        }
    }
    if (mode == WatchMode::Wifi && check(SelPress)) g_locked = !g_locked;
    if (mode != WatchMode::Wifi && check(SelPress)) g_mark_checkpoint = true;
}

void hop_channel(bool wifi_on) {
    if (!wifi_on || g_locked) return;
    static uint32_t last = 0;
    static int idx = 0;
    uint32_t now = millis();
    if ((uint32_t)(now - last) < kHopMs) return;
    last = now;
    idx = (idx + 1) % 11;
    g_ui_channel = kChannels[idx];
    esp_wifi_set_channel(g_ui_channel, WIFI_SECOND_CHAN_NONE);
}

void sentinel_watch(WatchMode mode) {
    if (!ensureSentinelRam()) {
        displayError("Not enough RAM", true);
        return;
    }
    if (g_mu != nullptr && xSemaphoreTake(g_mu, pdMS_TO_TICKS(50)) == pdTRUE) {
        session_reset();
        xSemaphoreGive(g_mu);
    } else {
        session_reset();
    }
    if (!start_worker()) {
        stop_worker();
        return;
    }

    bool wifi_on = false;
    bool ble_on = false;
    bool wifi_allowed = mode != WatchMode::Ble;
    bool ble_allowed = mode != WatchMode::Wifi;
    if (wifi_allowed) {
        wifi_on = start_wifi();
        if (!wifi_on) wifi_allowed = false;
    }
    if (!wifi_on && ble_allowed) {
        ble_on = start_ble();
        if (!ble_on) ble_allowed = false;
    }
    if (!wifi_on && !ble_on) {
        stop_worker();
        return;
    }
    open_log(mode);

    uint32_t phase_start = millis();
    bool on_wifi = wifi_on;
    uint32_t last_draw = 0;
    bool switching = false;
    while (!returnToMenu) {
        if (check(EscPress)) break;
        handle_buttons(mode, on_wifi && !switching);
        if (!switching) hop_channel(on_wifi);
        if (ble_on && pBLEScan != nullptr && !pBLEScan->isScanning() && !switching) {
            if (!pBLEScan->start(0, false)) pBLEScan->start(10000, false);
        }
        if (mode == WatchMode::Both && !switching) {
            bool other_ok = on_wifi ? ble_allowed : wifi_allowed;
            uint32_t slice = on_wifi ? kWifiSliceMs : kBleSliceMs;
            if (other_ok && (uint32_t)(millis() - phase_start) >= slice) {
                switching = true;
                draw_watch(mode, on_wifi, ble_on, true);
                if (on_wifi) {
                    stop_wifi();
                    wifi_on = false;
                    vTaskDelay(pdMS_TO_TICKS(250));
                    ble_on = start_ble();
                    if (!ble_on) {
                        ble_allowed = false;
                        wifi_on = start_wifi();
                        if (!wifi_on) wifi_allowed = false;
                    }
                    on_wifi = wifi_on && !ble_on;
                } else {
                    stop_ble();
                    ble_on = false;
                    vTaskDelay(pdMS_TO_TICKS(250));
                    wifi_on = start_wifi();
                    if (!wifi_on) {
                        wifi_allowed = false;
                        ble_on = start_ble();
                        if (!ble_on) ble_allowed = false;
                    }
                    on_wifi = wifi_on;
                }
                if (!wifi_on && !ble_on) break;
                phase_start = millis();
                switching = false;
                g_reset_window = true;
            }
        }
        drain_logs();
        if ((uint32_t)(millis() - last_draw) >= 500) {
            draw_watch(mode, wifi_on, ble_on, switching);
            last_draw = millis();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    g_wifi_capture = false;
    g_ble_capture = false;
    if (wifi_on) stop_wifi();
    if (ble_on) stop_ble();
    drain_logs();
    stop_worker();
    drain_logs();
    close_log();
}

const char *kHelp =
    "Sentinel listens on 2.4 GHz and logs patterns.\n"
    "It does not send deauth, spam, jamming, or exploits.\n"
    "A finding is a pattern. It is not an identification of a person.\n"
    "\n"
    "Wi-Fi, if monitor mode starts:\n"
    "Deauth and disassoc frames per access point.\n"
    "Beacon flood: many names heard once in a second.\n"
    "Same name on another access point, or with other security.\n"
    "Karma-style probe responses: one access point answering for several names.\n"
    "Probe names are counted, not stored.\n"
    "\n"
    "BLE, passive scan, no connection:\n"
    "Floods of Apple continuity, Fast Pair, Swift Pair, or Samsung EasySetup. Family evidence only.\n"
    "New HID-over-GATT advertisements after a 20s baseline.\n"
    "Tracker-family ads that stay in range or appear at checkpoints you mark with SEL.\n"
    "\n"
    "Limits:\n"
    "One channel and one radio at a time. Alternate mode switches, and hears nothing during the switch.\n"
    "Hopping under-counts. Lock a channel with UP or DOWN.\n"
    "Channels 12-13 and 5 GHz are not swept.\n"
    "BLE addresses rotate, so a tracker can be missed.\n"
    "Repeating names are labelled busy air, not a flood.\n"
    "The same name on several access points is often a normal network.\n"
    "Tables and the SD file are capped. The log says when a cap is hit.\n"
    "Advertisement payloads are not logged.\n"
    "\n"
    "Channel Analyzer is airtime. Jam Detect is a fast deauth alarm. Both stay in this menu.\n"
    "SD log: /Bruce/Sentinel/sentinel_*.jsonl\n"
    "SEL closes this note. UP/DN scrolls.";

void sentinel_help() {
    ScrollableTextArea area("SENTINEL");
    area.fromString(kHelp);
    area.show();
}

void sentinel_review() {
    if (!ensureSentinelRam()) {
        displayError("Not enough RAM", true);
        return;
    }
    Saved copy[kSavedCap];
    uint8_t count = 0;
    uint8_t next = 0;
    if (g_mu != nullptr && xSemaphoreTake(g_mu, pdMS_TO_TICKS(50)) == pdTRUE) {
        memcpy(copy, g_saved, sizeof(copy));
        count = g_saved_count;
        next = g_saved_next;
        xSemaphoreGive(g_mu);
    } else {
        memcpy(copy, g_saved, sizeof(copy));
        count = g_saved_count;
        next = g_saved_next;
    }
    if (count == 0) {
        displayInfo("No findings this session", true);
        return;
    }
    String text;
    for (uint8_t n = 0; n < count; n++) {
        uint8_t idx = (uint8_t)((next + kSavedCap - 1 - n) % kSavedCap);
        text += sentinel::severity_name(copy[idx].sev);
        text += " ";
        text += copy[idx].summary;
        text += "\n";
        text += copy[idx].detail;
        text += "\n\n";
    }
    text += "SEL closes. UP/DN scrolls.";
    ScrollableTextArea area("FINDINGS");
    area.fromString(text);
    area.show();
}

} // namespace

void sentinel_menu() {
    bool leave = false;
    while (!leave && !returnToMenu) {
        options.clear();
        options.push_back({"Wi-Fi patterns", []() { sentinel_watch(WatchMode::Wifi); }});
        options.push_back({"BLE patterns", []() { sentinel_watch(WatchMode::Ble); }});
        options.push_back({"Alternate radios", []() { sentinel_watch(WatchMode::Both); }});
        options.push_back({"Channel Analyzer", []() {
                               channel_analyzer_setup();
                               returnToMenu = false;
                           }});
        options.push_back({"Jam Detect", []() {
                               jam_detect_setup();
                               returnToMenu = false;
                           }});
        options.push_back({"What Sentinel claims", sentinel_help});
        options.push_back({"Review findings", sentinel_review});
        const char *log_label = "SD log: no card";
        if (sdcardMounted) log_label = g_sd_log ? "SD log: ON" : "SD log: OFF";
        options.push_back({log_label, []() {
                               if (!sdcardMounted) {
                                   displayInfo("No SD card mounted", true);
                                   return;
                               }
                               g_sd_log = !g_sd_log;
                           }});
        options.push_back({"Back", [&leave]() { leave = true; }});
        loopOptions(options, MENU_TYPE_SUBMENU, "Sentinel");
    }
}

#endif
