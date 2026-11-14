#include "radio_control.h"

#include "core/display.h"
#include "modules/NRF24/nrf_common.h"
#include "modules/rf/rf_utils.h"

#include <Preferences.h>
#include <cmath>
#include <RF24.h>
#include <globals.h>
#include <vector>

namespace RadioControl {
namespace {
Profile state;
bool loaded = false;

constexpr int8_t CC_POWER[] = {-30, -20, -10, 0};
constexpr uint8_t CC_MOD[] = {2, 0, 1};
constexpr const char *CC_MOD_NAMES[] = {"ASK/OOK", "2-FSK", "GFSK"};
constexpr float CC_RATE[] = {1.2f, 4.8f, 9.6f, 38.4f, 50.0f};
constexpr uint8_t NRF_CHANNELS[] = {2, 20, 40, 60, 76, 80};
constexpr const char *NRF_POWER_NAMES[] = {"MIN", "LOW", "HIGH", "MAX"};
constexpr const char *NRF_RATE_NAMES[] = {"250 kbps", "1 Mbps", "2 Mbps"};

template <typename T, size_t N>
uint8_t findIndex(const T (&values)[N], T value) {
    for (size_t i = 0; i < N; ++i) {
        if (values[i] == value) return static_cast<uint8_t>(i);
    }
    return 0;
}

void load() {
    if (loaded) return;
    loaded = true;
    Preferences prefs;
    if (!prefs.begin("radioctl", true)) return;
    state.ccEnabled = prefs.getBool("ccOn", false);
    state.ccPowerDbm = static_cast<int8_t>(prefs.getInt("ccPa", -10));
    state.ccModulation = prefs.getUChar("ccMod", 2);
    state.ccRateIndex = prefs.getUChar("ccRate", 4);
    state.nrfEnabled = prefs.getBool("nrfOn", false);
    state.nrfPower = prefs.getUChar("nrfPa", 0);
    state.nrfRate = prefs.getUChar("nrfRate", 1);
    state.nrfChannel = prefs.getUChar("nrfCh", 76);
    prefs.end();

    if (findIndex(CC_POWER, state.ccPowerDbm) == 0 && state.ccPowerDbm != -30)
        state.ccPowerDbm = -10;
    if (state.ccModulation > 2) state.ccModulation = 2;
    if (state.ccRateIndex >= sizeof(CC_RATE) / sizeof(CC_RATE[0])) state.ccRateIndex = 4;
    if (state.nrfPower > 3) state.nrfPower = 0;
    if (state.nrfRate > 2) state.nrfRate = 1;
    if (state.nrfChannel < 2 || state.nrfChannel > 80) state.nrfChannel = 76;
}

void save() {
    Preferences prefs;
    if (!prefs.begin("radioctl", false)) {
        Serial.println("[radioctl] NVS unavailable; changes will not persist");
        return;
    }
    prefs.putBool("ccOn", state.ccEnabled);
    prefs.putInt("ccPa", state.ccPowerDbm);
    prefs.putUChar("ccMod", state.ccModulation);
    prefs.putUChar("ccRate", state.ccRateIndex);
    prefs.putBool("nrfOn", state.nrfEnabled);
    prefs.putUChar("nrfPa", state.nrfPower);
    prefs.putUChar("nrfRate", state.nrfRate);
    prefs.putUChar("nrfCh", state.nrfChannel);
    prefs.end();
}

void resetCc() {
    state.ccEnabled = false;
    state.ccPowerDbm = -10;
    state.ccModulation = 2;
    state.ccRateIndex = 4;
    save();
}

void resetNrf() {
    state.nrfEnabled = false;
    state.nrfPower = 0;
    state.nrfRate = 1;
    state.nrfChannel = 76;
    save();
}

void ccDiagnostics() {
    if (bruceConfigPins.rfModule != CC1101_SPI_MODULE) {
        displayError("Select CC1101 in RF Config");
        return;
    }

    // Initialisation with no mode does not command RX or TX.
    bool connected = initRfModule("", 0);
    String status = connected ? "SPI: CC1101 found" : "SPI: CC1101 missing";
    std::vector<Option> items = {
        {status, []() {}},
        {String("Frequency: ") + String(bruceConfigPins.rfFreq, 2) + " MHz", []() {}},
        {String("CS: ") + String(static_cast<int>(bruceConfigPins.CC1101_bus.cs)), []() {}},
        {String("Profile: ") + (state.ccEnabled ? "enabled" : "off"), []() {}},
        {"Back", []() {}},
    };
    loopOptions(items, MENU_TYPE_SUBMENU, "CC1101 Diagnostics");
    deinitRfModule();
}

void nrfDiagnostics() {
    bool connected = nrf_start(NRF_MODE_SPI);
    std::vector<Option> items;
    items.push_back({connected ? "SPI: nRF24 found" : "SPI: nRF24 missing", []() {}});
    if (connected) {
        items.push_back({String("Channel: ") + String(NRFradio.getChannel()), []() {}});
        items.push_back({String("PA register: ") + String(static_cast<int>(NRFradio.getPALevel())), []() {}});
        items.push_back({String("Rate register: ") + String(static_cast<int>(NRFradio.getDataRate())), []() {}});
    }
    items.push_back({String("Profile: ") + (state.nrfEnabled ? "enabled" : "off"), []() {}});
    items.push_back({"Back", []() {}});
    loopOptions(items, MENU_TYPE_SUBMENU, "nRF24 Diagnostics");
    if (connected) {
        NRFradio.stopListening();
        NRFradio.powerDown();
    }
}

} // namespace

const Profile &profile() {
    load();
    return state;
}

void applyCcModulationAndRate() {
    const Profile &p = profile();
    if (!p.ccEnabled) return;
    ELECHOUSE_cc1101.setModulation(p.ccModulation);
    ELECHOUSE_cc1101.setDRate(CC_RATE[p.ccRateIndex]);
}

bool validReceiveSettings(const ReceiveSettings &s) {
    if (!std::isfinite(s.frequencyMHz) || !std::isfinite(s.rateKBaud) ||
        !std::isfinite(s.bandwidthKHz)) return false;
#if defined(FENRIR_EBYTE)
    const bool band = s.frequencyMHz >= 425.0f && s.frequencyMHz <= 450.5f;
#else
    const bool band = (s.frequencyMHz >= 300 && s.frequencyMHz <= 348) ||
                      (s.frequencyMHz >= 387 && s.frequencyMHz <= 464) ||
                      (s.frequencyMHz >= 779 && s.frequencyMHz <= 928);
#endif
    return band && s.modulation <= 2 && s.rateKBaud >= 1.2f && s.rateKBaud <= 50 &&
           s.bandwidthKHz >= 58 && s.bandwidthKHz <= 812.5f;
}

bool applyReceiveSettings(const ReceiveSettings &s) {
    if (bruceConfigPins.rfModule != CC1101_SPI_MODULE || !validReceiveSettings(s)) return false;
    ELECHOUSE_cc1101.setSidle();
    ELECHOUSE_cc1101.setModulation(s.modulation);
    ELECHOUSE_cc1101.setDRate(s.rateKBaud);
    ELECHOUSE_cc1101.setRxBW(s.bandwidthKHz);
    ELECHOUSE_cc1101.setPktFormat(3);
    ELECHOUSE_cc1101.setChannel(0);
    setMHZ(s.frequencyMHz);
    if (fabsf(programmedFrequencyMHz() - s.frequencyMHz) > 0.002f) return false;
    ELECHOUSE_cc1101.SetRx();
    return true;
}

float programmedFrequencyMHz() {
    const uint32_t word = (uint32_t(ELECHOUSE_cc1101.SpiReadReg(CC1101_FREQ2)) << 16) |
                          (uint32_t(ELECHOUSE_cc1101.SpiReadReg(CC1101_FREQ1)) << 8) |
                          ELECHOUSE_cc1101.SpiReadReg(CC1101_FREQ0);
    return float(word) * (26.0f / 65536.0f);
}

void applyCcTxPower() {
    const Profile &p = profile();
    if (p.ccEnabled) ELECHOUSE_cc1101.setPA(p.ccPowerDbm);
}

void applyNrfSettings(RF24 &radio) {
    const Profile &p = profile();
    if (!p.nrfEnabled) return;
#if !defined(FENRIR_NRF_RX_ONLY)
    const rf24_pa_dbm_e powers[] = {RF24_PA_MIN, RF24_PA_LOW, RF24_PA_HIGH, RF24_PA_MAX};
    radio.setPALevel(powers[p.nrfPower]);
#endif
    const rf24_datarate_e rates[] = {RF24_250KBPS, RF24_1MBPS, RF24_2MBPS};
    radio.setDataRate(rates[p.nrfRate]);
    radio.setChannel(p.nrfChannel);
}

void ccMenu() {
    load();
    while (true) {
        const uint8_t modIdx = findIndex(CC_MOD, state.ccModulation);
        const uint8_t paIdx = findIndex(CC_POWER, state.ccPowerDbm);
        std::vector<Option> items = {
            {String("Profile: ") + (state.ccEnabled ? "ON" : "OFF"), []() { state.ccEnabled = !state.ccEnabled; save(); }},
            {String("PA: ") + String(state.ccPowerDbm) + " dBm", [paIdx]() {
                 state.ccPowerDbm = CC_POWER[(paIdx + 1) % (sizeof(CC_POWER) / sizeof(CC_POWER[0]))];
                 save();
             }},
            {String("Mod: ") + CC_MOD_NAMES[modIdx], [modIdx]() {
                 state.ccModulation = CC_MOD[(modIdx + 1) % (sizeof(CC_MOD) / sizeof(CC_MOD[0]))];
                 save();
             }},
            {String("Rate: ") + String(CC_RATE[state.ccRateIndex], 1) + " kBaud", []() {
                 state.ccRateIndex = (state.ccRateIndex + 1) % (sizeof(CC_RATE) / sizeof(CC_RATE[0]));
                 save();
             }},
            {"Hardware check", []() { ccDiagnostics(); }},
            {"Restore defaults", []() { resetCc(); }},
            {"Back", []() {}},
        };
        int selected = loopOptions(items, MENU_TYPE_SUBMENU, "CC1101 Control");
        if (selected == -1 || selected == static_cast<int>(items.size() - 1)) return;
    }
}

void nrfMenu() {
    load();
    while (true) {
        const uint8_t chIdx = findIndex(NRF_CHANNELS, state.nrfChannel);
        std::vector<Option> items = {
            {String("Profile: ") + (state.nrfEnabled ? "ON" : "OFF"), []() { state.nrfEnabled = !state.nrfEnabled; save(); }},
#if defined(FENRIR_NRF_RX_ONLY)
            {"TX PA: LOCKED (RX only)", []() {}},
#else
            {String("PA: ") + NRF_POWER_NAMES[state.nrfPower], []() {
                 state.nrfPower = (state.nrfPower + 1) % 4;
                 save();
             }},
#endif
            {String("Rate: ") + NRF_RATE_NAMES[state.nrfRate], []() {
                 state.nrfRate = (state.nrfRate + 1) % 3;
                 save();
             }},
            {String("Channel: ") + String(state.nrfChannel), [chIdx]() {
                 state.nrfChannel = NRF_CHANNELS[(chIdx + 1) % (sizeof(NRF_CHANNELS) / sizeof(NRF_CHANNELS[0]))];
                 save();
             }},
            {"Hardware check", []() { nrfDiagnostics(); }},
            {"Restore defaults", []() { resetNrf(); }},
            {"Back", []() {}},
        };
        int selected = loopOptions(items, MENU_TYPE_SUBMENU, "nRF24 Control");
        if (selected == -1 || selected == static_cast<int>(items.size() - 1)) return;
    }
}

} // namespace RadioControl
