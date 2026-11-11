#pragma once

#include <Arduino.h>

class RF24;

namespace RadioControl {

// Profiles are opt-in so existing Bruce tools preserve their current defaults.
// Values describe chipset settings, NOT calibrated antenna output/EIRP.
struct Profile {
    bool ccEnabled = false;
    int8_t ccPowerDbm = -10;
    uint8_t ccModulation = 2; // ASK/OOK
    uint8_t ccRateIndex = 4;  // 50 kBaud

    bool nrfEnabled = false;
    uint8_t nrfPower = 0;    // RF24_PA_MIN
    uint8_t nrfRate = 1;     // 1 Mbps
    uint8_t nrfChannel = 76; // 2476 MHz
};

struct ReceiveSettings {
    float frequencyMHz = 433.92f;
    uint8_t modulation = 2;
    float rateKBaud = 4.8f;
    float bandwidthKHz = 203.125f;
};
// Session-only settings: never enable persistent TX overrides.
bool validReceiveSettings(const ReceiveSettings &settings);
bool applyReceiveSettings(const ReceiveSettings &settings);
const Profile &profile();
void ccMenu();
void nrfMenu();
void applyCcModulationAndRate();
void applyCcTxPower();
void applyNrfSettings(RF24 &radio);
} // namespace RadioControl
