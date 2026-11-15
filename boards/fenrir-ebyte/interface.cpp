#include "core/display.h"
#include "core/powerSave.h"
#include "core/utils.h"
#include "modules/rf/rf_utils.h"
#include "hal/inputs/touch.h"
#include <Arduino.h>
#include <interface.h>

static DeviceTouch touchCfg() {
    DeviceTouch cfg;
    // rotation:        0      1      2      3
    const bool swapXY[4] = {true, false, true, false};
    const bool mirrorX[4] = {true, false, false, true};
    const bool mirrorY[4] = {false, false, true, true};
    for (int i = 0; i < 4; i++) {
        cfg.SwapXY[i] = swapXY[i];
        cfg.MirrorX[i] = mirrorX[i];
        cfg.MirrorY[i] = mirrorY[i];
    }
    return cfg;
}

static void wiredPins() {
    bruceConfigPins.outer_bus = {GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_27};
    bruceConfigPins.PN532_bus = {GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_17};
    bruceConfigPins.SDCARD_bus = {GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_5};
    bruceConfigPins.CC1101_bus = {GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_27, GPIO_NUM_22, GPIO_NUM_35};
    bruceConfigPins.NRF24_bus = {GPIO_NUM_18, GPIO_NUM_19, GPIO_NUM_23, GPIO_NUM_26, GPIO_NUM_16};
    // These generic defaults conflict with the integrated radios on this board.
    bruceConfigPins.i2c_bus = {};
    bruceConfigPins.sys_i2c = {};
    bruceConfigPins.badusb_bus = {};
    bruceConfigPins.irTx = -1;
    bruceConfigPins.irRx = -1;
    bruceConfigPins.rfTx = 22;
    bruceConfigPins.rfRx = 22;
    bruceConfigPins.rfModule = CC1101_SPI_MODULE;
    if (bruceConfigPins.rfFreq < 425.0f || bruceConfigPins.rfFreq > 450.5f)
        bruceConfigPins.rfFreq = 433.92f;
}

void _setup_gpio() {
    wiredPins();
    bruceConfigPins.rotation = 1;
    // GPIO0 is the E07 RX enable, not a user button.
    pinMode(FENRIR_E07_RX_EN, OUTPUT);
    pinMode(FENRIR_E07_TX_EN, OUTPUT);
    digitalWrite(FENRIR_E07_RX_EN, LOW);
    digitalWrite(FENRIR_E07_TX_EN, LOW);
    for (uint8_t cs : {27, 26, 17, 5, 33, 15}) {
        pinMode(cs, OUTPUT);
        digitalWrite(cs, HIGH);
    }
    pinMode(16, OUTPUT);
    digitalWrite(16, LOW);
    analogSetPinAttenuation(ANALOG_BAT_PIN, ADC_11db);
    bruceConfig.colorInverted = 0;
}

void _post_setup_gpio() {
    // A saved generic CYD profile must not reroute the soldered peripherals.
    wiredPins();
    hal_touch_init(touchCfg(), 0, false); // dedicated software SPI: 25/39/32/33
    bruceConfig.colorInverted = 0;
    tft.invertDisplay(false);
    ledcAttach(TFT_BL, TFT_BRIGHT_FREQ, TFT_BRIGHT_Bits);
}

void _setBrightness(uint8_t brightval) {
    const int duty = brightval >= 100 ? 255 :
        brightval == 75 ? 130 :
        brightval == 50 ? 70 :
        brightval == 25 ? 20 :
        brightval == 0 ? 0 : (brightval * 255) / 100;
    ledcWrite(TFT_BL, duty);
}


void InputHandler() {
    static uint32_t lastTouch = 0;
    if (millis() - lastTouch < 200 && !LongPress) return;
    BruceTouchPoint point;
    if (hal_touch_read(touchCfg(), point)) {
        lastTouch = millis();
        hal_touch_apply(point);
    }
}

void powerOff() {
    deinitRfModule();
    digitalWrite(16, LOW);
    esp_sleep_enable_ext0_wakeup(GPIO_NUM_36, LOW);
    esp_deep_sleep_start();
}

void checkReboot() {}

void fenrirRssiScan() {
    // Only scan within the E07 425-450.5 MHz front-end specification.
    constexpr int points = 52;
    constexpr float lowMHz = 425.0f;
    constexpr float stepMHz = 0.5f;
    if (!initRfModule("rx", lowMHz)) {
        displayError("E07 RX unavailable", true);
        return;
    }
    while (!check(EscPress)) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.setTextColor(bruceConfig.priColor, bruceConfig.bgColor);
        tft.drawCentreString("E07 RSSI 425-450.5 MHz", tftWidth / 2, 10, 1);
        const int bottom = tftHeight - 38;
        const int plotHeight = tftHeight - 76;
        tft.drawFastHLine(4, bottom, tftWidth - 8, TFT_DARKGREY);
        int strongest = -200;
        float strongestMHz = lowMHz;
        for (int i = 0; i < points; ++i) {
            if (check(EscPress)) break;
            const float mhz = lowMHz + i * stepMHz;
            setMHZ(mhz);
            delay(8);
            const int rssi = static_cast<int>(ELECHOUSE_cc1101.getRssi());
            if (rssi > strongest) {
                strongest = rssi;
                strongestMHz = mhz;
            }
            const int height = constrain(map(rssi, -120, -30, 0, plotHeight), 0, plotHeight);
            const int x = 4 + i * (tftWidth - 8) / points;
            tft.drawFastVLine(x, bottom - height, height, bruceConfig.priColor);
        }
        tft.drawString(String("Peak ") + String(strongestMHz, 1) + " MHz  " +
                       String(strongest) + " dBm", 8, tftHeight - 30, 1);
        tft.drawCentreString("Esc to exit", tftWidth / 2, tftHeight - 14, 1);
        delay(60);
    }
    deinitRfModule();
}
