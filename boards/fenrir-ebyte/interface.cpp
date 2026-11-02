#include "core/display.h"
#include "core/powerSave.h"
#include "core/utils.h"
#include "modules/rf/rf_utils.h"
#include <Arduino.h>
#include <interface.h>
#include "CYD28_TouchscreenR.h"

// Dedicated software-SPI XPT2046: SCK25, MISO39, MOSI32, CS33, IRQ36.
CYD28_TouchR touch(320, 240);
SPIClass touchSPI;

void _setup_gpio() {
    // GPIO0 is a boot strap: only drive it after firmware has started.
    pinMode(FENRIR_E07_RX_EN, OUTPUT);
    pinMode(FENRIR_E07_TX_EN, OUTPUT);
    digitalWrite(FENRIR_E07_RX_EN, LOW);
    digitalWrite(FENRIR_E07_TX_EN, LOW);

    const uint8_t chipSelects[] = {27, 26, 17, 5, 33, 15};
    for (uint8_t cs : chipSelects) {
        pinMode(cs, OUTPUT);
        digitalWrite(cs, HIGH);
    }
    touch.begin();
    bruceConfig.colorInverted = 0;
}

void _post_setup_gpio() {
    // Enforce physical pin assignment even when a previous CYD pins file exists.
    bruceConfigPins.CC1101_bus.sck = GPIO_NUM_18;
    bruceConfigPins.CC1101_bus.miso = GPIO_NUM_19;
    bruceConfigPins.CC1101_bus.mosi = GPIO_NUM_23;
    bruceConfigPins.CC1101_bus.cs = GPIO_NUM_27;
    bruceConfigPins.CC1101_bus.io0 = GPIO_NUM_22;
    bruceConfigPins.CC1101_bus.io2 = GPIO_NUM_35;
    bruceConfigPins.NRF24_bus.sck = GPIO_NUM_18;
    bruceConfigPins.NRF24_bus.miso = GPIO_NUM_19;
    bruceConfigPins.NRF24_bus.mosi = GPIO_NUM_23;
    bruceConfigPins.NRF24_bus.cs = GPIO_NUM_26;
    bruceConfigPins.NRF24_bus.io0 = GPIO_NUM_16;
    // Reassert shared SD/radio SPI if a saved pin profile came from a different CYD.
    bruceConfigPins.SDCARD_bus.sck = GPIO_NUM_18;
    bruceConfigPins.SDCARD_bus.miso = GPIO_NUM_19;
    bruceConfigPins.SDCARD_bus.mosi = GPIO_NUM_23;
    bruceConfigPins.SDCARD_bus.cs = GPIO_NUM_5;
    bruceConfigPins.rfModule = CC1101_SPI_MODULE;
    if (bruceConfigPins.rfFreq < 425.0f || bruceConfigPins.rfFreq > 450.5f)
        bruceConfigPins.rfFreq = 433.92f;

    // Saved Classic CYD themes may request inversion on the ST7789; enforce INVOFF.
    bruceConfig.colorInverted = 0;
    tft.invertDisplay(false);
    pinMode(TFT_BL, OUTPUT);
    ledcAttach(TFT_BL, TFT_BRIGHT_FREQ, TFT_BRIGHT_Bits);
    ledcWrite(TFT_BL, 255);
}

void _setBrightness(uint8_t brightval) {
    const int duty = brightval >= 100 ? 255 :
        brightval == 75 ? 130 :
        brightval == 50 ? 70 :
        brightval == 25 ? 20 :
        brightval == 0 ? 0 : (brightval * 255) / 100;
    ledcWrite(TFT_BL, duty);
}

void InputHandler(void) {
    static uint32_t lastTouch = 0;
    if (millis() - lastTouch < 200 && !LongPress) return;
    checkPowerSaveTime();
    if (!touch.touched()) return;
    auto t = touch.getPointScaled();
    NextPress = false;
    PrevPress = false;
    UpPress = false;
    DownPress = false;
    SelPress = false;
    EscPress = false;
    AnyKeyPress = false;
    NextPagePress = false;
    PrevPagePress = false;
    touchPoint.pressed = false;
    if (bruceConfigPins.rotation == 3) {
        t.y = (tftHeight + 20) - t.y;
        t.x = tftWidth - t.x;
    } else if (bruceConfigPins.rotation == 0) {
        const int16_t tmp = t.x;
        t.x = tftWidth - t.y;
        t.y = tmp;
    } else if (bruceConfigPins.rotation == 2) {
        const int16_t tmp = t.x;
        t.x = t.y;
        t.y = (tftHeight + 20) - tmp;
    }
    lastTouch = millis();
    if (wakeUpScreen()) return;
    AnyKeyPress = true;
    touchPoint.x = t.x;
    touchPoint.y = t.y;
    touchPoint.pressed = true;
    touchHeatMap(touchPoint);
}

void powerOff() {
    deinitRfModule();
    // Use touch IRQ instead of GPIO0; GPIO0 controls E07 RX amplifier.
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
