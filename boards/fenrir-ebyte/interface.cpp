#include "core/powerSave.h"
#include "core/utils.h"
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

    const uint8_t chipSelects[] = {27, 26, 5, 33, 15};
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
    bruceConfigPins.rfModule = CC1101_SPI_MODULE;
    if (bruceConfigPins.rfFreq < 425.0f || bruceConfigPins.rfFreq > 450.5f)
        bruceConfigPins.rfFreq = 433.92f;

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
    // Use touch IRQ instead of GPIO0; GPIO0 controls E07 RX amplifier.
    esp_sleep_enable_ext0_wakeup(GPIO_NUM_36, LOW);
    esp_deep_sleep_start();
}

void checkReboot() {}
