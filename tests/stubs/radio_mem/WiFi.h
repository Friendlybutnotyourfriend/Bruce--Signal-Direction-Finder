#pragma once
constexpr int WIFI_MODE_NULL = 0;
constexpr int WIFI_OFF = 0;
struct FakeWifi {
    int currentMode = WIFI_MODE_NULL;
    int getMode() const { return currentMode; }
    void mode(int value) { currentMode = value; }
};
struct FakeSerial {
    void println(const char *) {}
    template <typename... Args> void printf(const char *, Args...) {}
};
extern FakeWifi WiFi;
extern FakeSerial Serial;
inline void delay(unsigned) {}
