#ifndef BLE_API_HPP
#define BLE_API_HPP
#if !defined(LITE_VERSION)
#include "services/BLESerialService.h"
#include "services/BatteryService.hpp"

class BLE_API {
public:
    BLE_API();
    bool setup();
    bool isActive() const { return active == this; }
    void end();
    void update_mtu(uint16_t mtu);
    void on_disconnect();

private:
    static BLE_API *active;
    static void detachActive();
    void detach();
    NimBLEServer *pServer = nullptr;
    BatteryService battery_service;
    BLESerialService serial_service;
};
#endif
#endif // BLE_API_HPP
