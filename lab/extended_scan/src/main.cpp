// Standalone, receive-only stack probe. Not a Bruce replacement or Launcher release image.
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

struct Report {
    char address[18];
    int rssi;
    bool legacy;
    uint8_t sid, primary, secondary, status;
    uint16_t length;
};
QueueHandle_t reports;
uint32_t dropped = 0;
class Callbacks : public NimBLEScanCallbacks {
    void onResult(const NimBLEAdvertisedDevice *d) override {
        Report r{};
        strncpy(r.address, d->getAddress().toString().c_str(), 17);
        r.rssi = d->getRSSI(); r.legacy = d->isLegacyAdvertisement();
        r.sid = d->getSetId(); r.primary = d->getPrimaryPhy(); r.secondary = d->getSecondaryPhy();
        r.status = d->getDataStatus(); r.length = d->getPayload().size();
        if (xQueueSend(reports, &r, 0) != pdTRUE) __atomic_fetch_add(&dropped, 1, __ATOMIC_RELAXED);
    }
} callbacks;

void setup() {
    Serial.begin(115200);
    delay(2000);
    Serial.println("EXTENDED SCAN PROBE: compile success does not prove controller/runtime support");
    reports = xQueueCreate(24, sizeof(Report));
    if (!reports) { Serial.println("Queue allocation failed"); return; }
    NimBLEDevice::init("Bruce passive scan probe");
    auto *scan = NimBLEDevice::getScan();
    scan->setScanCallbacks(&callbacks, true);
    scan->setMaxResults(0); scan->setActiveScan(false);
    scan->setInterval(100); scan->setWindow(90);
    scan->setPhy(NimBLEScan::SCAN_ALL);
    Serial.printf("Scan start (1M + Coded): %s\n", scan->start(0) ? "accepted" : "FAILED");
}
void loop() {
    Report r;
    if (reports && xQueueReceive(reports, &r, pdMS_TO_TICKS(50)) == pdTRUE)
        Serial.printf("%lu,%s,%d,legacy=%d,sid=%u,primary=%u,secondary=%u,status=%u,len=%u,dropped=%lu\n",
            static_cast<unsigned long>(millis()), r.address, r.rssi, r.legacy, r.sid, r.primary, r.secondary,
            r.status, r.length, static_cast<unsigned long>(__atomic_load_n(&dropped, __ATOMIC_RELAXED)));
    else delay(10);
}
