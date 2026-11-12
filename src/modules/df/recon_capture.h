#pragma once
#include <Arduino.h>
#include <atomic>
#include <FS.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

namespace recon {
struct CaptureRow {
    uint64_t us = 0;
    uint32_t ms = 0;
    char address[18]{};
    uint8_t addressType = 0, advType = 0, mode = 0, decision = 0, score = 0;
    int16_t rssi = -127;
    uint16_t length = 0, originalLength = 0, advLength = 0;
    uint8_t payload[256]{};
    uint8_t sid = 255, primaryPhy = 0, secondaryPhy = 0, dataStatus = 0;
};
class Capture {
    QueueHandle_t queue = nullptr;
    File file;
    std::atomic<bool> enabled{false};
    std::atomic<uint32_t> dropped{0}, truncated{0};
    uint32_t written = 0, lastFlush = 0;
    bool failed = false;
    String path;
    void line(const String &text);
public:
    bool begin(const char *mode, const char *target);
    void push(const CaptureRow &row);
    void drain(unsigned limit = 16);
    void event(const char *kind, const char *detail = "");
    void end();
    String status() const;
    bool active() const { return enabled.load(); }
};
extern Capture capture;
}
