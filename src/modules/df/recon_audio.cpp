#include "recon_audio.h"
#include "modules/others/audio.h"
#include <Arduino.h>
#include <globals.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>
#include <atomic>
#include <algorithm>
#include <cmath>

namespace recon {
namespace audio {
namespace {
struct Tone {
    uint16_t hz, durationMs;
    uint32_t epoch;
};
QueueHandle_t queue = nullptr;
TaskHandle_t worker = nullptr;
std::atomic<bool> active{false};
std::atomic<uint32_t> epoch{0};
uint32_t lastPulse = 0;

void playback(void *) {
    Tone tone;
    while (true) {
        if (xQueueReceive(queue, &tone, portMAX_DELAY) != pdTRUE) continue;
        if (!active.load() || tone.epoch != epoch.load() || !bruceConfig.soundEnabled) continue;
        if (isAudioPlaying()) continue;
#ifdef ES8311_CODEC
        // The ES8311 has no buzzer pin: playTone drives its codec over I2S.
        // Keep the blocking codec player off the BLE/UI thread.
        // UI input belongs to the scan task, not this background audio worker.
        playTone(tone.hz, tone.durationMs, 2, false);
#else
        _tone(tone.hz, tone.durationMs);
#endif
    }
}

bool initialise() {
#if !defined(ES8311_CODEC) && !defined(BUZZ_PIN) && !defined(HAS_NS4168_SPKR)
    return false;
#else
    if (queue && worker) return true;
    if (!queue) queue = xQueueCreate(8, sizeof(Tone));
    if (!queue) return false;
    if (xTaskCreate(playback, "HuginnAudio", 6144, nullptr, 1, &worker) != pdPASS) {
        vQueueDelete(queue);
        queue = nullptr;
        worker = nullptr;
        return false;
    }
    return true;
#endif
}

void push(uint16_t hz, uint16_t durationMs) {
    if (!active.load() || !queue) return;
    const Tone command{hz, durationMs, epoch.load()};
    xQueueSend(queue, &command, 0); // Drop excess audio; never block scan/UI.
}
} // namespace

bool enable(bool on) {
    if (on && (!bruceConfig.soundEnabled || !initialise())) return false;
    active.store(on);
    ++epoch;
    lastPulse = 0;
    if (queue) xQueueReset(queue);
    return on;
}
void stop() { enable(false); }
bool enabled() { return active.load() && bruceConfig.soundEnabled; }

void cue(Cue value) {
    if (!enabled()) return;
    if (queue) xQueueReset(queue); // Alerts override queued proximity chirps.
    switch (value) {
        case Cue::Lost:       push(640, 100); push(360, 140); break;
        case Cue::Reacquired: push(670, 80);  push(1100, 110); break;
        case Cue::Handoff:    push(820, 90);  push(820, 90); break;
        case Cue::Ambiguous:  push(300, 170); break;
        case Cue::Mutation:   push(1260, 65); break;
    }
}
void proximity(float rssi, float jitter, bool fresh, uint32_t now) {
    if (!enabled() || !fresh || jitter > 6.0f) return;
    const float level = std::max(0.0f, std::min(1.0f, (rssi + 95.0f) / 60.0f));
    const uint32_t interval = static_cast<uint32_t>(950.0f - level * 700.0f);
    if (lastPulse && static_cast<uint32_t>(now - lastPulse) < interval) return;
    // Always anchor to the time of the actual attempt, not a packet callback.
    lastPulse = now;
    push(static_cast<uint16_t>(520.0f + level * 860.0f), 70);
}
} // namespace audio
} // namespace recon
