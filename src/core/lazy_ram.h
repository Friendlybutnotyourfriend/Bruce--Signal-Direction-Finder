#pragma once

#include <esp_heap_caps.h>
#include <new>
#include <stddef.h>

// Storage for feature tables that must not sit in internal DRAM at boot.
// Cardputer ADV (ESP32-S3) starts Bruce from Launcher's OTA slot. The boot
// path is the same as stock 1.16.1, which fits its static data in internal
// RAM and then brings up the display and SD. Always-resident recon tables
// shrink that heap; an allocation failure there aborts and Launcher rolls
// the pending image back. PSRAM is preferred. Boards without it fall back
// to internal RAM, and only when the feature is actually opened.

template <typename T>
T *lazyRam(T *&slot) {
    if (slot) return slot;
    void *mem = heap_caps_malloc(sizeof(T), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!mem) mem = heap_caps_malloc(sizeof(T), MALLOC_CAP_8BIT);
    if (!mem) return nullptr;
    slot = new (mem) T();
    return slot;
}

template <typename T>
T *lazyRamArray(T *&slot, size_t count) {
    if (slot) return slot;
    if (count == 0) return nullptr;
    void *mem = heap_caps_malloc(sizeof(T) * count, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!mem) mem = heap_caps_malloc(sizeof(T) * count, MALLOC_CAP_8BIT);
    if (!mem) return nullptr;
    T *base = static_cast<T *>(mem);
    for (size_t i = 0; i < count; ++i) new (base + i) T();
    slot = base;
    return slot;
}
