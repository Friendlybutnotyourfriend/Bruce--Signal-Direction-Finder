#pragma once
#include <stddef.h>

namespace RfLab {
constexpr unsigned GlitchFilterNs = 3000;
constexpr size_t CaptureSymbols = 128;
// A full buffer cannot establish whether the transmitter ended the frame.
inline bool captureClipped(size_t received, size_t capacity) {
    return received >= capacity;
}
}
