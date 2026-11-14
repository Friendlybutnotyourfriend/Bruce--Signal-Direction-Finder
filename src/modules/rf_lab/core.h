#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace RfLab {
struct Sample { uint32_t ms = 0; int16_t rssi = -127; };
template <size_t N> struct Ring {
    std::array<Sample, N> data{};
    size_t count = 0, next = 0;
    void push(Sample s) { data[next] = s; next = (next + 1) % N; if (count < N) ++count; }
    Sample at(size_t i) const { return data[(next + N - count + i) % N]; }
};

// A frozen quiet baseline avoids learning a sustained interferer as the new normal.
struct Detector {
    static constexpr size_t Learning = 128;
    std::array<int16_t, Learning> training{};
    size_t learned = 0;
    int threshold = -80;
    uint8_t consecutive = 0;
    bool latched = false;
    uint32_t quietSince = 0;
    bool quiet = false;
    bool add(Sample s) {
        if (learned < Learning) {
            training[learned++] = s.rssi;
            if (learned == Learning) {
                std::sort(training.begin(), training.end());
                threshold = std::min(-20, static_cast<int>(training[Learning / 4]) + 10);
            }
            return false;
        }
        if (s.rssi >= threshold) {
            quiet = false;
            if (consecutive < 2) ++consecutive;
            if (!latched && consecutive == 2) { latched = true; return true; }
        } else {
            consecutive = 0;
            if (s.rssi < threshold - 3) {
                if (!quiet) { quiet = true; quietSince = s.ms; }
                if (static_cast<uint32_t>(s.ms - quietSince) >= 500) latched = false;
            } else quiet = false;
        }
        return false;
    }
};

// Coarse pulse-duration distributions are evidence of repeatability, not device identity.
struct Evidence {
    std::array<uint32_t, 32> bins{};
    uint32_t frames = 0, pulses = 0, clipped = 0;
    void pulse(uint32_t us) {
        if (us < 20 || us >= 12000) return;
        size_t b = 0;
        uint32_t edge = 25;
        while (b + 1 < bins.size() && us > edge) { ++b; edge = edge * 5 / 4 + 1; }
        ++bins[b]; ++pulses;
    }
};
inline int similarity(const Evidence &a, const Evidence &b) {
    if (a.frames < 2 || b.frames < 2 || a.pulses < 32 || b.pulses < 32) return 0;
    double overlap = 0;
    for (size_t i = 0; i < a.bins.size(); ++i)
        overlap += std::min(double(a.bins[i]) / a.pulses, double(b.bins[i]) / b.pulses);
    // Broad noise distributions can also repeat. Concentration is a conservative filter,
    // not proof of valid frames, modulation, checksum, or protocol.
    auto concentrated = [](const Evidence &e) {
        auto sorted = e.bins;
        std::sort(sorted.begin(), sorted.end(), std::greater<uint32_t>());
        return double(sorted[0] + sorted[1] + sorted[2]) / e.pulses;
    };
    const double concentration = std::min(concentrated(a), concentrated(b));
    if (concentration < 0.55 || a.clipped || b.clipped) return 0;
    return static_cast<int>(100 * overlap * concentration);
}
} // namespace RfLab
