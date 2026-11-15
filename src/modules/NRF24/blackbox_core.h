#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace NrfBlackBox {
constexpr size_t Channels = 84; // 2400..2483 MHz, inclusive.
constexpr size_t HistoryFrames = 12;
constexpr uint32_t FrameMs = 1000;
constexpr uint32_t MaxLogBytes = 16u * 1024u * 1024u;
constexpr uint16_t ListenUs = 200; // Above the 130 us RX settling + 40 us AGC requirement.

struct Frame {
    uint32_t startMs = 0;
    uint32_t spanMs = 0;
    std::array<uint16_t, Channels> samples{};
    std::array<uint16_t, Channels> hits{};
    bool marker = false;
    bool rise = false;
    bool saturated = false;
    void sample(size_t ch, bool detected) {
        if (ch >= Channels) return;
        if (samples[ch] == std::numeric_limits<uint16_t>::max()) { saturated = true; return; }
        ++samples[ch];
        if (detected) ++hits[ch];
    }
    unsigned percent(size_t ch) const {
        return ch < Channels && samples[ch] ? unsigned(hits[ch]) * 100u / samples[ch] : 0;
    }
    size_t peak() const {
        size_t best = 0;
        for (size_t ch = 1; ch < Channels; ++ch) if (percent(ch) > percent(best)) best = ch;
        return best;
    }
    bool hasSamples() const {
        for (auto n : samples) if (n) return true;
        return false;
    }
};

class Recorder {
    std::array<Frame, HistoryFrames> history{};
    size_t next = 0, count_ = 0;
public:
    Frame current;
    explicit Recorder(uint32_t now) { current.startMs = now; }
    bool due(uint32_t now) const { return uint32_t(now - current.startMs) >= FrameMs; }
    size_t count() const { return count_; }
    const Frame *ago(size_t age) const {
        return age < count_ ? &history[(next + HistoryFrames - 1 - age) % HistoryFrames] : nullptr;
    }
    const Frame &finish(uint32_t now) {
        current.spanMs = uint32_t(now - current.startMs);
        const Frame *previous = ago(0);
        if (previous && !current.saturated && !previous->saturated) {
            for (size_t ch = 0; ch < Channels; ++ch) {
                if (current.samples[ch] >= 3 && previous->samples[ch] >= 3 &&
                    current.percent(ch) >= 40 && previous->percent(ch) < 20) {
                    current.rise = true;
                    break;
                }
            }
        }
        history[next] = current;
        const size_t saved = next;
        next = (next + 1) % HistoryFrames;
        if (count_ < HistoryFrames) ++count_;
        current = Frame{};
        current.startMs = now;
        return history[saved];
    }
};

inline bool fitsLog(size_t written, size_t bytes) {
    return written <= MaxLogBytes && bytes <= MaxLogBytes - written;
}
} // namespace NrfBlackBox
