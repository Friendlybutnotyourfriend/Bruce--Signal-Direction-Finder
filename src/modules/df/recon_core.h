#pragma once
// Allocation-free association engine, shared by firmware and desktop replay.
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace recon {
inline uint32_t hash(const uint8_t *p, size_t n, uint32_t h = 2166136261u) {
    while (n--) { h ^= *p++; h *= 16777619u; }
    return h;
}
struct Field {
    uint32_t key = 0;
    uint8_t type = 0, len = 0, data[24]{};
    uint32_t stable = 0;
};
struct Signature {
    Field fields[16];
    uint8_t count = 0;
    bool malformed = false, truncated = false;
    uint32_t schema = 0;
};
inline Signature decode(const uint8_t *p, size_t n) {
    Signature s;
    for (size_t off = 0; off < n;) {
        const size_t len = p[off];
        if (!len) break;
        if (off + len + 1 > n) { s.malformed = true; break; }
        const uint8_t type = p[off + 1];
        const uint8_t *d = p + off + 2;
        const size_t dl = len - 1;
        off += len + 1;
        // Flags and TX power are not identity evidence.
        if (type == 1 || type == 10 || !dl) continue;
        const bool uuids = type >= 2 && type <= 7;
        const size_t width = type <= 3 ? 2 : type <= 5 ? 4 : 16;
        if (uuids && dl % width) { s.malformed = true; continue; }
        for (size_t pos = 0; pos < dl;) {
            if (s.count == 16) { s.truncated = true; break; }
            Field &f = s.fields[s.count++];
            f.type = uuids ? static_cast<uint8_t>(type | 1) : type == 8 ? 9 : type;
            const size_t size = uuids ? width : dl;
            size_t id = uuids ? width : type == 255 || type == 22 ? 2 : type == 32 ? 4 : type == 33 ? 16 : 0;
            if (id > size) { s.malformed = true; --s.count; break; }
            f.key = hash(&f.type, 1);
            if (id) f.key = hash(d + pos, id, f.key);
            f.len = static_cast<uint8_t>(std::min<size_t>(size, sizeof(f.data)));
            std::memcpy(f.data, d + pos, f.len);
            f.stable = (1u << f.len) - 1;
            // The bounded signature is separate from the full raw capture.
            pos += size;
        }
    }
    std::sort(s.fields, s.fields + s.count, [](const Field &a, const Field &b) {
        if (a.key != b.key) return a.key < b.key;
        if (a.len != b.len) return a.len < b.len;
        return std::memcmp(a.data, b.data, a.len) < 0;
    });
    // Duplicate keys make an unambiguous field pairing impossible: do not auto-associate.
    for (uint8_t i = 1; i < s.count; ++i)
        if (s.fields[i].key == s.fields[i-1].key) s.malformed = true;
    uint32_t h = 2166136261u;
    for (uint8_t i = 0; i < s.count; ++i) {
        const auto &f = s.fields[i];
        h = hash(reinterpret_cast<const uint8_t *>(&f.key), sizeof(f.key), h);
        h = hash(&f.len, 1, h);
    }
    s.schema = s.count ? h : 0;
    return s;
}
struct Packet {
    uint32_t ms = 0;
    char address[18]{};
    uint8_t addressType = 0;
    int rssi = -127;
    const uint8_t *payload = nullptr;
    size_t length = 0;
    bool response = false, truncated = false;
};
enum class Decision : uint8_t { Ignore, Current, Ambiguous, Handoff };
struct Match {
    char address[18]{};
    uint8_t addressType = 0, score = 0, hits = 0;
    uint32_t first = 0, last = 0;
    bool valid = false;
};
struct Status {
    char address[18]{};
    uint8_t addressType = 0, score = 0, hits = 0;
    uint32_t lastSeen = 0, timeout = 3000, handoffs = 0;
    bool ambiguous = false, tentative = false, locked = false;
};
class Association {
    Signature models[4]{};
    uint8_t modelCount = 0, nextModel = 0;
    Match candidates[8]{};
    char previous[18]{};
    uint8_t previousType = 0;
    float cadence = 0, deviation = 0, rssi = -127;
    uint32_t lastCadence = 0;
    uint32_t resumeTime = 0;
    bool grace = false;
    bool cadenceEstablished = false;
    Status state;
    static bool equalAddress(const Packet &p, const char *address, uint8_t type) {
        return p.addressType == type && std::strncmp(p.address, address, 17) == 0;
    }
    void learn(const Signature &s) {
        if (!s.count || s.malformed || s.truncated) return;
        for (uint8_t i = 0; i < modelCount; ++i) {
            auto &m = models[i];
            if (m.schema != s.schema) continue;
            for (uint8_t j = 0; j < m.count; ++j)
                for (uint8_t b = 0; b < m.fields[j].len; ++b)
                    if (m.fields[j].data[b] != s.fields[j].data[b]) m.fields[j].stable &= ~(1u << b);
            return;
        }
        models[nextModel] = s;
        nextModel = (nextModel + 1) % 4;
        if (modelCount < 4) ++modelCount;
    }
    int score(const Signature &s, int signal) const {
        if (!s.count || s.malformed || s.truncated) return 0;
        int best = 0;
        for (uint8_t k = 0; k < modelCount; ++k) {
            const auto &m = models[k];
            unsigned total = 0, same = 0, fields = 0, distinctive = 0, payloadEvidence = 0;
            for (uint8_t i = 0; i < m.count; ++i) {
                const auto &a = m.fields[i];
                const Field *b = nullptr;
                for (uint8_t j = 0; j < s.count; ++j)
                    if (s.fields[j].key == a.key) { b = &s.fields[j]; break; }
                if (!b || b->len != a.len) continue;
                ++fields;
                for (uint8_t j = 0; j < a.len; ++j) if (a.stable & (1u << j)) {
                    ++total;
                    if (a.data[j] == b->data[j]) {
                        ++same;
                        // Manufacturer/service payload after its identifier, or advertised name.
                        const int id = a.type == 255 || a.type == 22 ? 2 : a.type == 32 ? 4 : a.type == 33 ? 16 : 0;
                        if (a.type == 9 || ((a.type == 255 || a.type == 22 || a.type == 32 || a.type == 33) && j >= id))
                            ++distinctive;
                        if ((a.type == 255 || a.type == 22 || a.type == 32 || a.type == 33) && j >= id) ++payloadEvidence;
                    }
                }
            }
            if (total < 6 || distinctive < 4 || payloadEvidence < 4 || !fields) continue;
            const int content = static_cast<int>(same * 65 / total);
            const int coverage = static_cast<int>(fields * 20 / std::max(m.count, s.count));
            const int delta = static_cast<int>(std::fabs(rssi - signal));
            const int radio = delta <= 6 ? 15 : delta <= 12 ? 10 : delta <= 22 ? 4 : 0;
            best = std::max(best, content + coverage + radio);
        }
        return best;
    }
public:
    void reset(const Packet &p) {
        *this = Association();
        std::strncpy(state.address, p.address, 17);
        state.addressType = p.addressType;
        state.lastSeen = lastCadence = p.ms;
        rssi = p.rssi;
        if (!p.truncated) learn(decode(p.payload, p.length));
    }
    Status status(uint32_t now) const {
        Status out = state;
        out.ambiguous = false;
        for (const auto &c : candidates) if (c.valid && now - c.last <= state.timeout) out.ambiguous = true;
        return out;
    }
    void lock(bool value) { state.locked = value; }
    void resume(uint32_t now) {
        // A menu/GATT pause is missing coverage, not evidence of address rotation.
        lastCadence = resumeTime = now;
        grace = true;
        for (auto &c : candidates) c = Match{};
    }
    bool undo(uint32_t now) {
        if (!previous[0]) return false;
        std::memcpy(state.address, previous, 18);
        state.addressType = previousType;
        state.lastSeen = now - state.timeout - 1;
        state.tentative = false;
        state.locked = true; // Explicitly unlock before allowing another automatic change.
        state.score = state.hits = 0;
        previous[0] = 0;
        for (auto &c : candidates) c = Match{};
        return true;
    }
    Decision observe(const Packet &p) {
        if (equalAddress(p, state.address, state.addressType)) {
            if (p.response) return Decision::Current;
            grace = false;
            const uint32_t gap = p.ms - lastCadence;
            if (gap >= 40 && gap <= 60000) {
                cadenceEstablished = true;
                if (cadence == 0) cadence = static_cast<float>(gap);
                deviation += .2f * (std::fabs(gap - cadence) - deviation);
                cadence += .15f * (gap - cadence);
                state.timeout = static_cast<uint32_t>(std::max(3000.f, std::min(45000.f, cadence * 4 + deviation * 3)));
                lastCadence = p.ms;
            } else if (gap > 60000) lastCadence = p.ms;
            state.lastSeen = p.ms;
            rssi += .2f * (p.rssi - rssi);
            // Preserve original evidence until the user explicitly selects another target.
            if (!state.tentative && !p.truncated) learn(decode(p.payload, p.length));
            for (auto &c : candidates) c = Match{};
            return Decision::Current;
        }
        const uint32_t age = p.ms - state.lastSeen;
        // Discovery supplies only one observation. Learn an actual repeat before guessing rotations.
        if (!cadenceEstablished) return Decision::Ignore;
        if (grace && p.ms - resumeTime < state.timeout) return Decision::Ignore;
        if (state.locked || p.response || p.truncated || age < state.timeout || age > state.timeout * 4) return Decision::Ignore;
        const int points = score(decode(p.payload, p.length), p.rssi);
        if (points < 65) return Decision::Ignore;
        Match *slot = nullptr, *empty = nullptr;
        for (auto &c : candidates) {
            if (c.valid && p.ms - c.last > state.timeout) c = Match{};
            if (c.valid && equalAddress(p, c.address, c.addressType)) slot = &c;
            if (!c.valid && !empty) empty = &c;
        }
        if (!slot) {
            if (!empty) return Decision::Ambiguous; // Crowded table: abstain rather than evict rivals.
            slot = empty;
            slot->valid = true;
            std::strncpy(slot->address, p.address, 17);
            slot->addressType = p.addressType;
            slot->first = slot->last = p.ms;
            slot->hits = 1;
            slot->score = points;
        } else if (p.ms - slot->last >= 100) {
            if (slot->hits < 255) ++slot->hits;
            slot->score = static_cast<uint8_t>((slot->score * 2 + points) / 3);
            slot->last = p.ms;
        }
        Match *best = nullptr;
        int second = 0;
        for (auto &c : candidates) if (c.valid) {
            if (!best || c.score > best->score) { if (best) second = best->score; best = &c; }
            else second = std::max(second, static_cast<int>(c.score));
        }
        state.score = best ? best->score : 0;
        state.hits = best ? best->hits : 0;
        if (!best || best != slot || best->hits < 3 || p.ms - best->first < 600 || best->score < 85 || best->score - second < 10)
            return Decision::Ambiguous;
        std::memcpy(previous, state.address, 18);
        previousType = state.addressType;
        std::memcpy(state.address, best->address, 18);
        state.addressType = best->addressType;
        state.lastSeen = lastCadence = p.ms;
        state.tentative = true;
        ++state.handoffs;
        rssi = p.rssi;
        for (auto &c : candidates) c = Match{};
        return Decision::Handoff;
    }
};
struct AntennaComparison {
    float delta = 0, drift = 0, uncertainty = 0;
    bool reliable = false;
};
inline AntennaComparison compareAntenna(float before, float candidate, float after, float spread) {
    AntennaComparison r;
    r.delta = candidate - (before + after) / 2;
    r.drift = std::fabs(after - before);
    r.uncertainty = std::max(r.drift / 2, spread);
    r.reliable = before > -100 && candidate > -100 && after > -100 && before < -25 && candidate < -25 && after < -25 && r.drift <= 3 && spread <= 4;
    return r;
}
} // namespace recon
