#pragma once
#include <stdint.h>

namespace recon {
namespace audio {
enum class Cue : uint8_t { Lost, Reacquired, Handoff, Ambiguous, Mutation };
bool enable(bool on);
void stop();
bool enabled();
void cue(Cue value);
void proximity(float filteredRssi, float jitter, bool fresh, uint32_t now);
} // namespace audio
} // namespace recon
