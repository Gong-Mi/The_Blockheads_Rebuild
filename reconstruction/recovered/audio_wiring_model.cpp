#include "audio_wiring_model.h"

#include <string_view>

namespace blockheads::recovered::audio {
namespace {

// The guards here are content invariants, deliberately not restatements of the declared bounds.
// A std::array<T, N> with fewer initializers than N is legal: the tail is value-initialised. So
// "static_assert(kNotYetReferenced.size() == 94)" could never fail - it re-states the declaration - and the
// real hazard, someone removing an entry from the list without lowering the bound, went unguarded. That is
// exactly what happened when fanfare.wav was wired: the header said 93 while this file still asserted 94, and
// CI's build failed with "static assertion failed" pointing at a number rather than at the mismatch. These
// predicates fail on a short list, which is the condition that actually needs catching, and the bound is now
// written in one place.
constexpr bool everyWiringNamed() {
    for (const Wiring& w : kAudioWiring) {
        if (w.method.empty() || w.sound.empty()) return false;
    }
    return true;
}

constexpr bool everyUnwiredNamed() {
    for (std::string_view s : kNotYetReferenced) {
        if (s.empty()) return false;
    }
    return true;
}

static_assert(!kAudioWiring.empty());
static_assert(!kNotYetReferenced.empty());
static_assert(everyWiringNamed(), "a short initializer list leaves empty entries: the declared bound no longer matches the entries");
static_assert(everyUnwiredNamed(), "a short initializer list leaves empty entries: the declared bound no longer matches the entries");

}  // namespace
}  // namespace blockheads::recovered::audio
