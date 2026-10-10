// Contract tests for the recovered sound-accumulator gate (E24/E42/E43).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_sound_accumulator.cpp
//       reconstruction/recovered/sound_accumulator.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "sound_accumulator.h"

#include <cassert>
#include <cstdint>
#include <cstring>

using blockheads::recovered::kSoundGateThreshold;
using blockheads::recovered::SoundAccumulator;

static void test_threshold_bits() {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &kSoundGateThreshold, sizeof(bits));
    assert(bits == 0x3f800000u);  // IEEE-754 1.0f
}

static void test_gate_boundaries() {
    // below 1.0 -> allowed; at/above 1.0 -> the bpl exit.
    assert(SoundAccumulator::passesGate(0.0f));
    assert(SoundAccumulator::passesGate(0.999f));
    assert(SoundAccumulator::passesGate(0.5f));
    assert(!SoundAccumulator::passesGate(1.0f));
    assert(!SoundAccumulator::passesGate(1.5f));
    assert(!SoundAccumulator::passesGate(100.0f));
}

static void test_play_callback_gating() {
    SoundAccumulator acc;
    int plays = 0;
    float gotX = 0.0f;
    float gotY = 0.0f;
    // starts at 0.0 -> allowed to play with the position forwarded.
    assert(acc.playAtPosIfAllowed(4.0f, 9.0f, [&](float x, float y) {
        ++plays;
        gotX = x;
        gotY = y;
    }));
    assert(plays == 1);
    assert(gotX == 4.0f && gotY == 9.0f);
    // bump to >= 1.0: gated.
    acc.add(1.0f);
    assert(!acc.playAtPosIfAllowed(1.0f, 1.0f, [&](float, float) { ++plays; }));
    assert(plays == 1);
    // reset below: allowed again.
    acc.setValue(0.25f);
    assert(acc.playAtPosIfAllowed(0.0f, 0.0f, [&](float, float) { ++plays; }));
    assert(plays == 2);
}

static void test_accumulation() {
    SoundAccumulator acc;
    assert(acc.value() == 0.0f);
    acc.add(0.5f);
    acc.add(0.25f);
    assert(acc.value() == 0.75f);
    assert(SoundAccumulator::passesGate(acc.value()));
    acc.add(0.25f);
    assert(acc.value() == 1.0f);
    assert(!SoundAccumulator::passesGate(acc.value()));
}

int main() {
    test_threshold_bits();
    test_gate_boundaries();
    test_play_callback_gating();
    test_accumulation();
    return 0;
}
