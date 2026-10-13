// Recovered contract: the DynamicWorld sound accumulator gate
// (E24 free-block sound bump / E42 crystal player / E43 elevator player).
//
// Evidence (reverse-v3 level A):
//   - The ffffe5a4 float member is the shared sound accumulator:
//       * E24's createFreeBlockAtPosition:ofType:... bumps it (the
//         `freeBlockSoundDelay` family) - 0x008ddc78;
//       * E42's playTimeCrystalReceivedSoundAtPos: (0x008de650) reads it
//         (`vldr s2, [r0]` @0x8de690), compares against 1.0
//         (`vmov.f32 s0, 1; vcmpe.f32 s2, s0` @0x8de668-0x8de694) and - for a
//         value BELOW 1.0 (the bpl take at @0x8de6a4 exits on >= 1.0) -
//         plays the 0xfff34074 sound via class ffe2af10 + ffe232c8 with the
//         vcvt int->float position maths;
//       * E43's openElevatorAtPos: (0x008ebd50) is the same sound-player
//         shape with the 0xfff34174 string - the shared "play at position"
//         helper (ffe23480).
//
// This module models ONLY the accumulator gate: the value, the >= 1.0 exit
// rule (vcmpe/bpl) and the play-callback contract; sound playing itself is a
// callback.
//
// Boundaries (do not promote beyond evidence):
//   - The gate is modelled on the finite-value domain; the vcmpe NaN/
//     unordered behavior is NOT modelled (no evidence read for it).
//   - The accumulator increase amount (who bumps it and by how much) belongs
//     to the free-block sound sites and is caller-side here.
//   - The 1.0f literal is the pinned compare constant (bit-checked in tests
//     as 0x3f800000).
#pragma once

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

inline constexpr float kSoundGateThreshold = 1.0f;   // `vmov.f32 s0, 1` (E42)
inline constexpr std::int64_t kAccumulatorSlot = 0x00ffffe5a4;  // the shared float member

class SoundAccumulator {
public:
    // The gate: a value >= 1.0 exits (the bpl take @0x8de6a4); otherwise the
    // caller may play.
    static bool passesGate(float value) { return !(value >= kSoundGateThreshold); }

    // playTimeCrystalReceivedSoundAtPos: / openElevatorAtPos: shape: read the
    // accumulator, gate, then play via the callback. Returns true when the
    // play callback ran.
    bool playAtPosIfAllowed(float positionX, float positionY, const std::function<void(float, float)>& play) {
        if (!passesGate(value_)) {
            return false;
        }
        play(positionX, positionY);
        return true;
    }

    void add(float amount) { value_ += amount; }
    void setValue(float value) { value_ = value; }
    float value() const { return value_; }

private:
    float value_ = 0.0f;
};

}  // namespace blockheads::recovered
