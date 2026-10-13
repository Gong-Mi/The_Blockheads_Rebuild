// Recovered contract: the DynamicWorld simulation-step family (E40).
//
// Evidence (reverse-v3 level A):
//   - -[DynamicWorld simulate:] (imp 0x008c9740): the delta float arrives in
//     r2 (`vmov s0, r2`); the family step divides it by 8.0f
//     (`vmov.f32 s2, 8; vdiv.f32 s0, s0, s2` @0x8c9760-0x8c9778); the loop
//     runs `for arg in 0..8` (`cmp r0, 8` @0x8c9790) calling ffe234e8 per
//     family (@0x8c97a8-0x8c97e8) with the divided float and an sxtb flag;
//     the counter increments at 0x8c97f0.
//   - -[DynamicWorld update:accurateDT:] (imp 0x008c9810): both floats are
//     passed to the SAME ffe234e8 call (one site @0x8c983c-0x8c9888) with the
//     paired vmov/vstr - the update variant, no /8 divisor.
//   - -[DynamicWorld finishSimulating] (imp 0x008cbc8c): enumerates the
//     ffffe4f8 blockheads collection and runs an inner `cmp r0, 8` slot loop
//     per blockhead calling ffe234f8 (@0x8cbdec).
//
// This module models ONLY the numeric/loop contracts: the /8.0f family step
// with its 8 iterations, the accurate-update single call and the 8-slot
// finisher. The ffe234e8/ffe234f8 callees are callbacks.
//
// Boundaries (do not promote beyond evidence):
//   - The divisor is exactly the 8.0f literal (`vmov.f32 s2, 8`); compiled
//     with -ffp-contract=off (the recovered-lane convention).
//   - The sxtb flag argument of the ffe234e8 call is caller-provided
//     (its origin was not established in the batch).
//   - The finisher's slot count 8 is the inner loop bound; the per-blockhead
//     slot semantics are opaque (callback).
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

namespace blockheads::recovered {

inline constexpr float kFamilyStepDivisor = 8.0f;
inline constexpr int kFamilyCount = 8;      // cmp r0, 8; for 0..8 (E40)
inline constexpr int kSlotCount = 8;        // finishSimulating inner cmp r0, 8 (E40)

// simulate: - dt / 8.0f per family, 8 families (E40 0x008c9740).
// The callback receives (family index, family dt, pause flag).
inline void simulateStep(float dt, bool pauseFlag,
                         const std::function<void(int, float, bool)>& familyStep) {
    const float familyDT = dt / kFamilyStepDivisor;
    for (int family = 0; family < kFamilyCount; ++family) {
        familyStep(family, familyDT, pauseFlag);
    }
}

// update:accurateDT: - both floats to the same family call (E40 0x008c9810).
// The original issues ONE ffe234e8 site; preserved here.
inline void accurateUpdate(float dt, float accurateDT, bool pauseFlag,
                           const std::function<void(float, float, bool)>& update) {
    update(dt, accurateDT, pauseFlag);
}

// finishSimulating - per blockhead, the 8-slot inner loop (E40 0x008cbc8c).
inline void finishBlockheadSlots(std::size_t blockheadCount, const std::function<void(std::size_t, int)>& slotFinalize) {
    for (std::size_t blockhead = 0; blockhead < blockheadCount; ++blockhead) {
        for (int slot = 0; slot < kSlotCount; ++slot) {
            slotFinalize(blockhead, slot);
        }
    }
}

}  // namespace blockheads::recovered
