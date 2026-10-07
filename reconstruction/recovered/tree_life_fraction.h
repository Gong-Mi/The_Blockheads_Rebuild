// Recovered contract: the tree-life density kernel from
// -[DynamicWorld getTreeLifeFractionForPos:] (E23 world_update batch).
//
// Evidence (reverse-v3 level A; world_update.json / WORLD_UPDATE.md):
//   - getTreeLifeFractionForPos: (imp 0x008f9b70, 1160 words, fully read):
//     * a random gate against the half-range bound 2^31 (the batch notes
//       record the compare value as 2**31);
//     * a radius ladder starting at 2.0 and scaling by 5 (the recorded
//       literals 10/50/250 appear on the scaled path);
//     * the decay divisor 32.0;
//     * mode B: an all-tree weighted density field
//         sum over tree tiles of
//           max(0, 1 - |dx| / 32) * max(0, 1 - |dy| / 32) * (ffe236fc / 32)
//       i.e. a separable bilinear tent with the per-class weight supplied by
//       the ffe236fc scalar (the /32 normalisation is part of the field);
//     * the per-class weight table at 0xE4AA60 (11 classes; the table
//       contents are NOT resolved in this slice).
//
// This module models ONLY the kernel arithmetic: the tent contribution, the
// decay divisor, the 2^31 gate predicate and the weighted sum. The radius
// ladder and per-class weights are exposed as caller-provided inputs.
//
// Boundaries (do not promote beyond evidence):
//   - The tent is modelled as max(0, 1 - |d| / 32) per axis and the product
//     per tile (separable form recorded in the batch notes).
//   - The weight normalisation (ffe236fc / 32) is modelled as a caller
//     provided weight already in the same domain; the slice divides by the
//     same 32.0f divisor for parity with the recorded expression.
//   - The radius ladder (2.0, x5, 10/50/250) is recorded as constants but not
//     wired into the kernel; the selection logic stays caller-side.
//   - Compiled with -ffp-contract=off (recovered-lane convention); no runtime
//     equivalence claim (no differential oracle).
#pragma once

#include <cstdint>

namespace blockheads::recovered {

inline constexpr float kDecayDivisor = 32.0f;   // the decay divisor (E23)
inline constexpr float kRadiusBase = 2.0f;      // the radius ladder start (E23)
inline constexpr float kRadiusScale = 5.0f;     // the x5 scaling (E23)
inline constexpr std::uint32_t kRandomGateHalf = 0x80000000u;  // 2^31 gate (E23)

// The random gate predicate: a draw below the half range passes.
constexpr bool passesRandomGate(std::uint32_t draw) { return draw < kRandomGateHalf; }

// One axis of the bilinear tent: max(0, 1 - |d| / 32).
inline float tentAxis(int d) {
    const float magnitude = d < 0 ? -static_cast<float>(d) : static_cast<float>(d);
    const float value = 1.0f - magnitude / kDecayDivisor;
    return value > 0.0f ? value : 0.0f;
}

// One tile's tent contribution: the 2D product.
inline float tileContribution(int dx, int dy) {
    return tentAxis(dx) * tentAxis(dy);
}

// One tile's weighted term: contribution * (weight / 32) - matching the
// recorded (ffe236fc / 32) normalisation for weights in the ffe236fc domain.
inline float weightedTerm(int dx, int dy, float weight) {
    return tileContribution(dx, dy) * (weight / kDecayDivisor);
}

}  // namespace blockheads::recovered
