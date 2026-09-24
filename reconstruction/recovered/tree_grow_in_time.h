// Recovered semantics of -[Tree growInTimeSinceSaved:]
// (0x004c2568, 546 words) — the tree GROWTH STATE MACHINE, read-side
// counterpart of the b4d/b4e loader gates.
//
// Decoded from the pinned ARM binary (batch b3n) and verified bit-exactly
// against the original instructions executed under Unicorn
// (tools/test_tree_grow_arm.py, batch b4g — STAGE 1: the nil-tile path).
//
//   if ([self isStaticTree]) return            (sxtb on the stub result)
//   flag = false
//   if (self.dead == 0) {
//     elapsed = [world worldTime] - timeSinceSaved          (f64)
//     if ((double)age + elapsed < (double)maxAge) {          // else old path
//       timeToGrow = 1.0f - growthCounter                   // FIRST iteration
//       loop {
//         if (!(height < maxHeight && elapsed > 0.0)) break; // tail
//         // STAGE 1 FIXTURE: the tile lookup (bl 0xa12f24) returns nil, so
//         // chance stays 0.5f; the tile-record/PRNG block is a stage-2 slice.
//         chance = 0.5f
//         hpct = ((1.0f - (float)height/(float)maxHeight) + 0.2f) * 0.5f
//         denom = 0.005 * (double)hpct * (double)growthRate * (double)chance
//         growthTime = (float)((double)timeToGrow / denom)   (f32 result)
//         if (growthTime < elapsed) {          // (double)growthTime vs f64
//           elapsed  = elapsed - (double)growthTime          (f64)
//           age      = age + growthTime                      (f32 add)
//           growthCounter = 0.0f
//           [self incrementHeight]                           // may mutate
//           maxHeightReached = max(height, maxHeightReached) // AFTER reload
//           [self updateGrowth:1]  (+ spilled 1.0f = next timeToGrow)
//           timeToGrow = 1.0f; flag = true; continue;        // loop re-entry
//         } else {
//           eOverG = (float)(elapsed / (double)growthTime)
//           growthCounter += (1.0f - growthCounter) * eOverG   (f32)
//           elapsed = -1.0; break;                            // tail
//         }
//       }
//     } else if ([self isGrowingInCompost]) {
//       age = maxAge;
//     } else {
//       [dynamicWorld sowTreeNearParent:self adult:1
//                        adultMaxAge:(float)(elapsed - (double)(maxAge-age))]
//       dead = 1;
//       timeDied = timeSinceSaved + (double)maxAge - (double)age  (f64)
//       [self removeAllOwnedTiles:0]
//     }
//   }
//   if (flag) return;
//   if (dead != 0) return;
//   [self updateGrowth:0]
//
// Loop re-entry (0x4c26bc) recomputes timeToGrow NOWHERE: the first
// iteration uses 1-growthCounter, later iterations reuse the spilled 1.0f.
// The maxAge check runs ONCE per call (not per iteration). All comparisons
// are IEEE-754 with the exact vcvt/vsub/vadd/vmul/vdiv step order above;
// NaN takes the bpl branches (old path / partial path / grow-block skip).
//
// This module is a contract for the stage-1 slice only. The tile lookup,
// the 0x1c3728 PRNG chain, the real incrementHeight/updateGrowth/sowTree
// bodies and any device acceptance live outside it; incrementHeight's
// possible height/maxHeightReached mutations arrive as scripted inputs.
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kTreeGrowImageSize = 120;
inline constexpr std::size_t kTreeGrowMaxTrace = 32;

// Trace codes (enum class TreeGrowCall) live in generated/trace_codes.h —
// single source of truth: reconstruction/reverse-v3/native/trace_schemas.json
// via tools/gen_trace_codes.py. The b4f collision bug: two hand-maintained
// tables (Python enumerate + C++ enum) silently drifted.

struct TreeGrowInputs {
    // Stub-returned values.
    std::uint8_t is_static_tree = 0;
    std::uint8_t is_growing_in_compost = 0;
    double world_time = 0.0;
    // Method argument (softfp r2:r3).
    double time_since_saved = 0.0;
    // Instance ivars (initial image).
    std::uint8_t dead = 0;
    float max_age = 0.0f;
    float age = 0.0f;
    float growth_counter = 0.0f;
    float growth_rate = 0.0f;
    std::int32_t max_height = 0;
    std::int32_t height = 0;
    std::int32_t max_height_reached = 0;
    std::int32_t pos_x = 0;  // observed as the tile-lookup argument
    std::int32_t pos_y = 0;
    // Fixture tokens written to world@4 / dynamicWorld@8 (the ARM harness
    // puts the same pointers there; the contract echoes them into the
    // image so the two sides compare byte-for-byte).
    std::uint32_t world_token = 0;
    std::uint32_t dynamic_world_token = 0;
    // incrementHeight script: new height / maxHeightReached after each
    // message (-1 = leave unchanged). Lets the fixture drive the
    // height >= maxHeight loop-exit without a real incrementHeight body.
    std::int32_t height_after_increment = -1;
    std::int32_t max_height_reached_after_increment = -1;
};

struct TreeGrowResult {
    std::uint8_t image[kTreeGrowImageSize] = {};
    // (code, arg) pairs; arg carries the adultMaxAge float bits for
    // SowTreeNearParent and the spilled 1.0f bits for UpdateGrowthAdult.
    std::vector<std::pair<TreeGrowCall, std::uint32_t>> calls;
};

TreeGrowResult tree_grow_in_time_since_saved(const TreeGrowInputs& inputs);

}  // namespace blockheads::recovered
