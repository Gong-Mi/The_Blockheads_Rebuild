// Recovered contract: the NPC feed response (-[NPC feedByBlockhead:], E117).
//
// Evidence (reverse-v3 level A/B; imp 0x0064b398):
//   - The gate: a predicate on the blockhead argument (`blx ip` with sxtb
//     @0x64b3d8-0x64b3e4); false stores 0 and returns (@0x64b3e8-0x64b3f0).
//   - Fullness (the ffffd1a0 float): += 2700.0 with f32/f64 round-trips
//     (`vldr d1, [0x64b640]` = 2700.0; vcvt/vadd.f64/vcvt @0x64b420-0x64b42c)
//     then the clamp: compared in double against 8100.0
//     (`vldr d0, [0x64b638]` = 8100.0; `vcmpe d1, d0; ble` @0x64b444) and set
//     to 8100.0f when above (`vldr s0, [0x64b648]` + vstr @0x64b458-0x64b478).
//   - The u16 hunger field (ffffd198): `ldrh; cmp; ble` @0x64b494-0x64b4a0
//     skips at zero; the food value v = [self sel:arg] (`uxth` @0x64b4f8)
//     halved by integer division (`movw r1, 2; __aeabi_idiv` @0x64b500) and
//     folded min(field, v) (`cmp; bge` @0x64b52c-0x64b534), written back
//     `field -= min` (`sub; strh` @0x64b540-0x64b560).
//   - The state byte ffffcacc (`ldrsb; cmp` @0x64b564-0x64b570): non-zero
//     takes the blockhead payload path (the r0=1 / 0x2a3=675 / 675.0f write
//     chain @0x64b588-0x64b62c) and returns 1; zero falls into the fill path.
//   - The fill path: aux byte ffffd1a8 = 1 (@0x64b674); the ffffd1b4 slot is
//     read (old), set to 675.0f (`vldr s0, [0x64b64c]` @0x64b6c8) and when
//     old > 0 the code jumps straight to the tail (`vcmpe; bhi 0x64bcec`
//     @0x64b68c-0x64b690).
//   - The count stage: the per-blockhead key call @0x64b6e8 (selector cell
//     ffe1f71c; the 0 result becomes the static sentinel fff20b64
//     @0x64b708); the ffffd1c0 dict gate + read-modify-write
//     @0x64b714-0x64b8d4; count = read + 1 (`add r0, r0, 1` @0x64b868)
//     written back; `bl tameCountRequirementForNPCType` @0x64b8fc and
//     `cmp; blt` @0x64b904-0x64b908 (below the requirement goes to the tail);
//     the ffffd1c8 predicate (`sxtb; bne` @0x64b954-0x64b95c); the blockhead
//     enumeration with the max fold (`cmp; ble; str` keeping the max in
//     [fp,-0x48] @0x64bb48-0x64bb78); `cmp; ble 0x64bce4`
//     @0x64bc04-0x64bc08 - only count > max enters the set block
//     (@0x64bc0c-0x64bce0: the ffffd204 chain writes + a byte 1).
//   - The tail (0x64bcec): ffffd218 = 1 (@0x64bd18), the ffe1f6f4 call
//     (@0x64bd3c), the ffffc8b4/ffffc89c pair read (@0x64bd44-0x64bd64) and
//     the closing calls; returns 1. ALL success paths converge here
//     (0x64bce4/0x64bce8 are trampolines into 0x64bcec).
//
// Boundaries (do not promote beyond evidence):
//   - The receiver/selector cells (ffe1f6a0 for the food value, ffe1f71c,
//     ffe1f6f4, ffe1f714/718) stay callbacks; the requirement table body is
//     out of this slice.
//   - The blockhead payload path (state byte set) is modeled as one hook;
//     the sentinel fff20b64 semantics are not promoted beyond "replace a 0".
//   - The max fold only folds over qualifying elements (per-element sxtb
//     ffe1f61c @0x64ba94-0x64ba9c); the slice takes the folded value.
#pragma once

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

// The pinned constants (PIC-recomputed pool words).
inline constexpr double kFeedFullnessGain = 2700.0;  // pool 0x64b640
inline constexpr double kFeedFullnessMax = 8100.0;   // pools 0x64b638 / 648
inline constexpr float kFeedFillValue = 675.0f;      // pool 0x64b64c (0x2a3)
inline constexpr std::uint16_t kFeedHalveDivisor = 2; // `movw r1, 2`

// The world-side hooks. Every store access is a callback; empty hooks are
// skipped (the corresponding asm chain runs only behind its own gates).
struct FeedHooks {
    std::function<bool()> can_feed;               // @0x64b3d8
    std::function<float()> fullness;              // ffffd1a0
    std::function<void(float)> set_fullness;
    std::function<std::uint16_t()> hunger;        // ffffd198 (ldrh)
    std::function<void(std::uint16_t)> set_hunger;
    std::function<std::uint16_t()> food_points;   // the uxth'd call result
    // The ffffcacc state byte != 0: the blockhead payload path (one hook;
    // it returns 1 without the fill/count stages).
    std::function<bool()> state_flag_present;
    std::function<void()> blockhead_payload;      // @0x64b588-0x64b62c
    std::function<void()> set_aux_flag;           // ffffd1a8 = 1 (@0x64b674)
    std::function<float()> fill_slot;             // ffffd1b4 (old value)
    std::function<void(float)> set_fill_slot;     // = 675.0f (@0x64b6c8)
    std::function<void()> succeeded_tail;         // the 0x64bcec tail
    // The count stage (reached only when the state byte is 0 and the old
    // fill-slot value <= 0).
    std::function<int32_t()> tame_count_requirement; // tameCountRequirementForNPCType
    std::function<std::int32_t()> read_tame_count;   // @0x64b850 (the RMW read)
    std::function<void(std::int32_t)> write_tame_count; // @0x64b8d4
    std::function<bool()> count_predicate;        // ffffd1c8 pred (@0x64b92c)
    std::function<std::int32_t()> max_count_over_blockheads; // the fold
    std::function<void()> set_tamed;              // @0x64bc0c-0x64bce0
};

// Runs one feed. Returns false only on the gate (the asm stores 0); every
// deeper path stores 1.
inline bool npc_feed_response(const FeedHooks& h) {
    if (h.can_feed && !h.can_feed()) {
        return false; // @0x64b3e8-0x64b3f0
    }
    if (h.fullness) {
        float f = h.fullness();
        f = static_cast<float>(static_cast<double>(f) + kFeedFullnessGain);
        if (static_cast<double>(f) > kFeedFullnessMax) {
            f = static_cast<float>(kFeedFullnessMax); // @0x64b458-0x64b478
        }
        if (h.set_fullness) {
            h.set_fullness(f);
        }
    }
    if (h.hunger) {
        const std::uint16_t field = h.hunger();
        if (field > 0) { // cmp; ble @0x64b49c-0x64b4a0
            std::int32_t v = h.food_points ? h.food_points() : 0;
            v = v / static_cast<std::int32_t>(kFeedHalveDivisor); // idiv r1=2
            const std::uint16_t m = (field < v) ? field : static_cast<std::uint16_t>(v);
            if (h.set_hunger) {
                h.set_hunger(static_cast<std::uint16_t>(field - m)); // sub; strh
            }
        }
    }
    if (h.state_flag_present && h.state_flag_present()) {
        if (h.blockhead_payload) {
            h.blockhead_payload(); // boundary hook
        }
        return true; // @0x64b588-0x64b62c stores 1
    }
    if (h.set_aux_flag) {
        h.set_aux_flag(); // ffffd1a8 = 1
    }
    const bool filled = (h.fill_slot && h.fill_slot() > 0.0f) ? true : false;
    if (h.set_fill_slot) {
        h.set_fill_slot(kFeedFillValue); // ffffd1b4 = 675.0f
    }
    // The count stage (skipped when the old fill value was > 0 and when no
    // count store is attached to the host).
    if (!filled && h.read_tame_count && h.tame_count_requirement) {
        const std::int32_t count = h.read_tame_count() + 1; // @0x64b868
        if (h.write_tame_count) {
            h.write_tame_count(count);
        }
        if (count < h.tame_count_requirement()) {
            // below the requirement: straight to the tail (blt 0x64bce8);
            // the predicate is not consulted on this path.
        } else if (!(h.count_predicate && h.count_predicate())) {
            // predicate clear: the enumeration folds, and only count > max
            // enters the set block (cmp; ble 0x64bce4 skips it).
            const std::int32_t max_count =
                h.max_count_over_blockheads ? h.max_count_over_blockheads() : 0;
            if (count > max_count) {
                if (h.set_tamed) {
                    h.set_tamed(); // @0x64bc0c-0x64bce0
                }
            }
        }
    }
    if (h.succeeded_tail) {
        h.succeeded_tail(); // 0x64bcec
    }
    return true;
}

} // namespace blockheads::recovered
