// Recovered contract: the trade price response (World
// -[updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:], E108).
//
// Evidence (reverse-v3 level A/B):
//   - The epsilon gate: (double)delta vs 0.01 / -0.01
//     (`vcvt.f64.f32; vcmpe.f64` @0x5cd6d8 and @0x5cd6f8; pools 0x5cd708 =
//      0.01, 0x5cd710 = -0.01). The main path runs iff
//      delta >= 0.01 || delta <= -0.01 (`bpl` @0x5cd6e8 and `ble` @0x5cd700
//      both enter it); |delta| < 0.01 falls to the return at 0x5cd704.
//   - The multiplier law: factor = pow(0.999, (double)delta)
//     (`vldr d0, [0x5cd718]` = 0.999 @0x5cd7f4; `bl pow` @0x5cd808 with the
//      exponent in d2) and m_new = m * factor (`vldr d2, [fp,-0x38];
//      vmul.f64 d0, d2, d0` @0x5cd8a0-0x5cd8a8), where m defaults to 1.0
//      when the lookup misses (`vmov.f64 d0, 1` @0x5cd76c; the nil skip
//      @0x5cd7b8-0x5cd7f0).
//   - The multiplier block is entered only when the client-state slot
//     (ffffcc90) is NIL (`cmp r1, 0; bne 0x5cd9a0` @0x5cd740-0x5cd744 skips
//      it when non-nil) - modeled as the `client_state_present` hook.
//   - Two float accumulators: acc = delta + stored (`vadd.f32 s0, s2, s0`
//     @0x5cdb6c and @0x5cdcb4); the stored value is read through an
//     objectForKey:/floatValue pair (@0x5cdb60 / @0x5cdca8) and written back
//     through the setter chain (@0x5cd910 / @0x5cdd58); a missing key
//     leaves acc = delta (the nil skip at @0x5cdb34 / @0x5cdc7c).
//   - Two pass-through read-modify-write slots (@0x5cd9c8 / 0x5cda5c) are
//     NOT modeled: their increments live inside unread helper chains.
//
// Boundaries (do not promote beyond evidence):
//   - The dictionary identities are opaque cells (the ffffcc90 / ffffce84 /
//     ffffce7c slots); the slice takes callbacks for every store access.
//   - double math for pow and the multiply (the original uses vmul.f64 /
//     pow); the accumulators are f32 (`vadd.f32`).
//   - No claim about which transaction queue the pass-through slots feed.
#pragma once

#include <cmath>
#include <cstdint>
#include <functional>

namespace blockheads::recovered {

// The pinned constants (PIC-recomputed pool words).
inline constexpr float kPriceEpsilon = 0.01f;    // pools 0x5cd708 / 0x5cd710
inline constexpr double kPriceDecayBase = 0.999; // pool 0x5cd718

// The store access hooks (one per observed slot family).
struct PriceResponseHooks {
    // The client-state slot (ffffcc90): non-nil skips the multiplier block
    // (@0x5cd740-0x5cd744). May be empty - then the multiplier block runs.
    std::function<bool()> client_state_present;
    // [multiplierDict objectForKey:key] -> doubleValue (@0x5cd7a8-0x5cd7f0):
    // returns true and writes `out` when the lookup hit; a miss keeps the
    // 1.0 default.
    std::function<bool(double& out)> read_multiplier;
    // The numberWithDouble: write-back chain (@0x5cd910).
    std::function<void(double value)> write_multiplier;
    // The per-slot accumulator reads (slots 0, 1 - the ffffce84 / ffffce7c
    // pair): floatValue with a nil skip (@0x5cdb60 / @0x5cdca8).
    std::function<bool(int slot, float& out)> read_accumulator;
    // The per-slot write-back chain (@0x5cdd58).
    std::function<void(int slot, float value)> write_accumulator;
};

// Runs the response for one (key, delta) pair. Returns false on the
// epsilon-return path (|delta| < 0.01, NaN included - the unordered compare
// falls to the return); true when the response ran.
inline bool trade_price_response(const PriceResponseHooks& hooks, float delta) {
    if (!(delta >= kPriceEpsilon || delta <= -kPriceEpsilon)) {
        return false; // the |delta| < 0.01 return (0x5cd704 -> epilogue)
    }
    if (!hooks.client_state_present || !hooks.client_state_present()) {
        double old = 1.0; // vmov.f64 d0, 1 @0x5cd76c
        if (hooks.read_multiplier) {
            double v = 0.0;
            if (hooks.read_multiplier(v)) {
                old = v; // the doubleValue path (@0x5cd7e8)
            }
        }
        const double factor = std::pow(kPriceDecayBase, static_cast<double>(delta));
        if (hooks.write_multiplier) {
            hooks.write_multiplier(old * factor); // vmul.f64 @0x5cd8a4
        }
    }
    for (int slot = 0; slot < 2; ++slot) {
        float acc = delta; // vstr s0, [fp,-0x5c] / [fp,-0x64]
        if (hooks.read_accumulator) {
            float v = 0.0f;
            if (hooks.read_accumulator(slot, v)) {
                acc = delta + v; // vadd.f32 @0x5cdb6c / @0x5cdcb4
            }
        }
        if (hooks.write_accumulator) {
            hooks.write_accumulator(slot, acc);
        }
    }
    return true;
}

} // namespace blockheads::recovered
