// Recovered contract: the particle pool slots + the electric-arc gates
// (E73 init/singleton/adders/doAddElectricity).
//
// Evidence (reverse-v3 level A):
//   - The pool: init (0x00d85f98) allocates `__wrap_calloc(16384, 4)` (the
//     0x4000-word effect array @0xd860fc-0xd86104) with the cap 0x800
//     (2048) driving the fill loop (`movw r0, 0x800` @0xd86018, `cmp r0,
//     0x800; bge` @0xd86158); the singleton lives at the 0x67a4 cell
//     (instance @0xd85ecc).
//   - The free-slot sentinel: the adders compare a found slot id against
//     **0x7fffffff** (pe_addparticle_goal @0xd87de0, pe_addbonus @0xd88400,
//     doAddElectricity @0xd87740, render @0xd89984/@0xd8c000): INT_MAX marks
//     "no particle" (the reject arm).
//   - The stop gate: the adders test the ffffff50 byte with `ldrsb; cmp 0;
//     bne` (exit when stopped: @0xd87ce0 goal, @0xd88308 bonus); the
//     setter is dmb-fenced (E73 setStopAllParticles).
//   - The world-width bounds: the spawn position must lie inside the
//     4-tuple box read through ffffff58/5c/60/64 with the float compares
//     (`vcmpe; bmi` exit below the low bound, `bgt` exit above the high
//     bound: @0xd87d24-0xd87dd8 - the accepted band is low <= v <= high per
//     axis).
//   - The record stride: the slot payload dispatch uses `movw r1, 0x68`
//     (104) (@0xd87e44).
//
// This module models the pool's slot bookkeeping (capacity, sentinel,
// acquire/release) and the two pinned gates as pure predicates.
//
// Boundaries (do not promote beyond evidence):
//   - The effect arrays' contents and the render integration stay outside;
//     the stride 104 is pinned but the per-field layout is NOT asserted.
//   - The bounds box values come from the caller (the ffffff58.. cells);
//     only the band rule is modelled.
#pragma once

#include <cstdint>
#include <limits>
#include <vector>

namespace blockheads::recovered {

inline constexpr std::int32_t kParticlePoolCapacity = 0x800;             // 2048
inline constexpr std::int32_t kParticleEffectArrayWords = 0x4000;        // 16384
inline constexpr std::int32_t kParticleRecordStride = 0x68;              // 104
inline constexpr std::int32_t kParticleFreeSlotSentinel =
    std::numeric_limits<std::int32_t>::max();  // 0x7fffffff

// The stop gate: a set ffffff50 byte rejects the add (ldrsb; bne exit).
inline bool particleAddAllowed(bool stopFlagSet) { return !stopFlagSet; }

// The world-width band: accepted when low <= v <= high (the bmi/bgt exits).
inline bool withinWorldWidthBand(float v, float low, float high) {
    if (v < low) {
        return false;  // bmi exit
    }
    if (v > high) {
        return false;  // bgt exit
    }
    return true;
}

// The pool's slot bookkeeping with the sentinel semantics.
class ParticlePoolSlots {
public:
    explicit ParticlePoolSlots(std::int32_t capacity = kParticlePoolCapacity)
        : capacity_(capacity), slots_(static_cast<std::size_t>(capacity), kParticleFreeSlotSentinel) {}

    std::int32_t capacity() const { return capacity_; }

    // The adder's search: the first free slot, or the sentinel when full.
    std::int32_t acquire() {
        for (std::int32_t i = 0; i < capacity_; ++i) {
            if (slots_[static_cast<std::size_t>(i)] == kParticleFreeSlotSentinel) {
                slots_[static_cast<std::size_t>(i)] = 1;  // marked used
                return i;
            }
        }
        return kParticleFreeSlotSentinel;  // the reject arm
    }

    void release(std::int32_t slot) {
        if (slot >= 0 && slot < capacity_) {
            slots_[static_cast<std::size_t>(slot)] = kParticleFreeSlotSentinel;
        }
    }

    bool isFree(std::int32_t slot) const {
        return slot >= 0 && slot < capacity_ &&
               slots_[static_cast<std::size_t>(slot)] == kParticleFreeSlotSentinel;
    }

    std::int32_t usedCount() const {
        std::int32_t n = 0;
        for (std::int32_t i = 0; i < capacity_; ++i) {
            if (slots_[static_cast<std::size_t>(i)] != kParticleFreeSlotSentinel) {
                ++n;
            }
        }
        return n;
    }

private:
    std::int32_t capacity_;
    std::vector<std::int32_t> slots_;
};

}  // namespace blockheads::recovered
