// Contract tests for the recovered train type traits + particle pool slots
// (E73/E74).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_particle_pool_slots.cpp
//       reconstruction/recovered/particle_pool_slots.cpp
//       reconstruction/recovered/train_type_traits.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "particle_pool_slots.h"
#include "train_type_traits.h"

#include <cassert>
#include <cstdint>
#include <cstring>

using blockheads::recovered::kParticleFreeSlotSentinel;
using blockheads::recovered::kParticlePoolCapacity;
using blockheads::recovered::kParticleRecordStride;
using blockheads::recovered::kTrainFuelItemCount;
using blockheads::recovered::kTrainFuelUIOffsetY;
using blockheads::recovered::kTrainItemType;
using blockheads::recovered::kTrainMaxRiders;
using blockheads::recovered::kTrainObjectType;
using blockheads::recovered::particleAddAllowed;
using blockheads::recovered::ParticlePoolSlots;
using blockheads::recovered::trainCanDismissFuelUI;
using blockheads::recovered::trainIsEngine;
using blockheads::recovered::trainRequiresFuel;
using blockheads::recovered::trainSetTargetVelocity;
using blockheads::recovered::withinWorldWidthBand;

static void test_constants_bits() {
    static_assert(kTrainItemType == 0xcd);
    static_assert(kTrainObjectType == 0x2a);
    static_assert(kTrainFuelItemCount == 4);
    static_assert(kTrainMaxRiders == 1);
    std::uint32_t bits = 0;
    std::memcpy(&bits, &kTrainFuelUIOffsetY, sizeof(bits));
    assert(bits == 0x40800000u);  // IEEE-754 4.0f
    static_assert(kParticlePoolCapacity == 0x800);
    static_assert(kParticleRecordStride == 0x68);
    static_assert(kParticleFreeSlotSentinel == 0x7fffffff);
}

static void test_train_traits() {
    assert(trainIsEngine());
    assert(trainRequiresFuel());
    assert(!trainCanDismissFuelUI());  // contrast the Workbench's true
    // setTargetVelocity: is a no-op: calling it must not disturb anything.
    trainSetTargetVelocity(3.5f);
}

static void test_stop_gate() {
    assert(particleAddAllowed(false));   // stop flag clear -> allowed
    assert(!particleAddAllowed(true));   // ldrsb; bne exit
}

static void test_width_band() {
    const float low = -64.0f;
    const float high = 64.0f;
    assert(withinWorldWidthBand(0.0f, low, high));
    assert(withinWorldWidthBand(low, low, high));    // inclusive low
    assert(withinWorldWidthBand(high, low, high));   // inclusive high
    assert(!withinWorldWidthBand(low - 0.01f, low, high));  // bmi exit
    assert(!withinWorldWidthBand(high + 0.01f, low, high));  // bgt exit
}

static void test_pool_slots() {
    ParticlePoolSlots pool(4);
    assert(pool.capacity() == 4);
    assert(pool.usedCount() == 0);
    const std::int32_t a = pool.acquire();
    assert(a == 0);
    const std::int32_t b = pool.acquire();
    assert(b == 1);
    assert(pool.usedCount() == 2);
    pool.release(a);
    assert(pool.isFree(0));
    assert(!pool.isFree(1));
    assert(pool.acquire() == 0);  // the first free slot again
    // Filling the pool yields the sentinel (the reject arm of the adders).
    ParticlePoolSlots full(2);
    assert(full.acquire() == 0);
    assert(full.acquire() == 1);
    assert(full.acquire() == kParticleFreeSlotSentinel);
    assert(full.usedCount() == 2);
    // The default capacity is the pinned 2048.
    ParticlePoolSlots def;
    assert(def.capacity() == 2048);
}

int main() {
    test_constants_bits();
    test_train_traits();
    test_stop_gate();
    test_width_band();
    test_pool_slots();
    return 0;
}
