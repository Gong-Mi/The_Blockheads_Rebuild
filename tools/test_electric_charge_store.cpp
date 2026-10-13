// Contract tests for the recovered electric charge store (E75/E76).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_electric_charge_store.cpp
//       reconstruction/recovered/electric_charge_store.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "electric_charge_store.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <initializer_list>

using blockheads::recovered::ElectricChargeStore;
using blockheads::recovered::kFurnaceFuelFence;
using blockheads::recovered::kStorageCapacity;
using blockheads::recovered::kWorkbenchTypeGeneratorA;
using blockheads::recovered::kWorkbenchTypeGeneratorB;
using blockheads::recovered::kWorkbenchTypeStorage;

static void test_constants() {
    static_assert(kFurnaceFuelFence == 100);
    static_assert(kStorageCapacity == 8192);
    static_assert(kWorkbenchTypeGeneratorA == 15);
    static_assert(kWorkbenchTypeGeneratorB == 20);
    static_assert(kWorkbenchTypeStorage == 21);
}

static void test_drain_gate() {
    ElectricChargeStore s;
    s.setUnits(10);
    // not enough exits (cmp; bgt): false and unchanged.
    assert(!s.drain(11));
    assert(s.units() == 10);
    // exact and below succeed (stored >= requested).
    assert(s.drain(10));
    assert(s.units() == 0);
    assert(s.dirty());
    s.clearDirty();
    s.setUnits(255);
    assert(s.drain(5));
    assert(s.units() == 250);
}

static void test_furnace_fence() {
    ElectricChargeStore s;
    assert(s.addFuelUnits(kWorkbenchTypeGeneratorA, 40));
    assert(s.units() == 40);
    assert(s.addFuelUnits(kWorkbenchTypeGeneratorA, 59));
    assert(s.units() == 99);  // 99 < 100: accepted
    // At 99 the fence does NOT reject (cmp r0, 0x64; bge is false): the
    // 1-unit add lands and the store reaches exactly 100.
    assert(s.addFuelUnits(kWorkbenchTypeGeneratorA, 1));
    assert(s.units() == 100);
    assert(!s.addFuelUnits(kWorkbenchTypeGeneratorA, 5));  // at the fence: rejected
    assert(s.units() == 100);
    // the wrong type is out of the modelled scope.
    assert(!s.addFuelUnits(kWorkbenchTypeStorage, 5));
}

static void test_storage_fraction() {
    ElectricChargeStore s;
    s.setUnits(0x2000);
    assert(std::fabs(s.storageFraction(kWorkbenchTypeStorage) - 1.0f) < 1e-6f);
    s.setUnits(0x1000);
    assert(std::fabs(s.storageFraction(kWorkbenchTypeStorage) - 0.5f) < 1e-6f);
    s.setUnits(0);
    assert(s.storageFraction(kWorkbenchTypeStorage) == 0.0f);
    assert(s.storageFraction(kWorkbenchTypeGeneratorA) == 0.0f);  // non-storage: 0
}

static void test_type_tables() {
    assert(ElectricChargeStore::generatesElectricity(15));
    assert(ElectricChargeStore::generatesElectricity(20));
    assert(!ElectricChargeStore::generatesElectricity(21));
    assert(ElectricChargeStore::isStorageDevice(21));
    assert(!ElectricChargeStore::isStorageDevice(20));
    for (std::int32_t t : {15, 20, 21, 17, 16, 27}) {
        assert(ElectricChargeStore::usesStoresConductsOrProduces(t));
    }
    assert(!ElectricChargeStore::usesStoresConductsOrProduces(1));
    assert(!ElectricChargeStore::usesStoresConductsOrProduces(3));
}

static void test_u16_domain() {
    ElectricChargeStore s;
    s.setUnits(65535);
    // at the fence the add is rejected (65535 >= 100).
    assert(!s.addFuelUnits(kWorkbenchTypeGeneratorA, 0));
    assert(s.units() == 65535);
    // the 16-bit domain wraps like strh: 99 + 65500 = 65599 -> 63.
    ElectricChargeStore w;
    w.setUnits(99);
    assert(w.addFuelUnits(kWorkbenchTypeGeneratorA, 65500));
    assert(w.units() == 63);
}

int main() {
    test_constants();
    test_drain_gate();
    test_furnace_fence();
    test_storage_fraction();
    test_type_tables();
    test_u16_domain();
    return 0;
}
