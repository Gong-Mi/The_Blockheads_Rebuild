// Contract tests for the recovered simulation-step slice (E40).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_simulation_step.cpp
//       reconstruction/recovered/simulation_step.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "simulation_step.h"

#include <cassert>
#include <cstring>
#include <vector>

using blockheads::recovered::accurateUpdate;
using blockheads::recovered::finishBlockheadSlots;
using blockheads::recovered::kFamilyCount;
using blockheads::recovered::kFamilyStepDivisor;
using blockheads::recovered::kSlotCount;
using blockheads::recovered::simulateStep;

static void test_divisor_is_exact_8() {
    // The listing pins `vmov.f32 s2, 8` - the literal must be exactly 8.0f.
    std::uint32_t bits = 0;
    std::memcpy(&bits, &kFamilyStepDivisor, sizeof(bits));
    assert(bits == 0x41000000u);  // IEEE-754 8.0f
    assert(kFamilyStepDivisor == 8.0f);
}

static void test_simulate_visits_eight_families_with_divided_dt() {
    std::vector<int> order;
    std::vector<float> dts;
    simulateStep(8.0f, true, [&](int family, float familyDT, bool pause) {
        order.push_back(family);
        dts.push_back(familyDT);
        assert(pause == true);
    });
    assert(static_cast<int>(order.size()) == kFamilyCount);
    for (int i = 0; i < kFamilyCount; ++i) {
        assert(order[static_cast<std::size_t>(i)] == i);
        assert(dts[static_cast<std::size_t>(i)] == 8.0f / 8.0f);  // == 1.0f
    }
    // 24.0f / 8.0f == 3.0f, per family.
    simulateStep(24.0f, false, [&](int, float familyDT, bool pause) {
        assert(familyDT == 3.0f);
        assert(pause == false);
    });
}

static void test_accurate_update_passes_both_floats_once() {
    int calls = 0;
    float gotDT = 0.0f;
    float gotAccurate = 0.0f;
    accurateUpdate(0.25f, 0.125f, true, [&](float dt, float accurateDT, bool pause) {
        ++calls;
        gotDT = dt;
        gotAccurate = accurateDT;
        assert(pause == true);
    });
    // ONE ffe234e8 site in the original: exactly one call.
    assert(calls == 1);
    assert(gotDT == 0.25f);
    assert(gotAccurate == 0.125f);
}

static void test_finisher_slots() {
    int calls = 0;
    std::vector<int> slotsPerBlockhead;
    finishBlockheadSlots(3, [&](std::size_t blockhead, int slot) {
        ++calls;
        if (slot == 0) {
            slotsPerBlockhead.push_back(static_cast<int>(blockhead));
        }
        assert(slot >= 0 && slot < kSlotCount);
    });
    // 3 blockheads x 8 slots.
    assert(calls == 3 * kSlotCount);
    assert((slotsPerBlockhead == std::vector<int>{0, 1, 2}));
    // zero blockheads: nothing runs.
    finishBlockheadSlots(0, [&](std::size_t, int) { assert(false); });
}

int main() {
    test_divisor_is_exact_8();
    test_simulate_visits_eight_families_with_divided_dt();
    test_accurate_update_passes_both_floats_once();
    test_finisher_slots();
    return 0;
}
