// Contract tests for the recovered family-probe patterns (E32/E34/E38/E39/E43).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_family_probes.cpp
//       reconstruction/recovered/family_probes.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "family_probes.h"

#include <cassert>
#include <vector>

using blockheads::recovered::indexedArmProbe;
using blockheads::recovered::kInteractionArmCount;
using blockheads::recovered::kNpcArmCount;
using blockheads::recovered::kTrainArmCount;
using blockheads::recovered::kTreeArmCount;
using blockheads::recovered::sequentialArmProbe;

static void test_gate_counts() {
    assert(kNpcArmCount == 8);            // 0x00E4AA1C
    assert(kInteractionArmCount == 9);    // 0x00E4AA90
    assert(kTreeArmCount == 11);          // 0x00E4AA64
    assert(kTrainArmCount == 4);          // 0x00E4AA0C
}

static void test_indexed_probe_gate_and_arm() {
    std::vector<int> probedArms;
    const auto lookup = [&](int arm) -> std::optional<int> {
        probedArms.push_back(arm);
        return arm * 10;
    };
    // in range: exactly one arm probes (no fall-through across arms).
    const auto hit = indexedArmProbe<int>(3, kNpcArmCount, lookup);
    assert(hit.has_value() && *hit == 30);
    assert((probedArms == std::vector<int>{3}));
    // out of range (>= count): refused BEFORE any arm runs.
    probedArms.clear();
    assert(!indexedArmProbe<int>(8, kNpcArmCount, lookup).has_value());
    assert(!indexedArmProbe<int>(-1, kNpcArmCount, lookup).has_value());
    assert(!indexedArmProbe<int>(9, kInteractionArmCount, lookup).has_value());
    assert(probedArms.empty());
}

static void test_indexed_probe_miss_is_caller_side() {
    // a miss inside a valid arm returns nullopt - the second-registry
    // fallback is out of this slice.
    const auto miss = [](int) -> std::optional<int> { return std::nullopt; };
    assert(!indexedArmProbe<int>(0, kInteractionArmCount, miss).has_value());
}

static void test_sequential_probe_first_hit_wins() {
    std::vector<int> probedArms;
    const auto lookup = [&](int arm) -> std::optional<int> {
        probedArms.push_back(arm);
        if (arm == 4) {
            return 400;
        }
        return std::nullopt;
    };
    const auto hit = sequentialArmProbe<int>(kTreeArmCount, lookup);
    assert(hit.has_value() && *hit == 400);
    // probed 0..4 inclusive then stopped (first hit wins, ascending order).
    assert((probedArms == std::vector<int>{0, 1, 2, 3, 4}));
}

static void test_sequential_probe_exhaustion() {
    int probes = 0;
    const auto lookup = [&](int) -> std::optional<int> {
        ++probes;
        return std::nullopt;
    };
    assert(!sequentialArmProbe<int>(kTreeArmCount, lookup).has_value());
    assert(probes == kTreeArmCount);  // exhausted all 11 arms
    // zero-arm table: nothing probed.
    probes = 0;
    assert(!sequentialArmProbe<int>(0, lookup).has_value());
    assert(probes == 0);
}

int main() {
    test_gate_counts();
    test_indexed_probe_gate_and_arm();
    test_indexed_probe_miss_is_caller_side();
    test_sequential_probe_first_hit_wins();
    test_sequential_probe_exhaustion();
    return 0;
}
