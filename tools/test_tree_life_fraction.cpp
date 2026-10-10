// Contract tests for the recovered tree-life density kernel (E23).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_tree_life_fraction.cpp
//       reconstruction/recovered/tree_life_fraction.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "tree_life_fraction.h"

#include <cassert>
#include <cstring>

using blockheads::recovered::kDecayDivisor;
using blockheads::recovered::kRandomGateHalf;
using blockheads::recovered::passesRandomGate;
using blockheads::recovered::tentAxis;
using blockheads::recovered::tileContribution;
using blockheads::recovered::weightedTerm;

static void test_divisor_is_32() {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &kDecayDivisor, sizeof(bits));
    assert(bits == 0x42000000u);  // IEEE-754 32.0f
}

static void test_random_gate() {
    assert(kRandomGateHalf == 0x80000000u);
    assert(passesRandomGate(0));
    assert(passesRandomGate(0x7fffffffu));
    assert(!passesRandomGate(0x80000000u));
    assert(!passesRandomGate(0xffffffffu));
}

static void test_tent_axis_values() {
    // max(0, 1 - |d| / 32)
    assert(tentAxis(0) == 1.0f);
    assert(tentAxis(16) == 0.5f);
    assert(tentAxis(-16) == 0.5f);   // symmetric magnitude
    assert(tentAxis(7) == 1.0f - 7.0f / 32.0f);
    assert(tentAxis(31) == 1.0f - 31.0f / 32.0f);
    assert(tentAxis(32) == 0.0f);    // clamp at the divisor
    assert(tentAxis(33) == 0.0f);    // and beyond
    assert(tentAxis(-1000) == 0.0f);
}

static void test_tile_contribution_product() {
    assert(tileContribution(0, 0) == 1.0f);
    assert(tileContribution(16, 16) == 0.25f);
    assert(tileContribution(-16, 16) == 0.25f);
    assert(tileContribution(32, 0) == 0.0f);   // one axis clamps -> zero
    assert(tileContribution(0, 32) == 0.0f);
    // separable product parity.
    const float expected = tentAxis(5) * tentAxis(-9);
    assert(tileContribution(5, -9) == expected);
}

static void test_weighted_term_normalisation() {
    // weight 32 in the ffe236fc domain -> /32 -> factor 1.0.
    assert(weightedTerm(0, 0, 32.0f) == 1.0f);
    // weight 16 -> 0.5 factor at the centre.
    assert(weightedTerm(0, 0, 16.0f) == 0.5f);
    // combined: centre tent 1.0, weight 8 -> 0.25.
    assert(weightedTerm(0, 0, 8.0f) == 0.25f);
    // off-centre terms multiply both factors.
    assert(weightedTerm(16, 0, 32.0f) == 0.5f);
}

int main() {
    test_divisor_is_32();
    test_random_gate();
    test_tent_axis_values();
    test_tile_contribution_product();
    test_weighted_term_normalisation();
    return 0;
}
