// Contract tests for the recovered tile-marker constants/predicates (E30/E38).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_tile_markers.cpp
//       reconstruction/recovered/tile_markers.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "tile_markers.h"

#include <cassert>

using blockheads::recovered::exceedsOreThreshold;
using blockheads::recovered::kMarkerE;
using blockheads::recovered::kMarkerF;
using blockheads::recovered::kMarkerK;
using blockheads::recovered::kOreThreshold;
using blockheads::recovered::opensArm1;
using blockheads::recovered::opensArm2;

static void test_marker_values() {
    assert(kMarkerF == 0x46);  // 'F'
    assert(kMarkerK == 0x4b);  // 'K'
    assert(kMarkerE == 0x45);  // 'E'
    assert(kOreThreshold == 0xaa);
}

static void test_arm_predicates() {
    // arm 1: F or K.
    assert(opensArm1(0x46));
    assert(opensArm1(0x4b));
    assert(!opensArm1(0x45));
    assert(!opensArm1(0x00));
    // arm 2: E only.
    assert(opensArm2(0x45));
    assert(!opensArm2(0x46));
    assert(!opensArm2(0x4b));
    // the arms are disjoint.
    for (int b = 0; b <= 0xff; ++b) {
        assert(!(opensArm1(b) && opensArm2(b)));
    }
}

static void test_ore_threshold_strictly_greater() {
    assert(!exceedsOreThreshold(0xaa));  // equality does NOT pass
    assert(exceedsOreThreshold(0xab));
    assert(exceedsOreThreshold(0xff));
    assert(!exceedsOreThreshold(0xa9));
    assert(!exceedsOreThreshold(0));
}

int main() {
    test_marker_values();
    test_arm_predicates();
    test_ore_threshold_strictly_greater();
    return 0;
}
