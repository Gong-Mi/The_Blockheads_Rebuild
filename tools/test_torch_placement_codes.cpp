// Contract tests for the recovered torch placement codes (E72).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_torch_placement_codes.cpp
//       reconstruction/recovered/torch_placement_codes.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "torch_placement_codes.h"

#include <cassert>
#include <cstdint>

using blockheads::recovered::classifyTorchPlacement;
using blockheads::recovered::codeHasLightArm;
using blockheads::recovered::kMarkerByte;
using blockheads::recovered::TorchNeighbourProbes;
using blockheads::recovered::TorchPlacementCode;

static TorchNeighbourProbes none() { return TorchNeighbourProbes{}; }

static void test_codes_are_pinned() {
    static_assert(static_cast<std::int32_t>(TorchPlacementCode::kNoValidPosition) == -2);
    static_assert(static_cast<std::int32_t>(TorchPlacementCode::kXMinusOneDoor) == -1);
    static_assert(static_cast<std::int32_t>(TorchPlacementCode::kSolidBelow) == 0);
    static_assert(static_cast<std::int32_t>(TorchPlacementCode::kSolidPlusDoor) == 1);
    static_assert(static_cast<std::int32_t>(TorchPlacementCode::kHalfDepth) == 2);
    static_assert(static_cast<std::int32_t>(TorchPlacementCode::kMarkerD) == 3);
    static_assert(kMarkerByte == 0x64);
}

static void test_first_hit_wins() {
    // half-depth beats everything below it.
    TorchNeighbourProbes p = none();
    p.tileIsHalfDepth = [] { return true; };
    p.yMinusOneSolid = [] { return true; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kHalfDepth);

    // solid-below beats the marker / door arms.
    p = none();
    p.yMinusOneSolid = [] { return true; };
    p.markerAtB = [] { return kMarkerByte; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kSolidBelow);

    // the marker arm beats the door arms.
    p = none();
    p.markerAtB = [] { return kMarkerByte; };
    p.xPlusOneSolid = [] { return true; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kMarkerD);
}

static void test_marker_byte_exact() {
    TorchNeighbourProbes p = none();
    p.markerAtB = [] { return std::uint8_t{0x63}; };  // one below 'd'
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kNoValidPosition);
    p.markerAtB = [] { return kMarkerByte; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kMarkerD);
}

static void test_door_arms() {
    // x+1 solid without a door -> code 1.
    TorchNeighbourProbes p = none();
    p.xPlusOneSolid = [] { return true; };
    p.xPlusOneDoor = [] { return false; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kSolidPlusDoor);

    // x+1 solid WITH a door -> falls through; x-1 solid without a door -> -1.
    p = none();
    p.xPlusOneSolid = [] { return true; };
    p.xPlusOneDoor = [] { return true; };
    p.xMinusOneSolid = [] { return true; };
    p.xMinusOneDoor = [] { return false; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kXMinusOneDoor);

    // all doors -> the no-position sentinel.
    p = none();
    p.xPlusOneSolid = [] { return true; };
    p.xPlusOneDoor = [] { return true; };
    p.xMinusOneSolid = [] { return true; };
    p.xMinusOneDoor = [] { return true; };
    assert(classifyTorchPlacement(p) == TorchPlacementCode::kNoValidPosition);
}

static void test_empty_probes() {
    // no probes at all -> the -2 arm (the no-tile case).
    assert(classifyTorchPlacement(none()) == TorchPlacementCode::kNoValidPosition);
}

static void test_light_arms() {
    for (auto c : {TorchPlacementCode::kNoValidPosition, TorchPlacementCode::kXMinusOneDoor,
                   TorchPlacementCode::kSolidBelow, TorchPlacementCode::kSolidPlusDoor,
                   TorchPlacementCode::kHalfDepth, TorchPlacementCode::kMarkerD}) {
        assert(codeHasLightArm(c));
    }
}

int main() {
    test_codes_are_pinned();
    test_first_hit_wins();
    test_marker_byte_exact();
    test_door_arms();
    test_empty_probes();
    test_light_arms();
    return 0;
}
