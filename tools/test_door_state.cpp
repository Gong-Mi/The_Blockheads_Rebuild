// Contract tests for the recovered door-state slice (E38/E39).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_door_state.cpp
//       reconstruction/recovered/door_state.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "door_state.h"

#include <cassert>

using blockheads::recovered::canWriteDoorMarker;
using blockheads::recovered::DoorStateStore;
using blockheads::recovered::kDoorMarkerAcceptedByte1;
using blockheads::recovered::kDoorMarkerAcceptedByte2;
using blockheads::recovered::kDoorTileMarker;

static void test_marker_write_gate() {
    // Only 0x34 and 0xa4 tiles accept the 0x46 marker (E38 addDoorAtPos:).
    assert(kDoorTileMarker == 0x46);
    assert(kDoorMarkerAcceptedByte1 == 0x34);
    assert(kDoorMarkerAcceptedByte2 == 0xa4);
    assert(canWriteDoorMarker(0x34));
    assert(canWriteDoorMarker(0xa4));
    assert(!canWriteDoorMarker(0x46));  // already marked: not accepted again
    assert(!canWriteDoorMarker(0x00));
    assert(!canWriteDoorMarker(0xa3));
}

static void test_marker_write_calls_neighbour_reread() {
    DoorStateStore store;
    int rereads = 0;
    assert(store.writeTileMarker(0x34, [&]() { ++rereads; }));
    assert(rereads == 1);
    // rejected byte: no marker, no re-read.
    assert(!store.writeTileMarker(0x10, [&]() { ++rereads; }));
    assert(rereads == 1);
    // empty callback is fine (the original always re-fetches; the callback is
    // the modelled hop).
    assert(store.writeTileMarker(0xa4, {}));
    assert(rereads == 1);
}

static void test_open_state_round_trip() {
    DoorStateStore store;
    // missing doors read closed (the check path stores 0 - E38 0x008edb58).
    assert(!store.isOpen(7));
    store.setDoor(7, true, 2);
    assert(store.isOpen(7));
    const auto* state = store.state(7);
    assert(state != nullptr);
    assert(state->open);
    assert(state->direction == 2);
    store.setDoor(7, false, -1);
    assert(!store.isOpen(7));
    assert(store.state(7)->direction == -1);
}

static void test_multiple_doors_independent() {
    DoorStateStore store;
    store.setDoor(1, true, 0);
    store.setDoor(2, false, 3);
    assert(store.isOpen(1));
    assert(!store.isOpen(2));
    assert(store.state(2) != nullptr && store.state(2)->direction == 3);
    assert(store.state(3) == nullptr);
}

int main() {
    test_marker_write_gate();
    test_marker_write_calls_neighbour_reread();
    test_open_state_round_trip();
    test_multiple_doors_independent();
    return 0;
}
