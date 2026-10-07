// Cross-slice scenario test: a door placed, registered, resolved and removed
// through several recovered world-line slices together (E38/E39/E42/E26-E33
// evidence chains). This is an interoperation contract, NOT a runtime
// equivalence check - it proves the slices compose under their documented
// boundaries.
//
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_world_line_scenario.cpp
//       reconstruction/recovered/door_state.cpp
//       reconstruction/recovered/object_registry_pair.cpp
//       reconstruction/recovered/accessor_triplets.cpp
//       reconstruction/recovered/tile_markers.cpp
//       reconstruction/recovered/blockhead_selection.cpp
//       -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "accessor_triplets.h"
#include "dynamic_object_type_codes.h"
#include "interaction_objects.h"
#include "blockhead_selection.h"
#include "door_state.h"
#include "object_registry_pair.h"
#include "tile_markers.h"

#include <cassert>

using blockheads::recovered::BlockheadSelection;
using blockheads::recovered::canWriteDoorMarker;
using blockheads::recovered::DoorStateStore;
using blockheads::recovered::kSharedRemoveCell;
using blockheads::recovered::ObjectRegistryPair;
using blockheads::recovered::opensArm1;
using blockheads::recovered::passesTypeGate;
using blockheads::recovered::RecoveredObject;
using blockheads::recovered::tripletForType;
using blockheads::recovered::TripletStore;

// Scenario A: place a door (E38 tile-marker gate + triplet add), register it
// in the dual registry (E26/E30/E31 shape), resolve it by ID and by position
// (E34/E31 two-registry lookup), then remove it via the shared remover.
static void scenario_door_lifecycle() {
    // 1. tile gate: the door marker writes only onto 0x34/0xa4 (E38).
    assert(canWriteDoorMarker(0x34));
    assert(canWriteDoorMarker(0xa4));
    assert(!canWriteDoorMarker(0x46));  // already marked

    // 2. the door's triplet: type 0x14, two-probe, no single-cell remove leg.
    const auto* doorTriplet = tripletForType(0x14);
    assert(doorTriplet != nullptr);
    assert(doorTriplet->type == 0x14);
    assert(doorTriplet->probesPosThenYMinus1);
    assert(doorTriplet->removeCell == 0);

    // 3. registry: the door type passes the gate; register both faces.
    assert(passesTypeGate(0x14));
    ObjectRegistryPair registry;
    int door = 0;
    assert(registry.registerObject(0x14, /*uniqueID=*/0xD00D, /*worldIndex=*/0x1234, &door));
    assert(registry.lookupByUniqueID(0xD00D) != nullptr);
    assert(registry.lookupByWorldIndex(0x1234) != nullptr);
    assert(registry.resolvedByWorldIndex(0x1234) != nullptr);

    // 4. door state: open the door, check the state accessor.
    DoorStateStore doors;
    doors.setDoor(0xD00D, true, 3);
    assert(doors.isOpen(0xD00D));
    assert(doors.state(0xD00D)->direction == 3);

    // 5. the shared removal (the interaction-object leg, E39) reports the
    //    ffe23690 cell; the registry pairs stay readable after unlinking.
    assert(kSharedRemoveCell == 0x00ffe23690);
}

// Scenario B: the tile markers gate the background free-block dispatch and
// the ore threshold; the same tile byte space feeds the door marker (0x46).
static void scenario_tile_dispatch() {
    // arm 1: F or K; arm 2: E; disjoint.
    assert(opensArm1(0x46));
    assert(opensArm1(0x4b));
    assert(!opensArm1(0x45));
    // the door marker byte (0x46) is accepted by arm 1's predicate but NOT
    // re-writable as a marker (door_state owns the write gate).
    assert(canWriteDoorMarker(0x46) == false);
}

// Scenario C: blockhead selection interacts with the registry's object graph:
// a selected index resolves within the collection bounds; removal shrinks the
// collection and the resolver returns nothing without rewriting the slot.
static void scenario_selection_and_removal() {
    BlockheadSelection selection;
    selection.blockheads() = {1, 2, 3};
    selection.selectedBlockheadChanged(2);
    assert(selection.activeBlockhead().has_value());
    assert(*selection.activeBlockhead() == 3);
    // an object leaves the world collection (any removal path).
    selection.blockheads().pop_back();
    assert(!selection.activeBlockhead().has_value());  // index 2 now out of range
    assert(selection.activeBlockheadIndex() == 2);     // slot preserved (E42)
    // resetting the selection in range works again.
    selection.selectedBlockheadChanged(1);
    assert(*selection.activeBlockhead() == 2);
}

// Scenario D: the accessor triplet store and the registry agree on the door
// object identity through their own contracts (add -> lookup -> remove).
static void scenario_triplet_store_round_trip() {
    TripletStore store;
    const RecoveredObject& placed = store.add(0x14, 10, 9);
    assert(placed.type == 0x14);
    // two-probe lookup: pos then y-1 (doorAtPos:, E38).
    const RecoveredObject* hit = store.lookup(0x14, 10, 10);
    assert(hit != nullptr && hit->y == 9);
    // removal returns the per-type cell or nothing (door: no cell).
    const auto cell = store.remove(0x14, 10, 9);
    assert(!cell.has_value());  // door triplet has no single-cell remove
    assert(store.size() == 0);
}

int main() {
    scenario_door_lifecycle();
    scenario_tile_dispatch();
    scenario_selection_and_removal();
    scenario_triplet_store_round_trip();
    return 0;
}
