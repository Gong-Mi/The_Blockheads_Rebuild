// Contract tests for the recovered typed-accessor triplet dispatcher
// (E36/E37/E38/E39/E43).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_accessor_triplets.cpp
//       reconstruction/recovered/accessor_triplets.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "accessor_triplets.h"

#include <cassert>

using blockheads::recovered::AccessorTriplet;
using blockheads::recovered::kAddCell;
using blockheads::recovered::kLookupCell;
using blockheads::recovered::kRemoveGateCell;
using blockheads::recovered::RecoveredObject;
using blockheads::recovered::TripletStore;
using blockheads::recovered::tripletForType;

static void test_remove_cell_table() {
    // The pinned per-type remove cells (E36-E43).
    assert(tripletForType(0x11)->removeCell == 0x00ffe23564);  // torch
    assert(tripletForType(0x13)->removeCell == 0x00ffe23628);  // ladder
    assert(tripletForType(0x1e)->removeCell == 0x00ffe23618);  // egg
    assert(tripletForType(0x1f)->removeCell == 0x00ffe2364c);  // window
    assert(tripletForType(0x28)->removeCell == 0x00ffe23648);  // rail
    assert(tripletForType(0x34)->removeCell == 0x00ffe23558);  // painting
    assert(tripletForType(0x35)->removeCell == 0x00ffe2355c);  // column
    assert(tripletForType(0x36)->removeCell == 0x00ffe23560);  // stairs
    assert(tripletForType(0x37)->removeCell == 0x00ffe23640);  // motor
    assert(tripletForType(0x38)->removeCell == 0x00ffe2362c);  // shaft
    // the shared lookup/add cells of the family.
    const AccessorTriplet* torch = tripletForType(0x11);
    assert(torch->lookupCell == kLookupCell);
    assert(torch->addCell == kAddCell);
    assert(kRemoveGateCell == 0x00ffe23600);
}

static void test_doors_and_workbenches_are_two_probe() {
    assert(tripletForType(0x14)->probesPosThenYMinus1);  // door
    assert(tripletForType(0x2d)->probesPosThenYMinus1);  // workbench
    assert(tripletForType(0x14)->removeCell == 0);       // no single-cell remove leg
    assert(tripletForType(0x2d)->removeCell == 0);
    assert(!tripletForType(0x11)->probesPosThenYMinus1); // torch: single probe
    assert(tripletForType(0x99) == nullptr);
}

static void test_two_probe_falls_through_to_y_minus_1() {
    TripletStore store;
    // A door at (10, 9): doorAtPos(10, 10) probes y then y-1 and finds it (E38).
    store.add(0x14, 10, 9);
    const RecoveredObject* hit = store.lookup(0x14, 10, 10);
    assert(hit != nullptr);
    assert(hit->y == 9);
    // A torch at (10, 9): the single-probe accessor does NOT fall through.
    store.add(0x11, 10, 9);
    assert(store.lookup(0x11, 10, 10) == nullptr);
    assert(store.lookup(0x11, 10, 9) != nullptr);
    // workbench: same two-probe contract (E39).
    store.add(0x2d, 4, 4);
    const RecoveredObject* wb = store.lookup(0x2d, 4, 5);
    assert(wb != nullptr && wb->y == 4);
}

static void test_add_and_remove_round_trip() {
    TripletStore store;
    assert(store.size() == 0);
    const RecoveredObject& ladder = store.add(0x13, 1, 2);
    assert(ladder.type == 0x13);
    assert(store.size() == 1);
    const std::optional<std::int64_t> cell = store.remove(0x13, 1, 2);
    assert(cell.has_value());
    assert(*cell == 0x00ffe23628);  // ladder remove cell executed
    assert(store.size() == 0);
    // removing again finds nothing (the ffe23600 gate has no match).
    assert(!store.remove(0x13, 1, 2).has_value());
}

static void test_no_cell_leg_returns_nothing() {
    // door/workbench entries (removeCell == 0) have NO single-cell remove
    // leg: the removal rides the state family (E38/E39). The dispatcher must
    // return nullopt, not "cell 0".
    TripletStore store;
    store.add(0x14, 3, 3);
    assert(!store.remove(0x14, 3, 3).has_value());
    assert(store.size() == 0);
    store.add(0x2d, 4, 4);
    assert(!store.remove(0x2d, 4, 4).has_value());
}

static void test_remove_returns_type_specific_cell() {
    TripletStore store;
    store.add(0x37, 7, 7);
    const std::optional<std::int64_t> motor = store.remove(0x37, 7, 7);
    assert(motor.has_value() && *motor == 0x00ffe23640);
    store.add(0x28, 7, 7);
    const std::optional<std::int64_t> rail = store.remove(0x28, 7, 7);
    assert(rail.has_value() && *rail == 0x00ffe23648);
}

int main() {
    test_remove_cell_table();
    test_doors_and_workbenches_are_two_probe();
    test_two_probe_falls_through_to_y_minus_1();
    test_add_and_remove_round_trip();
    test_no_cell_leg_returns_nothing();
    test_remove_returns_type_specific_cell();
    return 0;
}
