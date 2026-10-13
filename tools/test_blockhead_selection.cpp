// Contract tests for the recovered blockhead-selection slice (E42).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_blockhead_selection.cpp
//       reconstruction/recovered/blockhead_selection.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "blockhead_selection.h"

#include <cassert>

using blockheads::recovered::BlockheadSelection;

static void test_default_slot_is_zero() {
    BlockheadSelection sel;
    assert(sel.activeBlockheadIndex() == 0);
    // empty collection: index 0 is out of range -> no active blockhead.
    assert(!sel.activeBlockhead().has_value());
}

static void test_in_range_store() {
    BlockheadSelection sel;
    sel.blockheads() = {100, 200, 300};
    sel.selectedBlockheadChanged(2);
    assert(sel.activeBlockheadIndex() == 2);
    assert(sel.activeBlockhead().has_value() && *sel.activeBlockhead() == 300);
    sel.selectedBlockheadChanged(0);
    assert(sel.activeBlockhead().has_value() && *sel.activeBlockhead() == 100);
}

static void test_out_of_range_stores_zero() {
    BlockheadSelection sel;
    sel.blockheads() = {10, 20};
    sel.selectedBlockheadChanged(5);   // >= count
    assert(sel.activeBlockheadIndex() == 0);  // the 0-store (E42)
    sel.selectedBlockheadChanged(-1);
    assert(sel.activeBlockheadIndex() == 0);
    // index == count is out of range (bhs boundary).
    sel.selectedBlockheadChanged(2);
    assert(sel.activeBlockheadIndex() == 0);
}

static void test_resolver_boundary() {
    BlockheadSelection sel;
    sel.blockheads() = {7, 8, 9};
    sel.selectedBlockheadChanged(2);
    assert(sel.activeBlockhead().has_value() && *sel.activeBlockhead() == 9);
    // shrink the collection: the stored index now exceeds the count.
    sel.blockheads() = {7};
    assert(!sel.activeBlockhead().has_value());  // resolver nil path
    assert(sel.activeBlockheadIndex() == 2);     // the slot is not rewritten
}

int main() {
    test_default_slot_is_zero();
    test_in_range_store();
    test_out_of_range_stores_zero();
    test_resolver_boundary();
    return 0;
}
