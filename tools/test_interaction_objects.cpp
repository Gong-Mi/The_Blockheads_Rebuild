// Contract tests for the recovered interaction-object query/remover slice (E39).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_interaction_objects.cpp
//       reconstruction/recovered/interaction_objects.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "interaction_objects.h"

#include <cassert>
#include <cstdint>
#include <optional>

using blockheads::recovered::interactionTypeForObjectAtPos;
using blockheads::recovered::kInteractionFetchCell;
using blockheads::recovered::kSharedRemoveCell;
using blockheads::recovered::kWorkbenchCheckCell;
using blockheads::recovered::removeInteractionLeg;
using blockheads::recovered::removeWorkbenchLeg;

static void test_type_query_values() {
    // fetch -> the 16-bit type; absent -> 0.
    assert(interactionTypeForObjectAtPos(std::nullopt) == 0);
    assert(interactionTypeForObjectAtPos(std::uint16_t{47}) == 47);
    assert(interactionTypeForObjectAtPos(std::uint16_t{60}) == 60);
    // the full uint16 range is representable (strh/ldrh width).
    assert(interactionTypeForObjectAtPos(std::uint16_t{0xFFFF}) == 0xFFFF);
}

static void test_remover_legs() {
    assert(kWorkbenchCheckCell == 0x00ffe233e0);
    assert(kInteractionFetchCell == 0x00ffe23570);
    assert(kSharedRemoveCell == 0x00ffe23690);
    // check hit -> refusal (both bodies return 0 on the early exit).
    assert(!removeWorkbenchLeg(true).has_value());
    assert(!removeInteractionLeg(true).has_value());
    // no hit -> the shared ffe23690 removal executes.
    const auto wb = removeWorkbenchLeg(false);
    assert(wb.has_value() && *wb == kSharedRemoveCell);
    const auto io = removeInteractionLeg(false);
    assert(io.has_value() && *io == kSharedRemoveCell);
}

static void test_legs_share_the_removal_cell() {
    // both legs funnel into ffe23690; their pre-checks differ.
    const auto wb = removeWorkbenchLeg(false);
    const auto io = removeInteractionLeg(false);
    assert(wb.has_value() && io.has_value());
    assert(*wb == *io);
}

int main() {
    test_type_query_values();
    test_remover_legs();
    test_legs_share_the_removal_cell();
    return 0;
}
