// Contract test for the recovered Action layout - the crafting interaction's state holder.
#include "action_layout.h"
#include "interaction_test_result.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::action_layout;

static std::size_t off(std::string_view n) { return offsetOf(n); }

int main() {
    assert(kActionFields.size() == 16);
    for (std::size_t i = 1; i < kActionFields.size(); ++i)
        assert(kActionFields[i - 1].offset < kActionFields[i].offset);

    // the offsets the earlier b3d artifact recorded from the deserialiser, all reproduced here
    assert(off("inProgress") == 4);
    assert(off("interactionItem") == 16);
    assert(off("interactionItemIndex") == 20);
    assert(off("interactionObjectID") == 32);
    assert(off("craftCountOrExtraData") == 44);
    assert(off("interactionTestResult") == 52);
    assert(off("inventoryChange") == 64);
    assert(off("notAnIvar") == static_cast<std::size_t>(-1));

    // the two models must agree about where the InteractionTestResult record lives: this layout says 52 and
    // interaction_test_result.h carries the same number as its host constant
    assert(off("interactionTestResult") == blockheads::recovered::kInteractionTestResultActionIvarOffset);
    // and the 12-byte record must fit inside the next ivar's slot, with nothing overlapping
    assert(off("interactionTestResult") + sizeof(blockheads::recovered::InteractionTestResult)
           <= off("inventoryChange"));

    std::puts("action-layout: PASS");
    return 0;
}
