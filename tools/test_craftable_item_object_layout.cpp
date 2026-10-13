// Contract test for the recovered CraftableItemObject layout (generated).
#include "craftable_item_object_layout.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::craftable_item_object_layout;

int main() {
    assert(kCraftableItemObjectFields.size() == 1);
    for (std::size_t i = 1; i < kCraftableItemObjectFields.size(); ++i)
        assert(kCraftableItemObjectFields[i - 1].offset < kCraftableItemObjectFields[i].offset);
    assert(offsetOf("craftableItem") == 4);
    assert(offsetOf("thisIsNotAnIvar") == static_cast<std::size_t>(-1));
    std::puts("craftable_item_object-layout: PASS");
    return 0;
}
