// Contract test for the recovered Workbench layout (generated).
#include "workbench_layout.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::workbench_layout;

int main() {
    assert(kWorkbenchFields.size() == 48);
    for (std::size_t i = 1; i < kWorkbenchFields.size(); ++i)
        assert(kWorkbenchFields[i - 1].offset < kWorkbenchFields[i].offset);
    assert(offsetOf("craftingItemObject") == 180);
    assert(offsetOf("selectedIndex") == 136);
    assert(offsetOf("numberOfCraftableItems") == 124);
    assert(offsetOf("type") == 120);
    assert(offsetOf("sourceItems") == 140);
    assert(offsetOf("thisIsNotAnIvar") == static_cast<std::size_t>(-1));
    std::puts("workbench-layout: PASS");
    return 0;
}
