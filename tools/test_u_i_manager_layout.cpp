// Contract test for the recovered UIManager layout (generated).
#include "u_i_manager_layout.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::u_i_manager_layout;

int main() {
    assert(kUIManagerFields.size() == 46);
    for (std::size_t i = 1; i < kUIManagerFields.size(); ++i)
        assert(kUIManagerFields[i - 1].offset < kUIManagerFields[i].offset);
    assert(offsetOf("paintMixUI") == 56);
    assert(offsetOf("world") == 4);
    assert(offsetOf("dynamicWorld") == 8);
    assert(offsetOf("craftUI") == 48);
    assert(offsetOf("thisIsNotAnIvar") == static_cast<std::size_t>(-1));
    std::puts("u_i_manager-layout: PASS");
    return 0;
}
