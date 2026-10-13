// Contract test for the recovered PaintMixUI layout - the class the live crafting read depends on.
#include "paint_mix_ui_layout.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::paint_mix_ui_layout;

static std::size_t off(std::string_view n) { return offsetOf(n); }

int main() {
    assert(kPaintMixUIFields.size() == 28);
    for (std::size_t i = 1; i < kPaintMixUIFields.size(); ++i)
        assert(kPaintMixUIFields[i - 1].offset < kPaintMixUIFields[i].offset);

    // the anchors the live probe watches, with the live values recorded elsewhere
    assert(off("world") == 20);
    assert(off("workbench") == 104);
    assert(off("blockhead") == 108);
    assert(off("incomingCraftableItemObject") == 112);
    assert(off("craftButton") == 120);
    assert(off("countSlider") == 128);
    assert(off("currentCount") == 132);
    assert(off("notAnIvar") == static_cast<std::size_t>(-1));

    std::puts("paint-mix-ui-layout: PASS");
    return 0;
}
