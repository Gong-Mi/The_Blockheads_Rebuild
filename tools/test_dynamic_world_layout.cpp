// Contract test for the recovered DynamicWorld layout.
#include "dynamic_world_layout.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::dynamic_world_layout;

static std::size_t off(std::string_view n) { return offsetOf(n); }

int main() {
    assert(kDynamicWorldFields.size() == 66);
    for (std::size_t i = 1; i < kDynamicWorldFields.size(); ++i)
        assert(kDynamicWorldFields[i - 1].offset < kDynamicWorldFields[i].offset);

    // a few named anchors a reader would rely on
    assert(off("world") == 4);
    assert(off("worldTileLoader") == 8);
    assert(off("dynamicObjectDatabase") == 36);
    assert(off("blockheads") == 44);
    assert(off("dynamicObjects") == 60);
    assert(off("workbenchHasBeenCrafted") == 7370);
    assert(off("wirePathCreator") == 9496);
    assert(off("notAnIvar") == static_cast<std::size_t>(-1));

    // the structural fact: three inline containers of the same shape, 780 bytes apart. This is why an
    // ObjC-graph walk stops in front of them - their contents are inside, not pointed at.
    assert(off("dynamicObjectsToAdd") - off("dynamicObjects") == 780);
    assert(off("dynamicObjectsByWorldPosIndex") - off("dynamicObjectsToAdd") == 780);
    assert(off("freeBlocksByPosition") - off("dynamicObjectsByWorldPosIndex") == 780);

    std::puts("dynamic-world-layout: PASS");
    return 0;
}
