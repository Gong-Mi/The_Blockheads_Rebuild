// Contract test for the recovered World layout model.
#include "world_layout.h"

#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::world_layout;

static std::size_t offsetOf(std::string_view want) {
    for (const Field& f : kWorldFields)
        if (f.name == want) return f.offset;
    return static_cast<std::size_t>(-1);
}

int main() {
    assert(kWorldFields.size() == 227);

    // sorted by offset and duplicate-free (also asserted at compile time in the header)
    for (std::size_t i = 1; i < kWorldFields.size(); ++i) {
        assert(kWorldFields[i - 1].offset < kWorldFields[i].offset);
    }

    // a few entries a reader would rely on, including byte-sized ones interleaved with 4-byte ones
    assert(offsetOf("motionManager") == 4);
    assert(offsetOf("interfaceOrientation") == 8);
    assert(offsetOf("supportsGyro") == 16);
    assert(offsetOf("isObservingMotionEvents") == 17);
    assert(offsetOf("worldTime") == 648);
    assert(offsetOf("sunDirection") == 660);
    assert(offsetOf("timeOfDayFraction") == 880);
    assert(offsetOf("fastForward") == 934);
    assert(offsetOf("isSimulating") == 3140);
    assert(offsetOf("imagePickerDelegate") == 3440);
    assert(offsetOf("notAnIvar") == static_cast<std::size_t>(-1));

    std::puts("world-layout: PASS");
    return 0;
}
