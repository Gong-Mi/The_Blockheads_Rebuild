// Contract test for the recovered DynamicObject flag-cluster model.
//
// The offsets in the header are the ones the artifact was derived to; the Python-side test
// (tools/test_dynamicobject_flags.py) additionally re-derives them from the binary and compares them
// with the header, so a typo here cannot survive both checks.
#include "dynamic_object_flags.h"

#include <cassert>
#include <cstdint>
#include <cstdio>

using namespace blockheads::recovered;

int main() {
    // offsets, in the order the artifact records them
    assert(kOffsetNeedsRemoved == 48);
    assert(kOffsetUpdateNeedsToBeSent == 49);
    assert(kOffsetCreationDataNeedsToBeSent == 50);
    assert(kOffsetUnreliableUpdateNeedsToBeSent == 51);
    assert(kOffsetIsNet == 52);

    // truthiness: the getter returns a signed char and callers test truth, so a negative is SET
    assert(flagIsSet(1) && flagIsSet(0xFF) && flagIsSet(static_cast<std::uint8_t>(-128 & 0xFF)));
    assert(!flagIsSet(0));

    // the verified setter stores 1
    assert(setFlag() == 1);

    // the gate: the loop leaves only when the flag is set
    assert(!leavesUpdateLoop(0));
    assert(leavesUpdateLoop(1));
    assert(leavesUpdateLoop(0xFF));

    std::puts("dynamic-object-flags-model: PASS");
    return 0;
}
