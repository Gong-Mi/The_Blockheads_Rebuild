// Contract test for the recovered DynamicObject layout.
//
// The Python side re-reads the ivar table and requires an exact match; this test keeps the layout
// reasoning (identity block, flag cluster after it) executable in C++.
#include "dynamic_object_layout.h"

#include <cassert>
#include <cstdio>

using namespace blockheads::recovered::dynamic_object;

int main() {
    // identity / geometry block
    assert(kOffsetWorld == 4);
    assert(kOffsetDynamicWorld == 8);
    assert(kOffsetMacroTileOwner == 12);
    assert(kOffsetPos == 16);
    assert(kOffsetFloatPos == 24);
    assert(kOffsetCache == 32);
    assert(kOffsetOwnerID == 36);
    assert(kOffsetUniqueID == 40);

    // the five one-byte flags, consecutive
    assert(kOffsetNeedsRemoved == 48);
    assert(kOffsetUpdateNeedsToBeSent == 49);
    assert(kOffsetCreationDataNeedsToBeSent == 50);
    assert(kOffsetUnreliableUpdateNeedsToBeSent == 51);
    assert(kOffsetIsNet == 52);
    assert(kOffsetUpdateNeedsToBeSent == kOffsetNeedsRemoved + 1);
    assert(kOffsetIsNet == kOffsetNeedsRemoved + 4);

    // the cluster follows the identity block rather than overlapping it
    assert(kOffsetNeedsRemoved >= kOffsetUniqueID + 4);
    // uniqueID is the last 4-byte field before the flags, so the identity block is 4-byte aligned
    assert(kOffsetUniqueID % 4 == 0);

    std::puts("dynamic-object-layout: PASS");
    return 0;
}
