#include "dynamic_object_layout.h"

namespace blockheads::recovered::dynamic_object {
namespace {
// the identity block is 4-byte aligned and contiguous in steps of four up to uniqueID
static_assert(kOffsetWorld == 4);
static_assert(kOffsetDynamicWorld == 8);
static_assert(kOffsetMacroTileOwner == 12);
static_assert(kOffsetPos == 16);
static_assert(kOffsetUniqueID == 40);
// the five flags are consecutive
static_assert(kOffsetUpdateNeedsToBeSent == kOffsetNeedsRemoved + 1);
static_assert(kOffsetCreationDataNeedsToBeSent == kOffsetNeedsRemoved + 2);
static_assert(kOffsetUnreliableUpdateNeedsToBeSent == kOffsetNeedsRemoved + 3);
static_assert(kOffsetIsNet == kOffsetNeedsRemoved + 4);
}  // namespace
}  // namespace blockheads::recovered::dynamic_object
