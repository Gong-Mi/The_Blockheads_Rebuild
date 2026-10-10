#include "dynamic_world_changed.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the dynamic-world-changed recorder family.
namespace blockheads::recovered {
namespace {

static_assert(DynamicWorldChangedRecorder::kSegmentCount == 65);
static_assert(DynamicWorldChangedRecorder::kTypeGate == 0x41);
static_assert(pairCountFromByteSpan(24) == 3);
static_assert(worldPosToMacroIndex(-33) == -1);
static_assert(worldPosToMacroIndex(31) == 0);
static_assert(worldPosToMacroIndex(32) == 1);

}  // namespace
}  // namespace blockheads::recovered
