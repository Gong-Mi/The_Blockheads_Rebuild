#include "blockhead_selection.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the blockhead-selection family.
namespace blockheads::recovered {
namespace {

static_assert(kSelectedIndexSlot == 0x00ffffe55c);

}  // namespace
}  // namespace blockheads::recovered
