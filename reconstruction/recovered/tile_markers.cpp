#include "tile_markers.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the tile-marker family.
namespace blockheads::recovered {
namespace {

static_assert(kMarkerF == 0x46);
static_assert(kMarkerK == 0x4b);
static_assert(kMarkerE == 0x45);
static_assert(kOreThreshold == 0xaa);
static_assert(opensArm1(0x46));
static_assert(opensArm1(0x4b));
static_assert(!opensArm1(0x45));

}  // namespace
}  // namespace blockheads::recovered
