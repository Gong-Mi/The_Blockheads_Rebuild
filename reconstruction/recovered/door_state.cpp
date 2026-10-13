#include "door_state.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the door-state family.
namespace blockheads::recovered {
namespace {

static_assert(kDoorTileMarker == 0x46);
static_assert(kDoorMarkerAcceptedByte1 == 0x34);
static_assert(kDoorMarkerAcceptedByte2 == 0xa4);
static_assert(canWriteDoorMarker(0x34));
static_assert(canWriteDoorMarker(0xa4));
static_assert(!canWriteDoorMarker(0x46));

}  // namespace
}  // namespace blockheads::recovered
