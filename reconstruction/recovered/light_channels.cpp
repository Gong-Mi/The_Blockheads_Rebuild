#include "light_channels.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the light-channel array family.
namespace blockheads::recovered {
namespace {

static_assert(kLightChannelCount == 32);
static_assert(kChannelRecordStride == 12);
static_assert(0x180 / 12 == kLightChannelCount);  // the E29 destructor loop

}  // namespace
}  // namespace blockheads::recovered
