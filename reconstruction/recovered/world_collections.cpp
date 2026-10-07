#include "world_collections.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the world-collections merge family.
namespace blockheads::recovered {
namespace {

static_assert(kSlotLocalBlockheads == 0x00ffffe4f0);
static_assert(kSlotNetBlockheads == 0x00ffffe4f4);
static_assert(kSlotBlockheads == 0x00ffffe4f8);
static_assert(kSlotClient == 0x00ffffe518);
static_assert(kSlotServer == 0x00ffffe51c);
static_assert(kSlotServerClients == 0x00ffffe514);

}  // namespace
}  // namespace blockheads::recovered
