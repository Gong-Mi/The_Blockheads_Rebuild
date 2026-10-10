#include "npc_feed_response.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the NPC-feed-response family (E117).
namespace blockheads::recovered {
namespace {

static_assert(kFeedFullnessGain == 2700.0, "fullness gain (pool 0x64b640)");
static_assert(kFeedFullnessMax == 8100.0, "fullness clamp (pools 0x64b638/648)");
static_assert(kFeedFillValue == 675.0f, "fill value 0x2a3 (pool 0x64b64c)");
static_assert(kFeedHalveDivisor == 2, "the idiv divisor (movw r1, 2)");

}  // namespace
}  // namespace blockheads::recovered
