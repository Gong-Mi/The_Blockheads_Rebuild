#include "client_registry.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the client-registry family.
namespace blockheads::recovered {
namespace {

static_assert(kMutePropagationCell == 0x00ffe237a8);
static_assert(kBanPropagationCell == 0x00ffe237ac);
static_assert(kBanQueryCell == 0x00ffe237b0);
static_assert(kPlayersChangedCell == 0x00ffe237b4);
static_assert(kOwnerNameCell == 0x00ffe237b8);
static_assert(kClientSliceOffset == 0x270);
static_assert(kPoleTakenKeyId == 0x00fff34284);

}  // namespace
}  // namespace blockheads::recovered
