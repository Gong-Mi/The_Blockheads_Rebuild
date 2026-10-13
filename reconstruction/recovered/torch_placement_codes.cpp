#include "torch_placement_codes.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the torch-placement-code family.
namespace blockheads::recovered {
namespace {

static_assert(static_cast<std::int32_t>(TorchPlacementCode::kNoValidPosition) == -2);
static_assert(static_cast<std::int32_t>(TorchPlacementCode::kXMinusOneDoor) == -1);
static_assert(static_cast<std::int32_t>(TorchPlacementCode::kSolidBelow) == 0);
static_assert(static_cast<std::int32_t>(TorchPlacementCode::kSolidPlusDoor) == 1);
static_assert(static_cast<std::int32_t>(TorchPlacementCode::kHalfDepth) == 2);
static_assert(static_cast<std::int32_t>(TorchPlacementCode::kMarkerD) == 3);
static_assert(kMarkerByte == 0x64);

}  // namespace
}  // namespace blockheads::recovered
