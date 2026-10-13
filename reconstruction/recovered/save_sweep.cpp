#include "save_sweep.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the five-container save sweep family.
namespace blockheads::recovered {
namespace {

static_assert(FiveContainerSweep::kContainerCount == 5);
static_assert(kSweepDynamicChangedSlice == 0x120);

}  // namespace
}  // namespace blockheads::recovered
