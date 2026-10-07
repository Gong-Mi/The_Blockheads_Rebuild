#include "simulation_step.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the simulation-step family.
namespace blockheads::recovered {
namespace {

static_assert(kFamilyCount == 8);
static_assert(kSlotCount == 8);

}  // namespace
}  // namespace blockheads::recovered
