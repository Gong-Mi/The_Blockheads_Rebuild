#include "family_probes.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the family-probe patterns.
namespace blockheads::recovered {
namespace {

static_assert(kNpcArmCount == 8);
static_assert(kInteractionArmCount == 9);
static_assert(kTreeArmCount == 11);
static_assert(kTrainArmCount == 4);

}  // namespace
}  // namespace blockheads::recovered
