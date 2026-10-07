#include "train_type_traits.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the train-type-traits family.
namespace blockheads::recovered {
namespace {

static_assert(kTrainItemType == 205);
static_assert(kTrainObjectType == 42);
static_assert(kTrainFuelItemCount == 4);
static_assert(kTrainMaxRiders == 1);
static_assert(kTrainFuelUIOffsetY == 4.0f);
static_assert(trainIsEngine());
static_assert(trainRequiresFuel());
static_assert(!trainCanDismissFuelUI());

}  // namespace
}  // namespace blockheads::recovered
