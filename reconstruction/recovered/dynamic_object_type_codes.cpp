#include "dynamic_object_type_codes.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the type-code table family, consistent with the other recovered modules.
namespace blockheads::recovered {
namespace {

static_assert(static_cast<int>(DynamicObjectType::kFire) == 16);
static_assert(static_cast<int>(DynamicObjectType::kTorch) == 17);
static_assert(static_cast<int>(DynamicObjectType::kLadder) == 19);
static_assert(static_cast<int>(DynamicObjectType::kDoor) == 20);
static_assert(static_cast<int>(DynamicObjectType::kEgg) == 30);
static_assert(static_cast<int>(DynamicObjectType::kWindow) == 31);
static_assert(static_cast<int>(DynamicObjectType::kRail) == 40);
static_assert(static_cast<int>(DynamicObjectType::kWorkbench) == 45);
static_assert(static_cast<int>(DynamicObjectType::kPainting) == 52);
static_assert(static_cast<int>(DynamicObjectType::kColumn) == 53);
static_assert(static_cast<int>(DynamicObjectType::kStairs) == 54);
static_assert(static_cast<int>(DynamicObjectType::kElevatorMotor) == 55);
static_assert(static_cast<int>(DynamicObjectType::kElevatorShaft) == 56);
static_assert(kTreeClassCount == 11);
static_assert(kNpcFamilyCount == 8);
static_assert(kInteractionFamilyCount == 9);
static_assert(kTrainFamilyCount == 4);
static_assert(sizeof(kRidableFamilySlices) / sizeof(kRidableFamilySlices[0]) == 5);

}  // namespace
}  // namespace blockheads::recovered
