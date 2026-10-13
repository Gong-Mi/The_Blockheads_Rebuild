// Contract tests for the recovered dynamic-object type-code slice (E24-E44).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_dynamic_object_type_codes.cpp
//       reconstruction/recovered/dynamic_object_type_codes.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "dynamic_object_type_codes.h"

#include <cassert>

using namespace blockheads::recovered;

static void test_type_codes_exact() {
    // Every value is an immediate pinned in its batch listing.
    assert(static_cast<int>(DynamicObjectType::kFire) == 16);           // E36
    assert(static_cast<int>(DynamicObjectType::kTorch) == 17);          // E36
    assert(static_cast<int>(DynamicObjectType::kLadder) == 19);         // E37
    assert(static_cast<int>(DynamicObjectType::kDoor) == 20);           // E38
    assert(static_cast<int>(DynamicObjectType::kEgg) == 30);            // E36
    assert(static_cast<int>(DynamicObjectType::kWindow) == 31);         // E38
    assert(static_cast<int>(DynamicObjectType::kRail) == 40);           // E43
    assert(static_cast<int>(DynamicObjectType::kWorkbench) == 45);      // E39
    assert(static_cast<int>(DynamicObjectType::kPainting) == 52);       // E36
    assert(static_cast<int>(DynamicObjectType::kColumn) == 53);         // E37
    assert(static_cast<int>(DynamicObjectType::kStairs) == 54);         // E37
    assert(static_cast<int>(DynamicObjectType::kElevatorMotor) == 55);  // E43
    assert(static_cast<int>(DynamicObjectType::kElevatorShaft) == 56);  // E37
}

static void test_type_gate() {
    assert(kTypeGate == 0x41);
    assert(passesTypeGate(0));
    assert(passesTypeGate(0x40));
    assert(!passesTypeGate(0x41));
    assert(!passesTypeGate(0x67));
}

static void test_skip_sets() {
    // E30 dynamicWorldChangedAtPos:
    assert(isDynamicWorldChangedSkip(0x16));
    assert(isDynamicWorldChangedSkip(0x1d));
    assert(!isDynamicWorldChangedSkip(0x15));
    // E40 saveDynamicObjects
    assert(isSaveDynamicObjectsSkip(0x2e));
    assert(isSaveDynamicObjectsSkip(0x18));
    assert(!isSaveDynamicObjectsSkip(0x2d));
    // E40 remoteCreate: (FreeBlock)
    assert(isRemoteCreateSkip(0xe));
    assert(!isRemoteCreateSkip(0xf));
}

static void test_family_gates() {
    assert(kTreeClassCount == 11);
    assert(isValidTreeClassIndex(0));
    assert(isValidTreeClassIndex(10));
    assert(!isValidTreeClassIndex(11));   // treeAtPos: arg >= 0xb -> nil
    assert(!isValidTreeClassIndex(-1));
    assert(kNpcFamilyCount == 8);
    assert(isValidNpcFamilyIndex(7));
    assert(!isValidNpcFamilyIndex(8));    // npcWithID:/npcExists: gate
    assert(kInteractionFamilyCount == 9);
    assert(isValidInteractionFamilyIndex(8));
    assert(!isValidInteractionFamilyIndex(9));  // interactionObjectWithID: gate
    assert(kTrainFamilyCount == 4);
    assert(isValidTrainFamilyIndex(3));
    assert(!isValidTrainFamilyIndex(4));  // rail/station + trainCar gate
}

static void test_slice_offsets() {
    assert(kSliceFreeBlocks == 0xa8);
    assert(kSliceBoats == 0x180);
    assert(kSlicePathUsers == 0x1d4);
    assert(kSliceRailExistence == 0x1e0);
    assert(kSliceWorkbenches == 0x21c);
    assert(kSliceClients == 0x270);
    assert(kSliceDrawFamilyCc == 0xcc);
    // The ridable cascade probes these five slices in this exact order (E31).
    assert(kRidableFamilySlices[0] == 0x150);
    assert(kRidableFamilySlices[1] == 0x2f4);
    assert(kRidableFamilySlices[2] == 0x9c);
    assert(kRidableFamilySlices[3] == 0x264);
    assert(kRidableFamilySlices[4] == 0x1d4);
}

static void test_macro_conversion() {
    // __aeabi_idiv truncation toward zero (E16/E22/E23).
    assert(worldPosToMacro(0) == 0);
    assert(worldPosToMacro(31) == 0);
    assert(worldPosToMacro(32) == 1);
    assert(worldPosToMacro(63) == 1);
    assert(worldPosToMacro(-1) == 0);
    assert(worldPosToMacro(-31) == 0);
    assert(worldPosToMacro(-32) == -1);
    assert(worldPosToMacro(-33) == -1);
}

int main() {
    test_type_codes_exact();
    test_type_gate();
    test_skip_sets();
    test_family_gates();
    test_slice_offsets();
    test_macro_conversion();
    return 0;
}
