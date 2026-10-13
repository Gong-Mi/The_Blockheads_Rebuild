// Recovered contract: the DynamicWorld dynamic-object type codes, family gates
// and the ffffe54c member slice offsets.
//
// Evidence (reverse-v3 level A, batches E24-E44; all values are immediates or
// cell-pinned member arithmetic recorded in the batch artifacts):
//   - Type codes (the `XAtPos:` / add / remove dispatch triples):
//       fire = 0x10 (16)          E36 placeFireAtPosition: (0x008e80e4)
//       torch = 0x11 (17)         E36 torchAtPos: (0x008e888c)
//       ladder = 0x13 (19)        E37 ladderAtPos: (0x008eb468)
//       door = 0x14 (20)          E38 doorAtPos: (0x008ed7c0)
//       egg = 0x1e (30)           E36 eggAtPos: (0x008ea738)
//       window = 0x1f (31)        E38 windowAtPos: (0x008ed3a4)
//       rail = 0x28 (40)          E43 getRailAtPos: (0x008ed254)
//       workbench = 0x2d (45)     E39 workbenchAtPos: (0x008efe3c)
//       painting = 0x34 (52)      E36 paintingAtPos: (0x008eabf8)
//       column = 0x35 (53)        E37 columnAtPos: (0x008eb630)
//       stairs = 0x36 (54)        E37 stairsAtPos: (0x008eb7f8)
//       elevatorMotor = 0x37 (55) E43 elevatorMotorAtPos: (0x008ebed0)
//       elevatorShaft = 0x38 (56) E37 elevatorShaftAtPos: (0x008ebb88)
//   - The >= 0x41 type gate: saveDynamicObjects (E40 0x008b254c), hasLight-
//     sToAdd (E34 0x009034b8), addArtificialLightContribution (E29), loadClien-
//     tOwned (E40) all bail for type >= 0x41 (65).
//   - Per-body skip sets (type immediates):
//       dynamicWorldChangedAtPos: skip {0x16, 0x1d}            E30 (0x008e1390)
//       saveDynamicObjects skip {0x2e, 0x18}                   E40 (0x008b254c)
//       remoteCreate: skip {0xe} (FreeBlock)                   E40 (0x008c3c08)
//   - Family index gates (the jump-table dispatch counts):
//       tree classes < 0xb (11)      E43 treeAtPos: (0x00E4AA64 table)
//       NPC families < 8             E32/E34 (0x00E4AA1C table)
//       interaction families < 9     E39 (0x00E4AA90 table)
//       train/rail/station < 4       E34/E38/E43 (0x00E4AA0C table)
//   - ffffe54c member slice offsets (offset-pinned by member arithmetic):
//       +0x9c  / +0x150 / +0x1d4 / +0x264 / +0x2f4   E31 ridable cascade order
//       +0xa8  free blocks                            E41 drawFreeBlocks / E42 freeblockWithUniqueID
//       +0x180 boats                                   E38 boatWithID / checkForBoatUnderTap
//       +0x1d4 path users                              E34 pathUsers
//       +0x1e0 rail existence                          E30 addRailAtPos:
//       +0x21c workbenches                             E39 assignCraftProgress...
//       +0x270 clients (mute walk) / painting lookup   E33 / E36
//       +0xcc  family slice seen in the draw composite E44 (0x008d7c84)
//
// This module models ONLY the constant tables and the two small pure helpers
// (the type gate and the macro-position conversion). It does not model any
// object graph.
//
// Boundaries (do not promote beyond evidence):
//   - Slice offsets are offset-pinned identities, not resolved member names.
//   - The ridable cascade order is the observed probe order (first hit wins).
//   - jump-table arm counts are read from the per-call gates; the tables'
//     remaining slots are not claimed.
#pragma once

#include <cstdint>

namespace blockheads::recovered {

enum class DynamicObjectType : int {
    kFire = 0x10,
    kTorch = 0x11,
    kLadder = 0x13,
    kDoor = 0x14,
    kEgg = 0x1e,
    kWindow = 0x1f,
    kRail = 0x28,
    kWorkbench = 0x2d,
    kPainting = 0x34,
    kColumn = 0x35,
    kStairs = 0x36,
    kElevatorMotor = 0x37,
    kElevatorShaft = 0x38,
};

// The universal type gate observed across the batch family: bodies bail when
// the object type is >= 0x41 (65).
constexpr int kTypeGate = 0x41;

constexpr bool passesTypeGate(int type) { return type < kTypeGate; }

// Per-body skip sets (exact type immediates from the compares).
constexpr bool isDynamicWorldChangedSkip(int type) { return type == 0x16 || type == 0x1d; }
constexpr bool isSaveDynamicObjectsSkip(int type) { return type == 0x2e || type == 0x18; }
constexpr bool isRemoteCreateSkip(int type) { return type == 0xe; }  // FreeBlock

// Family index gates (jump-table dispatch counts).
constexpr int kTreeClassCount = 0xb;         // 11  (0x00E4AA64 table)
constexpr int kNpcFamilyCount = 8;           //  8  (0x00E4AA1C table)
constexpr int kInteractionFamilyCount = 9;   //  9  (0x00E4AA90 table)
constexpr int kTrainFamilyCount = 4;         //  4  (0x00E4AA0C table)

constexpr bool isValidTreeClassIndex(int i) { return i >= 0 && i < kTreeClassCount; }
constexpr bool isValidNpcFamilyIndex(int i) { return i >= 0 && i < kNpcFamilyCount; }
constexpr bool isValidInteractionFamilyIndex(int i) { return i >= 0 && i < kInteractionFamilyCount; }
constexpr bool isValidTrainFamilyIndex(int i) { return i >= 0 && i < kTrainFamilyCount; }

// ffffe54c member slice offsets (offset-pinned).
constexpr int kSliceFreeBlocks = 0xa8;    // E41/E42
constexpr int kSliceBoats = 0x180;        // E38
constexpr int kSlicePathUsers = 0x1d4;    // E34
constexpr int kSliceRailExistence = 0x1e0;// E30
constexpr int kSliceWorkbenches = 0x21c;  // E39
constexpr int kSliceClients = 0x270;      // E33/E36
constexpr int kSliceDrawFamilyCc = 0xcc;  // E44 (0x008d7c84)

// The ridable resolver probes the family slices in this exact order (first hit wins).
inline constexpr int kRidableFamilySlices[] = {0x150, 0x2f4, 0x9c, 0x264, 0x1d4};

// Macro-position conversion: `pos / 32` using ARM __aeabi_idiv semantics
// (signed division truncating toward zero; the original computes this through
// the libcall and packs with makeIntpair - E16/E22/E23).
constexpr int worldPosToMacro(int worldPos) {
    return worldPos / 32;  // C++ / on ints truncates toward zero, matching __aeabi_idiv
}

}  // namespace blockheads::recovered
