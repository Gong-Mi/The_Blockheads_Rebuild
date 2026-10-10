#include "ownkey5_init.h"

namespace blockheads::recovered {
namespace {

using K = OwnKeyStepKind;
using C = OwnKeyConv;

// AppleTree: forward all six long-variant args to Tree, then
//   availableFood -> floatValue -> @136 (32-bit float store).
const OwnKeyStep kAppleTree[] = {
    {K::ReadOwnKey, C::FloatValue, "availableFood", 136},
};

// TrainStation: forward four, then
//   text -> retain -> @128, then [self initSubDerivedItems].
const OwnKeyStep kTrainStation[] = {
    {K::ReadOwnKey, C::Retain, "text", 128},
    {K::TailHook, C::IntValue, "initSubDerivedItems", 0},
};

// Plant: forward the FOUR-arg exact selector only; the two noise-function args
// are swallowed into own ivars 60/64, then delegate + notify.
const OwnKeyStep kPlant[] = {
    {K::StoreIncomingArg, C::IntValue, "treeDensityNoiseFunction", 60},
    {K::StoreIncomingArg, C::IntValue, "seasonOffsetNoiseFunction", 64},
    {K::TailHook, C::IntValue, "loadSaveDictValues:", 0},
    {K::DynamicWorldNotify, C::IntValue, nullptr, 0},
};

// GatherBlock: forward four, then
//   timer -> floatValue -> (float)(uint32) -> @56,
//   lastKnownGatherValue -> intValue -> @60.
// EXECUTED CORRECTION of the b3j static decode: the round-tripped float chain
// belongs to `timer` and the plain integer chain to `lastKnownGatherValue`
// (the static decode had the two key/conversion pairs swapped). Verified by
// the executed selector sequence (objectForKey:timer -> floatValue ->
// store@56, then objectForKey:lastKnownGatherValue -> intValue -> store@60)
// and by the ivar symbol table
// (OBJC_IVAR_$_GatherBlock.timer = 56, .lastKnownGatherValue = 60).
const OwnKeyStep kGatherBlock[] = {
    {K::ReadOwnKey, C::FloatValueThroughUint32, "timer", 56},
    {K::ReadOwnKey, C::IntValue, "lastKnownGatherValue", 60},
};

// Yak: milk -> floatValue -> @1136 first, then hair -> floatValue -> @1140,
// then updateTextures.
// EXECUTED CORRECTION of the b3j static decode: the read order is milk then
// hair (each key stores into its OWN ivar), not hair then milk. Verified by
// the executed selector sequence and the ivar symbol table
// (OBJC_IVAR_$_Yak.milk = 1136, .hair = 1140).
const OwnKeyStep kYak[] = {
    {K::ReadOwnKey, C::FloatValue, "milk", 1136},
    {K::ReadOwnKey, C::FloatValue, "hair", 1140},
    {K::TailHook, C::IntValue, "updateTextures", 0},
};

const OwnKeyProgram kPrograms[] = {
    {"AppleTree",
     "initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:"
     "seasonOffsetNoiseFunction:",
     true, kAppleTree, sizeof(kAppleTree) / sizeof(kAppleTree[0])},
    {"TrainStation", "initWithWorld:dynamicWorld:saveDict:cache:", false,
     kTrainStation, sizeof(kTrainStation) / sizeof(kTrainStation[0])},
    {"Plant",
     "initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:"
     "seasonOffsetNoiseFunction:",
     false, kPlant, sizeof(kPlant) / sizeof(kPlant[0])},
    {"GatherBlock", "initWithWorld:dynamicWorld:saveDict:cache:", false,
     kGatherBlock, sizeof(kGatherBlock) / sizeof(kGatherBlock[0])},
    {"Yak", "initWithWorld:dynamicWorld:saveDict:cache:", false, kYak,
     sizeof(kYak) / sizeof(kYak[0])},
};

const OwnKeyProgramRef kRefs[] = {
    {"AppleTree", &ownkey_program_apple_tree},
    {"TrainStation", &ownkey_program_train_station},
    {"Plant", &ownkey_program_plant},
    {"GatherBlock", &ownkey_program_gather_block},
    {"Yak", &ownkey_program_yak},
};

}  // namespace

const OwnKeyProgram& ownkey_program_apple_tree() { return kPrograms[0]; }
const OwnKeyProgram& ownkey_program_train_station() { return kPrograms[1]; }
const OwnKeyProgram& ownkey_program_plant() { return kPrograms[2]; }
const OwnKeyProgram& ownkey_program_gather_block() { return kPrograms[3]; }
const OwnKeyProgram& ownkey_program_yak() { return kPrograms[4]; }

const OwnKeyProgramRef* ownkey_programs() { return kRefs; }
std::size_t ownkey_program_count() {
    return sizeof(kRefs) / sizeof(kRefs[0]);
}

}  // namespace blockheads::recovered
