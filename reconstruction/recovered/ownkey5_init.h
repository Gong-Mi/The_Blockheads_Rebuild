// Per-class descriptors for the b3j "forward-then-read own key" family
// (batch ownkey5). Each class is ONE thin OwnKeyProgram table; the whole
// executed behaviour lives in the shared engine (ownkey_loader.cpp).
//
// Decode: reconstruction/reverse-v3/native/MIDSIZE5_INITWITHWORLD.md (b3j) and
// the listings reconstruction/reverse-v3/native/disasm_*_ownkey5.txt.
// Runtime supers (resolved from the class struct, never from name similarity):
//   AppleTree (long variant) -> Tree        forwards all SIX args
//   TrainStation             -> InteractionObject
//   Plant (long variant)     -> DynamicObject  forwards only the FOUR-arg exact
//                                              selector; swallows the two
//                                              noise-function args into its own
//                                              ivars 60/64
//   GatherBlock              -> DynamicObject
//   Yak                      -> DonkeyLike
#pragma once

#include "ownkey_loader.h"

namespace blockheads::recovered {

const OwnKeyProgram& ownkey_program_apple_tree();
const OwnKeyProgram& ownkey_program_train_station();
const OwnKeyProgram& ownkey_program_plant();
const OwnKeyProgram& ownkey_program_gather_block();
const OwnKeyProgram& ownkey_program_yak();

// The five programs in the batch, for iteration in tests / the bridge.
struct OwnKeyProgramRef {
    const char* name;
    const OwnKeyProgram& (*program)();
};
const OwnKeyProgramRef* ownkey_programs();
std::size_t ownkey_program_count();

}  // namespace blockheads::recovered
