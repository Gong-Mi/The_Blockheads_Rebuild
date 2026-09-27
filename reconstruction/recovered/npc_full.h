// Full NPC-family loader (bucket B): turns a real save record (Dodo 13,
// Donkey 28, and every NPC subclass whose records carry the NPC key set)
// into a populated ClientDynamicObject using ONLY executed/recovered
// contracts.
//
// Original chain (all links already recovered & executed in prior batches):
//   DynamicObject initWithWorld:dynamicWorld:saveDict:cache:
//       (base: uniqueID unsignedLongValue@40, pos_x/pos_y intValue@16/@20,
//        floatPos objectAtIndex:0/1 floatValue@24)          [b3l/PR#3]
//   NPC initWithWorld:dynamicWorld:saveDict:cache: (0x00644b24)
//       super init, nil propagation, then loadValuesFromSaveDict:,
//       randomHarmFromHungerTimer@144 = 1 + 20*(lrand48()/2^31)
//                                                          [b3g, executed]
//   NPC loadValuesFromSaveDict: (0x00643b20, 603 words)
//       G1 fullness gate  -> fullness@68 layTimer@80 damage@54(strh)
//                            age@88
//       G2 layCooldownTimer gate -> layCooldownTimer@84
//                            tameCooldownTimer@72 mateCooldownTimer@76
//                            hasBred@100 hasBeenFedByBlockheadOrChest@101
//                            mateBreed@98(strh)
//       G3 breed gate     -> breed@96(strh, unsignedIntegerValue)
//       ungated: tamedClientID@108 name@92 tameCountsByClientID@104(copy)
//                savedBlockheadIndex@136 = -1 / currentBlockheadIndex
//                                                          [b3n/b4f, executed]
//   Dodo/DonkeyLike initWithWorld:…: saveDict:cache: (forwarder5, 69 words)
//       forwards to NPC init, then [self loadDerivedStuff] — the five
//       forwarders are pinned word-for-word (static level-A); their own
//       loadDerivedStuff bodies are NOT recovered yet and contribute no
//       save keys of their own (zero-own-state readers).
//
// Save-record keys are therefore FULLY explained for the family:
//   {uniqueID, pos_x, pos_y, floatPos}                     (base level)
//   {fullness, layTimer, damage, age}                      (G1)
//   {layCooldownTimer, tameCooldownTimer, mateCooldownTimer,
//    hasBred, hasBeenFedByBlockheadOrChest, mateBreed}     (G2)
//   {breed}                                                (G3)
//   {tamedClientID, name, tameCountsByClientID,
//    currentBlockheadIndex}                                (ungated)
//   saveTime is written by NPC getSaveDict on the save side and is not
//   read back by this loader.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

#include "npc_load_values_from_save_dict.h"

namespace bh176 {

// The NPC-level state a record carries after the executed chain runs.
// Offsets are the original ivar offsets (see npc_load_values_from_save_dict.h);
// values are the decoded stores read back out of the contract's image.
struct NpcFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // G1 (fullness gate)
    bool g1_present = false;
    float fullness = 0.0f;           // @68
    float lay_timer = 0.0f;          // @80
    std::uint16_t damage = 0;        // @54 strh (intValue truncated)
    float age = 0.0f;                // @88
    // G2 (layCooldownTimer gate)
    bool g2_present = false;
    float lay_cooldown_timer = 0.0f; // @84
    float tame_cooldown_timer = 0.0f;// @72
    float mate_cooldown_timer = 0.0f;// @76
    bool has_bred = false;           // @100
    bool has_been_fed = false;       // @101
    std::uint16_t mate_breed = 0;    // @98 strh
    // G3
    std::uint16_t breed = 0;         // @96 strh
    // ungated object slots: retained object or nil (0 in the offline image)
    bool has_tamed_client_id = false;
    bool has_name = false;
    bool has_tame_counts = false;
    std::int32_t saved_blockhead_index = -1;  // @136
};

// Reads ONE dynamic-object entry dictionary through the executed NPC chain
// (the contract runs for real; the state is read back from its image).
// Unknown keys are ignored, never invented; missing keys decode as nil
// exactly like the harness (gates stay closed, ungated slots store nil).
NpcFullState npc_full_load(const SaveDict& entry);

// The registry factory for the NPC family (Dodo 13 / Donkey 28): executes
// the recovered chain on construction and returns the registry-shaped
// ClientDynamicObject; callers that need the per-type state take it via
// *out_state (nullable).
ClientDynamicObject npc_full_factory(int type_id, const SaveDict& entry,
                                     NpcFullState* out_state,
                                     std::string* error);

}  // namespace bh176
