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
// NPC specials (this batch):
//   DropBear 25 -(0x0079d538, 404w, super NPC): its own body reads, after the
//       super init, nine keys in ARM-attested order (EXECUTED differential
//       tools/test_specials_arm.py) — provokeMeter float @300 ; courageMeter
//       float @304 ; dropping byte @308 ; dropSpeed float @312 ; onGround
//       byte @344 ; dropPos.x/.y int words @348/@352 ; goalTreeDirection int
//       word @356 ; saveTime floatValue. The AGE STEP then runs:
//       age@88 += ([world worldTime] (a DOUBLE) - saveTime); when
//       age > [self maxAge] the body calls removeFromMacroBlock + release and
//       returns NIL; otherwise loadDerivedStuff + return self.
//   CaveTroll 39 -(0x00d538cc, 408w, super NPC): its own body, ARM-attested
//       by the EXECUTED differential (tools/test_specials_arm.py) — super,
//       then the coordinate-wrap helper ([world worldWidthMacro] queries),
//       then: defendSquare.x/.y intValue -> words @356/@360 ; state probe;
//       when present: [bytes]/[length] -> memcpy (PLT veneer 0x1C2894) into
//       the @208 blob ; dead boolValue -> STRB @56 ; when the state blob was
//       present the wrap helper runs again (the movement-state re-init),
//       then [self initSubDerivedStuffStuff]. travelSpeed@312/travelFraction
//       @400 are world-derived (4.0f / 1.0f under the harness's
//       worldWidthMacro=4 stub).
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
    // Yak own keys (ownkey5 executed; read order milk then hair, each key
    // stores into its OWN ivar — the b3j static order was corrected by the
    // ARM run). Presence-gated: only Yak records carry them.
    bool has_milk = false;
    float milk = 0.0f;   // @1136
    bool has_hair = false;
    float hair = 0.0f;   // @1140
    // --- DropBear 25 own keys (annotated-listing decode) ---
    bool has_courage_meter = false;
    float courage_meter = 0.0f;        // @304
    bool has_provoke_meter = false;
    float provoke_meter = 0.0f;        // @300
    bool has_drop_speed = false;
    float drop_speed = 0.0f;           // @312
    bool dropping = false;             // @308 byte
    bool on_ground = false;            // @344 byte
    bool has_drop_pos = false;
    std::int32_t drop_pos_x = 0;       // @348
    std::int32_t drop_pos_y = 0;       // @352
    bool has_goal_tree_direction = false;
    std::int32_t goal_tree_direction = 0;  // @356
    bool has_save_time = false;        // read by the DropBear body's age step
    float save_time = 0.0f;
    // --- CaveTroll 39 own keys (annotated-listing decode) ---
    bool dead = false;                 // NPC.dead@56 byte
    bool has_defend_square = false;
    std::int32_t defend_square_x = 0;  // @356
    std::int32_t defend_square_y = 0;  // @360
    bool has_state = false;            // the @208 state buffer's blob
    std::size_t state_bytes = 0;
    std::string state_hex;
    bool own_body_listing_decoded = false;  // 25/39 own bodies are listing-level
};

// Reads ONE dynamic-object entry dictionary through the executed NPC chain
// (the contract runs for real; the state is read back from its image).
// Unknown keys are ignored, never invented; missing keys decode as nil
// exactly like the harness (gates stay closed, ungated slots store nil).
// type_id selects the subclass own-key table (25 DropBear / 39 CaveTroll;
// 0 = the generic NPC chain only, every other id the same).
NpcFullState npc_full_load(const SaveDict& entry, int type_id = 0);

// The registry factory for the NPC family (Dodo 13 / Donkey 28): executes
// the recovered chain on construction and returns the registry-shaped
// ClientDynamicObject; callers that need the per-type state take it via
// *out_state (nullable).
ClientDynamicObject npc_full_factory(int type_id, const SaveDict& entry,
                                     NpcFullState* out_state,
                                     std::string* error);

}  // namespace bh176
