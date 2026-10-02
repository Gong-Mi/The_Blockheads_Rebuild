// FreeBlock loader (type 14): the b4p executed chain (1,347w, 14 cases
// bit-exact), save-key surface only — the world-dependent tail is stated,
// not simulated.
//
// Original chain (executed evidence, FREEBLOCK_INIT_ARM.md):
//   DynamicObject base (4-arg super forward, executed)
//   FreeBlock initWithWorld:dynamicWorld:saveDict:cache: (0x00626A68):
//     bounceTimer@?          floatValue
//     fallSpeed              floatValue
//     creationTime           doubleValue
//     floatPos.x             floatValue(key "floatPos[VX]")
//     floatPos.y             floatValue(key "floatPos[VY]")
//     hovers                 boolValue (byte)
//     itemType               intValue (word)
//     dataA / dataB          intValue -> strh truncation
//     subItems               array OF ARRAYS of InventoryItem save payloads,
//                            inner itemType != 11 filter (per inner item)
//     dynamicObjectSaveDict  copy (object slot)
//     priorityBlockheadUinqueID  intValue (the original's own typo); nonzero
//                            triggers the world blockhead lookup
//   tail (world-dependent, NOT save decode): hovers expiry via
//     [world worldTime] - creationTime, itemType blacklists, ground-fall
//     probe, then initSubDerivedObjects.
//
// SCOPE (stated): this loader captures the save-key surface — scalars, the
// two floatPos component keys, subItems slot/item counts (NO item payload
// decode: InventoryItem initWithSaveData: is a separate module, so the
// itemType != 11 filter is not applied offline), the dynamicObjectSaveDict
// slot presence and the priority id. The world-dependent tail (hovers
// re-anchor / blockhead lookup / ground fall) is not run offline and is
// reported as such.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>
#include <vector>

namespace bh176 {

struct FreeBlockFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // b4p own keys
    bool has_bounce_timer = false;
    float bounce_timer = 0.0f;
    bool has_fall_speed = false;
    float fall_speed = 0.0f;
    bool has_creation_time = false;
    double creation_time = 0.0;
    bool has_float_pos_vx = false;
    float float_pos_vx = 0.0f;   // key "floatPos[VX]"
    bool has_float_pos_vy = false;
    float float_pos_vy = 0.0f;   // key "floatPos[VY]"
    bool has_hovers = false;
    bool hovers = false;
    bool has_item_type = false;
    std::uint32_t item_type = 0;
    bool has_data_a = false;
    std::uint16_t data_a = 0;    // strh truncation
    bool has_data_b = false;
    std::uint16_t data_b = 0;    // strh truncation
    // subItems: array of arrays of item payloads — counts only (no decode)
    bool has_sub_items = false;
    std::size_t sub_slot_count = 0;
    std::vector<std::size_t> sub_slot_item_counts;
    bool item_decode_performed = false;  // always false offline (stated)
    bool has_dynamic_object_save_dict = false;  // object slot
    bool has_priority_blockhead_id = false;
    std::int32_t priority_blockhead_id = 0;     // int32 path of the int64 read
    // world-dependent tail not simulated offline
    bool world_tail_not_run = true;             // always true offline (stated)
};

FreeBlockFullState freeblock_full_load(const SaveDict& entry);

ClientDynamicObject freeblock_full_factory(int type_id, const SaveDict& entry,
                                           FreeBlockFullState* out_state,
                                           std::string* error);

}  // namespace bh176
