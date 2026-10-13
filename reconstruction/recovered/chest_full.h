// Chest loader (type 46): the b4m executed chain, same profile as Workbench /
// TrainStation (executed own-side + a stated InteractionObject static
// boundary).
//
// Original chain (executed evidence, CHEST_INIT_ARM.md, 13 cases bit-exact;
// the only front method with a stack canary):
//   DynamicObject base (executed)
//   InteractionObject initWithWorld:...:saveDict:cache: (352w)  [STATIC only —
//     the same boundary as Workbench/TrainStation; NOT loaded, reported]
//   Chest initWithWorld:dynamicWorld:saveDict:cache: (0x00CB627C, 760w):
//     chestType@108 = intValue(chestType); chestType == 4 runs the world
//       customRules gate (world-dependent, not save data — offline the key
//       value is kept and the gate is reported as not-run)
//     ownerID default: if nil -> retain(objectForKey:@"safeClientID")
//     saveItemSlots: array; [count] >= numberOfSlots(chestType) selects the
//       per-slot restore (16-wide batches, itemType != 11 filter, items built
//       via [[InventoryItem alloc] initWithSaveData:]); otherwise padding only
//     shelf restore (runs when inventoryItems stays nil): shelfRenderItems_%d
//       (word @116) and shelfItemDataBs_%d (strh @132) for m = 0..3
//     [self initSubDerivedItems] tail hook
//
// SCOPE (stated, not blurred): this loader captures the scalar/key surface —
// chestType, safeClientID presence, saveItemSlots slot count and per-slot raw
// item counts, the eight shelf fields — and does NOT decode item payloads
// (that is InventoryItem initWithSaveData:'s domain, a separate recovered
// module). The itemType != 11 filter therefore cannot be applied offline and
// is reported as not-applied.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace bh176 {

struct ChestFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // b4m own surface
    bool has_chest_type = false;
    std::int32_t chest_type = 0;              // @108
    bool has_safe_client_id = false;          // ownerID fallback (object slot)
    bool has_save_item_slots = false;         // "saveItemSlots" array present
    std::size_t save_slot_count = 0;          // saved slots (raw array count)
    std::vector<std::size_t> slot_item_counts;  // raw per-slot item counts
    bool item_decode_performed = false;       // always false offline (stated)
    std::array<std::int32_t, 4> shelf_render_items{};   // shelfRenderItems_0..3
    std::array<std::uint16_t, 4> shelf_item_data_bs{};  // shelfItemDataBs_0..3
    std::array<bool, 4> has_shelf_render_items{};
    std::array<bool, 4> has_shelf_item_data_bs{};
    // the InteractionObject static set — NOT loaded (no recovered module)
    bool interaction_static_keys_present = false;
};

ChestFullState chest_full_load(const SaveDict& entry);

ClientDynamicObject chest_full_factory(int type_id, const SaveDict& entry,
                                       ChestFullState* out_state,
                                       std::string* error);

}  // namespace bh176
