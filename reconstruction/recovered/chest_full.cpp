// Chest loader implementation. See chest_full.h.
#include "chest_full.h"

namespace bh176 {

ChestFullState chest_full_load(const SaveDict& entry) {
    ChestFullState state;

    // --- DynamicObject base loader (executed contract) ---
    state.unique_id =
        static_cast<std::uint64_t>(SaveDict::unsignedLongValue(
            entry.objectForKey("uniqueID")));
    state.pos_x = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_x")));
    state.pos_y = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_y")));
    const SaveValue* float_pos = entry.objectForKey("floatPos");
    if (SaveDict::count(float_pos) >= 2) {
        state.float_pos_x =
            SaveDict::floatValue(entry.objectAtIndex(float_pos, 0));
        state.float_pos_y =
            SaveDict::floatValue(entry.objectAtIndex(float_pos, 1));
        state.has_float_pos = true;
    }

    // --- b4m own surface ---
    if (const SaveValue* chest_type = entry.objectForKey("chestType")) {
        state.has_chest_type = true;
        state.chest_type = static_cast<std::int32_t>(
            SaveDict::intValue(chest_type));  // @108
    }
    if (entry.objectForKey("safeClientID") != nullptr) {
        state.has_safe_client_id = true;  // object slot; ownerID fallback
    }
    // saveItemSlots: slot count + per-slot RAW item counts. Item payload
    // decoding belongs to InventoryItem initWithSaveData: — not performed
    // here (item_decode_performed stays false, stated in the reason).
    const SaveValue* slots = entry.objectForKey("saveItemSlots");
    if (slots != nullptr && slots->isArray()) {
        state.has_save_item_slots = true;
        const std::size_t slot_count = SaveDict::count(slots);
        state.save_slot_count = slot_count;
        state.slot_item_counts.reserve(slot_count);
        for (std::size_t i = 0; i < slot_count; ++i) {
            const SaveValue* slot = entry.objectAtIndex(slots, i);
            state.slot_item_counts.push_back(
                (slot != nullptr && slot->isArray()) ? SaveDict::count(slot)
                                                     : 0);
        }
    }
    // Shelf restore surface: shelfRenderItems_%d (word) / shelfItemDataBs_%d
    // (strh-truncated halfword), m = 0..3. These keys are only READ by the
    // original when inventoryItems stayed nil (chestType == 4 or the slots
    // key was missing); the VALUES are captured whenever present, and the
    // gate condition is observable from chest_type + has_save_item_slots.
    for (std::size_t m = 0; m < 4; ++m) {
        const std::string render_key =
            "shelfRenderItems_" + std::to_string(m);
        const std::string data_key = "shelfItemDataBs_" + std::to_string(m);
        if (const SaveValue* render = entry.objectForKey(render_key)) {
            state.has_shelf_render_items[m] = true;
            state.shelf_render_items[m] = static_cast<std::int32_t>(
                SaveDict::intValue(render));  // word @116 + 4m
        }
        if (const SaveValue* data_b = entry.objectForKey(data_key)) {
            state.has_shelf_item_data_bs[m] = true;
            state.shelf_item_data_bs[m] = static_cast<std::uint16_t>(
                SaveDict::intValue(data_b));  // strh @132 + 2m
        }
    }

    // --- the InteractionObject static boundary (same as Workbench) ---
    state.interaction_static_keys_present =
        entry.objectForKey("flipped") != nullptr ||
        entry.objectForKey("paintColor") != nullptr ||
        entry.objectForKey("ownerID") != nullptr;
    return state;
}

ClientDynamicObject chest_full_factory(int type_id, const SaveDict& entry,
                                       ChestFullState* out_state,
                                       std::string* error) {
    if (error) error->clear();
    const ChestFullState state = chest_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "chest full chain: DynamicObject base + Chest b4m executed surface "
        "(chestType/safeClientID/saveItemSlots slot+item counts/shelf_0..3); "
        "item payload decode not performed (InventoryItem domain); "
        "customRules world gate not run offline; InteractionObject super "
        "keys static-only (not loaded)";
    return object;
}

}  // namespace bh176
