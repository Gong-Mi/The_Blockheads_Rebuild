// FreeBlock loader implementation. See freeblock_full.h.
#include "freeblock_full.h"

namespace bh176 {

FreeBlockFullState freeblock_full_load(const SaveDict& entry) {
    FreeBlockFullState state;

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

    // --- b4p own keys (executed read-back) ---
    if (const SaveValue* v = entry.objectForKey("bounceTimer")) {
        state.has_bounce_timer = true;
        state.bounce_timer = SaveDict::floatValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("fallSpeed")) {
        state.has_fall_speed = true;
        state.fall_speed = SaveDict::floatValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("creationTime")) {
        state.has_creation_time = true;
        state.creation_time = SaveDict::doubleValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("floatPos[VX]")) {
        state.has_float_pos_vx = true;
        state.float_pos_vx = SaveDict::floatValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("floatPos[VY]")) {
        state.has_float_pos_vy = true;
        state.float_pos_vy = SaveDict::floatValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("hovers")) {
        state.has_hovers = true;
        state.hovers = SaveDict::boolValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("itemType")) {
        state.has_item_type = true;
        state.item_type = static_cast<std::uint32_t>(SaveDict::intValue(v));
    }
    if (const SaveValue* v = entry.objectForKey("dataA")) {
        state.has_data_a = true;
        state.data_a = static_cast<std::uint16_t>(SaveDict::intValue(v));
    }
    if (const SaveValue* v = entry.objectForKey("dataB")) {
        state.has_data_b = true;
        state.data_b = static_cast<std::uint16_t>(SaveDict::intValue(v));
    }
    // subItems: source is an ARRAY OF ARRAYS of item payloads. Counts only —
    // item payload decoding belongs to InventoryItem initWithSaveData:
    // (separate module), so the itemType != 11 filter is NOT applied offline.
    const SaveValue* sub_items = entry.objectForKey("subItems");
    if (sub_items != nullptr && sub_items->isArray()) {
        state.has_sub_items = true;
        const std::size_t slot_count = SaveDict::count(sub_items);
        state.sub_slot_count = slot_count;
        state.sub_slot_item_counts.reserve(slot_count);
        for (std::size_t i = 0; i < slot_count; ++i) {
            const SaveValue* slot = entry.objectAtIndex(sub_items, i);
            state.sub_slot_item_counts.push_back(
                (slot != nullptr && slot->isArray()) ? SaveDict::count(slot)
                                                     : 0);
        }
    }
    if (entry.objectForKey("dynamicObjectSaveDict") != nullptr) {
        state.has_dynamic_object_save_dict = true;  // object slot (copy)
    }
    if (const SaveValue* pid = entry.objectForKey("priorityBlockheadUinqueID")) {
        state.has_priority_blockhead_id = true;
        // executed fact: the int64 read is used through the int32 path
        state.priority_blockhead_id =
            static_cast<std::int32_t>(SaveDict::intValue(pid));
    }
    // world-dependent tail (hovers expiry / blockhead lookup / ground fall)
    // runs during the original init but needs world state: not simulated
    // offline; world_tail_not_run stays true.
    state.world_tail_not_run = true;
    return state;
}

ClientDynamicObject freeblock_full_factory(int type_id, const SaveDict& entry,
                                           FreeBlockFullState* out_state,
                                           std::string* error) {
    if (error) error->clear();
    const FreeBlockFullState state = freeblock_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    std::string reason =
        "freeblock full chain: DynamicObject base + FreeBlock b4p executed "
        "save surface (bounceTimer/fallSpeed/creationTime/floatPos[VX,VY]/"
        "hovers/itemType/dataA,dataB/subItems counts/dynamicObjectSaveDict/"
        "priorityBlockheadUinqueID); item payload decode not performed "
        "(InventoryItem domain); world tail (hovers re-anchor, blockhead "
        "lookup, ground fall) not run offline";
    attachRecoveredState(object, state, ObjectLoadStatus::Recovered,
                             std::move(reason), "FreeBlockFullState");
    return object;
}

}  // namespace bh176
