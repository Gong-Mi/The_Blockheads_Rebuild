// Bed / Sign loader implementation. See bed_sign_full.h.
#include "bed_sign_full.h"

#include "interaction_object_init.h"

#include <cstring>

namespace bh176 {

BedSignFullState bed_sign_full_load(const SaveDict& entry, int type_id) {
    using blockheads::recovered::InteractionInitInputs;
    using blockheads::recovered::interaction_init_run;

    BedSignFullState state;

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

    // --- the executed InteractionObject super chain ---
    InteractionInitInputs in;
    const SaveValue* in_use = entry.objectForKey("isInUse");
    in.in_use_present = in_use != nullptr;
    in.in_use_value = SaveDict::boolValue(in_use);
    const SaveValue* flipped = entry.objectForKey("flipped");
    in.flipped_present = flipped != nullptr;
    in.flipped_value = SaveDict::boolValue(flipped);
    in.owner_id_present = entry.objectForKey("ownerID") != nullptr;
    in.owner_id_token = in.owner_id_present ? 0x60001020u : 0u;
    in.owner_name_present = entry.objectForKey("ownerName") != nullptr;
    in.owner_name_token = in.owner_name_present ? 0x60001030u : 0u;
    const SaveValue* paint = entry.objectForKey("paintColor");
    in.paint_color_present = paint != nullptr;
    in.paint_color_value = static_cast<std::uint32_t>(
        SaveDict::unsignedLongValue(paint));
    const SaveValue* blockhead = entry.objectForKey("currentBlockheadIndex");
    in.blockhead_index_present = blockhead != nullptr;
    in.blockhead_index_value = static_cast<std::int32_t>(
        SaveDict::intValue(blockhead));
    in.is_server = false;  // world state: not evaluable offline
    const auto result = interaction_init_run(in);
    const std::uint8_t* image = result.image.data();
    state.is_in_use = image[68] != 0;
    state.flipped = image[69] != 0;
    std::uint32_t owner_id = 0, owner_name = 0, blockhead_index = 0;
    std::uint16_t paint_color = 0;
    std::memcpy(&owner_id, image + 36, sizeof(owner_id));
    std::memcpy(&owner_name, image + 84, sizeof(owner_name));
    std::memcpy(&blockhead_index, image + 80, sizeof(blockhead_index));
    std::memcpy(&paint_color, image + 88, sizeof(paint_color));
    state.has_owner_id = owner_id != 0;
    state.has_owner_name = owner_name != 0;
    state.paint_color = paint_color;
    state.saved_blockhead_index = static_cast<std::int32_t>(blockhead_index);

    // --- own keys (annotated-listing decode; widths from the flow) ---
    if (type_id == 23) {
        state.item_type = static_cast<std::int32_t>(
            SaveDict::intValue(entry.objectForKey("itemType")));  // word @100
        if (state.item_type == 0) {          // the movw #0x3f default
            state.item_type = 0x3F;
            state.item_type_defaulted = true;
        }
        state.bedding_color = static_cast<std::uint16_t>(   // STRH @104
            SaveDict::intValue(entry.objectForKey("beddingColor")));
    } else if (type_id == 47) {
        state.has_text = entry.objectForKey("text") != nullptr;  // retain @100
        state.connection_type = static_cast<std::int32_t>(
            SaveDict::intValue(entry.objectForKey("connectionType")));  // @112
        state.offset_type = static_cast<std::int32_t>(
            SaveDict::intValue(entry.objectForKey("offsetType")));      // @116
    }
    state.world_tail_not_run = true;
    return state;
}

ClientDynamicObject bed_sign_full_factory(int type_id, const SaveDict& entry,
                                          BedSignFullState* out_state,
                                          std::string* error) {
    if (error) error->clear();
    const BedSignFullState state = bed_sign_full_load(entry, type_id);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        type_id == 23
            ? "bed full chain: DynamicObject base + InteractionObject super "
              "(executed 352w) + own keys itemType@100/beddingColor@104-strh "
              "with the itemType==0 -> 63 default (listing decode); world "
              "tail not evaluable offline"
            : "sign full chain: DynamicObject base + InteractionObject super "
              "(executed 352w) + own keys text@100-retain/"
              "connectionType@112/offsetType@116 (listing decode); world "
              "tail not evaluable offline";
    return object;
}

}  // namespace bh176
