// InteractionObject-family loader implementation. See interaction_full.h.
#include "interaction_full.h"

#include "interaction_object_init.h"

#include <cstring>

namespace bh176 {

InteractionFullState interaction_full_load(const SaveDict& entry) {
    using blockheads::recovered::InteractionInitInputs;
    using blockheads::recovered::interaction_init_run;

    InteractionFullState state;

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

    // --- map the record onto the EXECUTED contract's inputs ---
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
    // the world tail: not evaluable offline
    in.is_server = false;
    in.resolved_owner_name_token = 0;

    const auto result = interaction_init_run(in);
    const std::uint8_t* image = result.image.data();

    // --- read the executed stores back out ---
    state.is_in_use = image[68] != 0;
    state.flipped = image[69] != 0;
    std::uint32_t owner_id = 0;
    std::uint32_t owner_name = 0;
    std::uint32_t blockhead_index = 0;
    std::uint16_t paint_color = 0;
    std::memcpy(&owner_id, image + 36, sizeof(owner_id));
    std::memcpy(&owner_name, image + 84, sizeof(owner_name));
    std::memcpy(&blockhead_index, image + 80, sizeof(blockhead_index));
    std::memcpy(&paint_color, image + 88, sizeof(paint_color));
    state.has_owner_id = owner_id != 0;
    state.has_owner_name = owner_name != 0;
    state.paint_color = paint_color;
    state.saved_blockhead_index =
        static_cast<std::int32_t>(blockhead_index);
    state.had_blockhead_index = in.blockhead_index_present;
    state.world_tail_not_run = true;
    return state;
}

ClientDynamicObject interaction_full_factory(int type_id,
                                             const SaveDict& entry,
                                             InteractionFullState* out_state,
                                             std::string* error) {
    if (error) error->clear();
    const InteractionFullState state = interaction_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        type_id == 64
            ? "mirror full chain: DynamicObject base + InteractionObject "
              "init executed (352w differential; Mirror itself is a "
              "zero-own-key 71w super forwarder) + world tail not "
              "evaluable offline"
            : "interactionobject full chain: DynamicObject base + the "
              "executed 352w init (8-case differential: six keys, strh "
              "paintColor, -1 blockhead default, three-gate world tail) + "
              "world tail not evaluable offline";
    return object;
}

}  // namespace bh176
