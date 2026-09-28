// FireObject / Torch loader implementation. See fire_torch_full.h.
#include "fire_torch_full.h"

namespace bh176 {

FireTorchFullState fire_torch_full_load(const SaveDict& entry, int type_id) {
    FireTorchFullState state;

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

    // --- own keys (annotated-listing decode) ---
    if (type_id == 16) {
        if (const SaveValue* burn = entry.objectForKey("burnTimer")) {
            state.has_burn_timer = true;
            state.burn_timer = SaveDict::floatValue(burn);  // @56
        }
        for (int lane = 0; lane < 4; ++lane) {
            const std::string key = "spreadTimer_" + std::to_string(lane);
            if (const SaveValue* timer = entry.objectForKey(key)) {
                state.has_spread_timer[static_cast<std::size_t>(lane)] = true;
                state.spread_timers[static_cast<std::size_t>(lane)] =
                    SaveDict::floatValue(timer);  // @60 + 4*lane
            }
        }
    } else if (type_id == 17) {
        if (const SaveValue* v = entry.objectForKey("itemType")) {
            state.has_item_type = true;
            state.item_type = static_cast<std::int32_t>(SaveDict::intValue(v));
        }
        if (const SaveValue* v = entry.objectForKey("connectionType")) {
            state.has_connection_type = true;
            state.connection_type =
                static_cast<std::int32_t>(SaveDict::intValue(v));
        }
        if (const SaveValue* v = entry.objectForKey("dataA")) {
            state.has_data_a = true;
            state.data_a = static_cast<std::uint16_t>(SaveDict::intValue(v));
        }
        if (const SaveValue* v = entry.objectForKey("dataB")) {
            state.has_data_b = true;
            state.data_b = static_cast<std::uint16_t>(SaveDict::intValue(v));
        }
        state.has_owner_id = entry.objectForKey("ownerID") != nullptr;
    }
    state.light_present = entry.objectForKey("lightDict") != nullptr;
    state.light_child_not_run = true;
    state.world_post_step_not_run = true;
    return state;
}

ClientDynamicObject fire_torch_full_factory(int type_id, const SaveDict& entry,
                                            FireTorchFullState* out_state,
                                            std::string* error) {
    if (error) error->clear();
    const FireTorchFullState state = fire_torch_full_load(entry, type_id);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        type_id == 16
            ? "fireobject full chain: DynamicObject base + own keys "
              "burnTimer@56/spreadTimer_0..3@60..72 (listing decode); the "
              "ArtificialLight child and the macroTiles post-step are not "
              "run offline"
            : "torch full chain: DynamicObject base + own keys itemType@64/"
              "connectionType@60/dataA@80-strh/dataB@82-strh/ownerID@36 "
              "(listing decode); the ArtificialLight child is not run "
              "offline";
    return object;
}

}  // namespace bh176
