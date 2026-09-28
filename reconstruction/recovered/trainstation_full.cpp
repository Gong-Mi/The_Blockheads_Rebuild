// TrainStation loader implementation. See trainstation_full.h.
#include "trainstation_full.h"

namespace bh176 {

TrainStationFullState trainstation_full_load(const SaveDict& entry) {
    TrainStationFullState state;

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

    // --- ownkey5 own key (executed): text@128 (retain of the object) ---
    if (entry.objectForKey("text") != nullptr) {
        state.has_text = true;
    }

    // --- the InteractionObject static boundary (same as Workbench) ---
    state.interaction_static_keys_present =
        entry.objectForKey("flipped") != nullptr ||
        entry.objectForKey("paintColor") != nullptr ||
        entry.objectForKey("ownerID") != nullptr;
    return state;
}

ClientDynamicObject trainstation_full_factory(int type_id,
                                              const SaveDict& entry,
                                              TrainStationFullState* out_state,
                                              std::string* error) {
    if (error) error->clear();
    const TrainStationFullState state = trainstation_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "trainstation full chain: DynamicObject base + TrainStation ownkey5 "
        "own key text (executed, presence-gated); InteractionObject super "
        "keys static-only (not loaded); initSubDerivedItems tail hook "
        "carries no save state";
    return object;
}

}  // namespace bh176
