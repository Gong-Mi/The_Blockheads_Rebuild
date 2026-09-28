// GatherBlock loader implementation. See gatherblock_full.h.
#include "gatherblock_full.h"

namespace bh176 {

GatherBlockFullState gatherblock_full_load(const SaveDict& entry) {
    GatherBlockFullState state;

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

    // --- ownkey5 own keys (executed) ---
    if (const SaveValue* timer = entry.objectForKey("timer")) {
        state.has_timer = true;
        state.timer = SaveDict::floatValue(timer);  // @56
    }
    if (const SaveValue* last = entry.objectForKey("lastKnownGatherValue")) {
        state.has_last_known_gather_value = true;
        state.last_known_gather_value =
            static_cast<std::int32_t>(SaveDict::intValue(last));  // @60
    }
    return state;
}

ClientDynamicObject gatherblock_full_factory(int type_id, const SaveDict& entry,
                                             GatherBlockFullState* out_state,
                                             std::string* error) {
    if (error) error->clear();
    const GatherBlockFullState state = gatherblock_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "gatherblock full chain: DynamicObject base + GatherBlock ownkey5 "
        "own keys timer/lastKnownGatherValue (executed, presence-gated)";
    return object;
}

}  // namespace bh176
