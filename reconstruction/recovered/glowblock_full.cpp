// GlowBlock loader implementation. See glowblock_full.h.
#include "glowblock_full.h"

namespace bh176 {

GlowBlockFullState glowblock_full_load(const SaveDict& entry) {
    GlowBlockFullState state;

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
    if (const SaveValue* tile = entry.objectForKey("tileType")) {
        state.has_tile_type = true;
        state.tile_type = static_cast<std::int32_t>(SaveDict::intValue(tile));
    }
    // the lightDict child: only the key's presence is preserved; the
    // ArtificialLight 5-arg construction is not run offline (its body is
    // outside the recovered set).
    state.light_present = entry.objectForKey("lightDict") != nullptr;
    if (const SaveValue* light_dict = entry.objectForKey("lightDict")) {
        state.light = light_from_dict(SaveDict(*light_dict));
    }
    state.light_child_not_run = true;
    return state;
}

ClientDynamicObject glowblock_full_factory(int type_id,
                                           const SaveDict& entry,
                                           GlowBlockFullState* out_state,
                                           std::string* error) {
    if (error) error->clear();
    const GlowBlockFullState state = glowblock_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    std::string reason =
        "glowblock full chain: DynamicObject base + own keys tileType@60 "
        "(listing decode) + lightDict presence; the ArtificialLight child "
        "construction is not run offline";
    attachRecoveredState(object, state, ObjectLoadStatus::Recovered,
                             std::move(reason), "GlowBlockFullState");
    return object;
}

}  // namespace bh176
