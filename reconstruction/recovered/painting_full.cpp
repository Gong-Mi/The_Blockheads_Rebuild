// Painting loader implementation. See painting_full.h.
#include "painting_full.h"

namespace bh176 {

PaintingFullState painting_full_load(const SaveDict& entry) {
    PaintingFullState state;

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
    if (const SaveValue* v = entry.objectForKey("itemType")) {
        state.has_item_type = true;
        state.item_type = static_cast<std::int32_t>(SaveDict::intValue(v));
    }
    state.has_owner_id = entry.objectForKey("ownerID") != nullptr;
    state.has_owner_name = entry.objectForKey("ownerName") != nullptr;
    const SaveValue* verified = entry.objectForKey("hasVerifiedImageData");
    if (verified != nullptr) {
        state.has_verified_image_data = true;
        state.verified_image_data = SaveDict::boolValue(verified);  // STRB
    }
    state.has_image_data = entry.objectForKey("outputImageData") != nullptr;

    // the isServer-gated world steps (ownerName resolution, ban check) are
    // world state: not run offline; hiddenDueToServerBan keeps its default.
    state.hidden_due_to_server_ban = false;
    state.world_steps_not_run = true;
    return state;
}

ClientDynamicObject painting_full_factory(int type_id, const SaveDict& entry,
                                          PaintingFullState* out_state,
                                          std::string* error) {
    if (error) error->clear();
    const PaintingFullState state = painting_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "painting full chain: DynamicObject base + own keys itemType@56/"
        "ownerID@36/ownerName@64/hasVerifiedImageData@79-strb/"
        "outputImageData@60 (listing decode); the isServer-gated world steps "
        "(ownerName resolution, ban check) are not run offline";
    return object;
}

}  // namespace bh176
