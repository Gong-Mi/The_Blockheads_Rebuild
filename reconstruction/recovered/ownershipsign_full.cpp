// OwnershipSign loader implementation. See ownershipsign_full.h.
#include "ownershipsign_full.h"

#include "bed_sign_full.h"

namespace bh176 {

OwnershipSignFullState ownershipsign_full_load(const SaveDict& entry) {
    OwnershipSignFullState state;

    // --- the Sign chain (its own keys are type 47's table; reuse it) ---
    BedSignFullState sign_state = bed_sign_full_load(entry, 47);
    state.unique_id = sign_state.unique_id;
    state.pos_x = sign_state.pos_x;
    state.pos_y = sign_state.pos_y;
    state.has_text = sign_state.has_text;
    state.connection_type = sign_state.connection_type;
    state.offset_type = sign_state.offset_type;

    // --- own keys (annotated-listing decode) ---
    state.has_land_owner_id = entry.objectForKey("landOwnerID") != nullptr;
    state.has_land_owner_name = entry.objectForKey("landOwnerName") != nullptr;
    if (const SaveValue* w = entry.objectForKey("w")) {
        state.has_w = true;
        state.width_radius = static_cast<std::int32_t>(SaveDict::intValue(w));
    }
    if (const SaveValue* h = entry.objectForKey("h")) {
        state.has_h = true;
        state.height_radius = static_cast<std::int32_t>(SaveDict::intValue(h));
    }
    return state;
}

ClientDynamicObject ownershipsign_full_factory(int type_id,
                                               const SaveDict& entry,
                                               OwnershipSignFullState* out_state,
                                               std::string* error) {
    if (error) error->clear();
    const OwnershipSignFullState state = ownershipsign_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "ownershipsign full chain: base + the Sign chain (text@100/"
        "connectionType@112/offsetType@116) + own keys landOwnerID@124/"
        "landOwnerName@128/w@132-int/h@136-int (listing decode); updateText "
        "tail hook carries no save state";
    return object;
}

}  // namespace bh176
