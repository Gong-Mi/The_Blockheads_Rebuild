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

    // --- own keys (ARM-attested by tools/test_specials_arm.py) ---
    // The radii start at the body's DEFAULT 15 (movw lr, #0xf; two stores);
    // a present key replaces it with clampf(float(intValue), 1.0, 30.0)
    // (the clamp helper 0x4BE068 runs inside the body).
    state.width_radius = kOwnershipDefaultRadius;
    state.height_radius = kOwnershipDefaultRadius;
    const bool id_present = entry.objectForKey("landOwnerID") != nullptr;
    // The ID probe gates the whole object block: with a nil ID the body
    // never reads landOwnerName either.
    state.has_land_owner_id = id_present;
    state.has_land_owner_name =
        id_present && entry.objectForKey("landOwnerName") != nullptr;
    if (id_present) {
        if (const SaveValue* w = entry.objectForKey("w")) {
            state.has_w = true;
            state.width_radius = ownershipClampRadius(
                static_cast<std::int32_t>(SaveDict::intValue(w)));
        }
        if (const SaveValue* h = entry.objectForKey("h")) {
            state.has_h = true;
            state.height_radius = ownershipClampRadius(
                static_cast<std::int32_t>(SaveDict::intValue(h)));
        }
    } else {
        if (entry.objectForKey("w") != nullptr) {
            state.has_w = true;
            state.width_radius = ownershipClampRadius(
                static_cast<std::int32_t>(SaveDict::intValue(
                    entry.objectForKey("w"))));
        }
        if (entry.objectForKey("h") != nullptr) {
            state.has_h = true;
            state.height_radius = ownershipClampRadius(
                static_cast<std::int32_t>(SaveDict::intValue(
                    entry.objectForKey("h"))));
        }
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
    std::string reason =
        "ownershipsign full chain: base + the Sign chain (text@100/"
        "connectionType@112/offsetType@116) + own keys landOwnerID@124/"
        "landOwnerName@128/w@132/h@136 (EXECUTED differential "
        "tools/test_specials_arm.py: radii default 15, present values clamp to "
        "[1,30] via the body's own helper, the ID probe gates the object "
        "block); updateText tail hook carries no save state";
    attachRecoveredState(object, state, ObjectLoadStatus::Recovered,
                             std::move(reason), "OwnershipSignFullState");
    return object;
}

}  // namespace bh176
