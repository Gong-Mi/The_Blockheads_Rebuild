// OwnershipSign loader (type 60): the Sign chain (executed-shape key table)
// plus the four own keys, decoded from the annotated listing.
//
// OwnershipSign -(0x00a34b18, 352w), runtime superclass Sign:
//   Sign chain (type 47's own keys): text@100 (retain), connectionType@112
//     (int), offsetType@116 (int) — reused verbatim through
//     bed_sign_full_load(entry, 47).
//   own keys (this listing):
//     landOwnerID   objectForKey -> retain    -> str  @124
//     landOwnerName objectForKey -> retain    -> str  @128
//     w             objectForKey -> intValue  -> str  @132 (widthRadius)
//     h             objectForKey -> intValue  -> str  @136 (heightRadius)
//   [self updateText] tail hook (no save state)
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct OwnershipSignFullState {
    // base loader (through the Sign chain's base handling)
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    // Sign chain
    bool has_text = false;             // @100
    std::int32_t connection_type = 0;  // @112
    std::int32_t offset_type = 0;      // @116
    // own keys
    bool has_land_owner_id = false;    // @124
    bool has_land_owner_name = false;  // @128
    bool has_w = false;
    std::int32_t width_radius = 0;     // @132 (key w)
    bool has_h = false;
    std::int32_t height_radius = 0;    // @136 (key h)
    std::string tail_hook = "updateText";
};

OwnershipSignFullState ownershipsign_full_load(const SaveDict& entry);

ClientDynamicObject ownershipsign_full_factory(int type_id,
                                               const SaveDict& entry,
                                               OwnershipSignFullState* out_state,
                                               std::string* error);

}  // namespace bh176
