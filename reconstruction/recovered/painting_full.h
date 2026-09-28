// Painting loader (type 52): DynamicObject base + the five own keys, with
// the two isServer-gated world steps stated (not run offline).
//
// Painting -(0x00aa81e8, 358w), decoded from the annotated listing:
//   itemType     objectForKey -> intValue -> str  @56
//   ownerID      objectForKey -> retain   -> str  @36 (DynamicObject slot)
//   ownerName    objectForKey -> retain   -> str  @64
//   hasVerifiedImageData objectForKey -> boolValue -> STRB @79
//   outputImageData      objectForKey -> (object)  -> imageData@60
//   world steps (isServer-gated, NOT run offline) — conditions ARM-attested
//   by tools/test_specials_arm.py:
//     gate 1 [dynamicWorld isServer] AND ownerID != nil AND ownerName == nil
//       -> [dynamicWorld getOwnerNameForObjectOwnerID:<ownerID>] -> retain ->
//          stored back into ownerName @64;
//     gate 2 [dynamicWorld isServer]
//       -> [dynamicWorld playerIsBannedWithID:<ownerID>] -> STRB @77;
//     ownerName@64 = retain([dynamicWorld getOwnerNameForObjectOwnerID:
//                            ownerID@36])            when ownerName is nil
//     hiddenDueToServerBan@77 = [dynamicWorld playerIsBannedWithID:ownerID]
//   [self initSubDerivedItems]
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct PaintingFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // own keys
    bool has_item_type = false;
    std::int32_t item_type = 0;          // @56
    bool has_owner_id = false;           // @36
    bool has_owner_name = false;         // @64
    bool has_verified_image_data = false;
    bool verified_image_data = false;    // @79 STRB (boolValue)
    bool has_image_data = false;         // imageData@60 (outputImageData slot)
    bool hidden_due_to_server_ban = false;  // @77 default false; ban check world
    // world steps not run offline
    bool world_steps_not_run = true;
};

PaintingFullState painting_full_load(const SaveDict& entry);

ClientDynamicObject painting_full_factory(int type_id, const SaveDict& entry,
                                          PaintingFullState* out_state,
                                          std::string* error);

}  // namespace bh176
