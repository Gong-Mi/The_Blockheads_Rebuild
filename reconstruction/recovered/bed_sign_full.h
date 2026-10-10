// Bed (23) / Sign (47) loader: the executed InteractionObject super chain
// plus each class's own keys, decoded from their annotated listings.
//
// Evidence levels stated per part:
//   super   InteractionObject init — EXECUTED (352w, 8-case differential;
//           see INTERACTION_OBJECT_INIT_ARM.md); run here through
//           interaction_init_run and read back out of its image.
//   own     Bed/Sign own keys — decoded from the annotated listings
//           (emit_annotated_method.py over the pinned ELF, coverage gate OK),
//           store widths from the instruction stream; no executed
//           differential for the own part yet (tracked).
//
// Bed -(0xd407ec, 144w):
//   itemType     objectForKey -> intValue -> str  @100
//   beddingColor objectForKey -> intValue -> STRH @104 (halfword store!)
//   default: if (itemType@100 == 0) itemType@100 = 0x3F (63)   [movw #0x3f]
//   [self initSubDerivedItems]
// Sign -(0x5fa604, 166w):
//   text           objectForKey -> retain -> str @100 (object slot)
//   connectionType objectForKey -> intValue -> str @112
//   offsetType     objectForKey -> intValue -> str @116
//   [self initSubDerivedItems]
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct BedSignFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // the executed InteractionObject super surface (read back from the image)
    bool is_in_use = false;
    bool flipped = false;
    bool has_owner_id = false;
    bool has_owner_name = false;
    std::uint16_t paint_color = 0;
    std::int32_t saved_blockhead_index = -1;
    // Bed own keys
    std::int32_t item_type = 0;        // @100 word (post-default)
    bool item_type_defaulted = false;  // the itemType==0 -> 63 rule fired
    std::uint16_t bedding_color = 0;   // @104 STRH (16-bit truncation)
    // Sign own keys
    bool has_text = false;             // @100 retained object slot
    std::int32_t connection_type = 0;  // @112 word
    std::int32_t offset_type = 0;      // @116 word
    bool world_tail_not_run = true;
};

BedSignFullState bed_sign_full_load(const SaveDict& entry, int type_id);

ClientDynamicObject bed_sign_full_factory(int type_id, const SaveDict& entry,
                                          BedSignFullState* out_state,
                                          std::string* error);

}  // namespace bh176
