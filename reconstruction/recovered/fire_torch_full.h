// FireObject (16) / Torch (17) loader: DynamicObject base + each class's own
// keys, decoded from the annotated listings (emit_annotated_method.py over
// the pinned ELF; coverage gates OK).
//
// FireObject -(0x00674af4, 259w):
//   burnTimer       objectForKey -> floatValue -> vstr/str  @56
//   spreadTimer_0..3 objectForKey -> floatValue -> @60 +0/+4/+8/+0xc (the
//                   four float32 lanes of spreadTimers@60)
//   lightDict       child ArtificialLight (alloc + 5-arg) -> light@76
//   world post-step: a macroTiles-driven light contribution update runs after
//       the child construction (world state; not run offline, stated)
//   [self initSubDerivedItems]
//
// Torch -(0x004b5d38, 318w):
//   itemType       objectForKey -> intValue -> str  @64
//   connectionType objectForKey -> intValue -> str  @60
//   dataA          objectForKey -> intValue -> STRH @80 (zero-extended on the
//                  save side; halfword store on load)
//   dataB          objectForKey -> intValue -> STRH @82
//   ownerID        objectForKey -> retain   -> str  @36 (DynamicObject slot)
//   lightDict      child ArtificialLight (5-arg, parentObject:) -> light@56
//   [self initSubDerivedItems]
//
// The ArtificialLight body is NOT recovered in either class: offline the
// lightDict presence is preserved and the child construction is reported as
// not run (the same stated boundary as Workbench/GlowBlock).
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include "artificial_light_full.h"

#include <array>
#include <cstdint>
#include <string>

namespace bh176 {

struct FireTorchFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // FireObject own keys
    bool has_burn_timer = false;
    float burn_timer = 0.0f;            // @56
    std::array<bool, 4> has_spread_timer{};
    std::array<float, 4> spread_timers{};  // @60 +4n
    // Torch own keys
    bool has_item_type = false;
    std::int32_t item_type = 0;          // @64
    bool has_connection_type = false;
    std::int32_t connection_type = 0;    // @60
    bool has_data_a = false;
    std::uint16_t data_a = 0;            // @80 STRH
    bool has_data_b = false;
    std::uint16_t data_b = 0;            // @82 STRH
    bool has_owner_id = false;           // @36 retained slot
    // shared boundaries
    bool light_present = false;          // lightDict key
    LightFields light;  // decoded via the ArtificialLight key table (shared decoder)
    bool light_child_not_run = true;
    bool world_post_step_not_run = true;  // FireObject's macroTiles update
};

FireTorchFullState fire_torch_full_load(const SaveDict& entry, int type_id);

ClientDynamicObject fire_torch_full_factory(int type_id, const SaveDict& entry,
                                            FireTorchFullState* out_state,
                                            std::string* error);

}  // namespace bh176
