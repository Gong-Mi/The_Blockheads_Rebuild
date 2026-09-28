// GlowBlock loader (type 18): DynamicObject base + the two own keys,
// decoded from the annotated listing (emit_annotated_method.py over the
// pinned ELF; coverage gate OK).
//
// GlowBlock -(0x00ca8920, 214w):
//   tileType  objectForKey -> intValue -> str @60
//   lightDict objectForKey; if non-nil -> [[ArtificialLight alloc]
//       initWithWorld:dynamicWorld:saveDict:cache:parentObject:] (5-arg)
//       — the ArtificialLight body is NOT recovered: offline only the key's
//       presence is preserved and the child construction is reported as not
//       run (same boundary as Workbench/Torch/FireObject).
//   [super] forward is the ordinary 4-arg DynamicObject init (executed base).
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include "artificial_light_full.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct GlowBlockFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // own keys
    bool has_tile_type = false;
    std::int32_t tile_type = 0;   // @60 word
    bool light_present = false;   // lightDict key; child body not recovered
    LightFields light;  // decoded via the ArtificialLight key table (shared decoder)
    bool light_child_not_run = true;
};

GlowBlockFullState glowblock_full_load(const SaveDict& entry);

ClientDynamicObject glowblock_full_factory(int type_id,
                                           const SaveDict& entry,
                                           GlowBlockFullState* out_state,
                                           std::string* error);

}  // namespace bh176
