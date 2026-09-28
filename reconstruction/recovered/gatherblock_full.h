// GatherBlock loader (type 26): the ownkey5 executed chain.
//
// Original chain (executed evidence):
//   DynamicObject initWithWorld:dynamicWorld:saveDict:cache: (base)  [executed]
//   GatherBlock initWithWorld:dynamicWorld:saveDict:cache: (0x00869670-ish,
//     ownkey5 program; runtime superclass DynamicObject):
//       [super initWithWorld:...:saveDict:cache:]  (four-arg forward)
//       timer@56               [[dict objectForKey:@"timer"] floatValue]
//                              (executed: FloatValueThroughUint32 store)
//       lastKnownGatherValue@60 [[dict objectForKey:@"lastKnownGatherValue"]
//                              intValue]
//     Both are ownkey5 executed reads (tools/arm_harness/ownkey.py, Unicorn);
//     the batch corrected static decode order where the run disagreed.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct GatherBlockFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // ownkey5 own keys (presence-gated like every other own-key block)
    bool has_timer = false;
    float timer = 0.0f;                 // @56 (floatValue)
    bool has_last_known_gather_value = false;
    std::int32_t last_known_gather_value = 0;  // @60 (intValue)
};

GatherBlockFullState gatherblock_full_load(const SaveDict& entry);

ClientDynamicObject gatherblock_full_factory(int type_id, const SaveDict& entry,
                                             GatherBlockFullState* out_state,
                                             std::string* error);

}  // namespace bh176
