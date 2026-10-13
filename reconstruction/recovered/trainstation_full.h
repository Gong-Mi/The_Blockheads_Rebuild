// TrainStation loader (type 49): the ownkey5 executed chain, same evidence
// profile as Workbench (executed own-side + a stated InteractionObject
// static boundary).
//
// Original chain (executed evidence):
//   DynamicObject initWithWorld:dynamicWorld:saveDict:cache: (base)  [executed]
//   InteractionObject initWithWorld:...:saveDict:cache: (352w)  [STATIC only —
//     UPPERMID15 table: currentBlockheadIndex, flipped, isInUse, ownerID,
//     ownerName, paintColor; no recovered module; NOT loaded, reported]
//   TrainStation initWithWorld:dynamicWorld:saveDict:cache: (ownkey5 program;
//     super resolved from the class struct: InteractionObject):
//       [super initWithWorld:...:saveDict:cache:]  (four-arg forward, executed)
//       text@128   retain([dict objectForKey:@"text"])
//       [self initSubDerivedItems]  (tail hook; reads no save key)
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct TrainStationFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // ownkey5 own key (executed): text@128 — an object slot; offline only its
    // presence is preserved (the harness stores the retained pointer)
    bool has_text = false;
    // the InteractionObject static set — NOT loaded (no recovered module);
    // reported so callers can see the boundary instead of assuming zero
    bool interaction_static_keys_present = false;
};

TrainStationFullState trainstation_full_load(const SaveDict& entry);

ClientDynamicObject trainstation_full_factory(int type_id,
                                              const SaveDict& entry,
                                              TrainStationFullState* out_state,
                                              std::string* error);

}  // namespace bh176
