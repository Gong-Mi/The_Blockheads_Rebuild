// KelpPlant (34) / VinePlant (58) loader: the executed b4n/b4o chains.
//
// Both are Plant subclasses whose own loaders are "mirror twins" (b4o note):
// same selector set, mirrored axis. Their record key set =
//   base {uniqueID, pos_x, pos_y, floatPos}
//   Plant chain keys (executed b4b: seasonOffset/age/gatherProgress/
//     hasFloweredThisSeason/flowering/frozen/maxAgeGene/growthRateGene +
//     saveTime gate) — reused here through plant_full_load
//   own keys (executed b4n/b4o):
//     KelpPlant 34: numberOfOccupiedTilesAbove@200 int, growthTimer@176
//                   float, availableFood@180 float
//     VinePlant 58: numberOfOccupiedTilesBelow@180 int, growthTimer@176
//                   float, availableFood@100 float
// The big loader contracts (kelp_plant_init / vine_plant_init) additionally
// model world-interaction steps that are not save state; this module covers
// the save-record domain only, with the own-key conversions as executed.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "plant_full.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct KelpVineFullState {
    // the Plant chain (executed b4b) — own tulip block stays closed for
    // kelp/vine records (presence-gated)
    PlantFullState plant;
    bool is_kelp = false;   // type 34 when true, 58 when false
    // own keys (executed b4n/b4o)
    bool has_occupied_tiles = false;
    std::int32_t occupied_tiles = 0;  // Above (kelp @200) / Below (vine @180)
    bool has_growth_timer = false;
    float growth_timer = 0.0f;        // @176 both
    bool has_available_food = false;
    float available_food = 0.0f;      // @180 kelp / @100 vine
};

// world_time is the Plant saveTime gate's other input (as in plant_full_load).
KelpVineFullState kelpvine_full_load(const SaveDict& entry, double world_time,
                                     int type_id);

ClientDynamicObject kelpvine_full_factory(int type_id, const SaveDict& entry,
                                          double world_time,
                                          KelpVineFullState* out_state,
                                          std::string* error);

}  // namespace bh176
