// Full Workbench loader (bucket C, the last snapshot stub): runs the
// executed b4q contract on a real workbench record (type 45 in
// reverse-probe-001) and states exactly which fields are executed-grade
// and which remain static/absent.
//
// Original chain (executed evidence):
//   DynamicObject initWithWorld:dynamicWorld:saveDict:cache: (base)  [executed]
//   InteractionObject initWithWorld:...:saveDict:cache: (352w)        [STATIC
//     only — UPPERMID15 table: currentBlockheadIndex, flipped, isInUse,
//     ownerID, ownerName, paintColor; no recovered module yet]
//   Workbench initWithWorld:dynamicWorld:saveDict:cache: (0x00AE4ED8,
//     1,390 words) — the b4q executed differential, 11 cases bit-exact:
//     the 16-key scalar walk (workbenchType/selectedIndex/xScroll/level/
//     craftProgressCount/hurryTimer/hurrySeconds/hurrying[BOOL]/
//     hurryCost/fireSpreadTimer/fuelFraction/hasFuel[BOOL]/lastWorldTime
//     [double]/isInUseFuel[BOOL]/availableElectricity[UNSIGNEDINT]/
//     currentBlockheadIndexFuel [objectForKey twice, intValue once]),
//     the isInUse crafting wiring gate, the isInUseFuel gate, and the
//     lightDict presence restore (ArtificialLight alloc + 5-arg init ->
//     light@100). The light's INTERNAL save keys are not recovered; only
//     its presence and the store are executed facts.
//
// The snapshot's workbench record (uid 154) carries: the 16 executed
// scalars + saveTime (write-only stamp, same asymmetry as trees) +
// interactionObjectType (not a load key of this chain) + the
// InteractionObject static set (flipped/paintColor/isInUse...). The
// factory loads the executed set, reports the light restore, and leaves
// the InteractionObject set explicitly un-loaded (static evidence only).
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include "artificial_light_full.h"
#include "workbench_init.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct WorkbenchFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // the b4q executed scalar walk (original ivar offsets)
    std::int32_t workbench_type = 0;        // @120 word (intValue)
    std::int32_t selected_index = 0;        // @136 word (intValue)
    float x_scroll = 0.0f;                  // @172 (floatValue)
    std::int32_t level = 0;                 // @176 word (intValue)
    float craft_progress_count = 0.0f;      // @188 (floatValue)
    float hurry_timer = 0.0f;               // @192 (floatValue)
    float hurry_seconds = 0.0f;             // @196 (floatValue)
    bool hurrying = false;                  // @200 byte (BOOLValue)
    std::int32_t hurry_cost = 0;            // @204 word (intValue)
    float fire_spread_timer = 0.0f;         // @208 (floatValue)
    float fuel_fraction = 0.0f;             // @212 (floatValue)
    bool has_fuel = false;                  // @220 byte (BOOLValue)
    double last_world_time = 0.0;           // @256 (doubleValue)
    bool is_in_use_fuel = false;            // @112 byte (BOOLValue)
    std::uint16_t available_electricity = 0;// @222 halfword (unsignedInt)
    std::int32_t saved_blockhead_index_fuel = 0;  // @116 (intValue)
    // lightDict: presence is the executed fact; the ArtificialLight body
    // is outside the b4q differential
    bool light_present = false;
    LightFields light;  // decoded via the ArtificialLight key table (shared decoder)
    // the InteractionObject static set — NOT loaded (no recovered module);
    // reported so callers can see the boundary instead of assuming zero
    bool interaction_static_keys_present = false;
};

// Reads ONE workbench entry dictionary through the executed b4q contract.
WorkbenchFullState workbench_full_load(const SaveDict& entry);

// The registry factory for type 45.
ClientDynamicObject workbench_full_factory(int type_id, const SaveDict& entry,
                                           WorkbenchFullState* out_state,
                                           std::string* error);

}  // namespace bh176
