// Full Plant-family loader (batch b5b): turns a real save record into a
// populated ClientDynamicObject using ONLY executed/recovered contracts.
//
// Original chain (all links already recovered & executed in prior batches):
//   DynamicObject initWithWorld:dynamicWorld:saveDict:cache:
//       (base: uniqueID unsignedLongValue@40, pos_x/pos_y intValue@16/@20,
//        floatPos objectAtIndex:0/1 floatValue@24)          [b3l/PR#3]
//   Plant initWithWorld:...:treeDensityNoiseFunction:seasonOffsetNoiseFunction:
//       (swallows the two noise args into ivars 60/64, then delegates to
//        [self loadSaveDictValues:] and the DynamicWorld notify)  [ownkey5]
//   Plant loadSaveDictValues: (0x009554a0, 9-key contract: seasonOffset,
//       age, gatherProgress, hasFloweredThisSeason, flowering, frozen,
//       maxAgeGene, growthRateGene + the saveTime→1800s season gate)
//                                                              [b4b]
//   TulipPlant subclass reads availableFood/colorGenes/mateColorGenes/
//       mixGenes after the super chain                     [b3k static]
//
// Save-record keys are therefore FULLY explained for the family:
//   {seasonOffset, age, gatherProgress, hasFloweredThisSeason, flowering,
//    frozen, maxAgeGene, growthRateGene, saveTime}         (Plant level)
//   {uniqueID, pos_x, pos_y, floatPos}                     (base level)
//   {availableFood, colorGenes, mateColorGenes, mixGenes}  (TulipPlant level)
//   {height, treeSeasonOffset, dead, timeDied, removeCheckCount, growthCounter,
//    growthRate, maxHeightGene, maxHeightReached, treeFruit, maxAge}
//    are the TREE branch's keys (tree_load_save_dict_stage1 + b2l/b2o);
//    a Plant-type record never reads the tree-only set.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

// Recovered Plant ivar offsets (executed contracts; see plant_load_save_dict.h
// and the ownkey5 Plant program).
inline constexpr std::uint32_t kPlantIvarSeasonOffset = 68;
inline constexpr std::uint32_t kPlantIvarAge = 72;
inline constexpr std::uint32_t kPlantIvarGatherProgress = 80;
inline constexpr std::uint32_t kPlantIvarFrozen = 76;
inline constexpr std::uint32_t kPlantIvarHasFlowered = 84;
inline constexpr std::uint32_t kPlantIvarFlowering = 85;
inline constexpr std::uint32_t kPlantIvarMaxAgeGene = 54;   // strh, clamp 1..255
inline constexpr std::uint32_t kPlantIvarGrowthRateGene = 56;

// TulipPlant own keys (b3k, static level-A; consumed after the Plant chain).
struct TulipPlantFields {
    bool present = false;
    float available_food = 0.0f;      // floatValue
    std::uint16_t color_genes = 0;     // intValue stored per b2l strh profile
    std::uint16_t mate_color_genes = 0;
    std::uint16_t mix_genes = 0;
};

// Reads ONE dynamic-object entry dictionary into base+plant(+tulip) state.
// world_time is [world worldTime] at load time (the saveTime gate's other
// input). Unknown keys are ignored, never invented; missing keys decode as
// nil (0/false per the SaveDict contract).
struct PlantFullInputs {
    const SaveDict& entry;
    double world_time = 0.0;
};

struct PlantFullState {
    // base loader (executed)
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // Plant loadSaveDictValues: (executed)
    std::int32_t season_offset = 0;
    float age = 0.0f;
    std::int32_t gather_progress = 0;
    bool has_flowered = false;
    bool flowering = false;
    bool frozen = false;
    std::uint16_t max_age_gene = 0;
    std::uint16_t growth_rate_gene = 0;
    bool season_gate_fired = false;    // world_time - save_time > 1800
    // TulipPlant subclass keys (static)
    TulipPlantFields tulip;
};

PlantFullState plant_full_load(const PlantFullInputs& inputs);

// The registry factory for the Plant family (TulipPlant 59): executes the
// full recovered chain (plant_full_load) on construction and hands the
// per-type state to the caller through *out_state (nullable — the registry
// Factory signature path passes null). Returns the registry-shaped
// ClientDynamicObject (identity fields + Recovered status); the registry
// object deliberately carries no per-type fields, so callers that need the
// Plant state take it from *out_state instead of re-parsing the plist.
ClientDynamicObject plant_full_factory(int type_id, const SaveDict& entry,
                                       double world_time,
                                       PlantFullState* out_state,
                                       std::string* error);

}  // namespace bh176
