// Recovered semantics of -[DynamicObject initDerivedStuff:loadPhysicalBlockIfNeeded:] (batch b4k).
// Original IMP: 0x00839508, 242 words.
//
// Decoded shape:
//   id macroTiles = [self->world macroTiles];
//   IntPoint macroCoord = convertWorldToMacroCoord(self->pos, self->world);
//   MacroTile* macroTile = lookupMacroTile(macroCoord, macroTiles, self->world);
//   self->macroTileOwner = macroTile; // offset 12
//   if (macroTile == nil) return false;
//   if (macroTile->physicalBlock == nil) {
//       if (loadPhysicalBlockIfNeeded) {
//           [self->world loadPhysicalBlockForMacroTile:macroTile atX:macroCoord.x y:macroCoord.y loadSurroundingBlocks:false createIfNotCreated:true];
//       } else {
//           return false;
//       }
//   }
//   if (![self shouldAddToMacroBlock]) return true;
//   [self->dynamicWorld loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:macroTile includeSurfaceBlocks:true];
//   [macroTile->dynamicObjects addObject:self];
//   if (!initDerivedStuff) {
//       int objType = [self objectType];
//       [self->dynamicWorld dynamicWorldChangedAtPos:self->pos objectType:objType];
//   }
//   return true;
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kDynamicObjectDerivedImageSize = 48;
inline constexpr std::size_t kDynamicObjectDerivedMaxTrace = 32;

struct DynamicObjectInitDerivedInputs {
    std::uint32_t self_ptr = 0x60000000u;
    std::uint32_t world_ptr = 0x60010000u;
    std::uint32_t dynamic_world_ptr = 0x60020000u;
    int32_t pos_x = 100;
    int32_t pos_y = 200;
    std::uint32_t macro_tile_ptr = 0x60030000u; // 0 if nil
    bool physical_block_loaded = true;
    bool should_add_to_macro_block = true;
    int32_t object_type = 24;
    bool init_derived_stuff = true;
    bool load_physical_block_if_needed = true;
};

struct DynamicObjectInitDerivedResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<DynamicObjectInitDerivedStuffCall, std::uint32_t>> calls;
    bool return_value = false;
};

DynamicObjectInitDerivedResult dynamic_object_init_derived_stuff(
    const DynamicObjectInitDerivedInputs& in);

}  // namespace blockheads::recovered
