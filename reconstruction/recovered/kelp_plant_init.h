// Recovered semantics of the KelpPlant BIG loader (batch b4n):
//   -[KelpPlant initWithWorld:dynamicWorld:saveDict:cache:
//        treeDensityNoiseFunction:seasonOffsetNoiseFunction:]
// Original IMP 0x00815BE8, 606 words, runtime superclass Plant,
// KelpPlant.instance_size == 204 (class_ro_t+8; the last field read is
// numberOfOccupiedTilesAbove at 200).
//
// Decoded shape (see reconstruction/reverse-v3/native/KELP_PLANT_INIT_ARM.md):
//   self = [super initWithWorld:… treeDensityNoiseFunction:… seasonOffsetNoiseFunction:…];
//   if (!self) return nil;
//   self->numberOfOccupiedTilesAbove =
//       [[saveDict objectForKey:@"numberOfOccupiedTilesAbove"] intValue];
//   self->growthTimer = [[saveDict objectForKey:@"growthTimer"] floatValue];
//   [self initSubDerivedItems];
//   self->availableFood = [[saveDict objectForKey:@"availableFood"] floatValue];
//   if (self->availableFood < 0.1f) {
//       long r = lrand48();                     // via the 0x814F44 wrapper
//       self->availableFood =
//           (float)((double)((float)r / 900.0f * 900.0f) * 1.5);
//   }
//   if (self->frozen != 0) return self;         // ice-biome state, ldrsb
//   double elapsed = [world worldTime]
//                  - [[saveDict objectForKey:@"saveTime"] doubleValue];
//   self->growthTimer = (float)((double)self->growthTimer + elapsed);
//   if (!((double)self->age + elapsed < (double)self->maxAge)) {   // ARM `blt`
//       if ([self isGrowingInCompost])
//           elapsed = (double)((float)self->maxAge - (float)self->age) - 0.1;
//   }
//   if (!((double)self->age + elapsed < (double)self->maxAge)) {   // ARM `bpl`
//       [self dieOfOldAge];
//       return self;
//   }
//   for (;;) {                                   // multi-tile growth loop
//       bool canGrow = false;
//       if (self->numberOfOccupiedTilesAbove < 15) canGrow = self->growthTimer > 0.0f;
//       if (!canGrow) break;
//       float factor = (float)((double)(((1.0f
//                        - (float)self->numberOfOccupiedTilesAbove / 16.0f) + 0.2f)
//                        * self->growthRate) * 0.5 + 0.5);
//       float threshold = 225.0f / factor;
//       if (!(self->growthTimer > threshold)) break;             // ARM `ble`
//       int x = self->pos.x;
//       int y = self->pos.y + self->numberOfOccupiedTilesAbove + 1;
//       void* tile = [self->world tileAtX:x y:y];                // 0xA12F24
//       if (tileKindIsThree(tile) && tile->byte[11] == 0) {      // 0xA11690
//           tile->byte[11] = 0x51;
//           ++self->numberOfOccupiedTilesAbove;
//           [self->dynamicWorld worldContentsChangedAtPos:{x, y+1}]; // y AFTER ++occupied
//           self->growthTimer -= 225.0f / factor;
//       } else {
//           self->growthTimer = 0.0f;
//           break;
//       }
//   }
//   self->age = (float)((double)self->age + elapsed);
//   [self->dynamicWorld dynamicWorldChangedAtPos:self->pos objectType:[self objectType]];
//   return self;
//
// Branch forms are kept EXACTLY as the ARM compares them (BLT/N!=V, BPL/N==0,
// BLE, MOVGT): an unordered NaN takes the same edge here as in the original.
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kKelpImageSize = 204;   // KelpPlant.instance_size
inline constexpr std::size_t kKelpMaxTrace = 256;

inline constexpr std::uint32_t kKelpOffsetWorld = 4;
inline constexpr std::uint32_t kKelpOffsetDynamicWorld = 8;
inline constexpr std::uint32_t kKelpOffsetPosX = 16;
inline constexpr std::uint32_t kKelpOffsetPosY = 20;
inline constexpr std::uint32_t kKelpOffsetAge = 72;              // Plant.age
inline constexpr std::uint32_t kKelpOffsetFrozen = 76;           // Plant.frozen
inline constexpr std::uint32_t kKelpOffsetMaxAge = 88;           // Plant.maxAge
inline constexpr std::uint32_t kKelpOffsetGrowthRate = 92;       // Plant.growthRate
inline constexpr std::uint32_t kKelpOffsetGrowthTimer = 176;     // KelpPlant
inline constexpr std::uint32_t kKelpOffsetAvailableFood = 180;   // KelpPlant
inline constexpr std::uint32_t kKelpOffsetOccupied = 200;        // KelpPlant
inline constexpr std::uint32_t kKelpMaxOccupiedTiles = 15;

inline constexpr float kKelpFoodRefillThreshold = 0.1f;   // pool @0x815cc8
inline constexpr float kKelpRandomDenominator = 2147483648.0f;  // 2^31, pool @0x815cd0
inline constexpr float kKelpRefillScale = 900.0f;          // pool @0x815ccc
inline constexpr double kKelpRefillMultiplier = 1.5;
inline constexpr float kKelpCompostPenalty = 0.2f;
inline constexpr double kKelpCompostAdjust = 0.1;
inline constexpr float kKelpGrowthEnergy = 225.0f;
inline constexpr float kKelpTileSpacing = 16.0f;
inline constexpr std::uint8_t kKelpTileMarker = 0x51;
inline constexpr std::uint8_t kKelpTileKind = 3;
inline constexpr std::uint32_t kKelpTileMarkerOffset = 11;

struct KelpTileAnswer {
    bool present = false;
    std::uint8_t byte0 = 0;    // tile kind byte read by the 0xA11690 helper
    std::uint8_t byte11 = 0;   // occupancy marker the body tests and writes
};

struct KelpInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    bool super_returns_nil = false;

    // Method arguments (distinct from the ivars on purpose).
    std::uint32_t world_argument = 0;
    std::uint32_t dynamic_world_argument = 0;
    std::uint32_t save_dict_token = 0;
    std::uint32_t cache_token = 0;
    std::uint32_t tree_density_argument = 0;
    std::uint32_t season_offset_argument = 0;

    // Instance staging.
    std::uint32_t world_ivar = 0;
    std::uint32_t dynamic_world_ivar = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    std::int32_t occupied_init = 0;
    float growth_timer_init = 0.0f;
    float available_food_init = 0.0f;
    float age_init = 0.0f;
    float max_age = 0.0f;
    float growth_rate = 0.0f;
    std::int8_t frozen = 0;

    // saveDict surface.
    std::uint32_t occupied_box_token = 0;
    std::uint32_t growth_timer_box_token = 0;
    std::uint32_t available_food_box_token = 0;
    std::uint32_t save_time_box_token = 0;
    std::int32_t occupied_value = 0;
    float growth_timer_value = 0.0f;
    float available_food_value = 0.0f;
    double save_time_value = 0.0;
    double world_time = 0.0;

    std::int64_t lrand48_value = 0;
    bool is_growing_in_compost = false;
    std::uint32_t object_type_value = 0;
    std::vector<KelpTileAnswer> tiles;   // consumed in order by the world accessor
};

struct KelpInitResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<KelpInitCall, std::uint32_t>> calls;
    std::uint32_t return_value = 0;
    std::size_t tiles_consumed = 0;
};

KelpInitResult kelp_plant_init_with_world(const KelpInitInputs& in);

}  // namespace blockheads::recovered
