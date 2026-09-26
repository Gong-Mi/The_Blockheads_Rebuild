// Recovered semantics of the VinePlant BIG loader (batch b4o):
//   -[VinePlant initWithWorld:dynamicWorld:saveDict:cache:
//        treeDensityNoiseFunction:seasonOffsetNoiseFunction:]
// Original IMP 0x004F68A0, 681 words, runtime superclass Plant,
// VinePlant.instance_size == 184 (class_ro_t+8; the last field is
// numberOfOccupiedTilesBelow at 180).
//
// KelpPlant's mirror twin (b4n). Same 12-selector set and the same key family
// on the mirrored axis (numberOfOccupiedTilesBelow), with these decoded
// differences — all of them executed in tools/test_vine_plant_init_arm.py:
//   * no Plant.frozen gate (KelpPlant returns early when frozen != 0),
//   * the growth cell is pos.y - occupiedBelow - 1 (KelpPlant: +),
//   * an EXTRA tile-suitability scan (~75 words) with two __aeabi_idiv calls and
//     a light/sun key that must exceed 0.2f,
//   * the tile-kind gate is INVERTED (helperA(tile) must be 0, i.e. tile[0] != 3),
//     tile[0] == 31 is rejected too, and the marker written is 0x7C (KelpPlant:
//     0x51),
//   * the energy constant is 900.0f (KelpPlant: 225.0f),
//   * the worldContentsChangedAtPos: y equals the query y (KelpPlant: query + 1).
//
//   self = [super initWithWorld:… treeDensityNoiseFunction:… seasonOffsetNoiseFunction:…];
//   if (!self) return nil;
//   self->numberOfOccupiedTilesBelow =
//       [[saveDict objectForKey:@"numberOfOccupiedTilesBelow"] intValue];
//   self->growthTimer = [[saveDict objectForKey:@"growthTimer"] floatValue];
//   [self initSubDerivedItems];
//   self->availableFood = [[saveDict objectForKey:@"availableFood"] floatValue];
//   if (self->availableFood < 0.1f) {
//       long r = lrand48();                       // via the 0x4F688C wrapper
//       self->availableFood =
//           (float)((double)((float)r / 2147483648.0f * 900.0f) * 1.5);
//   }
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
//   for (;;) {
//       bool canGrow = false;
//       if (self->numberOfOccupiedTilesBelow < 15) canGrow = self->growthTimer > 0.0f;
//       if (!canGrow) break;
//       float factor = (float)((double)(((1.0f
//                        - (float)self->numberOfOccupiedTilesBelow / 16.0f) + 0.2f)
//                        * self->growthRate) * 0.5 + 0.5);
//       float threshold = 900.0f / factor;
//       if (!(self->growthTimer > threshold)) break;               // ARM `ble`
//       int x = self->pos.x;
//       int y = self->pos.y - self->numberOfOccupiedTilesBelow - 1;
//       void* tile = [self->world tileAtX:x y:y];                  // 0xA12F24
//       if (tile != nil) {
//           float lightSum = ((float)(uint16)tile->half[7] / 4.0f
//                           + (float)(int16)(tile->half[8] / 4)
//                           + (float)(int16)(tile->half[9] / 2)) / 1024.0f;
//           float key = (float)(((double)(float)(uint8)tile->byte[7] * 0.4) / 255.0
//                             + (double)lightSum);
//           if (key > 0.2f && tileKindIsThree(tile) == 0
//               && tile->byte[0] != 31 && tile->byte[11] == 0) {
//               tile->byte[11] = 0x7C;
//               ++self->numberOfOccupiedTilesBelow;
//               [self->dynamicWorld worldContentsChangedAtPos:{x, y}];   // y after ++
//               self->growthTimer -= 900.0f / factor;
//               continue;
//           }
//       }
//       self->growthTimer = 0.0f;
//       break;
//   }
//   self->age = (float)((double)self->age + elapsed);
//   [self->dynamicWorld dynamicWorldChangedAtPos:self->pos objectType:[self objectType]];
//   return self;
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kVineImageSize = 184;   // VinePlant.instance_size
inline constexpr std::size_t kVineMaxTrace = 256;

inline constexpr std::uint32_t kVineOffsetWorld = 4;
inline constexpr std::uint32_t kVineOffsetDynamicWorld = 8;
inline constexpr std::uint32_t kVineOffsetPosX = 16;
inline constexpr std::uint32_t kVineOffsetPosY = 20;
inline constexpr std::uint32_t kVineOffsetAge = 72;
inline constexpr std::uint32_t kVineOffsetMaxAge = 88;
inline constexpr std::uint32_t kVineOffsetGrowthRate = 92;
inline constexpr std::uint32_t kVineOffsetAvailableFood = 100;
inline constexpr std::uint32_t kVineOffsetGrowthTimer = 176;
inline constexpr std::uint32_t kVineOffsetOccupiedBelow = 180;

inline constexpr float kVineFoodRefillThreshold = 0.1f;
inline constexpr float kVineRandomDenominator = 2147483648.0f;   // 2^31
inline constexpr float kVineRefillScale = 900.0f;
inline constexpr double kVineRefillMultiplier = 1.5;
inline constexpr float kVineCompostPenalty = 0.2f;
inline constexpr double kVineCompostAdjust = 0.1;
inline constexpr float kVineGrowthEnergy = 900.0f;
inline constexpr float kVineTileSpacing = 16.0f;
inline constexpr float kVineLightDivisor = 1024.0f;
inline constexpr double kVineSunScale = 0.4;
inline constexpr double kVineSunDivisor = 255.0;
inline constexpr float kVineLightGate = 0.2f;
inline constexpr std::uint32_t kVineMaxOccupiedTiles = 15;
inline constexpr std::uint8_t kVineTileMarker = 0x7C;   // 124
inline constexpr std::uint8_t kVineRejectedTileKind = 3;      // helperA must be 0
inline constexpr std::uint8_t kVineRejectedTileByte0 = 31;
inline constexpr std::uint32_t kVineTileMarkerOffset = 11;

struct VineTileAnswer {
    bool present = false;
    std::uint8_t byte0 = 0;
    std::uint8_t byte7 = 0;
    std::uint8_t byte11 = 0;
    std::uint16_t half_a = 0;   // tile+0x0E
    std::uint16_t half_b = 0;   // tile+0x10
    std::uint16_t half_c = 0;   // tile+0x12
};

struct VineInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    bool super_returns_nil = false;

    std::uint32_t world_argument = 0;
    std::uint32_t dynamic_world_argument = 0;
    std::uint32_t save_dict_token = 0;
    std::uint32_t cache_token = 0;
    std::uint32_t tree_density_argument = 0;
    std::uint32_t season_offset_argument = 0;

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
    std::vector<VineTileAnswer> tiles;
};

struct VineInitResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<VineInitCall, std::uint32_t>> calls;
    std::uint32_t return_value = 0;
    std::size_t tiles_consumed = 0;
};

VineInitResult vine_plant_init_with_world(const VineInitInputs& in);

}  // namespace blockheads::recovered
