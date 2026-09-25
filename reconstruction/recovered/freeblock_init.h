// Recovered semantics of the FreeBlock exact-variant loader (batch b4p):
//   -[FreeBlock initWithWorld:dynamicWorld:saveDict:cache:]
// Original IMP 0x00626A68, 1,347 words, runtime superclass DynamicObject,
// FreeBlock.instance_size == 156 (class_ro_t+8; instanceStart 56).
//
// The falling/loose-item entity. Executed differential in
// tools/test_freeblock_init_arm.py; all statements below are pinned by the
// 1,347-word listing reconstruction/reverse-v3/native/
// disasm_freeblock_big_initwithworld.txt (level-A) and the Unicorn run
// (level-B, 14 cases).
//
//   self = [super initWithWorld:world dynamicWorld:dw saveDict:dict
//                           cache:cache];              // super2, 4 args
//   if (!self) return nil;
//   self->bounceTimer  = [[dict objectForKey:@"bounceTimer"]  floatValue];
//   self->fallSpeed   = [[dict objectForKey:@"fallSpeed"]   floatValue];
//   self->creationTime = [[dict objectForKey:@"creationTime"] doubleValue];
//   self->floatPos.x  = [[dict objectForKey:@"floatPos[VX]"] floatValue];
//   self->floatPos.y  = [[dict objectForKey:@"floatPos[VY]"] floatValue];
//   self->hovers      = (byte)[[dict objectForKey:@"hovers"]  boolValue];
//   self->itemType    = (u32) [[dict objectForKey:@"itemType"] intValue];
//   self->dataA       = (u16) [[dict objectForKey:@"dataA"]   intValue];
//   self->dataB       = (u16) [[dict objectForKey:@"dataB"]   intValue];
//   fresh = [NSMutableArray alloc] init];                    // stored in subItems
//   for (elem in [dict objectForKey:@"subItems"]) {           // NSFastEnum; the
//       temp = [NSMutableArray array];                       // source is an ARRAY
//       [self->subItems addObject:temp];                    // OF ARRAYS
//       for (payload in elem) {                              // inner NSFastEnum
//           item = [[InventoryItem alloc]
//                    initWithSaveData:payload autorelease];
//           if ([item itemType] != 11)                       // == 0xb skipped
//               [temp addObject:item];
//       }
//   }
//   self->dynamicObjectSaveDict =
//       [[dict objectForKey:@"dynamicObjectSaveDict"] copy];
//   int64_t pid = [[dict objectForKey:@"priorityBlockheadUinqueID"]
//                  intValue];                    // the original's own typo
//   if (pid != 0)
//       self->priorityBlockhead =
//           [[dynamicWorld blockheadWithIDIncludingNet:(int64_t)(int32_t)pid]
//              retain];        // receiver = self->dynamicWorld (executed fact)
//   [self initSubDerivedObjects];
//   if (self->hovers != 0) {
//       if ([world worldTime] - self->creationTime <= 900.0) return self;
//       // itemType blacklist: {0x1b,0x8e,0x8c,0x8f,0x8d} inline cmps, then
//       // the 0x627C40 helper (113 probed types), then the 0x5B2AD4
//       // liquid-container predicate (21 probed types); any hit returns.
//       if (itemType in kFreeblockInlineSkip
//           || kFreeblockBlacklist627C40(itemType)
//           || kFreeblockLiquid5B2AD4(itemType)) return self;
//       float elapsed = (float)([world worldTime] - self->creationTime
//                                - 900.0);
//       self->hovers = 0;
//       self->creationTime = [world worldTime] - (double)elapsed;  // re-anchor
//       // (executed fact: the re-anchor targets CREATION TIME, not floatPos)
//       if (elapsed < 900.0f) {
//           for (int i = 0; i < 16; ++i) {                  // ground fall
//               Tile* t = [world tileAtX:self->pos.x y:self->pos.y - 1];
//               if (t != nil && t->byte[0] == 2) {          // 0x00A12300
//                   self->floatPos.y -= 1.0f;
//                   [self updatePosition:{self->pos.x, self->pos.y - 1}];
//                   continue;         // pos re-read next step (keep falling)
//               }
//               break;
//           }
//       }
//       self->updateNeedsToBeSent = 1;
//       [dynamicWorld dynamicWorldChangedAtPos:self->pos
//                                 objectType:[self objectType]];
//   }
//   return self;
//
// Harness facts pinned by the run:
//   * the ground fall re-reads pos each iteration (updatePosition: mutated
//     it), so each step queries (pos.x, pos.y-1) with the NEW pos.y;
//   * the max-16 loop runs even when the tile answer is nil or soft
//     (byte[0] != 2): only a solid tile continues the fall;
//   * the 64-bit blockhead id is the 32-bit intValue sign-extended
//     (asr #31 on the high word), 0 skips the resolution entirely;
//   * the blacklist/liquid helpers ran NATIVELY in the differential; here
//     they are explicit probed tables (generated from the pinned ELF).
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kFreeblockImageSize = 156;   // instance_size
inline constexpr std::size_t kFreeblockMaxTrace = 512;

inline constexpr std::uint32_t kFreeblockOffsetWorld = 4;
inline constexpr std::uint32_t kFreeblockOffsetDynamicWorld = 8;
inline constexpr std::uint32_t kFreeblockOffsetPos = 16;
inline constexpr std::uint32_t kFreeblockOffsetFloatPos = 24;
inline constexpr std::uint32_t kFreeblockOffsetUpdateNeeds = 49;
inline constexpr std::uint32_t kFreeblockOffsetUniqueID = 40;
inline constexpr std::uint32_t kFreeblockOffsetItemType = 56;
inline constexpr std::uint32_t kFreeblockOffsetDataA = 60;
inline constexpr std::uint32_t kFreeblockOffsetDataB = 62;
inline constexpr std::uint32_t kFreeblockOffsetHovers = 64;
inline constexpr std::uint32_t kFreeblockOffsetBounceTimer = 68;
inline constexpr std::uint32_t kFreeblockOffsetFallSpeed = 72;
inline constexpr std::uint32_t kFreeblockOffsetCreationTime = 80;
inline constexpr std::uint32_t kFreeblockOffsetSubItems = 112;
inline constexpr std::uint32_t kFreeblockOffsetPriorityBlockhead = 136;
inline constexpr std::uint32_t kFreeblockOffsetDynSaveDict = 140;

inline constexpr float kFreeblockHoversAgeLimit = 900.0f;     // both gates
inline constexpr double kFreeblockHoversAgeLimitD = 900.0;
inline constexpr std::uint32_t kFreeblockSkippedItemType = 11; // subItems skip
inline constexpr std::uint32_t kFreeblockGroundFallMaxSteps = 16;
inline constexpr std::uint8_t kFreeblockGroundSolidKind = 2;  // tile byte 0

// itemType gates between the age gate and the re-anchor (decoded from the
// 1,347-word listing; the two helper sets were probed from the pinned ELF).
inline constexpr std::uint32_t kFreeblockInlineSkip[] = {
    0x1b, 0x8e, 0x8c, 0x8f, 0x8d,
};
inline constexpr std::uint32_t kFreeblockInlineSkip2[] = {
    0xcd, 0xd0, 0xce, 0xcc,
};
// 0x627C40 probed set (113 types over [0, 0x200)).
inline constexpr std::uint32_t kFreeblockBlacklist627C40[] = {
    0xf, 0x11, 0x2f, 0x34, 0x35, 0x3a, 0x3f, 0x45, 0x4b, 0x4c, 0x56, 0x57,
    0x58, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x91, 0x92, 0x93, 0x94, 0x95,
    0x96, 0x9d, 0xa1, 0xa3, 0xa4, 0xa5, 0xa8, 0xa9, 0xaa, 0xae, 0xb2, 0xb7,
    0xc8, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd2, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4,
    0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
    0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
    0xfd, 0xfe, 0x102, 0x107, 0x108, 0x109, 0x10a, 0x10b, 0x10c, 0x10e,
    0x119, 0x11a, 0x11b, 0x11c, 0x12c, 0x12d, 0x130, 0x14b, 0x14c, 0x14d,
    0x14e, 0x14f, 0x150, 0x151, 0x152, 0x153, 0x154, 0x155, 0x156, 0x157,
};
// 0x5B2AD4 probed set (21 types over [0, 0x200)): the "liquid container"
// family (buckets/flasks) checked AFTER the big blacklist.
inline constexpr std::uint32_t kFreeblockLiquid5B2AD4[] = {
    0xf, 0x3f, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0xa1, 0xa3, 0xa8, 0xa9,
    0xaa, 0xc8, 0xcf, 0xd2, 0xdd, 0x10e, 0x12c, 0x12d, 0x14b,
};

struct FreeblockTileAnswer {
    bool present = false;
    std::uint8_t byte0 = 0;
};

struct FreeblockInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    bool super_returns_nil = false;

    std::uint32_t world_argument = 0;
    std::uint32_t dynamic_world_argument = 0;
    std::uint32_t save_dict_token = 0;
    std::uint32_t cache_token = 0;

    std::uint32_t world_ivar = 0;
    std::uint32_t dynamic_world_ivar = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    std::uint32_t unique_id = 0;
    std::uint32_t item_type_init = 0;
    std::uint32_t hovers_init = 0;

    float bounce_timer_value = 0.0f;
    float fall_speed_value = 0.0f;
    double creation_time_value = 0.0;
    float float_vx_value = 0.0f;
    float float_vy_value = 0.0f;
    std::uint32_t hovers_value = 0;
    std::uint32_t item_type_value = 0;
    std::uint32_t data_a_value = 0;
    std::uint32_t data_b_value = 0;
    std::int32_t priority_id_value = 0;
    std::uint32_t blockhead_answer = 0;
    std::vector<std::uint32_t> sub_items;      // flattened sub-item types
    std::vector<std::uint32_t> elem_counts;    // per-element sub-item counts
    std::uint32_t elem_count = 0;              // number of elements

    double world_time = 0.0;
    std::uint32_t object_type_value = 0;
    std::vector<FreeblockTileAnswer> tiles;
};

struct FreeblockInitResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<FreeblockInitCall, std::uint32_t>> calls;
    std::uint32_t return_value = 0;
    std::size_t tiles_consumed = 0;
};

FreeblockInitResult freeblock_init_with_world(const FreeblockInitInputs& in);

bool freeblock_blacklist_627c40_contains(std::uint32_t item_type);
bool freeblock_liquid_5b2ad4_contains(std::uint32_t item_type);

}  // namespace blockheads::recovered
