// Recovered semantics of the Workbench loader (batch b4q):
//   -[Workbench initWithWorld:dynamicWorld:saveDict:cache:]
// Original IMP 0x00AE4ED8, 1,390 words, runtime superclass InteractionObject,
// Workbench.instance_size == 324 (class_ro_t+8; instanceStart 100).
//
// The crafting centerpiece — the LAST executed initWithWorld front member.
// All statements below are pinned by the 1,390-word listing
// reconstruction/reverse-v3/native/disasm_workbench_big_initwithworld.txt
// (level-A) and the Unicorn run (level-B, 11 cases).
//
// Executed key order (frozen):
//   workbenchType(intValue@120 word) selectedIndex(intValue@136 word)
//   xScroll(floatValue@172) level(intValue@176 word)
//   craftProgressCount(floatValue@188) hurryTimer(floatValue@192)
//   hurrySeconds(floatValue@196) hurrying(BOOL@200 byte)
//   hurryCost(intValue@204 word) fireSpreadTimer(floatValue@208)
//   fuelFraction(floatValue@212) hasFuel(BOOL@220 byte)
//   lastWorldTime(doubleValue@256 double) isInUseFuel(BOOL@112 byte)
//   availableElectricity(UNSIGNED int@222 halfword)
//   currentBlockheadIndexFuel: objectForKey TWICE then intValue, stored at
//   savedBlockheadIndexFuel@116 (word) — the double read happens regardless
//   of the value (executed fact, b4q).
// Then:
//   if (self->isInUse) {                        // InteractionObject.isInUse@68
//     v2 = [dict objectForKey:@"craftingItemDatav2"];
//     if (v2 != nil) {
//       type = [[v2 objectForKey:@"craftableObjectType"] intValue];
//       if (type == 1)      craftingItemObject = [[BlockheadCraftableItemObject alloc] initWithSaveDict:v2];
//       else if (type == 2) craftingItemObject = [[PaintingCraftableItemObject alloc] initWithSaveDict:v2];
//       else                craftingItemObject = [[CraftableItemObject alloc] initWithSaveDict:v2];
//     } else {
//       v1 = [dict objectForKey:@"craftingItemData"];
//       if (v1 != nil) {      // the v1 -> v2 MIGRATION
//         blob = [v1 bytes];                    // 124-byte CraftableItem
//         memcpy(local, blob, 124);             // GOT memcpy 0x105FB40
//         memcpy(argSlot, local, 124);          // second copy (executed)
//         craftingItemObject = [[CraftableItemObject alloc]
//             initWithCraftableItem:local];      // blob[0..3] as the arg
//       }
//     }
//     if (craftingItemObject != nil) {
//       item = [craftingItemObject craftableItem];  // objc_msgSend_stret
//         // 124-byte struct: +0x00 type, +8.. slot types, +0x48 slot count
//       count = [[dict objectForKey:@"count"] intValue];          // @228
//       countLeft = [[dict objectForKey:@"countLeft"] intValue];  // @232
//       countCreated = [[dict objectForKey:@"countCreated"] intValue]; // @236
//       for (int i = 0; i < item.slotCount; ++i) {
//         [self->sourceItems[i] release];       // msgSend release
//         self->sourceItems[i] = nil;
//         if (item.slotTypes[i] == 11) continue;   // the 0xb slot gate
//         key = [NSString stringWithFormat:@"sourceItems_%d", i];
//         arr = [dict objectForKey:key];
//         if ([arr count] == 0) continue;
//         fresh = [NSMutableArray alloc] init];
//         self->sourceItems[i] = fresh;
//         for (payload in arr) {                 // NSFastEnumeration
//           item = [[InventoryItem alloc]
//                     initWithSaveData:payload autorelease];
//           [fresh addObject:item];
//         }
//       }
//       [craftingItemObject setInteractionWorkbench:self];
//     }
//   }
//   if (self->isInUseFuel)                      // BOOL@112
//     [self->currentFuelBlockhead setInteractionWorkbench:self];
//   lightDict = [dict objectForKey:@"lightDict"];
//   if (lightDict != nil) {
//     light = [[ArtificialLight alloc]
//         initWithWorld:world dynamicWorld:dw saveDict:lightDict
//                   cache:cache parentObject:self];   // 5-arg variant
//     self->light = light;                      // @100
//     tiles = [world macroTiles];
//     w = [world worldWidthMacro];              // asked twice by 0xA197B4
//     ... tile-light update via 0xA197B4 (__aeabi_idiv) ...
//   }
//   [self initSubDerivedItems];
//   return self;
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kWorkbenchImageSize = 324;   // instance_size
inline constexpr std::size_t kWorkbenchMaxTrace = 1024;

inline constexpr std::uint32_t kWorkbenchOffsetWorld = 4;
inline constexpr std::uint32_t kWorkbenchOffsetDynamicWorld = 8;
inline constexpr std::uint32_t kWorkbenchOffsetPos = 16;
inline constexpr std::uint32_t kWorkbenchOffsetCache = 32;
inline constexpr std::uint32_t kWorkbenchOffsetCurrentBlockhead = 56;
inline constexpr std::uint32_t kWorkbenchOffsetIsInUse = 68;
inline constexpr std::uint32_t kWorkbenchOffsetLight = 100;
inline constexpr std::uint32_t kWorkbenchOffsetCurrentFuel = 108;
inline constexpr std::uint32_t kWorkbenchOffsetIsInUseFuel = 112;
inline constexpr std::uint32_t kWorkbenchOffsetSavedBhFuel = 116;
inline constexpr std::uint32_t kWorkbenchOffsetType = 120;
inline constexpr std::uint32_t kWorkbenchOffsetCraftingItem = 180;
inline constexpr std::uint32_t kWorkbenchOffsetSelectedIndex = 136;
inline constexpr std::uint32_t kWorkbenchOffsetSourceItems = 140;
inline constexpr std::uint32_t kWorkbenchOffsetXScroll = 172;
inline constexpr std::uint32_t kWorkbenchOffsetLevel = 176;
inline constexpr std::uint32_t kWorkbenchOffsetCraftProgress = 188;
inline constexpr std::uint32_t kWorkbenchOffsetHurryTimer = 192;
inline constexpr std::uint32_t kWorkbenchOffsetHurrySeconds = 196;
inline constexpr std::uint32_t kWorkbenchOffsetHurrying = 200;
inline constexpr std::uint32_t kWorkbenchOffsetHurryCost = 204;
inline constexpr std::uint32_t kWorkbenchOffsetFireSpread = 208;
inline constexpr std::uint32_t kWorkbenchOffsetFuelFraction = 212;
inline constexpr std::uint32_t kWorkbenchOffsetHasFuel = 220;
inline constexpr std::uint32_t kWorkbenchOffsetAvailableElec = 222;
inline constexpr std::uint32_t kWorkbenchOffsetCountCreated = 236;
inline constexpr std::uint32_t kWorkbenchOffsetCountLeft = 232;
inline constexpr std::uint32_t kWorkbenchOffsetCount = 228;
inline constexpr std::uint32_t kWorkbenchOffsetLastWorldTime = 256;

inline constexpr std::uint32_t kWorkbenchSkippedSlotType = 11;
inline constexpr std::uint32_t kWorkbenchCraftableBlobSize = 124;  // 0x7c
inline constexpr std::uint32_t kWorkbenchStretSlotCountOffset = 0x48;
inline constexpr std::uint32_t kWorkbenchStretSlotTypesOffset = 8;

// per-key box tokens (executed fact: the spill-driven call chain)
inline constexpr std::uint32_t kWorkbenchBoxWorkbenchType = 0x5E1A0C61;
inline constexpr std::uint32_t kWorkbenchBoxSelectedIndex = 0x5E1A0C62;
inline constexpr std::uint32_t kWorkbenchBoxXScroll = 0x5E1A0C63;
inline constexpr std::uint32_t kWorkbenchBoxLevel = 0x5E1A0C64;
inline constexpr std::uint32_t kWorkbenchBoxCraftProgress = 0x5E1A0C65;
inline constexpr std::uint32_t kWorkbenchBoxHurryTimer = 0x5E1A0C66;
inline constexpr std::uint32_t kWorkbenchBoxHurrySeconds = 0x5E1A0C67;
inline constexpr std::uint32_t kWorkbenchBoxHurrying = 0x5E1A0C68;
inline constexpr std::uint32_t kWorkbenchBoxHurryCost = 0x5E1A0C69;
inline constexpr std::uint32_t kWorkbenchBoxFireSpread = 0x5E1A0C6A;
inline constexpr std::uint32_t kWorkbenchBoxFuelFraction = 0x5E1A0C6B;
inline constexpr std::uint32_t kWorkbenchBoxHasFuel = 0x5E1A0C6C;
inline constexpr std::uint32_t kWorkbenchBoxLastWorldTime = 0x5E1A0C6D;
inline constexpr std::uint32_t kWorkbenchBoxIsInUseFuel = 0x5E1A0C6E;
inline constexpr std::uint32_t kWorkbenchBoxAvailableElec = 0x5E1A0C6F;
inline constexpr std::uint32_t kWorkbenchBoxBhIndexFuel = 0x5E1A0C70;
inline constexpr std::uint32_t kWorkbenchBoxCountCreated = 0x5E1A0C71;
inline constexpr std::uint32_t kWorkbenchBoxCountLeft = 0x5E1A0C72;
inline constexpr std::uint32_t kWorkbenchBoxCount = 0x5E1A0C73;
inline constexpr std::uint32_t kWorkbenchBoxCraftableObjectType = 0x5E1A0C74;
inline constexpr std::uint32_t kWorkbenchClusterV2 = 0x5E1A0C10;
inline constexpr std::uint32_t kWorkbenchClusterV1 = 0x5E1A0C20;
inline constexpr std::uint32_t kWorkbenchLightDict = 0x5E1A0C30;
inline constexpr std::uint32_t kWorkbenchSlotArray = 0x5E1A0C40;
inline constexpr std::uint32_t kWorkbenchFreshSlot = 0x5E1A0C50;
inline constexpr std::uint32_t kWorkbenchCraftableResult = 0x5E1A0CB0;
inline constexpr std::uint32_t kWorkbenchLightResult = 0x5E1A0C80;

struct WorkbenchInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    bool super_returns_nil = false;

    std::uint32_t world_argument = 0;
    std::uint32_t dynamic_world_argument = 0;
    std::uint32_t save_dict_token = 0;
    std::uint32_t cache_token = 0;
    std::uint32_t world_ivar = 0;
    std::uint32_t dynamic_world_ivar = 0;
    std::uint32_t cache_ivar = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    std::uint32_t is_in_use_init = 0;      // the super's isInUse side effect

    std::uint32_t workbench_type_value = 0;
    std::uint32_t selected_index_value = 0;
    float x_scroll_value = 0.0f;
    std::uint32_t level_value = 0;
    float craft_progress_value = 0.0f;
    float hurry_timer_value = 0.0f;
    float hurry_seconds_value = 0.0f;
    std::uint32_t hurrying_value = 0;
    std::uint32_t hurry_cost_value = 0;
    float fire_spread_value = 0.0f;
    float fuel_fraction_value = 0.0f;
    std::uint32_t has_fuel_value = 0;
    double last_world_time_value = 0.0;
    std::uint32_t is_in_use_fuel_value = 0;
    std::uint32_t available_elec_value = 0;
    std::int32_t blockhead_index_fuel_value = 0;

    std::uint32_t is_in_use = 0;
    bool crafting_v2_present = false;
    std::uint32_t craftable_object_type = 0;
    bool crafting_v1_present = false;
    bool crafting_item_nonnil = false;    // the alloc+init result
    std::uint32_t craftable_item_stret_type = 0;
    std::vector<std::uint32_t> slot_types;   // the stret struct slot types
    std::uint32_t count_created_value = 0;
    std::uint32_t count_left_value = 0;
    std::uint32_t count_value = 0;
    std::vector<std::uint32_t> slot_elem_counts;  // per-slot sub-item counts
    std::vector<std::uint32_t> sub_types;         // flattened sub-item types

    std::uint32_t current_blockhead = 0;
    std::uint32_t current_fuel_blockhead = 0;
    bool light_dict_present = false;
    std::uint32_t light_answer = 0;
    std::uint32_t sub_page_base = 0;   // the harness's payload-token base
};

struct WorkbenchInitResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<WorkbenchInitCall, std::uint32_t>> calls;
    std::uint32_t return_value = 0;
};

WorkbenchInitResult workbench_init_with_world(const WorkbenchInitInputs& in);

}  // namespace blockheads::recovered
