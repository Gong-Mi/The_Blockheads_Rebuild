// Recovered semantics of -[Chest initWithWorld:dynamicWorld:saveDict:cache:]
// (batch b4m, read-back line). Original IMP: 0x00CB627C, 760 words,
// runtime superclass InteractionObject, exact selector variant.
//
// Decoded shape (see reconstruction/reverse-v3/native/CHEST_INIT_ARM.md):
//   self = [super initWithWorld:world dynamicWorld:dynamicWorld
//                      saveDict:saveDict cache:cache];
//   if (self == nil) return nil;
//   self->chestType = [[saveDict objectForKey:@"chestType"] intValue];
//   if (self->chestType == 4) {
//       Rules r;                                  // 64-byte struct by value
//       if (self->world) objc_msgSend_stret(&r, self->world, @selector(customRules));
//       else memset(&r, 0, 0x40);                 // nil world -> zero-filled
//       if (r.byte0 != 0) self->chestType = 0;    // gate, then the field is RE-READ
//   }
//   if (self->ownerID == nil) {
//       self->ownerID = [[saveDict objectForKey:@"safeClientID"] retain];
//   }
//   if (self->chestType == 4) {                   // re-read after the gate above
//       self->inventoryItems = nil;
//   } else {
//       id slots = [saveDict objectForKey:@"saveItemSlots"];
//       if (slots != nil) {
//           [dynamicWorld dynamicWorldChangedAtPos:self->pos
//                                        objectType:[self objectType]];
//           NSMutableArray* arr = [[NSMutableArray alloc] initWithCapacity:
//                                   numberOfSlots(self->chestType)];
//           self->inventoryItems = arr;
//           if ([slots count] >= numberOfSlots(self->chestType)) {
//               for (NSUInteger i = 0; i < numberOfSlots(self->chestType); ++i) {
//                   NSMutableArray* slot = [NSMutableArray array];
//                   [self->inventoryItems addObject:slot];
//                   NSArray* slotData = [slots objectAtIndex:i];
//                   for (id itemData in slotData) {           // 16-wide batches
//                       InventoryItem* item =
//                           [[InventoryItem alloc] initWithSaveData:itemData];
//                       [item autorelease];
//                       if ([item itemType] != 11) [slot addObject:item];
//                   }
//               }
//           } else {
//               for (NSUInteger k = 0; k < numberOfSlots(self->chestType); ++k) {
//                   [self->inventoryItems addObject:[NSMutableArray array]];
//               }
//           }
//       }
//   }
//   if (self->inventoryItems == nil) {            // nil slots OR chestType == 4
//       for (NSUInteger m = 0; m < 4; ++m) {
//           self->shelfRenderItems[m] =
//               [[saveDict objectForKey:[NSString stringWithFormat:@"shelfRenderItems_%d", m]] intValue];
//           self->shelfItemDataBs[m] = (uint16_t)[[saveDict
//               objectForKey:[NSString stringWithFormat:@"shelfItemDataBs_%d", m]] intValue];
//       }
//   }
//   [self initSubDerivedItems];
//   return self;
//
// SLOT CAPACITY RULE (private helper 0x00CB623C, four call sites):
//   numberOfSlots(chestType) = (chestType == 2 || chestType == 5) ? 4 : 16
//
// The original body is the only method of the initWithWorld front with a
// __stack_chk_guard canary (GOT slot 0x0105B7E0, fail path 0x001C28B8).
#pragma once

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

// Chest class_ro_t instance_size == 0x8C == 140: the last restored field is
// shelfItemDataBs at 132 with four uint16 records, so 132 + 4 * 2 == 140 —
// the whole instance image is compared byte for byte.
inline constexpr std::size_t kChestImageSize = 140;
inline constexpr std::size_t kChestMaxTrace = 1024;

// Fixture token conventions shared by the ARM harness and this contract.
inline constexpr std::uint32_t kChestInventoryArrayToken = 0x5E1C0401u;
inline constexpr std::uint32_t kChestSlotArrayBase = 0x5E1C1000u;
inline constexpr std::uint32_t kChestShelfRenderBoxBase = 0x5E1C1A00u;
inline constexpr std::uint32_t kChestShelfItemDataBoxBase = 0x5E1C1B00u;

// Instance offsets (resolved through the PIC ivar-offset cells).
inline constexpr std::uint32_t kChestOffsetWorld = 4;            // DynamicObject.world
inline constexpr std::uint32_t kChestOffsetDynamicWorld = 8;     // DynamicObject.dynamicWorld
inline constexpr std::uint32_t kChestOffsetPosX = 16;            // DynamicObject.pos.x
inline constexpr std::uint32_t kChestOffsetPosY = 20;            // DynamicObject.pos.y
inline constexpr std::uint32_t kChestOffsetOwnerID = 36;         // DynamicObject.ownerID
inline constexpr std::uint32_t kChestOffsetInventoryItems = 100; // Chest.inventoryItems
inline constexpr std::uint32_t kChestOffsetChestType = 108;      // Chest.chestType
inline constexpr std::uint32_t kChestOffsetShelfRenderItems = 116;
inline constexpr std::uint32_t kChestOffsetShelfItemDataBs = 132;
inline constexpr std::uint32_t kChestShelfSlotCount = 4;
inline constexpr std::uint32_t kChestFastEnumerationBatch = 16;

// The decoded private helper 0x00CB623C.
int chest_slot_capacity(std::int32_t chest_type);

struct ChestSlotItemEntry {
    std::uint32_t item_token = 0;
    std::uint32_t item_type = 0;
};

struct ChestSlotEntry {
    std::vector<ChestSlotItemEntry> items;
};

struct ChestInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    bool super_returns_nil = false;

    // Method arguments (r2 / r3 / [sp] / [sp+4]) — deliberately distinct from
    // the instance ivars so a wrongly-forwarded argument cannot pass.
    std::uint32_t world_argument = 0;
    std::uint32_t dynamic_world_argument = 0;
    std::uint32_t save_dict_token = 0x60010000u;
    std::uint32_t cache_token = 0;

    // Instance ivars as staged in the fixture image before the call.
    std::uint32_t world_ivar = 0;
    std::uint32_t dynamic_world_ivar = 0;
    std::uint32_t pos_x = 0;
    std::uint32_t pos_y = 0;
    std::uint32_t owner_id_ivar = 0;

    // saveDict surface.
    bool has_chest_type_key = true;
    std::uint32_t chest_type_box_token = 0;
    std::int32_t chest_type_value = 0;
    std::int32_t rules_byte0 = 0;          // [world customRules] struct byte 0
    std::uint32_t safe_client_id_token = 0;
    std::uint32_t object_type_value = 0;
    std::uint32_t slots_array_token = 0;   // 0 == key missing / nil
    std::vector<ChestSlotEntry> slots;

    std::array<std::uint32_t, kChestShelfSlotCount> shelf_render_box_tokens{};
    std::array<std::uint32_t, kChestShelfSlotCount> shelf_render_values{};
    std::array<std::uint32_t, kChestShelfSlotCount> shelf_item_data_box_tokens{};
    std::array<std::uint32_t, kChestShelfSlotCount> shelf_item_data_values{};

    // Enumeration-mutation fixture: the mutation counter is bumped while the
    // designated element is constructed, so the NEXT element of the same
    // batch observes the change (the per-batch capture resets it after).
    int mutate_slot = -1;
    int mutate_item = -1;
};

struct ChestInitResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<ChestInitCall, std::uint32_t>> calls;
    std::uint32_t return_value = 0;
};

ChestInitResult chest_init_with_world(const ChestInitInputs& in);

}  // namespace blockheads::recovered
