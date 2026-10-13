// Recovered semantics of -[TradingPost initSlotsWithSaveDict:] (batch b4j).
// Original IMP: 0x005E4914, 243 words.
//
// Decoded shape:
//   self->sellSlot = [[NSMutableArray alloc] init];
//   id sellSlotArray = [saveDict objectForKey:@"sellSlot"];
//   if (sellSlotArray != nil) {
//       for (id itemData in sellSlotArray) {
//           InventoryItem* item = [[[InventoryItem alloc] initWithSaveData:itemData] autorelease];
//           if ([item itemType] != 11) {
//               [self->sellSlot addObject:item];
//           }
//       }
//   }
//   self->needsToUpdateBitmapString = true;
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kTradingPostImageSize = 160;
inline constexpr std::size_t kTradingPostMaxTrace = 128;

inline constexpr std::uint32_t kSellSlotArrayToken = 0x5E115107u;

struct TradingPostSlotItemEntry {
    std::uint32_t item_data_token = 0;
    std::uint32_t item_type = 0;
};

struct TradingPostInitSlotsInputs {
    std::uint32_t self_ptr = 0x60000000u;
    std::uint32_t sell_slot_array_token = kSellSlotArrayToken;
    bool has_sell_slot_key = true;
    std::vector<TradingPostSlotItemEntry> items;
};

struct TradingPostInitSlotsResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<TradingPostInitSlotsCall, std::uint32_t>> calls;
    std::vector<std::uint32_t> added_items;
};

TradingPostInitSlotsResult trading_post_init_slots_with_save_dict(
    const TradingPostInitSlotsInputs& in);

}  // namespace blockheads::recovered
