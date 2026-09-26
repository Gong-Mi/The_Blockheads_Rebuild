#include "trading_post_init_slots.h"

namespace blockheads::recovered {

namespace {

void store_word(std::vector<std::uint8_t>& image, std::size_t offset, std::uint32_t val) {
    if (offset + 4 <= image.size()) {
        image[offset + 0] = static_cast<std::uint8_t>(val & 0xff);
        image[offset + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
        image[offset + 2] = static_cast<std::uint8_t>((val >> 16) & 0xff);
        image[offset + 3] = static_cast<std::uint8_t>((val >> 24) & 0xff);
    }
}

void store_byte(std::vector<std::uint8_t>& image, std::size_t offset, std::uint8_t val) {
    if (offset < image.size()) {
        image[offset] = val;
    }
}

}  // namespace

TradingPostInitSlotsResult trading_post_init_slots_with_save_dict(
    const TradingPostInitSlotsInputs& in) {
    TradingPostInitSlotsResult result;
    result.image.assign(kTradingPostImageSize, 0);

    // 1. [NSMutableArray alloc] -> [init] -> self->sellSlot = token (ivar offset 100)
    result.calls.emplace_back(TradingPostInitSlotsCall::AllocNSMutableArray, in.sell_slot_array_token);
    result.calls.emplace_back(TradingPostInitSlotsCall::InitNSMutableArray, in.sell_slot_array_token);
    store_word(result.image, 100, in.sell_slot_array_token);

    // 2. [saveDict objectForKey:@"sellSlot"]
    result.calls.emplace_back(TradingPostInitSlotsCall::ObjectForKey, in.has_sell_slot_key ? in.sell_slot_array_token : 0);

    if (in.has_sell_slot_key) {
        std::size_t total = in.items.size();
        std::size_t idx = 0;

        while (idx < total) {
            std::size_t batch = (total - idx > 16) ? 16 : (total - idx);
            result.calls.emplace_back(TradingPostInitSlotsCall::FastEnumeration, static_cast<std::uint32_t>(batch));

            for (std::size_t i = 0; i < batch; ++i) {
                const auto& item_entry = in.items[idx + i];
                // [InventoryItem alloc]
                result.calls.emplace_back(TradingPostInitSlotsCall::AllocInventoryItem, item_entry.item_data_token);
                // [item initWithSaveData:itemData]
                result.calls.emplace_back(TradingPostInitSlotsCall::InitWithSaveData, item_entry.item_data_token);
                // [item autorelease]
                result.calls.emplace_back(TradingPostInitSlotsCall::AutoreleaseItem, item_entry.item_data_token);
                // [item itemType]
                result.calls.emplace_back(TradingPostInitSlotsCall::ItemType, item_entry.item_type);

                // Filter: itemType == 11 (0xb) is skipped!
                if (item_entry.item_type != 11) {
                    result.calls.emplace_back(TradingPostInitSlotsCall::AddObject, item_entry.item_data_token);
                    result.added_items.push_back(item_entry.item_data_token);
                }
            }
            idx += batch;
        }

        // Terminal fast enumeration call returns 0
        result.calls.emplace_back(TradingPostInitSlotsCall::FastEnumeration, 0);
    }

    // 3. Epilogue: self->needsToUpdateBitmapString = true (offset 124)
    store_byte(result.image, 124, 1);

    return result;
}

}  // namespace blockheads::recovered
