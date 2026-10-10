#include "trading_post_init_slots.h"

#include <cassert>
#include <iostream>

using blockheads::recovered::TradingPostInitSlotsCall;
using blockheads::recovered::TradingPostInitSlotsInputs;
using blockheads::recovered::TradingPostSlotItemEntry;
using blockheads::recovered::trading_post_init_slots_with_save_dict;

int main() {
    // 1. Missing sellSlot key: allocates NSMutableArray and sets needsToUpdateBitmapString, skips loop
    {
        TradingPostInitSlotsInputs in;
        in.self_ptr = 0x60000000u;
        in.has_sell_slot_key = false;

        auto res = trading_post_init_slots_with_save_dict(in);
        // AllocNSMutableArray, InitNSMutableArray, ObjectForKey
        assert(res.calls.size() == 3);
        assert(res.calls[0].first == TradingPostInitSlotsCall::AllocNSMutableArray);
        assert(res.calls[1].first == TradingPostInitSlotsCall::InitNSMutableArray);
        assert(res.calls[2].first == TradingPostInitSlotsCall::ObjectForKey);
        assert(res.calls[2].second == 0);

        // sellSlot ivar at 100
        std::uint32_t sellSlot_val = *reinterpret_cast<const std::uint32_t*>(&res.image[100]);
        assert(sellSlot_val == in.sell_slot_array_token);

        // needsToUpdateBitmapString ivar at 124
        assert(res.image[124] == 1);
        assert(res.added_items.empty());
    }

    // 2. Empty sellSlot array
    {
        TradingPostInitSlotsInputs in;
        in.has_sell_slot_key = true;
        in.items = {};

        auto res = trading_post_init_slots_with_save_dict(in);
        // Alloc, Init, OFK, FastEnumeration(0)
        assert(res.calls.size() == 4);
        assert(res.calls[3].first == TradingPostInitSlotsCall::FastEnumeration);
        assert(res.calls[3].second == 0);
        assert(res.image[124] == 1);
        assert(res.added_items.empty());
    }

    // 3. Multi-item array with itemType == 11 filtering
    {
        TradingPostInitSlotsInputs in;
        in.has_sell_slot_key = true;

        TradingPostSlotItemEntry e1{0x8001, 1};   // added
        TradingPostSlotItemEntry e2{0x8002, 11};  // filtered out (itemType == 11)
        TradingPostSlotItemEntry e3{0x8003, 42};  // added
        in.items = {e1, e2, e3};

        auto res = trading_post_init_slots_with_save_dict(in);
        assert(res.added_items.size() == 2);
        assert(res.added_items[0] == 0x8001);
        assert(res.added_items[1] == 0x8003);

        assert(res.image[124] == 1);
    }

    std::cout << "test_trading_post_init_slots: PASS\n";
    return 0;
}
