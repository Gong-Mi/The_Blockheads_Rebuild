#include "trading_post_init_slots.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::TradingPostInitSlotsCall;
using blockheads::recovered::TradingPostInitSlotsInputs;
using blockheads::recovered::TradingPostSlotItemEntry;

extern "C" {

std::uint32_t recovered_trading_post_init_slots_run(
    std::uint32_t self_ptr,
    std::uint32_t sell_slot_array_token,
    std::uint32_t has_sell_slot_key,
    std::uint32_t count,
    const std::uint32_t* item_tokens,
    const std::uint32_t* item_types,
    std::uint8_t* image_out,
    std::uint8_t* trace_out) {
    TradingPostInitSlotsInputs in;
    in.self_ptr = self_ptr;
    in.sell_slot_array_token = sell_slot_array_token;
    in.has_sell_slot_key = (has_sell_slot_key != 0);

    for (std::uint32_t i = 0; i < count; ++i) {
        TradingPostSlotItemEntry e;
        e.item_data_token = item_tokens[i];
        e.item_type = item_types[i];
        in.items.push_back(e);
    }

    const auto res = blockheads::recovered::trading_post_init_slots_with_save_dict(in);
    for (std::size_t i = 0; i < blockheads::recovered::kTradingPostImageSize; ++i) {
        image_out[i] = res.image[i];
    }

    const std::uint32_t n =
        res.calls.size() > blockheads::recovered::kTradingPostMaxTrace
            ? blockheads::recovered::kTradingPostMaxTrace
            : static_cast<std::uint32_t>(res.calls.size());
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint8_t* rec = trace_out + i * 8;
        rec[0] = static_cast<std::uint8_t>(res.calls[i].first);
        rec[1] = rec[2] = rec[3] = 0;
        const std::uint32_t arg = res.calls[i].second;
        rec[4] = static_cast<std::uint8_t>(arg & 0xff);
        rec[5] = static_cast<std::uint8_t>((arg >> 8) & 0xff);
        rec[6] = static_cast<std::uint8_t>((arg >> 16) & 0xff);
        rec[7] = static_cast<std::uint8_t>((arg >> 24) & 0xff);
    }
    return n;
}

}  // extern "C"
