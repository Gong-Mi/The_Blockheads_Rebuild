// Optional ARM differential bridge: exposes the recovered TradePortal
// loadPriceOffsets: contract to tools/test_trade_portal_price_offsets_arm.py,
// which executes the ORIGINAL ARM method under Unicorn and compares the
// instance image and message trace byte-for-byte against this module
// (built at -O0 and -O2).
#include "trade_portal_price_offsets.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::TradePortalPriceOffsetsCall;
using blockheads::recovered::TradePortalPriceOffsetsInputs;
using blockheads::recovered::PriceOffsetEntry;

extern "C" {

std::uint32_t recovered_trade_portal_price_offsets_run(
    std::uint32_t self_ptr,
    std::uint32_t local_price_offsets_token,
    std::uint32_t count,
    const std::uint32_t* key_tokens,
    const double* raw_values,
    std::uint8_t* image_out,
    std::uint8_t* trace_out) {
    TradePortalPriceOffsetsInputs in;
    in.self_ptr = self_ptr;
    in.local_price_offsets_token = local_price_offsets_token;
    for (std::uint32_t i = 0; i < count; ++i) {
        PriceOffsetEntry e;
        e.key_token = key_tokens[i];
        e.raw_value = raw_values[i];
        in.entries.push_back(e);
    }

    const auto res = blockheads::recovered::trade_portal_load_price_offsets(in);
    for (std::size_t i = 0; i < blockheads::recovered::kTradePortalImageSize; ++i) {
        image_out[i] = res.image[i];
    }
    const std::uint32_t n =
        res.calls.size() > blockheads::recovered::kTradePortalMaxTrace
            ? blockheads::recovered::kTradePortalMaxTrace
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
