// Recovered semantics of -[TradePortal loadPriceOffsets:] (batch b4i).
// Original IMP: 0x00D37A78, 197 words.
//
// Decoded shape:
//   for (id key in sourceDict) {
//       id val = [sourceDict objectForKey:key];
//       double d = [val doubleValue];
//       // Clamp to [0.5, 2.0] with ARM VFP branch semantics
//       if (d < 0.5) d = 0.5;
//       else if (d > 2.0) d = 2.0;
//       id num = [NSNumber numberWithDouble:d];
//       [self->localPriceOffsets setObject:num forKey:key];
//   }
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kTradePortalImageSize = 160;
inline constexpr std::size_t kTradePortalMaxTrace = 64;

inline constexpr std::uint32_t kLocalPriceOffsetsDictToken = 0xD1C70001u;

struct PriceOffsetEntry {
    std::string key;
    std::uint32_t key_token = 0;
    double raw_value = 1.0;
};

struct TradePortalPriceOffsetsInputs {
    std::uint32_t self_ptr = 0x60000000u;
    std::uint32_t local_price_offsets_token = kLocalPriceOffsetsDictToken;
    std::vector<PriceOffsetEntry> entries;
};

struct TradePortalPriceOffsetsResult {
    std::vector<std::uint8_t> image;
    std::vector<std::pair<TradePortalPriceOffsetsCall, std::uint32_t>> calls;
    std::vector<std::pair<std::uint32_t, double>> clamped_entries;
};

double clamp_price_offset(double val);

TradePortalPriceOffsetsResult trade_portal_load_price_offsets(
    const TradePortalPriceOffsetsInputs& in);

}  // namespace blockheads::recovered
