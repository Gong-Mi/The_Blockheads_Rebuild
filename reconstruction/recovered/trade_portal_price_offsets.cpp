#include "trade_portal_price_offsets.h"

#include <cmath>
#include <cstring>

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

}  // namespace

double clamp_price_offset(double val) {
    // Matches the ARM32 VFP vcmpe / bpl / ble sequence at 0xd37c0c..0xd37c3c:
    // val < 0.5 -> 0.5
    // val > 2.0 -> 2.0
    // NaN has N=0, V=1 -> bpl taken, ble taken -> NaN preserved
    if (std::isnan(val)) {
        return val;
    }
    if (val < 0.5) {
        return 0.5;
    }
    if (val > 2.0) {
        return 2.0;
    }
    return val;
}

TradePortalPriceOffsetsResult trade_portal_load_price_offsets(
    const TradePortalPriceOffsetsInputs& in) {
    TradePortalPriceOffsetsResult result;
    result.image.assign(kTradePortalImageSize, 0);

    // Initial state: self->localPriceOffsets at offset 128
    store_word(result.image, 128, in.local_price_offsets_token);

    std::size_t total = in.entries.size();
    std::size_t idx = 0;

    // Fast enumeration loop in batches of up to 16
    while (idx < total) {
        std::size_t batch = (total - idx > 16) ? 16 : (total - idx);
        result.calls.emplace_back(TradePortalPriceOffsetsCall::FastEnumeration,
                                  static_cast<std::uint32_t>(batch));

        for (std::size_t i = 0; i < batch; ++i) {
            const auto& entry = in.entries[idx + i];
            result.calls.emplace_back(TradePortalPriceOffsetsCall::ObjectForKey,
                                      entry.key_token);
            result.calls.emplace_back(TradePortalPriceOffsetsCall::DoubleValue,
                                      entry.key_token);

            double clamped = clamp_price_offset(entry.raw_value);
            std::uint64_t dbits;
            std::memcpy(&dbits, &clamped, 8);
            result.calls.emplace_back(TradePortalPriceOffsetsCall::NumberWithDouble,
                                      static_cast<std::uint32_t>(dbits & 0xffffffffu));
            result.calls.emplace_back(TradePortalPriceOffsetsCall::SetObjectForKey,
                                      entry.key_token);
            result.clamped_entries.emplace_back(entry.key_token, clamped);
        }
        idx += batch;
    }

    // Terminal fast enumeration call returns 0
    result.calls.emplace_back(TradePortalPriceOffsetsCall::FastEnumeration, 0);

    return result;
}

}  // namespace blockheads::recovered
