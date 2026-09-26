#include "trade_portal_price_offsets.h"

#include <cassert>
#include <cmath>
#include <iostream>

using blockheads::recovered::TradePortalPriceOffsetsCall;
using blockheads::recovered::TradePortalPriceOffsetsInputs;
using blockheads::recovered::PriceOffsetEntry;
using blockheads::recovered::trade_portal_load_price_offsets;
using blockheads::recovered::clamp_price_offset;

int main() {
    // 1. Clamping function unit tests
    assert(clamp_price_offset(0.1) == 0.5);
    assert(clamp_price_offset(0.49999) == 0.5);
    assert(clamp_price_offset(0.5) == 0.5);
    assert(clamp_price_offset(1.0) == 1.0);
    assert(clamp_price_offset(1.75) == 1.75);
    assert(clamp_price_offset(2.0) == 2.0);
    assert(clamp_price_offset(2.0001) == 2.0);
    assert(clamp_price_offset(100.0) == 2.0);
    assert(clamp_price_offset(-5.0) == 0.5);
    assert(std::isnan(clamp_price_offset(NAN)));

    // 2. Multi-entry contract test
    {
        TradePortalPriceOffsetsInputs in;
        in.self_ptr = 0x60000000u;
        in.local_price_offsets_token = 0xD1C70001u;

        PriceOffsetEntry e1{"itemA", 0xA1, 0.2};   // clamped to 0.5
        PriceOffsetEntry e2{"itemB", 0xA2, 1.25};  // preserved 1.25
        PriceOffsetEntry e3{"itemC", 0xA3, 5.0};   // clamped to 2.0
        in.entries = {e1, e2, e3};

        auto res = trade_portal_load_price_offsets(in);
        // FastEnumeration(3) -> for each: (ObjectForKey, DoubleValue, NumberWithDouble, SetObjectForKey) -> FastEnumeration(0)
        // 1 + 3 * 4 + 1 = 14 calls
        assert(res.calls.size() == 14);
        assert(res.calls[0].first == TradePortalPriceOffsetsCall::FastEnumeration);
        assert(res.calls[0].second == 3);

        assert(res.clamped_entries.size() == 3);
        assert(res.clamped_entries[0].second == 0.5);
        assert(res.clamped_entries[1].second == 1.25);
        assert(res.clamped_entries[2].second == 2.0);

        assert(res.calls.back().first == TradePortalPriceOffsetsCall::FastEnumeration);
        assert(res.calls.back().second == 0);
    }

    // 3. Empty dictionary test
    {
        TradePortalPriceOffsetsInputs in;
        auto res = trade_portal_load_price_offsets(in);
        assert(res.calls.size() == 1);
        assert(res.calls[0].first == TradePortalPriceOffsetsCall::FastEnumeration);
        assert(res.calls[0].second == 0);
    }

    std::cout << "test_trade_portal_price_offsets: PASS\n";
    return 0;
}
