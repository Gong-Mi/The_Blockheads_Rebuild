// TradingPost full-chain test: static own keys + the executed sellSlot hook
// (counts only; the itemType != 11 filter is stated as not applied).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "tradingpost_full.h"

#include <cassert>
#include <cstdio>
#include <string>

namespace {

const bh176::SaveDict entryOf(const char* plist, bh176::SaveValue& value,
                              std::string& error) {
    assert(bh176::parseXmlPlist(plist, value, &error));
    const bh176::SaveDict dict(value);
    const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
    const bh176::SaveValue* entry = dict.objectAtIndex(objects, 0);
    return bh176::SaveDict(*entry);
}

}  // namespace

int main() {
    bh176::SaveValue value;
    std::string error;

    const char* kPost = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>210</integer><key>pos_x</key><integer>91</integer><key>pos_y</key><integer>519</integer><key>coinCount</key><integer>12</integer><key>priceTier</key><integer>2</integer><key>sellerClientID</key><string>client-9</string><key>sellerClientName</key><string>seller</string><key>sellSlot</key><array><dict><key>itemType</key><integer>1</integer></dict><dict><key>itemType</key><integer>11</integer></dict><dict><key>itemType</key><integer>4</integer></dict></array></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kPost, value, error);
    bh176::TradingPostFullState state;
    bh176::ClientDynamicObject object =
        bh176::tradingpost_full_factory(48, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 48);
    assert(object.class_name == "TradingPost");
    assert(object.unique_id == 210);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("sellSlot") != std::string::npos);
    assert(state.has_coin_count && state.coin_count == 12);
    assert(state.has_price_tier && state.price_tier == 2);
    assert(state.has_seller_client_id);
    assert(state.has_seller_client_name);
    // raw count includes the type-11 item (no decode -> filter not applied)
    assert(state.has_sell_slot);
    assert(state.sell_slot_item_count == 3);
    assert(!state.item_decode_performed);

    // ---- base-only record -------------------------------------------------
    const char* kEmpty = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>211</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kEmpty, value2, error);
    bh176::TradingPostFullState state2;
    bh176::tradingpost_full_factory(48, entry2, &state2, &error);
    assert(!state2.has_coin_count && state2.coin_count == 0);
    assert(!state2.has_sell_slot && state2.sell_slot_item_count == 0);

    std::printf("test_tradingpost_full: PASS\n");
    return 0;
}
