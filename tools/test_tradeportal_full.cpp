// TradePortal full-chain test: static own keys + the executed b4i clamp
// hook through the production factory.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "tradeportal_full.h"

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

    // ---- full record: level + lightDict + localPriceOffsets --------------
    const char* kPortal = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>200</integer><key>pos_x</key><integer>89</integer><key>pos_y</key><integer>519</integer><key>floatPos</key><array><real>89.5</real><real>519.0</real></array><key>level</key><integer>1</integer><key>lightDict</key><dict><key>radius</key><integer>5</integer></dict><key>localPriceOffsets</key><dict><key>wood</key><real>0.25</real><key>stone</key><real>3.5</real><key>iron</key><real>1.0</real></dict></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kPortal, value, error);
    bh176::TradePortalFullState state;
    bh176::ClientDynamicObject object =
        bh176::tradeportal_full_factory(50, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 50);
    assert(object.class_name == "TradePortal");
    assert(object.unique_id == 200);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("b4i") != std::string::npos);
    assert(state.has_level && state.level == 1);
    assert(state.light_present);
    // raw + clamped (executed b4i semantics: [0.5, 2.0]); the SaveDict map
    // iterates in key order: iron, stone, wood
    assert(state.has_local_price_offsets);
    assert(state.price_offsets_raw.size() == 3);
    assert(state.price_offsets_clamped.size() == 3);
    assert(state.price_offsets_raw[0].first == "iron");
    assert(state.price_offsets_raw[0].second == 1.0);      // untouched
    assert(state.price_offsets_clamped[0].second == 1.0);
    assert(state.price_offsets_raw[1].first == "stone");
    assert(state.price_offsets_raw[1].second == 3.5);
    assert(state.price_offsets_clamped[1].second == 2.0);  // clamped down
    assert(state.price_offsets_raw[2].first == "wood");
    assert(state.price_offsets_raw[2].second == 0.25);
    assert(state.price_offsets_clamped[2].second == 0.5);  // clamped up

    // ---- base-only record -------------------------------------------------
    const char* kEmpty = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>201</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kEmpty, value2, error);
    bh176::TradePortalFullState state2;
    bh176::tradeportal_full_factory(50, entry2, &state2, &error);
    assert(!state2.has_level);
    assert(!state2.light_present);
    assert(!state2.has_local_price_offsets);
    assert(state2.price_offsets_raw.empty());

    std::printf("test_tradeportal_full: PASS\n");
    return 0;
}
