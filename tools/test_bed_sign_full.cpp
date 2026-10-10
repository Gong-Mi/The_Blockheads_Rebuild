// Bed / Sign full-chain test: executed InteractionObject super + the
// listing-decoded own keys (incl. Bed's strh beddingColor and the
// itemType == 0 -> 63 default).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "bed_sign_full.h"

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

    // ---- Bed: itemType word, beddingColor STRH, no default ----------------
    const char* kBed = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>230</integer><key>pos_x</key><integer>94</integer><key>pos_y</key><integer>521</integer><key>isInUse</key><true/><key>itemType</key><integer>2</integer><key>beddingColor</key><integer>70000</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict bed = entryOf(kBed, value, error);
    bh176::BedSignFullState state;
    bh176::ClientDynamicObject object =
        bh176::bed_sign_full_factory(23, bed, &state, &error);
    assert(error.empty());
    assert(object.class_name == "Bed");
    assert(object.unique_id == 230);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("beddingColor@104-strh") != std::string::npos);
    assert(state.item_type == 2);
    assert(!state.item_type_defaulted);
    assert(state.bedding_color == 4464);  // 70000 through the STRH store
    assert(state.is_in_use);              // the executed super chain ran

    // ---- Bed: the itemType == 0 -> 63 default -----------------------------
    const char* kBedZero = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>231</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>itemType</key><integer>0</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict bed2 = entryOf(kBedZero, value2, error);
    bh176::BedSignFullState state2;
    bh176::bed_sign_full_factory(23, bed2, &state2, &error);
    assert(state2.item_type == 63);
    assert(state2.item_type_defaulted);

    // ---- Sign: text retained slot + the two ints --------------------------
    const char* kSign = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>232</integer><key>pos_x</key><integer>95</integer><key>pos_y</key><integer>521</integer><key>text</key><string>hello</string><key>connectionType</key><integer>3</integer><key>offsetType</key><integer>1</integer><key>flipped</key><true/></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict sign = entryOf(kSign, value3, error);
    bh176::BedSignFullState state3;
    bh176::ClientDynamicObject object3 =
        bh176::bed_sign_full_factory(47, sign, &state3, &error);
    assert(object3.class_name == "Sign");
    assert(object3.status == bh176::ObjectLoadStatus::Recovered);
    assert(state3.has_text);
    assert(state3.connection_type == 3);
    assert(state3.offset_type == 1);
    assert(state3.flipped);   // the executed super chain

    // ---- Sign without text: the retained slot stays nil -------------------
    bh176::SaveValue value4;
    const bh176::SaveDict sign_no_text = entryOf(kBed, value4, error);
    bh176::BedSignFullState state4;
    bh176::bed_sign_full_factory(47, sign_no_text, &state4, &error);
    assert(!state4.has_text);
    assert(state4.connection_type == 0 && state4.offset_type == 0);

    std::printf("test_bed_sign_full: PASS\n");
    return 0;
}
