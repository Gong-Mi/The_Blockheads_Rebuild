// Painting / OwnershipSign full-chain test.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "ownershipsign_full.h"
#include "painting_full.h"

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

    // ---- Painting 52 ------------------------------------------------------
    const char* kPainting = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>272</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>itemType</key><integer>9</integer><key>ownerID</key><string>c</string><key>ownerName</key><string>bob</string><key>hasVerifiedImageData</key><true/><key>outputImageData</key><string>blob</string></dict>
</array></dict></plist>
)";
    const bh176::SaveDict painting = entryOf(kPainting, value, error);
    bh176::PaintingFullState state;
    bh176::ClientDynamicObject object =
        bh176::painting_full_factory(52, painting, &state, &error);
    assert(error.empty());
    assert(object.class_name == "Painting");
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("outputImageData@60") != std::string::npos);
    assert(state.has_item_type && state.item_type == 9);
    assert(state.has_owner_id);
    assert(state.has_owner_name);
    assert(state.has_verified_image_data && state.verified_image_data);
    assert(state.has_image_data);
    assert(!state.hidden_due_to_server_ban);  // world ban check not run
    assert(state.world_steps_not_run);

    // ---- OwnershipSign 60 -------------------------------------------------
    const char* kSign = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>273</integer><key>pos_x</key><integer>3</integer><key>pos_y</key><integer>4</integer><key>text</key><string>mine</string><key>connectionType</key><integer>1</integer><key>offsetType</key><integer>2</integer><key>landOwnerID</key><string>c</string><key>landOwnerName</key><string>bob</string><key>w</key><integer>5</integer><key>h</key><integer>6</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict sign = entryOf(kSign, value2, error);
    bh176::OwnershipSignFullState state2;
    bh176::ClientDynamicObject object2 =
        bh176::ownershipsign_full_factory(60, sign, &state2, &error);
    assert(error.empty());
    assert(object2.class_name == "OwnershipSign");
    assert(object2.status == bh176::ObjectLoadStatus::Recovered);
    assert(object2.status_reason.find("landOwnerID@124") != std::string::npos);
    // the Sign chain ran (text/connectionType/offsetType)
    assert(state2.has_text);
    assert(state2.connection_type == 1 && state2.offset_type == 2);
    // the four own keys
    assert(state2.has_land_owner_id && state2.has_land_owner_name);
    assert(state2.has_w && state2.width_radius == 5);
    assert(state2.has_h && state2.height_radius == 6);
    assert(state2.tail_hook == "updateText");

    // ---- base-only control -------------------------------------------------
    const char* kEmpty = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>274</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict empty = entryOf(kEmpty, value3, error);
    bh176::OwnershipSignFullState state3;
    bh176::ownershipsign_full_factory(60, empty, &state3, &error);
    assert(!state3.has_text && !state3.has_w && !state3.has_h);
    // the body's DEFAULT radius is 15 (ARM-attested), not 0
    assert(state3.width_radius == 15 && state3.height_radius == 15);

    // ---- ARM-attested semantics: clamp + the ID gate ---------------------
    {
        // a present radius clamps into [1, 30]; a tiny one clamps up to 1
        bh176::SaveValue value4;
        const bh176::SaveDict clamped = entryOf(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>275</integer><key>pos_x</key><integer>3</integer><key>pos_y</key><integer>4</integer><key>landOwnerID</key><string>o</string><key>w</key><integer>70000</integer><key>h</key><integer>0</integer></dict>
</array></dict></plist>
)", value4, error);
        bh176::OwnershipSignFullState state4;
        bh176::ownershipsign_full_factory(60, clamped, &state4, &error);
        assert(state4.has_w && state4.width_radius == 30);   // clamped down
        assert(state4.has_h && state4.height_radius == 1);   // clamped up (0 -> 1)
    }
    {
        // with a nil landOwnerID the body never reads landOwnerName: the
        // record may carry a name, the loader must not claim it
        bh176::SaveValue value5;
        const bh176::SaveDict gated = entryOf(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>276</integer><key>pos_x</key><integer>5</integer><key>pos_y</key><integer>6</integer><key>landOwnerName</key><string>n</string><key>w</key><integer>7</integer></dict>
</array></dict></plist>
)", value5, error);
        bh176::OwnershipSignFullState state5;
        bh176::ownershipsign_full_factory(60, gated, &state5, &error);
        assert(!state5.has_land_owner_id);
        assert(!state5.has_land_owner_name);   // gated off despite the record
        assert(state5.has_w && state5.width_radius == 7);
    }

    std::printf("test_painting_sign_full: PASS\n");
    return 0;
}
