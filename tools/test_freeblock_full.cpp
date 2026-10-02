// FreeBlock full-chain test: the b4p executed save surface through the
// production factory, with the stated boundaries (no item decode, no world
// tail) reported rather than blurred.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "freeblock_full.h"

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

    // ---- full record ------------------------------------------------------
    const char* kFreeRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>190</integer><key>pos_x</key><integer>87</integer><key>pos_y</key><integer>518</integer><key>floatPos</key><array><real>87.5</real><real>518.0</real></array><key>bounceTimer</key><real>0.1</real><key>fallSpeed</key><real>0.2</real><key>creationTime</key><real>100.0</real><key>floatPos[VX]</key><real>87.5</real><key>floatPos[VY]</key><real>518.0</real><key>hovers</key><true/><key>itemType</key><integer>3</integer><key>dataA</key><integer>1</integer><key>dataB</key><integer>2</integer><key>subItems</key><array><array><dict><key>itemType</key><integer>1</integer></dict><dict><key>itemType</key><integer>11</integer></dict></array><array></array></array><key>dynamicObjectSaveDict</key><dict><key>seed</key><integer>1</integer></dict><key>priorityBlockheadUinqueID</key><integer>0</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kFreeRecord, value, error);
    bh176::FreeBlockFullState state;
    bh176::ClientDynamicObject object =
        bh176::freeblock_full_factory(14, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 14);
    assert(object.class_name == "FreeBlock");
    assert(object.unique_id == 190);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("b4p") != std::string::npos);
    assert(object.status_reason.find("not performed") != std::string::npos);
    assert(state.has_bounce_timer && state.bounce_timer > 0.099f &&
           state.bounce_timer < 0.101f);
    assert(state.has_fall_speed && state.fall_speed > 0.199f &&
           state.fall_speed < 0.201f);
    assert(state.has_creation_time && state.creation_time == 100.0);
    assert(state.has_float_pos_vx && state.has_float_pos_vy);
    assert(state.float_pos_vx == 87.5f && state.float_pos_vy == 518.0f);
    assert(state.has_hovers && state.hovers);
    assert(state.has_item_type && state.item_type == 3);
    assert(state.has_data_a && state.data_a == 1);
    assert(state.has_data_b && state.data_b == 2);
    // subItems: raw counts (the type-11 item is INCLUDED — no decode/filter)
    assert(state.has_sub_items && state.sub_slot_count == 2);
    assert(state.sub_slot_item_counts[0] == 2);
    assert(state.sub_slot_item_counts[1] == 0);
    assert(!state.item_decode_performed);
    assert(state.has_dynamic_object_save_dict);
    assert(state.has_priority_blockhead_id && state.priority_blockhead_id == 0);
    assert(state.world_tail_not_run);

    // ---- strh truncation control on dataA ---------------------------------
    const char* kBigData = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>191</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>dataA</key><integer>70000</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kBigData, value2, error);
    bh176::FreeBlockFullState state2;
    bh176::freeblock_full_factory(14, entry2, &state2, &error);
    assert(state2.data_a == 4464);  // 70000 through the strh store

    // ---- base-only record: all gates closed -------------------------------
    const char* kEmpty = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>192</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>3</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict entry3 = entryOf(kEmpty, value3, error);
    bh176::FreeBlockFullState state3;
    bh176::freeblock_full_factory(14, entry3, &state3, &error);
    assert(!state3.has_item_type && state3.item_type == 0);
    assert(!state3.has_sub_items && state3.sub_slot_count == 0);
    assert(!state3.has_hovers);

    std::printf("test_freeblock_full: PASS\n");
    return 0;
}
