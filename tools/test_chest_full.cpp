// Chest full-chain test: the b4m executed surface through the production
// factory (chestType / safeClientID / saveItemSlots counts / shelf_0..3),
// with the stated boundaries reported rather than blurred.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "chest_full.h"

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

    // ---- full record: chestType + safeClientID + slots + shelves ---------
    const char* kChestRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>180</integer><key>pos_x</key><integer>86</integer><key>pos_y</key><integer>517</integer><key>floatPos</key><array><real>86.5</real><real>517.0</real></array><key>chestType</key><integer>2</integer><key>safeClientID</key><string>client-1</string><key>saveItemSlots</key><array><array><dict><key>itemType</key><integer>1</integer></dict><dict><key>itemType</key><integer>11</integer></dict></array><array><dict><key>itemType</key><integer>4</integer></dict></array><array></array><array></array></array><key>shelfRenderItems_0</key><integer>3</integer><key>shelfItemDataBs_0</key><integer>5</integer><key>shelfRenderItems_3</key><integer>9</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kChestRecord, value, error);
    bh176::ChestFullState state;
    bh176::ClientDynamicObject object =
        bh176::chest_full_factory(46, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 46);
    assert(object.class_name == "Chest");
    assert(object.unique_id == 180);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("b4m") != std::string::npos);
    assert(object.status_reason.find("not performed") != std::string::npos);

    assert(state.has_chest_type && state.chest_type == 2);
    assert(state.has_safe_client_id);
    // slots: raw counts (no item decode — the filter is NOT applied offline)
    assert(state.has_save_item_slots);
    assert(state.save_slot_count == 4);
    assert(state.slot_item_counts.size() == 4);
    assert(state.slot_item_counts[0] == 2);  // includes the type-11 item
    assert(state.slot_item_counts[1] == 1);
    assert(state.slot_item_counts[2] == 0 && state.slot_item_counts[3] == 0);
    assert(!state.item_decode_performed);
    // shelves: values captured where present, presence tracked per index
    assert(state.has_shelf_render_items[0] && state.shelf_render_items[0] == 3);
    assert(state.has_shelf_item_data_bs[0] && state.shelf_item_data_bs[0] == 5);
    assert(state.has_shelf_render_items[3] && state.shelf_render_items[3] == 9);
    assert(!state.has_shelf_item_data_bs[1]);
    assert(state.shelf_item_data_bs[1] == 0);

    // ---- base-only record: every gate closed, nothing invented -----------
    const char* kEmptyChest = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>181</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kEmptyChest, value2, error);
    bh176::ChestFullState state2;
    bh176::chest_full_factory(46, entry2, &state2, &error);
    assert(!state2.has_chest_type);
    assert(!state2.has_safe_client_id);
    assert(!state2.has_save_item_slots && state2.save_slot_count == 0);
    assert(state2.slot_item_counts.empty());
    assert(!state2.interaction_static_keys_present);

    // ---- strh truncation control on the shelf halfword -------------------
    const char* kShelfBig = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>182</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>shelfItemDataBs_2</key><integer>70000</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict entry3 = entryOf(kShelfBig, value3, error);
    bh176::ChestFullState state3;
    bh176::chest_full_factory(46, entry3, &state3, &error);
    // 70000 through the strh store: low 16 bits (4464)
    assert(state3.has_shelf_item_data_bs[2]);
    assert(state3.shelf_item_data_bs[2] == 4464);

    std::printf("test_chest_full: PASS\n");
    return 0;
}
