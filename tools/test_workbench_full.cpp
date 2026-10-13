// Workbench full-chain test (bucket C): the executed b4q contract runs
// through the production factory on the REAL workbench record (uid 154,
// keys copied from reverse-probe-001), the lightDict presence restore is
// visible, and the InteractionObject static boundary is reported.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "workbench_full.h"

#include <cassert>
#include <cstdio>
#include <string>

namespace {

// Keys from the real reverse-probe-001 workbench record (uid 154).
const char* kWorkbenchRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>154</integer><key>pos_x</key><integer>143</integer><key>pos_y</key><integer>532</integer><key>floatPos</key><array><real>143.5</real><real>532.0</real></array><key>availableElectricity</key><integer>0</integer><key>craftProgressCount</key><real>0.0</real><key>fireSpreadTimer</key><real>0.0</real><key>flipped</key><false/><key>fuelFraction</key><real>0.0</real><key>hasFuel</key><false/><key>hurryCost</key><integer>0</integer><key>hurrySeconds</key><real>0.0</real><key>hurryTimer</key><real>0.0</real><key>hurrying</key><false/><key>interactionObjectType</key><integer>1</integer><key>isInUse</key><false/><key>lastWorldTime</key><real>900.0</real><key>level</key><integer>0</integer><key>lightDict</key><dict><key>contributionGridOrigin.x</key><integer>131</integer></dict><key>paintColor</key><integer>0</integer><key>saveTime</key><real>900.0</real><key>selectedIndex</key><integer>0</integer><key>workbenchType</key><integer>1</integer><key>xScroll</key><real>0.0</real></dict>
</array></dict></plist>
)";

}  // namespace

int main() {
    bh176::SaveValue value;
    std::string error;
    assert(bh176::parseXmlPlist(kWorkbenchRecord, value, &error));
    const bh176::SaveDict dict(value);
    const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
    const bh176::SaveValue* entry = dict.objectAtIndex(objects, 0);
    const bh176::SaveDict entry_dict(*entry);

    // ---- the production factory -------------------------------------------
    bh176::WorkbenchFullState state;
    bh176::ClientDynamicObject object =
        bh176::workbench_full_factory(45, entry_dict, &state, &error);
    assert(error.empty());
    assert(object.type_id == 45);
    assert(object.class_name == "Workbench");
    assert(object.unique_id == 154);
    assert(object.pos_x == 143 && object.pos_y == 532);
    assert(object.float_pos_x == 143.5f && object.float_pos_y == 532.0f);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);

    // the b4q executed scalar walk
    assert(state.workbench_type == 1);
    assert(state.selected_index == 0);
    assert(state.x_scroll == 0.0f);
    assert(state.level == 0);
    assert(state.craft_progress_count == 0.0f);
    assert(state.hurry_timer == 0.0f);
    assert(state.hurry_seconds == 0.0f);
    assert(!state.hurrying);
    assert(state.hurry_cost == 0);
    assert(state.fire_spread_timer == 0.0f);
    assert(state.fuel_fraction == 0.0f);
    assert(!state.has_fuel);
    assert(state.last_world_time == 900.0);
    assert(!state.is_in_use_fuel);
    assert(state.available_electricity == 0);
    // currentBlockheadIndexFuel absent -> the intValue of nil is 0
    assert(state.saved_blockhead_index_fuel == 0);
    // lightDict present -> the executed restore fired
    assert(state.light_present);
    // the InteractionObject static boundary is REPORTED, not loaded
    assert(state.interaction_static_keys_present);

    // ---- a fuel-workbench control: BOOL/double/unsigned kinds ------------
    const char* kFuelRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>7</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>workbenchType</key><integer>3</integer><key>hurrying</key><true/><key>hasFuel</key><true/><key>isInUseFuel</key><true/><key>lastWorldTime</key><real>123.5</real><key>availableElectricity</key><integer>77</integer><key>currentBlockheadIndexFuel</key><integer>-1</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    assert(bh176::parseXmlPlist(kFuelRecord, value2, &error));
    const bh176::SaveDict dict2(value2);
    const bh176::SaveValue* objects2 = dict2.objectForKey("dynamicObjects");
    const bh176::SaveValue* entry2 = dict2.objectAtIndex(objects2, 0);
    const bh176::SaveDict entry2_dict(*entry2);
    bh176::WorkbenchFullState state2;
    bh176::workbench_full_factory(45, entry2_dict, &state2, &error);
    assert(state2.workbench_type == 3);
    assert(state2.hurrying);        // BOOLValue
    assert(state2.has_fuel);        // BOOLValue
    assert(state2.is_in_use_fuel);  // BOOLValue
    assert(state2.last_world_time == 123.5);  // doubleValue
    assert(state2.available_electricity == 77);  // unsignedInt halfword
    // currentBlockheadIndexFuel = -1: intValue of the -1 box -> -1 stored
    // (the double objectForKey read happens regardless, an executed fact)
    assert(state2.saved_blockhead_index_fuel == -1);
    assert(!state2.light_present);  // no lightDict key

    std::printf("test_workbench_full: PASS\n");
    return 0;
}
