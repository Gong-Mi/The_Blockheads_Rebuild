// KelpPlant / VinePlant full-chain test: the executed b4n/b4o twin chains
// (Plant chain reused via plant_full_load + the mirrored occupied axis).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "kelpvine_full.h"

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

    // ---- KelpPlant 34: numberOfOccupiedTilesAbove + growthTimer + food ----
    const char* kKelpRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>140</integer><key>pos_x</key><integer>60</integer><key>pos_y</key><integer>500</integer><key>floatPos</key><array><real>60.5</real><real>500.0</real></array><key>seasonOffset</key><integer>5</integer><key>age</key><real>300.0</real><key>maxAgeGene</key><integer>150</integer><key>growthRateGene</key><integer>160</integer><key>saveTime</key><real>900.0</real><key>numberOfOccupiedTilesAbove</key><integer>6</integer><key>growthTimer</key><real>1.25</real><key>availableFood</key><real>55.5</real></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kKelpRecord, value, error);
    bh176::KelpVineFullState state;
    bh176::ClientDynamicObject object =
        bh176::kelpvine_full_factory(34, entry, 900.0, &state, &error);
    assert(error.empty());
    assert(object.type_id == 34);
    assert(object.class_name == "KelpPlant");
    assert(object.unique_id == 140);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("b4n") != std::string::npos);
    assert(state.is_kelp);
    assert(state.has_occupied_tiles && state.occupied_tiles == 6);
    assert(state.has_growth_timer && state.growth_timer == 1.25f);
    assert(state.has_available_food && state.available_food > 55.4f &&
           state.available_food < 55.6f);
    // the Plant chain ran (executed b4b): gate input consumed, no tulip keys
    assert(!state.plant.tulip.present);
    assert(state.plant.max_age_gene == 150);
    assert(state.plant.growth_rate_gene == 160);

    // ---- VinePlant 58: numberOfOccupiedTilesBelow (the mirror) ------------
    const char* kVineRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>141</integer><key>pos_x</key><integer>61</integer><key>pos_y</key><integer>500</integer><key>age</key><real>400.0</real><key>numberOfOccupiedTilesBelow</key><integer>9</integer><key>growthTimer</key><real>2.5</real><key>availableFood</key><real>66.0</real></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kVineRecord, value2, error);
    bh176::KelpVineFullState state2;
    bh176::ClientDynamicObject object2 =
        bh176::kelpvine_full_factory(58, entry2, 900.0, &state2, &error);
    assert(!state2.is_kelp);
    assert(object2.class_name == "VinePlant");
    assert(object2.status == bh176::ObjectLoadStatus::Recovered);
    assert(state2.has_occupied_tiles && state2.occupied_tiles == 9);
    assert(state2.has_growth_timer && state2.growth_timer == 2.5f);
    assert(state2.has_available_food && state2.available_food > 65.9f &&
           state2.available_food < 66.1f);

    // ---- cross-check: the kelp key must NOT feed the vine axis ------------
    // (feed the kelp-shaped record to the vine factory: the mirrored key is
    // absent, so the occupied block stays closed — never cross-read)
    bh176::KelpVineFullState state3;
    bh176::kelpvine_full_factory(58, entry, 900.0, &state3, &error);
    assert(!state3.has_occupied_tiles);
    assert(state3.occupied_tiles == 0);

    std::printf("test_kelpvine_full: PASS\n");
    return 0;
}
