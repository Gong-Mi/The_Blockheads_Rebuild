// TrainStation full-chain test: the ownkey5 executed chain through the
// production factory (base keys + the text@128 own key, presence-gated;
// InteractionObject static boundary reported like Workbench).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "trainstation_full.h"

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

    // ---- full record: base + text + the InteractionObject static set -----
    const char* kStationRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>170</integer><key>pos_x</key><integer>85</integer><key>pos_y</key><integer>516</integer><key>floatPos</key><array><real>85.5</real><real>516.0</real></array><key>text</key><string>Depot A</string><key>flipped</key><false/><key>paintColor</key><integer>2</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kStationRecord, value, error);
    bh176::TrainStationFullState state;
    bh176::ClientDynamicObject object =
        bh176::trainstation_full_factory(49, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 49);
    assert(object.class_name == "TrainStation");
    assert(object.unique_id == 170);
    assert(object.pos_x == 85 && object.pos_y == 516);
    assert(object.float_pos_x == 85.5f && object.float_pos_y == 516.0f);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("ownkey5") != std::string::npos);
    assert(object.status_reason.find("static-only") != std::string::npos);
    assert(state.has_text);
    // the boundary is reported, never loaded as values
    assert(state.interaction_static_keys_present);

    // ---- base-only record: text gate closed ------------------------------
    const char* kStationNoText = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>171</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kStationNoText, value2, error);
    bh176::TrainStationFullState state2;
    bh176::trainstation_full_factory(49, entry2, &state2, &error);
    assert(!state2.has_text);
    assert(!state2.interaction_static_keys_present);

    std::printf("test_trainstation_full: PASS\n");
    return 0;
}
