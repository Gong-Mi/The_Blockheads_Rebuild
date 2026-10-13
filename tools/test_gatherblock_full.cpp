// GatherBlock full-chain test: the ownkey5 executed chain through the
// production factory (base keys + timer@56 floatValue + lastKnownGatherValue@60
// intValue, presence-gated).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "gatherblock_full.h"

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

    // ---- full record: base + both own keys ---------------------------------
    const char* kGatherRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>130</integer><key>pos_x</key><integer>98</integer><key>pos_y</key><integer>521</integer><key>floatPos</key><array><real>98.5</real><real>521.0</real></array><key>timer</key><real>0.5</real><key>lastKnownGatherValue</key><integer>42</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kGatherRecord, value, error);
    bh176::GatherBlockFullState state;
    bh176::ClientDynamicObject object =
        bh176::gatherblock_full_factory(26, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 26);
    assert(object.class_name == "GatherBlock");
    assert(object.unique_id == 130);
    assert(object.pos_x == 98 && object.pos_y == 521);
    assert(object.float_pos_x == 98.5f && object.float_pos_y == 521.0f);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("ownkey5") != std::string::npos);
    assert(state.has_timer && state.timer == 0.5f);
    assert(state.has_last_known_gather_value &&
           state.last_known_gather_value == 42);

    // ---- base-only record: gates stay closed, nothing invented ------------
    const char* kBaseOnly = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>131</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kBaseOnly, value2, error);
    bh176::GatherBlockFullState state2;
    bh176::gatherblock_full_factory(26, entry2, &state2, &error);
    assert(!state2.has_timer && state2.timer == 0.0f);
    assert(!state2.has_last_known_gather_value);
    assert(state2.last_known_gather_value == 0);

    std::printf("test_gatherblock_full: PASS\n");
    return 0;
}
