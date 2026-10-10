// InteractionObject-family full-chain test: the executed 352w contract runs
// through the production factory and the state is read back from its image.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "interaction_full.h"

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

    // ---- InteractionObject 15: the six keys through the executed chain ----
    const char* kInterRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>220</integer><key>pos_x</key><integer>92</integer><key>pos_y</key><integer>520</integer><key>floatPos</key><array><real>92.5</real><real>520.0</real></array><key>isInUse</key><true/><key>flipped</key><false/><key>ownerID</key><string>c-1</string><key>paintColor</key><integer>70000</integer><key>currentBlockheadIndex</key><integer>5</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kInterRecord, value, error);
    bh176::InteractionFullState state;
    bh176::ClientDynamicObject object =
        bh176::interaction_full_factory(15, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 15);
    assert(object.class_name == "InteractionObject");
    assert(object.unique_id == 220);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("executed 352w") != std::string::npos);
    assert(state.is_in_use);
    assert(!state.flipped);
    assert(state.has_owner_id);
    assert(!state.has_owner_name);   // the key is absent
    // paintColor through the executed STRH store: 70000 -> 4464
    assert(state.paint_color == 4464);
    // currentBlockheadIndex present -> the overwrite store wins
    assert(state.had_blockhead_index);
    assert(state.saved_blockhead_index == 5);
    assert(state.world_tail_not_run);

    // ---- the -1 default survives when the probe key is absent ------------
    const char* kNoBlockhead = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>221</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>isInUse</key><false/></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kNoBlockhead, value2, error);
    bh176::InteractionFullState state2;
    bh176::interaction_full_factory(15, entry2, &state2, &error);
    assert(!state2.had_blockhead_index);
    assert(state2.saved_blockhead_index == -1);   // the unconditional default
    assert(!state2.is_in_use);
    assert(state2.paint_color == 0);

    // ---- Mirror 64: zero own keys, the same chain ------------------------
    bh176::SaveValue value3;
    const bh176::SaveDict entry3 = entryOf(kInterRecord, value3, error);
    bh176::InteractionFullState state3;
    bh176::ClientDynamicObject object3 =
        bh176::interaction_full_factory(64, entry3, &state3, &error);
    assert(object3.class_name == "Mirror");
    assert(object3.status == bh176::ObjectLoadStatus::Recovered);
    assert(object3.status_reason.find("zero-own-key") != std::string::npos);
    assert(state3.is_in_use);
    assert(state3.paint_color == 4464);

    std::printf("test_interaction_full: PASS\n");
    return 0;
}
