// GlowBlock full-chain test: base + the listing-decoded own keys, with the
// lightDict child boundary stated (not run offline).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "glowblock_full.h"

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

    const char* kGlow = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>240</integer><key>pos_x</key><integer>96</integer><key>pos_y</key><integer>522</integer><key>floatPos</key><array><real>96.5</real><real>522.0</real></array><key>tileType</key><integer>7</integer><key>lightDict</key><dict><key>radius</key><integer>3</integer></dict></dict>
</array></dict></plist>
)";
    const bh176::SaveDict entry = entryOf(kGlow, value, error);
    bh176::GlowBlockFullState state;
    bh176::ClientDynamicObject object =
        bh176::glowblock_full_factory(18, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 18);
    assert(object.class_name == "GlowBlock");
    assert(object.unique_id == 240);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("tileType@60") != std::string::npos);
    assert(state.has_tile_type && state.tile_type == 7);
    assert(state.light_present);
    assert(state.light_child_not_run);

    // ---- base-only record: every gate closed ------------------------------
    const char* kEmpty = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>241</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kEmpty, value2, error);
    bh176::GlowBlockFullState state2;
    bh176::glowblock_full_factory(18, entry2, &state2, &error);
    assert(!state2.has_tile_type && state2.tile_type == 0);
    assert(!state2.light_present);

    std::printf("test_glowblock_full: PASS\n");
    return 0;
}
