// FireObject / Torch full-chain test: base + the listing-decoded own keys,
// with the light-child boundary stated (not run offline).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "fire_torch_full.h"

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

    // ---- FireObject 16: burnTimer + the four spread lanes -----------------
    const char* kFire = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>250</integer><key>pos_x</key><integer>97</integer><key>pos_y</key><integer>523</integer><key>floatPos</key><array><real>97.5</real><real>523.0</real></array><key>burnTimer</key><real>0.75</real><key>spreadTimer_0</key><real>1.0</real><key>spreadTimer_1</key><real>2.0</real><key>spreadTimer_2</key><real>3.0</real><key>spreadTimer_3</key><real>4.0</real><key>lightDict</key><dict><key>radius</key><integer>2</integer></dict></dict>
</array></dict></plist>
)";
    const bh176::SaveDict fire = entryOf(kFire, value, error);
    bh176::FireTorchFullState state;
    bh176::ClientDynamicObject object =
        bh176::fire_torch_full_factory(16, fire, &state, &error);
    assert(error.empty());
    assert(object.class_name == "FireObject");
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("burnTimer@56") != std::string::npos);
    assert(state.has_burn_timer && state.burn_timer > 0.749f &&
           state.burn_timer < 0.751f);
    for (int i = 0; i < 4; ++i) {
        assert(state.has_spread_timer[static_cast<std::size_t>(i)]);
        assert(state.spread_timers[static_cast<std::size_t>(i)] ==
               static_cast<float>(i + 1));
    }
    assert(state.light_present && state.light_child_not_run);
    assert(state.world_post_step_not_run);

    // ---- Torch 17: the five scalar slots incl. the two STRH halves --------
    const char* kTorch = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>251</integer><key>pos_x</key><integer>98</integer><key>pos_y</key><integer>523</integer><key>itemType</key><integer>9</integer><key>connectionType</key><integer>1</integer><key>dataA</key><integer>70000</integer><key>dataB</key><integer>2</integer><key>ownerID</key><string>c-7</string><key>lightDict</key><dict><key>radius</key><integer>4</integer></dict></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict torch = entryOf(kTorch, value2, error);
    bh176::FireTorchFullState state2;
    bh176::ClientDynamicObject object2 =
        bh176::fire_torch_full_factory(17, torch, &state2, &error);
    assert(object2.class_name == "Torch");
    assert(object2.status == bh176::ObjectLoadStatus::Recovered);
    assert(state2.has_item_type && state2.item_type == 9);
    assert(state2.has_connection_type && state2.connection_type == 1);
    assert(state2.has_data_a && state2.data_a == 4464);  // 70000 through STRH
    assert(state2.has_data_b && state2.data_b == 2);
    assert(state2.has_owner_id);
    assert(state2.light_present);

    // ---- base-only records: gates closed ----------------------------------
    const char* kEmpty = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>252</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict empty = entryOf(kEmpty, value3, error);
    bh176::FireTorchFullState state3;
    bh176::fire_torch_full_factory(16, empty, &state3, &error);
    assert(!state3.has_burn_timer && state3.burn_timer == 0.0f);
    assert(!state3.has_spread_timer[0]);
    assert(!state3.light_present);
    bh176::FireTorchFullState state4;
    bh176::fire_torch_full_factory(17, empty, &state4, &error);
    assert(!state4.has_item_type && !state4.has_owner_id);

    std::printf("test_fire_torch_full: PASS\n");
    return 0;
}
