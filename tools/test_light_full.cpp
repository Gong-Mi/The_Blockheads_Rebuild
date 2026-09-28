// ArtificialLight body + the four classes' lightDict decode (shared decoder).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "artificial_light_full.h"
#include "fire_torch_full.h"
#include "glowblock_full.h"
#include "workbench_full.h"

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

    // ---- the light body itself (type 21) ----------------------------------
    const char* kLight = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>300</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>downlight</key><true/><key>lightDirection</key><integer>3</integer><key>radius</key><integer>4</integer><key>maxRed</key><integer>15</integer><key>maxGreen</key><integer>8</integer><key>maxBlue</key><integer>2</integer><key>maxHeat</key><integer>1</integer><key>contributionGridOrigin.x</key><integer>100</integer><key>contributionGridOrigin.y</key><integer>200</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict light = entryOf(kLight, value, error);
    bh176::ArtificialLightFullState state;
    bh176::ClientDynamicObject object =
        bh176::artificial_light_full_factory(21, light, &state, &error);
    assert(error.empty());
    assert(object.class_name == "ArtificialLight");
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("addToTiles") != std::string::npos);
    assert(state.light.has_downlight && state.light.downlight);
    assert(state.light.has_light_direction && state.light.light_direction == 3);
    assert(state.light.has_radius && state.light.radius == 4);
    assert(state.light.has_max_red && state.light.max_red == 15);
    assert(state.light.has_max_green && state.light.max_green == 8);
    assert(state.light.has_max_blue && state.light.max_blue == 2);
    assert(state.light.has_max_heat && state.light.max_heat == 1);
    assert(state.light.has_contribution_origin);
    assert(state.light.contribution_origin_x == 100);
    assert(state.light.contribution_origin_y == 200);
    assert(!state.has_parent_object);  // a constructor argument, not a key

    // ---- the shared decoder is what the four classes call ----------------
    bh176::SaveValue v2;
    const bh176::SaveDict wb = entryOf(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>301</integer><key>pos_x</key><integer>5</integer><key>pos_y</key><integer>6</integer><key>lastWorldTime</key><integer>900</integer><key>lightDict</key><dict><key>maxRed</key><integer>12</integer><key>radius</key><integer>6</integer></dict></dict>
</array></dict></plist>
)", v2, error);
    bh176::WorkbenchFullState wb_state;
    bh176::workbench_full_factory(45, wb, &wb_state, &error);
    assert(wb_state.light_present);
    assert(wb_state.light.has_max_red && wb_state.light.max_red == 12);
    assert(wb_state.light.has_radius && wb_state.light.radius == 6);
    assert(!wb_state.light.has_max_green);  // absent keys stay absent

    bh176::SaveValue v3;
    const bh176::SaveDict glow = entryOf(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>302</integer><key>pos_x</key><integer>7</integer><key>pos_y</key><integer>8</integer><key>tileType</key><integer>2</integer><key>lightDict</key><dict><key>maxHeat</key><integer>9</integer><key>downlight</key><true/></dict></dict>
</array></dict></plist>
)", v3, error);
    bh176::GlowBlockFullState glow_state;
    bh176::glowblock_full_factory(18, glow, &glow_state, &error);
    assert(glow_state.light_present);
    assert(glow_state.light.has_max_heat && glow_state.light.max_heat == 9);
    assert(glow_state.light.has_downlight && glow_state.light.downlight);

    bh176::SaveValue v4;
    const bh176::SaveDict torch = entryOf(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>303</integer><key>pos_x</key><integer>9</integer><key>pos_y</key><integer>10</integer><key>itemType</key><integer>4</integer><key>connectionType</key><integer>1</integer><key>dataA</key><integer>2</integer><key>dataB</key><integer>3</integer><key>ownerID</key><string>c</string><key>lightDict</key><dict><key>maxBlue</key><integer>5</integer></dict></dict>
</array></dict></plist>
)", v4, error);
    bh176::FireTorchFullState torch_state;
    bh176::fire_torch_full_factory(17, torch, &torch_state, &error);
    assert(torch_state.light_present);
    assert(torch_state.light.has_max_blue && torch_state.light.max_blue == 5);
    assert(torch_state.light_child_not_run);  // tile registration still world

    std::printf("test_light_full: PASS\n");
    return 0;
}
