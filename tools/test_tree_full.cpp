// Tree-family full-chain test (bucket A, trees): the b4d stage-1 contract
// runs through the production factory on a REAL AppleTree-shaped record
// (keys copied from reverse-probe-001 uniqueID 39), the b3a static gene
// block is loaded for non-static trees and skipped by the gate, and the
// AppleTree availableFood own key is presence-gated (OrangeTree has none).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "tree_full.h"

#include <cassert>
#include <cstdio>
#include <string>

namespace {

// Keys from the real reverse-probe-001 AppleTree record (uniqueID 39).
const char* kAppleTreeRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>39</integer><key>pos_x</key><integer>114</integer><key>pos_y</key><integer>526</integer><key>floatPos</key><array><real>114.5</real><real>526.0</real></array><key>age</key><real>1422.129</real><key>availableFood</key><real>279.3271</real><key>dead</key><false/><key>growthCounter</key><real>0.4282283</real><key>growthRate</key><real>0.2343903</real><key>growthRateGene</key><integer>235</integer><key>height</key><integer>1</integer><key>maxAge</key><real>26853.88</real><key>maxHeight</key><integer>7</integer><key>maxHeightGene</key><integer>211</integer><key>maxHeightReached</key><integer>1</integer><key>removeCheckCount</key><real>0.0</real><key>saveTime</key><real>900.0</real><key>timeDied</key><real>0.0</real><key>treeFruit</key><array><dict><key>hasCreatedFreeBlockThisSeason</key><false/><key>pos.x</key><integer>113</integer><key>pos.y</key><integer>526</integer></dict></array><key>treeSeasonOffset</key><integer>0</integer></dict>
</array></dict></plist>
)";

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

    // ---- production factory on the real AppleTree record -----------------
    const bh176::SaveDict entry = entryOf(kAppleTreeRecord, value, error);
    bh176::TreeFullState state;
    bh176::ClientDynamicObject object =
        bh176::tree_full_factory(1, entry, &state, &error);
    assert(error.empty());
    assert(object.type_id == 1);
    assert(object.class_name == "AppleTree");
    assert(object.unique_id == 39);
    assert(object.pos_x == 114 && object.pos_y == 526);
    assert(object.float_pos_x == 114.5f && object.float_pos_y == 526.0f);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);

    // stage 1 (executed) fields
    assert(state.tree_season_offset == 0);
    assert(!state.dead);
    assert(state.time_died == 0.0);
    assert(state.remove_check_count == 0.0f);
    assert(state.height == 1);
    assert(state.age > 1422.0f && state.age < 1423.0f);
    // fruit_count is stage 1's explicit unknown domain: the executed
    // differential only covers an EMPTY treeFruit array, so a non-empty
    // array yields the -1 sentinel (never an invented count)
    assert(state.fruit_count == -1);
    assert(!state.static_gate_fired);
    // gene/growth block (static decode, non-static tree -> loaded)
    assert(state.max_height_reached == 1);
    assert(state.growth_rate_gene == 235);
    assert(state.max_height_gene == 211);
    assert(state.max_height == 7.0f);
    assert(state.growth_rate > 0.234f && state.growth_rate < 0.235f);
    assert(state.growth_counter > 0.428f && state.growth_counter < 0.429f);
    assert(state.max_age > 26853.0f && state.max_age < 26854.0f);
    // AppleTree own key (presence-gated)
    assert(state.has_available_food);
    assert(state.available_food > 279.0f && state.available_food < 280.0f);

    // ---- the isStaticTree gate control (stage-1 semantics) ---------------
    const bh176::TreeFullState gated =
        bh176::tree_full_load(entry, /*is_static_tree=*/true);
    assert(gated.static_gate_fired);
    // the gene/growth block is skipped: fields stay at their defaults even
    // though every gene key is present in the record
    assert(gated.max_height_reached == 0);
    assert(gated.growth_rate_gene == 0);
    assert(gated.max_height_gene == 0);
    assert(gated.max_height == 0.0f);
    assert(gated.growth_rate == 0.0f);
    assert(gated.growth_counter == 0.0f);
    assert(gated.max_age == 0.0f);
    // availableFood is the OWN class step, outside the Tree gate: still read
    assert(gated.has_available_food);

    // ---- an OrangeTree-shaped record: no availableFood own key -----------
    const char* kOrangeTreeRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>115</integer><key>pos_x</key><integer>157</integer><key>pos_y</key><integer>537</integer><key>age</key><real>1968.187</real><key>dead</key><false/><key>growthCounter</key><real>0.4034734</real><key>height</key><integer>2</integer><key>maxHeight</key><integer>10</integer><key>treeSeasonOffset</key><integer>160</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict entry2 = entryOf(kOrangeTreeRecord, value2, error);
    bh176::TreeFullState state2;
    bh176::ClientDynamicObject object2 =
        bh176::tree_full_factory(7, entry2, &state2, &error);
    assert(error.empty());
    assert(object2.class_name == "OrangeTree");
    assert(object2.status == bh176::ObjectLoadStatus::Recovered);
    // no availableFood key -> the own-key block stays closed
    assert(!state2.has_available_food);
    assert(state2.available_food == 0.0f);
    // present keys still load (stage 1 + static block)
    assert(state2.tree_season_offset == 160);
    assert(state2.height == 2);
    assert(state2.max_height == 10.0f);
    // missing gene keys decode as nil (0), never invented
    assert(state2.growth_rate_gene == 0);
    assert(state2.max_height_reached == 0);
    assert(state2.fruit_count == 0);

    // ---- CactusTree: own keys route to the @148 block --------------------
    const char* kCactusRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>126</integer><key>pos_x</key><integer>95</integer><key>pos_y</key><integer>521</integer><key>age</key><real>2100.0</real><key>height</key><integer>4</integer><key>splitHeightA</key><integer>3</integer><key>splitHeightB</key><integer>4</integer><key>splitDirection</key><true/><key>availableFood</key><real>12.5</real></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict entry3 = entryOf(kCactusRecord, value3, error);
    bh176::TreeFullState state3;
    bh176::ClientDynamicObject object3 =
        bh176::tree_full_factory(5, entry3, &state3, &error);
    assert(error.empty());
    assert(object3.class_name == "CactusTree");
    assert(object3.status == bh176::ObjectLoadStatus::Recovered);
    assert(state3.has_cactus_own);
    assert(state3.split_height_a == 3);
    assert(state3.split_height_b == 4);
    assert(state3.split_direction);
    assert(state3.cactus_available_food > 12.4f &&
           state3.cactus_available_food < 12.6f);
    // the cactus availableFood must NOT land in the fruit-tree @136 slot
    assert(!state3.has_available_food);
    assert(state3.available_food == 0.0f);

    // ---- GemTree: own keys (gemTreeType/fruitYear) ------------------------
    const char* kGemRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>127</integer><key>pos_x</key><integer>96</integer><key>pos_y</key><integer>521</integer><key>age</key><real>2200.0</real><key>height</key><integer>5</integer><key>gemTreeType</key><integer>2</integer><key>fruitYear</key><integer>3</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value4;
    const bh176::SaveDict entry4 = entryOf(kGemRecord, value4, error);
    bh176::TreeFullState state4;
    bh176::ClientDynamicObject object4 =
        bh176::tree_full_factory(57, entry4, &state4, &error);
    assert(error.empty());
    assert(object4.class_name == "GemTree");
    assert(object4.status == bh176::ObjectLoadStatus::Recovered);
    assert(state4.has_gem_own);
    assert(state4.gem_tree_type == 2);
    assert(state4.fruit_year == 3);
    // no cactus/fruit own keys on a gem record
    assert(!state4.has_cactus_own);
    assert(!state4.has_available_food);

    // ---- CactusTree partial own keys: any present key opens the block -----
    const char* kCactusPartial = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>128</integer><key>pos_x</key><integer>97</integer><key>pos_y</key><integer>521</integer><key>splitHeightA</key><integer>7</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value5;
    const bh176::SaveDict entry5 = entryOf(kCactusPartial, value5, error);
    bh176::TreeFullState state5;
    bh176::tree_full_factory(5, entry5, &state5, &error);
    assert(state5.has_cactus_own);           // the block opened on one key
    assert(state5.split_height_a == 7);
    assert(state5.split_height_b == 0);      // absent keys decode as nil
    assert(!state5.split_direction);
    assert(state5.cactus_available_food == 0.0f);

    std::printf("test_tree_full: PASS\n");
    return 0;
}
