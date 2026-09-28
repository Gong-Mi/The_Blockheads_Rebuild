// NPC-family full-chain test (bucket B): the executed b3g/b4f contracts run
// for real through the production factory, on a REAL dodo-shaped record
// (the keys the reverse-probe-001 dodo actually carries).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "npc_full.h"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

void writeText(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
    assert(out.good());
}

// Keys copied from the real reverse-probe-001 dodo record (uniqueID 38):
// base + G1 (fullness gate) + G2 (layCooldownTimer gate) + breed + saveTime
// (the save-side key the loader must NOT read).
const char* kDodoRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>38</integer><key>pos_x</key><integer>110</integer><key>pos_y</key><integer>525</integer><key>floatPos</key><array><real>110.5</real><real>525.0</real></array><key>age</key><real>3432.53</real><key>breed</key><integer>0</integer><key>damage</key><integer>0</integer><key>fullness</key><real>1623.233</real><key>hasBeenFedByBlockheadOrChest</key><false/><key>hasBred</key><false/><key>layCooldownTimer</key><real>82.93232</real><key>layTimer</key><real>0.0</real><key>mateBreed</key><integer>0</integer><key>mateCooldownTimer</key><real>0.0</real><key>saveTime</key><real>900.0</real><key>tameCooldownTimer</key><real>0.0</real></dict>
</array></dict></plist>
)";

}  // namespace

int main() {
    bh176::SaveValue value;
    std::string error;
    assert(bh176::parseXmlPlist(kDodoRecord, value, &error));
    const bh176::SaveDict dict(value);
    const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
    assert(objects != nullptr && objects->isArray());
    const bh176::SaveValue* entry = dict.objectAtIndex(objects, 0);
    assert(entry != nullptr && entry->isDict());
    const bh176::SaveDict entry_dict(*entry);

    // ---- the chain runs through the production factory -------------------
    bh176::NpcFullState state;
    bh176::ClientDynamicObject object =
        bh176::npc_full_factory(13, entry_dict, &state, &error);
    assert(error.empty());
    assert(object.type_id == 13);
    assert(object.class_name == "Dodo");
    assert(object.unique_id == 38);
    assert(object.pos_x == 110 && object.pos_y == 525);
    assert(object.float_pos_x == 110.5f && object.float_pos_y == 525.0f);
    assert(object.status == bh176::ObjectLoadStatus::Recovered);

    // ---- the executed contract's stores are visible in the state ---------
    assert(state.g1_present);
    // fullness 1623.233: the ARM store is a word write; the bits round-trip
    assert(state.fullness > 1623.0f && state.fullness < 1624.0f);
    assert(state.lay_timer == 0.0f);
    assert(state.damage == 0);
    assert(state.age > 3432.0f && state.age < 3433.0f);
    assert(state.g2_present);
    assert(state.lay_cooldown_timer > 82.9f && state.lay_cooldown_timer < 83.0f);
    assert(state.tame_cooldown_timer == 0.0f);
    assert(state.mate_cooldown_timer == 0.0f);
    assert(!state.has_bred);
    assert(!state.has_been_fed);
    assert(state.mate_breed == 0);
    assert(state.breed == 0);
    // ungated slots: none of the object keys present -> nil/absent
    assert(!state.has_tamed_client_id);
    assert(!state.has_name);
    assert(!state.has_tame_counts);
    // savedBlockheadIndex: -1 default (no currentBlockheadIndex key)
    assert(state.saved_blockhead_index == -1);

    // ---- the factory via the registry signature path (null out_state) ----
    bh176::ClientDynamicObject object2 =
        bh176::npc_full_factory(28, entry_dict, nullptr, &error);
    assert(error.empty());
    assert(object2.type_id == 28);
    assert(object2.class_name == "Donkey");
    assert(object2.unique_id == 38);
    assert(object2.status == bh176::ObjectLoadStatus::Recovered);

    // ---- gate controls: a G1-absent record keeps G1 stores at zero --------
    const char* kDodoNoG1 = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>7</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>layTimer</key><real>5.0</real><key>damage</key><integer>9</integer><key>age</key><real>10.0</real></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    assert(bh176::parseXmlPlist(kDodoNoG1, value2, &error));
    const bh176::SaveDict dict2(value2);
    const bh176::SaveValue* objects2 = dict2.objectForKey("dynamicObjects");
    const bh176::SaveValue* entry2 = dict2.objectAtIndex(objects2, 0);
    const bh176::SaveDict entry2_dict(*entry2);
    bh176::NpcFullState state2;
    bh176::npc_full_factory(13, entry2_dict, &state2, &error);
    // the fullness probe closed the gate: layTimer/damage/age are present in
    // the dictionary but the ARM chain never reads them back (G1 semantics)
    assert(!state2.g1_present);
    assert(state2.lay_timer == 0.0f);
    assert(state2.damage == 0);
    assert(state2.age == 0.0f);

    // ---- damage strh truncation control ------------------------------------
    const char* kDodoBigDamage = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>7</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>fullness</key><real>1.0</real><key>damage</key><integer>70000</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    assert(bh176::parseXmlPlist(kDodoBigDamage, value3, &error));
    const bh176::SaveDict dict3(value3);
    const bh176::SaveValue* objects3 = dict3.objectForKey("dynamicObjects");
    const bh176::SaveValue* entry3 = dict3.objectAtIndex(objects3, 0);
    const bh176::SaveDict entry3_dict(*entry3);
    bh176::NpcFullState state3;
    bh176::npc_full_factory(13, entry3_dict, &state3, &error);
    // intValue 70000 stored via strh: truncated to the low 16 bits (4464)
    assert(state3.g1_present);
    assert(state3.damage == 4464);

    // ---- Yak: the same NPC chain + ownkey5 own keys {milk, hair} ---------
    const char* kYakRecord = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>124</integer><key>pos_x</key><integer>93</integer><key>pos_y</key><integer>520</integer><key>age</key><real>1100.0</real><key>fullness</key><real>700.0</real><key>milk</key><real>2.5</real><key>hair</key><real>12.0</real></dict>
</array></dict></plist>
)";
    bh176::SaveValue value4;
    assert(bh176::parseXmlPlist(kYakRecord, value4, &error));
    const bh176::SaveDict dict4(value4);
    const bh176::SaveValue* objects4 = dict4.objectForKey("dynamicObjects");
    const bh176::SaveValue* entry4 = dict4.objectAtIndex(objects4, 0);
    const bh176::SaveDict entry4_dict(*entry4);
    bh176::NpcFullState state4;
    bh176::ClientDynamicObject object4 =
        bh176::npc_full_factory(63, entry4_dict, &state4, &error);
    assert(error.empty());
    assert(object4.class_name == "Yak");
    assert(object4.unique_id == 124);
    assert(object4.status == bh176::ObjectLoadStatus::Recovered);
    assert(object4.status_reason.find("Yak own keys") != std::string::npos);
    assert(object4.status_reason.find("ownkey5 executed") != std::string::npos);
    // the NPC chain still ran (G1 group open, fullness stored)
    assert(state4.g1_present);
    assert(state4.fullness > 699.0f && state4.fullness < 701.0f);
    // the ownkey5 own keys, each into its own slot
    assert(state4.has_milk && state4.milk == 2.5f);
    assert(state4.has_hair && state4.hair == 12.0f);
    // a Dodo record must NOT get yak own keys
    assert(!state.has_milk);
    assert(!state.has_hair);

    // ---- DropBear 25: the NPC chain plus the eight own keys -------------
    {
        bh176::SaveValue value;
        std::string error;
        assert(bh176::parseXmlPlist(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>310</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>fullness</key><real>0.5</real><key>courageMeter</key><real>0.25</real><key>provokeMeter</key><real>0.75</real><key>dropSpeed</key><real>1.5</real><key>dropping</key><false/><key>onGround</key><true/><key>dropPos.x</key><integer>11</integer><key>dropPos.y</key><integer>12</integer><key>goalTreeDirection</key><integer>2</integer><key>saveTime</key><real>100.0</real></dict>
</array></dict></plist>
)", value, &error));
        const bh176::SaveDict dict(value);
        const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
        const bh176::SaveDict entry(*dict.objectAtIndex(objects, 0));
        bh176::NpcFullState state;
        bh176::ClientDynamicObject object =
            bh176::npc_full_factory(25, entry, &state, &error);
        assert(error.empty());
        assert(object.class_name == "DropBear");
        assert(object.status == bh176::ObjectLoadStatus::Recovered);
        assert(object.status_reason.find("DropBear own body") != std::string::npos);
        // the NPC chain still runs (G1 gate on fullness)
        assert(state.g1_present);
        assert(state.fullness == 0.5f);
        // own keys
        assert(state.has_courage_meter && state.courage_meter == 0.25f);
        assert(state.has_provoke_meter && state.provoke_meter == 0.75f);
        assert(state.has_drop_speed && state.drop_speed == 1.5f);
        assert(!state.dropping);
        assert(state.on_ground);
        assert(state.has_drop_pos && state.drop_pos_x == 11 &&
               state.drop_pos_y == 12);
        assert(state.has_goal_tree_direction && state.goal_tree_direction == 2);
        assert(state.has_save_time && state.save_time == 100.0f);
        assert(state.own_body_listing_decoded);
    }

    // ---- CaveTroll 39: dead byte + defendSquare + the state blob ----------
    {
        bh176::SaveValue value;
        std::string error;
        assert(bh176::parseXmlPlist(R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>311</integer><key>pos_x</key><integer>3</integer><key>pos_y</key><integer>4</integer><key>dead</key><false/><key>defendSquare.x</key><integer>5</integer><key>defendSquare.y</key><integer>6</integer><key>state</key><data>AQIDBA==</data></dict>
</array></dict></plist>
)", value, &error));
        const bh176::SaveDict dict(value);
        const bh176::SaveValue* objects = dict.objectForKey("dynamicObjects");
        const bh176::SaveDict entry(*dict.objectAtIndex(objects, 0));
        bh176::NpcFullState state;
        bh176::ClientDynamicObject object =
            bh176::npc_full_factory(39, entry, &state, &error);
        assert(object.class_name == "CaveTroll");
        assert(object.status == bh176::ObjectLoadStatus::Recovered);
        assert(object.status_reason.find("CaveTroll own body") != std::string::npos);
        assert(!state.dead);
        assert(state.has_defend_square && state.defend_square_x == 5 &&
               state.defend_square_y == 6);
        assert(state.has_state);
        assert(state.state_bytes == 4);          // 01020304
        assert(state.state_hex.size() == 8);
        assert(state.own_body_listing_decoded);
    }

    std::printf("test_npc_full: PASS\n");
    return 0;
}
