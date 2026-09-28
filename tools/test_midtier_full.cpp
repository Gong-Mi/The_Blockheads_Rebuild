// Mid-tier family test: per-class key tables through the production factory
// (widths from the annotated listings, incl. the STRH/STRB truncations and
// Boat's -1 probe default).
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "midtier_full.h"

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

const bh176::SaveDict load(int type_id, const char* plist,
                           bh176::SaveValue& value, std::string& error,
                           bh176::MidtierFullState* state) {
    const bh176::SaveDict entry = entryOf(plist, value, error);
    bh176::ClientDynamicObject object =
        bh176::midtier_full_factory(type_id, entry, state, &error);
    assert(error.empty());
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("midtier") != std::string::npos);
    return entry;
}

}  // namespace

int main() {
    bh176::SaveValue value;
    std::string error;

    // ---- Window: itemType word + ownerID object ---------------------------
    {
        bh176::MidtierFullState s;
        load(31, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>260</integer><key>itemType</key><integer>5</integer><key>ownerID</key><string>c</string></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("itemType") == 5.0);
        assert(s.objects.at("ownerID"));
    }

    // ---- Rail: the bool -> BRYTE truncation -------------------------------
    {
        bh176::MidtierFullState s;
        load(40, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>261</integer><key>configuration</key><integer>3</integer><key>ownedByStation</key><true/><key>itemType</key><integer>8</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("configuration") == 3.0);
        assert(s.numbers.at("ownedByStation") == 1.0);
        assert(s.numbers.at("itemType") == 8.0);
    }

    // ---- Boat: the probe overwrite + the -1 default -----------------------
    {
        bh176::MidtierFullState s;
        load(32, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>262</integer><key>currentBlockheadIndex</key><integer>4</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.had_blockhead_index);
        assert(s.saved_blockhead_index == 4);
        assert(s.tail_hook == "loadDerivedStuff");

        bh176::MidtierFullState s2;
        load(32, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>263</integer></dict>
</array></dict></plist>
)", value, error, &s2);
        assert(!s2.had_blockhead_index);
        assert(s2.saved_blockhead_index == -1);   // the unconditional default
    }

    // ---- Ladder: paintColor unsignedInt -> STRH ---------------------------
    {
        bh176::MidtierFullState s;
        load(19, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>264</integer><key>itemType</key><integer>6</integer><key>ownerID</key><string>c</string><key>paintColor</key><integer>70000</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("paintColor") == 4464.0);  // 70000 -> STRH
        assert(s.objects.at("ownerID"));
    }

    // ---- Egg: breed read INSIDE the genesDict child (ARM-attested) --------
    {
        bh176::MidtierFullState s;
        load(30, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>265</integer><key>genesDict</key><dict><key>breed</key><integer>70000</integer></dict><key>hatchTimer</key><real>1.5</real></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("breed") == 4464.0);       // STRH truncation, nested
        assert(s.numbers.at("hatchTimer") == 1.5);
        assert(s.objects.at("genesDict"));
    }
    {
        // control: a TOP-LEVEL breed is NOT read (the body goes through the
        // child dictionary only); an absent child leaves breed absent.
        bh176::MidtierFullState s;
        load(30, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>266</integer><key>breed</key><integer>5</integer><key>hatchTimer</key><real>2.0</real></dict>
</array></dict></plist>
)", value, error, &s);
        assert(!s.present.at("breed"));
        assert(!s.objects.at("genesDict"));
        assert(s.numbers.at("hatchTimer") == 2.0);
    }

    // ---- Column / Stairs: paintColor STRH at the per-class offsets --------
    {
        bh176::MidtierFullState s;
        load(53, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>266</integer><key>configuration</key><integer>2</integer><key>itemType</key><integer>7</integer><key>paintColor</key><integer>3</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("paintColor") == 3.0);
        assert(s.numbers.at("configuration") == 2.0);
    }
    {
        bh176::MidtierFullState s;
        load(54, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>267</integer><key>configuration</key><integer>2</integer><key>itemType</key><integer>7</integer><key>paintColor</key><integer>3</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("paintColor") == 3.0);
    }

    // ---- Door: blocked byte + the two object slots ------------------------
    {
        bh176::MidtierFullState s;
        load(20, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>268</integer><key>blocked</key><true/><key>ironPlaceClientID</key><string>x</string><key>itemType</key><integer>4</integer><key>ownerID</key><string>c</string></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("blocked") == 1.0);
        assert(s.objects.at("ironPlaceClientID"));
        assert(s.objects.at("ownerID"));
        assert(s.numbers.at("itemType") == 4.0);
    }

    // ---- Wire: the three ints --------------------------------------------
    {
        bh176::MidtierFullState s;
        load(38, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>269</integer><key>configuration</key><integer>1</integer><key>itemType</key><integer>2</integer><key>solidConfiguration</key><integer>3</integer><key>ownerID</key><string>c</string></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("configuration") == 1.0);
        assert(s.numbers.at("solidConfiguration") == 3.0);
        assert(s.objects.at("ownerID"));
    }

    // ---- ElevatorMotor: ARM-attested widths/conversions ------------------
    {
        // availableElectricity is UNSIGNED-int -> STRH@60 (truncates), minY
        // and maxY are unsigned words @64/@68 (no truncation).
        bh176::MidtierFullState s;
        load(55, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>270</integer><key>itemType</key><integer>3</integer><key>ownerID</key><string>c</string><key>availableElectricity</key><integer>70000</integer><key>minY</key><integer>1</integer><key>maxY</key><integer>2</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("availableElectricity") == 4464.0);  // STRH
        assert(s.numbers.at("minY") == 1.0);                      // word
        assert(s.numbers.at("maxY") == 2.0);                      // word
    }
    {
        // ElevatorShaft: pos.x/.y words @60/@64, paintColor UINT->STRH@84.
        bh176::MidtierFullState s;
        load(56, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>271</integer><key>itemType</key><integer>3</integer><key>ownerID</key><string>c</string><key>lastKnownMotorPos.x</key><integer>10</integer><key>lastKnownMotorPos.y</key><integer>20</integer><key>paintColor</key><integer>70000</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.at("lastKnownMotorPos.x") == 10.0);
        assert(s.numbers.at("lastKnownMotorPos.y") == 20.0);
        assert(s.numbers.at("paintColor") == 4464.0);             // STRH
    }

    // ---- forwarder5b zeros: no own keys, base-only record domain --------
    {
        bh176::MidtierFullState s;
        load(22, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>280</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>itemType</key><integer>99</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.numbers.empty());   // extra keys are ignored, never invented
        assert(s.objects.empty());
        assert(s.tail_hook.empty());
    }
    {
        bh176::MidtierFullState s;
        load(29, R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>281</integer><key>pos_x</key><integer>3</integer><key>pos_y</key><integer>4</integer></dict>
</array></dict></plist>
)", value, error, &s);
        assert(s.tail_hook == "initSubDerivedItems");
        assert(s.numbers.empty());
    }

    std::printf("test_midtier_full: PASS\n");
    return 0;
}
