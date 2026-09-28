// TrainCar family test: the TrainCar chain + SteamTrain's own keys, incl. the
// formatted per-rider keys and the u64 car IDs.
#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "traincar_full.h"

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

    // ---- HandCar 41: zero own keys, the TrainCar chain only ---------------
    const char* kHandCar = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>290</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>engineCarID</key><integer>1</integer><key>leftCarID</key><integer>2</integer><key>rightCarID</key><integer>3</integer><key>engineIsRight</key><true/><key>ownerID</key><string>c</string><key>currentBlockheadIndex_0</key><integer>42</integer></dict>
</array></dict></plist>
)";
    const bh176::SaveDict handcar = entryOf(kHandCar, value, error);
    bh176::TrainCarFullState state;
    bh176::ClientDynamicObject object =
        bh176::traincar_full_factory(41, handcar, &state, &error);
    assert(error.empty());
    assert(object.class_name == "HandCar");
    assert(object.status == bh176::ObjectLoadStatus::Recovered);
    assert(object.status_reason.find("zero-own-key") != std::string::npos);
    assert(state.has_engine_car_id && state.engine_car_id == 1);
    assert(state.has_left_car_id && state.left_car_id == 2);
    assert(state.has_right_car_id && state.right_car_id == 3);
    assert(state.has_owner_id);
    assert(state.has_engine_is_right && state.engine_is_right);
    assert(state.saved_blockhead_indices.size() == 1);
    assert(state.saved_blockhead_indices[0].first == 0);
    assert(state.saved_blockhead_indices[0].second == 42);

    // ---- the per-rider keys are index-ordered (two riders) ----------------
    const char* kTwoRiders = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>292</integer><key>pos_x</key><integer>5</integer><key>pos_y</key><integer>6</integer><key>currentBlockheadIndex_1</key><integer>66</integer><key>currentBlockheadIndex_0</key><integer>55</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value2;
    const bh176::SaveDict two = entryOf(kTwoRiders, value2, error);
    bh176::TrainCarFullState state2;
    bh176::traincar_full_factory(44, two, &state2, &error);
    assert(state2.saved_blockhead_indices.size() == 2);
    assert(state2.saved_blockhead_indices[0] ==
           std::make_pair(0, std::uint64_t{55}));
    assert(state2.saved_blockhead_indices[1] ==
           std::make_pair(1, std::uint64_t{66}));

    // ---- SteamTrain 42: the four own keys on top of the chain -------------
    const char* kSteam = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>291</integer><key>pos_x</key><integer>3</integer><key>pos_y</key><integer>4</integer><key>engineCarID</key><integer>7</integer><key>fuelFraction</key><real>0.5</real><key>hasFuel</key><true/><key>goingRight</key><false/><key>stopped</key><true/></dict>
</array></dict></plist>
)";
    bh176::SaveValue value3;
    const bh176::SaveDict steam = entryOf(kSteam, value3, error);
    bh176::TrainCarFullState state3;
    bh176::ClientDynamicObject object3 =
        bh176::traincar_full_factory(42, steam, &state3, &error);
    assert(object3.class_name == "SteamTrain");
    assert(object3.status == bh176::ObjectLoadStatus::Recovered);
    assert(object3.status_reason.find("fuelFraction@260") != std::string::npos);
    assert(state3.has_engine_car_id && state3.engine_car_id == 7);
    assert(state3.has_fuel_fraction && state3.fuel_fraction == 0.5f);
    assert(state3.has_fuel);
    assert(!state3.going_right);
    assert(state3.stopped);

    // ---- u64 carrier: a large car ID survives as 64-bit -------------------
    const char* kBigId = R"(<?xml version="1.0"?>
<plist version="1.0"><dict><key>dynamicObjects</key><array>
<dict><key>uniqueID</key><integer>293</integer><key>pos_x</key><integer>1</integer><key>pos_y</key><integer>2</integer><key>rightCarID</key><integer>4294967297</integer></dict>
</array></dict></plist>
)";
    bh176::SaveValue value4;
    const bh176::SaveDict big = entryOf(kBigId, value4, error);
    bh176::TrainCarFullState state4;
    bh176::traincar_full_factory(41, big, &state4, &error);
    assert(state4.has_right_car_id &&
           state4.right_car_id == 4294967297ULL);  // 2^32 + 1

    std::printf("test_traincar_full: PASS\n");
    return 0;
}
