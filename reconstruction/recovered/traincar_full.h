// TrainCar family loader (types 41 HandCar, 42 SteamTrain, 44 PassengerCar):
// the TrainCar chain + SteamTrain's own keys, decoded from the annotated
// listings (emit_annotated_method.py over the pinned ELF; coverage gates OK).
//
// TrainCar -(0x00a3892c, 363w), the family's shared chain:
//   [self maxNumberOfRiders]; per rider i: the FORMATTED key
//     currentBlockheadIndex_%d (stringWithFormat:) -> objectForKey ->
//     unsignedLongLongValue -> the per-rider savedBlockheadIndex record
//     (offline: every key matching the prefix is captured, index-ordered)
//   rightCarID  -> unsignedLongLongValue -> remoteRightCarID@152 (u64)
//   leftCarID   -> unsignedLongLongValue -> remoteLeftCarID@144 (u64)
//   engineCarID -> unsignedLongLongValue -> remoteEngineCarID@160 (u64)
//   [self loadDerivedStuff] tail hook (no save state)
//   ownerID     -> retain -> @36 (DynamicObject slot)
//   engineIsRight -> boolValue -> STRB @180
//
// SteamTrain -(0x00d18834, 180w) adds its own keys (super = TrainCar):
//   fuelFraction -> floatValue -> str @260
//   hasFuel      -> boolValue  -> STRB @268
//   goingRight   -> boolValue  -> STRB @252
//   stopped      -> boolValue  -> STRB @325
//
// HandCar (60w) and PassengerCar (60w) are the forwarder5b ZERO-own-key
// super-only forwarders over TrainCar (own_keys empty in the batch's
// evidence): their whole record domain is the base + the TrainCar chain.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>
#include <vector>

namespace bh176 {

struct TrainCarFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // the TrainCar chain
    bool has_engine_car_id = false;
    std::uint64_t engine_car_id = 0;      // remoteEngineCarID@160
    bool has_left_car_id = false;
    std::uint64_t left_car_id = 0;        // remoteLeftCarID@144
    bool has_right_car_id = false;
    std::uint64_t right_car_id = 0;       // remoteRightCarID@152
    bool has_owner_id = false;            // @36
    bool has_engine_is_right = false;
    bool engine_is_right = false;         // @180 STRB
    // the per-rider formatted keys (index-ordered)
    std::vector<std::pair<int, std::uint64_t>> saved_blockhead_indices;
    // SteamTrain own keys
    bool has_fuel_fraction = false;
    float fuel_fraction = 0.0f;           // @260
    bool has_fuel = false;                // @268 STRB
    bool going_right = false;             // @252 STRB
    bool stopped = false;                 // @325 STRB
    bool tail_hook_not_run = true;        // loadDerivedStuff carries no save state
};

TrainCarFullState traincar_full_load(const SaveDict& entry, int type_id);

ClientDynamicObject traincar_full_factory(int type_id, const SaveDict& entry,
                                          TrainCarFullState* out_state,
                                          std::string* error);

}  // namespace bh176
