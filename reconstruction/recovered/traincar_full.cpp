// TrainCar family loader implementation. See traincar_full.h.
#include "traincar_full.h"

#include <algorithm>
#include <cstdlib>

namespace bh176 {

namespace {

// Parse "currentBlockheadIndex_%d" style keys; returns -1 for non-matching.
int riderIndexFromKey(const std::string& key) {
    static const std::string prefix = "currentBlockheadIndex_";
    if (key.size() <= prefix.size() ||
        key.compare(0, prefix.size(), prefix) != 0) {
        return -1;
    }
    const std::string digits = key.substr(prefix.size());
    for (const char c : digits) {
        if (c < '0' || c > '9') return -1;
    }
    return std::atoi(digits.c_str());
}

}  // namespace

TrainCarFullState traincar_full_load(const SaveDict& entry, int type_id) {
    TrainCarFullState state;

    // --- DynamicObject base loader (executed contract) ---
    state.unique_id =
        static_cast<std::uint64_t>(SaveDict::unsignedLongValue(
            entry.objectForKey("uniqueID")));
    state.pos_x = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_x")));
    state.pos_y = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_y")));
    const SaveValue* float_pos = entry.objectForKey("floatPos");
    if (SaveDict::count(float_pos) >= 2) {
        state.float_pos_x =
            SaveDict::floatValue(entry.objectAtIndex(float_pos, 0));
        state.float_pos_y =
            SaveDict::floatValue(entry.objectAtIndex(float_pos, 1));
        state.has_float_pos = true;
    }

    // --- the TrainCar chain (annotated-listing decode) ---
    if (const SaveValue* v = entry.objectForKey("engineCarID")) {
        state.has_engine_car_id = true;
        state.engine_car_id = SaveDict::unsignedLongValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("leftCarID")) {
        state.has_left_car_id = true;
        state.left_car_id = SaveDict::unsignedLongValue(v);
    }
    if (const SaveValue* v = entry.objectForKey("rightCarID")) {
        state.has_right_car_id = true;
        state.right_car_id = SaveDict::unsignedLongValue(v);
    }
    state.has_owner_id = entry.objectForKey("ownerID") != nullptr;
    const SaveValue* engine_right = entry.objectForKey("engineIsRight");
    if (engine_right != nullptr) {
        state.has_engine_is_right = true;
        state.engine_is_right = SaveDict::boolValue(engine_right);  // STRB @180
    }
    // the formatted per-rider keys: every matching key is captured,
    // index-ordered (the loop's own bound is [self maxNumberOfRiders], a
    // class constant outside the record).
    for (const auto& kv : entry.value().dict) {
        const int index = riderIndexFromKey(kv.first);
        if (index < 0) continue;
        state.saved_blockhead_indices.emplace_back(
            index, SaveDict::unsignedLongValue(&kv.second));
    }
    std::sort(state.saved_blockhead_indices.begin(),
              state.saved_blockhead_indices.end());

    // --- SteamTrain own keys (its super is TrainCar) ---
    if (type_id == 42) {
        if (const SaveValue* v = entry.objectForKey("fuelFraction")) {
            state.has_fuel_fraction = true;
            state.fuel_fraction = SaveDict::floatValue(v);  // @260
        }
        state.has_fuel = entry.objectForKey("hasFuel") != nullptr;
        const SaveValue* going = entry.objectForKey("goingRight");
        if (going != nullptr) state.going_right = SaveDict::boolValue(going);
        const SaveValue* stopped = entry.objectForKey("stopped");
        if (stopped != nullptr) state.stopped = SaveDict::boolValue(stopped);
    }
    state.tail_hook_not_run = true;
    return state;
}

ClientDynamicObject traincar_full_factory(int type_id, const SaveDict& entry,
                                          TrainCarFullState* out_state,
                                          std::string* error) {
    if (error) error->clear();
    const TrainCarFullState state = traincar_full_load(entry, type_id);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        type_id == 42
            ? "steamtrain full chain: DynamicObject base + the TrainCar "
              "chain (listing decode: formatted currentBlockheadIndex_%d "
              "rider keys, the three car IDs, engineIsRight) + own keys "
              "fuelFraction@260/hasFuel@268/goingRight@252/stopped@325; the "
              "loadDerivedStuff tail hook carries no save state"
            : "traincar zero-own-key forwarder (forwarder5b): DynamicObject "
              "base + the TrainCar chain (listing decode) only";
    return object;
}

}  // namespace bh176
