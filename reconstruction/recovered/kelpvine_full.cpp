// KelpPlant / VinePlant loader implementation. See kelpvine_full.h.
#include "kelpvine_full.h"

namespace bh176 {

KelpVineFullState kelpvine_full_load(const SaveDict& entry, double world_time,
                                     int type_id) {
    KelpVineFullState state;
    state.is_kelp = (type_id == 34);

    // --- the Plant chain (executed b4b), reused verbatim ---
    state.plant = plant_full_load({entry, world_time});

    // --- own keys (executed b4n/b4o): the mirrored occupied axis ---
    const char* occupied_key =
        state.is_kelp ? "numberOfOccupiedTilesAbove" : "numberOfOccupiedTilesBelow";
    if (const SaveValue* occupied = entry.objectForKey(occupied_key)) {
        state.has_occupied_tiles = true;
        state.occupied_tiles =
            static_cast<std::int32_t>(SaveDict::intValue(occupied));
    }
    if (const SaveValue* timer = entry.objectForKey("growthTimer")) {
        state.has_growth_timer = true;
        state.growth_timer = SaveDict::floatValue(timer);  // @176 both
    }
    if (const SaveValue* food = entry.objectForKey("availableFood")) {
        state.has_available_food = true;
        state.available_food = SaveDict::floatValue(food);
    }
    return state;
}

ClientDynamicObject kelpvine_full_factory(int type_id, const SaveDict& entry,
                                          double world_time,
                                          KelpVineFullState* out_state,
                                          std::string* error) {
    if (error) error->clear();
    const KelpVineFullState state = kelpvine_full_load(entry, world_time, type_id);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    std::string reason =
        state.is_kelp
            ? "kelp full chain: DynamicObject base + Plant chain (executed "
              "b4b) + own keys (executed b4n loader, presence-gated)"
            : "vine full chain: DynamicObject base + Plant chain (executed "
              "b4b) + own keys (executed b4o loader, presence-gated)";
    attachRecoveredState(object, state, ObjectLoadStatus::Recovered,
                             std::move(reason), "KelpVineFullState");
    return object;
}

}  // namespace bh176
