// ArtificialLight loader implementation. See artificial_light_full.h.
#include "artificial_light_full.h"

namespace bh176 {

namespace {

std::int32_t intKey(const SaveDict& d, const char* key, bool* present) {
    const SaveValue* v = d.objectForKey(key);
    if (v == nullptr) {
        if (present) *present = false;
        return 0;
    }
    if (present) *present = true;
    return static_cast<std::int32_t>(SaveDict::intValue(v));
}

}  // namespace

LightFields light_from_dict(const SaveDict& light) {
    LightFields fields;
    const SaveValue* down = light.objectForKey("downlight");
    if (down != nullptr) {
        fields.has_downlight = true;
        fields.downlight = SaveDict::boolValue(down);
    }
    fields.light_direction =
        intKey(light, "lightDirection", &fields.has_light_direction);
    fields.contribution_origin_x = intKey(
        light, "contributionGridOrigin.x", &fields.has_contribution_origin);
    if (fields.has_contribution_origin) {
        bool has_y = false;
        fields.contribution_origin_y =
            intKey(light, "contributionGridOrigin.y", &has_y);
        fields.has_contribution_origin = has_y;
    }
    fields.radius = intKey(light, "radius", &fields.has_radius);
    fields.max_heat = intKey(light, "maxHeat", &fields.has_max_heat);
    fields.max_blue = intKey(light, "maxBlue", &fields.has_max_blue);
    fields.max_green = intKey(light, "maxGreen", &fields.has_max_green);
    fields.max_red = intKey(light, "maxRed", &fields.has_max_red);
    fields.tile_registration_not_run = true;
    return fields;
}

ArtificialLightFullState artificial_light_full_load(const SaveDict& entry) {
    ArtificialLightFullState state;
    state.unique_id = static_cast<std::uint64_t>(
        SaveDict::unsignedLongValue(entry.objectForKey("uniqueID")));
    state.pos_x = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_x")));
    state.pos_y = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_y")));
    // The record itself carries the light keys (the dictionary a parent's
    // lightDict holds); parentObject is a constructor argument, not a key.
    state.light = light_from_dict(entry);
    state.has_parent_object = false;
    return state;
}

// The reads are captured key-by-key (order-insensitive), but the body's
// actual order is maxRed..downlight (ARM-attested, see the header).
ClientDynamicObject artificial_light_full_factory(
    int type_id, const SaveDict& entry, ArtificialLightFullState* out_state,
    std::string* error) {
    if (error) error->clear();
    const ArtificialLightFullState state = artificial_light_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "artificial light body: the light key table decoded from the 5-arg "
        "initWithWorld:dynamicWorld:saveDict:cache:parentObject: listing "
        "(downlight/lightDirection/contributionGridOrigin.x+.y/radius/"
        "maxRed/maxGreen/maxBlue/maxHeat); parentObject is a constructor "
        "argument; tile registration (addToTiles) is world state - not run "
        "offline";
    return object;
}

}  // namespace bh176
