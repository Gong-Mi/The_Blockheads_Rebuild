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
    // the downlight gate: a true value lands as lightDirection = 1
    if (fields.has_downlight && fields.downlight) {
        fields.has_light_direction = true;
        fields.light_direction = 1;
        fields.downlight_forces_direction = true;
    }
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
    // diameter = radius << 1 (the body's derived store @92)
    if (state.light.has_radius) {
        state.light.has_diameter = true;
        state.light.diameter = state.light.radius << 1;
    }
    state.has_parent_object = false;  // the 5th constructor argument
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
    std::string reason =
        "artificial light body (EXECUTED differential "
        "tools/test_specials_arm.py: call order + the memory-write trace): "
        "[self isClient] first (true -> [self release] + nil); super; the "
        "eight int reads stored in order maxRed@64 maxGreen@68 maxBlue@72 "
        "maxHeat@76 radius@80 contributionGridOrigin.x@84 .y@88 "
        "lightDirection@96; the downlight boolValue read stores NO own field "
        "and forces lightDirection := 1 when true; diameter@92 = radius << 1; "
        "contributionGrid@56/addedGrid@60 from two __wrap_calloc calls; "
        "parentObject@100 is the 5th argument; [self addToTiles] tile "
        "registration is world state - not run offline";
    attachRecoveredState(object, state, ObjectLoadStatus::Recovered,
                             std::move(reason), "ArtificialLightFullState");
    return object;
}

}  // namespace bh176
