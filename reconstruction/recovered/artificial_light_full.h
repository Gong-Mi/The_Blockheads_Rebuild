// ArtificialLight loader (type 21) — the light child body, plus the shared
// lightDict decoder the four light-owning classes now use.
//
// ArtificialLight -(0x00a93c64, 412w) initWithWorld:dynamicWorld:saveDict:
// cache:parentObject: — decoded from its annotated listing:
//   [isClient] check + a release of the previous child
//   [super initWithWorld:dynamicWorld:saveDict:cache:]
//   downlight              -> boolValue -> byte
//   lightDirection         -> intValue  -> @96
//   contributionGridOrigin.x/.y -> intValue -> @84/+4 (the two-int struct)
//   radius                 -> @80
//   maxHeat                -> @76
//   maxBlue                -> @72
//   maxGreen               -> @68
//   maxRed                 -> @64
//   parentObject (the 5th argument) -> retained @100
//   tail: diameter@92 derived from radius; contributionGrid@56 setup;
//         [self addToTiles] — TILE REGISTRATION IS WORLD STATE: not run
//         offline (stated).
//
// The same key table serves the lightDict children of Workbench/GlowBlock/
// FireObject/Torch (their lightDict dictionaries carry exactly this shape;
// the light body is what those classes' records store).
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct LightFields {
    bool has_downlight = false;
    bool downlight = false;
    bool has_light_direction = false;
    std::int32_t light_direction = 0;      // @96
    bool has_contribution_origin = false;
    std::int32_t contribution_origin_x = 0;  // @84
    std::int32_t contribution_origin_y = 0;  // @88
    bool has_radius = false;
    std::int32_t radius = 0;               // @80
    bool has_max_heat = false;
    std::int32_t max_heat = 0;             // @76
    bool has_max_blue = false;
    std::int32_t max_blue = 0;             // @72
    bool has_max_green = false;
    std::int32_t max_green = 0;            // @68
    bool has_max_red = false;
    std::int32_t max_red = 0;              // @64
    bool tile_registration_not_run = true; // addToTiles is world state
};

// Decode a lightDict-shaped dictionary (the shared decoder).
LightFields light_from_dict(const SaveDict& light);

struct ArtificialLightFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    LightFields light;
    bool has_parent_object = false;  // the 5-arg's parentObject (not a save key)
};

ArtificialLightFullState artificial_light_full_load(const SaveDict& entry);

ClientDynamicObject artificial_light_full_factory(int type_id,
                                                  const SaveDict& entry,
                                                  ArtificialLightFullState* out_state,
                                                  std::string* error);

}  // namespace bh176
