// Optional ARM differential bridge: exposes the recovered Tree
// growInTimeSinceSaved: contract (stage 1, nil-tile path) to
// tools/test_tree_grow_arm.py, which executes the ORIGINAL ARM method under
// Unicorn and compares the instance image and message trace byte-for-byte
// against this module (built at -O0 and -O2).
#include "tree_grow_in_time.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::TreeGrowCall;
using blockheads::recovered::TreeGrowInputs;

extern "C" {

// image_out: kTreeGrowImageSize bytes. trace_out: kTreeGrowMaxTrace * 8
// bytes, one (code u8, pad u24, arg u32 LE) record per call. Returns the
// call count.
std::uint32_t recovered_tree_grow_run(
    std::uint8_t is_static_tree, std::uint8_t is_growing_in_compost,
    double world_time, double time_since_saved, std::uint8_t dead,
    float max_age, float age, float growth_counter, float growth_rate,
    std::int32_t max_height, std::int32_t height,
    std::int32_t max_height_reached, std::int32_t pos_x, std::int32_t pos_y,
    std::uint32_t world_token, std::uint32_t dynamic_world_token,
    std::int32_t height_after_increment,
    std::int32_t max_height_reached_after_increment,
    std::uint8_t has_tile,
    std::uint8_t tile_sun_light,
    std::uint16_t tile_artificial_light_r,
    std::uint16_t tile_artificial_light_g,
    std::uint16_t tile_artificial_light_b,
    std::uint8_t* image_out,
    std::uint8_t* trace_out) {
    TreeGrowInputs inputs;
    inputs.is_static_tree = is_static_tree;
    inputs.is_growing_in_compost = is_growing_in_compost;
    inputs.world_time = world_time;
    inputs.time_since_saved = time_since_saved;
    inputs.dead = dead;
    inputs.max_age = max_age;
    inputs.age = age;
    inputs.growth_counter = growth_counter;
    inputs.growth_rate = growth_rate;
    inputs.max_height = max_height;
    inputs.height = height;
    inputs.max_height_reached = max_height_reached;
    inputs.pos_x = pos_x;
    inputs.pos_y = pos_y;
    inputs.world_token = world_token;
    inputs.dynamic_world_token = dynamic_world_token;
    inputs.height_after_increment = height_after_increment;
    inputs.max_height_reached_after_increment =
        max_height_reached_after_increment;
    inputs.has_tile = has_tile;
    inputs.tile_sun_light = tile_sun_light;
    inputs.tile_artificial_light_r = tile_artificial_light_r;
    inputs.tile_artificial_light_g = tile_artificial_light_g;
    inputs.tile_artificial_light_b = tile_artificial_light_b;

    const auto result = blockheads::recovered::tree_grow_in_time_since_saved(inputs);
    for (std::size_t i = 0; i < blockheads::recovered::kTreeGrowImageSize; ++i) {
        image_out[i] = result.image[i];
    }
    const std::uint32_t n =
        result.calls.size() > blockheads::recovered::kTreeGrowMaxTrace
            ? blockheads::recovered::kTreeGrowMaxTrace
            : static_cast<std::uint32_t>(result.calls.size());
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint8_t* rec = trace_out + i * 8;
        rec[0] = static_cast<std::uint8_t>(result.calls[i].first);
        rec[1] = rec[2] = rec[3] = 0;
        const std::uint32_t arg = result.calls[i].second;
        rec[4] = static_cast<std::uint8_t>(arg & 0xff);
        rec[5] = static_cast<std::uint8_t>((arg >> 8) & 0xff);
        rec[6] = static_cast<std::uint8_t>((arg >> 16) & 0xff);
        rec[7] = static_cast<std::uint8_t>((arg >> 24) & 0xff);
    }
    return n;
}

}  // extern "C"
