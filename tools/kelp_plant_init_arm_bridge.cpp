// Flat C ABI bridge for the b4n KelpPlant loader differential.
#include "kelp_plant_init.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::KelpInitInputs;
using blockheads::recovered::KelpTileAnswer;

namespace {
constexpr std::uint32_t kMaxTiles = 64;
}

typedef struct KelpBridgeInput {
    std::uint32_t self_ptr;
    std::uint32_t super_returns_nil;
    std::uint32_t world_argument;
    std::uint32_t dynamic_world_argument;
    std::uint32_t save_dict_token;
    std::uint32_t cache_token;
    std::uint32_t tree_density_argument;
    std::uint32_t season_offset_argument;
    std::uint32_t world_ivar;
    std::uint32_t dynamic_world_ivar;
    std::int32_t pos_x;
    std::int32_t pos_y;
    std::int32_t occupied_init;
    float growth_timer_init;
    float available_food_init;
    float age_init;
    float max_age;
    float growth_rate;
    std::int32_t frozen;
    std::uint32_t occupied_box_token;
    std::uint32_t growth_timer_box_token;
    std::uint32_t available_food_box_token;
    std::uint32_t save_time_box_token;
    std::int32_t occupied_value;
    float growth_timer_value;
    float available_food_value;
    double save_time_value;
    double world_time;
    std::int64_t lrand48_value;
    std::uint32_t is_growing_in_compost;
    std::uint32_t object_type_value;
    std::uint32_t tile_count;
    std::uint32_t tile_present[kMaxTiles];
    std::uint32_t tile_byte0[kMaxTiles];
    std::uint32_t tile_byte11[kMaxTiles];
} KelpBridgeInput;

extern "C" {

std::uint32_t recovered_kelp_plant_init_run(const KelpBridgeInput* cfg,
                                            std::uint8_t* image_out,
                                            std::uint8_t* trace_out,
                                            std::uint32_t* return_out,
                                            std::uint32_t* tiles_out) {
    if (cfg->tile_count > kMaxTiles) return 0xFFFFFFFFu;

    KelpInitInputs in;
    in.self_ptr = cfg->self_ptr;
    in.super_returns_nil = cfg->super_returns_nil != 0;
    in.world_argument = cfg->world_argument;
    in.dynamic_world_argument = cfg->dynamic_world_argument;
    in.save_dict_token = cfg->save_dict_token;
    in.cache_token = cfg->cache_token;
    in.tree_density_argument = cfg->tree_density_argument;
    in.season_offset_argument = cfg->season_offset_argument;
    in.world_ivar = cfg->world_ivar;
    in.dynamic_world_ivar = cfg->dynamic_world_ivar;
    in.pos_x = cfg->pos_x;
    in.pos_y = cfg->pos_y;
    in.occupied_init = cfg->occupied_init;
    in.growth_timer_init = cfg->growth_timer_init;
    in.available_food_init = cfg->available_food_init;
    in.age_init = cfg->age_init;
    in.max_age = cfg->max_age;
    in.growth_rate = cfg->growth_rate;
    in.frozen = static_cast<std::int8_t>(cfg->frozen);
    in.occupied_box_token = cfg->occupied_box_token;
    in.growth_timer_box_token = cfg->growth_timer_box_token;
    in.available_food_box_token = cfg->available_food_box_token;
    in.save_time_box_token = cfg->save_time_box_token;
    in.occupied_value = cfg->occupied_value;
    in.growth_timer_value = cfg->growth_timer_value;
    in.available_food_value = cfg->available_food_value;
    in.save_time_value = cfg->save_time_value;
    in.world_time = cfg->world_time;
    in.lrand48_value = cfg->lrand48_value;
    in.is_growing_in_compost = cfg->is_growing_in_compost != 0;
    in.object_type_value = cfg->object_type_value;
    for (std::uint32_t i = 0; i < cfg->tile_count; ++i) {
        KelpTileAnswer answer;
        answer.present = cfg->tile_present[i] != 0;
        answer.byte0 = static_cast<std::uint8_t>(cfg->tile_byte0[i] & 0xff);
        answer.byte11 = static_cast<std::uint8_t>(cfg->tile_byte11[i] & 0xff);
        in.tiles.push_back(answer);
    }

    const auto res = blockheads::recovered::kelp_plant_init_with_world(in);
    for (std::size_t i = 0; i < blockheads::recovered::kKelpImageSize; ++i) {
        image_out[i] = res.image[i];
    }
    *return_out = res.return_value;
    *tiles_out = static_cast<std::uint32_t>(res.tiles_consumed);

    const std::uint32_t n = res.calls.size() > blockheads::recovered::kKelpMaxTrace
                                ? blockheads::recovered::kKelpMaxTrace
                                : static_cast<std::uint32_t>(res.calls.size());
    for (std::uint32_t i = 0; i < n; ++i) {
        std::uint8_t* rec = trace_out + i * 8;
        rec[0] = static_cast<std::uint8_t>(res.calls[i].first);
        rec[1] = rec[2] = rec[3] = 0;
        const std::uint32_t arg = res.calls[i].second;
        rec[4] = static_cast<std::uint8_t>(arg & 0xff);
        rec[5] = static_cast<std::uint8_t>((arg >> 8) & 0xff);
        rec[6] = static_cast<std::uint8_t>((arg >> 16) & 0xff);
        rec[7] = static_cast<std::uint8_t>((arg >> 24) & 0xff);
    }
    return n;
}

}  // extern "C"
