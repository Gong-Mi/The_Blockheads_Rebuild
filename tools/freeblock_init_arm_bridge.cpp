// ctypes bridge for the FreeBlock loader differential (batch b4p).
// Mirrors tools/test_freeblock_init_arm.py BridgeInput exactly.
#include <cstdint>
#include <cstring>
#include <vector>

#include "freeblock_init.h"

using namespace blockheads::recovered;

namespace {

struct BridgeInput {
    std::uint32_t self_ptr;
    std::uint32_t super_returns_nil;
    std::uint32_t world_argument;
    std::uint32_t dynamic_world_argument;
    std::uint32_t save_dict_token;
    std::uint32_t cache_token;
    std::uint32_t world_ivar;
    std::uint32_t dynamic_world_ivar;
    std::int32_t pos_x;
    std::int32_t pos_y;
    std::uint32_t unique_id;
    std::uint32_t item_type_init;
    std::uint32_t hovers_init;
    float bounce_timer_value;
    float fall_speed_value;
    double creation_time_value;
    float float_vx_value;
    float float_vy_value;
    std::uint32_t hovers_value;
    std::uint32_t item_type_value;
    std::uint32_t data_a_value;
    std::uint32_t data_b_value;
    std::int32_t priority_id_value;
    std::uint32_t blockhead_answer;
    std::uint32_t sub_items[64];     // flattened sub-item types
    std::uint32_t sub_item_count;     // number of flattened types
    std::uint32_t elem_counts[16];   // per-element sub-item counts
    std::uint32_t elem_count;         // number of elements
    double world_time;
    std::uint32_t object_type_value;
    std::uint32_t tile_count;
    std::uint32_t tile_present[64];
    std::uint32_t tile_byte0[64];
};

}  // namespace

extern "C" std::uint32_t recovered_freeblock_init_run(
        const void* input, char* image_out, char* trace_out,
        std::uint32_t* ret_out, std::uint32_t* tiles_out) {
    const BridgeInput* in = static_cast<const BridgeInput*>(input);

    FreeblockInitInputs cfg;
    cfg.self_ptr = in->self_ptr;
    cfg.super_returns_nil = in->super_returns_nil != 0;
    cfg.world_argument = in->world_argument;
    cfg.dynamic_world_argument = in->dynamic_world_argument;
    cfg.save_dict_token = in->save_dict_token;
    cfg.cache_token = in->cache_token;
    cfg.world_ivar = in->world_ivar;
    cfg.dynamic_world_ivar = in->dynamic_world_ivar;
    cfg.pos_x = in->pos_x;
    cfg.pos_y = in->pos_y;
    cfg.unique_id = in->unique_id;
    cfg.item_type_init = in->item_type_init;
    cfg.hovers_init = in->hovers_init;
    cfg.bounce_timer_value = in->bounce_timer_value;
    cfg.fall_speed_value = in->fall_speed_value;
    cfg.creation_time_value = in->creation_time_value;
    cfg.float_vx_value = in->float_vx_value;
    cfg.float_vy_value = in->float_vy_value;
    cfg.hovers_value = in->hovers_value;
    cfg.item_type_value = in->item_type_value;
    cfg.data_a_value = in->data_a_value;
    cfg.data_b_value = in->data_b_value;
    cfg.priority_id_value = in->priority_id_value;
    cfg.blockhead_answer = in->blockhead_answer;
    cfg.sub_items.assign(in->sub_items, in->sub_items + in->sub_item_count);
    cfg.elem_counts.assign(in->elem_counts, in->elem_counts + in->elem_count);
    cfg.elem_count = in->elem_count;
    cfg.world_time = in->world_time;
    cfg.object_type_value = in->object_type_value;
    cfg.tiles.resize(in->tile_count);
    for (std::uint32_t i = 0; i < in->tile_count; ++i) {
        cfg.tiles[i].present = in->tile_present[i] != 0;
        cfg.tiles[i].byte0 = static_cast<std::uint8_t>(in->tile_byte0[i]);
    }

    FreeblockInitResult r = freeblock_init_with_world(cfg);
    std::memcpy(image_out, r.image.data(), r.image.size());
    std::uint32_t n = 0;
    for (const auto& call : r.calls) {
        if (n >= 512) return 0xFFFFFFFFu;
        std::uint8_t code = static_cast<std::uint8_t>(call.first);
        std::memcpy(trace_out + n * 8 + 0, &code, 1);
        std::uint32_t arg = call.second;
        std::memcpy(trace_out + n * 8 + 4, &arg, 4);
        ++n;
    }
    *ret_out = r.return_value;
    *tiles_out = static_cast<std::uint32_t>(r.tiles_consumed);
    return n;
}
