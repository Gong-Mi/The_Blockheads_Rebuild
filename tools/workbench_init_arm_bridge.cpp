// ctypes bridge for the Workbench loader differential (batch b4q).
// Mirrors tools/test_workbench_init_arm.py BridgeInput exactly.
#include <cstdint>
#include <cstring>
#include <vector>

#include "workbench_init.h"

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
    std::uint32_t cache_ivar;
    std::int32_t pos_x;
    std::int32_t pos_y;
    std::uint32_t is_in_use_init;
    std::uint32_t workbench_type_value;
    std::uint32_t selected_index_value;
    float x_scroll_value;
    std::uint32_t level_value;
    float craft_progress_value;
    float hurry_timer_value;
    float hurry_seconds_value;
    std::uint32_t hurrying_value;
    std::uint32_t hurry_cost_value;
    float fire_spread_value;
    float fuel_fraction_value;
    std::uint32_t has_fuel_value;
    double last_world_time_value;
    std::uint32_t is_in_use_fuel_value;
    std::uint32_t available_elec_value;
    std::int32_t blockhead_index_fuel_value;
    std::uint32_t is_in_use;
    std::uint32_t crafting_v2_present;
    std::uint32_t craftable_object_type;
    std::uint32_t crafting_v1_present;
    std::uint32_t crafting_item_nonnil;
    std::uint32_t craftable_item_stret_type;
    std::uint32_t count_created_value;
    std::uint32_t count_left_value;
    std::uint32_t count_value;
    std::uint32_t slot_count;
    std::uint32_t slot_elem_counts[16];
    std::uint32_t sub_types[64];
    std::uint32_t sub_type_count;
    std::uint32_t current_blockhead;
    std::uint32_t current_fuel_blockhead;
    std::uint32_t light_dict_present;
    std::uint32_t light_answer;
    std::uint32_t sub_page_base;
};

}  // namespace

extern "C" std::uint32_t recovered_workbench_init_run(
        const void* input, char* image_out, char* trace_out,
        std::uint32_t* ret_out) {
    const BridgeInput* in = static_cast<const BridgeInput*>(input);

    WorkbenchInitInputs cfg;
    cfg.self_ptr = in->self_ptr;
    cfg.super_returns_nil = in->super_returns_nil != 0;
    cfg.world_argument = in->world_argument;
    cfg.dynamic_world_argument = in->dynamic_world_argument;
    cfg.save_dict_token = in->save_dict_token;
    cfg.cache_token = in->cache_token;
    cfg.world_ivar = in->world_ivar;
    cfg.dynamic_world_ivar = in->dynamic_world_ivar;
    cfg.cache_ivar = in->cache_ivar;
    cfg.pos_x = in->pos_x;
    cfg.pos_y = in->pos_y;
    cfg.is_in_use_init = in->is_in_use_init;
    cfg.workbench_type_value = in->workbench_type_value;
    cfg.selected_index_value = in->selected_index_value;
    cfg.x_scroll_value = in->x_scroll_value;
    cfg.level_value = in->level_value;
    cfg.craft_progress_value = in->craft_progress_value;
    cfg.hurry_timer_value = in->hurry_timer_value;
    cfg.hurry_seconds_value = in->hurry_seconds_value;
    cfg.hurrying_value = in->hurrying_value;
    cfg.hurry_cost_value = in->hurry_cost_value;
    cfg.fire_spread_value = in->fire_spread_value;
    cfg.fuel_fraction_value = in->fuel_fraction_value;
    cfg.has_fuel_value = in->has_fuel_value;
    cfg.last_world_time_value = in->last_world_time_value;
    cfg.is_in_use_fuel_value = in->is_in_use_fuel_value;
    cfg.available_elec_value = in->available_elec_value;
    cfg.blockhead_index_fuel_value = in->blockhead_index_fuel_value;
    cfg.is_in_use = in->is_in_use;
    cfg.crafting_v2_present = in->crafting_v2_present != 0;
    cfg.craftable_object_type = in->craftable_object_type;
    cfg.crafting_v1_present = in->crafting_v1_present != 0;
    cfg.crafting_item_nonnil = in->crafting_item_nonnil != 0;
    cfg.craftable_item_stret_type = in->craftable_item_stret_type;
    cfg.count_created_value = in->count_created_value;
    cfg.count_left_value = in->count_left_value;
    cfg.count_value = in->count_value;
    cfg.slot_elem_counts.assign(in->slot_elem_counts,
                                in->slot_elem_counts + in->slot_count);
    cfg.sub_types.assign(in->sub_types, in->sub_types + in->sub_type_count);
    // slot types: the stret fixture keeps them equal to the element counts
    // marker (the differential's source_items case uses non-11 slot types).
    cfg.slot_types.assign(in->slot_count, 0);
    cfg.current_blockhead = in->current_blockhead;
    cfg.current_fuel_blockhead = in->current_fuel_blockhead;
    cfg.light_dict_present = in->light_dict_present != 0;
    cfg.light_answer = in->light_answer;
    cfg.sub_page_base = in->sub_page_base;

    WorkbenchInitResult r = workbench_init_with_world(cfg);
    std::memcpy(image_out, r.image.data(), r.image.size());
    std::uint32_t n = 0;
    for (const auto& call : r.calls) {
        if (n >= 1024) return 0xFFFFFFFFu;
        std::uint8_t code = static_cast<std::uint8_t>(call.first);
        std::memcpy(trace_out + n * 8 + 0, &code, 1);
        std::uint32_t arg = call.second;
        std::memcpy(trace_out + n * 8 + 4, &arg, 4);
        ++n;
    }
    *ret_out = r.return_value;
    return n;
}
