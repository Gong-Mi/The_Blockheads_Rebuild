// Flat C ABI bridge for the b4m Chest loader differential: the ARM harness
// (ctypes) and the recovered C++ contract exchange one input struct plus
// image/trace/return outputs. Fixed-size tables keep the ABI trivial and the
// bridge fails loudly when a case exceeds them.
#include "chest_init_with_world.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::ChestInitInputs;
using blockheads::recovered::ChestSlotEntry;
using blockheads::recovered::ChestSlotItemEntry;

namespace {

constexpr std::uint32_t kMaxSlots = 64;
constexpr std::uint32_t kMaxItems = 512;

}  // namespace

typedef struct ChestBridgeInput {
    std::uint32_t self_ptr;
    std::uint32_t super_returns_nil;
    std::uint32_t world_argument;
    std::uint32_t dynamic_world_argument;
    std::uint32_t save_dict_token;
    std::uint32_t cache_token;
    std::uint32_t world_ivar;
    std::uint32_t dynamic_world_ivar;
    std::uint32_t pos_x;
    std::uint32_t pos_y;
    std::uint32_t owner_id_ivar;
    std::uint32_t has_chest_type_key;
    std::uint32_t chest_type_box_token;
    std::int32_t chest_type_value;
    std::int32_t rules_byte0;
    std::uint32_t safe_client_id_token;
    std::uint32_t object_type_value;
    std::uint32_t slots_array_token;
    std::uint32_t slot_count;
    std::uint32_t slot_item_offsets[kMaxSlots];
    std::uint32_t slot_item_counts[kMaxSlots];
    std::uint32_t item_count;
    std::uint32_t item_tokens[kMaxItems];
    std::uint32_t item_types[kMaxItems];
    std::uint32_t shelf_render_box_tokens[4];
    std::uint32_t shelf_render_values[4];
    std::uint32_t shelf_item_data_box_tokens[4];
    std::uint32_t shelf_item_data_values[4];
    std::int32_t mutate_slot;
    std::int32_t mutate_item;
} ChestBridgeInput;

extern "C" {

std::uint32_t recovered_chest_init_run(const ChestBridgeInput* cfg,
                                       std::uint8_t* image_out,
                                       std::uint8_t* trace_out,
                                       std::uint32_t* return_out) {
    if (cfg->slot_count > kMaxSlots || cfg->item_count > kMaxItems) {
        return 0xFFFFFFFFu;  // fixture overflow: never silently truncate
    }

    ChestInitInputs in;
    in.self_ptr = cfg->self_ptr;
    in.super_returns_nil = (cfg->super_returns_nil != 0);
    in.world_argument = cfg->world_argument;
    in.dynamic_world_argument = cfg->dynamic_world_argument;
    in.save_dict_token = cfg->save_dict_token;
    in.cache_token = cfg->cache_token;
    in.world_ivar = cfg->world_ivar;
    in.dynamic_world_ivar = cfg->dynamic_world_ivar;
    in.pos_x = cfg->pos_x;
    in.pos_y = cfg->pos_y;
    in.owner_id_ivar = cfg->owner_id_ivar;
    in.has_chest_type_key = (cfg->has_chest_type_key != 0);
    in.chest_type_box_token = cfg->chest_type_box_token;
    in.chest_type_value = cfg->chest_type_value;
    in.rules_byte0 = cfg->rules_byte0;
    in.safe_client_id_token = cfg->safe_client_id_token;
    in.object_type_value = cfg->object_type_value;
    in.slots_array_token = cfg->slots_array_token;

    for (std::uint32_t i = 0; i < cfg->slot_count; ++i) {
        ChestSlotEntry slot;
        const std::uint32_t off = cfg->slot_item_offsets[i];
        const std::uint32_t n = cfg->slot_item_counts[i];
        if (off + n > cfg->item_count) return 0xFFFFFFFEu;
        for (std::uint32_t j = 0; j < n; ++j) {
            ChestSlotItemEntry e;
            e.item_token = cfg->item_tokens[off + j];
            e.item_type = cfg->item_types[off + j];
            slot.items.push_back(e);
        }
        in.slots.push_back(slot);
    }

    for (std::size_t m = 0; m < 4; ++m) {
        in.shelf_render_box_tokens[m] = cfg->shelf_render_box_tokens[m];
        in.shelf_render_values[m] = cfg->shelf_render_values[m];
        in.shelf_item_data_box_tokens[m] = cfg->shelf_item_data_box_tokens[m];
        in.shelf_item_data_values[m] = cfg->shelf_item_data_values[m];
    }
    in.mutate_slot = cfg->mutate_slot;
    in.mutate_item = cfg->mutate_item;

    const auto res = blockheads::recovered::chest_init_with_world(in);
    for (std::size_t i = 0; i < blockheads::recovered::kChestImageSize; ++i) {
        image_out[i] = res.image[i];
    }
    *return_out = res.return_value;

    const std::uint32_t n =
        res.calls.size() > blockheads::recovered::kChestMaxTrace
            ? blockheads::recovered::kChestMaxTrace
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
