#include "dynamic_object_init_derived_stuff.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::DynamicObjectInitDerivedStuffCall;
using blockheads::recovered::DynamicObjectInitDerivedInputs;

extern "C" {

std::uint32_t recovered_dynamic_object_init_derived_stuff_run(
    std::uint32_t self_ptr,
    std::uint32_t world_ptr,
    std::uint32_t dynamic_world_ptr,
    int32_t pos_x,
    int32_t pos_y,
    std::uint32_t macro_tile_ptr,
    std::uint32_t physical_block_loaded,
    std::uint32_t should_add_to_macro_block,
    int32_t object_type,
    std::uint32_t init_derived_stuff,
    std::uint32_t load_physical_block_if_needed,
    std::uint8_t* image_out,
    std::uint8_t* trace_out,
    std::uint32_t* ret_val_out) {
    DynamicObjectInitDerivedInputs in;
    in.self_ptr = self_ptr;
    in.world_ptr = world_ptr;
    in.dynamic_world_ptr = dynamic_world_ptr;
    in.pos_x = pos_x;
    in.pos_y = pos_y;
    in.macro_tile_ptr = macro_tile_ptr;
    in.physical_block_loaded = (physical_block_loaded != 0);
    in.should_add_to_macro_block = (should_add_to_macro_block != 0);
    in.object_type = object_type;
    in.init_derived_stuff = (init_derived_stuff != 0);
    in.load_physical_block_if_needed = (load_physical_block_if_needed != 0);

    const auto res = blockheads::recovered::dynamic_object_init_derived_stuff(in);
    for (std::size_t i = 0; i < blockheads::recovered::kDynamicObjectDerivedImageSize; ++i) {
        image_out[i] = res.image[i];
    }

    const std::uint32_t n =
        res.calls.size() > blockheads::recovered::kDynamicObjectDerivedMaxTrace
            ? blockheads::recovered::kDynamicObjectDerivedMaxTrace
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
    *ret_val_out = res.return_value ? 1 : 0;
    return n;
}

}  // extern "C"
