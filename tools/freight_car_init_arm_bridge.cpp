// Optional ARM differential bridge: exposes the recovered FreightCar
// initWithWorld:... contract to tools/test_freight_car_init_arm.py,
// which executes the ORIGINAL ARM method under Unicorn and compares the
// instance image and message trace byte-for-byte against this module
// (built at -O0 and -O2).
#include "freight_car_init.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::FreightCarInitCall;
using blockheads::recovered::FreightCarInitInputs;

extern "C" {

std::uint32_t recovered_freight_car_init_run(
    std::uint32_t self_ptr,
    std::uint32_t world_token,
    std::uint32_t dynamic_world_token,
    std::uint32_t save_dict_token,
    std::uint32_t chest_save_dict_token,
    std::uint32_t cache_token,
    float float_pos_x,
    float float_pos_y,
    std::uint8_t super_returns_nil,
    std::uint32_t chest_alloc_token,
    std::uint32_t chest_init_token,
    std::uint8_t* image_out,
    std::uint8_t* trace_out) {
    FreightCarInitInputs in;
    in.self_ptr = self_ptr;
    in.world_token = world_token;
    in.dynamic_world_token = dynamic_world_token;
    in.save_dict_token = save_dict_token;
    in.chest_save_dict_token = chest_save_dict_token;
    in.cache_token = cache_token;
    in.float_pos_x = float_pos_x;
    in.float_pos_y = float_pos_y;
    in.super_returns_nil = (super_returns_nil != 0);
    in.chest_alloc_token = chest_alloc_token;
    in.chest_init_token = chest_init_token;

    const auto res = blockheads::recovered::freight_car_init_with_world(in);
    for (std::size_t i = 0; i < blockheads::recovered::kFreightCarImageSize; ++i) {
        image_out[i] = res.image[i];
    }
    const std::uint32_t n =
        res.calls.size() > blockheads::recovered::kFreightCarMaxTrace
            ? blockheads::recovered::kFreightCarMaxTrace
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
