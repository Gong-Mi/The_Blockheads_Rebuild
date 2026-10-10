#include "freight_car_init.h"

#include <cstring>

namespace blockheads::recovered {

namespace {

void store_word(std::vector<std::uint8_t>& image, std::size_t offset, std::uint32_t val) {
    if (offset + 4 <= image.size()) {
        image[offset + 0] = static_cast<std::uint8_t>(val & 0xff);
        image[offset + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
        image[offset + 2] = static_cast<std::uint8_t>((val >> 16) & 0xff);
        image[offset + 3] = static_cast<std::uint8_t>((val >> 24) & 0xff);
    }
}

}  // namespace

FreightCarInitResult freight_car_init_with_world(const FreightCarInitInputs& in) {
    FreightCarInitResult result;
    result.image.assign(kFreightCarImageSize, 0);

    // Initial state set by callers / super class prior to chest setup:
    store_word(result.image, 4, in.world_token);
    store_word(result.image, 8, in.dynamic_world_token);
    std::uint32_t pos_x_bits, pos_y_bits;
    std::memcpy(&pos_x_bits, &in.float_pos_x, 4);
    std::memcpy(&pos_y_bits, &in.float_pos_y, 4);
    store_word(result.image, 24, pos_x_bits);
    store_word(result.image, 28, pos_y_bits);

    // 1. objc_msgSendSuper2 to TrainCar
    result.calls.emplace_back(FreightCarInitCall::MsgSendSuper, in.save_dict_token);
    if (in.super_returns_nil) {
        result.returned_nil = true;
        result.returned_ptr = 0;
        return result;
    }

    result.returned_nil = false;
    result.returned_ptr = in.self_ptr;

    // 2. [Chest alloc]
    result.calls.emplace_back(FreightCarInitCall::ChestAlloc, in.chest_alloc_token);

    // 3. [chest initWithWorld:world dynamicWorld:dynamicWorld saveDict:chestSaveDict cache:cache]
    result.calls.emplace_back(FreightCarInitCall::ChestInitWithWorld, in.chest_save_dict_token);
    // Write chest pointer into FreightCar.chest @ 220
    store_word(result.image, 220, in.chest_init_token);

    // 4. [chest setProxyObjectOwner:self]
    result.calls.emplace_back(FreightCarInitCall::ChestSetProxyObjectOwner, in.self_ptr);

    // 5. [chest setFloatPosAndUpdatePosition:self->floatPos]
    result.calls.emplace_back(FreightCarInitCall::ChestSetFloatPosAndUpdatePosition, pos_x_bits);

    return result;
}

}  // namespace blockheads::recovered
