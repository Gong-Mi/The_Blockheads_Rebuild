// Recovered semantics of -[FreightCar initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:]
// (batch b4h).
// Original IMP: 0x00a403e8, 134 words.
//
// Decoded shape:
//   super = [super initWithWorld:world dynamicWorld:dynamicWorld saveDict:saveDict cache:cache];
//   if (super == nil) return nil;
//   Chest* chest = [[Chest alloc] initWithWorld:self->world dynamicWorld:dynamicWorld
//                                      saveDict:chestSaveDict cache:cache];
//   self->chest = chest;
//   [chest setProxyObjectOwner:self];
//   [chest setFloatPosAndUpdatePosition:self->floatPos];
//   return self;
#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

inline constexpr std::size_t kFreightCarImageSize = 256;
inline constexpr std::size_t kFreightCarMaxTrace = 16;

inline constexpr std::uint32_t kChestClassToken = 0x00E92240u;
inline constexpr std::uint32_t kChestAllocToken = 0xC8E57001u;
inline constexpr std::uint32_t kChestInitToken  = 0xC8E57002u;

struct FreightCarInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    std::uint32_t world_token = 0x51CE0004u;
    std::uint32_t dynamic_world_token = 0x51CE0005u;
    std::uint32_t save_dict_token = 0x51CE0006u;
    std::uint32_t chest_save_dict_token = 0x51CE0007u;
    std::uint32_t cache_token = 0x51CE0008u;

    float float_pos_x = 100.5f;
    float float_pos_y = 200.25f;

    bool super_returns_nil = false;

    std::uint32_t chest_alloc_token = kChestAllocToken;
    std::uint32_t chest_init_token = kChestInitToken;
};

struct FreightCarInitResult {
    bool returned_nil = false;
    std::uint32_t returned_ptr = 0;
    std::vector<std::uint8_t> image;
    std::vector<std::pair<FreightCarInitCall, std::uint32_t>> calls;
};

FreightCarInitResult freight_car_init_with_world(const FreightCarInitInputs& in);

}  // namespace blockheads::recovered
