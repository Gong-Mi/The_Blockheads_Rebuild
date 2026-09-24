#include "freight_car_init.h"

#include <cassert>
#include <iostream>

using blockheads::recovered::FreightCarInitCall;
using blockheads::recovered::FreightCarInitInputs;
using blockheads::recovered::freight_car_init_with_world;
using blockheads::recovered::kFreightCarImageSize;

int main() {
    // Case 1: normal initialization path
    {
        FreightCarInitInputs in;
        in.self_ptr = 0x60000000u;
        in.world_token = 0x51CE0004u;
        in.dynamic_world_token = 0x51CE0005u;
        in.save_dict_token = 0x51CE0006u;
        in.chest_save_dict_token = 0x51CE0007u;
        in.cache_token = 0x51CE0008u;
        in.float_pos_x = 123.5f;
        in.float_pos_y = 456.75f;
        in.super_returns_nil = false;

        auto res = freight_car_init_with_world(in);
        assert(!res.returned_nil);
        assert(res.returned_ptr == in.self_ptr);
        assert(res.calls.size() == 5);
        assert(res.calls[0].first == FreightCarInitCall::MsgSendSuper);
        assert(res.calls[1].first == FreightCarInitCall::ChestAlloc);
        assert(res.calls[2].first == FreightCarInitCall::ChestInitWithWorld);
        assert(res.calls[3].first == FreightCarInitCall::ChestSetProxyObjectOwner);
        assert(res.calls[4].first == FreightCarInitCall::ChestSetFloatPosAndUpdatePosition);

        // Check chest pointer written to self+220
        std::uint32_t chest_written =
            res.image[220] | (res.image[221] << 8) |
            (res.image[222] << 16) | (res.image[223] << 24);
        assert(chest_written == in.chest_init_token);
    }

    // Case 2: nil super returns nil early without creating child Chest
    {
        FreightCarInitInputs in;
        in.super_returns_nil = true;

        auto res = freight_car_init_with_world(in);
        assert(res.returned_nil);
        assert(res.returned_ptr == 0);
        assert(res.calls.size() == 1);
        assert(res.calls[0].first == FreightCarInitCall::MsgSendSuper);

        // Chest offset untouched
        std::uint32_t chest_written =
            res.image[220] | (res.image[221] << 8) |
            (res.image[222] << 16) | (res.image[223] << 24);
        assert(chest_written == 0);
    }

    std::cout << "test_freight_car_init: PASS\n";
    return 0;
}
