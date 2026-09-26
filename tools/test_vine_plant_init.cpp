// Hand-written contract checks for the recovered VinePlant BIG loader (b4o).
#include "vine_plant_init.h"

#include <cassert>
#include <cstring>
#include <iostream>

using blockheads::recovered::VineInitCall;
using blockheads::recovered::VineInitInputs;
using blockheads::recovered::VineTileAnswer;
using blockheads::recovered::vine_plant_init_with_world;
using blockheads::recovered::kVineImageSize;
using blockheads::recovered::kVineOffsetAge;
using blockheads::recovered::kVineOffsetAvailableFood;
using blockheads::recovered::kVineOffsetGrowthTimer;
using blockheads::recovered::kVineOffsetOccupiedBelow;

namespace {

std::uint32_t word_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint32_t>(image[off]) |
           (static_cast<std::uint32_t>(image[off + 1]) << 8) |
           (static_cast<std::uint32_t>(image[off + 2]) << 16) |
           (static_cast<std::uint32_t>(image[off + 3]) << 24);
}

float float_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    const std::uint32_t bits = word_at(image, off);
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

int count_code(const std::vector<std::pair<VineInitCall, std::uint32_t>>& t,
               VineInitCall code) {
    int n = 0;
    for (const auto& c : t) {
        if (c.first == code) ++n;
    }
    return n;
}

VineInitInputs base_inputs() {
    VineInitInputs in;
    in.self_ptr = 0x60000000u;
    in.world_ivar = 0x5E1A0004u;
    in.dynamic_world_ivar = 0x5E1A0008u;
    in.pos_x = 10;
    in.pos_y = -4;
    in.occupied_value = 2;
    in.occupied_init = 2;
    in.growth_timer_value = 1.0f;
    in.growth_timer_init = 1.0f;
    in.available_food_value = 5.0f;
    in.age_init = 10.0f;
    in.max_age = 1000.0f;
    in.growth_rate = 1.0f;
    in.save_time_value = 100.0;
    in.world_time = 150.0;              // elapsed = 50
    in.object_type_value = 0x5E1A0041u;
    in.occupied_box_token = 0x5E1A0A01u;
    in.growth_timer_box_token = 0x5E1A0A02u;
    in.available_food_box_token = 0x5E1A0A03u;
    in.save_time_box_token = 0x5E1A0A04u;
    return in;
}

VineTileAnswer growable_tile() {
    // key = 0.4 * (255/255) + (4/4 + 8/4 + 8/2)/1024 > 0.2, byte0 = 7
    VineTileAnswer tile;
    tile.present = true;
    tile.byte0 = 7;
    tile.byte7 = 255;
    tile.byte11 = 0;
    tile.half_a = 4;
    tile.half_b = 8;
    tile.half_c = 8;
    return tile;
}

}  // namespace

int main() {
    assert(kVineImageSize == 184);

    // 1. Nil super.
    {
        VineInitInputs in = base_inputs();
        in.super_returns_nil = true;
        auto res = vine_plant_init_with_world(in);
        assert(res.return_value == 0);
        assert(res.calls.size() == 1);
        assert(word_at(res.image, kVineOffsetOccupiedBelow) == 2);
        assert(float_at(res.image, kVineOffsetGrowthTimer) == 1.0f);
    }

    // 2. No-growth path: full sequence, timer/age updated by elapsed.
    {
        VineInitInputs in = base_inputs();
        auto res = vine_plant_init_with_world(in);
        assert(res.return_value == in.self_ptr);
        assert(res.calls.size() == 13);
        assert(res.calls[1].first == VineInitCall::ObjectForKeyOccupiedBelow);
        assert(res.calls[2].first == VineInitCall::IntValueOccupiedBelow);
        assert(res.calls[3].first == VineInitCall::ObjectForKeyGrowthTimer);
        assert(res.calls[4].first == VineInitCall::FloatValueGrowthTimer);
        assert(res.calls[5].first == VineInitCall::InitSubDerivedItems);
        assert(res.calls[6].first == VineInitCall::ObjectForKeyAvailableFood);
        assert(res.calls[7].first == VineInitCall::FloatValueAvailableFood);
        assert(res.calls[8].first == VineInitCall::ObjectForKeySaveTime);
        assert(res.calls[9].first == VineInitCall::DoubleValueSaveTime);
        assert(res.calls[10].first == VineInitCall::WorldTime);
        assert(res.calls[11].first == VineInitCall::ObjectType);
        assert(res.calls[12].first == VineInitCall::DynamicWorldChangedAtPos);
        assert(count_code(res.calls, VineInitCall::Lrand48) == 0);
        assert(float_at(res.image, kVineOffsetGrowthTimer) == 51.0f);
        assert(float_at(res.image, kVineOffsetAge) == 60.0f);
    }

    // 3. Food refill (normalised lrand48 dose; 2^31 denominator).
    {
        VineInitInputs in = base_inputs();
        in.available_food_value = 0.05f;
        in.lrand48_value = 900;
        auto res = vine_plant_init_with_world(in);
        assert(count_code(res.calls, VineInitCall::Lrand48) == 1);
        assert(float_at(res.image, kVineOffsetAvailableFood) == 0.0005657784640789032f);
    }

    // 4. Compost rewrite keeps the plant alive; die without compost.
    {
        VineInitInputs in = base_inputs();
        in.age_init = 990.0f;
        in.is_growing_in_compost = true;
        auto res = vine_plant_init_with_world(in);
        assert(count_code(res.calls, VineInitCall::DieOfOldAge) == 0);
        assert(float_at(res.image, kVineOffsetAge) == 999.9f);

        VineInitInputs dead = base_inputs();
        dead.age_init = 990.0f;
        auto res2 = vine_plant_init_with_world(dead);
        assert(count_code(res2.calls, VineInitCall::DieOfOldAge) == 1);
        assert(count_code(res2.calls, VineInitCall::WorldTileQuery) == 0);
    }

    // 5. Growth success: light/kind gates pass, marker + occupied++ + notify.
    {
        VineInitInputs in = base_inputs();
        in.growth_timer_value = 2000.0f;
        in.tiles = {growable_tile()};
        auto res = vine_plant_init_with_world(in);
        // The loop re-evaluates after a growth: with one tile answer the second
        // query has no answer left and zeroes the timer.
        assert(count_code(res.calls, VineInitCall::WorldTileQuery) == 2);
        assert(count_code(res.calls, VineInitCall::WorldContentsChangedAtPos) == 1);
        assert(word_at(res.image, kVineOffsetOccupiedBelow) == 3);
        // query y = pos.y - occupied - 1 = -7 and the notification y is the same
        for (const auto& c : res.calls) {
            if (c.first == VineInitCall::WorldContentsChangedAtPos) {
                assert(c.second == 0xfffffff9u);   // -7
            }
        }
        // first query y = -7; after the growth the count is 3 so the second
        // query is y = -4 - 3 - 1 = -8
        {
            std::vector<std::uint32_t> ys;
            for (const auto& c : res.calls) {
                if (c.first == VineInitCall::WorldTileQuery) ys.push_back(c.second);
            }
            assert(ys.size() == 2);
            assert(ys[0] == 0xfffffff9u && ys[1] == 0xfffffff8u);
        }
        // 900/((1-3/16+0.2)*1*0.5+0.5) is still below the remaining timer, so
        // the failed second query is what zeroes it.
        assert(float_at(res.image, kVineOffsetGrowthTimer) == 0.0f);
        assert(res.tiles_consumed == 2);
    }

    // 6. Blocked growth: each gate zeroes the timer and stops.
    {
        const char* names[] = {"kind3", "byte0_31", "marker", "too_dark"};
        for (int i = 0; i < 4; ++i) {
            VineInitInputs in = base_inputs();
            in.growth_timer_value = 2000.0f;
            VineTileAnswer tile = growable_tile();
            if (i == 0) tile.byte0 = 3;          // helperA != 0 -> rejected
            if (i == 1) tile.byte0 = 31;         // explicit rejection value
            if (i == 2) tile.byte11 = 1;         // occupied marker
            if (i == 3) { tile.byte7 = 0; tile.half_a = 0; tile.half_b = 0; tile.half_c = 0; }
            in.tiles = {tile};
            auto res = vine_plant_init_with_world(in);
            assert(count_code(res.calls, VineInitCall::WorldTileQuery) == 1);
            assert(count_code(res.calls, VineInitCall::WorldContentsChangedAtPos) == 0);
            assert(word_at(res.image, kVineOffsetOccupiedBelow) == 2);
            assert(float_at(res.image, kVineOffsetGrowthTimer) == 0.0f);
            (void)names;
        }
    }

    // 7. Multi-tile loop and the 15-tile limit.
    {
        VineInitInputs in = base_inputs();
        in.growth_timer_value = 100000.0f;
        in.tiles = {growable_tile(), growable_tile(), growable_tile()};
        auto res = vine_plant_init_with_world(in);
        // 2 -> 5 occupied; the 4th query has no answer -> timer = 0
        assert(count_code(res.calls, VineInitCall::WorldTileQuery) == 4);
        assert(word_at(res.image, kVineOffsetOccupiedBelow) == 5);
        assert(res.tiles_consumed == 4);

        VineInitInputs limited = base_inputs();
        limited.occupied_value = 15;
        limited.occupied_init = 15;
        limited.growth_timer_value = 100000.0f;
        limited.tiles = {growable_tile()};
        auto res2 = vine_plant_init_with_world(limited);
        assert(count_code(res2.calls, VineInitCall::WorldTileQuery) == 0);
        assert(word_at(res2.image, kVineOffsetOccupiedBelow) == 15);
    }

    std::cout << "test_vine_plant_init: PASS\n";
    return 0;
}
