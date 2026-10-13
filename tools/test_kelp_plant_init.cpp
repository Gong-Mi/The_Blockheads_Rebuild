// Hand-written contract checks for the recovered KelpPlant BIG loader (b4n).
#include "kelp_plant_init.h"

#include <cassert>
#include <cstring>
#include <iostream>

using blockheads::recovered::KelpInitCall;
using blockheads::recovered::KelpInitInputs;
using blockheads::recovered::KelpTileAnswer;
using blockheads::recovered::kelp_plant_init_with_world;
using blockheads::recovered::kKelpImageSize;
using blockheads::recovered::kKelpOffsetAge;
using blockheads::recovered::kKelpOffsetAvailableFood;
using blockheads::recovered::kKelpOffsetFrozen;
using blockheads::recovered::kKelpOffsetGrowthTimer;
using blockheads::recovered::kKelpOffsetOccupied;

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

int count_code(const std::vector<std::pair<KelpInitCall, std::uint32_t>>& t,
               KelpInitCall code) {
    int n = 0;
    for (const auto& c : t) {
        if (c.first == code) ++n;
    }
    return n;
}

KelpInitInputs base_inputs() {
    KelpInitInputs in;
    in.self_ptr = 0x60000000u;
    in.world_ivar = 0x5E1B0004u;
    in.dynamic_world_ivar = 0x5E1B0008u;
    in.pos_x = 10;
    in.pos_y = -4;
    in.occupied_value = 2;
    in.occupied_init = 2;                // staged ivar (nil-super path keeps it)
    in.growth_timer_value = 300.0f;      // above the threshold below
    in.growth_timer_init = 300.0f;       // staged ivar (pre-key-read state)
    in.available_food_value = 5.0f;      // no refill
    in.age_init = 10.0f;
    in.max_age = 1000.0f;
    in.growth_rate = 1.0f;
    in.save_time_value = 100.0;
    in.world_time = 150.0;               // elapsed = 50
    in.object_type_value = 0x5E1B0041u;
    in.occupied_box_token = 0x5E1B0A01u;
    in.growth_timer_box_token = 0x5E1B0A02u;
    in.available_food_box_token = 0x5E1B0A03u;
    in.save_time_box_token = 0x5E1B0A04u;
    return in;
}

}  // namespace

int main() {
    // 1. Nil super: no key read, no ivar touched.
    {
        KelpInitInputs in = base_inputs();
        in.super_returns_nil = true;
        auto res = kelp_plant_init_with_world(in);
        assert(res.return_value == 0);
        assert(res.calls.size() == 1);
        assert(res.calls[0].first == KelpInitCall::MsgSendSuper);
        assert(word_at(res.image, kKelpOffsetOccupied) == 2);
        assert(float_at(res.image, kKelpOffsetGrowthTimer) == 300.0f);
    }

    // 2. No-growth path: timer below the threshold, full sequence executed.
    {
        KelpInitInputs in = base_inputs();
        in.growth_timer_value = 1.0f;    // threshold = 225 / ((1 - 2/16 + 0.2) * 1 * 0.5 + 0.5)
        auto res = kelp_plant_init_with_world(in);
        assert(res.return_value == in.self_ptr);
        // call order: super, occupied x2, growthTimer x2, initSubDerivedItems,
        // availableFood x2, saveTime x2, worldTime, objectType, dynamicWorldChanged
        assert(res.calls.size() == 13);
        assert(res.calls[1].first == KelpInitCall::ObjectForKeyOccupied);
        assert(res.calls[2].first == KelpInitCall::IntValueOccupied);
        assert(res.calls[3].first == KelpInitCall::ObjectForKeyGrowthTimer);
        assert(res.calls[4].first == KelpInitCall::FloatValueGrowthTimer);
        assert(res.calls[5].first == KelpInitCall::InitSubDerivedItems);
        assert(res.calls[6].first == KelpInitCall::ObjectForKeyAvailableFood);
        assert(res.calls[7].first == KelpInitCall::FloatValueAvailableFood);
        assert(res.calls[8].first == KelpInitCall::ObjectForKeySaveTime);
        assert(res.calls[9].first == KelpInitCall::DoubleValueSaveTime);
        assert(res.calls[10].first == KelpInitCall::WorldTime);
        assert(res.calls[11].first == KelpInitCall::ObjectType);
        assert(res.calls[12].first == KelpInitCall::DynamicWorldChangedAtPos);
        assert(count_code(res.calls, KelpInitCall::Lrand48) == 0);
        assert(count_code(res.calls, KelpInitCall::WorldTileQuery) == 0);
        assert(word_at(res.image, kKelpOffsetOccupied) == 2);
        // growthTimer = 1.0f + 50.0
        assert(float_at(res.image, kKelpOffsetGrowthTimer) == 51.0f);
        assert(float_at(res.image, kKelpOffsetAge) == 60.0f);
        assert(res.tiles_consumed == 0);
        assert(kKelpImageSize == 204);
    }

    // 3. availableFood < 0.1f triggers the lrand48 refill (0x814F44 wrapper).
    {
        KelpInitInputs in = base_inputs();
        in.available_food_value = 0.05f;
        in.lrand48_value = 900;
        auto res = kelp_plant_init_with_world(in);
        assert(count_code(res.calls, KelpInitCall::Lrand48) == 1);
        for (const auto& c : res.calls) {
            if (c.first == KelpInitCall::Lrand48) assert(c.second == 900u);
        }
        // (float)900 / 2^31 * 900.0f = 3.7718564e-4 -> (double) * 1.5
        assert(float_at(res.image, kKelpOffsetAvailableFood) == 0.0005657784640789032f);
    }

    // 4. frozen != 0 returns right after the food stage (ldrsb gate).
    {
        KelpInitInputs in = base_inputs();
        in.frozen = 1;
        in.available_food_value = 0.05f;
        in.lrand48_value = 100;
        auto res = kelp_plant_init_with_world(in);
        assert(res.return_value == in.self_ptr);
        assert(count_code(res.calls, KelpInitCall::ObjectForKeySaveTime) == 0);
        assert(count_code(res.calls, KelpInitCall::WorldTime) == 0);
        assert(count_code(res.calls, KelpInitCall::InitSubDerivedItems) == 1);
        // growthTimer only got the saveTime-based update? No: frozen returns
        // before the elapsed maths, so the loaded value stays.
        assert(float_at(res.image, kKelpOffsetGrowthTimer) == 300.0f);
        assert(float_at(res.image, kKelpOffsetAge) == 10.0f);
    }

    // 5. Age overflow without compost -> dieOfOldAge, no age write.
    {
        KelpInitInputs in = base_inputs();
        in.age_init = 990.0f;                 // 990 + 50 >= 1000
        in.is_growing_in_compost = false;
        auto res = kelp_plant_init_with_world(in);
        assert(count_code(res.calls, KelpInitCall::IsGrowingInCompost) == 1);
        assert(count_code(res.calls, KelpInitCall::DieOfOldAge) == 1);
        assert(count_code(res.calls, KelpInitCall::WorldTileQuery) == 0);
        assert(count_code(res.calls, KelpInitCall::ObjectType) == 0);
        assert(float_at(res.image, kKelpOffsetAge) == 990.0f);
    }

    // 6. Age overflow WITH compost: elapsed is rewritten to
    //    (maxAge - age) - 0.1, which is < maxAge - age, so no death.
    {
        KelpInitInputs in = base_inputs();
        in.age_init = 990.0f;
        in.is_growing_in_compost = true;
        in.growth_timer_value = 1.0f;
        auto res = kelp_plant_init_with_world(in);
        assert(count_code(res.calls, KelpInitCall::IsGrowingInCompost) == 1);
        assert(count_code(res.calls, KelpInitCall::DieOfOldAge) == 0);
        assert(count_code(res.calls, KelpInitCall::ObjectType) == 1);
        // elapsed = (1000 - 990) - 0.1 = 9.9 -> age = 990 + 9.9 = 999.9
        assert(float_at(res.image, kKelpOffsetAge) == 999.9f);
    }

    // 7. Growth success: tile kind 3, marker 0 -> occupied++, timer -= threshold,
    //    worldContentsChanged fired; a second tile answer lets the loop repeat.
    {
        KelpInitInputs in = base_inputs();
        in.growth_timer_value = 700.0f;   // threshold = 225/0.75 = 300 for rate 1, occ 2
        KelpTileAnswer first;
        first.present = true;
        first.byte0 = 3;
        first.byte11 = 0;
        KelpTileAnswer second;   // occupied marker set -> growth stops
        second.present = true;
        second.byte0 = 3;
        second.byte11 = 1;
        in.tiles = {first, second};
        auto res = kelp_plant_init_with_world(in);
        // threshold = 225 / ((1 - 2/16 + 0.2)*1*0.5 + 0.5) = 225 / 0.75 = 300
        assert(count_code(res.calls, KelpInitCall::WorldTileQuery) == 2);
        assert(count_code(res.calls, KelpInitCall::WorldContentsChangedAtPos) == 1);
        for (const auto& c : res.calls) {
            // query y = pos.y + occupied + 1 = -1; notification adds the
            // already-incremented count, so it is 0
            if (c.first == KelpInitCall::WorldContentsChangedAtPos) assert(c.second == 0u);
        }
        assert(word_at(res.image, kKelpOffsetOccupied) == 3);
        // first growth subtracts the threshold (300) from 700 + 50 = 750 -> 450;
        // the second query fails -> timer = 0
        assert(float_at(res.image, kKelpOffsetGrowthTimer) == 0.0f);
        assert(res.tiles_consumed == 2);
        // the two queries carry y = pos.y + occupied + 1 = -4 + 2 + 1 = -1 then
        // -4 + 3 + 1 = 0
        int queries = 0;
        for (const auto& c : res.calls) {
            if (c.first != KelpInitCall::WorldTileQuery) continue;
            assert(c.second == (queries == 0 ? 0xffffffffu : 0u));
            ++queries;
        }
        assert(count_code(res.calls, KelpInitCall::ObjectType) == 1);
        // age still got the elapsed update on the tail
        assert(float_at(res.image, kKelpOffsetAge) == 60.0f);
    }

    // 8. Growth gate: 15 occupied tiles stop the loop; timer <= 0 also stops it.
    {
        KelpInitInputs in = base_inputs();
        in.occupied_value = 15;
        in.growth_timer_value = 100000.0f;
        auto res = kelp_plant_init_with_world(in);
        assert(count_code(res.calls, KelpInitCall::WorldTileQuery) == 0);
        assert(word_at(res.image, kKelpOffsetOccupied) == 15);
    }
    {
        KelpInitInputs in = base_inputs();
        in.growth_timer_value = -500.0f;
        auto res = kelp_plant_init_with_world(in);
        assert(count_code(res.calls, KelpInitCall::WorldTileQuery) == 0);
    }

    std::cout << "test_kelp_plant_init: PASS\n";
    return 0;
}
