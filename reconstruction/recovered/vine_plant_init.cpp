#include "vine_plant_init.h"

#include <cstring>

namespace blockheads::recovered {

namespace {

void store_word(std::vector<std::uint8_t>& image, std::size_t offset,
                std::uint32_t val) {
    if (offset + 4 <= image.size()) {
        image[offset + 0] = static_cast<std::uint8_t>(val & 0xff);
        image[offset + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
        image[offset + 2] = static_cast<std::uint8_t>((val >> 16) & 0xff);
        image[offset + 3] = static_cast<std::uint8_t>((val >> 24) & 0xff);
    }
}

void store_float(std::vector<std::uint8_t>& image, std::size_t offset, float val) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &val, sizeof(bits));
    store_word(image, offset, bits);
}

std::uint32_t load_word(const std::vector<std::uint8_t>& image, std::size_t offset) {
    if (offset + 4 > image.size()) return 0;
    return static_cast<std::uint32_t>(image[offset + 0]) |
           (static_cast<std::uint32_t>(image[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(image[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(image[offset + 3]) << 24);
}

float load_float(const std::vector<std::uint8_t>& image, std::size_t offset) {
    const std::uint32_t bits = load_word(image, offset);
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

std::int32_t load_int(const std::vector<std::uint8_t>& image, std::size_t offset) {
    return static_cast<std::int32_t>(load_word(image, offset));
}

std::uint32_t low32(double value) {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return static_cast<std::uint32_t>(bits & 0xffffffffu);
}

std::uint32_t float_bits(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

// (float)((double)((float)lrand48() / 2^31 * 900.0f) * 1.5)
float refill_dose(std::int64_t lrand48_value) {
    const float as_float = static_cast<float>(static_cast<std::int32_t>(lrand48_value));
    const float scaled = as_float / kVineRandomDenominator * kVineRefillScale;
    return static_cast<float>(static_cast<double>(scaled) * kVineRefillMultiplier);
}

}  // namespace

VineInitResult vine_plant_init_with_world(const VineInitInputs& in) {
    VineInitResult result;
    result.image.assign(kVineImageSize, 0);

    store_word(result.image, kVineOffsetWorld, in.world_ivar);
    store_word(result.image, kVineOffsetDynamicWorld, in.dynamic_world_ivar);
    store_word(result.image, kVineOffsetPosX, static_cast<std::uint32_t>(in.pos_x));
    store_word(result.image, kVineOffsetPosY, static_cast<std::uint32_t>(in.pos_y));
    store_word(result.image, kVineOffsetOccupiedBelow,
               static_cast<std::uint32_t>(in.occupied_init));
    store_float(result.image, kVineOffsetGrowthTimer, in.growth_timer_init);
    store_float(result.image, kVineOffsetAvailableFood, in.available_food_init);
    store_float(result.image, kVineOffsetAge, in.age_init);
    store_float(result.image, kVineOffsetMaxAge, in.max_age);
    store_float(result.image, kVineOffsetGrowthRate, in.growth_rate);

    result.calls.emplace_back(VineInitCall::MsgSendSuper, in.self_ptr);
    if (in.super_returns_nil) {
        result.return_value = 0;
        return result;
    }
    result.return_value = in.self_ptr;

    result.calls.emplace_back(VineInitCall::ObjectForKeyOccupiedBelow,
                              in.occupied_box_token);
    result.calls.emplace_back(VineInitCall::IntValueOccupiedBelow,
                              static_cast<std::uint32_t>(in.occupied_value));
    store_word(result.image, kVineOffsetOccupiedBelow,
               static_cast<std::uint32_t>(in.occupied_value));

    result.calls.emplace_back(VineInitCall::ObjectForKeyGrowthTimer,
                              in.growth_timer_box_token);
    result.calls.emplace_back(VineInitCall::FloatValueGrowthTimer,
                              float_bits(in.growth_timer_value));
    store_float(result.image, kVineOffsetGrowthTimer, in.growth_timer_value);

    result.calls.emplace_back(VineInitCall::InitSubDerivedItems, 0);

    result.calls.emplace_back(VineInitCall::ObjectForKeyAvailableFood,
                              in.available_food_box_token);
    result.calls.emplace_back(VineInitCall::FloatValueAvailableFood,
                              float_bits(in.available_food_value));
    store_float(result.image, kVineOffsetAvailableFood, in.available_food_value);

    if (load_float(result.image, kVineOffsetAvailableFood) < kVineFoodRefillThreshold) {
        result.calls.emplace_back(VineInitCall::Lrand48,
                                  static_cast<std::uint32_t>(in.lrand48_value));
        store_float(result.image, kVineOffsetAvailableFood,
                    refill_dose(in.lrand48_value));
    }
    // NOTE: no Plant.frozen gate here — that is a KelpPlant-only early return.

    result.calls.emplace_back(VineInitCall::ObjectForKeySaveTime,
                              in.save_time_box_token);
    result.calls.emplace_back(VineInitCall::DoubleValueSaveTime,
                              low32(in.save_time_value));
    result.calls.emplace_back(VineInitCall::WorldTime, low32(in.world_time));
    double elapsed = in.world_time - in.save_time_value;

    store_float(result.image, kVineOffsetGrowthTimer,
                static_cast<float>(static_cast<double>(
                    load_float(result.image, kVineOffsetGrowthTimer)) + elapsed));

    float age = load_float(result.image, kVineOffsetAge);
    const float max_age = load_float(result.image, kVineOffsetMaxAge);
    const double max_age_d = static_cast<double>(max_age);
    if (!((static_cast<double>(age) + elapsed) < max_age_d)) {   // ARM `blt` edge
        result.calls.emplace_back(VineInitCall::IsGrowingInCompost,
                                  in.is_growing_in_compost ? 1u : 0u);
        if (in.is_growing_in_compost) {
            elapsed = static_cast<double>(max_age - age) - kVineCompostAdjust;
        }
    }
    if (!((static_cast<double>(age) + elapsed) < max_age_d)) {   // ARM `bpl` edge
        result.calls.emplace_back(VineInitCall::DieOfOldAge, 0);
        return result;
    }

    for (;;) {
        std::int32_t occupied = load_int(result.image, kVineOffsetOccupiedBelow);
        bool can_grow = false;
        if (occupied < static_cast<std::int32_t>(kVineMaxOccupiedTiles)) {
            can_grow = load_float(result.image, kVineOffsetGrowthTimer) > 0.0f;
        }
        if (!can_grow) break;

        const float growth_rate = load_float(result.image, kVineOffsetGrowthRate);
        const float occupied_f = static_cast<float>(occupied);
        const float density = (1.0f - occupied_f / kVineTileSpacing) + kVineCompostPenalty;
        const float scaled_rate = density * growth_rate;
        const float factor =
            static_cast<float>(static_cast<double>(scaled_rate) * 0.5 + 0.5);
        const float threshold = kVineGrowthEnergy / factor;
        if (!(load_float(result.image, kVineOffsetGrowthTimer) > threshold)) break;

        const std::int32_t x = load_int(result.image, kVineOffsetPosX);
        const std::int32_t y = load_int(result.image, kVineOffsetPosY) - occupied - 1;
        result.calls.emplace_back(VineInitCall::WorldTileQuery,
                                  static_cast<std::uint32_t>(y));
        const VineTileAnswer* answer =
            result.tiles_consumed < in.tiles.size() ? &in.tiles[result.tiles_consumed]
                                                    : nullptr;
        ++result.tiles_consumed;
        (void)x;

        bool grow = false;
        if (answer != nullptr && answer->present) {
            // lightSum = ((float)(u32)half_a / 4.0f
            //          + (float)(s32)(half_b / 4)
            //          + (float)(s32)(half_c / 2)) / 1024.0f
            const float a = static_cast<float>(answer->half_a) / 4.0f;
            const float b = static_cast<float>(static_cast<std::int32_t>(answer->half_b) / 4);
            const float c = static_cast<float>(static_cast<std::int32_t>(answer->half_c) / 2);
            const float light_sum = ((a + b) + c) / kVineLightDivisor;
            // key = (float)(((double)(float)(u32)byte7 * 0.4) / 255.0 + (double)light_sum)
            const double sun = (static_cast<double>(static_cast<float>(answer->byte7)) *
                                kVineSunScale) / kVineSunDivisor;
            const float key = static_cast<float>(sun + static_cast<double>(light_sum));
            grow = key > kVineLightGate &&
                   answer->byte0 != kVineRejectedTileKind &&
                   answer->byte0 != kVineRejectedTileByte0 &&
                   answer->byte11 == 0;
        }

        if (grow) {
            // tile->byte[11] = 0x7C; ++occupiedBelow
            store_word(result.image, kVineOffsetOccupiedBelow,
                       static_cast<std::uint32_t>(occupied + 1));
            // notification y = pos.y - occupied_after == the query y (mirror of
            // KelpPlant, where the ++ moved it the other way).
            result.calls.emplace_back(VineInitCall::WorldContentsChangedAtPos,
                                      static_cast<std::uint32_t>(y));
            store_float(result.image, kVineOffsetGrowthTimer,
                        load_float(result.image, kVineOffsetGrowthTimer) - threshold);
        } else {
            store_float(result.image, kVineOffsetGrowthTimer, 0.0f);
            break;
        }
    }

    store_float(result.image, kVineOffsetAge,
                static_cast<float>(static_cast<double>(
                    load_float(result.image, kVineOffsetAge)) + elapsed));
    result.calls.emplace_back(VineInitCall::ObjectType, in.object_type_value);
    result.calls.emplace_back(VineInitCall::DynamicWorldChangedAtPos,
                              in.object_type_value);
    return result;
}

}  // namespace blockheads::recovered
