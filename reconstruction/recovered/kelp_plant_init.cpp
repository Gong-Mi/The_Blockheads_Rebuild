#include "kelp_plant_init.h"

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

void store_byte(std::vector<std::uint8_t>& image, std::size_t offset,
                std::uint8_t val) {
    if (offset < image.size()) image[offset] = val;
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

}  // namespace

KelpInitResult kelp_plant_init_with_world(const KelpInitInputs& in) {
    KelpInitResult result;
    result.image.assign(kKelpImageSize, 0);

    // Fixture staging (the ARM harness writes the same words).
    store_word(result.image, kKelpOffsetWorld, in.world_ivar);
    store_word(result.image, kKelpOffsetDynamicWorld, in.dynamic_world_ivar);
    store_word(result.image, kKelpOffsetPosX, static_cast<std::uint32_t>(in.pos_x));
    store_word(result.image, kKelpOffsetPosY, static_cast<std::uint32_t>(in.pos_y));
    store_word(result.image, kKelpOffsetOccupied,
               static_cast<std::uint32_t>(in.occupied_init));
    store_float(result.image, kKelpOffsetGrowthTimer, in.growth_timer_init);
    store_float(result.image, kKelpOffsetAvailableFood, in.available_food_init);
    store_float(result.image, kKelpOffsetAge, in.age_init);
    store_float(result.image, kKelpOffsetMaxAge, in.max_age);
    store_float(result.image, kKelpOffsetGrowthRate, in.growth_rate);
    store_byte(result.image, kKelpOffsetFrozen,
               static_cast<std::uint8_t>(in.frozen));

    // 1. [super initWithWorld:…:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]
    result.calls.emplace_back(KelpInitCall::MsgSendSuper, in.self_ptr);
    if (in.super_returns_nil) {
        result.return_value = 0;
        return result;
    }
    result.return_value = in.self_ptr;

    // 2. numberOfOccupiedTilesAbove -> intValue -> +200
    result.calls.emplace_back(KelpInitCall::ObjectForKeyOccupied, in.occupied_box_token);
    result.calls.emplace_back(KelpInitCall::IntValueOccupied,
                              static_cast<std::uint32_t>(in.occupied_value));
    store_word(result.image, kKelpOffsetOccupied,
               static_cast<std::uint32_t>(in.occupied_value));

    // 3. growthTimer -> floatValue -> +176
    result.calls.emplace_back(KelpInitCall::ObjectForKeyGrowthTimer,
                              in.growth_timer_box_token);
    result.calls.emplace_back(KelpInitCall::FloatValueGrowthTimer,
                              float_bits(in.growth_timer_value));
    store_float(result.image, kKelpOffsetGrowthTimer, in.growth_timer_value);

    // 4. [self initSubDerivedItems] (runs BEFORE the availableFood read)
    result.calls.emplace_back(KelpInitCall::InitSubDerivedItems, 0);

    // 5. availableFood -> floatValue -> +180
    result.calls.emplace_back(KelpInitCall::ObjectForKeyAvailableFood,
                              in.available_food_box_token);
    result.calls.emplace_back(KelpInitCall::FloatValueAvailableFood,
                              float_bits(in.available_food_value));
    store_float(result.image, kKelpOffsetAvailableFood, in.available_food_value);

    // 6. Food refill: the 0x814F44 wrapper -> 0x001C2804 (lrand48).
    if (load_float(result.image, kKelpOffsetAvailableFood) < kKelpFoodRefillThreshold) {
        result.calls.emplace_back(KelpInitCall::Lrand48,
                                  static_cast<std::uint32_t>(in.lrand48_value));
        const float as_float = static_cast<float>(static_cast<std::int32_t>(in.lrand48_value));
        const float scaled = as_float / kKelpRandomDenominator * kKelpRefillScale;
        const double widened = static_cast<double>(scaled);
        const float refilled = static_cast<float>(widened * kKelpRefillMultiplier);
        store_float(result.image, kKelpOffsetAvailableFood, refilled);
    }

    // 7. frozen gate: a set frozen byte returns self immediately (0x8164C0).
    if (static_cast<std::int8_t>(result.image[kKelpOffsetFrozen]) != 0) {
        return result;
    }

    // 8. saveTime / worldTime / elapsed
    result.calls.emplace_back(KelpInitCall::ObjectForKeySaveTime,
                              in.save_time_box_token);
    result.calls.emplace_back(KelpInitCall::DoubleValueSaveTime,
                              low32(in.save_time_value));
    result.calls.emplace_back(KelpInitCall::WorldTime, low32(in.world_time));
    double elapsed = in.world_time - in.save_time_value;

    store_float(result.image, kKelpOffsetGrowthTimer,
                static_cast<float>(static_cast<double>(
                    load_float(result.image, kKelpOffsetGrowthTimer)) + elapsed));

    float age = load_float(result.image, kKelpOffsetAge);
    const float max_age = load_float(result.image, kKelpOffsetMaxAge);
    const double max_age_d = static_cast<double>(max_age);
    if (!((static_cast<double>(age) + elapsed) < max_age_d)) {  // ARM `blt` edge
        result.calls.emplace_back(KelpInitCall::IsGrowingInCompost,
                                  in.is_growing_in_compost ? 1u : 0u);
        if (in.is_growing_in_compost) {
            elapsed = static_cast<double>(max_age - age) - kKelpCompostAdjust;
        }
    }

    if (!((static_cast<double>(age) + elapsed) < max_age_d)) {  // ARM `bpl` edge
        result.calls.emplace_back(KelpInitCall::DieOfOldAge, 0);
        return result;
    }

    // 9. Growth loop (multi-tile: the ARM's 0x8163DC back-edge targets 0x816108).
    for (;;) {
        std::int32_t occupied = load_int(result.image, kKelpOffsetOccupied);
        bool can_grow = false;
        if (occupied < static_cast<std::int32_t>(kKelpMaxOccupiedTiles)) {
            can_grow = load_float(result.image, kKelpOffsetGrowthTimer) > 0.0f;
        }
        if (!can_grow) break;

        const float growth_rate = load_float(result.image, kKelpOffsetGrowthRate);
        const float occupied_f = static_cast<float>(occupied);
        const float density = (1.0f - occupied_f / kKelpTileSpacing) + kKelpCompostPenalty;
        const float scaled_rate = density * growth_rate;      // f32 multiply, then widen
        const float factor =
            static_cast<float>(static_cast<double>(scaled_rate) * 0.5 + 0.5);
        const float threshold = kKelpGrowthEnergy / factor;
        if (!(load_float(result.image, kKelpOffsetGrowthTimer) > threshold)) break;  // ble

        const std::int32_t x = load_int(result.image, kKelpOffsetPosX);
        const std::int32_t y = load_int(result.image, kKelpOffsetPosY) + occupied + 1;
        result.calls.emplace_back(KelpInitCall::WorldTileQuery,
                                  static_cast<std::uint32_t>(y));
        const KelpTileAnswer* answer =
            result.tiles_consumed < in.tiles.size() ? &in.tiles[result.tiles_consumed]
                                                    : nullptr;
        ++result.tiles_consumed;
        (void)x;
        if (answer != nullptr && answer->present &&
            answer->byte0 == kKelpTileKind && answer->byte11 == 0) {
            // tile->byte[11] = 0x51 and numberOfOccupiedTilesAbove += 1
            store_word(result.image, kKelpOffsetOccupied,
                       static_cast<std::uint32_t>(occupied + 1));
            // The notification is built AFTER the ++: y = pos.y + occupied_after + 1
            // (the ARM reloads the incremented field), i.e. the query y + 1.
            result.calls.emplace_back(KelpInitCall::WorldContentsChangedAtPos,
                                      static_cast<std::uint32_t>(y + 1));
            store_float(result.image, kKelpOffsetGrowthTimer,
                        load_float(result.image, kKelpOffsetGrowthTimer) - threshold);
        } else {
            store_float(result.image, kKelpOffsetGrowthTimer, 0.0f);
            break;
        }
    }

    // 10. Tail: age += elapsed, then the two notifications.
    store_float(result.image, kKelpOffsetAge,
                static_cast<float>(static_cast<double>(
                    load_float(result.image, kKelpOffsetAge)) + elapsed));
    result.calls.emplace_back(KelpInitCall::ObjectType, in.object_type_value);
    result.calls.emplace_back(KelpInitCall::DynamicWorldChangedAtPos,
                              in.object_type_value);
    return result;
}

}  // namespace blockheads::recovered
