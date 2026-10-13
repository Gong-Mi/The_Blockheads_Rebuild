#include "tree_grow_in_time.h"

#include <cstring>

namespace blockheads::recovered {

namespace {

std::uint32_t bits32(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

void store_word(std::uint8_t* image, std::size_t offset, std::int32_t value) {
    std::memcpy(image + offset, &value, sizeof(value));
}

void store_f32(std::uint8_t* image, std::size_t offset, float value) {
    std::memcpy(image + offset, &value, sizeof(value));
}

void store_f64(std::uint8_t* image, std::size_t offset, double value) {
    std::memcpy(image + offset, &value, sizeof(value));
}

}  // namespace

TreeGrowResult tree_grow_in_time_since_saved(const TreeGrowInputs& in) {
    TreeGrowResult result;
    std::uint8_t* image = result.image;
    auto& calls = result.calls;
    const auto emit = [&calls](TreeGrowCall code, std::uint32_t arg = 0) {
        calls.emplace_back(code, arg);
    };

    // Fixture tokens (observed by the harness, not behavior of this slice).
    std::uint32_t world_token = in.world_token;
    std::uint32_t dynamic_world_token = in.dynamic_world_token;
    std::memcpy(image + 4, &world_token, 4);
    std::memcpy(image + 8, &dynamic_world_token, 4);
    store_word(image, 16, in.pos_x);
    store_word(image, 20, in.pos_y);

    // Live ivar state (the ARM body reads/writes these at their offsets).
    std::int32_t height = in.height;
    std::int32_t max_height_reached = in.max_height_reached;
    float growth_counter = in.growth_counter;
    const float growth_rate = in.growth_rate;
    const std::int32_t max_height = in.max_height;
    const float max_age = in.max_age;
    float age = in.age;
    std::uint8_t dead = in.dead;
    double time_died = 0.0;
    bool time_died_written = false;

    emit(TreeGrowCall::IsStaticTree);
    if (in.is_static_tree == 0) {
        bool grew = false;
        if (dead == 0) {
            emit(TreeGrowCall::WorldTime);
            const double world_time = in.world_time;
            double elapsed = world_time - in.time_since_saved;
            if ((double)age + elapsed < (double)max_age) {
                // Growth loop. timeToGrow is computed ONLY for the first
                // iteration; later iterations reuse the spilled 1.0f.
                float time_to_grow = 1.0f - growth_counter;
                for (;;) {
                    const bool grow_block =
                        (height < max_height) && (elapsed > 0.0);
                    if (!grow_block) {
                        break;
                    }
                    // Stage 1 / Stage 2 chance calculation:
                    // If tile lookup returns nil (has_tile == 0), chance defaults to 0.5f.
                    // If tile is present, chance is computed from sunLight + artificialLightR/G/B.
                    float chance = 0.5f;
                    if (in.has_tile) {
                        const float sun_contrib = (0.5f * static_cast<float>(in.tile_sun_light)) / 255.0f;
                        const int r_div = static_cast<int>(in.tile_artificial_light_r) / 4;
                        const int g_div = static_cast<int>(in.tile_artificial_light_g) / 4;
                        const int b_div = static_cast<int>(in.tile_artificial_light_b) / 2;
                        const int sum = r_div + g_div + b_div;
                        const float art_contrib = static_cast<float>(sum / 1024);
                        chance = sun_contrib + art_contrib;
                    }
                    const float height_ratio =
                        (1.0f - (float)height / (float)max_height) + 0.2f;
                    const float hpct = height_ratio * 0.5f;
                    double denom = 0.005;
                    denom = denom * (double)hpct;
                    denom = denom * (double)growth_rate;
                    denom = denom * (double)chance;
                    const float growth_time =
                        (float)((double)time_to_grow / denom);
                    if ((double)growth_time < elapsed) {
                        elapsed = elapsed - (double)growth_time;
                        age = age + growth_time;
                        growth_counter = 0.0f;
                        emit(TreeGrowCall::IncrementHeight);
                        if (in.height_after_increment >= 0) {
                            height = in.height_after_increment;
                        }
                        if (in.max_height_reached_after_increment >= 0) {
                            max_height_reached =
                                in.max_height_reached_after_increment;
                        }
                        max_height_reached =
                            (height >= max_height_reached)
                                ? height
                                : max_height_reached;
                        emit(TreeGrowCall::UpdateGrowthAdult, bits32(1.0f));
                        time_to_grow = 1.0f;
                        grew = true;
                        continue;
                    }
                    const float e_over_g =
                        (float)(elapsed / (double)growth_time);
                    growth_counter =
                        growth_counter +
                        (1.0f - growth_counter) * e_over_g;
                    elapsed = -1.0;
                    break;
                }
            } else {
                emit(TreeGrowCall::IsGrowingInCompost);
                if (in.is_growing_in_compost != 0) {
                    age = max_age;
                } else {
                    const float adult_max_age =
                        (float)(elapsed - (double)(max_age - age));
                    emit(TreeGrowCall::SowTreeNearParent,
                         bits32(adult_max_age));
                    dead = 1;
                    time_died =
                        in.time_since_saved + (double)max_age - (double)age;
                    time_died_written = true;
                    emit(TreeGrowCall::RemoveAllOwnedTiles);
                }
            }
        }
        if (!grew && dead == 0) {
            emit(TreeGrowCall::UpdateGrowthNo);
        }
    }

    store_word(image, 60, height);
    store_word(image, 64, max_height_reached);
    store_f32(image, 68, growth_counter);
    store_f32(image, 72, growth_rate);
    store_word(image, 88, max_height);
    store_f32(image, 92, max_age);
    store_f32(image, 96, age);
    image[104] = dead;
    if (time_died_written) {
        store_f64(image, 112, time_died);
    }
    return result;
}

}  // namespace blockheads::recovered
