// Contract test for the recovered Plant load slice
// (reconstruction/recovered/plant_load_save_dict.cpp). Runs in CTest so CI
// exercises it without the original ELF. The case list is shared with
// tools/test_plant_loadsave_arm.py, which executes the original ARM method.
#include "plant_load_save_dict.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

using blockheads::recovered::PlantLoadFields;
using blockheads::recovered::PlantLoadInputs;
using blockheads::recovered::plant_gene_clamp;
using blockheads::recovered::plant_load_save_dict_values;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

struct Case {
    std::int32_t season_offset;
    float age;
    std::int32_t gather_progress;
    std::int32_t has_flowered;
    std::int32_t flowering;
    std::int32_t frozen;
    std::int32_t max_age_gene;
    std::int32_t growth_rate_gene;
    double save_time;
    double world_time;
};

}  // namespace

int main() {
    // Same inputs as the ARM harness (keep both lists in sync).
    const std::vector<Case> cases = {
        {0, 0.0f, 0, 0, 0, 0, 0, 0, 0.0, 0.0},
        {1, 1.5f, 2, 1, 1, 1, 1, 1, 0.0, 0.0},
        {100, 42.25f, 7, 1, 0, 1, 255, 255, 0.0, 0.0},
        {-5, -1.0f, -3, 0, 1, 0, 256, 65535, 0.0, 0.0},
        {7, 0.5f, 9, 1, 1, 0, 32768, 300, 0.0, 0.0},
        {3, 2.0f, 4, 1, 0, 1, -1, -2, 0.0, 0.0},
        {11, 3.75f, 12, 1, 1, 1, 254, 2, 1000.0, 2800.5},
        {12, 4.0f, 13, 1, 1, 1, 60, 60, 1000.0, 2800.0},
        {13, 5.0f, 14, 1, 0, 1, 60, 60, 1000.0, 2799.9999},
        {0, 0.0f, 0, 0, 0, 0, 1000, 1000, 500.0, 2300.5},
    };

    // Direct helper checks (the real 0x004c0b70 semantics).
    expect(plant_gene_clamp(0, 1, 255) == 1, "clamp low");
    expect(plant_gene_clamp(1, 1, 255) == 1, "clamp low boundary");
    expect(plant_gene_clamp(255, 1, 255) == 255, "clamp high boundary");
    expect(plant_gene_clamp(256, 1, 255) == 255, "clamp high");
    expect(plant_gene_clamp(65535, 1, 255) == 255, "clamp truncated -1");
    expect(plant_gene_clamp(128, 1, 255) == 128, "clamp identity");

    for (const auto& c : cases) {
        PlantLoadInputs in;
        in.season_offset = c.season_offset;
        in.age = c.age;
        in.gather_progress = c.gather_progress;
        in.has_flowered = c.has_flowered != 0;
        in.flowering = c.flowering != 0;
        in.frozen = c.frozen != 0;
        in.max_age_gene = c.max_age_gene;
        in.growth_rate_gene = c.growth_rate_gene;
        in.save_time = c.save_time;
        in.world_time = c.world_time;
        const PlantLoadFields f = plant_load_save_dict_values(in);
        expect(f.season_offset == c.season_offset, "seasonOffset passthrough");
        expect(std::memcmp(&f.age, &c.age, 4) == 0, "age float passthrough");
        expect(f.gather_progress == c.gather_progress, "gatherProgress");
        expect(f.frozen == static_cast<std::uint8_t>(c.frozen), "frozen byte");
        expect(f.flowering == static_cast<std::uint8_t>(c.flowering),
               "flowering byte");
        const auto trunc = [](std::int32_t v) {
            return static_cast<std::int32_t>(static_cast<std::uint16_t>(v));
        };
        expect(f.max_age_gene == static_cast<std::uint16_t>(
                   plant_gene_clamp(trunc(c.max_age_gene), 1, 255)),
               "maxAgeGene truncate+clamp");
        expect(f.growth_rate_gene == static_cast<std::uint16_t>(
                   plant_gene_clamp(trunc(c.growth_rate_gene), 1, 255)),
               "growthRateGene truncate+clamp");
        const std::uint8_t expected_flag =
            (c.world_time - c.save_time > 1800.0)
                ? 0u
                : static_cast<std::uint8_t>(c.has_flowered);
        expect(f.has_flowered == expected_flag, "hasFloweredThisSeason gate");
    }

    // The saveTime gate must not disturb the other fields.
    const PlantLoadFields reset =
        plant_load_save_dict_values([] {
            PlantLoadInputs in;
            in.season_offset = 9;
            in.age = 8.5f;
            in.gather_progress = 7;
            in.has_flowered = true;
            in.max_age_gene = 30;
            in.growth_rate_gene = 40;
            in.save_time = 0.0;
            in.world_time = 1800.0001;
            return in;
        }());
    expect(reset.has_flowered == 0, "gate resets the flag");
    expect(reset.season_offset == 9 && reset.gather_progress == 7 &&
               reset.max_age_gene == 30 && reset.growth_rate_gene == 40,
           "gate leaves the other fields alone");
    expect(std::memcmp(&reset.age, &std::vector<float>{8.5f}[0], 4) == 0,
           "gate leaves age alone");

    if (failures == 0) {
        std::printf("recovered_plant_load_save_dict: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
