// Optional ARM differential bridge: exposes the recovered Plant load contract
// to tools/test_plant_loadsave_arm.py, which executes the ORIGINAL 332-word
// method under Unicorn (with the real 0x004c0b70 clamp helper) and compares the
// resulting object fields against this module built at -O0 and -O2.
#include "plant_load_save_dict.h"

#include <cstdint>

using blockheads::recovered::PlantLoadFields;
using blockheads::recovered::PlantLoadInputs;

extern "C" {

struct RecoveredPlantLoadIn {
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

struct RecoveredPlantLoadOut {
    std::int32_t season_offset;
    float age;
    std::int32_t gather_progress;
    std::uint8_t has_flowered;
    std::uint8_t flowering;
    std::uint8_t frozen;
    std::uint16_t max_age_gene;
    std::uint16_t growth_rate_gene;
};

void recovered_plant_load_fields(const RecoveredPlantLoadIn* in,
                                 RecoveredPlantLoadOut* out) {
    PlantLoadInputs inputs;
    inputs.season_offset = in->season_offset;
    inputs.age = in->age;
    inputs.gather_progress = in->gather_progress;
    inputs.has_flowered = in->has_flowered != 0;
    inputs.flowering = in->flowering != 0;
    inputs.frozen = in->frozen != 0;
    inputs.max_age_gene = in->max_age_gene;
    inputs.growth_rate_gene = in->growth_rate_gene;
    inputs.save_time = in->save_time;
    inputs.world_time = in->world_time;
    const PlantLoadFields fields =
        blockheads::recovered::plant_load_save_dict_values(inputs);
    out->season_offset = fields.season_offset;
    out->age = fields.age;
    out->gather_progress = fields.gather_progress;
    out->has_flowered = fields.has_flowered;
    out->flowering = fields.flowering;
    out->frozen = fields.frozen;
    out->max_age_gene = fields.max_age_gene;
    out->growth_rate_gene = fields.growth_rate_gene;
}

}  // extern "C"
