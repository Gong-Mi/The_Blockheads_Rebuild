#include "plant_load_save_dict.h"

namespace blockheads::recovered {

std::int32_t plant_gene_clamp(std::int32_t value, std::int32_t low,
                              std::int32_t high) {
    // Mirrors 0x004c0b70 exactly: the upper bound is applied first, then the
    // lower bound, both with signed 32-bit compares on the ldrh value.
    std::int32_t out = value;
    if (value > high) {
        out = high;
    }
    if (value < low) {
        out = low;
    }
    return out;
}

PlantLoadFields plant_load_save_dict_values(const PlantLoadInputs& inputs) {
    PlantLoadFields fields;
    // The stores happen in the read order; every field is overwritten from the
    // dictionary (the load is destructive, not additive).
    fields.season_offset = inputs.season_offset;                       // @68
    fields.age = inputs.age;                                           // @72
    fields.gather_progress = inputs.gather_progress;                   // @80
    fields.has_flowered = inputs.has_flowered ? 1u : 0u;               // @84
    fields.flowering = inputs.flowering ? 1u : 0u;                     // @85
    fields.frozen = inputs.frozen ? 1u : 0u;                           // @76
    // Genes: the halfword store truncates first (strh of the intValue), then the
    // value is read back and clamped through the real helper.
    const auto truncate16 = [](std::int32_t v) {
        return static_cast<std::int32_t>(static_cast<std::uint16_t>(v));
    };
    fields.max_age_gene = static_cast<std::uint16_t>(
        plant_gene_clamp(truncate16(inputs.max_age_gene), 1, 255));
    fields.growth_rate_gene = static_cast<std::uint16_t>(
        plant_gene_clamp(truncate16(inputs.growth_rate_gene), 1, 255));
    // saveTime is not restored: it only gates the season flag, and only when
    // the world clock has advanced more than 1800 seconds past it.
    if (inputs.world_time - inputs.save_time > 1800.0) {
        fields.has_flowered = 0;
    }
    return fields;
}

}  // namespace blockheads::recovered
