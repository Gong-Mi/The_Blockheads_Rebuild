// Recovered semantics of -[Plant loadSaveDictValues:] (0x009554a0, 332 words)
// — the tree-family read-back path decoded in batch b3b and promoted to
// executed evidence in batch b4b.
//
// Decoded order (every step verified against the pinned ARM in b3b):
//   seasonOffset@68        objectForKey → intValue   → str
//   age@72                 objectForKey → floatValue → vstr s0
//   gatherProgress@80      objectForKey → intValue   → str
//   hasFloweredThisSeason@84 / flowering@85 / frozen@76
//                          objectForKey → boolValue  → strb
//   maxAgeGene@54          objectForKey → intValue   → strh → clamp(1,255)
//   growthRateGene@56      objectForKey → intValue   → strh → clamp(1,255)
//   saveTime               objectForKey → doubleValue → NO store; compared
//                          against [self.world worldTime]:
//                            if (worldTime - saveTime > 1800.0)
//                                hasFloweredThisSeason@84 = 0
// The clamp is the real local helper at 0x004c0b70
// (`out=v; if v>b out=b; if v<a out=a`), executed rather than re-derived.
#pragma once

#include <cstdint>

namespace blockheads::recovered {

struct PlantLoadInputs {
    std::int32_t season_offset = 0;      // dictionary seasonOffset (int)
    float age = 0.0f;                    // dictionary age (float)
    std::int32_t gather_progress = 0;    // dictionary gatherProgress (int)
    bool has_flowered = false;           // dictionary hasFloweredThisSeason
    bool flowering = false;              // dictionary flowering
    bool frozen = false;                 // dictionary frozen
    std::int32_t max_age_gene = 0;       // dictionary maxAgeGene (int)
    std::int32_t growth_rate_gene = 0;   // dictionary growthRateGene (int)
    double save_time = 0.0;              // dictionary saveTime (world clock)
    double world_time = 0.0;             // [self.world worldTime]
};

struct PlantLoadFields {
    std::int32_t season_offset = 0;      // @68 word
    float age = 0.0f;                    // @72 float
    std::int32_t gather_progress = 0;    // @80 word
    std::uint8_t has_flowered = 0;       // @84 byte
    std::uint8_t flowering = 0;          // @85 byte
    std::uint8_t frozen = 0;             // @76 byte
    std::uint16_t max_age_gene = 0;      // @54 halfword, clamped to [1,255]
    std::uint16_t growth_rate_gene = 0;  // @56 halfword, clamped to [1,255]
};

// The 0x004c0b70 helper: out=v; if (v > high) out=high; if (v < low) out=low.
std::int32_t plant_gene_clamp(std::int32_t value, std::int32_t low, std::int32_t high);

PlantLoadFields plant_load_save_dict_values(const PlantLoadInputs& inputs);

}  // namespace blockheads::recovered
