// Recovered semantics of -[Tree loadSaveDictValues:] (0x004c2df0, 748 words) —
// STAGE 1 of the level-B promotion: the scalar chains, the treeFruit reset, the
// enumeration entry and the isStaticTree gate, with an EMPTY fruit array.
//
// Decoded (b3a static + b4d executed):
//   treeSeasonOffset@84   objectForKey → intValue   → str
//   dead@104             objectForKey → boolValue  → strb
//   timeDied@112         objectForKey → doubleValue → vstr d0 (64-bit)
//   removeCheckCount@120 objectForKey → floatValue → vstr s2
//   height@60            objectForKey → intValue   → str      (ALWAYS-ON)
//   age@96               objectForKey → floatValue → vstr s0  (ALWAYS-ON)
//   treeFruit            objectForKey → array; fruitCount@128 reset to 0;
//                        memset(…, 0, …) executed; then
//                        countByEnumeratingWithState:objects:count: which
//                        returns 0 for an empty array, so no record is built
//   isStaticTree gate    [self isStaticTree] → sxtb → when true the gene/growth
//                        block is skipped and control jumps to the epilogue
// NOT covered by this stage (next batches): the gene/growth block for
// non-static trees and the per-fruit 12-byte record construction, which needs
// the local coordinate helper 0x00a12f24, the `tileIsKindOfSelf:` check and
// the 64-bit uniqueID@40 identity comparison.
#pragma once

#include <cstdint>

namespace blockheads::recovered {

struct TreeLoadInputs {
    std::int32_t season_offset = 0;   // dictionary treeSeasonOffset (int)
    bool dead = false;                // dictionary dead (bool)
    double time_died = 0.0;           // dictionary timeDied (double)
    float remove_check_count = 0.0f;  // dictionary removeCheckCount (float)
    std::int32_t height = 0;          // dictionary height (int, always-on)
    float age = 0.0f;                 // dictionary age (float, always-on)
    int fruit_array_count = 0;        // number of entries in the treeFruit array
    bool is_static_tree = false;      // [self isStaticTree]
};

struct TreeLoadFields {
    std::int32_t tree_season_offset = 0;  // @84 word
    std::uint8_t dead = 0;                // @104 byte
    double time_died = 0.0;               // @112 64-bit
    float remove_check_count = 0.0f;      // @120 float
    std::int32_t height = 0;              // @60 word (always-on)
    float age = 0.0f;                     // @96 float (always-on)
    std::int32_t fruit_count = 0;         // @128, reset then incremented per record
    bool gene_block_skipped = false;      // true when isStaticTree gate fired
};

TreeLoadFields tree_load_save_dict_stage1(const TreeLoadInputs& inputs);

}  // namespace blockheads::recovered
