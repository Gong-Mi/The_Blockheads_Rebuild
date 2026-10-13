#include "tree_load_save_dict.h"

namespace blockheads::recovered {

TreeLoadFields tree_load_save_dict_stage1(const TreeLoadInputs& inputs) {
    TreeLoadFields fields;
    fields.tree_season_offset = inputs.season_offset;   // @84 word
    fields.dead = inputs.dead ? 1u : 0u;                // @104 byte
    fields.time_died = inputs.time_died;                // @112 64-bit
    fields.remove_check_count = inputs.remove_check_count;  // @120 float
    // height and age are read *before* the gate: the executed differential
    // (batch b4d) showed the always-on key order as treeSeasonOffset, dead,
    // timeDied, removeCheckCount, treeFruit, height, age, and only then
    // [self isStaticTree].
    fields.height = inputs.height;                          // @60 word
    fields.age = inputs.age;                                // @96 float
    // treeFruit: fruitCount@128 is reset to 0 before the enumeration. With an
    // empty array the enumeration returns 0 and the loop body never runs, so the
    // counter stays 0 (the 12-byte records and the identity checks are a later
    // stage).
    fields.fruit_count = 0;
    if (inputs.fruit_array_count != 0) {
        // Outside this stage's verified domain — the harness only feeds 0.
        fields.fruit_count = -1;
    }
    // The gate: static trees skip the gene/growth block entirely.
    fields.gene_block_skipped = inputs.is_static_tree;
    return fields;
}

}  // namespace blockheads::recovered
