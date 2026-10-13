// Optional ARM differential bridge for the Tree loader stage-1 slice
// (reconstruction/recovered/tree_load_save_dict.cpp), driven by
// tools/test_tree_loadsave_arm.py which executes the original 748-word body.
#include "tree_load_save_dict.h"

#include <cstdint>

using blockheads::recovered::TreeLoadFields;
using blockheads::recovered::TreeLoadInputs;

extern "C" {

struct RecoveredTreeLoadIn {
    std::int32_t season_offset;
    std::int32_t dead;
    double time_died;
    float remove_check_count;
    std::int32_t height;
    float age;
    std::int32_t fruit_array_count;
    std::int32_t is_static_tree;
};

struct RecoveredTreeLoadOut {
    std::int32_t tree_season_offset;
    std::uint8_t dead;
    double time_died;
    float remove_check_count;
    std::int32_t height;
    float age;
    std::int32_t fruit_count;
    std::int32_t gene_block_skipped;
};

void recovered_tree_load_stage1(const RecoveredTreeLoadIn* in,
                                RecoveredTreeLoadOut* out) {
    TreeLoadInputs inputs;
    inputs.season_offset = in->season_offset;
    inputs.dead = in->dead != 0;
    inputs.time_died = in->time_died;
    inputs.remove_check_count = in->remove_check_count;
    inputs.height = in->height;
    inputs.age = in->age;
    inputs.fruit_array_count = in->fruit_array_count;
    inputs.is_static_tree = in->is_static_tree != 0;
    const TreeLoadFields fields =
        blockheads::recovered::tree_load_save_dict_stage1(inputs);
    out->tree_season_offset = fields.tree_season_offset;
    out->dead = fields.dead;
    out->time_died = fields.time_died;
    out->remove_check_count = fields.remove_check_count;
    out->height = fields.height;
    out->age = fields.age;
    out->fruit_count = fields.fruit_count;
    out->gene_block_skipped = fields.gene_block_skipped ? 1 : 0;
}

}  // extern "C"
