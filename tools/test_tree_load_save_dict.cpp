// Contract test for the recovered Tree loader stage-1 slice
// (reconstruction/recovered/tree_load_save_dict.cpp). Runs in CTest so CI
// exercises it without the original ELF; tools/test_tree_loadsave_arm.py
// executes the original 748-word body over the same case list.
#include "tree_load_save_dict.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

using blockheads::recovered::TreeLoadFields;
using blockheads::recovered::TreeLoadInputs;
using blockheads::recovered::tree_load_save_dict_stage1;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

struct Case {
    std::int32_t season_offset;
    std::int32_t dead;
    double time_died;
    float remove_check_count;
    std::int32_t height;
    float age;
    std::int32_t is_static_tree;
};

}  // namespace

int main() {
    // Same inputs as the ARM harness (keep both lists in sync); the harness
    // only feeds cases with is_static_tree = 1 and an empty fruit array.
    const std::vector<Case> cases = {
        {0, 0, 0.0, 0.0f, 0, 0.0f, 1},
        {1, 1, 1.5, 2.5f, 12, 3.5f, 1},
        {-7, 0, -0.25, 1234.5f, -9, -2.5f, 1},
        {INT32_MAX, 1, 1.0e9, -1.5f, INT32_MAX, 1.5f, 1},
        {INT32_MIN, 0, 1.7976931348623157e308, 3.4028234663852886e38f,
         INT32_MIN, 7.25f, 1},
    };
    for (const auto& c : cases) {
        TreeLoadInputs in;
        in.season_offset = c.season_offset;
        in.dead = c.dead != 0;
        in.time_died = c.time_died;
        in.remove_check_count = c.remove_check_count;
        in.height = c.height;
        in.age = c.age;
        in.fruit_array_count = 0;
        in.is_static_tree = c.is_static_tree != 0;
        const TreeLoadFields f = tree_load_save_dict_stage1(in);
        expect(f.tree_season_offset == c.season_offset, "treeSeasonOffset word");
        expect(f.dead == static_cast<std::uint8_t>(c.dead), "dead byte");
        expect(std::memcmp(&f.time_died, &c.time_died, 8) == 0,
               "timeDied 64-bit");
        expect(std::memcmp(&f.remove_check_count, &c.remove_check_count, 4) == 0,
               "removeCheckCount float");
        expect(f.height == c.height, "height word (always-on)");
        expect(std::memcmp(&f.age, &c.age, 4) == 0, "age float (always-on)");
        expect(f.fruit_count == 0, "fruitCount reset to 0");
        expect(f.gene_block_skipped, "static tree skips the gene block");
    }

    // Non-static trees must NOT report the gate as fired. This branch needs the
    // gene/growth block stubs and is deliberately outside the executed domain.
    TreeLoadInputs live;
    live.is_static_tree = false;
    const TreeLoadFields live_fields = tree_load_save_dict_stage1(live);
    expect(!live_fields.gene_block_skipped,
           "non-static tree does not skip the gene block");

    if (failures == 0) {
        std::printf("recovered_tree_load_save_dict_stage1: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
