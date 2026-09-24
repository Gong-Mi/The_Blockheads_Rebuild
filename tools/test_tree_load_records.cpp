// Contract test for the recovered Tree fruit-record slice
// (reconstruction/recovered/tree_load_records.cpp). Runs in CTest so CI
// exercises it without the original ELF; tools/test_tree_loadsave_arm_stage2.py
// executes the original 748-word body over the same fruit cases.
#include "tree_load_records.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

using blockheads::recovered::FruitRecordInput;
using blockheads::recovered::FruitRecordResult;
using blockheads::recovered::tree_write_fruit_records;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

}  // namespace

int main() {
    // Fruit cases shared with the ARM harness (x, y, hasCreated) — the harness
    // fits the identity gate so every fruit is written.
    const std::vector<std::vector<std::array<std::int32_t, 3>>> cases = {
        {},
        {{5, 6, 1}},
        {{1, 2, 0}, {3, 4, 1}},
        {{12, 12, 1}, {12, 12, 1}, {12, 12, 1}, {12, 12, 1}},
        {{1023, 1023, 1}, {1023, 0, 0}, {0, 1023, 1}},
        {{100, 100, 0}},
    };
    for (const auto& fruits : cases) {
        std::vector<FruitRecordInput> inputs;
        for (const auto& f : fruits) {
            FruitRecordInput in;
            in.pos_x = f[0];
            in.pos_y = f[1];
            in.has_created_free_block = f[2] != 0;
            in.identity_matches = true;
            inputs.push_back(in);
        }
        const FruitRecordResult result = tree_write_fruit_records(inputs);
        expect(result.fruit_count == static_cast<std::int32_t>(fruits.size()),
               "fruitCount equals the number of written records");
        expect(result.records.size() == fruits.size(), "one record per fruit");
        for (std::size_t i = 0; i < fruits.size(); ++i) {
            expect(result.records[i].pos_x == fruits[i][0], "record +0 pos.x");
            expect(result.records[i].pos_y == fruits[i][1], "record +4 pos.y");
            expect(result.records[i].has_created_free_block ==
                       static_cast<std::uint8_t>(fruits[i][2]),
                   "record +8 hasCreatedFreeBlockThisSeason");
        }
    }

    // The gate: a fruit whose tile identity does not match the tree is skipped
    // and does not advance the counter (the harness proves this path against the
    // original as a negative control).
    std::vector<FruitRecordInput> gated;
    FruitRecordInput skipped;
    skipped.pos_x = 9;
    skipped.pos_y = 9;
    skipped.identity_matches = false;
    gated.push_back(skipped);
    FruitRecordInput kept;
    kept.pos_x = 1;
    kept.pos_y = 1;
    kept.identity_matches = true;
    gated.push_back(kept);
    const FruitRecordResult gated_result = tree_write_fruit_records(gated);
    expect(gated_result.fruit_count == 1, "gate: counter counts written records only");
    expect(gated_result.records.size() == 1 && gated_result.records[0].pos_x == 1,
           "gate: only the matching fruit produced a record");

    if (failures == 0) {
        std::printf("recovered_tree_load_records: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
