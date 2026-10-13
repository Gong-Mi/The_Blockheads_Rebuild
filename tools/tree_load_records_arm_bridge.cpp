// Optional ARM differential bridge for the Tree fruit-record slice
// (reconstruction/recovered/tree_load_records.cpp), driven by
// tools/test_tree_loadsave_arm_stage2.py which executes the original 748-word
// body and reads the records back out of the tree instance.
#include "tree_load_records.h"

#include <cstdint>
#include <cstring>

using blockheads::recovered::FruitRecordInput;

extern "C" {

struct RecoveredFruitIn {
    std::int32_t count;          // up to 4 fruits
    std::int32_t pos_x[4];
    std::int32_t pos_y[4];
    std::int32_t created[4];
};

struct RecoveredFruitOut {
    std::int32_t fruit_count;
    std::int32_t record_x[4];
    std::int32_t record_y[4];
    std::int32_t record_created[4];
};

void recovered_tree_fruit_records(const RecoveredFruitIn* in,
                                  RecoveredFruitOut* out) {
    std::vector<FruitRecordInput> fruits;
    for (std::int32_t i = 0; i < in->count && i < 4; ++i) {
        FruitRecordInput fruit;
        fruit.pos_x = in->pos_x[i];
        fruit.pos_y = in->pos_y[i];
        fruit.has_created_free_block = in->created[i] != 0;
        fruit.identity_matches = true;  // harness fits the identity gate
        fruits.push_back(fruit);
    }
    const auto result = blockheads::recovered::tree_write_fruit_records(fruits);
    std::memset(out, 0, sizeof(*out));
    out->fruit_count = result.fruit_count;
    for (std::size_t i = 0; i < result.records.size() && i < 4; ++i) {
        out->record_x[i] = result.records[i].pos_x;
        out->record_y[i] = result.records[i].pos_y;
        out->record_created[i] = result.records[i].has_created_free_block;
    }
}

}  // extern "C"
