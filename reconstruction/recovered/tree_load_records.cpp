#include "tree_load_records.h"

namespace blockheads::recovered {

FruitRecordResult tree_write_fruit_records(
    const std::vector<FruitRecordInput>& fruits) {
    FruitRecordResult result;
    // fruitCount@128 was reset to 0 before the enumeration; it is the running
    // index, so only written records advance it.
    for (const auto& fruit : fruits) {
        if (!fruit.identity_matches) {
            continue;
        }
        WrittenFruitRecord record;
        record.pos_x = fruit.pos_x;
        record.pos_y = fruit.pos_y;
        record.has_created_free_block = fruit.has_created_free_block ? 1u : 0u;
        result.records.push_back(record);
        ++result.fruit_count;
    }
    return result;
}

}  // namespace blockheads::recovered
