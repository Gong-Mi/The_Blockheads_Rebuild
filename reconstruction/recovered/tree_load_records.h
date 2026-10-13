// Recovered semantics of the per-fruit record writer inside
// -[Tree loadSaveDictValues:] (0x004c2df0) — batch b4e stage 2, verified by
// executing the original 748-word body under Unicorn
// (tools/test_tree_loadsave_arm_stage2.py).
//
// Executed facts (the record path really runs):
//   * treeFruit → array; fruitCount@128 is reset to 0 and then used as the
//     RUNNING INDEX of the record buffer pointed at by treeFruits@124.
//   * Per enumerated fruit dictionary:
//       +0  pos.x word                        (objectForKey → intValue)
//       +4  pos.y word                        (objectForKey → intValue)
//       +8  hasCreatedFreeBlockThisSeason byte (objectForKey → boolValue)
//     stride 0xc, and fruitCount@128 is incremented per WRITTEN record.
//   * A record is written only when the tile looked up for (pos.x, pos.y)
//     satisfies the original's gate:
//       [tile+0x28] == self[uniqueID@40] && [tile+0x2c] == self[uniqueID@44]
//       && [self tileIsKindOfSelf:tile]
//     A fruit failing the gate is skipped without touching the counter.
#pragma once

#include <cstdint>
#include <vector>

namespace blockheads::recovered {

struct FruitRecordInput {
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    bool has_created_free_block = false;
    // Whether the looked-up tile matches this tree (the original's gate).
    bool identity_matches = true;
};

struct WrittenFruitRecord {
    std::int32_t pos_x = 0;                // +0
    std::int32_t pos_y = 0;                // +4
    std::uint8_t has_created_free_block = 0;  // +8
};

struct FruitRecordResult {
    std::vector<WrittenFruitRecord> records;
    std::int32_t fruit_count = 0;  // @128 == records.size() in the verified domain
};

FruitRecordResult tree_write_fruit_records(
    const std::vector<FruitRecordInput>& fruits);

}  // namespace blockheads::recovered
