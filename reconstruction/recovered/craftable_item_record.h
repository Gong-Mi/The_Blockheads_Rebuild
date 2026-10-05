// Recovered model: the CraftableItem record - the 124-byte value the crafting pipeline copies.
//
// The evidence here is unusually direct: the type encoding in the original's own method table IS a layout
// description. -[PaintingCraftableItemObject initWithCraftableItem:imageData:outputImageData:] declares
//
//     @140@0:4{CraftableItem=ii[8i][8i]iiiSSi[8i]}8@132@136
//
// so the record is eleven fields of int / unsigned short / int[8] in that order. Its size comes out the
// same two independent ways: the encoding sums to 124 bytes, and the argument offsets in the same
// signature step from 8 to 132, a difference of 124. The 51 recorded 124-byte copy sites agree too.
//
// The offsets below are computed from the encoding by tools/test_craftable_item_record.py, which also
// re-derives them from the method table and requires this header to match - so a hand-edited offset fails
// instead of quietly retyping the binary.
//
// WHAT IS STILL NOT KNOWN, and is not faked here: what the fields MEAN. They are positional (f0..f10).
// The two int[8] arrays read like per-slot inventories or counted lists and the two `S` fields like small
// counts, but that is a reading, not evidence. The shape is now machine-checked; the semantics remain the
// open problem this project has carried the longest.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered {

struct CraftableItemRecord {
    std::int32_t f0;  // +0
    std::int32_t f1;  // +4
    std::int32_t f2[8];  // +8
    std::int32_t f3[8];  // +40
    std::int32_t f4;  // +72
    std::int32_t f5;  // +76
    std::int32_t f6;  // +80
    std::uint16_t f7;  // +84
    std::uint16_t f8;  // +86
    std::int32_t f9;  // +88
    std::int32_t f10[8];  // +92
};

static_assert(sizeof(CraftableItemRecord) == 124, "the encoding sums to 124 bytes");
static_assert(offsetof(CraftableItemRecord, f0) == 0, "field f0");
static_assert(offsetof(CraftableItemRecord, f1) == 4, "field f1");
static_assert(offsetof(CraftableItemRecord, f2) == 8, "field f2");
static_assert(offsetof(CraftableItemRecord, f3) == 40, "field f3");
static_assert(offsetof(CraftableItemRecord, f4) == 72, "field f4");
static_assert(offsetof(CraftableItemRecord, f5) == 76, "field f5");
static_assert(offsetof(CraftableItemRecord, f6) == 80, "field f6");
static_assert(offsetof(CraftableItemRecord, f7) == 84, "field f7");
static_assert(offsetof(CraftableItemRecord, f8) == 86, "field f8");
static_assert(offsetof(CraftableItemRecord, f9) == 88, "field f9");
static_assert(offsetof(CraftableItemRecord, f10) == 92, "field f10");

}  // namespace blockheads::recovered
