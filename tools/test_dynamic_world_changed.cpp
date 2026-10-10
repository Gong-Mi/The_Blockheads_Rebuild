// Contract tests for the recovered dynamic-world-changed recorder slice
// (E29/E30/E40).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_dynamic_world_changed.cpp
//       reconstruction/recovered/dynamic_world_changed.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "dynamic_world_changed.h"

#include <cassert>

using blockheads::recovered::DynamicWorldChangedRecorder;
using blockheads::recovered::MacroPair;
using blockheads::recovered::pairCountFromByteSpan;
using blockheads::recovered::worldPosToMacroIndex;

static void test_producer_skip_set() {
    // E30: objectType 0x16 and 0x1d return before any bookkeeping.
    assert(DynamicWorldChangedRecorder::isProducerSkip(0x16));
    assert(DynamicWorldChangedRecorder::isProducerSkip(0x1d));
    assert(!DynamicWorldChangedRecorder::isProducerSkip(0x15));
    assert(!DynamicWorldChangedRecorder::isProducerSkip(0x1e));

    DynamicWorldChangedRecorder rec;
    assert(!rec.recordAtWorldPos(100, 100, 0x16));
    assert(!rec.recordAtWorldPos(100, 100, 0x1d));
    assert(rec.totalRecords() == 0);
    assert(rec.recordAtWorldPos(100, 100, 0x10));
    assert(rec.totalRecords() == 1);
}

static void test_type_gate() {
    DynamicWorldChangedRecorder rec;
    assert(!rec.recordAtWorldPos(1, 1, 0x41));  // family gate
    assert(!rec.recordAtWorldPos(1, 1, 0x67));
    assert(rec.recordAtWorldPos(1, 1, 0x40));
    assert(rec.totalRecords() == 1);
}

static void test_macro_conversion_and_dedup() {
    DynamicWorldChangedRecorder rec;
    // /32 truncation toward zero (E30 __aeabi_idiv + the E22/E23 cases).
    assert(rec.recordAtWorldPos(63, -63, 0x10));   // -> (1, -1)
    assert(rec.recordAtWorldPos(64, -64, 0x10));   // -> (2, -2), same segment
    assert(!rec.recordAtWorldPos(65, -65, 0x10));  // -> (2, -2): exact-pair dedup
    const auto& seg = rec.segmentAt(DynamicWorldChangedRecorder::segmentForType(0x10));
    assert(seg.size() == 2);
    assert((seg[0] == MacroPair{1, -1}));
    assert((seg[1] == MacroPair{2, -2}));
    // a second identical world position in the same macro cell dedups too.
    assert(!rec.recordAtWorldPos(66, -66, 0x10));
    assert(seg.size() == 2);
}

static void test_segments_are_65() {
    DynamicWorldChangedRecorder rec;
    // records landing in different segments both persist (no cross-segment dedup).
    assert(rec.recordAtWorldPos(32, 32, 0x10));  // -> (1,1)
    assert(rec.recordAtWorldPos(32, 32, 0x20));  // -> (1,1) but a different segment
    assert(rec.totalRecords() == 2);
    const std::size_t s1 = DynamicWorldChangedRecorder::segmentForType(0x10);
    const std::size_t s2 = DynamicWorldChangedRecorder::segmentForType(0x20);
    assert(s1 != s2);
    assert(rec.segmentAt(s1).size() == 1);
    assert(rec.segmentAt(s2).size() == 1);
}

static void test_consumer_idioms() {
    // E40: (end - start) / 8 == pair count (two words per pair).
    assert(pairCountFromByteSpan(0) == 0);
    assert(pairCountFromByteSpan(8) == 1);
    assert(pairCountFromByteSpan(0x30c) == 0x61);  // 780 / 8 = 97 pairs (a full segment)
    // consumer type skip {0x2e, 0x18}
    assert(DynamicWorldChangedRecorder::isConsumerTypeSkip(0x2e));
    assert(DynamicWorldChangedRecorder::isConsumerTypeSkip(0x18));
    assert(!DynamicWorldChangedRecorder::isConsumerTypeSkip(0x2d));
}

static void test_macro_index_helper() {
    assert(worldPosToMacroIndex(0) == 0);
    assert(worldPosToMacroIndex(31) == 0);
    assert(worldPosToMacroIndex(32) == 1);
    assert(worldPosToMacroIndex(-31) == 0);
    assert(worldPosToMacroIndex(-32) == -1);
    assert(worldPosToMacroIndex(-33) == -1);
}

int main() {
    test_producer_skip_set();
    test_type_gate();
    test_macro_conversion_and_dedup();
    test_segments_are_65();
    test_consumer_idioms();
    test_macro_index_helper();
    return 0;
}
