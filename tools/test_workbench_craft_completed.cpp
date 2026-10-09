// Contract tests for the recovered workbench craft completion
// (-[craftCompleted], E75/E78 line).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_workbench_craft_completed.cpp
//       reconstruction/recovered/workbench_craft_completed.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "workbench_craft_completed.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using blockheads::recovered::CraftCompletedHooks;
using blockheads::recovered::kAbortPaidItemType;
using blockheads::recovered::workbench_craft_completed;

namespace {

// A record-driven harness with a call log, so the tests pin the stage order.
struct Harness {
    std::vector<std::string> log;
    bool blockhead_present = true;
    bool needs_removed_value = false;
    std::int32_t f0_value = 0;
    std::vector<std::int32_t> types;
    std::vector<std::int32_t> values;
    // source_count per (slot, unit) - consumed from the front.
    std::vector<std::vector<std::int32_t>> source_counts;
    // preserve results per (slot, unit).
    std::vector<std::vector<bool>> preserve_results;
    int abort_calls = 0;
    int finish_calls = 0;
    std::vector<std::pair<int, int>> builds;    // (slot, unit)
    std::vector<std::pair<int, int>> consumes;  // (slot, unit)
    std::vector<std::vector<std::int32_t>> preserve_args; // (slot_type, f0)

    CraftCompletedHooks hooks() {
        CraftCompletedHooks h;
        h.current_blockhead_present = [this] {
            log.push_back("cb");
            return blockhead_present;
        };
        h.needs_removed = [this] {
            log.push_back("nr");
            return needs_removed_value;
        };
        h.abort_craft = [this] {
            log.push_back("abort");
            ++abort_calls;
        };
        h.finish = [this] {
            log.push_back("finish");
            ++finish_calls;
        };
        h.slot_count = [this] {
            log.push_back("count");
            return static_cast<std::int32_t>(types.size());
        };
        h.slot_item_type = [this](int slot) {
            log.push_back("type");
            return types[static_cast<std::size_t>(slot)];
        };
        h.slot_value = [this](int slot) {
            log.push_back("value");
            return values[static_cast<std::size_t>(slot)];
        };
        h.record_f0 = [this] {
            log.push_back("f0");
            return f0_value;
        };
        h.source_count = [this](int slot) {
            log.push_back("scount");
            return source_counts[static_cast<std::size_t>(slot)][cur(static_cast<std::size_t>(slot))];
        };
        h.preserve_data_a = [this](int slot, std::int32_t slot_type, std::int32_t rec_f0) {
            log.push_back("preserve");
            preserve_args.push_back({slot_type, rec_f0});
            return preserve_results[static_cast<std::size_t>(slot)][cur(static_cast<std::size_t>(slot))];
        };
        h.build_output_unit = [this](int slot) {
            log.push_back("build");
            builds.emplace_back(slot, cur(static_cast<std::size_t>(slot)));
        };
        h.consume_source = [this](int slot) {
            log.push_back("consume");
            const auto s = static_cast<std::size_t>(slot);
            consumes.emplace_back(slot, cur(s));
            ++unit_index_[s];
        };
        return h;
    }

    // Per-slot unit cursors advanced by consume_source (lazily sized).
    std::vector<int> unit_index_ = {};
    int cur(std::size_t slot) {
        if (unit_index_.size() < types.size()) {
            unit_index_.assign(types.size(), 0);
        }
        return unit_index_[slot];
    }
};

// The nil-blockhead bail: abortCraft runs WITHOUT a needsRemoved probe, then
// the shared tail; no record work happens.
static void test_bail_missing_blockhead() {
    Harness h;
    h.blockhead_present = false;
    auto hooks = h.hooks();
    workbench_craft_completed(hooks);
    const std::vector<std::string> expected = {"cb", "abort", "finish"};
    assert(h.log == expected);
    assert(h.abort_calls == 1);
}

// A present blockhead with needsRemoved set: the probe runs, then the same
// abort bail.
static void test_bail_needs_removed() {
    Harness h;
    h.blockhead_present = true;
    h.needs_removed_value = true;
    auto hooks = h.hooks();
    workbench_craft_completed(hooks);
    const std::vector<std::string> expected = {"cb", "nr", "abort", "finish"};
    assert(h.log == expected);
}

// The paid slots skip the unit loop; the unit-less slots still read their
// f3 value.
static void test_paid_skip_and_empty_units() {
    Harness h;
    h.types = {kAbortPaidItemType, 7};
    h.values = {9, 0};
    h.source_counts = {{}, {}};
    h.preserve_results = {{}, {}};
    auto hooks = h.hooks();
    workbench_craft_completed(hooks);
    const std::vector<std::string> expected = {
        "cb", "nr", "count",
        "type",            // slot 0: paid - skipped without a value read
        "type", "value",   // slot 1: zero units - no inner reads
        "finish",
    };
    assert(h.log == expected);
    assert(h.builds.empty());
    assert(h.consumes.empty());
}

// The unit loop matrix: the count>0 predicate, the preserve gate (build
// only on true) and the consume that runs on BOTH outcomes; a zero count
// abandons the remaining units of the slot.
static void test_unit_loop_matrix() {
    Harness h;
    h.types = {5};
    h.values = {3};
    h.f0_value = 42;
    h.source_counts = {{2, 1, 0}};
    h.preserve_results = {{true, false, true}};
    auto hooks = h.hooks();
    workbench_craft_completed(hooks);
    const std::vector<std::string> expected = {
        "cb", "nr", "count",
        "type", "value",
        "scount", "type", "f0", "preserve", "build", "consume", // j0: built
        "scount", "type", "f0", "preserve", "consume",           // j1: not built
        "scount",                                                // j2: count 0 -> break
        "finish",
    };
    assert(h.log == expected);
    assert(h.builds.size() == 1);
    assert(h.builds[0] == std::make_pair(0, 0));
    assert(h.consumes.size() == 2);
    assert(h.consumes[1] == std::make_pair(0, 1));
    // The preserve arguments: (f2[i], f0).
    assert(h.preserve_args.size() == 2);
    assert(h.preserve_args[0][0] == 5);
    assert(h.preserve_args[0][1] == 42);
}

// A mixed record: the full order across three slots in one log.
static void test_mixed_record_order() {
    Harness h;
    h.types = {5, kAbortPaidItemType, 7};
    h.values = {1, 8, 1};
    h.f0_value = 60;
    h.source_counts = {{4}, {}, {9}};
    h.preserve_results = {{true}, {}, {true}};
    auto hooks = h.hooks();
    workbench_craft_completed(hooks);
    const std::vector<std::string> expected = {
        "cb", "nr", "count",
        "type", "value", "scount", "type", "f0", "preserve", "build", "consume",
        "type", // paid slot: no value read
        "type", "value", "scount", "type", "f0", "preserve", "build", "consume",
        "finish",
    };
    assert(h.log == expected);
    assert(h.finish_calls == 1);
}

// An empty record walks straight to the finish.
static void test_empty_record() {
    Harness h;
    auto hooks = h.hooks();
    workbench_craft_completed(hooks);
    const std::vector<std::string> expected = {"cb", "nr", "count", "finish"};
    assert(h.log == expected);
}

} // namespace

int main() {
    test_bail_missing_blockhead();
    test_bail_needs_removed();
    test_paid_skip_and_empty_units();
    test_unit_loop_matrix();
    test_mixed_record_order();
    test_empty_record();
    std::printf("workbench_craft_completed: all cases passed\n");
    return 0;
}
