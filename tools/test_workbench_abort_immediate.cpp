// Contract tests for the recovered workbench hard abort
// (-[abortImmediatelyAndRestoreBlockheadItems], E78).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_workbench_abort_immediate.cpp
//       reconstruction/recovered/workbench_abort_immediate.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
// The hook set itself pins the missing fractionComplete reset: there is no
// set_fraction_complete hook on this abort (unlike the soft one).
#include "workbench_abort_immediate.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using blockheads::recovered::AbortImmediateHooks;
using blockheads::recovered::kAbortPaidItemType;
using blockheads::recovered::kAbortPaidUnitCap;
using blockheads::recovered::workbench_abort_immediately;

namespace {

// A record-driven harness with a call log, so the tests pin the stage order.
struct Harness {
    std::vector<std::string> log;
    bool blockhead_present = true;
    bool in_use = true;
    std::int32_t count_left_value = 0;
    std::vector<std::int32_t> types;
    std::vector<std::int32_t> values;
    std::vector<bool> controlled;
    int paid_calls = 0;
    std::int32_t paid_units = -1;
    int watch_resets = 0;
    int restore_calls = 0;
    int in_use_written = -1;
    int update_written = -1;
    std::int32_t count_left_written = -1;

    AbortImmediateHooks hooks() {
        AbortImmediateHooks h;
        h.current_blockhead_present = [this] {
            log.push_back("cb");
            return blockhead_present;
        };
        h.is_in_use = [this] {
            log.push_back("inuse?");
            return in_use;
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
        h.count_left = [this] {
            log.push_back("left");
            return count_left_value;
        };
        h.client_controlled = [this](int slot) {
            log.push_back("ctl");
            return controlled[static_cast<std::size_t>(slot)];
        };
        h.watch_reset = [this] {
            log.push_back("watch");
            ++watch_resets;
        };
        h.paid_bookkeeping = [this](int slot, std::int32_t units) {
            log.push_back("paid");
            (void)slot;
            ++paid_calls;
            paid_units = units;
        };
        h.restore_to_inventory = [this](int slot) {
            log.push_back("restore");
            (void)slot;
            ++restore_calls;
        };
        h.craft_aborted = [this] { log.push_back("abort"); };
        h.set_is_in_use = [this](bool v) {
            log.push_back("inuse!");
            in_use_written = v ? 1 : 0;
        };
        h.craft_item_finished = [this] { log.push_back("fin"); };
        h.world_changed = [this] { log.push_back("world"); };
        h.set_update_needs_to_be_sent = [this](bool v) {
            log.push_back("upd");
            update_written = v ? 1 : 0;
        };
        h.set_count_left = [this](std::int32_t v) {
            log.push_back("cleft");
            count_left_written = v;
        };
        return h;
    }
};

// Both head gates: a missing blockhead exits before isInUse is read; a
// false isInUse exits before the record is fetched.
static void test_head_gates() {
    Harness missing;
    missing.blockhead_present = false;
    auto hooks = missing.hooks();
    assert(!workbench_abort_immediately(hooks));
    const std::vector<std::string> expected = {"cb"};
    assert(missing.log == expected);

    Harness idle;
    idle.in_use = false;
    auto hooks2 = idle.hooks();
    assert(!workbench_abort_immediately(hooks2));
    const std::vector<std::string> expected2 = {"cb", "inuse?"};
    assert(idle.log == expected2);

    Harness ok;
    auto hooks3 = ok.hooks();
    assert(workbench_abort_immediately(hooks3));
    assert(ok.in_use_written == 0);
    assert(ok.update_written == 1);
    assert(ok.count_left_written == 0);
}

// The plain arm: one unconditional restore per slot (a nil sub-array is the
// callback's zero-iteration case), the enumerated arm only.
static void test_plain_arm() {
    Harness h;
    h.types = {5, 7};
    h.values = {3, 4};
    h.controlled = {false, false};
    h.count_left_value = 6;
    auto hooks = h.hooks();
    assert(workbench_abort_immediately(hooks));
    assert(h.restore_calls == 2);
    const std::vector<std::string> expected = {
        "cb", "inuse?", "count",
        "type", "restore",  // slot 0: no value/left reads on this path
        "type", "restore",  // slot 1
        "abort", "inuse!", "fin", "world", "upd", "cleft",
    };
    assert(h.log == expected);
}

// The paid arm: the client gate skips; otherwise the watcher reset precedes
// the value/left reads and the strict 50000 cap.
static void test_paid_arm() {
    Harness ctl;
    ctl.types = {kAbortPaidItemType};
    ctl.values = {1};
    ctl.controlled = {true};
    ctl.count_left_value = 10;
    auto hooks = ctl.hooks();
    assert(workbench_abort_immediately(hooks));
    assert(ctl.watch_resets == 0);
    assert(ctl.paid_calls == 0);
    assert(ctl.restore_calls == 0);

    Harness paid;
    paid.types = {kAbortPaidItemType};
    paid.values = {4};
    paid.controlled = {false};
    paid.count_left_value = 10000;
    auto hooks2 = paid.hooks();
    assert(workbench_abort_immediately(hooks2));
    assert(paid.watch_resets == 1);
    assert(paid.paid_calls == 1);
    assert(paid.paid_units == 40000);
    const std::vector<std::string> expected = {
        "cb", "inuse?", "count", "type", "ctl", "watch", "value", "left", "paid",
        "abort", "inuse!", "fin", "world", "upd", "cleft",
    };
    assert(paid.log == expected);
}

// The cap: 50000 passes, 50001 skips the bookkeeping (the watcher reset
// still ran before the compare).
static void test_paid_cap() {
    Harness over;
    over.types = {kAbortPaidItemType};
    over.values = {50001};
    over.controlled = {false};
    over.count_left_value = 1;
    auto hooks = over.hooks();
    assert(workbench_abort_immediately(hooks));
    assert(over.watch_resets == 1);
    assert(over.paid_calls == 0);

    Harness exact;
    exact.types = {kAbortPaidItemType};
    exact.values = {50000};
    exact.controlled = {false};
    exact.count_left_value = 1;
    auto hooks2 = exact.hooks();
    assert(workbench_abort_immediately(hooks2));
    assert(exact.paid_calls == 1);
    assert(exact.paid_units == 50000);
}

// A mixed record: the whole order in one log.
static void test_mixed_record_order() {
    Harness h;
    h.types = {5, kAbortPaidItemType};
    h.values = {1, 2};
    h.controlled = {false, false};
    h.count_left_value = 3;
    auto hooks = h.hooks();
    assert(workbench_abort_immediately(hooks));
    const std::vector<std::string> expected = {
        "cb", "inuse?", "count",
        "type", "restore",                       // slot 0
        "type", "ctl", "watch", "value", "left", "paid", // slot 1
        "abort", "inuse!", "fin", "world", "upd", "cleft",
    };
    assert(h.log == expected);
    assert(h.paid_units == 6);
}

// An empty record: straight to the finalize.
static void test_empty_record() {
    Harness h;
    auto hooks = h.hooks();
    assert(workbench_abort_immediately(hooks));
    const std::vector<std::string> expected = {
        "cb", "inuse?", "count",
        "abort", "inuse!", "fin", "world", "upd", "cleft",
    };
    assert(h.log == expected);
}

} // namespace

int main() {
    test_head_gates();
    test_plain_arm();
    test_paid_arm();
    test_paid_cap();
    test_mixed_record_order();
    test_empty_record();
    std::printf("workbench_abort_immediate: all cases passed\n");
    return 0;
}
