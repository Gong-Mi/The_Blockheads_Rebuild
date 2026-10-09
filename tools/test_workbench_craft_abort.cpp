// Contract tests for the recovered workbench craft abort (-[abortCraft],
// E78).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_workbench_craft_abort.cpp
//       reconstruction/recovered/workbench_craft_abort.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "workbench_craft_abort.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using blockheads::recovered::AbortCraftHooks;
using blockheads::recovered::kAbortPaidItemType;
using blockheads::recovered::kAbortPaidUnitCap;
using blockheads::recovered::workbench_abort_craft;

namespace {

// A record-driven harness with a call log, so the tests pin the stage order.
struct Harness {
    std::vector<std::string> log;
    bool needs_removed_value = false;
    float fraction_written = -1.0f;
    std::int32_t count_left_value = 0;
    // Per-slot tables: type (f2), value (f3), sub-items presence.
    std::vector<std::int32_t> types;
    std::vector<std::int32_t> values;
    std::vector<bool> subs;
    std::vector<bool> controlled;
    // Captured outputs.
    int paid_calls = 0;
    std::int32_t paid_units = -1;
    int watch_resets = 0;
    int in_use_written = -1;
    int update_written = -1;
    std::int32_t count_left_written = -1;
    std::vector<std::pair<int, std::int32_t>> unit_calls;

    AbortCraftHooks hooks() {
        AbortCraftHooks h;
        h.needs_removed = [this] {
            log.push_back("gate");
            return needs_removed_value;
        };
        h.release_crafting_item = [this] { log.push_back("release"); };
        h.set_fraction_complete = [this](float v) {
            log.push_back("frac");
            fraction_written = v;
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
        h.sub_items_present = [this](int slot) {
            log.push_back("subs");
            return subs[static_cast<std::size_t>(slot)];
        };
        h.restore_via_sub_items = [this](int slot) {
            log.push_back("sub");
            (void)slot;
        };
        h.restore_unit = [this](int slot, std::int32_t index) {
            log.push_back("unit");
            unit_calls.emplace_back(slot, index);
        };
        h.craft_aborted = [this] { log.push_back("abort"); };
        h.set_is_in_use = [this](bool v) {
            log.push_back("inuse");
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

// The head gate: needsRemoved releases the crafting item; a false gate skips
// the release but the reset still runs.
static void test_head_gate() {
    Harness h;
    h.needs_removed_value = true;
    auto hooks = h.hooks();
    workbench_abort_craft(hooks);
    assert(h.log.size() >= 3);
    assert(h.log[0] == "gate");
    assert(h.log[1] == "release");
    assert(h.log[2] == "frac");
    assert(h.fraction_written == 0.0f);

    Harness plain;
    auto hooks2 = plain.hooks();
    workbench_abort_craft(hooks2);
    assert(plain.log[0] == "gate");
    assert(plain.log[1] == "frac"); // no release
    assert(plain.in_use_written == 0);
    assert(plain.update_written == 1);
    assert(plain.count_left_written == 0);
}

// The plain arm with sub-items: the enumerated drop runs once, the unit
// loop never does.
static void test_plain_arm_sub_items() {
    Harness h;
    h.types = {5};
    h.values = {3};
    h.subs = {true};
    h.controlled = {false};
    h.count_left_value = 4;
    auto hooks = h.hooks();
    workbench_abort_craft(hooks);
    assert(h.unit_calls.empty());
    const std::vector<std::string> expected = {
        "gate", "frac", "count", "type", "subs", "sub",
        "abort", "inuse", "fin", "world", "upd", "cleft",
    };
    assert(h.log == expected);
}

// The plain unit loop: exactly f3[i] * countLeft drops with the 0-based
// indices in order; zero and negative products drop nothing.
static void test_plain_arm_unit_loop() {
    Harness h;
    h.types = {7};
    h.values = {3};
    h.subs = {false};
    h.controlled = {false};
    h.count_left_value = 4;
    auto hooks = h.hooks();
    workbench_abort_craft(hooks);
    assert(h.unit_calls.size() == 12);
    for (std::int32_t j = 0; j < 12; ++j) {
        assert(h.unit_calls[static_cast<std::size_t>(j)].first == 0);
        assert(h.unit_calls[static_cast<std::size_t>(j)].second == j);
    }

    Harness zero;
    zero.types = {7};
    zero.values = {0};
    zero.subs = {false};
    zero.controlled = {false};
    zero.count_left_value = 9;
    auto hooks2 = zero.hooks();
    workbench_abort_craft(hooks2);
    assert(zero.unit_calls.empty());

    Harness negative;
    negative.types = {7};
    negative.values = {-3};
    negative.subs = {false};
    negative.controlled = {false};
    negative.count_left_value = 2;
    auto hooks3 = negative.hooks();
    workbench_abort_craft(hooks3);
    assert(negative.unit_calls.empty()); // cmp; bge skips at j=0 >= -6
}

// The paid arm: the client gate skips everything; otherwise the watcher
// reset precedes the units and the cap.
static void test_paid_arm() {
    Harness ctl;
    ctl.types = {kAbortPaidItemType};
    ctl.values = {1};
    ctl.subs = {false};
    ctl.controlled = {true};
    ctl.count_left_value = 10;
    auto hooks = ctl.hooks();
    workbench_abort_craft(hooks);
    assert(ctl.watch_resets == 0);
    assert(ctl.paid_calls == 0);

    Harness paid;
    paid.types = {kAbortPaidItemType};
    paid.values = {4};
    paid.subs = {false};
    paid.controlled = {false};
    paid.count_left_value = 10000;
    auto hooks2 = paid.hooks();
    workbench_abort_craft(hooks2);
    assert(paid.watch_resets == 1);
    assert(paid.paid_calls == 1);
    assert(paid.paid_units == 40000);
    // The watch reset precedes the value/left reads (asm order).
    const std::vector<std::string> expected = {
        "gate", "frac", "count", "type", "ctl", "watch", "value", "left", "paid",
        "abort", "inuse", "fin", "world", "upd", "cleft",
    };
    assert(paid.log == expected);
}

// The cap: units above 50000 skip the bookkeeping (watch reset still ran);
// 50000 itself passes (bgt is strict).
static void test_paid_cap() {
    Harness over;
    over.types = {kAbortPaidItemType};
    over.values = {50001};
    over.subs = {false};
    over.controlled = {false};
    over.count_left_value = 1;
    auto hooks = over.hooks();
    workbench_abort_craft(hooks);
    assert(over.watch_resets == 1);
    assert(over.paid_calls == 0);

    Harness exact;
    exact.types = {kAbortPaidItemType};
    exact.values = {50000};
    exact.subs = {false};
    exact.controlled = {false};
    exact.count_left_value = 1;
    auto hooks2 = exact.hooks();
    workbench_abort_craft(hooks2);
    assert(exact.paid_calls == 1);
    assert(exact.paid_units == 50000);

    Harness product;
    product.types = {kAbortPaidItemType};
    product.values = {6};
    product.subs = {false};
    product.controlled = {false};
    product.count_left_value = 8334; // 50004 > 50000: skipped
    auto hooks3 = product.hooks();
    workbench_abort_craft(hooks3);
    assert(product.paid_calls == 0);
}

// A mixed record: the whole order in one log, including the two-arm
// dispatch per slot.
static void test_mixed_record_order() {
    Harness h;
    h.types = {5, 7, kAbortPaidItemType};
    h.values = {1, 2, 1};
    h.subs = {true, false, false};
    h.controlled = {false, false, false};
    h.count_left_value = 3;
    auto hooks = h.hooks();
    workbench_abort_craft(hooks);
    const std::vector<std::string> expected = {
        "gate", "frac", "count",
        "type", "subs", "sub",            // slot 0: the enumerated arm
        "type", "subs", "value", "left", "unit", "unit", "unit",
        "unit", "unit", "unit",           // slot 1: 2 x 3 drops
        "type", "ctl", "watch", "value", "left", "paid", // slot 2
        "abort", "inuse", "fin", "world", "upd", "cleft",
    };
    assert(h.log == expected);
    assert(h.unit_calls.size() == 6);
    assert(h.unit_calls.front().first == 1);
    assert(h.unit_calls.front().second == 0);
    assert(h.unit_calls.back().second == 5);
    assert(h.paid_units == 3);
}

// An empty record: no slots, straight to the finalize.
static void test_empty_record() {
    Harness h;
    auto hooks = h.hooks();
    workbench_abort_craft(hooks);
    const std::vector<std::string> expected = {
        "gate", "frac", "count",
        "abort", "inuse", "fin", "world", "upd", "cleft",
    };
    assert(h.log == expected);
}

} // namespace

int main() {
    test_head_gate();
    test_plain_arm_sub_items();
    test_plain_arm_unit_loop();
    test_paid_arm();
    test_paid_cap();
    test_mixed_record_order();
    test_empty_record();
    std::printf("workbench_craft_abort: all cases passed\n");
    return 0;
}
