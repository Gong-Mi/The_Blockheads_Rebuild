// Contract tests for the recovered NPC feed response ([NPC feedByBlockhead:],
// E117).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_npc_feed_response.cpp
//       reconstruction/recovered/npc_feed_response.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "npc_feed_response.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using blockheads::recovered::FeedHooks;
using blockheads::recovered::kFeedFillValue;
using blockheads::recovered::kFeedFullnessGain;
using blockheads::recovered::kFeedFullnessMax;
using blockheads::recovered::npc_feed_response;

namespace {

// The full hook set with a call log, so the tests can pin the stage order.
struct Harness {
    std::vector<std::string> log;
    bool can_feed_value = true;
    float fullness_value = 0.0f;
    float fullness_written = -1.0f;
    std::uint16_t hunger_value = 0;
    std::uint16_t food_value = 0;
    std::uint16_t hunger_written = 0;
    bool hunger_written_flag = false;
    bool state_flag = false;
    bool blockhead_payload_called = false;
    bool aux_flag_set = false;
    float fill_slot_value = 0.0f;
    float fill_slot_written = -1.0f;
    int32_t tame_count_value = 0;
    int32_t tame_count_written = 0;
    int32_t requirement_value = 0;
    bool predicate_value = false;
    int32_t max_count_value = 0;
    bool tamed_set = false;
    bool tail_called = false;

    FeedHooks hooks() {
        FeedHooks h;
        h.can_feed = [this] {
            log.push_back("can");
            return can_feed_value;
        };
        h.fullness = [this] {
            log.push_back("ful?");
            return fullness_value;
        };
        h.set_fullness = [this](float v) {
            log.push_back("ful!");
            fullness_written = v;
        };
        h.hunger = [this] {
            log.push_back("hun?");
            return hunger_value;
        };
        h.set_hunger = [this](std::uint16_t v) {
            log.push_back("hun!");
            hunger_written = v;
            hunger_written_flag = true;
        };
        h.food_points = [this] {
            log.push_back("food");
            return food_value;
        };
        h.state_flag_present = [this] {
            log.push_back("flag");
            return state_flag;
        };
        h.blockhead_payload = [this] { log.push_back("bhead"); blockhead_payload_called = true; };
        h.set_aux_flag = [this] { log.push_back("aux"); aux_flag_set = true; };
        h.fill_slot = [this] {
            log.push_back("fill?");
            return fill_slot_value;
        };
        h.set_fill_slot = [this](float v) {
            log.push_back("fill!");
            fill_slot_written = v;
        };
        h.succeeded_tail = [this] { log.push_back("tail"); tail_called = true; };
        h.tame_count_requirement = [this] {
            log.push_back("req");
            return requirement_value;
        };
        h.read_tame_count = [this] {
            log.push_back("cnt?");
            return tame_count_value;
        };
        h.write_tame_count = [this](std::int32_t v) {
            log.push_back("cnt!");
            tame_count_written = v;
        };
        h.count_predicate = [this] {
            log.push_back("pred");
            return predicate_value;
        };
        h.max_count_over_blockheads = [this] {
            log.push_back("max");
            return max_count_value;
        };
        h.set_tamed = [this] { log.push_back("tamed"); tamed_set = true; };
        return h;
    }
};

// The gate: false stores 0 and returns before any other stage.
static void test_gate() {
    Harness h;
    h.can_feed_value = false;
    h.fullness_value = 100.0f;
    auto hooks = h.hooks();
    assert(!npc_feed_response(hooks));
    const std::vector<std::string> expected = {"can"};
    assert(h.log == expected);
    assert(h.fullness_written == -1.0f);
}

// The fullness law: += 2700.0 in f64, clamped above 8100.0 (strictly).
static void test_fullness() {
    Harness h;
    h.fullness_value = 5400.0f; // 5400 + 2700 = 8100 exactly: not clamped
    auto hooks = h.hooks();
    assert(npc_feed_response(hooks));
    assert(h.fullness_written == static_cast<float>(kFeedFullnessMax));

    Harness over;
    over.fullness_value = 6150.0f; // 8850 > 8100: clamped
    auto hooks2 = over.hooks();
    assert(npc_feed_response(hooks2));
    assert(over.fullness_written == static_cast<float>(kFeedFullnessMax));

    Harness fresh;
    fresh.fullness_value = 0.0f; // 0 + 2700
    auto hooks3 = fresh.hooks();
    assert(npc_feed_response(hooks3));
    assert(fresh.fullness_written == static_cast<float>(kFeedFullnessGain));

    Harness full;
    full.fullness_value = 8100.0f; // 10800 > 8100: clamped
    auto hooks4 = full.hooks();
    assert(npc_feed_response(hooks4));
    assert(full.fullness_written == static_cast<float>(kFeedFullnessMax));
}

// The hunger law: field -= min(field, food/2) with the idiv truncation,
// skipped entirely at zero.
static void test_hunger() {
    // (a) food 101 halves to 50; 1000 - 50.
    Harness a;
    a.hunger_value = 1000;
    a.food_value = 101;
    auto hooks = a.hooks();
    assert(npc_feed_response(hooks));
    assert(a.hunger_written == 950);

    // (b) min picks the field: 30 - min(30, 50) = 0.
    Harness b;
    b.hunger_value = 30;
    b.food_value = 100;
    auto hooks2 = b.hooks();
    assert(npc_feed_response(hooks2));
    assert(b.hunger_written == 0);

    // (c) food 1 halves to 0: subtract nothing (still written back).
    Harness c;
    c.hunger_value = 5;
    c.food_value = 1;
    auto hooks3 = c.hooks();
    assert(npc_feed_response(hooks3));
    assert(c.hunger_written_flag && c.hunger_written == 5);

    // (d) field 0: the food call never happens (cmp; ble).
    Harness d;
    d.hunger_value = 0;
    d.food_value = 999;
    auto hooks4 = d.hooks();
    assert(npc_feed_response(hooks4));
    assert(!d.hunger_written_flag);
    bool food_seen = false;
    for (const auto& entry : d.log) {
        if (entry == "food") {
            food_seen = true;
        }
    }
    assert(!food_seen);
}

// The state-byte path: non-zero takes the blockhead payload and returns
// without the fill slot or the count stage.
static void test_state_flag_path() {
    Harness h;
    h.state_flag = true;
    h.hunger_value = 100;
    h.food_value = 10;
    auto hooks = h.hooks();
    assert(npc_feed_response(hooks));
    assert(h.blockhead_payload_called);
    assert(h.fill_slot_written == -1.0f);
    assert(!h.tail_called);
    bool count_seen = false;
    for (const auto& entry : h.log) {
        if (entry == "cnt?" || entry == "tail") {
            count_seen = true;
        }
    }
    assert(!count_seen);
}

// The fill slot replay: old > 0 goes straight to the tail; the slot is
// still rewritten to 675.0 first (order: aux, fill read, fill write, tail).
static void test_fill_slot_replay() {
    Harness h;
    h.fill_slot_value = 100.0f;
    h.tame_count_value = 99;
    h.requirement_value = 0;
    auto hooks = h.hooks();
    assert(npc_feed_response(hooks));
    assert(h.fill_slot_written == kFeedFillValue);
    assert(h.tail_called);
    assert(!h.tamed_set);
    bool count_seen = false;
    for (const auto& entry : h.log) {
        if (entry == "cnt?") {
            count_seen = true;
        }
    }
    assert(!count_seen);
    // Order pin: aux before the fill read; fill write before the tail.
    const std::vector<std::string> expected_tail = {"aux", "fill?", "fill!", "tail"};
    assert(h.log.size() >= 4);
    assert(std::vector<std::string>(h.log.end() - 4, h.log.end()) == expected_tail);
}

// The count stage matrix: read + 1, the requirement gate (predicate not
// consulted below it), the predicate gate (max not consulted when set),
// and the strict count > max tame trigger.
static void test_count_stage() {
    // (a) count 7 + 1 < requirement 9: tail only; no predicate, no max.
    Harness below;
    below.tame_count_value = 7;
    below.requirement_value = 9;
    below.predicate_value = true; // would exit anyway - must not be called
    auto hooks = below.hooks();
    assert(npc_feed_response(hooks));
    assert(below.tame_count_written == 8);
    assert(below.tail_called);
    assert(!below.tamed_set);
    bool pred_or_max = false;
    for (const auto& entry : below.log) {
        if (entry == "pred" || entry == "max") {
            pred_or_max = true;
        }
    }
    assert(!pred_or_max);

    // (b) count 8 >= requirement 8, predicate set: tail only, no max.
    Harness pred;
    pred.tame_count_value = 7;
    pred.requirement_value = 8;
    pred.predicate_value = true;
    auto hooks2 = pred.hooks();
    assert(npc_feed_response(hooks2));
    assert(pred.tail_called);
    assert(!pred.tamed_set);
    bool max_seen = false;
    for (const auto& entry : pred.log) {
        if (entry == "max") {
            max_seen = true;
        }
    }
    assert(!max_seen);

    // (c) count 8 > max 7: the tame set block runs, then the tail.
    Harness tame;
    tame.tame_count_value = 7;
    tame.requirement_value = 8;
    tame.predicate_value = false;
    tame.max_count_value = 7;
    auto hooks3 = tame.hooks();
    assert(npc_feed_response(hooks3));
    assert(tame.tamed_set);
    assert(tame.tail_called);
    const std::vector<std::string> expected_tame = {"tamed", "tail"};
    assert(std::vector<std::string>(tame.log.end() - 2, tame.log.end()) == expected_tame);

    // (d) count 8 == max 8: ble skips the set block; the tail still runs.
    Harness notame;
    notame.tame_count_value = 7;
    notame.requirement_value = 8;
    notame.predicate_value = false;
    notame.max_count_value = 8;
    auto hooks4 = notame.hooks();
    assert(npc_feed_response(hooks4));
    assert(!notame.tamed_set);
    assert(notame.tail_called);
}

// The stage order across the whole flow.
static void test_stage_order() {
    Harness h;
    h.fullness_value = 100.0f;
    h.hunger_value = 500;
    h.food_value = 40;
    h.tame_count_value = 3;
    h.requirement_value = 4;
    h.predicate_value = false;
    h.max_count_value = 3;
    auto hooks = h.hooks();
    assert(npc_feed_response(hooks));
    const std::vector<std::string> expected = {
        "can", "ful?", "ful!", "hun?", "food", "hun!", "flag", "aux",
        "fill?", "fill!", "cnt?", "cnt!", "req", "pred", "max", "tamed", "tail",
    };
    assert(h.log == expected);
}

} // namespace

int main() {
    test_gate();
    test_fullness();
    test_hunger();
    test_state_flag_path();
    test_fill_slot_replay();
    test_count_stage();
    test_stage_order();
    std::printf("npc_feed_response: all cases passed\n");
    return 0;
}
