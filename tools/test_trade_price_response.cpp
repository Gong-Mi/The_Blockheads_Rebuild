// Contract tests for the recovered trade price response (E108).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_trade_price_response.cpp
//       reconstruction/recovered/trade_price_response.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "trade_price_response.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

using blockheads::recovered::kPriceDecayBase;
using blockheads::recovered::kPriceEpsilon;
using blockheads::recovered::PriceResponseHooks;
using blockheads::recovered::trade_price_response;

namespace {

// The full hook set with a call log, so the tests can pin the call order.
struct Harness {
    std::vector<int> log;  // 0 client, 1 readM, 2 writeM, 3 readA, 4 writeA
    bool client_present = false;
    bool multiplier_found = false;
    double multiplier_value = 0.0;
    double written_multiplier = 0.0;
    int write_multiplier_calls = 0;
    bool acc_found[2] = {false, false};
    float acc_value[2] = {0.0f, 0.0f};
    bool acc_written[2] = {false, false};
    float acc_written_value[2] = {0.0f, 0.0f};

    PriceResponseHooks hooks() {
        PriceResponseHooks h;
        h.client_state_present = [this] {
            log.push_back(0);
            return client_present;
        };
        h.read_multiplier = [this](double& out) {
            log.push_back(1);
            if (multiplier_found) {
                out = multiplier_value;
            }
            return multiplier_found;
        };
        h.write_multiplier = [this](double value) {
            log.push_back(2);
            ++write_multiplier_calls;
            written_multiplier = value;
        };
        h.read_accumulator = [this](int slot, float& out) {
            log.push_back(3);
            if (acc_found[slot]) {
                out = acc_value[slot];
            }
            return acc_found[slot];
        };
        h.write_accumulator = [this](int slot, float value) {
            log.push_back(4);
            acc_written[slot] = true;
            acc_written_value[slot] = value;
        };
        return h;
    }
};

// The epsilon gate: |delta| < 0.01 returns without any hook call; the
// boundaries +-0.01 enter the main path (bpl / ble are inclusive).
static void test_epsilon_gate() {
    Harness harness;
    auto hooks = harness.hooks();
    assert(!trade_price_response(hooks, 0.009f));
    assert(!trade_price_response(hooks, -0.009f));
    assert(!trade_price_response(hooks, 0.0f));
    assert(!trade_price_response(hooks, std::numeric_limits<float>::quiet_NaN()));
    assert(harness.log.empty());
    assert(harness.write_multiplier_calls == 0);

    assert(trade_price_response(hooks, 0.01f));  // >= 0.01 admits
    assert(trade_price_response(hooks, -0.01f)); // <= -0.01 admits
    assert(harness.write_multiplier_calls == 2);
}

// The multiplier law: m' = m * pow(0.999, delta), m defaulting to 1.0.
static void test_multiplier_law() {
    Harness harness;
    harness.multiplier_found = true;
    harness.multiplier_value = 2.0;
    auto hooks = harness.hooks();
    assert(trade_price_response(hooks, 1.0f));
    const double expected = 2.0 * std::pow(kPriceDecayBase, 1.0);
    assert(harness.written_multiplier == expected);

    // The miss path: the 1.0 default is multiplied (vmov.f64 d0, 1).
    harness.multiplier_found = false;
    assert(trade_price_response(hooks, -2.0f));
    assert(harness.written_multiplier == std::pow(kPriceDecayBase, -2.0));
}

// The client-state gate: non-nil skips the multiplier block entirely
// (bne 0x5cd9a0); the accumulators still run.
static void test_client_state_skips_multiplier() {
    Harness harness;
    harness.client_present = true;
    auto hooks = harness.hooks();
    assert(trade_price_response(hooks, 3.0f));
    assert(harness.write_multiplier_calls == 0);
    assert(harness.acc_written[0] && harness.acc_written[1]);
    assert(harness.acc_written_value[0] == 3.0f); // delta + missing 0
    assert(harness.acc_written_value[1] == 3.0f);
}

// The accumulators: acc = delta + stored (vadd.f32), per slot, in the
// f32 domain; a miss leaves acc = delta.
static void test_accumulators() {
    Harness harness;
    harness.acc_found[0] = true;
    harness.acc_value[0] = 5.0f;
    // slot 1 stays missing.
    auto hooks = harness.hooks();
    assert(trade_price_response(hooks, 2.0f));
    assert(harness.acc_written_value[0] == 2.0f + 5.0f);
    assert(harness.acc_written_value[1] == 2.0f);

    // f32 precision: no double promotion in the add.
    Harness precise;
    precise.acc_found[0] = true;
    precise.acc_value[0] = 0.456f;
    auto hooks2 = precise.hooks();
    assert(trade_price_response(hooks2, 0.123f));
    const float expected = 0.123f + 0.456f; // computed in float
    assert(precise.acc_written_value[0] == expected);
}

// The call order: client probe, multiplier read/write, then slot 0 and
// slot 1 read/write pairs.
static void test_call_order() {
    Harness harness;
    harness.multiplier_found = true;
    harness.multiplier_value = 1.5;
    harness.acc_found[0] = true;
    harness.acc_value[0] = 1.0f;
    harness.acc_found[1] = true;
    harness.acc_value[1] = 2.0f;
    auto hooks = harness.hooks();
    assert(trade_price_response(hooks, 0.5f));
    const std::vector<int> expected = {0, 1, 2, 3, 4, 3, 4};
    assert(harness.log == expected);

    // Non-nil client state: the multiplier calls vanish from the order.
    Harness skipped;
    skipped.client_present = true;
    auto hooks2 = skipped.hooks();
    assert(trade_price_response(hooks2, 0.5f));
    const std::vector<int> expected2 = {0, 3, 4, 3, 4};
    assert(skipped.log == expected2);
}

// The infinite deltas of the f64 pow: base < 1 sends +inf to 0 and -inf to
// +inf; the accumulator f32 add keeps its IEEE result.
static void test_infinite_delta() {
    Harness harness;
    auto hooks = harness.hooks();
    assert(trade_price_response(hooks, std::numeric_limits<float>::infinity()));
    assert(harness.written_multiplier == 0.0);
    assert(trade_price_response(hooks, -std::numeric_limits<float>::infinity()));
    assert(std::isinf(harness.written_multiplier));
    assert(harness.acc_written_value[0] == -std::numeric_limits<float>::infinity());
}

} // namespace

int main() {
    test_epsilon_gate();
    test_multiplier_law();
    test_client_state_skips_multiplier();
    test_accumulators();
    test_call_order();
    test_infinite_delta();
    std::printf("trade_price_response: all cases passed\n");
    return 0;
}
