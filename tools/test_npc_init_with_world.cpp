// Contract test for the recovered NPC loader slice
// (reconstruction/recovered/npc_init_with_world.cpp). Runs in CTest so CI
// exercises the contract without needing the original ELF.
//
// The numeric expectations below are the same cases the ARM differential
// (tools/test_npc_initwithworld_arm.py) executes against the original
// instructions; keep the two lists in sync.
#include "npc_init_with_world.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

using blockheads::recovered::NpcInitCall;
using blockheads::recovered::NpcInitInputs;
using blockheads::recovered::NpcInitResult;
using blockheads::recovered::npc_hunger_timer_seed;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

std::uint32_t bits_of(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

// The seed must equal 1.0f + 20.0f * (float(v) / 2^31f) with the same step
// order, so check the reference expression as well as the endpoints.
float reference_seed(std::int32_t v) {
    const float as_float = static_cast<float>(v);
    const float normalised = as_float / 2147483648.0f;
    const float scaled = normalised * 20.0f;
    return scaled + 1.0f;
}

}  // namespace

int main() {
    const std::vector<std::int32_t> values = {
        0, 1, 2, 3, 1024, 1048576, 1 << 23, 123456789, 1073741823,
        (1 << 30), 2147483646, 2147483647, -1, -2147483648};
    for (const auto v : values) {
        const float seed = npc_hunger_timer_seed(v);
        expect(bits_of(seed) == bits_of(reference_seed(v)),
               "seed bits match the decoded step order");
        if (v >= 0) {
            // float32 rounds the largest lrand48 values up to 2147483648.0f, so
            // the top of the range is 21.0f exactly — see the dedicated check.
            expect(seed >= 1.0f && seed <= 21.0f, "seed in [1, 21]");
        }
        expect(std::isfinite(seed), "seed is finite");
    }
    // Endpoint behaviour: v = 0 → exactly 1.0f; v = 2^31-1 → just below 21.
    expect(npc_hunger_timer_seed(0) == 1.0f, "v=0 → 1.0f exactly");
    expect(npc_hunger_timer_seed(2147483647) > 20.99f, "v=max → close to 21");
    // Rounding edge proven by the ARM differential: (float)2147483647 ==
    // 2147483648.0f, so v >= ~2^31-2^7 yields exactly 21.0f.
    expect(bits_of(npc_hunger_timer_seed(2147483647)) == bits_of(21.0f),
           "v=max → exactly 21.0f after float32 rounding");
    expect(bits_of(npc_hunger_timer_seed(2147483646)) == bits_of(21.0f),
           "v=2^31-2 → exactly 21.0f after float32 rounding");
    expect(npc_hunger_timer_seed(1 << 30) < 11.0001f, "v=2^30 → ~11.0f");

    // Nil-super path: only the super call happens, no hook, no seed.
    NpcInitInputs nil_inputs;
    nil_inputs.super_returns_nil = true;
    const NpcInitResult nil_result =
        blockheads::recovered::npc_init_with_world(nil_inputs);
    expect(nil_result.returned_nil, "nil super → loader returns nil");
    expect(!nil_result.timer_written, "nil super → timer not written");
    expect(nil_result.calls.size() == 1 &&
               nil_result.calls[0] == NpcInitCall::SuperInit,
           "nil super → only the super call is recorded");

    // Happy path: super → hook → lrand48 → timer write, in that order.
    NpcInitInputs inputs;
    inputs.lrand48_value = 123456789;
    const NpcInitResult result =
        blockheads::recovered::npc_init_with_world(inputs);
    expect(!result.returned_nil, "happy path returns self");
    expect(result.timer_written, "happy path writes the timer");
    expect(result.calls.size() == 3, "happy path makes three calls");
    expect(result.calls[0] == NpcInitCall::SuperInit, "call 0 is super");
    expect(result.calls[1] == NpcInitCall::LoadValuesFromSaveDict,
           "call 1 is loadValuesFromSaveDict:");
    expect(result.calls[2] == NpcInitCall::Lrand48, "call 2 is lrand48");
    expect(bits_of(result.random_harm_from_hunger_timer) ==
               bits_of(npc_hunger_timer_seed(123456789)),
           "timer equals the seed");

    if (failures == 0) {
        std::printf("recovered_npc_init_with_world: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
