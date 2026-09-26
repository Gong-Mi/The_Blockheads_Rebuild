// Optional ARM differential bridge: exposes the recovered NPC loader contract
// to tools/test_npc_initwithworld_arm.py, which executes the ORIGINAL ARM
// method under Unicorn with synthetic ObjC messages and compares the seeded
// timer float and the call order against this module (built at -O0 and -O2).
#include "npc_init_with_world.h"

#include <cstdint>

using blockheads::recovered::NpcInitInputs;
using blockheads::recovered::NpcInitResult;

extern "C" {

// Returns the seeded timer as raw IEEE-754 bits so the harness can compare
// bit-exactly instead of relying on float return ABI equality.
std::uint32_t recovered_npc_hunger_timer_bits(std::int32_t lrand48_value) {
    const float value = blockheads::recovered::npc_hunger_timer_seed(lrand48_value);
    std::uint32_t bits = 0;
    __builtin_memcpy(&bits, &value, sizeof(bits));
    return bits;
}

// Call-order trace as bit flags: bit0 super, bit1 loadValuesFromSaveDict,
// bit2 lrand48. Zero means the loader returned nil without any further call.
std::uint32_t recovered_npc_init_trace(std::int32_t lrand48_value,
                                       std::int32_t super_returns_nil) {
    NpcInitInputs inputs;
    inputs.lrand48_value = lrand48_value;
    inputs.super_returns_nil = super_returns_nil != 0;
    const NpcInitResult result = blockheads::recovered::npc_init_with_world(inputs);
    std::uint32_t trace = 0;
    for (const auto call : result.calls) {
        trace |= 1u << static_cast<int>(call);
    }
    if (result.returned_nil) {
        trace |= 0x80000000u;
    }
    return trace;
}

}  // extern "C"
