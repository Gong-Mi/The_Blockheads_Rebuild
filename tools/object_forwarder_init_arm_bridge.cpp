// Optional ARM differential bridge: exposes the recovered forwarder contract to
// tools/test_forwarder_arm.py, which executes the five original 74-word
// forwarder bodies under Unicorn and compares the call-order trace.
#include "object_forwarder_init.h"

#include <cstdint>

using blockheads::recovered::ForwarderInputs;
using blockheads::recovered::ForwarderResult;

extern "C" {

// Trace bits: bit0 super call, bit1 post-init hook, bit31 returned-nil.
// Variant that also controls the post-init hook (forwarder5b's super-only
// bodies pass hook_present=0).
std::uint32_t recovered_forwarder_trace_ex(std::int32_t super_returns_nil,
                                           std::int32_t hook_present);

std::uint32_t recovered_forwarder_trace(std::int32_t super_returns_nil) {
    return recovered_forwarder_trace_ex(super_returns_nil, 1);
}

std::uint32_t recovered_forwarder_trace_ex(std::int32_t super_returns_nil,
                                           std::int32_t hook_present) {
    ForwarderInputs inputs;
    inputs.super_returns_nil = super_returns_nil != 0;
    inputs.hook_present = hook_present != 0;
    const ForwarderResult result =
        blockheads::recovered::forwarder_init_with_world(inputs);
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
