// Optional ARM differential bridge: exposes the recovered forwarder contract to
// tools/test_forwarder_arm.py, which executes the five original 74-word
// forwarder bodies under Unicorn and compares the call-order trace.
#include "object_forwarder_init.h"

#include <cstdint>

using blockheads::recovered::ForwarderInputs;
using blockheads::recovered::ForwarderResult;

extern "C" {

// Trace bits: bit0 super call, bit1 post-init hook, bit31 returned-nil.
std::uint32_t recovered_forwarder_trace(std::int32_t super_returns_nil) {
    ForwarderInputs inputs;
    inputs.super_returns_nil = super_returns_nil != 0;
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
