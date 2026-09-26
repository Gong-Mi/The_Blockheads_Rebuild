// Contract test for the recovered forwarder convention
// (reconstruction/recovered/object_forwarder_init.cpp). Runs in CTest so CI
// exercises it without the original ELF; tools/test_forwarder_arm.py executes
// the five original ARM bodies and must produce the same traces.
#include "object_forwarder_init.h"

#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

using blockheads::recovered::ForwarderCall;
using blockheads::recovered::ForwarderInputs;
using blockheads::recovered::ForwarderResult;
using blockheads::recovered::forwarder_init_with_world;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

}  // namespace

int main() {
    // Happy path: super, then the post-init hook, then return self.
    const ForwarderResult ok = forwarder_init_with_world(ForwarderInputs{});
    expect(!ok.returned_nil, "happy path returns self");
    expect(ok.calls.size() == 2, "happy path makes two calls");
    expect(ok.calls[0] == ForwarderCall::SuperInit, "call 0 is super");
    expect(ok.calls[1] == ForwarderCall::PostInitHook, "call 1 is the hook");

    // Nil super: only the super call, and the forwarder returns nil.
    ForwarderInputs nil_inputs;
    nil_inputs.super_returns_nil = true;
    const ForwarderResult nil = forwarder_init_with_world(nil_inputs);
    expect(nil.returned_nil, "nil super → returns nil");
    expect(nil.calls.size() == 1, "nil super → one call only");
    expect(nil.calls[0] == ForwarderCall::SuperInit, "that call is super");

    // The trace encoding used by the ARM differential: 0b11 happy, 0b1|nil-bit.
    const std::uint32_t happy_trace = (1u << 0) | (1u << 1);
    const std::uint32_t nil_trace = (1u << 0) | 0x80000000u;
    expect(happy_trace == 0x3u, "trace literal sanity");
    expect(nil_trace == 0x80000001u, "nil trace literal sanity");

    if (failures == 0) {
        std::printf("recovered_object_forwarder_init: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
