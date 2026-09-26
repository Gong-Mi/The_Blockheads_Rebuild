// ARM differential bridge: exposes the recovered tree-family LONG loader
// contract to tools/test_treefamily9_long_init_arm.py, which executes the nine
// original 62-word bodies under Unicorn and compares (a) the forwarded
// argument tuple, (b) the call-order trace bits and (c) the nil-guard return.
//
// Built at -O0 and -O2 by the harness so the comparison never relies on the
// float/register return ABI differing between builds.
#include "treefamily9_long_init.h"

#include <cstdint>

using blockheads::recovered::TreeForward9Inputs;
using blockheads::recovered::TreeForward9Result;

extern "C" {

// in_args        — the six argument tokens in declared order.
// out_trace      — the call-order bitset (bit k set for call code k).
// out_forwarded  — the six forwarded tokens in forward order.
// returns        — 1 when the body returned nil, else 0.
void recovered_treefamily9_long_init_trace(const std::uint32_t* in_args,
                                          std::uint32_t class_ref,
                                          std::uint32_t selector_ref,
                                          std::uint32_t super_returns_nil,
                                          std::uint32_t* out_trace,
                                          std::uint32_t* out_forwarded,
                                          std::uint32_t* returned_nil) {
    TreeForward9Inputs inputs;
    for (int i = 0; i < 6; ++i) {
        inputs.args[i] = in_args[i];
    }
    inputs.class_ref = class_ref;
    inputs.selector_ref = selector_ref;
    inputs.super_returns_nil = super_returns_nil != 0;
    const TreeForward9Result result =
        blockheads::recovered::treefamily9_long_init_forward(inputs);
    std::uint32_t trace = 0;
    for (const int call : result.calls) {
        trace |= 1u << call;
    }
    *out_trace = trace;
    for (int i = 0; i < 6; ++i) {
        out_forwarded[i] = static_cast<std::uint32_t>(result.forwarded[i]);
    }
    *returned_nil = result.returned_nil ? 1u : 0u;
}

}  // extern "C"
