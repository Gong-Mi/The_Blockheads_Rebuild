#include "treefamily9_long_init.h"

#include "generated/trace_codes.h"

namespace blockheads::recovered {

TreeForward9Result treefamily9_long_init_forward(
    const TreeForward9Inputs& inputs) {
    TreeForward9Result result;
    // All six arguments spill straight through into the super call frame, so
    // the forwarded tuple is the incoming tuple in the same order.
    result.forwarded = inputs.args;
    result.super_class_ref = inputs.class_ref;
    result.super_selector_ref = inputs.selector_ref;
    result.calls.push_back(
        static_cast<int>(TreeFamily9LongInitCall::MsgSendSuper));
    if (inputs.super_returns_nil) {
        result.returned_nil = true;
    }
    return result;
}

}  // namespace blockheads::recovered
