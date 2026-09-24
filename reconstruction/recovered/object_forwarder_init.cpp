#include "object_forwarder_init.h"

namespace blockheads::recovered {

ForwarderResult forwarder_init_with_world(const ForwarderInputs& inputs) {
    ForwarderResult result;
    result.calls.push_back(ForwarderCall::SuperInit);
    if (inputs.super_returns_nil) {
        result.returned_nil = true;
        return result;
    }
    result.calls.push_back(ForwarderCall::PostInitHook);
    return result;
}

}  // namespace blockheads::recovered
