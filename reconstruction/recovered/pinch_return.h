#pragma once
namespace blockheads::recovered {
// Entry flags/state from the pinchZooming branch, ordinary finite IEEE inputs.
struct PinchReturnState { bool pinchZooming; double pinchScale; };
struct PinchReturnResult {
    PinchReturnState state;
    bool handledBranch; // true even when this step clears pinchZooming
    bool persistScale;
    float persistedValue;
};
PinchReturnResult stepPinchReturn(PinchReturnState state, float dt);
}
