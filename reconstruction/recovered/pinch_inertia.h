#pragma once
namespace blockheads::recovered {
struct PinchInertiaState {
    bool pinchZooming;
    bool hasPinchVelocity;
    float pinchVelocity;
    float lastPinchFactor;
    float pinchStartScale;
    double pinchScale;
};
struct PinchInertiaResult {
    PinchInertiaState state;
    bool notifyScaleChanged;
};
// Finite-input local slice, not a full gesture/lifecycle implementation.
PinchInertiaResult stepPinchInertia(PinchInertiaState state, bool translatingToGoal,
                                   bool takingPhoto, float dt);
}
