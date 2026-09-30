#include "pinch_inertia.h"
#include <cmath>
namespace blockheads::recovered {
PinchInertiaResult stepPinchInertia(PinchInertiaState state, bool translatingToGoal,
                                   bool takingPhoto, float dt) {
    PinchInertiaResult out{state, false};
    if (state.pinchZooming || !state.hasPinchVelocity) return out;
    if (translatingToGoal) {
        out.state.hasPinchVelocity = false;
        return out;
    }
    // 0x926490..0x9264cc: float dt*16, double subtraction/multiply, float store.
    const float scaledDt = dt * 16.0f;
    const double factor = 1.0 - static_cast<double>(scaledDt);
    out.state.pinchVelocity = static_cast<float>(static_cast<double>(state.pinchVelocity) * factor);
    if (std::fabs(out.state.pinchVelocity) < 0.01f) {
        out.state.hasPinchVelocity = false;
        return out;
    }
    const float movement = out.state.pinchVelocity * dt;
    out.state.lastPinchFactor = state.lastPinchFactor + movement;
    if (out.state.lastPinchFactor < 0.01f) {
        out.state.hasPinchVelocity = false;
        return out;
    }
    // 0x9265d8: division is float32, then widened to double.
    const float ratio = state.pinchStartScale / out.state.lastPinchFactor;
    const double minimum = takingPhoto ? 0.125 : 0.5;
    const double scale = static_cast<double>(ratio);
    out.state.pinchScale = scale < minimum ? minimum : scale;
    out.notifyScaleChanged = true; // 0x9266bc; no persistence request here.
    return out;
}
}
