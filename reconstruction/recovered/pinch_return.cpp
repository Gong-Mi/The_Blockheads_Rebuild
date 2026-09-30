#include "pinch_return.h"
#include <cmath>
namespace blockheads::recovered {
PinchReturnResult stepPinchReturn(PinchReturnState state, float dt) {
    PinchReturnResult out{state, false, false, 0.0f};
    if (!state.pinchZooming) return out;
    out.handledBranch = true;
    // 0x9262cc..0x926304: double delta times float32(dt*8), then double add.
    const double remaining = 1.0 - state.pinchScale;
    const float factor = dt * 8.0f;
    const double delta = remaining * static_cast<double>(factor);
    out.state.pinchScale = state.pinchScale + delta;
    // 0x926318..0x926334: cast to float BEFORE subtract/abs/compare.
    const float scale32 = static_cast<float>(out.state.pinchScale);
    const float difference = scale32 - 1.0f;
    if (std::fabs(difference) < 0.01f) {
        out.state.pinchZooming = false;
        out.persistScale = true;
        out.persistedValue = scale32;
    }
    // 0x9263dc jumps over the pinch-velocity branch even after flag clearing.
    return out;
}
}
