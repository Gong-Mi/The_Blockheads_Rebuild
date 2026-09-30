#include "scroll_inertia.h"

namespace blockheads::recovered {
InertiaResult stepInertia(ScrollState state, bool translatingToGoal,
                          Vec2 translation, float dt) {
    InertiaResult out{state, false, translation};
    // 0x925c6c..0x925d44: manual input precedes goal/inertia decisions.
    if (state.scrolling || state.pinching || !state.hasVelocity) return out;
    if (translatingToGoal) {
        out.state.hasVelocity = false;
        return out;
    }
    // 0x925d54..0x925dcc: float multiply, double subtract, float conversion.
    // Compile with -ffp-contract=off; do not reassociate or add a clamp.
    const float scaledDt = dt * 4.0f;
    const float factor = static_cast<float>(1.0 - static_cast<double>(scaledDt));
    out.state.velocity = {state.velocity.x * factor, state.velocity.y * factor};
    // Vector2::lengthSquared at 0x5dfa7c uses separate mul/mul/add.
    const float xx = out.state.velocity.x * out.state.velocity.x;
    const float yy = out.state.velocity.y * out.state.velocity.y;
    const float squared = xx + yy;
    if (squared < 0.1f) {
        out.state.hasVelocity = false;
        return out;
    }
    // 0x925e7c..0x925f28: getter, decayed velocity * dt, subtract, setter.
    const float dx = out.state.velocity.x * dt;
    const float dy = out.state.velocity.y * dt;
    out.translation = {translation.x - dx, translation.y - dy};
    out.writeTranslation = true;
    return out;
}
}
