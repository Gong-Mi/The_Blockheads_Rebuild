#include "translation_return.h"
#include <cassert>
#include <initializer_list>
#include <cstdio>
using namespace blockheads::recovered;
static TranslationReturnInput input(float y, float dt = 0.05f) {
    return {123.0f, y, 1000.0f, 1.0, dt, false, false, false};
}
int main() {
    // Getter result is sent back even if no coordinate needs correction.
    auto r = stepTranslationReturn(input(500.0f));
    assert(r.writeTranslation && r.x == 123.0f && r.y == 500.0f);
    for (int gate = 0; gate < 3; ++gate) {
        auto s = input(0.0f);
        if (gate == 0) s.scrolling = true;
        if (gate == 1) s.pinching = true;
        if (gate == 2) s.translatingToGoal = true;
        r = stepTranslationReturn(s);
        assert(!r.writeTranslation && r.y == 0.0f);
    }
    r = stepTranslationReturn(input(0.0f));
    assert(r.y == 12.51f && r.x == 123.0f);
    r = stepTranslationReturn(input(1100.0f));
    assert(r.y == 1049.49f);
    // Bias is still applied at zero dt; no invented dt gate.
    assert(stepTranslationReturn(input(0.0f, 0.0f)).y == 0.01f);
    assert(stepTranslationReturn(input(1100.0f, 0.0f)).y == 1099.99f);
    // Crossing the strict near-boundary test snaps to that boundary.
    assert(stepTranslationReturn(input(24.995f)).y == 25.0f);
    assert(stepTranslationReturn(input(999.005f)).y == 999.0f);
    assert(stepTranslationReturn(input(0.0f, 0.2f)).y == 25.0f);
    assert(stepTranslationReturn(input(1100.0f, 0.2f)).y == 999.0f);
    // Equality at the snap thresholds must NOT snap (strict > / <).
    auto strictLower = input(-0.02f, 0.0f); strictLower.windowInfoLane3 = 0.0f;
    assert(stepTranslationReturn(strictLower).y == -0.01f);
    auto strictUpper = input(1024.02f, 0.0f); strictUpper.windowInfoLane3 = 0.0f;
    assert(stepTranslationReturn(strictUpper).y == 1024.01f);
    // Both bounds are tested, not an assumed sorted clamp interval.
    auto inverted = input(500.0f);
    inverted.windowInfoLane3 = 30000.0f; // bounds 750 and 274
    assert(stepTranslationReturn(inverted).y == 500.0f);
    for (float y : {25.0f, 999.0f}) {
        assert(stepTranslationReturn(input(y)).y == y);
    }
    // Even nil getter's zero result can be numerically changed; the caller
    // must retain Objective-C nil dispatch rather than creating a world.
    auto nilResult = input(0.0f); nilResult.x = 0.0f;
    assert(stepTranslationReturn(nilResult).x == 0.0f);
    assert(stepTranslationReturn(nilResult).writeTranslation);
    assert(capPinchScale(100.0, 1024.0f) == 40.0);
    assert(capPinchScale(40.0, 1024.0f) == 40.0);
    assert(capPinchScale(0.125, 1024.0f) == 0.125);
    const float floatLimit = 40960.0f / 1001.0f;
    assert(capPinchScale(100.0, 1001.0f) == static_cast<double>(floatLimit));
    assert(capPinchScale(100.0, 1001.0f) != 40960.0 / 1001.0);
    std::puts("translation-return: PASS");
}
