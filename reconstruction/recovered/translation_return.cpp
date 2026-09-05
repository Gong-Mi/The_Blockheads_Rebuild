#include "translation_return.h"
namespace blockheads::recovered {
TranslationReturnResult stepTranslationReturn(TranslationReturnInput input) {
    TranslationReturnResult out{input.x, input.y, false};
    // 0x925c8c/0x925cb0 bypass this entire region; 0x926718 skips on goal.
    if (input.scrolling || input.pinching || input.translatingToGoal) return out;
    // 0x9267bc..0x9267ec: float product, double scale, float bounds.
    const float laneProduct = input.windowInfoLane3 * 0.025f;
    const float lower = static_cast<float>(static_cast<double>(laneProduct) * input.pinchScale);
    const float upper = 1024.0f - lower;
    // The double literal at 0x926b80 equals widened float(0.01), NOT double .01.
    constexpr double bias = static_cast<double>(0.01f);
    if (out.y < lower && out.y < upper) {
        const float distance = out.y - lower;
        const float scaledDt = input.dt * 10.0f;
        const double factor = 1.0 - static_cast<double>(scaledDt);
        const double movement = static_cast<double>(distance) * factor;
        const double position = static_cast<double>(lower) + movement;
        out.y = static_cast<float>(position + bias);
        if (out.y > lower - 0.01f) out.y = lower;
    } else if (out.y > upper && out.y > lower) {
        const float distance = out.y - upper;
        const float scaledDt = input.dt * 10.0f;
        const double factor = 1.0 - static_cast<double>(scaledDt);
        const double movement = static_cast<double>(distance) * factor;
        const double position = static_cast<double>(upper) + movement;
        out.y = static_cast<float>(position - bias);
        if (out.y < upper + 0.01f) out.y = upper;
    }
    // 0x926a24..0x926a44 copies both float lanes into r2/r3 for setTranslation:.
    // This request occurs even when neither correction branch changed y.
    out.writeTranslation = true;
    return out;
}
double capPinchScale(double pinchScale, float windowInfoLane1) {
    const float limit = 40960.0f / windowInfoLane1;
    return pinchScale > static_cast<double>(limit) ? static_cast<double>(limit) : pinchScale;
}
}
