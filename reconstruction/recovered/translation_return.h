#pragma once
namespace blockheads::recovered {
// Finite normal inputs/intermediates; FP contraction disabled, no fast-math.
// Snapshot-based numerical slice, not a replacement Objective-C callback.
// windowInfo lanes are deliberately not renamed to viewport dimensions.
struct TranslationReturnInput {
    float x;
    float y;
    float windowInfoLane3;
    double pinchScale;
    float dt;
    bool scrolling;
    bool pinching;
    bool translatingToGoal;
};
struct TranslationReturnResult {
    float x;
    float y;
    bool writeTranslation;
};
TranslationReturnResult stepTranslationReturn(TranslationReturnInput input);
// 0x926a4c..0x926acc only; later zoom flags can change this value again.
double capPinchScale(double pinchScale, float windowInfoLane1);
}
