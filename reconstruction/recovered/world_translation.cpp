#include "world_translation.h"
#include <cstring>
namespace blockheads::recovered {
namespace {
float widthTiles(const WorldTranslationState& s) {
    // lsl #5 discards high bits BEFORE vcvt.f32.s32. Avoid C++ signed-shift UB.
    std::uint32_t bits=static_cast<std::uint32_t>(s.worldWidthMacro.load(std::memory_order_relaxed)) << 5;
    std::int32_t signedBits; std::memcpy(&signedBits,&bits,sizeof(bits));
    return static_cast<float>(signedBits);
}
float quantum(double scale) {
    // Preserve BOTH f64 divisions followed by f64 -> f32; not scale/40.
    const double inverse=40.0/scale;
    return static_cast<float>(1.0/inverse);
}
}
void worldSetTranslation(WorldTranslationState& s, FrameVector2 value, WorldTranslationRuntime& rt) {
    std::memcpy(&s.accurateTranslation,&value,sizeof(value)); // 55321c/220
    // VFP BLT (N!=V) includes unordered; fallthrough is ordered >=.
    if (s.accurateTranslation.x >= widthTiles(s)) {
        s.accurateTranslation.x = s.accurateTranslation.x-widthTiles(s);
        if (s.translationGoal.x >= widthTiles(s))
            s.translationGoal.x = s.translationGoal.x-widthTiles(s);
    } else if (s.accurateTranslation.x < 0.0f) { // BPL skips zero/positive/unordered
        s.accurateTranslation.x = s.accurateTranslation.x+widthTiles(s);
        if (s.translationGoal.x < 0.0f)
            s.translationGoal.x = s.translationGoal.x+widthTiles(s);
    }
    // Exactly one wrap, not modulo or a loop. Goal adjustment is conditional.
    double scale=s.pinchScale;
    if (scale < 1.0) scale=1.0; // unordered survives BPL
    // Quantize original by-value input, NOT the wrapped accurateTranslation.
    const float rx=rt.wrapFmodf(value.x,quantum(scale));
    s.roundedTranslation.x=value.x-rx;
    const float ry=rt.wrapFmodf(value.y,quantum(scale));
    s.roundedTranslation.y=value.y-ry;
    auto* sound=rt.soundManagerInstance(); // may mutate any world fields
    // Snapshot only AFTER instance callback; do not reuse original/clamped values.
    const FrameVector2 position=s.accurateTranslation;
    const float zoom=static_cast<float>(s.pinchScale);
    if (sound) sound->setListenerPositionZoom(position,zoom); // ObjC nil dispatch
}
}
