#pragma once
namespace blockheads::recovered {
// 0x926acc..0x927ed4: finite normal inputs/intermediates, contraction off.
// Snapshot/effect API: external queries and callbacks are NOT executed here.
enum class ZoomSettleBranch {
    None, CameraOut, HalfDown, OneUp, OneDown, OneHalfUp, OneHalfDown,
    TwoUp, TwoDown, ThreeUp, ThreeDown, EightUp, HighCap
};
struct ZoomSettleInput {
    double pinchScale;
    float pinchStartScale;
    float lastPinchFactor;
    float maxScale; // already computed as f32(40960 / windowInfo lane1)
    float dt;
    bool isZoomingCameraOut;
    bool pinching;
    bool takingPhoto;
    bool pinchZooming;
    bool hasPinchVelocity;
};
struct ZoomSettleResult {
    double pinchScale;
    float pinchStartScale;
    ZoomSettleBranch branch;
    bool queryTakingPhoto;
    bool writeScale;
    bool persistScale;
    float persistedScale;
    bool notifyScaleChanged; // after persistence, if any
    bool writePinchStartScale; // after notification, under snapshot assumption
};
ZoomSettleResult stepZoomSettle(ZoomSettleInput input);
}
