#include "zoom_settle.h"
namespace blockheads::recovered {
namespace {
using B = ZoomSettleBranch;
// Literal double is widened float(.01), not the nearest double .01.
constexpr double bias = 0x1.47ae140000000p-7;
void ease(ZoomSettleResult& out, float dt, double target, bool upward,
          double snapThreshold, B branch) {
    const double delta = out.pinchScale - target;
    const float step = dt * 10.0f;
    const double factor = 1.0 - static_cast<double>(step);
    const double product = delta * factor;
    const double sum = target + product;
    out.pinchScale = upward ? sum + bias : sum - bias;
    out.branch = branch;
    out.writeScale = true;
    out.notifyScaleChanged = true;
    const bool snap = upward ? out.pinchScale > snapThreshold : out.pinchScale < snapThreshold;
    if (snap) {
        out.pinchScale = target;
        out.persistScale = true;
        out.persistedScale = static_cast<float>(target);
    }
}
}
ZoomSettleResult stepZoomSettle(ZoomSettleInput in) {
    ZoomSettleResult out{in.pinchScale, in.pinchStartScale, B::None,
                        false, false, false, 0.0f, false, false};
    if (in.isZoomingCameraOut) {
        // 0x926b88 contains double ZERO. Retain the written arithmetic,
        // do not invent zoom-out speed from the flag's name.
        const double amount = static_cast<double>(in.dt) * 0.0;
        const double product = amount * in.pinchScale;
        out.pinchScale = in.pinchScale + product;
        out.branch = B::CameraOut;
        out.writeScale = true;
        return out; // bypasses photo query and pinchStartScale tail
    }
    if (in.pinching) return out;
    out.queryTakingPhoto = true; // 0x926c20, before pinchZooming check
    if (in.takingPhoto || in.pinchZooming) return out;
    const double scale = in.pinchScale;
    if (scale < 0x1.fffeb00000000p-1) { // literal0x926b90
        if (scale < 0x1.3333340000000p-1) { // float(.6) widened
            if (scale > 0x1.0083126e978d5p-1) { // double .501
                ease(out, in.dt, 0.5, false, 0x1.fffd600000000p-2, B::HalfDown);
            }
        } else if (scale < 0x1.ff7ced916872bp-1) { // double .999
            ease(out, in.dt, 1.0, true, 0x1.0000100000000p+0, B::OneUp);
        }
        // Common call0x926fa0 includes both non-easing low deadbands.
        out.notifyScaleChanged = true;
    } else if (scale > 0x1.0000a80000000p+0) {
        if (scale < 1.25) { // VFP at0x926fe0; rendered text says1
            if (scale > 0x1.004189374bc6ap+0) {
                ease(out, in.dt, 1.0, false, 1.0, B::OneDown);
            }
        } else if (scale < 1.75) { // VFP at0x9271a0
            if (scale < 0x1.7fbe76c8b4396p+0) { // double1.499
                ease(out, in.dt, 1.5, true, 0x1.7fbe760000000p+0, B::OneHalfUp);
            } else if (scale > 0x1.804189374bc6ap+0) { // double1.501
                ease(out, in.dt, 1.5, false, 0x1.80418a0000000p+0, B::OneHalfDown);
            }
        } else if (scale < 2.5) { // VFP at0x927558; rendered text says2
            if (scale < 0x1.fff9720000000p+0) {
                ease(out, in.dt, 2.0, true, 0x1.ffbe760000000p+0, B::TwoUp);
            } else if (scale > 0x1.0003460000000p+1) {
                ease(out, in.dt, 2.0, false, 0x1.0020c40000000p+1, B::TwoDown);
            }
        } else if (scale < 0x1.7ffcba0000000p+1) {
            ease(out, in.dt, 3.0, true, 0x1.7fdf3c0000000p+1, B::ThreeUp);
        } else if (scale < 5.0) {
            if (scale > 0x1.8003460000000p+1) {
                ease(out, in.dt, 3.0, false, 0x1.8020c40000000p+1, B::ThreeDown);
            }
        } else if (scale < 0x1.fffe5c0000000p+2) {
            ease(out, in.dt, 8.0, true, 0x1.ffef9e0000000p+2, B::EightUp);
        } else {
            out.branch = B::HighCap;
            if (scale > static_cast<double>(in.maxScale)) {
                out.pinchScale = static_cast<double>(in.maxScale);
                out.writeScale = true;
            }
        }
    }
    // 0x927e50..0x927ec8: runs even in eligible deadbands; no flag clearing.
    // Actual code reloads scale AFTER callbacks: this snapshot result assumes
    // those callbacks did not mutate the relevant GameView state.
    if (in.hasPinchVelocity) {
        const double product = static_cast<double>(in.lastPinchFactor) * out.pinchScale;
        out.pinchStartScale = static_cast<float>(product);
        out.writePinchStartScale = true;
    }
    return out;
}
}
