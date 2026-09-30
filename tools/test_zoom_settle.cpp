#include "zoom_settle.h"
#include <cassert>
#include <cmath>
#include <cstdio>
#include <limits>
#include <initializer_list>
using namespace blockheads::recovered;
using B = ZoomSettleBranch;
static ZoomSettleInput input(double s, float dt = 0.05f) {
    return {s, 77.0f, 2.0f, 40.0f, dt, false, false, false, false, false};
}
int main() {
    struct Case { double s, expected, target; B branch; };
    const Case cases[] = {
        {0.55, 0x1.07ae147cccccdp-1, 0.5, B::HalfDown},
        {0.8, 0x1.d1eb851cccccdp-1, 1.0, B::OneUp},
        {1.1, 0x1.0a3d70a4ccccdp+0, 1.0, B::OneDown},
        {1.3, 0x1.68f5c28e66666p+0, 1.5, B::OneHalfUp},
        {1.7, 0x1.970a3d719999ap+0, 1.5, B::OneHalfDown},
        {1.8, 0x1.e8f5c28e66666p+0, 2.0, B::TwoUp},
        {2.2, 0x1.0b851eb8ccccdp+1, 2.0, B::TwoDown},
        {2.6, 0x1.67ae147a66666p+1, 3.0, B::ThreeUp},
        {3.2, 0x1.8b851eb8ccccdp+1, 3.0, B::ThreeDown},
        {6.0, 0x1.c0a3d70a00000p+2, 8.0, B::EightUp},
    };
    for (auto c : cases) {
        auto r = stepZoomSettle(input(c.s));
        assert(r.pinchScale == c.expected && r.branch == c.branch);
        assert(r.queryTakingPhoto && r.writeScale && r.notifyScaleChanged);
        assert(!r.persistScale && !r.writePinchStartScale);
        r = stepZoomSettle(input(c.s, 0.1f));
        assert(r.pinchScale == c.target && r.persistScale);
        assert(r.persistedScale == static_cast<float>(c.target));
        // Snap branch is consumed; do not cascade into another scale range.
        assert(r.branch == c.branch && r.notifyScaleChanged);
        auto velocity = input(c.s);
        velocity.hasPinchVelocity = true;
        velocity.lastPinchFactor = 1.234567f;
        r = stepZoomSettle(velocity);
        assert(r.writePinchStartScale);
        assert(r.pinchStartScale == static_cast<float>(static_cast<double>(velocity.lastPinchFactor) * c.expected));
        velocity.dt = 0.1f;
        r = stepZoomSettle(velocity);
        assert(r.pinchStartScale == static_cast<float>(static_cast<double>(velocity.lastPinchFactor) * c.target));
    }
    // Every path: equality must not snap; adjacent inputs probe crossing.
    struct SnapEdge { double input, threshold; bool upward; B branch; };
    const SnapEdge edges[] = {
        {0x1.051d685000000p-1, 0x1.fffd600000000p-2, false, B::HalfDown},
        {0x1.fae167b000000p-1, 0x1.0000100000000p+0, true, B::OneUp},
        {0x1.028f5c2800000p+0, 0x1.0000000000000p+0, false, B::OneDown},
        {0x1.7d2f19d800000p+0, 0x1.7fbe760000000p+0, true, B::OneHalfUp},
        {0x1.82d0e62800000p+0, 0x1.80418a0000000p+0, false, B::OneHalfDown},
        {0x1.fd2f19d800000p+0, 0x1.ffbe760000000p+0, true, B::TwoUp},
        {0x1.0168721400000p+1, 0x1.0020c40000000p+1, false, B::TwoDown},
        {0x1.7e978dec00000p+1, 0x1.7fdf3c0000000p+1, true, B::ThreeUp},
        {0x1.8168721400000p+1, 0x1.8020c40000000p+1, false, B::ThreeDown},
        {0x1.ff4bc6f600000p+2, 0x1.ffef9e0000000p+2, true, B::EightUp},
    };
    for (auto edge : edges) {
        auto exact = stepZoomSettle(input(edge.input, 0.0f));
        assert(exact.branch == edge.branch && exact.pinchScale == edge.threshold);
        assert(!exact.persistScale);
        double toward = edge.upward ? std::numeric_limits<double>::infinity()
                                    : -std::numeric_limits<double>::infinity();
        double next = std::nextafter(edge.input, toward);
        auto crossed = stepZoomSettle(input(next, 0.0f));
        if (edge.branch == B::OneUp) {
            // Addition crosses an exponent boundary: one input ULP rounds
            // back to the threshold; the second representable input snaps.
            assert(crossed.pinchScale == edge.threshold && !crossed.persistScale);
            crossed = stepZoomSettle(input(std::nextafter(next, toward), 0.0f));
        }
        assert(crossed.branch == edge.branch && crossed.persistScale);
    }
    auto camera = input(6.0); camera.isZoomingCameraOut = true;
    camera.hasPinchVelocity = true; camera.pinching = true;
    auto r = stepZoomSettle(camera);
    assert(r.branch == B::CameraOut && r.writeScale && r.pinchScale == 6.0);
    assert(!r.queryTakingPhoto && !r.notifyScaleChanged && !r.persistScale);
    assert(!r.writePinchStartScale && r.pinchStartScale == 77.0f);
    for (int gate = 0; gate < 3; ++gate) {
        auto in = input(1.3); in.hasPinchVelocity = true;
        if (gate == 0) in.pinching = true;
        if (gate == 1) in.takingPhoto = true;
        if (gate == 2) in.pinchZooming = true;
        r = stepZoomSettle(in);
        assert(!r.writeScale && !r.notifyScaleChanged && !r.writePinchStartScale);
        assert(r.queryTakingPhoto == (gate != 0));
    }
    // Low-scale deadbands still notify; higher deadbands do not.
    for (double s : {0.4, 0.5, 0.501, 0.999}) {
        r = stepZoomSettle(input(s));
        assert(!r.writeScale && !r.persistScale && r.notifyScaleChanged);
    }
    for (double s : {1.0, 1.001, 1.5, 1.501, 2.0, 3.0}) {
        auto in = input(s); in.hasPinchVelocity = true;
        r = stepZoomSettle(in);
        assert(!r.writeScale && !r.persistScale && !r.notifyScaleChanged);
        assert(r.writePinchStartScale && r.pinchStartScale == static_cast<float>(2.0*s));
    }
    // Actual basin boundaries decoded from VFP bits, not rounded display labels.
    assert(stepZoomSettle(input(1.25)).branch == B::OneHalfUp);
    assert(stepZoomSettle(input(1.75)).branch == B::TwoUp);
    assert(stepZoomSettle(input(2.5)).branch == B::ThreeUp);
    assert(stepZoomSettle(input(5.0)).branch == B::EightUp);
    // Strict gate threshold: the neighbouring representable value enters.
    auto above = [](double s) { return std::nextafter(s, std::numeric_limits<double>::infinity()); };
    auto below = [](double s) { return std::nextafter(s, -std::numeric_limits<double>::infinity()); };
    assert(stepZoomSettle(input(0.501)).branch == B::None);
    assert(stepZoomSettle(input(above(0.501))).branch == B::HalfDown);
    assert(stepZoomSettle(input(0.999)).branch == B::None);
    assert(stepZoomSettle(input(below(0.999))).branch == B::OneUp);
    assert(stepZoomSettle(input(1.001)).branch == B::None);
    assert(stepZoomSettle(input(above(1.001))).branch == B::OneDown);
    assert(stepZoomSettle(input(1.499)).branch == B::None);
    assert(stepZoomSettle(input(below(1.499))).branch == B::OneHalfUp);
    // High cap only in its branch; no invented universal final clamp.
    auto high = input(100.0); high.maxScale = 10.0f;
    r = stepZoomSettle(high);
    assert(r.branch == B::HighCap && r.pinchScale == 10.0 && r.writeScale);
    assert(!r.notifyScaleChanged && !r.persistScale);
    auto overshoot = input(6.0, 0.1f); overshoot.maxScale = 6.0f;
    assert(stepZoomSettle(overshoot).pinchScale == 8.0);
    // Bias is applied at dt=0; it is not a velocity-only step.
    assert(stepZoomSettle(input(1.3, 0.0f)).pinchScale == 1.3 + static_cast<double>(0.01f));
    std::puts("zoom-settle: PASS");
}
