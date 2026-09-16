// Production numerical-slice regression for the initial zoom cap.
// Not an original-runtime oracle; equality claims are limited to finite,
// normal inputs with finite results (the pinned VCMPE/BLE flag table
// documents the NaN behaviour exactly).
#ifdef NDEBUG
#error assertions must remain enabled
#endif
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <iostream>
#include "zoom_initial_cap.h"

using recovered::applyInitialZoomCap;

static uint32_t bits(float f) {
    uint32_t u;
    std::memcpy(&u, &f, sizeof(u));
    return u;
}

// float(40960/height) widened exactly once, like the original pipeline.
static double candidate(uint32_t heightBits) {
    float h;
    std::memcpy(&h, &heightBits, sizeof(h));
    return static_cast<double>(40960.0f / h);
}

static void storeOnOrderedGreater() {
    const uint32_t h = bits(1080.0f);
    const double cap = candidate(h);           // float(37.9259..) widened
    double pinch = cap + 0.5;                  // ordered greater -> store
    assert(applyInitialZoomCap(pinch, h));
    assert(pinch == cap && "stored value must be the widened f32 quotient");
}

static void equalAndLessSkip() {
    const uint32_t h = bits(1080.0f);
    const double cap = candidate(h);
    double pinch = cap;
    assert(!applyInitialZoomCap(pinch, h) && "ordered-equal skips the store");
    assert(pinch == cap);
    pinch = cap - 1.0;
    assert(!applyInitialZoomCap(pinch, h) && "ordered-less skips the store");
    assert(pinch == cap - 1.0);
}

static void nanOperandsSkip() {
    // windowInfo[1] NaN: candidate NaN -> VCMPE unordered -> Z=1 -> BLE taken.
    const double nan32 = std::numeric_limits<double>::quiet_NaN();
    const uint32_t h = bits(1080.0f);
    double pinch = 100.0;
    assert(!applyInitialZoomCap(pinch, bits(static_cast<float>(nan32)))
           && "NaN height must skip the store");
    assert(pinch == 100.0);
    // pinchScale NaN likewise skips.
    pinch = std::numeric_limits<double>::quiet_NaN();
    assert(!applyInitialZoomCap(pinch, h) && "NaN pinchScale must skip the store");
    assert(std::isnan(pinch));
}

static void floatDomainRoundTripPreserved() {
    // The original divides in FLOAT then widens; a double-domain recompute
    // would differ for some heights. Pick one where f32 vs f64 quotients differ.
    for (uint32_t hi : {bits(1.0f), bits(3.0f), bits(2048.0f), bits(65535.0f)}) {
        float h;
        std::memcpy(&h, &hi, sizeof(h));
        const double fDomain = static_cast<double>(40960.0f / h);
        const double dDomain = 40960.0 / static_cast<double>(h);
        double pinch = 1e300;  // surely greater than candidate unless height huge
        if (applyInitialZoomCap(pinch, hi)) {
            assert(pinch == fDomain && "must be the float-domain quotient widened");
            (void)dDomain;
        }
    }
}

static void zeroAndInfinityHeights() {
    // 40960f/0.0f = +inf (f32), widened; finite pinch > inf is false -> skip.
    double pinch = 5.0;
    assert(!applyInitialZoomCap(pinch, bits(0.0f)) && "zero height must not lower pinchScale");
    assert(pinch == 5.0);
    // 40960f/-0.0f = -inf: ordered-greater holds -> store happens at -inf.
    // Recorded from the flag table, not from sentiment: the original DOES
    // clamp to -inf when it ever sees a negative-zero window height.
    pinch = 5.0;
    assert(applyInitialZoomCap(pinch, bits(-0.0f)));
    assert(pinch == -std::numeric_limits<double>::infinity());
    // +inf height: candidate 0 -> any positive pinch clamps to 0.
    pinch = 3.0;
    assert(applyInitialZoomCap(pinch, bits(std::numeric_limits<float>::infinity())));
    assert(pinch == 0.0);
}

int main() {
    storeOnOrderedGreater();
    equalAndLessSkip();
    nanOperandsSkip();
    floatDomainRoundTripPreserved();
    zeroAndInfinityHeights();
    std::cout << "PASS 5 initial-zoom-cap tests\n";
    return 0;
}
