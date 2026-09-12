#include "pinch_return.h"
#include <cstdlib>
#include <iostream>
using namespace blockheads::recovered;
void check(bool ok, const char* message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; std::exit(1); }
}
int main() {
    auto r = stepPinchReturn({true, 2.0}, 0.125f);
    check(r.handledBranch && r.persistScale && !r.state.pinchZooming, "finish branch and persist");
    check(r.state.pinchScale == 1.0 && r.persistedValue == 1.0f, "dt times eight");
    r = stepPinchReturn({true, 1.005}, 0.0f);
    check(!r.state.pinchZooming && r.persistScale && r.state.pinchScale == 1.005, "do not snap scale to one");
    check(r.persistedValue == static_cast<float>(1.005), "persist current float value");
    r = stepPinchReturn({true, 2.0}, 0.0f);
    check(r.handledBranch && !r.persistScale && r.state.pinchZooming && r.state.pinchScale == 2.0, "continue outside threshold");
    r = stepPinchReturn({false, 2.0}, 0.125f);
    check(!r.handledBranch && !r.persistScale && r.state.pinchScale == 2.0, "disabled branch");
    r = stepPinchReturn({true, 2.0}, 0.25f);
    check(r.state.pinchScale == 0.0 && !r.persistScale, "no invented interpolation clamp");
    r = stepPinchReturn({true, 0.5}, 0.0625f);
    check(r.state.pinchScale == 0.75 && r.state.pinchZooming, "approach from below");
    std::cout << "pinch-return: PASS\n";
}
