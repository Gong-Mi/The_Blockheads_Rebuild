#include "zoom_initial_cap.h"
#include <cstring>

namespace recovered {

bool applyInitialZoomCap(double &pinchScale, uint32_t windowHeightBits) {
    // 0x00926a74 vldr s2,[r3,#4]: windowInfo[1], inline float at self+212.
    float height;
    std::memcpy(&height, &windowHeightBits, sizeof(height));
    // 0x00926a78 vdiv.f32 s0 = 40960.0f / height (word literal 0x47200000),
    // 0x00926a94 vcvt.f64.f32 d3, s0: widen the FLOAT result, never recompute in double.
    const double candidate = static_cast<double>(40960.0f / height);
    // 0x00926a98 vcmpe.f64 d2=pinchScale, d3; vmrs; 0x00926aa4 ble skip-store.
    // ARMv7 VCMPE flag table (Rn vs Rm):
    //   Equal      N=0 Z=1 C=1 V=1  -> BLE taken  (skip)
    //   Greater    N=0 Z=0 C=1 V=0  -> BLE not    (STORE)
    //   Less       N=1 Z=0 C=0 V=0  -> BLE not? N!=V -> taken (skip)
    //   Unordered  N=1 Z=1 C=1 V=1  -> Z==1 -> BLE taken (skip)
    // So the store executes exactly on ordered greater; NaN operands skip.
    // IEEE C++ `>` is ordered greater and false for unordered — equivalent.
    if (pinchScale > candidate) {
        // 0x00926ab8 vcvt d1,s0; 0x00926ac8 vstr d1,[self+152]
        pinchScale = candidate;
        return true;
    }
    return false;
}

} // namespace recovered
