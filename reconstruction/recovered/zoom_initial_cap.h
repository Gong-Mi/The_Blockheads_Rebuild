#pragma once
#include <cstdint>

namespace recovered {

// Exact numerical slice of GameView -[update:accurateDT:...] region
// 0x00926a4c..0x00926acc (pinned original ELF 733d8210…b94c7):
//
//   ivar cells: GameView.pinchScale (offset 152), GameView.windowInfo (208).
//   candidate = (double)(float)(40960.0f / (float)windowInfo[1])
//             // word literal 0xa000 movw -> int 40960; vdiv.f32; vcvt.f64.f32
//   vcmpe.f64 pinchScale, candidate; ble skip-store (0x00926aa4)
//   -> store executes ONLY on ordered pinchScale > candidate
//   -> ordered-equal, ordered-less and unordered (NaN operand) all skip
//      (ARM VCMPE sets Z for unordered, so BLE is taken)
//
// Returns whether the store executes (models the original write decision).
// windowHeightBits carries the exact float bits of windowInfo[1].
bool applyInitialZoomCap(double &pinchScale, uint32_t windowHeightBits);

} // namespace recovered
