#include "gameview_move_touch.h"
#include <cmath>
namespace blockheads::recovered {
void moveTouch(GameViewState& self, GameViewStartTouchState& touchState,
               GameViewMoveTouchMenuUI* mainMenuUI, FrameVector2 point) {
    // 0x0092c190 / 0x0092c1b8: menu route iff mainMenuUI != nil AND world == nil.
    if (mainMenuUI != nullptr && self.world == nullptr) {
        // 0x0092c1f8: [mainMenuUI moveTouch:point].
        mainMenuUI->moveTouch(point);
        return;
    }

    // 0x0092c23c: reload world and require loadComplete's signed-byte result != 0.
    FrameWorld* world = self.world;
    if (world == nullptr || !world->loadComplete()) return;

    // 0x0092c288: reload after callback; a nil receiver returns 0, hence not simulating.
    world = self.world;
    if (world != nullptr && world->isSimulating()) return;

    // 0x0092c2b0 ldrsb: only primaryTouchIsActiveInUI gates the indexed callback.
    // Reload the receiver after isSimulating; literal index 0 is sent at 0x0092c300.
    world = self.world;
    if (world != nullptr && touchState.primaryTouchIsActiveInUI != 0) {
        world->moveTouch(point, 0);
    }

    // 0x0092c330/0x0092c374 subtract in f32, widen the rounded delta to f64,
    // abs, then ordered-compare against exact 2.0. NaN is not greater.
    const float deltaX = point.x - touchState.startTouchPos.x;
    if (std::fabs(static_cast<double>(deltaX)) > 2.0) {
        // 0x0092c3ac strb: clear only startTouchHasntMoved.
        touchState.startTouchHasntMoved = 0;
        return;
    }
    const float deltaY = point.y - touchState.startTouchPos.y;
    if (std::fabs(static_cast<double>(deltaY)) > 2.0) {
        // 0x0092c3ac strb: same store when Y is strictly over the threshold.
        touchState.startTouchHasntMoved = 0;
    }
}
}
