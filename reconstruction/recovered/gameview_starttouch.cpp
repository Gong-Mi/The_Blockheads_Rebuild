#include "gameview_starttouch.h"
namespace blockheads::recovered {
void startTouch(GameViewState& self, GameViewStartTouchState& touchState,
                StartTouchMenuUI* mainMenuUI, GameViewStartTouchRuntime& runtime,
                FrameVector2 point) {
    // 0x0092be8c / 0x0092be9c strb: both byte ivars cleared before any gate.
    touchState.startTouchHasntMoved = 0;
    touchState.primaryTouchIsActiveInUI = 0;
    // 0x0092beb8 beq / 0x0092bee0 bne: menu path iff mainMenuUI != nil AND
    // world == nil; otherwise the world path runs even for a nil world.
    if (mainMenuUI != nullptr && self.world == nullptr) {
        // 0x0092bf2c [withTouch tapCount]; 0x0092bf50
        // [mainMenuUI startTouch:point tapCount:tapCount]; then return.
        mainMenuUI->startTouch(point, runtime.touchTapCount());
        return;
    }
    // World gates reload self->world per send (0x0092bf70.. / 0x0092bfbc..).
    // Each send is nil-guarded: ObjC nil-dispatch yields 0/false WITHOUT
    // executing any callee, which C++ virtual calls on nullptr cannot model.
    FrameWorld* world = self.world; // reloaded 0x0092bf70..0x0092bf84
    if (world == nullptr || !world->loadComplete()) return;
    world = self.world; // reloaded 0x0092bfbc..0x0092bfd0
    // 0x0092bfe4 [world isSimulating], sxtb; nonzero skips the whole region.
    // Nil world models the ObjC zero, so the region still runs.
    if (world != nullptr && world->isSimulating()) return;
    // 0x0092c03c: tapCount is re-sent AFTER the gates, not reused.
    const std::int32_t tapCount = runtime.touchTapCount();
    // 0x0092c068 [world startTouch:point tapCount:tapCount index:0] with the
    // index literal 0 on the stack; 0x0092c080 strb keeps ONLY the low result
    // byte (GameView performs no sxtb of its own).
    world = self.world; // receiver reloaded 0x0092bff4..0x0092c00c
    touchState.primaryTouchIsActiveInUI =
        world ? world->startTouch(point, tapCount, 0) : 0;
    // 0x0092c0a8 [world touchIsInUI:point], sxtb; nonzero skips both stores.
    // Nil world again models the ObjC zero, so the stores DO execute for it.
    const bool touchInUI = world != nullptr && world->touchIsInUI(point) != 0;
    if (!touchInUI) {
        // 0x0092c0dc startTouchHasntMoved = 1; 0x0092c0f0/0x0092c0f8 store the
        // CGPoint as two full words (not byte clears).
        touchState.startTouchHasntMoved = 1;
        touchState.startTouchPos = point;
    }
}
}
