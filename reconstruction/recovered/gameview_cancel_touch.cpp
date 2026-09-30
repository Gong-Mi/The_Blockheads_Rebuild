#include "gameview_cancel_touch.h"
namespace blockheads::recovered {
void cancelTouch(GameViewState& self, GameViewStartTouchState& touchState,
                 GameViewCancelTouchMenuUI* mainMenuUI, FrameVector2 point) {
    // 0x0092c680 / 0x0092c6a8: menu route iff mainMenuUI != nil AND world == nil.
    if (mainMenuUI != nullptr && self.world == nullptr) {
        // 0x0092c6e8 reloads self->mainMenuUI, then [mainMenuUI endTouch:point]
        // — the menu receives an END, never a cancel selector.
        mainMenuUI->endTouch(point);
    } else {
        // 0x0092c72c: reload receiver; nil world is ObjC nil-dispatch (false).
        FrameWorld* world = self.world;
        const bool loaded = (world != nullptr) && world->loadComplete();
        if (loaded) {
            // 0x0092c778: reload again after the loadComplete message.
            world = self.world;
            const bool simulating = (world != nullptr) && world->isSimulating();
            if (!simulating) {
                // 0x0092c7a8/0x0092c7cc: send iff primary is active OR both
                // primary and secondary UI bytes are zero (ldrsb signed).
                const bool send = touchState.primaryTouchIsActiveInUI != 0 ||
                                  touchState.secondaryTouchIsActiveInUI == 0;
                if (send) {
                    // 0x0092c818: reload the receiver after the ivar tests;
                    // literal index 0 was stored on the stack at 0x0092c814.
                    world = self.world;
                    if (world != nullptr) world->cancelTouch(point, 0);
                }
                // Join 0x0092c81c: reached by the send fall-through AND by the
                // primary==0&&secondary!=0 skip. startTouchHasntMoved=0 is
                // world-path-only: the menu route and the gate early-exits
                // never execute it (unlike endTouch's universal tail clear).
                touchState.startTouchHasntMoved = 0;
            }
        }
    }
    // Shared tail 0x0092c840..0x0092c85c: every path stores zero to
    // primaryTouchIsActiveInUI (offset 496).
    touchState.primaryTouchIsActiveInUI = 0;
}
}
