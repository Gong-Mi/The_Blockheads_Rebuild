#include "gameview_end_touch.h"
namespace blockheads::recovered {
void endTouch(GameViewState& self, GameViewStartTouchState& touchState,
              GameViewEndTouchMenuUI* mainMenuUI, FrameVector2 point) {
    // 0x0092c43c / 0x0092c464: menu route iff mainMenuUI != nil AND world == nil.
    if (mainMenuUI != nullptr && self.world == nullptr) {
        // 0x0092c4a4 reloads self->mainMenuUI before [mainMenuUI endTouch:point].
        mainMenuUI->endTouch(point);
    } else {
        // 0x0092c4e8: reload receiver; a nil world is ObjC nil-dispatch (false).
        FrameWorld* world = self.world;
        const bool loaded = (world != nullptr) && world->loadComplete();
        if (loaded) {
            // 0x0092c534: reload again after the loadComplete message.
            world = self.world;
            const bool simulating = (world != nullptr) && world->isSimulating();
            if (!simulating) {
                // 0x0092c564/0x0092c588: send iff primary is active OR both
                // primary and secondary are inactive (ldrsb signed bytes).
                const bool send = touchState.primaryTouchIsActiveInUI != 0 ||
                                  touchState.secondaryTouchIsActiveInUI == 0;
                if (send) {
                    // 0x0092c5a4: reload the receiver after the ivar tests;
                    // literal index 0 was stored on the stack at 0x0092c5d0.
                    world = self.world;
                    if (world != nullptr) world->endTouch(point, 0);
                }
            }
        }
    }
    // Shared tail 0x0092c5e0..0x0092c5fc: every path stores zero to
    // primaryTouchIsActiveInUI (offset 496). That is the only GameView write.
    touchState.primaryTouchIsActiveInUI = 0;
}
}
