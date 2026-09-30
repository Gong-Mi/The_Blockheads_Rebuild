#include "gameview_secondary_touch.h"
namespace blockheads::recovered {
namespace {
// Shared World-path gates for both secondary bodies: reload the receiver for
// every message, exactly as the primary bodies do.
bool worldGatesPass(GameViewState& self, FrameWorld*& world) {
    world = self.world;                                    // 0x0092ce34/0x0092d01c
    if (world == nullptr || !world->loadComplete()) return false;
    world = self.world;                                    // reload after callback
    if (world != nullptr && world->isSimulating()) return false;
    world = self.world;                                    // reload before the send
    return true;
}
}

void endSecondaryTouch(GameViewState& self, GameViewStartTouchState& primary,
                       GameViewSecondaryTouchState& secondary, FrameVector2 point) {
    // 0x0092ce1c: gate on secondaryTouchStarted through ldrsb/cmp signed-byte
    // semantics.
    if (secondary.secondaryTouchStarted != 0) {
        FrameWorld* world = nullptr;
        if (worldGatesPass(self, world)) {
            // 0x0092ced8/0x0092cefc: send iff secondary active OR primary idle —
            // the mirror of the primary pair's own-active OR other-idle gate.
            if (primary.secondaryTouchIsActiveInUI != 0 ||
                primary.primaryTouchIsActiveInUI == 0) {
                if (world != nullptr) world->endTouch(point, 1);  // literal 1 at 0x0092cf40
            }
        }
    }
    // Shared tail 0x0092cf50..0x0092cf6c: clear secondaryTouchIsActiveInUI on
    // every path (mirror of the primary tail clearing the primary byte).
    primary.secondaryTouchIsActiveInUI = 0;
}

void cancelSecondaryTouch(GameViewState& self, GameViewStartTouchState& primary,
                          GameViewSecondaryTouchState& secondary, FrameVector2 point) {
    if (secondary.secondaryTouchStarted != 0) {            // 0x0092cfe4
        FrameWorld* world = nullptr;
        if (worldGatesPass(self, world)) {
            if (primary.secondaryTouchIsActiveInUI != 0 ||
                primary.primaryTouchIsActiveInUI == 0) {
                if (world != nullptr) world->cancelTouch(point, 1);  // literal 1 at 0x0092d108
            }
            // Join 0x0092d114: reached by the send fall-through AND by the
            // secondary==0/primary!=0 skip — world-path-only latch clear.
            secondary.secondaryStartTouchHasntMoved = 0;
        }
    }
    // Shared tail 0x0092d134..0x0092d150.
    primary.secondaryTouchIsActiveInUI = 0;
}
}
