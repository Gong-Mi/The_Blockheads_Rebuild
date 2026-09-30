#pragma once
#include "gameview_starttouch.h"
namespace blockheads::recovered {
// Secondary-touch state fields discovered with the secondary end/cancel batch:
// OBJC_IVAR_$_GameView.secondaryTouchStarted (offset 498) and
// secondaryStartTouchHasntMoved (offset 497). Added to the shared touch state
// rather than a duplicate struct.
struct GameViewSecondaryTouchState {
    std::int8_t secondaryTouchStarted{};        // ivar @498, gate byte
    std::int8_t secondaryStartTouchHasntMoved{}; // ivar @497, world-path latch
    // secondaryTouchIsActiveInUI (@508) already lives in GameViewStartTouchState.
};
// GameView -[endSecondaryTouch:] (0x0092cdd8). Mirror of the primary endTouch
// with ivar roles swapped: gate secondaryTouchStarted, forward index literal 1,
// clear secondaryTouchIsActiveInUI in the tail. No menu route.
void endSecondaryTouch(GameViewState& self, GameViewStartTouchState& primary,
                       GameViewSecondaryTouchState& secondary, FrameVector2 point);
// GameView -[cancelSecondaryTouch:] (0x0092cfa0). Same gates/send condition as
// endSecondaryTouch, forwards cancelTouch:index: with index 1, and additionally
// clears secondaryStartTouchHasntMoved on the world path (both send and skip).
void cancelSecondaryTouch(GameViewState& self, GameViewStartTouchState& primary,
                          GameViewSecondaryTouchState& secondary, FrameVector2 point);
}
