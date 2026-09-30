#pragma once
#include "gameview_starttouch.h"
namespace blockheads::recovered {
class GameViewCancelTouchMenuUI {
public:
    virtual ~GameViewCancelTouchMenuUI() = default;
    // cancelTouch: maps to the menu UI's touch END, not a cancel selector
    // (0x0092c6e8 sends endTouch:).
    virtual void endTouch(FrameVector2 point) = 0;
};
// GameView -[cancelTouch:] (0x0092c638). Same menu/world gates and
// primary-or-idle-UI send condition as -[endTouch:], but the world path
// additionally clears startTouchHasntMoved and forwards to World's
// cancelTouch:index: (wasCancelled 1).
void cancelTouch(GameViewState& self, GameViewStartTouchState& touchState,
                 GameViewCancelTouchMenuUI* mainMenuUI, FrameVector2 point);
}
