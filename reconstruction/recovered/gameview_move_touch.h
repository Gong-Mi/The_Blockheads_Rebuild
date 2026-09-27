#pragma once
#include "gameview_starttouch.h"
namespace blockheads::recovered {
class GameViewMoveTouchMenuUI {
public:
    virtual ~GameViewMoveTouchMenuUI() = default;
    virtual void moveTouch(FrameVector2 point) = 0;
};
// GameView -[moveTouch:] (0x0092c148). This executes the recovered callback
// routing and local 2-point drag latch; Objective-C receivers remain adapters.
void moveTouch(GameViewState& self, GameViewStartTouchState& touchState,
               GameViewMoveTouchMenuUI* mainMenuUI, FrameVector2 point);
}
