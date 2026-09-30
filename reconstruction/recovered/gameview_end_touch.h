#pragma once
#include "gameview_starttouch.h"
namespace blockheads::recovered {
class GameViewEndTouchMenuUI {
public:
    virtual ~GameViewEndTouchMenuUI() = default;
    virtual void endTouch(FrameVector2 point) = 0;
};
// GameView -[endTouch:] (0x0092c3f4). Executes the recovered menu/world
// routing, the loadComplete/isSimulating gates, the primary-or-idle-UI
// indexed-send condition, and the unconditional primary-active clear.
void endTouch(GameViewState& self, GameViewStartTouchState& touchState,
              GameViewEndTouchMenuUI* mainMenuUI, FrameVector2 point);
}
