#pragma once
#include "gameview_update.h"
namespace blockheads::recovered {
// Additional original ivars for -[startTouch:withTouch:withEvent:]; shared
// fields remain in the ONE GameViewState. Not an Objective-C layout.
struct GameViewStartTouchState {
    std::int8_t startTouchHasntMoved{};
    std::int8_t primaryTouchIsActiveInUI{};
    FrameVector2 startTouchPos{};
};
class StartTouchMenuUI {
public:
    virtual ~StartTouchMenuUI() = default;
    // -[UIManager startTouch:tapCount:] on mainMenuUI. Full int tapCount.
    virtual void startTouch(FrameVector2 point, std::int32_t tapCount) = 0;
};
class GameViewStartTouchRuntime {
public:
    virtual ~GameViewStartTouchRuntime() = default;
    // UITouch -[tapCount] via objc_msgSend, sent exactly where the original
    // sends it (menu path and post-gate world path). A nil touch models the
    // ObjC nil-dispatch zero by returning 0 without any other side effect.
    virtual std::int32_t touchTapCount() = 0;
};
// GameView -[startTouch:withTouch:withEvent:] (0x0092be2c, PIC base 0x0105faf4).
// withEvent is never read by the original body and is not modeled.
void startTouch(GameViewState& self, GameViewStartTouchState& touchState,
                StartTouchMenuUI* mainMenuUI, GameViewStartTouchRuntime& runtime,
                FrameVector2 point);
}
