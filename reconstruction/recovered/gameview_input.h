#pragma once
#include "gameview_update.h"
namespace blockheads::recovered {
// Additional original ivars; shared fields remain in the ONE GameViewState.
// Not an Objective-C layout. Keep this extension paired with its owning state.
struct GameViewInputState {
    FrameVector2 pinchOffset{}, pinchStartOffset{}, translationOffset{};
};
class InputUI {
public:
    virtual ~InputUI() = default;
    virtual bool currentTouchIsInAnyButtons() = 0;
};
class GameViewInputRuntime : public FrameRuntime {
public:
    // Non-null receiver calls only. Dynamic ObjC boundaries are mandatory,
    // not guessed implementations of World/UI methods.
    virtual InputUI* uiManager(FrameWorld& receiver) = 0;
    virtual bool allowsPanning(FrameWorld& receiver) = 0;
    virtual void setTranslatingToGoal(FrameWorld& receiver, bool value) = 0;
    virtual void startPinchOrPan(FrameWorld& receiver) = 0;
    virtual void updateTranslation(GameViewState& self, FrameVector2 value) = 0;
};
void pinchZoomToScale(GameViewState& self, float ignoredScale);
bool shouldAllowDoubleTap(const GameViewState& self);
void pinchGesture(GameViewState& self, GameViewInputState& input,
                  GameViewInputRuntime& runtime, float factor, float velocity,
                  std::int32_t state, FrameVector2 center, std::int32_t numberOfTouches);
}
