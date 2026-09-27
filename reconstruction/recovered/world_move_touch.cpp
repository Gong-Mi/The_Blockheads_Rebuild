#include "world_move_touch.h"
namespace blockheads::recovered {
void worldMoveTouch(WorldMoveTouchUI* uiManager, FrameVector2 point,
                    std::int32_t index) {
    // Objective-C nil-dispatch is a no-op; non-nil preserves CGPoint/index.
    if (uiManager != nullptr) uiManager->moveTouch(point, index);
}
}
