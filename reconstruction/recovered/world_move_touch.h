#pragma once
#include "gameview_update.h"
namespace blockheads::recovered {
class WorldMoveTouchUI {
public:
    virtual ~WorldMoveTouchUI() = default;
    virtual void moveTouch(FrameVector2 point, std::int32_t index) = 0;
};
// World -[moveTouch:index:] (0x005b3278): one nil-safe UIManager dispatch.
void worldMoveTouch(WorldMoveTouchUI* uiManager, FrameVector2 point,
                    std::int32_t index);
}
