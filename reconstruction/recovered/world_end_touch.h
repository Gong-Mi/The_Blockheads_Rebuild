#pragma once
#include "gameview_update.h"
namespace blockheads::recovered {
class WorldEndTouchSink {
public:
    virtual ~WorldEndTouchSink() = default;
    // -[doEndTouch:wasCancelled:index:]: wasCancelled is the original
    // signed-char argument; 0 is what endTouch:index: pushes.
    virtual void doEndTouch(FrameVector2 point, std::int8_t wasCancelled,
                            std::int32_t index) = 0;
};
// World -[endTouch:index:] (0x005b3430): one nil-safe self-dispatch of
// doEndTouch:wasCancelled:index: with wasCancelled pinned to 0.
void worldEndTouch(WorldEndTouchSink* self, FrameVector2 point,
                   std::int32_t index);
}
