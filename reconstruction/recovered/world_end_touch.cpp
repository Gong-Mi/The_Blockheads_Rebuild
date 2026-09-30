#include "world_end_touch.h"
namespace blockheads::recovered {
void worldEndTouch(WorldEndTouchSink* self, FrameVector2 point,
                   std::int32_t index) {
    // World -[endTouch:index:] (0x005b3430) dispatches on self only:
    // [self doEndTouch:point wasCancelled:0 index:index].
    // Objective-C nil self is a no-op. CGPoint and index are preserved; the
    // wasCancelled stack word is the pinned constant 0 at 0x005b348c/0x005b3490.
    if (self != nullptr) self->doEndTouch(point, 0, index);
}
}
