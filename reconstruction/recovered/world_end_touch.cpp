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
void worldCancelTouch(WorldEndTouchSink* self, FrameVector2 point,
                      std::int32_t index) {
    // World -[cancelTouch:index:] (0x005b33ac) is the same forwarding body:
    // [self doEndTouch:point wasCancelled:1 index:index]. The pinning tool
    // proves the two 30-word intervals differ only at the wasCancelled mov
    // (+0x5c) and the site-relative bl displacement (+0x70, same stub).
    if (self != nullptr) self->doEndTouch(point, 1, index);
}
}
