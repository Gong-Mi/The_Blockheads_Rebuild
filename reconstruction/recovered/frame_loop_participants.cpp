#include "frame_loop_participants.h"

namespace blockheads::recovered {
// header-only by design: this translation unit exists so the participant list is part of the recovered
// view library and gets compiled with the rest of it.
namespace {
static_assert(!kFrameLoopParticipants.empty());
}  // namespace
}  // namespace blockheads::recovered
