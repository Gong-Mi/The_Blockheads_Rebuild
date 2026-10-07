#include "bucket_arrays.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the remote-receive bucket-array family.
namespace blockheads::recovered {
namespace {

static_assert(kObjectTypeGate == 0x41);
static_assert(kFreeBlockSkipType == 0xe);
static_assert(kRemoteUpdateSlotGate == 0x3c);

}  // namespace
}  // namespace blockheads::recovered
