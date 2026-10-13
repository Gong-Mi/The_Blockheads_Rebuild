#include "workbench_craft_completed.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the craft-completed family (E75/E78 line).
namespace blockheads::recovered {
namespace {

static_assert(kAbortPaidItemType == 11, "the shared cmp r1, 0xb skip code");

}  // namespace
}  // namespace blockheads::recovered
