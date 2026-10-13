#include "workbench_craft_abort.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the workbench craft abort family (E78).
namespace blockheads::recovered {
namespace {

static_assert(kAbortPaidItemType == 11, "the cmp r1, 0xb paid item code");
static_assert(kAbortPaidUnitCap == 50000, "the 0xc350 cap");

}  // namespace
}  // namespace blockheads::recovered
