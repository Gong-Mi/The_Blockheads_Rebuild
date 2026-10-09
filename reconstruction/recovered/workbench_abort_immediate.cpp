#include "workbench_abort_immediate.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the workbench hard-abort family (E78).
namespace blockheads::recovered {
namespace {

static_assert(kAbortPaidItemType == 11, "the shared paid item code");
static_assert(kAbortPaidUnitCap == 50000, "the shared 0xc350 cap");

}  // namespace
}  // namespace blockheads::recovered
