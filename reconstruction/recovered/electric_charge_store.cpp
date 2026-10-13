#include "electric_charge_store.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the electric-charge-store family.
namespace blockheads::recovered {
namespace {

static_assert(kFurnaceFuelFence == 100);
static_assert(kStorageCapacity == 8192);
static_assert(kWorkbenchTypeGeneratorA == 15);
static_assert(kWorkbenchTypeGeneratorB == 20);
static_assert(kWorkbenchTypeStorage == 21);

}  // namespace
}  // namespace blockheads::recovered
