#include "object_registry_pair.h"

// The registry pair is header-only in behaviour; this translation unit anchors
// the compiled unit, consistent with the other recovered modules.
namespace blockheads::recovered {
namespace {

static_assert(sizeof(RegisteredObject) > 0);

}  // namespace
}  // namespace blockheads::recovered
