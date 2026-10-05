#include "dynamic_object_flags.h"

// The model is deliberately header-only in behaviour; this translation unit exists so the recovered view
// library has a compiled unit for the flag cluster, keeping it consistent with the other recovered
// modules (which are all built into blockheads_recovered_view).
namespace blockheads::recovered {
namespace {
constexpr int kFlagClusterBytes = 5;  // 48..52 inclusive
static_assert(kFlagClusterBytes == static_cast<int>(kOffsetIsNet - kOffsetNeedsRemoved) + 1);
}  // namespace
}  // namespace blockheads::recovered
