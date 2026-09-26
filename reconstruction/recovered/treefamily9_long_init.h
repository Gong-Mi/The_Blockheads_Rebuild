// Recovered semantics of the tree-family LONG loader selector (batch b3i,
// executed at Level-B here):
//
//   -[<Class> initWithWorld:dynamicWorld:saveDict:cache:
//              treeDensityNoiseFunction:seasonOffsetNoiseFunction:]
//
// Nine classes (CactusTree, CherryTree, CoconutTree, CoffeeTree, GemTree,
// LimeTree, MangoTree, MapleTree, OrangeTree) share ONE byte-identical body
// (words 0..58, sha256-gated in b3i); only the per-class tail literal words
// 59..61 differ (own-class superref / selector cells). So ONE recovered
// implementation describes all nine, and each class gets a thin wrapper that
// binds its own superref/selector cells (see treefamily9_long_init_classes.h).
//
// Decoded + executed shape:
//   spill all six incoming arguments into an outgoing call frame;
//   objc_msgSendSuper2({receiver = self, class = own-class superref},
//                      selector, world, dynamicWorld,
//                      saveDict, cache, treeDensityNoiseFunction,
//                      seasonOffsetNoiseFunction);
//   if (super result == nil) return nil;
//   return the super result (return self);
//   no CFString key, no own ivar, no post-init hook.
#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace blockheads::recovered {

// The six forwarded arguments in their declared order.
enum TreeForward9Arg : int {
    kArgWorld = 0,
    kArgDynamicWorld = 1,
    kArgSaveDict = 2,
    kArgCache = 3,
    kArgTreeDensityNoiseFunction = 4,
    kArgSeasonOffsetNoiseFunction = 5,
};

struct TreeForward9Inputs {
    // Opaque fixture tokens for the six arguments, in declared order.
    std::array<std::uintptr_t, 6> args{};
    // The class word the body stores into objc_super (its own-class superref).
    std::uintptr_t class_ref = 0;
    // The selector cell the body loads and passes as _cmd.
    std::uintptr_t selector_ref = 0;
    // When true the stubbed super returns nil, so the body must return nil.
    bool super_returns_nil = false;
};

struct TreeForward9Result {
    bool returned_nil = false;
    // The argument tuple handed to [super …], in forward order.
    std::array<std::uintptr_t, 6> forwarded{};
    std::uintptr_t super_class_ref = 0;
    std::uintptr_t super_selector_ref = 0;
    std::vector<int> calls;  // blockheads::recovered::TreeFamily9LongInitCall
};

TreeForward9Result treefamily9_long_init_forward(const TreeForward9Inputs&);

}  // namespace blockheads::recovered
