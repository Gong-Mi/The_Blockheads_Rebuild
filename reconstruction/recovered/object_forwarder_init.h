// Recovered semantics of the `initWithWorld:dynamicWorld:saveDict:cache:`
// forwarder convention (batch b4c), shared by ClownFish, Shark, Scorpion, Dodo
// and DonkeyLike (each 74 words, one 69-word body pinned by sha256 in b3f).
//
// Decoded shape, executed under Unicorn in tools/test_forwarder_arm.py:
//   [super initWithWorld:dynamicWorld:saveDict:cache:]   (objc_msgSendSuper2,
//         struct {self, OBJC_CLASS_$_<own class>}, forwarder selector)
//   if (super result == nil) return nil
//   [self loadDerivedStuff]                              (zero-argument hook)
//   return self
//
// The contract is class-agnostic on purpose: the five bodies differ only in
// their literal cells, so the same recovered behaviour must describe all five.
#pragma once

#include <vector>

namespace blockheads::recovered {

struct ForwarderInputs {
    // When true the stubbed objc_msgSendSuper2 returns nil, so the forwarder
    // must return nil without calling its post-init hook.
    bool super_returns_nil = false;
};

enum class ForwarderCall : int {
    SuperInit = 0,
    PostInitHook = 1,
};

struct ForwarderResult {
    bool returned_nil = false;
    std::vector<ForwarderCall> calls;
};

ForwarderResult forwarder_init_with_world(const ForwarderInputs& inputs);

}  // namespace blockheads::recovered
