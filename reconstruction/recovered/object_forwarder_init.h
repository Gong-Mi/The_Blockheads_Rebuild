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
// The contract is class-agnostic on purpose: the bodies differ only in their
// literal cells (and, for forwarder5b, in whether they carry a post-init
// hook), so the same recovered behaviour must describe all of them. The
// forwarder5b differential (tools/test_forwarder5b_arm.py) executes the five
// 5b bodies against this contract with hook_present per class.
#pragma once

#include <vector>

namespace blockheads::recovered {

struct ForwarderInputs {
    // When true the stubbed objc_msgSendSuper2 returns nil, so the forwarder
    // must return nil without calling its post-init hook.
    bool super_returns_nil = false;
    // The forwarder5b batch's five bodies split on this: SurfaceBlock /
    // PassengerCar / HandCar are super-only (57-60 words, no hook), while
    // Mirror / SnowSurfaceBlock (71 words) additionally call
    // [self initSubDerivedItems]. Default true keeps the b3f five (which all
    // call loadDerivedStuff) unchanged.
    bool hook_present = true;
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
