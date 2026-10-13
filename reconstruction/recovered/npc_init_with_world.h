// Recovered semantics of -[NPC initWithWorld:dynamicWorld:saveDict:cache:]
// (0x00644b24, 95 words) — the loader b3f's five creatures forward into.
//
// Decoded from the pinned ARM binary (batch b3g) and verified bit-exactly
// against the original instructions executed under Unicorn
// (tools/test_npc_initwithworld_arm.py):
//
//   [super initWithWorld:dynamicWorld:saveDict:cache:]   (objc_msgSendSuper2,
//         struct {self, OBJC_CLASS_$_NPC})
//   if (super result == nil) return nil
//   [self loadValuesFromSaveDict:saveDict]
//   randomHarmFromHungerTimer@144 = 1.0f + 20.0f * (float(lrand48()) / 2^31f)
//
// This module is a contract for that slice only. It is not the Android
// runtime, not Foundation, and not a replacement for the whole method: the
// superclass initialiser, the save dictionary and the hook body live outside
// this contract.
#pragma once

#include <cstdint>
#include <vector>

namespace blockheads::recovered {

enum class NpcInitCall : int {
    SuperInit = 0,
    LoadValuesFromSaveDict = 1,
    Lrand48 = 2,
};

struct NpcInitInputs {
    // Value the stubbed lrand48 returns (the original calls the real one).
    std::int32_t lrand48_value = 0;
    // When true the stubbed objc_msgSendSuper2 returns nil, which must make
    // the loader return nil without calling the hook or seeding the timer.
    bool super_returns_nil = false;
};

struct NpcInitResult {
    bool returned_nil = false;
    float random_harm_from_hunger_timer = 0.0f;
    bool timer_written = false;
    std::vector<NpcInitCall> calls;
};

// randomHarmFromHungerTimer seed: 1.0f + 20.0f * (float(v) / 2^31f), computed
// with the same single-precision step order as the ARM VFP sequence
// (vcvt.f32.s32 → vdiv → vmul → vadd).
float npc_hunger_timer_seed(std::int32_t lrand48_value);

NpcInitResult npc_init_with_world(const NpcInitInputs& inputs);

}  // namespace blockheads::recovered
