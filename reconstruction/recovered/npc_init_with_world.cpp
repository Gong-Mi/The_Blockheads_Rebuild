#include "npc_init_with_world.h"

namespace blockheads::recovered {

float npc_hunger_timer_seed(std::int32_t lrand48_value) {
    // Step order matters: the original converts, divides by the pinned 2^31
    // float literal, multiplies by 20 and adds 1, each in single precision
    // (vldr s4 = 0x4f000000 → 2147483648.0f).
    const float as_float = static_cast<float>(lrand48_value);      // vcvt.f32.s32
    const float normalised = as_float / 2147483648.0f;             // vdiv.f32
    const float scaled = normalised * 20.0f;                       // vmul.f32
    return scaled + 1.0f;                                          // vadd.f32
}

NpcInitResult npc_init_with_world(const NpcInitInputs& inputs) {
    NpcInitResult result;
    result.calls.push_back(NpcInitCall::SuperInit);
    if (inputs.super_returns_nil) {
        result.returned_nil = true;
        return result;
    }
    result.calls.push_back(NpcInitCall::LoadValuesFromSaveDict);
    result.calls.push_back(NpcInitCall::Lrand48);
    result.random_harm_from_hunger_timer =
        npc_hunger_timer_seed(inputs.lrand48_value);
    result.timer_written = true;
    return result;
}

}  // namespace blockheads::recovered
