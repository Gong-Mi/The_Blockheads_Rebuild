// Shared recovered engine for the b3j "forward-then-read own key" family
// (batch ownkey5): AppleTree / TrainStation / Plant / GatherBlock / Yak.
//
// All five are one shape, executed identically in the original ARM32:
//
//   objc_msgSendSuper2(forward)      // same-shape super forward
//   if (result == nil) return nil    // the shared nil guard
//   <per-class own steps>            // own-key reads / arg stores / hooks
//   return self
//
// The COMMON path (super forward, nil guard, the per-step trace vocabulary,
// the 32-bit ivar stores, the post-init hooks) lives here once. Each class is
// a thin OwnKeyProgram table in ownkey5_init.cpp. Nothing in this file is
// class-specific.
//
// Static level-A decode: reconstruction/reverse-v3/native/MIDSIZE5_INITWITHWORLD.md
// (batch b3j) + the per-method listings in
// reconstruction/reverse-v3/native/disasm_*_ownkey5.txt.
#pragma once

#include <cstddef>
#include <cstdint>

#include "generated/trace_codes.h"

namespace blockheads::recovered {

// The objc_msgSend conversion that follows objectForKey: on the boxed value.
enum class OwnKeyConv : std::uint8_t {
    IntValue,
    FloatValue,
    BoolValue,
    DoubleValue,
    Retain,
    // GatherBlock's lastKnownGatherValue passes through an explicit
    // `vcvt.u32.f32` / `vcvt.f32.u32` pair: (float)(std::uint32_t)floatValue.
    FloatValueThroughUint32,
};

enum class OwnKeyStepKind : std::uint8_t {
    ReadOwnKey,          // objectForKey: name -> conv -> 32-bit store @ ivar
    StoreIncomingArg,    // store a raw incoming long-variant arg @ ivar (Plant)
    TailHook,            // [self name]
    DynamicWorldNotify,  // [self objectType] then
                         // [self->dynamicWorld dynamicWorldChangedAtPos:pos objectType:type]
};

struct OwnKeyStep {
    OwnKeyStepKind kind;
    OwnKeyConv conv;              // ReadOwnKey only
    const char* name;             // key (ReadOwnKey) or hook selector (TailHook)
    std::uint32_t ivar_offset;
};

struct OwnKeyProgram {
    const char* class_name;
    const char* selector;          // the method's OWN selector (passed in r1)
    bool forwards_long_selector;   // true: forward all 6 args to super, false: 4
    const OwnKeyStep* steps;
    std::size_t step_count;
};

struct OwnKeyInputs {
    std::uint32_t self_token;
    std::uint32_t world_token;
    std::uint32_t dynamic_world_token;
    std::uint32_t save_dict_token;
    std::uint32_t cache_token;
    std::uint32_t tree_density_token;    // long-variant arg 7
    std::uint32_t season_offset_token;   // long-variant arg 8
    bool super_returns_nil;
    std::uint32_t ivar_dynamic_world;    // pre-existing self->dynamicWorld (Plant)
    std::uint32_t ivar_pos_x;            // pre-existing self->pos.x (offset 16)
    std::uint32_t ivar_pos_y;            // pre-existing self->pos.y (offset 20)
    std::uint32_t object_type;           // [self objectType] answer
    const std::uint32_t* key_values;     // raw 32-bit bits per ReadOwnKey, in order
    std::size_t key_value_count;
};

struct OwnKeyTraceEntry {
    std::uint8_t code;
    std::uint32_t arg;
};

struct OwnKeyOutputs {
    std::uint8_t* image;         // caller-owned instance image, zero-filled
    std::size_t image_size;
    OwnKeyTraceEntry* trace;     // caller-owned trace buffer
    std::size_t trace_capacity;
};

struct OwnKeyResult {
    std::uint32_t returned_token;  // self_token, or 0 on the nil-super path
    std::size_t trace_count;
};

// The shared forward-then-read driver. The class-specific behaviour is data
// (the OwnKeyProgram); this function is the common executed path.
OwnKeyResult ownkey_run(const OwnKeyProgram& program, const OwnKeyInputs& in,
                        OwnKeyOutputs& out);

}  // namespace blockheads::recovered
