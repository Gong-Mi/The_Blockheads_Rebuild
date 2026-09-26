#include "ownkey_loader.h"

#include <cmath>
#include <cstring>

namespace blockheads::recovered {
namespace {

using Code = OwnKey5InitCall;

float bits_to_float(std::uint32_t bits) {
    float value;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

std::uint32_t float_to_bits(float value) {
    std::uint32_t bits;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

// ARM VCVT.U32.F32 semantics (round toward zero): NaN -> 0, negative -> 0,
// >= 2^32 -> 0xFFFFFFFF, otherwise truncate. Then VCVT.F32.U32 is exact.
std::uint32_t float_through_uint32(std::uint32_t bits) {
    const float value = bits_to_float(bits);
    std::uint32_t converted;
    if (std::isnan(value) || value < 0.0f) {
        converted = 0u;
    } else if (value >= 4294967296.0f) {
        converted = 0xFFFFFFFFu;
    } else {
        converted = static_cast<std::uint32_t>(value);
    }
    return float_to_bits(static_cast<float>(converted));
}

void store32(std::uint8_t* image, std::size_t size, std::uint32_t offset,
             std::uint32_t value) {
    if (static_cast<std::size_t>(offset) + 4 <= size) {
        std::memcpy(image + offset, &value, sizeof(value));
    }
}

}  // namespace

OwnKeyResult ownkey_run(const OwnKeyProgram& program, const OwnKeyInputs& in,
                        OwnKeyOutputs& out) {
    std::size_t count = 0;
    const auto record = [&](OwnKey5InitCall code, std::uint32_t arg) {
        if (count < out.trace_capacity) {
            out.trace[count] = OwnKeyTraceEntry{static_cast<std::uint8_t>(code),
                                                arg};
        }
        ++count;
    };

    // (1) the shared prologue: objc_msgSendSuper2 with the same-shape forward.
    record(Code::MsgSendSuper,
           program.forwards_long_selector ? 6u : 4u);

    // (2) the shared nil guard: every b3j member returns nil untouched.
    if (in.super_returns_nil) {
        return OwnKeyResult{0u, count};
    }

    // (3) the class-specific own steps, in the decoded order.
    std::size_t key_index = 0;
    for (std::size_t i = 0; i < program.step_count; ++i) {
        const OwnKeyStep& step = program.steps[i];
        switch (step.kind) {
            case OwnKeyStepKind::ReadOwnKey: {
                const std::uint32_t bits =
                    (key_index < in.key_value_count) ? in.key_values[key_index]
                                                     : 0u;
                record(Code::ObjectForKey,
                       static_cast<std::uint32_t>(key_index));
                std::uint32_t stored = bits;
                switch (step.conv) {
                    case OwnKeyConv::IntValue:
                        record(Code::IntValue, bits);
                        break;
                    case OwnKeyConv::FloatValue:
                        record(Code::FloatValue, bits);
                        break;
                    case OwnKeyConv::BoolValue:
                        record(Code::BoolValue, bits);
                        break;
                    case OwnKeyConv::DoubleValue:
                        record(Code::DoubleValue, bits);
                        break;
                    case OwnKeyConv::Retain:
                        record(Code::Retain, bits);
                        break;
                    case OwnKeyConv::FloatValueThroughUint32:
                        record(Code::FloatValue, bits);
                        stored = float_through_uint32(bits);
                        break;
                }
                store32(out.image, out.image_size, step.ivar_offset, stored);
                record(Code::StoreIvar, step.ivar_offset);
                ++key_index;
                break;
            }
            case OwnKeyStepKind::StoreIncomingArg: {
                const std::uint32_t value =
                    (std::strcmp(step.name, "seasonOffsetNoiseFunction") == 0)
                        ? in.season_offset_token
                        : in.tree_density_token;
                store32(out.image, out.image_size, step.ivar_offset, value);
                record(Code::StoreIvar, step.ivar_offset);
                break;
            }
            case OwnKeyStepKind::TailHook: {
                if (std::strcmp(step.name, "initSubDerivedItems") == 0) {
                    record(Code::InitSubDerivedItems, 0u);
                } else if (std::strcmp(step.name, "updateTextures") == 0) {
                    record(Code::UpdateTextures, 0u);
                } else if (std::strcmp(step.name, "loadSaveDictValues:") == 0) {
                    record(Code::LoadSaveDictValues, 0u);
                }
                break;
            }
            case OwnKeyStepKind::DynamicWorldNotify: {
                record(Code::ObjectType, in.object_type);
                record(Code::DynamicWorldChangedAtPos, in.ivar_pos_x);
                break;
            }
        }
    }

    return OwnKeyResult{in.self_token, count};
}

}  // namespace blockheads::recovered
