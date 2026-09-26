// CTest driver for the recovered b3j "forward-then-read" loader contract
// (reconstruction/recovered/ownkey5_init.cpp + the shared engine
// reconstruction/recovered/ownkey_loader.cpp).
//
// It runs the recovered engine for all five classes with synthetic inputs and
// asserts the returned receiver, the (code, arg) trace and the instance image
// against expectations transcribed from the batch decode -- including the
// EXECUTED CORRECTION for GatherBlock (timer -> floatValue+vcvt -> @56 first,
// lastKnownGatherValue -> intValue -> @60). CI therefore checks the contract
// without the original ELF; tools/test_ownkey5_arm.py executes the five
// original ARM32 bodies and must produce the same traces and images.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "generated/trace_codes.h"
#include "ownkey5_init.h"
#include "ownkey_loader.h"

namespace {

using blockheads::recovered::OwnKey5InitCall;
using blockheads::recovered::OwnKeyInputs;
using blockheads::recovered::OwnKeyOutputs;
using blockheads::recovered::OwnKeyResult;
using blockheads::recovered::OwnKeyTraceEntry;
using blockheads::recovered::ownkey_run;

constexpr std::uint32_t kSelf = 0x60000000;
constexpr std::uint32_t kWorld = 0x11110000;
constexpr std::uint32_t kDyn = 0x22220000;
constexpr std::uint32_t kSave = 0x33330000;
constexpr std::uint32_t kCache = 0x44440000;
constexpr std::uint32_t kDensity = 0x55550000;
constexpr std::uint32_t kSeason = 0x66660000;
constexpr std::uint32_t kDynIvar = 0x0D0D0001;
constexpr std::uint32_t kPosX = 0x00000011;
constexpr std::uint32_t kPosY = 0x00000022;
constexpr std::uint32_t kOtype = 0x00000033;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

struct Step {
    OwnKey5InitCall code;
    std::uint32_t arg;
};

bool same_trace(const std::vector<OwnKeyTraceEntry>& got,
                const std::vector<Step>& want) {
    if (got.size() != want.size()) {
        return false;
    }
    for (std::size_t i = 0; i < want.size(); ++i) {
        if (got[i].code != static_cast<std::uint8_t>(want[i].code) ||
            got[i].arg != want[i].arg) {
            return false;
        }
    }
    return true;
}

void dump(const char* name, const std::vector<OwnKeyTraceEntry>& got) {
    std::printf("  %s got trace:", name);
    for (const auto& e : got) {
        std::printf(" (%u,%u)", e.code, e.arg);
    }
    std::printf("\n");
}

// Runs one program and checks receiver, trace and image words.
void check(const char* name, const blockheads::recovered::OwnKeyProgram& prog,
           const std::vector<std::uint32_t>& keys,
           const std::vector<Step>& want_trace,
           const std::vector<std::pair<std::uint32_t, std::uint32_t>>& image,
           std::uint32_t image_size,
           const std::vector<std::pair<std::uint32_t, std::uint32_t>>& presets) {
    std::vector<std::uint8_t> buffer(image_size, 0);
    for (const auto& preset : presets) {
        std::memcpy(buffer.data() + preset.first, &preset.second, 4);
    }
    std::vector<OwnKeyTraceEntry> trace(32);

    OwnKeyInputs in{};
    in.self_token = kSelf;
    in.world_token = kWorld;
    in.dynamic_world_token = kDyn;
    in.save_dict_token = kSave;
    in.cache_token = kCache;
    in.tree_density_token = kDensity;
    in.season_offset_token = kSeason;
    in.super_returns_nil = false;
    in.ivar_dynamic_world = kDynIvar;
    in.ivar_pos_x = kPosX;
    in.ivar_pos_y = kPosY;
    in.object_type = kOtype;
    in.key_values = keys.empty() ? nullptr : keys.data();
    in.key_value_count = keys.size();

    OwnKeyOutputs out{};
    out.image = buffer.data();
    out.image_size = image_size;
    out.trace = trace.data();
    out.trace_capacity = trace.size();

    const OwnKeyResult result = ownkey_run(prog, in, out);
    expect(result.returned_token == kSelf, name);
    trace.resize(result.trace_count);
    if (!same_trace(trace, want_trace)) {
        expect(false, name);
        dump(name, trace);
    }
    for (const auto& entry : image) {
        std::uint32_t got = 0;
        std::memcpy(&got, buffer.data() + entry.first, 4);
        if (got != entry.second) {
            std::printf("  %s image@%u got 0x%08x want 0x%08x\n", name,
                        entry.first, got, entry.second);
            expect(false, name);
        }
    }
}

// Every b3j member returns nil on a nil super result and writes nothing.
void check_nil(const char* name,
               const blockheads::recovered::OwnKeyProgram& prog,
               const std::vector<std::uint32_t>& keys,
               std::uint32_t image_size, std::uint32_t super_args) {
    std::vector<std::uint8_t> buffer(image_size, 0xAB);
    std::vector<OwnKeyTraceEntry> trace(32);

    OwnKeyInputs in{};
    in.self_token = kSelf;
    in.super_returns_nil = true;
    in.key_values = keys.empty() ? nullptr : keys.data();
    in.key_value_count = keys.size();

    OwnKeyOutputs out{};
    out.image = buffer.data();
    out.image_size = image_size;
    out.trace = trace.data();
    out.trace_capacity = trace.size();

    const OwnKeyResult result = ownkey_run(prog, in, out);
    expect(result.returned_token == 0u, name);
    expect(result.trace_count == 1u, name);
    expect(trace[0].code == static_cast<std::uint8_t>(
               OwnKey5InitCall::MsgSendSuper), name);
    expect(trace[0].arg == super_args, name);
    for (std::uint32_t i = 0; i < image_size; ++i) {
        if (buffer[i] != 0xAB) {
            std::printf("  %s nil path wrote image@%u\n", name, i);
            expect(false, name);
            break;
        }
    }
}

}  // namespace

int main() {
    using blockheads::recovered::ownkey_program_apple_tree;
    using blockheads::recovered::ownkey_program_gather_block;
    using blockheads::recovered::ownkey_program_plant;
    using blockheads::recovered::ownkey_program_train_station;
    using blockheads::recovered::ownkey_program_yak;
    using C = OwnKey5InitCall;

    // AppleTree: availableFood -> floatValue -> @136
    check("AppleTree", ownkey_program_apple_tree(), {0x41480000},
          {{C::MsgSendSuper, 6}, {C::ObjectForKey, 0},
           {C::FloatValue, 0x41480000}, {C::StoreIvar, 136}},
          {{136, 0x41480000}}, 152, {});

    // TrainStation: text -> retain -> @128, then initSubDerivedItems
    check("TrainStation", ownkey_program_train_station(), {0xC0FFEE01},
          {{C::MsgSendSuper, 4}, {C::ObjectForKey, 0},
           {C::Retain, 0xC0FFEE01}, {C::StoreIvar, 128},
           {C::InitSubDerivedItems, 0}},
          {{128, 0xC0FFEE01}}, 160, {});

    // Plant: swallow both noise args into @60/@64, then delegate + notify.
    // @8/@16/@20 come from the pre-state (declared by the caller).
    check("Plant", ownkey_program_plant(), {},
          {{C::MsgSendSuper, 4}, {C::StoreIvar, 60}, {C::StoreIvar, 64},
           {C::LoadSaveDictValues, 0}, {C::ObjectType, kOtype},
           {C::DynamicWorldChangedAtPos, kPosX}},
          {{60, kDensity}, {64, kSeason}, {8, kDynIvar}, {16, kPosX},
           {20, kPosY}},
          96, {{8, kDynIvar}, {16, kPosX}, {20, kPosY}});

    // GatherBlock: executed correction -- timer -> floatValue + vcvt round
    // trip -> @56 first, then lastKnownGatherValue -> intValue -> @60.
    check("GatherBlock", ownkey_program_gather_block(), {0x41480000, 0x64},
          {{C::MsgSendSuper, 4}, {C::ObjectForKey, 0},
           {C::FloatValue, 0x41480000}, {C::StoreIvar, 56},
           {C::ObjectForKey, 1}, {C::IntValue, 0x64}, {C::StoreIvar, 60}},
          {{56, 0x41400000}, {60, 0x64}}, 96, {});

    // Yak: executed correction -- milk -> floatValue -> @1136 first, then
    // hair -> floatValue -> @1140, then updateTextures.
    check("Yak", ownkey_program_yak(), {0x40B00000, 0x40100000},
          {{C::MsgSendSuper, 4}, {C::ObjectForKey, 0},
           {C::FloatValue, 0x40B00000}, {C::StoreIvar, 1136},
           {C::ObjectForKey, 1}, {C::FloatValue, 0x40100000},
           {C::StoreIvar, 1140}, {C::UpdateTextures, 0}},
          {{1136, 0x40B00000}, {1140, 0x40100000}}, 1160, {});

    // nil super: every member returns nil and writes nothing.
    check_nil("AppleTree", ownkey_program_apple_tree(), {0x41480000}, 152, 6);
    check_nil("TrainStation", ownkey_program_train_station(), {0xC0FFEE01},
              160, 4);
    check_nil("Plant", ownkey_program_plant(), {}, 96, 4);
    check_nil("GatherBlock", ownkey_program_gather_block(), {0x41480000, 0x64},
              96, 4);
    check_nil("Yak", ownkey_program_yak(), {0x40B00000, 0x40100000}, 1160, 4);

    if (failures) {
        std::printf("ownkey5 contract: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("ownkey5 contract: 5 classes, happy + nil paths, "
                "trace and image matched\n");
    return 0;
}
