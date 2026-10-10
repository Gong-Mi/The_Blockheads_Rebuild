// Optional ARM differential bridge for the b3j "forward-then-read" family
// (batch ownkey5). Exposes the shared recovered engine + the five thin class
// descriptors to tools/test_ownkey5_arm.py, which executes the ORIGINAL ARM32
// bodies under Unicorn and compares the instance image, the message trace and
// the returned receiver bit-for-bit against this module at -O0 and -O2.
#include "ownkey5_init.h"

#include <cstdint>
#include <cstring>

using blockheads::recovered::OwnKeyInputs;
using blockheads::recovered::OwnKeyOutputs;
using blockheads::recovered::OwnKeyProgram;
using blockheads::recovered::ownkey_run;

extern "C" {

struct RecoveredOwnKeyIn {
    std::uint32_t self_token;
    std::uint32_t world_token;
    std::uint32_t dynamic_world_token;
    std::uint32_t save_dict_token;
    std::uint32_t cache_token;
    std::uint32_t tree_density_token;
    std::uint32_t season_offset_token;
    std::uint32_t super_returns_nil;
    std::uint32_t ivar_dynamic_world;
    std::uint32_t ivar_pos_x;
    std::uint32_t ivar_pos_y;
    std::uint32_t object_type;
};

struct RecoveredOwnKeyTrace {
    std::uint8_t code;
    std::uint32_t arg;
};

// which: 0 AppleTree, 1 TrainStation, 2 Plant, 3 GatherBlock, 4 Yak.
// Returns the trace length; the returned receiver token is written to
// *returned_token.
//
// preset_offsets/preset_values/preset_count declare ivar state that already
// exists BEFORE this method runs (e.g. Plant's dynamicWorld/pos fields, set by
// an earlier load step). Both sides must start from that state or a whole-image
// comparison reports a difference the method did not cause.
std::uint32_t recovered_ownkey5_run(int which, const RecoveredOwnKeyIn* in,
                                    const std::uint32_t* key_values,
                                    std::uint32_t key_value_count,
                                    const std::uint32_t* preset_offsets,
                                    const std::uint32_t* preset_values,
                                    std::uint32_t preset_count,
                                    std::uint8_t* image,
                                    std::uint32_t image_size,
                                    RecoveredOwnKeyTrace* trace,
                                    std::uint32_t trace_capacity,
                                    std::uint32_t* returned_token) {
    static const OwnKeyProgram* const kPrograms[] = {
        &blockheads::recovered::ownkey_program_apple_tree(),
        &blockheads::recovered::ownkey_program_train_station(),
        &blockheads::recovered::ownkey_program_plant(),
        &blockheads::recovered::ownkey_program_gather_block(),
        &blockheads::recovered::ownkey_program_yak(),
    };
    const OwnKeyProgram& program = *kPrograms[which];

    OwnKeyInputs inputs{};
    inputs.self_token = in->self_token;
    inputs.world_token = in->world_token;
    inputs.dynamic_world_token = in->dynamic_world_token;
    inputs.save_dict_token = in->save_dict_token;
    inputs.cache_token = in->cache_token;
    inputs.tree_density_token = in->tree_density_token;
    inputs.season_offset_token = in->season_offset_token;
    inputs.super_returns_nil = in->super_returns_nil != 0;
    inputs.ivar_dynamic_world = in->ivar_dynamic_world;
    inputs.ivar_pos_x = in->ivar_pos_x;
    inputs.ivar_pos_y = in->ivar_pos_y;
    inputs.object_type = in->object_type;
    inputs.key_values = key_values;
    inputs.key_value_count = key_value_count;

    // Pre-existing ivar state: declared by the caller so BOTH sides start from
    // an identical image (the ARM side gets the same words written before its
    // run) and the whole image can be compared.
    for (std::uint32_t i = 0; i < preset_count; ++i) {
        const std::uint32_t offset = preset_offsets[i];
        if (static_cast<std::uint64_t>(offset) + 4u <= image_size) {
            std::memcpy(image + offset, &preset_values[i], 4u);
        }
    }

    OwnKeyOutputs outputs{};
    outputs.image = image;
    outputs.image_size = image_size;
    outputs.trace = reinterpret_cast<blockheads::recovered::OwnKeyTraceEntry*>(
        trace);
    outputs.trace_capacity = trace_capacity;

    const auto result = ownkey_run(program, inputs, outputs);
    *returned_token = result.returned_token;
    return static_cast<std::uint32_t>(result.trace_count);
}

}  // extern "C"
