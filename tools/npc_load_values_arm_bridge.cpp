// Optional ARM differential bridge: exposes the recovered NPC
// loadValuesFromSaveDict: contract to tools/test_npc_loadvalues_arm.py, which
// executes the ORIGINAL ARM method under Unicorn with a synthetic save
// dictionary and compares the resulting instance image and call trace
// byte-for-byte against this module (built at -O0 and -O2).
#include "npc_load_values_from_save_dict.h"

#include <cstddef>
#include <cstdint>

using blockheads::recovered::NpcLoadCall;
using blockheads::recovered::NpcLoadKey;
using blockheads::recovered::NpcLoadValuesInputs;

extern "C" {

// present/bits: one entry per NpcLoadKey (15 entries). old_name/old_tame_counts:
// initial name@92 / tameCountsByClientID@104 contents (0 = nil).
// image_out: kNpcLoadImageSize bytes receive the zero-init instance image
// with the decoded stores applied. trace_out: up to kNpcLoadMaxTrace codes.
// Returns the trace length.
std::uint32_t recovered_npc_load_values_run(
    const std::uint8_t* present, const std::uint32_t* bits,
    std::uint32_t old_name, std::uint32_t old_tame_counts,
    std::uint8_t* image_out, std::uint8_t* trace_out) {
    NpcLoadValuesInputs inputs;
    for (int i = 0; i < static_cast<int>(NpcLoadKey::Count); ++i) {
        inputs.present[i] = present[i] != 0;
        inputs.bits[i] = bits[i];
    }
    inputs.old_name = old_name;
    inputs.old_tame_counts = old_tame_counts;

    const auto result = blockheads::recovered::npc_load_values_run(inputs);
    for (std::size_t i = 0; i < blockheads::recovered::kNpcLoadImageSize; ++i) {
        image_out[i] = result.image[i];
    }
    const std::uint32_t n =
        result.calls.size() > blockheads::recovered::kNpcLoadMaxTrace
            ? blockheads::recovered::kNpcLoadMaxTrace
            : static_cast<std::uint32_t>(result.calls.size());
    for (std::uint32_t i = 0; i < n; ++i) {
        trace_out[i] = static_cast<std::uint8_t>(result.calls[i]);
    }
    return n;
}

}  // extern "C"
