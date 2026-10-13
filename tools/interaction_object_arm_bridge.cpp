// ARM-bridge for the InteractionObject init differential: drives the
// recovered contract with the SAME case table the Unicorn harness uses and
// exports the resulting 96-byte image plus the call-trace bits.
//
// Case values are shared by convention with tools/test_interaction_object_arm.py
// (kept trivial and explicit so both sides cannot drift silently).
#include "interaction_object_init.h"

#include <cstdint>
#include <cstring>

namespace {

using blockheads::recovered::InteractionInitCall;
using blockheads::recovered::InteractionInitInputs;
using blockheads::recovered::interaction_init_run;

int callBit(InteractionInitCall call) { return static_cast<int>(call); }

// Per-case wiring — mirrors the Python table one-to-one.
// Boxed-token convention (shared with the harness): 0x60001000 + i*0x10
// (isInUse 0x00, flipped 0x10, ownerID 0x20, ownerName 0x30, paintColor
// 0x40, blockhead 0x50); the world-resolved name token is 0x60001060.
InteractionInitInputs makeInputs(std::uint32_t case_id) {
    InteractionInitInputs in;
    in.self_ptr = 0x60000000u;
    switch (case_id) {
        case 0:  // all present, server + ownerID -> resolution runs
            in.in_use_present = true; in.in_use_value = true;
            in.flipped_present = true; in.flipped_value = true;
            in.owner_id_present = true; in.owner_id_token = 0x60001020u;
            // ownerName ABSENT: the ownerName==nil gate lets the world
            // resolution run
            in.paint_color_present = true; in.paint_color_value = 0x10005u;
            in.blockhead_index_present = true; in.blockhead_index_value = -7;
            in.is_server = true;
            in.resolved_owner_name_token = 0x60001060u;
            break;
        case 1:  // super nil
            in.super_returns_nil = true;
            break;
        case 2:  // everything absent (nil semantics), not server
            break;
        case 3:  // blockhead probe absent, paint present
            in.paint_color_present = true; in.paint_color_value = 0x1234u;
            break;
        case 4:  // server but ownerID absent -> no resolution
            in.is_server = true;
            in.resolved_owner_name_token = 0x60001060u;
            break;
        case 5:  // ownerID present but not server -> key value stays
            in.owner_id_present = true; in.owner_id_token = 0x60001020u;
            in.owner_name_present = true; in.owner_name_token = 0x60001030u;
            in.is_server = false;
            break;
        case 6:  // strh truncation edge: 0x1FFFF -> 0xFFFF
            in.paint_color_present = true; in.paint_color_value = 0x1FFFFu;
            break;
        case 7:  // server + ownerID, but ownerName present -> resolution SKIPPED
            in.owner_id_present = true; in.owner_id_token = 0x60001020u;
            in.owner_name_present = true; in.owner_name_token = 0x60001030u;
            in.is_server = true;
            in.resolved_owner_name_token = 0x60001060u;
            break;
        default:
            break;
    }
    return in;
}

}  // namespace

extern "C" std::uint64_t recovered_interaction_arm_case(std::uint32_t case_id,
                                                        std::uint8_t* out_image) {
    const auto result = interaction_init_run(makeInputs(case_id));
    std::uint64_t bits = 0;
    for (const auto call : result.calls) {
        bits |= (std::uint64_t{1} << callBit(call));
    }
    if (result.return_value == 0) {
        bits |= (std::uint64_t{1} << 40);  // the returned-nil flag
    }
    if (out_image != nullptr) {
        std::memcpy(out_image, result.image.data(),
                    blockheads::recovered::kInteractionImageSize);
    }
    return bits;
}
