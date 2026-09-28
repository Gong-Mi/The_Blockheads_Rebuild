// InteractionObject init contract test: pins the decoded flow — call order,
// store widths (incl. the paintColor STRH), the currentBlockheadIndex probe,
// the isServer + ownerID tail gates, and nil semantics.
#include "interaction_object_init.h"

#include <cassert>
#include <cstdio>
#include <cstring>

namespace {

using blockheads::recovered::InteractionInitCall;
using blockheads::recovered::InteractionInitInputs;
using blockheads::recovered::interaction_init_run;

std::uint32_t word(const std::vector<std::uint8_t>& image, std::size_t off) {
    std::uint32_t v = 0;
    std::memcpy(&v, image.data() + off, sizeof(v));
    return v;
}

std::uint16_t half(const std::vector<std::uint8_t>& image, std::size_t off) {
    std::uint16_t v = 0;
    std::memcpy(&v, image.data() + off, sizeof(v));
    return v;
}

}  // namespace

int main() {
    // ---- full case: every key present, server resolution runs ------------
    {
        InteractionInitInputs in;
        in.in_use_present = true;
        in.in_use_value = true;
        in.flipped_present = true;
        in.flipped_value = true;
        in.owner_id_present = true;
        in.owner_id_token = 0x0A000001;
        in.owner_name_present = true;
        in.owner_name_token = 0x0A000002;
        in.paint_color_present = true;
        in.paint_color_value = 0x10005;  // will truncate to 0x0005
        in.blockhead_index_present = true;
        in.blockhead_index_value = -7;
        in.is_server = true;
        in.resolved_owner_name_token = 0x0A000003;

        const auto r = interaction_init_run(in);
        assert(r.return_value == in.self_ptr);
        assert(r.image[68] == 1);                  // isInUse byte
        assert(r.image[69] == 1);                  // flipped byte
        assert(word(r.image, 36) == 0x0A000001);   // ownerID retained token
        // the tail resolution OVERWRITES ownerName@84 (server + ownerID)
        assert(word(r.image, 84) == 0x0A000003);
        assert(word(r.image, 80) == static_cast<std::uint32_t>(-7));
        // paintColor: STRH truncation to the low 16 bits
        assert(half(r.image, 88) == 0x0005);
        // the call trace order, exactly the decoded sequence
        const std::vector<InteractionInitCall> expected = {
            InteractionInitCall::SuperInit,
            InteractionInitCall::ObjectForKeyIsInUse,
            InteractionInitCall::BoolValueIsInUse,
            InteractionInitCall::ObjectForKeyFlipped,
            InteractionInitCall::BoolValueFlipped,
            InteractionInitCall::ObjectForKeyOwnerID,
            InteractionInitCall::RetainOwnerID,
            InteractionInitCall::ObjectForKeyOwnerName,
            InteractionInitCall::RetainOwnerName,
            InteractionInitCall::ObjectForKeyPaintColor,
            InteractionInitCall::UnsignedIntValuePaintColor,
            InteractionInitCall::ObjectForKeyCurrentBlockheadIndexProbe,
            InteractionInitCall::ObjectForKeyCurrentBlockheadIndex,
            InteractionInitCall::IntValueCurrentBlockheadIndex,
            InteractionInitCall::IsServer,
            InteractionInitCall::GetOwnerNameForObjectOwnerID,
            InteractionInitCall::RetainResolvedOwnerName,
        };
        assert(r.calls == expected);
    }

    // ---- super nil: no key read at all -----------------------------------
    {
        InteractionInitInputs in;
        in.super_returns_nil = true;
        const auto r = interaction_init_run(in);
        assert(r.return_value == 0);
        assert(r.calls.size() == 1);  // only the super call
        for (std::uint8_t b : r.image) assert(b == 0);
    }

    // ---- probe gate: blockhead absent -> no second read, no store --------
    {
        InteractionInitInputs in;
        in.blockhead_index_present = false;
        in.paint_color_present = true;
        in.paint_color_value = 4660;
        const auto r = interaction_init_run(in);
        assert(word(r.image, 80) == 0);
        for (auto c : r.calls) {
            assert(c != InteractionInitCall::ObjectForKeyCurrentBlockheadIndex);
            assert(c != InteractionInitCall::IntValueCurrentBlockheadIndex);
        }
        assert(half(r.image, 88) == 4660);
    }

    // ---- tail gate: is_server false -> no resolution ----------------------
    {
        InteractionInitInputs in;
        in.owner_id_present = true;
        in.owner_id_token = 0x0A000010;
        in.owner_name_present = true;
        in.owner_name_token = 0x0A000011;
        in.is_server = false;
        const auto r = interaction_init_run(in);
        assert(word(r.image, 84) == 0x0A000011);  // the key value stays
        for (auto c : r.calls) {
            assert(c != InteractionInitCall::GetOwnerNameForObjectOwnerID);
        }
    }

    // ---- tail gate: server but ownerID nil -> no resolution ---------------
    {
        InteractionInitInputs in;
        in.is_server = true;
        in.resolved_owner_name_token = 0x0A000020;
        const auto r = interaction_init_run(in);
        assert(word(r.image, 84) == 0);
        for (auto c : r.calls) {
            assert(c != InteractionInitCall::GetOwnerNameForObjectOwnerID);
        }
    }

    // ---- nil semantics: absent keys decode as zero ------------------------
    {
        InteractionInitInputs in;
        const auto r = interaction_init_run(in);
        for (std::uint8_t b : r.image) assert(b == 0);
        assert(r.image[68] == 0 && r.image[69] == 0);
        assert(half(r.image, 88) == 0);
    }

    std::printf("test_interaction_object_init: PASS\n");
    return 0;
}
