// Recovered semantics of -[InteractionObject initWithWorld:dynamicWorld:saveDict:cache:]
// (0x005f4634, 352 words, exact selector variant). Source of truth: the
// annotated listing reconstruction/reverse-v3/native/
// disasm_interactionobject_initwithworld.txt (emit_annotated_method.py over
// the SHA-256-pinned ELF; coverage gate OK), decoded from the execution flow
// (call sites + store widths), not from the literal-pool order.
//
// Decoded shape (call order and store widths from the instruction stream):
//   [super initWithWorld:dynamicWorld:saveDict:cache:]   (super2, four args)
//   if (result == nil) return nil
//   isInUse    objectForKey -> boolValue          -> strb  @68
//   flipped    objectForKey -> boolValue          -> strb  @69
//   ownerID    objectForKey -> retain             -> str   @36
//   ownerName  objectForKey -> retain             -> str   @84
//   paintColor objectForKey -> unsignedIntValue   -> STRH  @88 (halfword store!)
//   currentBlockheadIndex: objectForKey PROBE; only when the probe is
//       non-nil: objectForKey AGAIN -> intValue   -> str   @80
//   tail (world-dependent): if ([self->dynamicWorld isServer]) and the image's
//       ownerID@36 is non-nil:
//           ownerName@84 = retain([dynamicWorld
//               getOwnerNameForObjectOwnerID:ownerID@36])
//
// Image size: the deepest write is paintColor@88 (+2) — 96 bytes cover every
// store of this contract (stated rationale, like the NPC 160-byte image).
// This module is a contract for that slice only: the Foundation objects, the
// boxed values and the world side live outside it (the harness models them
// synthetically).
#pragma once

#include <cstdint>
#include <vector>

namespace blockheads::recovered {

inline constexpr std::size_t kInteractionImageSize = 96;
inline constexpr std::size_t kInteractionMaxTrace = 32;

enum class InteractionInitCall : int {
    SuperInit = 0,
    ObjectForKeyIsInUse,
    BoolValueIsInUse,
    ObjectForKeyFlipped,
    BoolValueFlipped,
    ObjectForKeyOwnerID,
    RetainOwnerID,
    ObjectForKeyOwnerName,
    RetainOwnerName,
    ObjectForKeyPaintColor,
    UnsignedIntValuePaintColor,
    ObjectForKeyCurrentBlockheadIndexProbe,
    ObjectForKeyCurrentBlockheadIndex,
    IntValueCurrentBlockheadIndex,
    IsServer,
    GetOwnerNameForObjectOwnerID,
    RetainResolvedOwnerName,
    Count,
};

struct InteractionInitInputs {
    std::uint32_t self_ptr = 0x60000000u;
    bool super_returns_nil = false;

    // saveDict surface. The original reads every key unconditionally except
    // currentBlockheadIndex (probe first, skip when nil) — the presence flags
    // model exactly that probe/nil surface.
    bool in_use_present = false;
    bool in_use_value = false;              // boolValue
    bool flipped_present = false;
    bool flipped_value = false;             // boolValue
    bool owner_id_present = false;
    std::uint32_t owner_id_token = 0;       // object token (retained)
    bool owner_name_present = false;
    std::uint32_t owner_name_token = 0;     // object token (retained)
    bool paint_color_present = false;
    std::uint32_t paint_color_value = 0;    // unsignedIntValue; stored STRH
    bool blockhead_index_present = false;   // the probe result
    std::int32_t blockhead_index_value = 0; // intValue on the second read

    // world side (tail).
    bool is_server = false;
    std::uint32_t resolved_owner_name_token = 0;
};

struct InteractionInitResult {
    std::vector<std::uint8_t> image;
    std::vector<InteractionInitCall> calls;
    std::uint32_t return_value = 0;
};

InteractionInitResult interaction_init_run(const InteractionInitInputs& in);

}  // namespace blockheads::recovered
