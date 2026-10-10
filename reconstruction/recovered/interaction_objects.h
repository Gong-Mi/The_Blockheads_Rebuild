// Recovered contract: the DynamicWorld interaction-object type query and the
// shared remover pair (E39).
//
// Evidence (reverse-v3 level A; workbench_interaction.json /
// WORKBENCH_INTERACTION.md):
//   - -[DynamicWorld interactionObjectTypeForObjectAtPos:] (imp 0x008f1284):
//     the ffe23570 fetch -> the ffe23688 type read returned as a **uint16**
//     (`strh r0, [fp, -2]` @0x8f1324, `ldrh r0, [fp, -2]` @0x8f1334);
//     0 when no object (@0x8f132c-0x8f1330).
//   - The remover pair sharing ffe23690:
//       removeWorkbenchAtPos:removeBlockhead: (0x008f1354): the ffe233e0
//         check (a hit returns 0) else the ffe23690 remove call
//         (cell @0x8f1408);
//       removeInteractionObjectAtPos:removeBlockhead: (0x008f145c): the
//         ffe23570 fetch (a hit returns 0) else the ffe23690 remove call
//         (cell @0x8f1510).
//   - interactionObjectWithID:'s 9-arm lookup is modelled in family_probes
//     (E39/E56) and NOT repeated here.
//
// This module models ONLY the type-query contract (fetch -> uint16 type;
// absent -> 0) and the two remover legs (their distinct pre-checks with the
// shared ffe23690 removal return).
//
// Boundaries (do not promote beyond evidence):
//   - The type is modelled as std::uint16_t per the strh/ldrh width.
//   - "A hit returns 0" is the observed early-exit shape (the check found
//     something handled elsewhere); modelled as refusal, not success.
//   - Cells are opaque handles.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>

namespace blockheads::recovered {

inline constexpr std::int64_t kInteractionFetchCell = 0x00ffe23570;
inline constexpr std::int64_t kInteractionTypeReadCell = 0x00ffe23688;
inline constexpr std::int64_t kWorkbenchCheckCell = 0x00ffe233e0;
inline constexpr std::int64_t kSharedRemoveCell = 0x00ffe23690;

// The type query: fetch -> the 16-bit type; absent -> 0 (the initialized
// return slot at 0x8f132c-0x8f1330).
inline std::uint16_t interactionTypeForObjectAtPos(
    const std::optional<std::uint16_t>& fetchedType) {
    return fetchedType.value_or(0);
}

// The remover pair result: the shared ffe23690 removal, or nothing when the
// leg's pre-check hit (both bodies return 0 on a check hit).
struct RemoverLeg {
    std::int64_t preCheckCell = 0;
    std::int64_t removeCell = kSharedRemoveCell;
};

struct InteractionRemovers {
    RemoverLeg workbenchLeg{kWorkbenchCheckCell, kSharedRemoveCell};
    RemoverLeg interactionLeg{kInteractionFetchCell, kSharedRemoveCell};
};

// removeWorkbenchAtPos:removeBlockhead: - check hit returns nothing;
// otherwise the ffe23690 removal is executed.
inline std::optional<std::int64_t> removeWorkbenchLeg(bool checkHit) {
    if (checkHit) {
        return std::nullopt;
    }
    return kSharedRemoveCell;
}

// removeInteractionObjectAtPos:removeBlockhead: - the same shape off the
// ffe23570 fetch.
inline std::optional<std::int64_t> removeInteractionLeg(bool fetchHit) {
    if (fetchHit) {
        return std::nullopt;
    }
    return kSharedRemoveCell;
}

}  // namespace blockheads::recovered
