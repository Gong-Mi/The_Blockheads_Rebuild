// Recovered contract: the DynamicWorld family-probe patterns (E32/E34/E39/E43).
//
// Evidence (reverse-v3 level A; the family gates and tables):
//   - npcExistsAtPos:ignoreNPC: (E32 0x008f28a4): `arg >= 8` gate + the
//     0x00E4AA1C table (8 NPC family arms) + the ffffe54c 12-byte segment
//     tree walk + the pos / xPos / yPos compares under the ignoreNPC gate.
//   - npcWithID: (E34 0x008f23f4): `arg >= 8` gate + 0xE4AA1C arm ->
//     ffffe54c family slice __count_unique -> operator[](u64 const&), the
//     miss falling to the ffffe550 segment.
//   - interactionObjectWithID: (E39 0x008f1048): `arg >= 9` gate + the
//     0x00E4AA90 table (9 arms) -> the same two-registry lookup shape.
//   - treeAtPos: (E43 0x008ef618): `arg >= 0xb` gate (**11 tree classes**)
//     + the 0x00E4AA64 table - the observed body probes each family in a
//     LOOP (`add r0, r0, 1` @0x8ef6cc) via the ffe235f0 lookup until a hit
//     or exhaustion - the sequential-probe variant.
//   - checkForTrainCarUnderTap: / trainCarWithID: (E38): `arg >= 4` gate +
//     the 0x00E4AA0C table (4 arms).
//
// This module models ONLY the two probe disciplines: the INDEXED arm probe
// (gate -> table arm -> lookup, as npcWithID/interactionObjectWithID) and
// the SEQUENTIAL loop probe (treeAtPos: arms 0..N until first hit). Arm
// callbacks are caller-provided.
//
// Boundaries (do not promote beyond evidence):
//   - The table contents (which family each arm resolves) are out of scope;
//     the arm identity is opaque.
//   - The gate counts are the pinned values (8 / 9 / 11 / 4) - exposed as
//     per-family constants, not a single generic bound.
//   - The treeAtPos: loop direction (ascending arms, first hit wins) is the
//     observed listing behavior; the indexed variant resolves exactly one
//     arm and does not fall through the other arms (only the second
//     registry).
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace blockheads::recovered {

// The pinned family-gate counts (E32/E34/E39/E43/E38).
inline constexpr int kNpcArmCount = 8;           // 0x00E4AA1C
inline constexpr int kInteractionArmCount = 9;   // 0x00E4AA90
inline constexpr int kTreeArmCount = 0xb;        // 0x00E4AA64 (11)
inline constexpr int kTrainArmCount = 4;         // 0x00E4AA0C

// The indexed probe (npcWithID: / interactionObjectWithID:): the arm gate
// refuses indices outside [0, armCount); the selected arm's lookup runs; the
// miss path is the caller's second-registry lookup.
template <typename T, typename Lookup>
std::optional<T> indexedArmProbe(int armIndex, int armCount, Lookup&& armLookup) {
    if (armIndex < 0 || armIndex >= armCount) {
        return std::nullopt;
    }
    return armLookup(armIndex);
}

// The sequential probe (treeAtPos:): arms 0..armCount-1 probed in order;
// the first arm returning a value wins; exhaustion -> nothing.
template <typename T, typename Lookup>
std::optional<T> sequentialArmProbe(int armCount, Lookup&& armLookup) {
    for (int arm = 0; arm < armCount; ++arm) {
        if (std::optional<T> hit = armLookup(arm)) {
            return hit;
        }
    }
    return std::nullopt;
}

}  // namespace blockheads::recovered
