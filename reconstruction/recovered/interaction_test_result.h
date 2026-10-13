// Recovered model: the InteractionTestResult record - a 12-byte value passed BY VALUE between Action and
// Blockhead.
//
// The evidence is a set of independent confirmations that happen to agree, which is what makes this one of
// the better-established structures in the binary:
//
//   * the type encoding {InteractionTestResult=iiSS} sums to 12 bytes (iiSS = 4+4+2+2);
//   * Action -[setInteractionTestResult:] declares v20@0:4{...}8 - a by-value argument at offset 8 with a
//     20-byte frame, i.e. 8 + 12;
//   * Blockhead -[goodOrBadInteractionForAction:] RETURNS the same struct with a 12-byte frame;
//   * the save read-back in Action -[initWithSaveDict:inventoryItems:] uses getBytes:length: 12 at 0x00735be8;
//   * the host is named by the symbol table: OBJC_IVAR_$_Action.interactionTestResult, cell 0xf33648,
//     ivar offset 52 - which also matches that 12-byte read.
//
// The field OFFSETS come from the encoding, and tools/test_interaction_test_result.py re-parses it from the
// method table and re-checks the two argument frames, so this header cannot drift from the binary.
//
// Field meanings are NOT claimed: four positional fields. The two `S` fields tail the record and the getter
// Action -[interactionTestResult] returns the whole thing, so a caller reads them together - but that is a
// reading, not evidence about what they hold.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered {

struct InteractionTestResult {
    std::int32_t f0;  // +0
    std::int32_t f1;  // +4
    std::uint16_t f2;  // +8
    std::uint16_t f3;  // +10
};

static_assert(sizeof(InteractionTestResult) == 12, "the encoding sums to 12 bytes");
static_assert(offsetof(InteractionTestResult, f0) == 0, "field f0");
static_assert(offsetof(InteractionTestResult, f1) == 4, "field f1");
static_assert(offsetof(InteractionTestResult, f2) == 8, "field f2");
static_assert(offsetof(InteractionTestResult, f3) == 10, "field f3");

inline constexpr std::size_t kInteractionTestResultActionIvarOffset = 52;
inline constexpr std::uint32_t kInteractionTestResultActionIvarCell = 0x00f33648U;

}  // namespace blockheads::recovered
