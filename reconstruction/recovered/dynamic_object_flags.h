// Recovered model: the DynamicObject one-byte flag cluster at offsets 48..52.
//
// Evidence (see reconstruction/reverse-v3/native/DYNAMICOBJECT_FLAGS.md and
// IVAR_ACCESS_CLASSIFIER_FIX.md):
//   * every offset here is DERIVED from the getter's own literal pool and cross-checked against the
//     symbol table, which names each flag and stores the same offset in its ivar cell;
//   * `needsRemoved` (48) is EXECUTED under Unicorn - the char getter returns 0/1/127/-128/-1 for the
//     planted encodings, with cell-rewrite negative controls - and it is the gate the update loop calls;
//   * the three "…NeedsToBeSent" flags are SET as `mov rN,#1 ; strb rN,[self,offset]` at 22 verified
//     sites across TradingPost/Sign/Stairs/Chest/Bed/Ladder/FreeBlock/Door and friends - one dirty bit,
//     set by every "something changed" path, which is what makes them network-dirty flags;
//   * `isNet` (52) is READ by NPC/FireObject/Blockhead but no writer was found through the cell idiom,
//     so how an object becomes networked is explicitly NOT modelled here.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered {

// Byte offsets inside DynamicObject. Five adjacent one-byte flags, which is why this family's accessors
// all share the `ldrsb` body.
inline constexpr std::size_t kOffsetNeedsRemoved = 48;
inline constexpr std::size_t kOffsetUpdateNeedsToBeSent = 49;
inline constexpr std::size_t kOffsetCreationDataNeedsToBeSent = 50;
inline constexpr std::size_t kOffsetUnreliableUpdateNeedsToBeSent = 51;
inline constexpr std::size_t kOffsetIsNet = 52;

static_assert(kOffsetUpdateNeedsToBeSent == kOffsetNeedsRemoved + 1);
static_assert(kOffsetIsNet == kOffsetNeedsRemoved + 4);

// A byte flag is "set" when it is non-zero. The original returns a signed char and its callers test it
// for truth, so a negative encoding is still set - that is why this is != 0 and not == 1.
inline bool flagIsSet(std::uint8_t raw) { return raw != 0; }

// What the verified setters do: `mov rN,#1 ; strb rN,[self,offset]`.
inline std::uint8_t setFlag() { return 1u; }

// The update loop calls -[DynamicObject needsRemoved] and keeps iterating while it is false; a stubbed
// zero made the traced loop run forever, which is how this gate was identified.
inline bool leavesUpdateLoop(std::uint8_t needsRemovedRaw) { return flagIsSet(needsRemovedRaw); }

}  // namespace blockheads::recovered
