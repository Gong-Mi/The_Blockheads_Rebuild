// Recovered model: the DynamicObject instance layout.
//
// Provenance, which matters more than the numbers: every offset here is the CONTENT of the ivar's cell in
// OBJC_IVAR_$_DynamicObject.<name>, i.e. read out of the binary's own ivar table - the same mechanism the
// getters use at run time, and the source that made `needsRemoved` at 48 agree with the executed getter.
// The Python contract test re-reads the symbol table and requires an exact match, so this cannot drift.
//
// Two observations the layout itself carries:
//   * offsets 4..40 are the object's identity and geometry (world, dynamicWorld, macroTileOwner, pos,
//     floatPos, cache, ownerID, uniqueID);
//   * offsets 48..52 are five adjacent ONE-BYTE flags (see dynamic_object_flags.h) - the flag cluster sits
//     right after the identity fields, which is why every accessor in this family is a one-byte `ldrsb`.
//
// Deliberately NOT claimed here: the TYPE of the pointer-ish fields. The symbol table gives names and
// offsets, not types, and guessing `world` is a World* would be inference rather than evidence.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered::dynamic_object {

inline constexpr std::size_t kOffsetWorld = 4;
inline constexpr std::size_t kOffsetDynamicWorld = 8;
inline constexpr std::size_t kOffsetMacroTileOwner = 12;
inline constexpr std::size_t kOffsetPos = 16;
inline constexpr std::size_t kOffsetFloatPos = 24;
inline constexpr std::size_t kOffsetCache = 32;
inline constexpr std::size_t kOffsetOwnerID = 36;
inline constexpr std::size_t kOffsetUniqueID = 40;
inline constexpr std::size_t kOffsetNeedsRemoved = 48;  // one-byte flag
inline constexpr std::size_t kOffsetUpdateNeedsToBeSent = 49;  // one-byte flag
inline constexpr std::size_t kOffsetCreationDataNeedsToBeSent = 50;  // one-byte flag
inline constexpr std::size_t kOffsetUnreliableUpdateNeedsToBeSent = 51;  // one-byte flag
inline constexpr std::size_t kOffsetIsNet = 52;  // one-byte flag

// the ivar cells these offsets live in, for comparing against the binary
inline constexpr std::uint32_t kCellWorld = 0x00f33e24;
inline constexpr std::uint32_t kCellDynamicWorld = 0x00f33e30;
inline constexpr std::uint32_t kCellMacroTileOwner = 0x00f33e2c;
inline constexpr std::uint32_t kCellPos = 0x00f33e28;
inline constexpr std::uint32_t kCellFloatPos = 0x00f33e3c;
inline constexpr std::uint32_t kCellCache = 0x00f33e34;
inline constexpr std::uint32_t kCellOwnerID = 0x00f33e54;
inline constexpr std::uint32_t kCellUniqueID = 0x00f33e38;
inline constexpr std::uint32_t kCellNeedsRemoved = 0x00f33e44;
inline constexpr std::uint32_t kCellUpdateNeedsToBeSent = 0x00f33e48;
inline constexpr std::uint32_t kCellCreationDataNeedsToBeSent = 0x00f33e4c;
inline constexpr std::uint32_t kCellUnreliableUpdateNeedsToBeSent = 0x00f33e50;
inline constexpr std::uint32_t kCellIsNet = 0x00f33e40;

static_assert(kOffsetNeedsRemoved == 48);
static_assert(kOffsetIsNet == 52);
// the flag cluster starts after the identity block and is one byte per flag
static_assert(kOffsetNeedsRemoved - kOffsetUniqueID >= 4);

}  // namespace blockheads::recovered::dynamic_object
