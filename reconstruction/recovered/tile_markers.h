// Recovered contract: the tile-marker constants and predicates (E30/E38).
//
// Evidence (reverse-v3 level A; placement.json / PLACEMENT.md +
// accessor_c.json / ACCESSOR_C.md):
//   - createBackgroundContentFreeBlockAtPosition:forTile:removeBlockhead:
//     (E30 0x008df3c4) inspects the tile byte at +0xc:
//       * **0x46 ('F')** or **0x4b ('K')** open arm 1 (the ffe23578 call);
//       * **0x45 ('E')** opens arm 2 (the ffe2357c call);
//       * the byte at [r1+6] compared **> 0xaa** sets the flag passed to the
//         8-arg create (r2 = 1 when > 0xaa @0x8df4cc-0x8df4d8) - the
//         ore-threshold predicate.
//   - addDoorAtPos: (E38 0x008ed56c) writes the **0x46 marker** to
//     [tile+0xc] after the 0x34/0xa4 pre-check (the door_state slice) - the
//     same marker byte reused by a second feature.
//
// This module models ONLY the marker constants and predicates; the affected
// ffe23578/ffe2357c/ffe23410 call sites stay callbacks/out of scope.
//
// Boundaries (do not promote beyond evidence):
//   - The marker meanings (which background content each byte denotes) are
//     not resolved; only the dispatch classes are recorded.
//   - The threshold compare is strictly greater-than (> 0xaa), modelled
//     exactly; equality (0xaa) does NOT pass.
#pragma once

#include <cstdint>

namespace blockheads::recovered {

inline constexpr int kMarkerF = 0x46;  // 'F' - arm 1 / the door marker write
inline constexpr int kMarkerK = 0x4b;  // 'K' - arm 1
inline constexpr int kMarkerE = 0x45;  // 'E' - arm 2
inline constexpr int kOreThreshold = 0xaa;

// The arm predicates over the tile byte at +0xc (E30).
constexpr bool opensArm1(int tileByte) { return tileByte == kMarkerF || tileByte == kMarkerK; }
constexpr bool opensArm2(int tileByte) { return tileByte == kMarkerE; }

// The ore-threshold predicate: strictly greater than 0xaa (E30).
constexpr bool exceedsOreThreshold(int byte) { return byte > kOreThreshold; }

}  // namespace blockheads::recovered
