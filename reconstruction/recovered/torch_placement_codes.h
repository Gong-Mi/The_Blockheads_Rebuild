// Recovered contract: the Torch light-placement codes (the neighbour solver)
// (E72 worldContentsChanged: / lightPos).
//
// Evidence (reverse-v3 level A):
//   - worldContentsChanged: (0x004b7bd4) scans the +/-2 neighbourhood
//     (`add r0, r0, 2` / `sub r0, r0, 2` / `cmn r0, 2` @0x4b7d44-0x4b7e1c)
//     and classifies the neighbours into a code stored through the
//     ffffc8bc cell:
//       * code -2 (`mvn r0, 1` @0x4b7ec4): no valid position;
//       * code 2 (tileIsHalfDepth @0x4b7f60);
//       * code 0 (tileIsSolid at y-1 @0x4b7ffc);
//       * code 3 (tile byte +0xb == 0x64 ('d') @0x4b8048);
//       * code 1 (solid + tileContainsDoor @0x4b80f0);
//       * code -1 (`mvn r0, 0` @0x4b81b0: the x-1 solid+door arm).
//   - lightPos (0x004be0d4) selects the per-code offset via the ffffc8bc
//     cascade (code 0 @0x4be244, code 3 @0x4be2b0, code 1 @0x4be31c, the
//     rest of the -2..3 family @0x4be360+).
//
// This module models the classification ORDER and the resulting codes: the
// caller supplies the tile probes (solid / contains-door / half-depth /
// byte-at-0xb); the classify function returns the code the listing stores.
// The probe order of the listing: half-depth, then y-1 solid, then the
// 0x64 byte, then x+1 solid+door, then x-1 solid+door; a bare none yields
// -2.
//
// Boundaries (do not promote beyond evidence):
//   - The neighbourhood WALK (the +/-2 scan and the per-probe coordinates)
//     belongs to the caller here - only the ORDER + codes are modelled.
//   - The creation tail (the torch-spread call when all arms fail) is NOT
//     modelled (it is a side effect on the world, caller-side).
//   - The 0x64 byte is the pinned marker (tile +0xb).
#pragma once

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

// The pinned codes (the ffffc8bc store values).
enum class TorchPlacementCode : std::int32_t {
    kNoValidPosition = -2,   // mvn r0, 1
    kXMinusOneDoor = -1,     // mvn r0, 0 (the x-1 solid+door arm)
    kSolidBelow = 0,         // tileIsSolid at y-1
    kSolidPlusDoor = 1,      // solid + tileContainsDoor
    kHalfDepth = 2,          // tileIsHalfDepth
    kMarkerD = 3,            // tile byte +0xb == 0x64 ('d')
};

// The tile marker byte the code-3 arm checks.
inline constexpr std::uint8_t kMarkerByte = 0x64;  // 'd'

// The neighbour probe answers the caller supplies (each maps to a listing
// predicate call).
struct TorchNeighbourProbes {
    std::function<bool()> tileIsHalfDepth;    // @0x4b7f60
    std::function<bool()> yMinusOneSolid;     // tileIsSolid @0x4b7ffc
    std::function<std::uint8_t()> markerAtB;  // the tile byte +0xb
    std::function<bool()> xPlusOneSolid;      // @0x4b80f0 arm
    std::function<bool()> xPlusOneDoor;       // tileContainsDoor
    std::function<bool()> xMinusOneSolid;     // @0x4b81b0 arm
    std::function<bool()> xMinusOneDoor;      // tileContainsDoor
};

// The classification in the listing's ORDER (first hit wins): the arms are
// the store sites in address order - 2 @0x4b7f60, 0 @0x4b7ffc, 3 @0x4b8048,
// 1 @0x4b80f0, -1 @0x4b81b0, else -2 @0x4b7ec4 (the no-tile arm).
inline TorchPlacementCode classifyTorchPlacement(const TorchNeighbourProbes& p) {
    if (p.tileIsHalfDepth && p.tileIsHalfDepth()) {
        return TorchPlacementCode::kHalfDepth;
    }
    if (p.yMinusOneSolid && p.yMinusOneSolid()) {
        return TorchPlacementCode::kSolidBelow;
    }
    if (p.markerAtB && p.markerAtB() == kMarkerByte) {
        return TorchPlacementCode::kMarkerD;
    }
    if (p.xPlusOneSolid && p.xPlusOneSolid() && p.xPlusOneDoor && !p.xPlusOneDoor()) {
        return TorchPlacementCode::kSolidPlusDoor;
    }
    if (p.xMinusOneSolid && p.xMinusOneSolid() && p.xMinusOneDoor && !p.xMinusOneDoor()) {
        return TorchPlacementCode::kXMinusOneDoor;
    }
    return TorchPlacementCode::kNoValidPosition;
}

// The lightPos selector: which codes carry their own offset arm (the
// cascade reads: 0, 3, 1 and the -2..3 family); codes -2..3 are all valid
// selector inputs; the helper models only the code set.
inline bool codeHasLightArm(TorchPlacementCode code) {
    switch (code) {
        case TorchPlacementCode::kNoValidPosition:
        case TorchPlacementCode::kXMinusOneDoor:
        case TorchPlacementCode::kSolidBelow:
        case TorchPlacementCode::kSolidPlusDoor:
        case TorchPlacementCode::kHalfDepth:
        case TorchPlacementCode::kMarkerD:
            return true;
    }
    return false;
}

}  // namespace blockheads::recovered
