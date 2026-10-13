// Recovered contract: the SteamTrain's type traits (the pinned constants)
// (E74 itemType/objectType + E70 fuel cluster + E71 smalls).
//
// Evidence (reverse-v3 level A - all pinned immediates):
//   - itemType (0x00d2f8c8): returns 0xcd (205) - the same constant as the
//     addToFuelForItem: fuel gate (E70 @0xd30054).
//   - objectType (0x00d17e7c): returns 0x2a (42) - the dynamic-object type.
//   - fuelItemCount (0x00d2fda8): returns 4 (`movw r2, 4`).
//   - maxNumberOfRiders (0x00d311dc): returns 1.
//   - isEngine (0x00d3106c): returns 1.
//   - requiresFuel (0x00d304e8): returns 1.
//   - canDismissFuelUI (0x00d304cc): returns 0 (contrast the Workbench's 1
//     in E76).
//   - setTargetVelocity: (0x00d2f8ac): empty body - motion is computed.
//   - fuelUIPos (0x00d30504): Vector2(0, 4.0f) over the macro position
//     (`movw ip, 0; movt ip, 0x4080` = 0x40800000).
//
// This module models ONLY the pinned traits; behaviour that reads state
// (fuel counts, rider logic) belongs to the stateful slices.
//
// Boundaries (do not promote beyond evidence):
//   - The trait functions have no state in the listing; this module pins
//     them as constants/predicates.
//   - The title/actionTitle gates (fffffce8) are NOT modelled here.
#pragma once

#include <cstdint>

namespace blockheads::recovered {

inline constexpr std::int32_t kTrainItemType = 0xcd;    // 205
inline constexpr std::int32_t kTrainObjectType = 0x2a;  // 42
inline constexpr std::int32_t kTrainFuelItemCount = 4;
inline constexpr std::int32_t kTrainMaxRiders = 1;
inline constexpr float kTrainFuelUIOffsetY = 4.0f;  // 0x40800000

// The boolean traits (all pinned returns).
inline constexpr bool trainIsEngine() { return true; }
inline constexpr bool trainRequiresFuel() { return true; }
inline constexpr bool trainCanDismissFuelUI() { return false; }

// setTargetVelocity: is an empty body in the listing: the call is a no-op.
inline void trainSetTargetVelocity(float /*velocity*/) {}

}  // namespace blockheads::recovered
