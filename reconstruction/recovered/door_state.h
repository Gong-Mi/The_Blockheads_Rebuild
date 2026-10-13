// Recovered contract: the DynamicWorld door state family (E38).
//
// Evidence (reverse-v3 level A; accessor_c.json / ACCESSOR_C.md):
//   - -[DynamicWorld doorIsOpenAtPos:] (imp 0x008edb58):
//       the ffe23650 fetch (the door resolver cell) -> the ffe23658 open
//       check; true stores 1, false stores 0 into the return byte
//       (@0x8edc04-0x8edc14) - the boolean accessor.
//   - -[DynamicWorld setDoorAtPos:toOpen:direction:] (imp 0x008ef3c8):
//       the ffe2366c fetch cell -> the ffe23650 call -> the setter blx with
//       the open byte [sp,0x1f] and the sxtb'd direction (@0x8ef444-0x8ef468).
//   - -[DynamicWorld addDoorAtPos:ofType:saveDict:placedByClient:]
//     (imp 0x008ed56c, E38): after the create, the tile-state write -
//       `tileAtWorldPositionLoaded` then the tile byte at +0xc compared
//       against **0x34 ('4') and 0xa4** (@0x8ed640-0x8ed650); passing, the
//       **0x46 ('F') marker** is written (`movw r2, 0x46; strb r2, [r3,
//       0xc]` @0x8ed660-0x8ed668) and the neighbouring tile re-fetched.
//   - -[DynamicWorld doorCanBeUsedByPathUser:atPos:] (0x008ed950): the
//       ffe23654 usage fetch + the world chain + the ffe232b0 predicate.
//   - The removers (E39): removeWorkbenchAtPos: (ffe233e0 check -> ffe23690)
//       and removeInteractionObjectAtPos: (ffe23570 -> ffe23690) - the
//       ffe23690 removal shared by the door-adjacent families.
//   - doorAtPos:'s pos-then-y-1 probe is modelled in accessor_triplets
//     (E38) and NOT repeated here.
//
// This module models ONLY the door state contract: the marker-write gate
// (0x34/0xa4 -> 0x46), the open flag with its direction and the usage
// predicate boundary. World lookups are out of scope.
//
// Boundaries (do not promote beyond evidence):
//   - The fetch/check/set cells are opaque handles (pinned values).
//   - The direction domain is not resolved beyond "an sxtb'd byte".
//   - The neighbouring-tile re-fetch after the marker write is recorded as
//     a callback (`onNeighbourReread`), not modelled.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>

namespace blockheads::recovered {

// The door state cells (E38).
inline constexpr std::int64_t kDoorFetchCell = 0x00ffe23650;
inline constexpr std::int64_t kDoorOpenCheckCell = 0x00ffe23658;
inline constexpr std::int64_t kDoorSetFetchCell = 0x00ffe2366c;
inline constexpr std::int64_t kDoorUsageFetchCell = 0x00ffe23654;
inline constexpr std::int64_t kDoorUsagePredicateCell = 0x00ffe232b0;
inline constexpr std::int64_t kDoorRemovalCell = 0x00ffe23690;

// The tile marker write constants (E38 addDoorAtPos:).
inline constexpr int kDoorTileMarker = 0x46;            // 'F'
inline constexpr int kDoorMarkerAcceptedByte1 = 0x34;   // '4'
inline constexpr int kDoorMarkerAcceptedByte2 = 0xa4;

// The marker write gate: only tiles carrying 0x34 or 0xa4 are marked.
constexpr bool canWriteDoorMarker(int tileByte) {
    return tileByte == kDoorMarkerAcceptedByte1 || tileByte == kDoorMarkerAcceptedByte2;
}

struct DoorState {
    bool open = false;
    std::int8_t direction = 0;
};

class DoorStateStore {
public:
    // addDoorAtPos:'s tile-state write: gated marker write with the
    // neighbour re-read callback (the original re-fetches the tile).
    bool writeTileMarker(int tileByte, const std::function<void()>& onNeighbourReread) const {
        if (!canWriteDoorMarker(tileByte)) {
            return false;
        }
        if (onNeighbourReread) {
            onNeighbourReread();
        }
        return true;
    }

    // setDoorAtPos:toOpen:direction: (E38 0x008ef3c8) - ffe2366c fetch ->
    // the setter with the open byte and the sxtb'd direction.
    void setDoor(std::uint64_t doorKey, bool open, std::int8_t direction) {
        doors_[doorKey] = DoorState{open, direction};
    }

    // doorIsOpenAtPos: (E38 0x008edb58) - ffe23650 fetch -> ffe23658 check.
    // Missing keys read false (the check path stores 0).
    bool isOpen(std::uint64_t doorKey) const {
        const auto it = doors_.find(doorKey);
        return it != doors_.end() && it->second.open;
    }

    const DoorState* state(std::uint64_t doorKey) const {
        const auto it = doors_.find(doorKey);
        return it == doors_.end() ? nullptr : &it->second;
    }

private:
    std::unordered_map<std::uint64_t, DoorState> doors_;
};

}  // namespace blockheads::recovered
