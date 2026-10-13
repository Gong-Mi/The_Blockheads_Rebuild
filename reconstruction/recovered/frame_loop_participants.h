// Recovered model: the frame-loop protocol participants.
//
// `-update:accurateDT:isSimulation:` is implemented by 52 classes in the original and ALL of them use the
// same signature `v20@0:4f8f12c16` - one uniform protocol, not a set of
// lookalikes (see FRAME_LOOP_PROTOCOL.md, which re-derives this list and would fail if a participant
// appeared or vanished). A reimplementation's simulation step should therefore visit exactly these
// object types, and nothing else should claim the protocol.
//
// Evidence grade: static and exact - the list comes from the method table, so it is complete for this
// pinned build. The per-class INTERPRETATION is not uniform (a Tree and an Egg do different things with
// the same signature); only membership is asserted here.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace blockheads::recovered {

inline constexpr std::string_view kFrameLoopSelector = "update:accurateDT:isSimulation:";
inline constexpr std::string_view kFrameLoopSignature = "v20@0:4f8f12c16";

inline constexpr std::array<std::string_view, 52> kFrameLoopParticipants = {{
    "AppleTree",
    "Bed",
    "Blockhead",
    "Boat",
    "CactusTree",
    "CaveTroll",
    "CherryTree",
    "Chest",
    "ClownFish",
    "CoconutTree",
    "CoffeeTree",
    "Column",
    "Dodo",
    "DonkeyLike",
    "DropBear",
    "DynamicObject",
    "DynamicWorld",
    "Egg",
    "ElevatorMotor",
    "FireObject",
    "FishingRod",
    "FreeBlock",
    "FreightCar",
    "GatherBlock",
    "GemTree",
    "HandCar",
    "InteractionObject",
    "KelpPlant",
    "LimeTree",
    "MangoTree",
    "MapleTree",
    "Mirror",
    "NPC",
    "NormalPlant",
    "OrangeTree",
    "PassengerCar",
    "PineTree",
    "Plant",
    "Scorpion",
    "Shark",
    "Sign",
    "SnowSurfaceBlock",
    "Stairs",
    "SteamTrain",
    "SurfaceBlock",
    "TradingPost",
    "TrainCar",
    "Tree",
    "TulipPlant",
    "VinePlant",
    "Workbench",
    "Yak",
}};

static_assert(kFrameLoopParticipants.size() == 52);

// sorted, so membership can be tested with a binary search and a duplicate shows up as a failed assert
constexpr bool participantsAreSorted() {
    for (std::size_t i = 1; i < kFrameLoopParticipants.size(); ++i)
        if (!(kFrameLoopParticipants[i - 1] < kFrameLoopParticipants[i])) return false;
    return true;
}
static_assert(participantsAreSorted(), "participant list must be sorted and duplicate-free");

inline constexpr bool isFrameLoopParticipant(std::string_view name) {
    std::size_t lo = 0, hi = kFrameLoopParticipants.size();
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        if (kFrameLoopParticipants[mid] == name) return true;
        if (kFrameLoopParticipants[mid] < name) lo = mid + 1; else hi = mid;
    }
    return false;
}

}  // namespace blockheads::recovered
