// Recovered model: the Action layout (16 ivars, offsets 4..68).
//
// Action is the crafting interaction's state holder, and this table also closes a loop with the other records
// this project modelled: Action.interactionTestResult at offset 52 is the host of the 12-byte
// InteractionTestResult record, whose size is confirmed four independent ways in interaction_test_result.h. The
// static_assert below ties the two models together, so they cannot disagree about where that record lives.
//
// The ivar names are the binary's own (offline the artifacts of earlier batches used them as key mappings:
// inProgress, interactionItem, interactionItemIndex, craftCountOrExtraData, goalInteraction, goalTilePos).
//
// Rows are (offset, name, ivar cell) read out of OBJC_IVAR_$_Action.*; the Python test re-reads the table and
// requires an exact match.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace blockheads::recovered::action_layout {

struct Field {
    std::size_t offset;
    std::string_view name;
    std::uint32_t cell;
};

inline constexpr std::array<Field, 16> kActionFields = {{
    {4, "inProgress", 0x00f33640U},
    {5, "complete", 0x00f33650U},
    {6, "isAI", 0x00f33638U},
    {8, "goalTilePos", 0x00f33614U},
    {16, "interactionItem", 0x00f33620U},
    {20, "interactionItemIndex", 0x00f33624U},
    {22, "interactionItemSubIndex", 0x00f33628U},
    {24, "goalInteraction", 0x00f33618U},
    {28, "pathType", 0x00f3361cU},
    {32, "interactionObjectID", 0x00f3362cU},
    {40, "craftableItemObject", 0x00f33630U},
    {44, "craftCountOrExtraData", 0x00f33634U},
    {48, "blockCube", 0x00f3364cU},
    {52, "interactionTestResult", 0x00f33648U},
    {64, "inventoryChange", 0x00f3363cU},
    {68, "animationTimer", 0x00f33644U},
}};

constexpr bool offsetsRise() {
    for (std::size_t i = 1; i < kActionFields.size(); ++i)
        if (kActionFields[i - 1].offset >= kActionFields[i].offset) return false;
    return true;
}
static_assert(offsetsRise(), "the ivar table must be ordered and duplicate-free");

constexpr std::size_t offsetOf(std::string_view want) {
    for (const Field& f : kActionFields)
        if (f.name == want) return f.offset;
    return static_cast<std::size_t>(-1);
}

// the host of the InteractionTestResult record, matching interaction_test_result.h
static_assert(offsetOf("interactionTestResult") == 52);
static_assert(offsetOf("inProgress") == 4);

}  // namespace blockheads::recovered::action_layout
