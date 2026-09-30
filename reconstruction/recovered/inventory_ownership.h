#pragma once
#include <cstdint>
namespace blockheads::recovered::ownership {
// Fixed Android 1.7.6 ItemType domain; not the replacement Player IDs.
// Local descriptive name for the unnamed direct callee at 0x5deeb8.
std::int32_t workbenchKindForItemType(std::int32_t type);
std::int8_t itemTypeIsWorkbench(std::int32_t type);
std::int8_t itemTypeIsTorch(std::int32_t type);
std::int8_t itemTypeIsStairs(std::int32_t type);
std::int8_t itemTypeIsColumn(std::int32_t type);
std::int8_t itemTypeIsPainting(std::int32_t type);
std::int8_t itemTypeRequiresOwnershipToRemove(std::int32_t type);
}
