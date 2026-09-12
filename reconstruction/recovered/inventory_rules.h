#pragma once
#include <cstdint>

namespace blockheads::recovered {
// Original Android 1.7.6 ItemType numeric domain; NOT replacement game_item_ids.h.
std::int8_t itemTypeIsValidFillItem(std::int32_t type);
std::int8_t itemTypeIsValidInventoryItem(std::int32_t type);
std::int8_t itemTypeIsLiquid(std::int32_t type);
std::int8_t itemTypeCarriesLiquids(std::int32_t type);
std::int8_t itemTypeSubItemsCanBeModifiedWhileCarried(std::int32_t type);
std::int8_t itemTypeCanBeColored(std::int32_t type);
// These are the two values compared by the helper. Their caller-specific
// meaning must be established at each call, not inferred as dataA/dataB.
std::int8_t itemTypeIsStackable(std::int32_t type, std::uint16_t first, std::uint16_t second);
// Preserve the original integer/byte ABI without assigning guessed flag names.
std::int32_t usageIncrementPerUse(std::int32_t type, std::int32_t mode,
                                  std::int8_t flag2, std::int8_t flag3);
}
