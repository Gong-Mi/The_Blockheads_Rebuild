// Recovered model: DynamicObjectNetData, the 24-byte header a whole family of network records starts with.
//
// The family is visible only because the type encodings NEST: TrainCarCreationNetData, NPCCreationNetData,
// PlantCreationNetData and NPCUpdateNetData all embed this header at offset 0 and then add their own fields.
// The layout below is parsed from the encoding {DynamicObjectNetData=QIIC[7C]}
// by tools/extract_struct_census.py - the same single parser the census uses, so there is no second copy of
// the rule to drift.
//
// Sizes of the family, also from the census:
//
// Field NAMES are not claimed: a 64-bit value, two 32-bit values, a byte and seven bytes. What is claimed is
// the shape every member of the family shares.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered {

// family sizes, from the same census the layout above comes from
inline constexpr std::size_t kDynamicObjectNetDataSize = 24;
inline constexpr std::size_t kInteractionObjectCreationNetDataSize = 40;
inline constexpr std::size_t kNPCCreationNetDataSize = 72;
inline constexpr std::size_t kNPCUpdateNetDataSize = 24;
inline constexpr std::size_t kPlantCreationNetDataSize = 40;
inline constexpr std::size_t kTrainCarCreationNetDataSize = 104;

struct DynamicObjectNetData {
    std::uint64_t f0;  // +0
    std::uint32_t f1;  // +8
    std::uint32_t f2;  // +12
    std::uint8_t f3;  // +16
    std::uint8_t f4[7];  // +17
};

static_assert(sizeof(DynamicObjectNetData) == 24, "the encoding gives 24 bytes");
static_assert(offsetof(DynamicObjectNetData, f0) == 0);
static_assert(offsetof(DynamicObjectNetData, f1) == 8);
static_assert(offsetof(DynamicObjectNetData, f2) == 12);
static_assert(offsetof(DynamicObjectNetData, f3) == 16);
static_assert(offsetof(DynamicObjectNetData, f4) == 17);

}  // namespace blockheads::recovered