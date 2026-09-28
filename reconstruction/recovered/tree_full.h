// Full Tree-family loader (bucket A, trees): turns a real save record
// (AppleTree 1 / PineTree 4 / OrangeTree 7 in reverse-probe-001) into a
// populated ClientDynamicObject using the recovered Tree chain, with the
// evidence level of each field stated explicitly.
//
// Original chain:
//   DynamicObject initWithWorld:dynamicWorld:saveDict:cache: (base)  [executed]
//   Tree loadSaveDictValues: (0x004c2df0, 748 words)
//     stage 1 (executed differential, b4d, 5/5 cases):
//       treeSeasonOffset@84 int/word, dead@104 bool/byte, timeDied@112
//       double/64-bit, removeCheckCount@120 float, treeFruit (fruitCount@128
//       reset, empty-array enumeration), height@60 int/word (ALWAYS-ON),
//       age@96 float (ALWAYS-ON), then the isStaticTree gate
//     gene/growth block (static decode b3a; ivar offsets and key order
//       pinned from the instruction stream, NOT yet an executed
//       differential): maxHeightReached@64 int/word, growthRateGene@56
//       int/strh, maxHeightGene@54 int/strh, maxHeight@88 float,
//       growthRate@72 float, growthCounter@68 float, maxAge@92 float.
//       The block is gated by [self isStaticTree]; a loaded tree record in
//       this snapshot is a real tree (not static), so the block runs.
//   AppleTree own step (ownkey5, static): availableFood floatValue -> @136
//   PineTree own step (ownkey5, static): availableFood floatValue -> @136
//   (OrangeTree carries no own key — its record has no availableFood and
//    the ownkey5 table has no OrangeTree program.)
//   saveTime is write-only for trees (b3a negative scan: no saveTime
//   CFString in the load body) — unlike the Plant chain there is no gate.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"
#include "tree_load_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

// Recovered Tree ivar offsets (b3a/b4d evidence).
inline constexpr std::uint32_t kTreeIvarSeasonOffset = 84;
inline constexpr std::uint32_t kTreeIvarDead = 104;
inline constexpr std::uint32_t kTreeIvarTimeDied = 112;
inline constexpr std::uint32_t kTreeIvarRemoveCheckCount = 120;
inline constexpr std::uint32_t kTreeIvarHeight = 60;
inline constexpr std::uint32_t kTreeIvarAge = 96;
inline constexpr std::uint32_t kTreeIvarFruitCount = 128;
inline constexpr std::uint32_t kTreeIvarMaxHeightReached = 64;
inline constexpr std::uint32_t kTreeIvarGrowthRateGene = 56;
inline constexpr std::uint32_t kTreeIvarMaxHeightGene = 54;
inline constexpr std::uint32_t kTreeIvarMaxHeight = 88;
inline constexpr std::uint32_t kTreeIvarGrowthRate = 72;
inline constexpr std::uint32_t kTreeIvarGrowthCounter = 68;
inline constexpr std::uint32_t kTreeIvarMaxAge = 92;
// AppleTree/PineTree own ivar (TREE_SAVEDICT_KEYS, static level-A)
inline constexpr std::uint32_t kFruitTreeIvarAvailableFood = 136;

struct TreeFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // stage 1 (executed)
    std::int32_t tree_season_offset = 0;
    bool dead = false;
    double time_died = 0.0;
    float remove_check_count = 0.0f;
    std::int32_t height = 0;
    float age = 0.0f;
    std::int32_t fruit_count = 0;      // enumeration count of treeFruit
    bool static_gate_fired = false;    // isStaticTree == true
    // gene/growth block (static decode; loaded for non-static trees)
    std::int32_t max_height_reached = 0;
    std::uint16_t growth_rate_gene = 0;
    std::uint16_t max_height_gene = 0;
    float max_height = 0.0f;
    float growth_rate = 0.0f;
    float growth_counter = 0.0f;
    float max_age = 0.0f;
    // AppleTree/PineTree own key (b3b read-back, static): availableFood
    // floatValue -> @136. Presence-gated.
    bool has_available_food = false;
    float available_food = 0.0f;
    // CactusTree own keys (b3b read-back, static; read order: super then own):
    // splitHeightA@136 word, splitHeightB@140 word, splitDirection@144 byte,
    // availableFood@148 float (the same key name as the fruit trees but a
    // DIFFERENT ivar offset on this class).
    bool has_cactus_own = false;
    std::int32_t split_height_a = 0;
    std::int32_t split_height_b = 0;
    bool split_direction = false;
    float cactus_available_food = 0.0f;
    // GemTree own keys (b3b read-back, static; read order: own then super):
    // gemTreeType@136 word, fruitYear@140 word.
    bool has_gem_own = false;
    std::int32_t gem_tree_type = 0;
    std::int32_t fruit_year = 0;
};

// Reads ONE dynamic-object entry dictionary through the Tree chain.
// is_static_tree models [self isStaticTree]; real loaded trees are false.
// type_id selects the per-class own-key block (5 CactusTree, 57 GemTree,
// 1/4 fruit trees); 0 keeps the generic presence-gated behaviour the unit
// tests use. Unknown keys are ignored, never invented; a missing key
// decodes as nil.
TreeFullState tree_full_load(const SaveDict& entry, bool is_static_tree,
                             int type_id = 0);

// The registry factory for the tree family (AppleTree 1 / PineTree 4 /
// OrangeTree 7). The stage-1 keys are an executed contract; the gene/growth
// block is a static decode — the reason string states both levels.
ClientDynamicObject tree_full_factory(int type_id, const SaveDict& entry,
                                      TreeFullState* out_state,
                                      std::string* error);

}  // namespace bh176
