#ifndef ORIGINAL_WORLD_IMPORT_H
#define ORIGINAL_WORLD_IMPORT_H

// The world-data-source bridge, layer 1: import a decoded original block
// domain into the replacement GameWorld.
//
// Mapping discipline:
//   * Tile[0] is the ORIGINAL TileType (1..77 jump table). Only the direct,
//     A-grade tile->item assignments from tools/extract_original_tile_item_map.py
//     (original_tile_item_map.tsv, client ItemType domain) are converted into
//     the replacement's compatibility id via ItemManager::fromOriginalType.
//   * Tile types WITHOUT a direct assignment stay empty and are COUNTED.
//     Nothing is inferred from tile numbers, names or atlas guesses.
//   * Import is one-way into fresh chunks: it never mutates the stored
//     original domain (that domain stays the evidence copy).
//
// Back wall (Tile[1]) is NOT mapped yet: the replacement Tile has a single
// background field with different semantics, and no A-grade per-value mapping
// exists in-repo for it.  Contents (Tile[3]) IS resolvable for the nine
// conditional TileTypes: tools/extract_original_tile_conditional.py walks the
// original chains of `itemTypeFromTileIsForegorund()` and shows they compare
// OriginalTile.contentsType() against item types before returning.  Steps that
// sit behind a helper call, or behind an assignment this map cannot follow, are
// counted as unresolved instead of guessed.

#include <cstdint>
#include <memory>
#include <vector>
#include <map>
#include <string>

#include "game_world.h"
#include "item_manager.h"
#include "original_client_world.h"

namespace bh176 {

// How a TileType's ItemType was (or was not) obtained.
enum class TileMappingKind {
    Direct,                 // Tile[0] has a direct assignment in the original switch
    ConditionalContents,    // conditional case resolved by OriginalTile.contentsType()
    ConditionalHelper,      // conditional case behind a helper call this map does not model
    ConditionalUnresolved,  // conditional case whose tail cannot be followed
    NoMapping,              // no assignment for this TileType
};

struct TileMappingResult {
    int item_type = -1;
    TileMappingKind kind = TileMappingKind::NoMapping;
};

struct WorldImportReport {
    std::size_t blocks_imported = 0;
    std::size_t tiles_total = 0;
    std::size_t tiles_mapped = 0;         // direct-assignment TileType hit
    std::size_t tiles_empty = 0;          // original type 0 (air) / literal-0 item
    std::size_t tiles_unmapped = 0;       // type present, no usable mapping
    std::size_t tiles_conditional_mapped = 0;  // resolved through contentsType()
    std::map<int, std::size_t> mapped_by_legacy_id;   // compatibility id -> tiles
    std::map<int, std::size_t> unmapped_by_tile_type; // original TileType -> tiles
    std::map<int, std::size_t> unmapped_by_block;     // (x<<16)|y -> count
    std::map<std::string, std::size_t> unmapped_by_reason;  // reason -> tiles
    std::string error;
};

// Imports every decoded original block into fresh replacement chunks and
// registers them in `world`. Player/entity state is NOT touched: this is the
// terrain layer only. Returns false with report.error on any structural
// problem; per-tile unknowns are counted, never fatal.
bool importOriginalWorld(const OriginalClientWorld& original,
                         GameWorld& world,
                         WorldImportReport& report);

// TileType (client domain) -> original ItemType for the direct assignments,
// or -1. Shared with the loader so the mapping lives in exactly one place.
int originalItemTypeForTileType(int tile_type);

// Full mapping for one decoded original tile: direct assignment first, then the
// conditional contentsType() chain. Never invents a value: a chain step that
// needs an unmapped helper reports ConditionalHelper.
TileMappingResult mapOriginalTile(const OriginalTile& tile);

}  // namespace bh176

#endif
