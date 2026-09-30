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
// Back wall (Tile[1]) and contents (Tile[3]) are NOT mapped yet: the
// replacement Tile has single background/paint fields with different
// semantics, and no A-grade per-value mapping exists in-repo for them.
// They are counted in the report so the gap is visible, not silent.

#include <cstdint>
#include <memory>
#include <vector>
#include <map>
#include <string>

#include "game_world.h"
#include "item_manager.h"
#include "original_client_world.h"

namespace bh176 {

struct WorldImportReport {
    std::size_t blocks_imported = 0;
    std::size_t tiles_total = 0;
    std::size_t tiles_mapped = 0;         // direct-assignment TileType hit
    std::size_t tiles_empty = 0;          // original type 0 (air)
    std::size_t tiles_unmapped = 0;       // type present, no direct mapping
    std::map<int, std::size_t> mapped_by_legacy_id;   // compatibility id -> tiles
    std::map<int, std::size_t> unmapped_by_tile_type; // original TileType -> tiles
    std::map<int, std::size_t> unmapped_by_block;     // (x<<16)|y -> count
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

}  // namespace bh176

#endif
