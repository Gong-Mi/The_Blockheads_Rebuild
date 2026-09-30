#include "original_world_import.h"

#include "sha256_util.h"

#include <array>
#include <cassert>

namespace bh176 {
namespace {

// The direct-only rows of original_tile_item_map.tsv
// (tools/extract_original_tile_item_map.py over the pinned ELF; the table
// also records case_target VAs — this is the same data, keyed for lookup).
// Conditional rows (nine entries inspect Tile fields or call helpers) are
// deliberately absent: no guess is made for them.
struct TileItemEntry {
    int tile_type;
    int item_type;
};

constexpr TileItemEntry kDirectTileItems[] = {
    // item_type 0 rows: the original body stores literal 0 (air / non-item).
    {25, 0}, {31, 0}, {33, 0}, {34, 0}, {35, 0}, {36, 0}, {37, 0}, {38, 0},
    {39, 0}, {40, 0}, {41, 0}, {42, 0}, {43, 0}, {44, 0}, {45, 0}, {46, 0},
    {47, 0}, {60, 0}, {61, 0}, {62, 0}, {63, 0}, {64, 0}, {65, 0}, {66, 0},
    // item_type > 0 rows: the collected/free-block item the tile yields.
    {4, 1060}, {7, 1051}, {8, 1051}, {9, 1049}, {10, 1024}, {11, 1026},
    {14, 1030}, {15, 1030}, {16, 11}, {17, 1036}, {18, 1036}, {19, 1038},
    {20, 1038}, {21, 1039}, {22, 1040}, {23, 1041}, {24, 1042}, {26, 1045},
    {29, 1054}, {30, 1054}, {32, 1057}, {48, 1062}, {49, 1062}, {50, 1062},
    {51, 1063}, {52, 1063}, {53, 1066}, {54, 1067}, {55, 1068}, {56, 1069},
    {57, 1070}, {58, 1075}, {59, 1076}, {67, 1089}, {68, 1091}, {69, 1090},
    {70, 1094}, {71, 1098}, {72, 1099}, {73, 1100}, {74, 1101}, {75, 1102},
    {76, 1103}, {77, 1105},
};

}  // namespace

int originalItemTypeForTileType(int tile_type) {
    for (const auto& entry : kDirectTileItems) {
        if (entry.tile_type == tile_type) return entry.item_type;
    }
    return -1;
}

bool importOriginalWorld(const OriginalClientWorld& original,
                         GameWorld& world,
                         WorldImportReport& report) {
    report = WorldImportReport{};

    const int max_x = static_cast<int>(GameWorld::MAX_CHUNKS_X);
    const int max_y = static_cast<int>(GameWorld::MAX_CHUNKS_Y);

    // Collect first: any chunk outside the replacement grid is a structural
    // mismatch worth failing on (the two worlds must agree on scale).
    std::vector<std::pair<int, int>> coords;
    for (int cy = 0; cy < max_y; ++cy) {
        for (int cx = 0; cx < max_x; ++cx) {
            if (original.blockAt(cx, cy) != nullptr) coords.emplace_back(cx, cy);
        }
    }
    if (coords.empty()) {
        report.error = "original block domain is empty";
        return false;
    }

    std::vector<std::unique_ptr<PhysicalBlock>> fresh;
    fresh.reserve(coords.size());
    for (const auto& [cx, cy] : coords) {
        const PhysicalBlockPayload* payload = original.blockAt(cx, cy);
        auto block = std::make_unique<PhysicalBlock>();
        block->x = cx;
        block->y = cy;
        for (std::size_t i = 0; i < kTilesPerPhysicalBlock; ++i) {
            const OriginalTile& src = payload->tiles[i];
            Tile& dst = block->tiles[i];
            const int tile_type = src.type();
            ++report.tiles_total;
            if (tile_type == 0) {
                ++report.tiles_empty;
                continue;
            }
            const int item_type = originalItemTypeForTileType(tile_type);
            if (item_type < 0) {
                ++report.tiles_unmapped;
                ++report.unmapped_by_tile_type[tile_type];
                ++report.unmapped_by_block[(cx << 16) | cy];
                continue;
            }
            if (item_type == 0) {
                // the original body stores literal 0 for these TileTypes:
                // the tile yields no item; the replacement cell stays empty
                ++report.tiles_empty;
                continue;
            }
            const int legacy = ItemManager::getInstance().fromOriginalType(item_type);
            if (legacy <= 0) {
                // direct assignment exists but the rebuild table has no
                // counterpart: counted, not coerced
                ++report.tiles_unmapped;
                ++report.unmapped_by_tile_type[tile_type];
                ++report.unmapped_by_block[(cx << 16) | cy];
                continue;
            }
            dst.foreground = static_cast<std::uint16_t>(legacy);
            ++report.tiles_mapped;
            ++report.mapped_by_legacy_id[legacy];
        }
        fresh.push_back(std::move(block));
    }

    // Register into the live grid only after every block decoded cleanly.
    for (auto& block : fresh) {
        PhysicalBlock* raw = block.get();
        world.chunkGrid[raw->x][raw->y] = raw;
        world.chunks.push_back(raw);
        world.processChunkAsync(raw);
        block.release();
        ++report.blocks_imported;
    }
    (void)max_x;
    (void)max_y;
    return true;
}

}  // namespace bh176
