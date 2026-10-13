// World-data-source bridge test: decoded original block domain ->
// replacement GameWorld. Host-only; real decode + real import + real ItemManager.
#ifdef NDEBUG
#error assertions must remain enabled
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "item_manager.h"
#include "original_save_format.h"
#include "original_world_import.h"
#include "sha256_util.h"
#include "../../reconstruction/recovered/original_client_world.h"

namespace {

void writeText(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path);
    out << text;
    assert(out.good());
}

// A physical block whose tiles are written per-cell by the caller.
std::string blockPayload(const std::string& sha,
                         void (*fill)(bh176::PhysicalBlockPayload&)) {
    (void)sha;
    bh176::PhysicalBlockPayload payload;
    fill(payload);
    return std::string(reinterpret_cast<const char*>(payload.tiles.data()),
                       bh176::kTileBytesPerPhysicalBlock) +
           std::string(1, static_cast<char>(0)) +
           std::string("\x00\x00\x00\x00", 4);
}

std::string hex(const std::string& raw) { return bh176::sha256Hex(raw); }

}  // namespace

int main() {
    namespace fs = std::filesystem;

    // ---- assemble a two-block snapshot through the real index grammar ------
    fs::path root = fs::temp_directory_path() / "bh-world-import-test";
    fs::remove_all(root);
    fs::create_directories(root / "blocks");

    // block (0,0): stone(1024 legacy 2) surface, conditional dirt, one
    // unmapped conditional type — Dirt 1048 has NO direct tile row (tile 6
    // is the conditional world-dependent case), so it must count as unmapped.
    auto fill0 = [](bh176::PhysicalBlockPayload& p) {
        p.tiles[0].raw[0] = 10;  // direct -> item 1024 (Stone, legacy 2)
        p.tiles[1].raw[0] = 6;   // conditional row -> unmapped (no guess)
        p.tiles[2].raw[0] = 12;  // NO direct row (conditional case) -> unmapped
        p.tiles[3].raw[0] = 0;   // air
        p.tiles[4].raw[0] = 25;  // direct row with item_type 0 -> stays empty
    };
    // block (1,0): one mapped tile at local (1,0) -> tiles[1]; world (33,0)
    auto fill1 = [](bh176::PhysicalBlockPayload& p) {
        p.tiles[1].raw[0] = 4;  // direct -> item 1060 (Ice, legacy 13)
    };
    const std::string raw0 = blockPayload("0", fill0);
    const std::string raw1 = blockPayload("1", fill1);
    writeText(root / "blocks/0_0.raw", raw0);
    writeText(root / "blocks/1_0.raw", raw1);
    writeText(root / "blocks/index.tsv",
              "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
              "305f30\t0\t0\tblocks/0_0.raw\t" + hex(raw0) + "\t" +
                  std::to_string(raw0.size()) + "\n"
              "315f30\t1\t0\tblocks/1_0.raw\t" + hex(raw1) + "\t" +
                  std::to_string(raw1.size()) + "\n");

    bh176::OriginalClientWorld original;
    std::string error;
    assert(original.load(root, &error));
    assert(error.empty());
    assert(original.blockCount() == 2);

    // ---- import into a stopped-worker replacement world --------------------
    GameWorld world;
    world.stopThread = true;
    world.queueCV.notify_all();
    world.workerThread.join();

    bh176::WorldImportReport report;
    assert(bh176::importOriginalWorld(original, world, report));
    assert(report.blocks_imported == 2);
    assert(report.tiles_total == 2 * bh176::kTilesPerPhysicalBlock);
    assert(world.chunks.size() == 2);
    assert(world.chunkGrid[0][0] != nullptr && world.chunkGrid[1][0] != nullptr);

    // stone + ice mapped directly; tile 6 resolves through its contentsType()
    // chain fallback (1048 -> dirt); conditional 12 resolves to 1028, which has
    // no rebuild counterpart and stays counted; the item-0 direct row stays
    // empty WITHOUT counting as unmapped.
    if (report.tiles_mapped != 3) {
        std::cerr << "mapped=" << report.tiles_mapped
                  << " unmapped=" << report.tiles_unmapped
                  << " empty=" << report.tiles_empty << "\n";
        for (const auto& [tt, n] : report.unmapped_by_tile_type)
            std::cerr << "  unmapped tile " << tt << " x" << n << "\n";
        for (const auto& [id, n] : report.mapped_by_legacy_id)
            std::cerr << "  legacy " << id << " x" << n << "\n";
    }
    assert(report.tiles_mapped == 3);
    assert(report.tiles_conditional_mapped == 1);  // tile 6 via 1048 fallback
    assert(report.tiles_unmapped == 1);
    assert(report.unmapped_by_tile_type.at(12) == 1);
    assert(report.unmapped_by_reason.at("no_compat_id") == 1);
    assert(world.getTile(0, 0)->foreground == ITEM_STONE);
    assert(world.getTile(1, 0)->foreground == ITEM_DIRT);   // conditional 6 fallback
    assert(world.getTile(2, 0)->foreground == ITEM_EMPTY);  // 1028 has no compat id
    assert(world.getTile(3, 0)->foreground == ITEM_EMPTY);  // air
    assert(world.getTile(4, 0)->foreground == ITEM_EMPTY);  // direct item 0
    assert(world.getTile(1 * 32 + 1, 0)->foreground == 13); // Ice legacy id

    // the mesh pipeline ran on the imported chunks (worker stopped, so the
    // synchronous processChunkAsync path built them)
    assert(world.chunkGrid[0][0]->meshReady);
    assert(!world.chunkGrid[0][0]->vertexCache.empty());

    // ---- conditional contentsType() chains (mapOriginalTile) ---------------
    auto tile_with = [](int type, int contents) {
        bh176::OriginalTile tile;
        tile.raw[0] = static_cast<std::uint8_t>(type);
        tile.raw[3] = static_cast<std::uint8_t>(contents);
        return tile;
    };
    // tile 2 chain: the first contents compare is 96 -> item 178
    assert(bh176::mapOriginalTile(tile_with(2, 96)).item_type == 178);
    assert(bh176::mapOriginalTile(tile_with(2, 96)).kind ==
           bh176::TileMappingKind::ConditionalContents);
    // tile 1 chain: contents 61 -> 31
    assert(bh176::mapOriginalTile(tile_with(1, 61)).item_type == 31);
    // tile 12: contents 64 -> 48, every other contents takes the 1028 fallback
    assert(bh176::mapOriginalTile(tile_with(12, 64)).item_type == 48);
    assert(bh176::mapOriginalTile(tile_with(12, 0)).item_type == 1028);
    // tile 6: contents 1 -> 3, contents 2 -> 28, otherwise the 1048 fallback
    assert(bh176::mapOriginalTile(tile_with(6, 1)).item_type == 3);
    assert(bh176::mapOriginalTile(tile_with(6, 2)).item_type == 28);
    assert(bh176::mapOriginalTile(tile_with(6, 7)).item_type == 1048);
    // the tail of the tiles 2/3/5 chain (contents 101) sits BEHIND the helper
    // gate, so it reports helper-gated rather than a tail this map could follow
    assert(bh176::mapOriginalTile(tile_with(2, 101)).kind ==
           bh176::TileMappingKind::ConditionalHelper);
    // tiles 2/3/5 reach a helper gate BEFORE their later compares: the chain is
    // ordered, so contents 12 (matched after the gate) must NOT be applied
    const auto gated = bh176::mapOriginalTile(tile_with(2, 12));
    assert(gated.kind == bh176::TileMappingKind::ConditionalHelper);
    assert(gated.item_type == -1);

    // ---- idempotence at the mapping-table level -----------------------------
    // every direct row in the table resolves through one lookup, and the
    // count of rows matches the committed TSV (44 yield items, 24 store 0)
    int positive = 0, zero = 0;
    for (int t = 0; t <= 77; ++t) {
        const int item = bh176::originalItemTypeForTileType(t);
        if (item > 0) ++positive;
        else if (item == 0) ++zero;
    }
    assert(positive == 44 && zero == 24);

    // fromOriginalType refuses the original-only ids, maps the real ones
    assert(ItemManager::getInstance().fromOriginalType(1024) == ITEM_STONE);
    assert(ItemManager::getInstance().fromOriginalType(1048) == ITEM_DIRT);
    assert(ItemManager::getInstance().fromOriginalType(1060) == 13);

    fs::remove_all(root);
    std::cout << "world-import: PASS (2 blocks; mapped/unmapped/item-0 "
                 "counted separately; mesh rebuilt; table=TSV 44+24)\n";
}
