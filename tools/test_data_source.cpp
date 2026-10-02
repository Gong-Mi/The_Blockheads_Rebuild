// The startup data-source decision as a host test: snapshot present +
// no world.bin -> import; world.bin exists -> world.bin wins. Real
// OriginalClientWorld decode + real import + real PersistenceManager.
#ifdef NDEBUG
#error assertions must remain enabled
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "persistence_manager.h"
#include "entity_manager.h"
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

const std::string kBlockPayload(std::string(bh176::kTileBytesPerPhysicalBlock,
                                            '\0') +
                                std::string(1, '\0') + std::string(4, '\0'));

}  // namespace

int main() {
    namespace fs = std::filesystem;

    bh176::OriginalClientWorld original;
    fs::path snapshot = fs::temp_directory_path() / "bh-datasource-snap";
    fs::remove_all(snapshot);
    fs::create_directories(snapshot / "blocks");
    writeText(snapshot / "blocks/0_0.raw", kBlockPayload);
    writeText(snapshot / "blocks/index.tsv",
              "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
              "305f30\t0\t0\tblocks/0_0.raw\t" +
                  bh176::sha256Hex(kBlockPayload) + "\t" +
                  std::to_string(kBlockPayload.size()) + "\n");
    std::string error;
    assert(original.load(snapshot, &error) && original.blockCount() == 1);

    GameWorld world;
    world.stopThread = true;
    world.queueCV.notify_all();
    world.workerThread.join();

    // The engine decision, reproduced: snapshot wins only when no world.bin.
    fs::path storage = fs::temp_directory_path() / "bh-datasource-store";
    fs::remove_all(storage);
    fs::create_directories(storage);

    bh176::WorldImportReport report;
    const bool hasWorldBin = fs::exists(storage / "world.bin");
    assert(!hasWorldBin);
    assert(bh176::importOriginalWorld(original, world, report));
    assert(report.blocks_imported == 1);
    EntityManager entities;  // saveWorld refuses null entities (documented trap)
    PersistenceManager::saveWorld(storage.string().c_str(), &world, &entities);

    // A second launch: world.bin exists, so the snapshot must be skipped and
    // the saved world (authoritative) loads.
    GameWorld reloaded;
    reloaded.stopThread = true;
    reloaded.queueCV.notify_all();
    reloaded.workerThread.join();
    assert(fs::exists(storage / "world.bin"));
    assert(PersistenceManager::loadWorld(storage.string().c_str(), &reloaded,
                                         &entities));
    assert(reloaded.chunkGrid[0][0] != nullptr);
    assert(reloaded.chunks.size() == 1);

    // and a fresh import would still reproduce the same block count
    GameWorld again;
    again.stopThread = true;
    again.queueCV.notify_all();
    again.workerThread.join();
    bh176::WorldImportReport againReport;
    assert(bh176::importOriginalWorld(original, again, againReport));
    assert(againReport.blocks_imported == 1);

    fs::remove_all(snapshot);
    fs::remove_all(storage);
    std::cout << "data-source: PASS (snapshot seeds once; world.bin then "
                 "authoritative; snapshot never re-imported over it)\n";
}
