#ifndef ORIGINAL_CLIENT_APP_H
#define ORIGINAL_CLIENT_APP_H

// Client-side assembly app skeleton (batch b5a).
//
// Pipeline the framework already supports end to end:
//
//   snapshot root
//     -> blocks/index.tsv          (OriginalClientWorld, real decoder output)
//     -> dynamic/index.tsv         (this file: row parsing + payload load)
//     -> XML plist payload         (SaveDict stub layer)
//     -> dynamicObjects[] entries  (SaveDict reads)
//     -> type id -> DynamicObjectRegistry -> ClientDynamicObject
//     -> report                    (per-type histogram + stub counters)
//
// Everything that is not recovered yet is a stub that reports itself: unknown
// or missing type keys skip construction and are counted, malformed payloads
// are counted, and every constructed object carries its load status. Nothing
// is inferred from the key shape, and no stub claims a recovered behavior.
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "dynamic_object_registry.h"
#include "original_dynamic_import.h"
#include "original_client_world.h"
#include "original_save_dict.h"
#include "sha256_util.h"

namespace bh176 {

struct DynamicRecordRow {
    std::string key_hex;
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::string file;
    std::string raw_sha256;
    std::size_t bytes = 0;
    bool has_coordinate = false;
    // Type id parsed from the record key suffix (`<x>_<y>/<type>`); -1 when
    // the key carries no type suffix (metadata-only snapshot shape).
    long long key_type_id = -1;
};

// World-level (main domain) state decoded from the original save: worldv2,
// dynamicWorldv2 and the blockheads record. Recognised fields are read by name;
// recognised-but-undecoded Data blobs and every unrecognised key are COUNTED,
// never guessed at.
struct OriginalWorldState {
    bool worldv2_present = false;
    bool dynamic_worldv2_present = false;
    bool blockheads_present = false;
    long long random_seed = 0;
    long long portal_level = 0;
    bool expert_mode = false;
    std::string max_players;
    std::string host_port;
    bool remote_game = false;
    bool run_at_launch = false;
    double no_rain_timer = 0.0;
    bool migration_complete = false;
    long long active_blockhead_index = 0;
    long long dynamic_object_id_count = 0;
    long long save_version = 0;
    bool workbench_has_been_crafted = false;
    // Player records found in this save (blockheadDatasv2 + blockheads
    // dynamicObjects). The assembled server save carries none, and that fact is
    // reported instead of being left as an open "not imported yet".
    std::size_t player_records = 0;
    std::size_t opaque_data_blobs = 0;
    std::map<std::string, std::size_t> unread_keys;
    // The replacement generator accepts a seed (GameWorld::setGenerationSeed),
    // so random_seed has a consumer; game_engine applies it on the first seed.
    bool seed_has_consumer = true;
};

struct ClientAppReport {
    std::size_t blocks = 0;
    std::size_t dynamic_records = 0;
    std::size_t dynamic_objects = 0;
    std::size_t stub_objects = 0;
    std::size_t recovered_objects = 0;
    std::size_t verified_objects = 0;
    std::size_t shared_object_type_objects = 0;
    std::size_t opaque_records = 0;
    std::size_t malformed_records = 0;
    std::size_t unidentified_objects = 0;
    std::size_t unknown_type_objects = 0;
    std::size_t out_of_range_objects = 0;
    std::map<int, std::size_t> per_type;
    std::map<std::string, std::size_t> type_key_used;
};

class OriginalClientApp {
public:
    // Loads the block domain and the dynamic index. Returns false with a
    // message for index-level failures (missing/duplicate/malformed rows).
    bool open(const std::filesystem::path& snapshot_root, std::string* error);

    // Parses every dynamic record and constructs its objects through the
    // registry. Record-level problems are counted in the report and do not
    // abort the load; the index must already have been opened.
    bool loadDynamicObjects(std::string* error);

    DynamicObjectRegistry& registry() { return registry_; }
    const OriginalClientWorld& world() const { return world_; }
    const std::vector<DynamicRecordRow>& dynamicRows() const { return rows_; }
    const std::vector<ClientDynamicObject>& objects() const { return objects_; }
    const ClientAppReport& report() const { return report_; }
    std::size_t saveDictStubHits() const { return save_dict_stub_hits_; }
    // Layer 3: the markers the dynamic domain materialized into, and the
    // per-object outcome. Markers are data, not gameplay consumers.
    const std::vector<MaterializedOriginalObject>& materializedObjects() const {
        return materialized_;
    }
    const DynamicImportReport& materializationReport() const {
        return materialization_;
    }
    const OriginalWorldState& worldState() const { return world_state_; }

    // [world worldTime] at load time — the saveTime gate's other input
    // (Plant loadSaveDictValues). Set from the assembled snapshot's main-db
    // worldv2 record (worldTime key) before loadDynamicObjects(); an unset
    // value defaults to 0.0 exactly like the b5b harness, which keeps the
    // gate testable and never invents a clock.
    void setWorldTime(double world_time) { world_time_ = world_time; }
    double worldTime() const { return world_time_; }

    // Registers the batch-recovered factories on this app's registry (today:
    // the Plant family — TulipPlant 59 + every Plant subclass whose records
    // carry only the Plant-level key set; see plant_full.h). Idempotent;
    // called by open() so every caller (CLI, JNI, tests) gets the recovered
    // chain without re-registering by hand.
    void registerRecoveredFactories();

    // Stable JSON for the CLI/guard (keys sorted, no locale dependence).
    std::string toJson() const;

    const std::filesystem::path& root() const { return root_; }

private:
    std::filesystem::path root_;
    OriginalClientWorld world_;
    DynamicObjectRegistry registry_;
    std::vector<DynamicRecordRow> rows_;
    std::vector<ClientDynamicObject> objects_;
    std::vector<MaterializedOriginalObject> materialized_;
    DynamicImportReport materialization_;
    OriginalWorldState world_state_;
    ClientAppReport report_;
    std::size_t save_dict_stub_hits_ = 0;
    double world_time_ = 0.0;
};

}  // namespace bh176

#endif  // ORIGINAL_CLIENT_APP_H
