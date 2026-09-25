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
#include "original_client_world.h"
#include "original_save_dict.h"

namespace bh176 {

struct DynamicRecordRow {
    std::string key_hex;
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::string file;
    std::string raw_sha256;
    std::size_t bytes = 0;
    bool has_coordinate = false;
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

    // Stable JSON for the CLI/guard (keys sorted, no locale dependence).
    std::string toJson() const;

    const std::filesystem::path& root() const { return root_; }

private:
    std::filesystem::path root_;
    OriginalClientWorld world_;
    DynamicObjectRegistry registry_;
    std::vector<DynamicRecordRow> rows_;
    std::vector<ClientDynamicObject> objects_;
    ClientAppReport report_;
    std::size_t save_dict_stub_hits_ = 0;
};

}  // namespace bh176

#endif  // ORIGINAL_CLIENT_APP_H
