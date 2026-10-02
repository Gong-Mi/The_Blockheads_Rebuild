#ifndef ORIGINAL_DYNAMIC_IMPORT_H
#define ORIGINAL_DYNAMIC_IMPORT_H

// World-data-source bridge, layer 3: the assembled original snapshot's dynamic
// objects become materialized replacement-world objects.
//
// Layer scope, so nothing is overclaimed:
//   layer 1 (original_world_import.cpp)  original block domain -> seed terrain
//   layer 2 (game_engine startup)        snapshot seeds the world once, then
//                                        world.bin is authoritative
//   layer 3 (this file)                  dynamic objects -> typed markers with
//                                        their decoded identity and position
//
// Layer 3 materializes; it does not consume. Each marker carries the original
// type id, the unique id, the decoded position and the load status the registry
// gave the object (Stub / Recovered / Verified). No gameplay system reads the
// markers yet, so this must not be reported as entities, AI, growth, rendering
// or save back-write. Anything without a usable position, or whose block is not
// part of the imported domain, is counted instead of clamped or dropped
// silently.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "dynamic_object_registry.h"

namespace bh176 {

class OriginalClientApp;

struct MaterializedOriginalObject {
    int type_id = 0;
    std::uint64_t unique_id = 0;
    float x = 0.0f;
    float y = 0.0f;
    bool from_float_pos = false;
    ObjectLoadStatus status = ObjectLoadStatus::Stub;
};

struct DynamicImportReport {
    std::size_t objects_total = 0;
    std::size_t materialized = 0;
    std::size_t from_float_pos = 0;
    std::size_t from_integer_pos = 0;
    std::size_t recovered_objects = 0;
    std::size_t stub_objects = 0;
    std::size_t verified_objects = 0;
    std::size_t without_position = 0;
    std::size_t out_of_world = 0;
    std::map<int, std::size_t> per_type;
    std::map<std::string, std::size_t> skipped_by_reason;
    std::string error;
};

// Materializes every object the assembled app produced. `objects_total` counts
// what the app held, `materialized` counts what got a marker. Returns false with
// report.error only for a structural failure: the dynamic index carried records
// but not one of them produced an object. Per-object problems are counted, never
// fatal, and an empty index is not a failure.
bool materializeOriginalDynamicObjects(const OriginalClientApp& app,
                                       std::vector<MaterializedOriginalObject>& out,
                                       DynamicImportReport& report);

}  // namespace bh176

#endif
