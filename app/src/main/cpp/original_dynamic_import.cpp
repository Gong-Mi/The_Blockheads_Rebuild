#include "original_dynamic_import.h"

#include "original_client_app.h"

#include <cmath>

namespace bh176 {
namespace {

// A physical block is 32x32 original tiles (1024 x 64-byte OriginalTile).
constexpr int kTilesPerBlockSide = 32;

int floorDiv(int value, int divisor) {
    int quotient = value / divisor;
    if ((value % divisor != 0) && ((value < 0) != (divisor < 0))) {
        --quotient;
    }
    return quotient;
}

}  // namespace

bool materializeOriginalDynamicObjects(const OriginalClientApp& app,
                                       std::vector<MaterializedOriginalObject>& out,
                                       DynamicImportReport& report) {
    report = DynamicImportReport{};
    out.clear();

    const auto& objects = app.objects();
    report.objects_total = objects.size();

    // A structural failure, not an empty snapshot: the index carried records but
    // every one of them failed to produce an object.
    if (objects.empty() && !app.dynamicRows().empty()) {
        report.error = "dynamic index carried records but no object was constructed";
        return false;
    }

    for (const ClientDynamicObject& object : objects) {
        MaterializedOriginalObject marker;
        marker.type_id = object.type_id;
        marker.unique_id = object.unique_id;
        marker.status = object.status;

        bool have_position = false;
        if (object.has_float_pos) {
            marker.x = object.float_pos_x;
            marker.y = object.float_pos_y;
            marker.from_float_pos = true;
            have_position = true;
        } else if (object.pos_x != 0 || object.pos_y != 0) {
            marker.x = static_cast<float>(object.pos_x);
            marker.y = static_cast<float>(object.pos_y);
            have_position = true;
        }
        if (!have_position) {
            ++report.without_position;
            ++report.skipped_by_reason["without_position"];
            continue;
        }

        // The marker only counts as materialized when it lands inside the block
        // domain we actually imported: coordinates are not clamped, and an
        // object outside that domain is reported instead of being moved.
        const int block_x =
            floorDiv(static_cast<int>(std::floor(marker.x)), kTilesPerBlockSide);
        const int block_y =
            floorDiv(static_cast<int>(std::floor(marker.y)), kTilesPerBlockSide);
        if (app.world().blockAt(block_x, block_y) == nullptr) {
            ++report.out_of_world;
            ++report.skipped_by_reason["outside_imported_block_domain"];
            continue;
        }

        out.push_back(marker);
        ++report.materialized;
        if (marker.from_float_pos) {
            ++report.from_float_pos;
        } else {
            ++report.from_integer_pos;
        }
        switch (object.status) {
            case ObjectLoadStatus::Stub: ++report.stub_objects; break;
            case ObjectLoadStatus::Recovered: ++report.recovered_objects; break;
            case ObjectLoadStatus::Verified: ++report.verified_objects; break;
        }
        ++report.per_type[object.type_id];
    }

    return true;
}

}  // namespace bh176
