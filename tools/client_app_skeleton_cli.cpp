// Client assembly app skeleton CLI (batch b5a).
//
//   client_app_skeleton_cli <snapshot-root> [--json]
//
// Loads the block domain and the dynamic-object domain of an assembled
// snapshot through the app skeleton and prints the load report. Exit codes:
// 0 loaded, 1 index/load failure, 2 usage. The CLI never claims more than the
// report does: objects built by stubs are printed as stubs.
#include "original_client_app.h"
#include "original_dynamic_import.h"

#include <cstdio>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::fprintf(stderr, "usage: %s <snapshot-root> [--json]\n", argv[0]);
        return 2;
    }
    const bool json = argc == 3 && std::string(argv[2]) == "--json";
    if (argc == 3 && !json) {
        std::fprintf(stderr, "unknown option: %s\n", argv[2]);
        return 2;
    }

    bh176::OriginalClientApp app;
    std::string error;
    if (!app.open(argv[1], &error)) {
        std::fprintf(stderr, "open failed: %s\n", error.c_str());
        return 1;
    }
    if (!app.loadDynamicObjects(&error)) {
        std::fprintf(stderr, "dynamic load failed: %s\n", error.c_str());
        return 1;
    }

    if (json) {
        std::cout << app.toJson();
        return 0;
    }

    const auto& report = app.report();
    const auto& materialization = app.materializationReport();
    std::cout << "client assembly app skeleton (stub framework)\n";
    std::cout << "  blocks:                " << report.blocks << "\n";
    std::cout << "  worldTime (main/worldv2): " << app.worldTime() << "\n";
    std::cout << "  dynamic records:       " << report.dynamic_records << "\n";
    std::cout << "  dynamic objects:       " << report.dynamic_objects << "\n";
    std::cout << "    stub objects:        " << report.stub_objects << "\n";
    std::cout << "    recovered objects:   " << report.recovered_objects << "\n";
    std::cout << "    verified objects:    " << report.verified_objects << "\n";
    std::cout << "    shared objectType:   " << report.shared_object_type_objects << "\n";
    std::cout << "  unidentified objects:  " << report.unidentified_objects << "\n";
    std::cout << "  out-of-range types:    " << report.out_of_range_objects << "\n";
    std::cout << "  opaque records:        " << report.opaque_records << "\n";
    std::cout << "  malformed records:     " << report.malformed_records << "\n";
    // Layer 3: markers materialized from the dynamic domain. These are data
    // with identity and position; no gameplay system consumes them yet.
    std::cout << "  materialized objects:  " << materialization.materialized << "\n";
    std::cout << "    from floatPos:       " << materialization.from_float_pos << "\n";
    std::cout << "    from integer pos:    " << materialization.from_integer_pos << "\n";
    std::cout << "    recovered markers:   " << materialization.recovered_objects << "\n";
    std::cout << "    stub markers:        " << materialization.stub_objects << "\n";
    std::cout << "    without position:    " << materialization.without_position << "\n";
    std::cout << "    outside imported:    " << materialization.out_of_world << "\n";
    const auto& world_state = app.worldState();
    std::cout << "  world records:         worldv2="
              << (world_state.worldv2_present ? "yes" : "no")
              << " dynamicWorldv2="
              << (world_state.dynamic_worldv2_present ? "yes" : "no")
              << " blockheads="
              << (world_state.blockheads_present ? "yes" : "no") << "\n";
    std::cout << "  world randomSeed:      " << world_state.random_seed
              << " (consumer: "
              << (world_state.seed_has_consumer ? "yes" : "none") << ")\n";
    std::cout << "  world config:          portal=" << world_state.portal_level
              << " expert=" << (world_state.expert_mode ? 1 : 0)
              << " maxPlayers=" << world_state.max_players
              << " hostPort=" << world_state.host_port << "\n";
    std::cout << "  dynamic object ids:    next="
              << world_state.dynamic_object_id_count
              << " activeBlockhead=" << world_state.active_blockhead_index
              << " saveVersion=" << world_state.save_version << "\n";
    std::cout << "  player records:        " << world_state.player_records << "\n";
    std::cout << "  opaque world blobs:    " << world_state.opaque_data_blobs << "\n";
    for (const auto& entry : report.per_type) {
        std::cout << "  type " << entry.first << ": " << entry.second << " object(s)\n";
    }
    return 0;
}
