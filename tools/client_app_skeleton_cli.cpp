// Client assembly app skeleton CLI (batch b5a).
//
//   client_app_skeleton_cli <snapshot-root> [--json]
//
// Loads the block domain and the dynamic-object domain of an assembled
// snapshot through the app skeleton and prints the load report. Exit codes:
// 0 loaded, 1 index/load failure, 2 usage. The CLI never claims more than the
// report does: objects built by stubs are printed as stubs.
#include "original_client_app.h"

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
    std::cout << "client assembly app skeleton (stub framework)\n";
    std::cout << "  blocks:                " << report.blocks << "\n";
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
    for (const auto& entry : report.per_type) {
        std::cout << "  type " << entry.first << ": " << entry.second << " object(s)\n";
    }
    return 0;
}
