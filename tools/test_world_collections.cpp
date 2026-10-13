// Contract tests for the recovered world-collections merge slice
// (E27/E29/E31/E35/E40/E42 readers).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_world_collections.cpp
//       reconstruction/recovered/world_collections.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "world_collections.h"

#include <cassert>
#include <vector>

using blockheads::recovered::WorldCollections;

static void seed(WorldCollections& c) {
    c.localBlockheads() = {10, 11};
    c.netBlockheadsMember() = {20};
    c.blockheadsMember() = {30, 31};
}

static void test_client_server_booleans() {
    WorldCollections c;
    assert(!c.isClient());
    assert(!c.isServer());
    c.setClientPresent(true);
    assert(c.isClient());
    assert(!c.isServer());
    c.setServerAndClients(true, true);
    assert(c.isServer());
    assert(c.hasServerClients());
    c.setClientPresent(false);
    assert(!c.isClient());
}

static void test_net_blockheads_merges_local_and_net() {
    WorldCollections c;
    seed(c);
    const std::vector<std::uint64_t> merged = c.netBlockheads();
    assert((merged == std::vector<std::uint64_t>{10, 11, 20}));
    // the blockheads member is NOT part of the netBlockheads merge.
    for (std::uint64_t id : merged) {
        assert(id != 30 && id != 31);
    }
}

static void test_all_blockheads_merges_three() {
    WorldCollections c;
    seed(c);
    const std::vector<std::uint64_t> merged = c.allBlockheadsIncludingNet();
    assert((merged == std::vector<std::uint64_t>{10, 11, 20, 30, 31}));
}

static void test_local_and_disconnected_branch() {
    WorldCollections c;
    seed(c);
    // client branch: blockheads directly.
    c.setClientPresent(true);
    assert((c.localAndDisconnectedClientBlockheads() == std::vector<std::uint64_t>{30, 31}));
    // server branch: local + blockheads.
    c.setClientPresent(false);
    assert((c.localAndDisconnectedClientBlockheads() == std::vector<std::uint64_t>{10, 11, 30, 31}));
}

static void test_duplicates_preserved() {
    // No dedup evidence: a shared id in two collections appears twice.
    WorldCollections c;
    c.localBlockheads() = {7};
    c.blockheadsMember() = {7};
    assert((c.localAndDisconnectedClientBlockheads() == std::vector<std::uint64_t>{7, 7}));
}

int main() {
    test_client_server_booleans();
    test_net_blockheads_merges_local_and_net();
    test_all_blockheads_merges_three();
    test_local_and_disconnected_branch();
    test_duplicates_preserved();
    return 0;
}
