// Contract tests for the recovered net-sync phase contract (E21/E32/E40).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_net_sync_phases.cpp
//       reconstruction/recovered/net_sync_phases.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "net_sync_phases.h"

#include <cassert>
#include <utility>
#include <vector>

using blockheads::recovered::kFreeBlockType;
using blockheads::recovered::kNetCreationRecordBytes;
using blockheads::recovered::kNetIDBytes;
using blockheads::recovered::kNetSlotCount;
using blockheads::recovered::kRemoteUpdateGateType;
using blockheads::recovered::NetPhase;
using blockheads::recovered::NetSyncPhases;
using blockheads::recovered::remoteCreateSkipped;
using blockheads::recovered::remoteUpdateGated;

static void test_constants() {
    assert(kNetSlotCount == 65);
    assert(kNetIDBytes == 8);
    assert(kNetCreationRecordBytes == 24);
    assert(kFreeBlockType == 0xe);
    assert(kRemoteUpdateGateType == 0x3c);
}

static void test_receiver_gates() {
    // remoteCreate: skips the FreeBlock (0xe) type (E40).
    assert(remoteCreateSkipped(0xe));
    assert(!remoteCreateSkipped(0xd));
    assert(!remoteCreateSkipped(0xf));
    // remoteUpdate: takes only the 0x3c gate (E32).
    assert(remoteUpdateGated(0x3c));
    assert(!remoteUpdateGated(0x3b));
    assert(!remoteUpdateGated(0x3d));
}

static void test_phase_order_and_drain() {
    NetSyncPhases sync;
    sync.phaseQueue(NetPhase::kCreateRemove).push_back({1});
    sync.phaseQueue(NetPhase::kCreateRemove).push_back({2});
    sync.phaseQueue(NetPhase::kCreationData).push_back({3});
    // the update phase stays empty.
    sync.phaseQueue(NetPhase::kRemove).push_back({4});

    std::vector<std::pair<NetPhase, std::uint64_t>> sent;
    const std::vector<std::size_t> counts = sync.runPhases([&](NetPhase phase, const auto& record) {
        sent.emplace_back(phase, record.id);
    });

    // pinned order A -> B -> C -> D with per-phase counts.
    assert((counts == std::vector<std::size_t>{2, 1, 0, 1}));
    assert(sent.size() == 4);
    assert(sent[0].first == NetPhase::kCreateRemove && sent[0].second == 1);
    assert(sent[1].first == NetPhase::kCreateRemove && sent[1].second == 2);
    assert(sent[2].first == NetPhase::kCreationData && sent[2].second == 3);
    assert(sent[3].first == NetPhase::kRemove && sent[3].second == 4);

    // drain: every queue is empty after the pass (removeAllObjects).
    for (int i = 0; i < NetSyncPhases::kPhaseCount; ++i) {
        assert(sync.phaseQueue(static_cast<NetPhase>(i)).empty());
    }
    // a second pass sends nothing.
    const std::vector<std::size_t> again = sync.runPhases([&](NetPhase, const auto&) {
        assert(false);
    });
    assert((again == std::vector<std::size_t>{0, 0, 0, 0}));
}

int main() {
    test_constants();
    test_receiver_gates();
    test_phase_order_and_drain();
    return 0;
}
