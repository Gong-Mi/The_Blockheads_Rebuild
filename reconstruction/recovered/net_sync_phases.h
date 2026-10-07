// Recovered contract: the DynamicWorld net-sync phase contract (E21/E32/E40).
//
// Evidence (reverse-v3 level A; net_sync.json / NET_SYNC.md + the E32/E40
// remote-receive batch):
//   - -[DynamicWorld updateNetObjects] (E21 0x008c4c20) runs FOUR phases:
//       A: the 65-slot netCreate/netRemove pairs - 8-byte ID reads via
//          getBytes:length:8, the NSMutableIndexSet addIndex: accumulation,
//          the FreeBlock type-14 branch and the freeBlockSoundDelay ladder;
//       B: netUpdateCreationDataDynamicObjects - 24-byte netBlockhead records
//          routed to remoteCreationDataUpdate:;
//       C: netUpdateDynamicObjects - routed to remoteUpdate:;
//       D: netRemoveDynamicObjects - the index set routed to
//          setNeedsRemoved:1;
//     each phase ends with removeAllObjects (the drain semantics).
//   - The receiver-side gates (E32/E40):
//       remoteCreate:forObjectsOfType:clientID: (E40 0x008c3c08) skips the
//       0xe (14, FreeBlock) case and lazily buckets per objectType;
//       remoteUpdate:forObjectsOfType:fromClient: (E32 0x008c3fa0) takes the
//       objectType == 0x3c gate.
//   - sendNetDataIfNeededForObject:isCreation: (E21 0x008c7fe4): the needs
//     flags gate the send; the flags clear after the packet goes out.
//
// This module models ONLY the phase bookkeeping: the four ordered phases,
// the per-phase drain (removeAllObjects), the 8-byte ID and 24-byte record
// strides as constants, and the two receiver gates as predicates.
//
// Boundaries (do not promote beyond evidence):
//   - The wire/packet marshalling is out of scope; the phase queues carry
//     typed records and a send callback consumes them.
//   - The 65-slot count is recorded as a constant (the per-slot pair
//     structure is not modelled).
//   - The receiver buckets are opaque (the lazy-create shape is noted, not
//     reproduced).
#pragma once

#include <cstdint>
#include <functional>
#include <vector>

namespace blockheads::recovered {

inline constexpr int kNetSlotCount = 65;            // the netCreate/netRemove pair count (E21)
inline constexpr std::size_t kNetIDBytes = 8;       // getBytes:length:8 reads
inline constexpr std::size_t kNetCreationRecordBytes = 24;  // the netBlockhead record (E21)
inline constexpr int kFreeBlockType = 0xe;          // the remoteCreate skip (E40)
inline constexpr int kRemoteUpdateGateType = 0x3c;  // the remoteUpdate gate (E32)

// Receiver-side gates.
constexpr bool remoteCreateSkipped(int objectType) { return objectType == kFreeBlockType; }
constexpr bool remoteUpdateGated(int objectType) { return objectType == kRemoteUpdateGateType; }

struct NetIDRecord {
    std::uint64_t id = 0;
};

enum class NetPhase {
    kCreateRemove = 0,   // A
    kCreationData = 1,   // B (24-byte records)
    kUpdate = 2,         // C
    kRemove = 3,         // D (needsRemoved)
};

class NetSyncPhases {
public:
    static constexpr int kPhaseCount = 4;

    std::vector<NetIDRecord>& phaseQueue(NetPhase phase) {
        return queues_[static_cast<int>(phase)];
    }

    // The drain contract: phases run in the pinned order A -> B -> C -> D;
    // each phase's queue is consumed by the callback and emptied
    // (removeAllObjects semantics). Returns the per-phase record counts.
    std::vector<std::size_t> runPhases(const std::function<void(NetPhase, const NetIDRecord&)>& send) {
        static constexpr NetPhase kOrder[kPhaseCount] = {
            NetPhase::kCreateRemove,
            NetPhase::kCreationData,
            NetPhase::kUpdate,
            NetPhase::kRemove,
        };
        std::vector<std::size_t> counts;
        for (const NetPhase phase : kOrder) {
            std::vector<NetIDRecord>& queue = phaseQueue(phase);
            const std::size_t n = queue.size();
            for (const NetIDRecord& record : queue) {
                send(phase, record);
            }
            queue.clear();  // the phase-end drain
            counts.push_back(n);
        }
        return counts;
    }

private:
    std::vector<NetIDRecord> queues_[kPhaseCount];
};

}  // namespace blockheads::recovered
