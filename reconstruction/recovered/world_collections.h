// Recovered contract: the DynamicWorld blockhead-collection members and their
// merge getters (E35 query/accessor batch + E31/E40 cross-references).
//
// Evidence (reverse-v3 level A; every slot below is confirmed by the ivar
// symbol tables and by the reader/writer bodies):
//   - Slots:
//       ffffe4f0 = local blockheads              (E35 localAndDisconnected...)
//       ffffe4f4 = netBlockheads                 (E31 symbol table; E21/E40
//                                                 enumeration sites)
//       ffffe4f8 = blockheads                    (E27/E29/E35/E42 readers; the
//                                                 setPaused sweep + activeBlockhead)
//       ffffe518 = client   (isClient: != nil -> true; E35 0x008f64c0)
//       ffffe51c = server   (isServer: != nil -> true; E35 0x008f6514;
//                            setServer:serverClients: writes it; E40)
//       ffffe514 = serverClients (written by setServer:serverClients:; E40)
//   - Merge getters (E35 0x008f6698/0x008f676c/0x008f67f8):
//       netBlockheads        = merge(ffffe4f0, ffffe4f4) via the ffe236a8 call
//       allBlockheadsIncludingNet = merge(ffffe4f0, ffffe4f4, ffffe4f8)
//       localAndDisconnectedClientBlockheads:
//           client != nil -> ffffe4f8 directly;
//           otherwise     -> the ffffe4f0 collection consulted via
//                            ffe23204/ffe236a8 and merged with ffffe4f8.
//   - The client/server booleans are exactly `slot != nil` (E35).
//
// This module models ONLY the collection bookkeeping and the merge/boolean
// contract. Real blockhead objects are opaque ids here.
//
// Boundaries (do not promote beyond evidence):
//   - The three collections are modelled as ordered id lists; the original
//     containers (NSArray/NSMutableArray shapes) are not modelled.
//   - The merge ORDER is recorded as (local, net, blockheads) for the merge
//     getters based on the call-site enumeration order in E35; duplicates are
//     preserved (the original merges without dedup evidence).
//   - Server-side merge internals (ffe23204/ffe236a8 identities) are opaque
//     call handles, not reproduced.
#pragma once

#include <cstdint>
#include <vector>

namespace blockheads::recovered {

// Slot identities (pinned by the symbol tables; stable handles here).
inline constexpr std::int64_t kSlotLocalBlockheads = 0x00ffffe4f0;
inline constexpr std::int64_t kSlotNetBlockheads = 0x00ffffe4f4;
inline constexpr std::int64_t kSlotBlockheads = 0x00ffffe4f8;
inline constexpr std::int64_t kSlotClient = 0x00ffffe518;
inline constexpr std::int64_t kSlotServer = 0x00ffffe51c;
inline constexpr std::int64_t kSlotServerClients = 0x00ffffe514;

using BlockheadId = std::uint64_t;

class WorldCollections {
public:
    // The three member collections.
    std::vector<BlockheadId>& localBlockheads() { return local_; }
    std::vector<BlockheadId>& netBlockheadsMember() { return net_; }
    std::vector<BlockheadId>& blockheadsMember() { return blockheads_; }

    // The client/server presence slots (nil-ness is the boolean).
    void setClientPresent(bool present) { clientPresent_ = present; }
    void setServerAndClients(bool serverPresent, bool clientsPresent) {
        serverPresent_ = serverPresent;
        serverClientsPresent_ = clientsPresent;
    }

    // isClient / isServer (E35): slot != nil.
    bool isClient() const { return clientPresent_; }
    bool isServer() const { return serverPresent_; }
    bool hasServerClients() const { return serverClientsPresent_; }

    // netBlockheads (E35 0x008f676c): merge(local, net).
    std::vector<BlockheadId> netBlockheads() const {
        std::vector<BlockheadId> out = local_;
        out.insert(out.end(), net_.begin(), net_.end());
        return out;
    }

    // allBlockheadsIncludingNet (E35 0x008f6698): merge(local, net, blockheads).
    std::vector<BlockheadId> allBlockheadsIncludingNet() const {
        std::vector<BlockheadId> out = local_;
        out.insert(out.end(), net_.begin(), net_.end());
        out.insert(out.end(), blockheads_.begin(), blockheads_.end());
        return out;
    }

    // localAndDisconnectedClientBlockheads (E35 0x008f67f8):
    // client -> ffffe4f8 directly; server -> local + ffffe4f8 merge.
    std::vector<BlockheadId> localAndDisconnectedClientBlockheads() const {
        if (clientPresent_) {
            return blockheads_;
        }
        std::vector<BlockheadId> out = local_;
        out.insert(out.end(), blockheads_.begin(), blockheads_.end());
        return out;
    }

private:
    std::vector<BlockheadId> local_;
    std::vector<BlockheadId> net_;
    std::vector<BlockheadId> blockheads_;
    bool clientPresent_ = false;
    bool serverPresent_ = false;
    bool serverClientsPresent_ = false;
};

}  // namespace blockheads::recovered
