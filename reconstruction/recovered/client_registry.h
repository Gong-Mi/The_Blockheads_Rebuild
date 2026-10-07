// Recovered contract: the DynamicWorld client registry and flag slots
// (E33 users/bans batch + E30/E39 flag readers).
//
// Evidence (reverse-v3 level A; users_bans.json / USERS_BANS.md):
//   - The registry:
//       ffffe51c = server  (isServer: != nil; the users/bans lookups below
//                          require it non-NULL);
//       ffffe54c member's +0x270 slice = the client walk target (E33 mute/ban
//                          per-node calls; the same +0x270 offset appears in
//                          E36's paintingWithID lookup - offset-pinned).
//   - The selector quintet (call cells):
//       ffe237a8 - userMuteChanged: per-node propagation (0x009023f4);
//       ffe237ac - userBanChanged:isBanned: per-node with the sxtb'd flag
//                  (0x009025e4);
//       fffe237b0 - playerIsBannedWithID: query (0x0090280c);
//       ffffe237b4 - playersChanged per-blockhead notice over the ffffe4f4
//                  netBlockheads enumeration (0x009028c8);
//       fffe237b8 - getOwnerNameForObjectOwnerID: name accessor off the
//                  ffffe51c slot (0x00902ac0).
//   - The poleItemTaken: registry dict ffffe564 with its format key
//     0xfff34284 (E30 poleItemTaken: 0x0090365c; same key as E23's restorer).
//   - The workbench flag: ffffe558 (workbenchHasBeenCrafted getter E39
//     0x008f015c; writer E30 workbenchPlacedAtPosition: - `strb 1` @0x8e78a8).
//
// This module models ONLY the registry bookkeeping: client entries keyed by
// id with mute/ban flags and names, the five notification operations as
// callbacks, the pole-taken dict with its key, and the workbench flag store.
//
// Boundaries (do not promote beyond evidence):
//   - The +0x270 client-slice identity is offset-pinned, not name-derived.
//   - The selector cells are opaque handles; notification fan-out order is
//     the observed enumeration order (caller-provided iteration here).
//   - The pole-taken dict's value domain is not resolved (records the raw
//     value); the key is the E30/E23-pinned 0xfff34284.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace blockheads::recovered {

// The selector quintet (call cells, E33).
inline constexpr std::int64_t kMutePropagationCell = 0x00ffe237a8;
inline constexpr std::int64_t kBanPropagationCell = 0x00ffe237ac;
inline constexpr std::int64_t kBanQueryCell = 0x00ffe237b0;
inline constexpr std::int64_t kPlayersChangedCell = 0x00ffe237b4;
inline constexpr std::int64_t kOwnerNameCell = 0x00ffe237b8;

// Slot identities.
inline constexpr std::int64_t kServerSlot = 0x00ffffe51c;
inline constexpr std::int64_t kClientSliceOffset = 0x270;      // ffffe54c +0x270
inline constexpr std::int64_t kPoleTakenDictSlot = 0x00ffffe564;
inline constexpr std::int64_t kWorkbenchFlagSlot = 0x00ffffe558;
inline constexpr std::int64_t kPoleTakenKeyId = 0x00fff34284;  // the format key (E23/E30)

struct ClientEntry {
    bool muted = false;
    bool banned = false;
    std::string name;
};

class ClientRegistry {
public:
    using Notify = std::function<void(std::uint64_t, std::int64_t)>;

    void setServerPresent(bool present) { serverPresent_ = present; }
    bool serverPresent() const { return serverPresent_; }

    // The users/bans lookups require the server slot non-NULL (E33).
    bool addClient(std::uint64_t clientID, std::string name) {
        if (!serverPresent_) {
            return false;
        }
        clients_[clientID] = ClientEntry{false, false, std::move(name)};
        return true;
    }

    // userMuteChanged: - the +0x270 walk with the ffe237a8 per-node call.
    bool muteChanged(std::uint64_t clientID, const Notify& notify) {
        if (!serverPresent_) {
            return false;
        }
        const auto it = clients_.find(clientID);
        if (it == clients_.end()) {
            return false;
        }
        it->second.muted = true;
        notify(clientID, kMutePropagationCell);
        return true;
    }

    // userBanChanged:isBanned: - the ffe237ac per-node call with the flag.
    bool banChanged(std::uint64_t clientID, bool banned, const Notify& notify) {
        if (!serverPresent_) {
            return false;
        }
        const auto it = clients_.find(clientID);
        if (it == clients_.end()) {
            return false;
        }
        it->second.banned = banned;
        notify(clientID, kBanPropagationCell);
        return true;
    }

    // playerIsBannedWithID: - the ffe237b0 query.
    std::optional<bool> banQuery(std::uint64_t clientID) const {
        if (!serverPresent_) {
            return std::nullopt;
        }
        const auto it = clients_.find(clientID);
        if (it == clients_.end()) {
            return std::nullopt;
        }
        return it->second.banned;
    }

    // playersChanged - the ffe237b4 per-client notice (over ffffe4f4).
    void playersChanged(const Notify& notify) const {
        if (!serverPresent_) {
            return;
        }
        for (const auto& kv : clients_) {
            notify(kv.first, kPlayersChangedCell);
        }
    }

    // getOwnerNameForObjectOwnerID: - the ffe237b8 name accessor.
    std::optional<std::string> ownerName(std::uint64_t ownerID) const {
        if (!serverPresent_) {
            return std::nullopt;
        }
        const auto it = clients_.find(ownerID);
        if (it == clients_.end()) {
            return std::nullopt;
        }
        return it->second.name;
    }

    // poleItemTaken: - the ffffe564 dict write under the pinned key.
    void poleTaken(std::uint64_t ownerID, std::int64_t value) {
        poleTaken_[ownerID] = value;
    }

    bool poleTakenRecorded(std::uint64_t ownerID) const {
        return poleTaken_.find(ownerID) != poleTaken_.end();
    }

    // The workbench flag (ffffe558) getter/setter pair (E39 reader / E30 writer).
    bool workbenchHasBeenCrafted() const { return workbenchCrafted_; }
    void setWorkbenchHasBeenCrafted(bool crafted) { workbenchCrafted_ = crafted; }

private:
    bool serverPresent_ = false;
    std::unordered_map<std::uint64_t, ClientEntry> clients_;
    std::unordered_map<std::uint64_t, std::int64_t> poleTaken_;
    bool workbenchCrafted_ = false;
};

}  // namespace blockheads::recovered
