// Recovered contract: the DynamicWorld remote-receive slot arrays
// (E32/E40 remote-receive batch).
//
// Evidence (reverse-v3 level A; remote_receive.json / REMOTE_RECEIVE.md):
//   - remoteCreationDataUpdate:forObjectsOfType:fromClient: (E40 0x008c3e64):
//     the **ffffe544** 4-byte pointer array (`add r0, r1, r0, lsl 2`
//     @0x8c3eb4-0x8c3ebc) indexed by objectType; a NULL cell creates
//     `[[class ffe2aeb0 alloc] init]` (@0x8c3ed8-0x8c3f14) and stores it
//     (@0x8c3f38) - the lazy-bucket create-on-null semantics.
//   - remoteCreate:forObjectsOfType:clientID: (E40 0x008c3c08): the
//     **ffffe53c** 4-byte slot array with the **ffe2aeb4** lazy class; the
//     type >= 0x41 family gate and the 0xe (FreeBlock) skip precede.
//   - remoteUpdate:forObjectsOfType:fromClient: (E32 0x008c3fa0): the
//     objectType == 0x3c gate; its walk reads ffffe51c, which E33/E35 later
//     established as the **server registry slot** (setServer:serverClients:
//     writes it; isServer reads its nil-ness) - NOT a bucket array, so the
//     third array is deliberately NOT modelled here.
//
// This module models ONLY the slot-array bookkeeping: a fixed 4-byte-slot
// pointer array with lazy create-on-null per index, the three named arrays
// with their pinned slot identities and eager class handles, and the
// objectType-gate + skip triple that precedes the bucketing.
//
// Boundaries (do not promote beyond evidence):
//   - Slots are modelled as lazily-created bucket objects (opaque); the
//     original stores objc object pointers.
//   - The array's slot capacity follows the objectType domain (< 0x41 for
//     the family gate); indices outside are refused by the caller-side gate,
//     which remains a predicate here.
//   - The bucket contents' semantics (what each objectType bucket holds) are
//     out of scope.
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>

namespace blockheads::recovered {

inline constexpr int kObjectTypeGate = 0x41;       // the family gate
inline constexpr int kFreeBlockSkipType = 0xe;     // remoteCreate skip (E40)
inline constexpr int kRemoteUpdateSlotGate = 0x3c; // remoteUpdate gate (E32)

inline constexpr std::int64_t kCreationDataArraySlot = 0x00ffffe544;  // ffe2aeb0 class
inline constexpr std::int64_t kRemoteCreateArraySlot = 0x00ffffe53c;  // ffe2aeb4 class

// The pre-bucketing gates.
constexpr bool bucketIndexAllowed(int objectType) { return objectType >= 0 && objectType < kObjectTypeGate; }
constexpr bool remoteCreateSkipsType(int objectType) { return objectType == kFreeBlockSkipType; }
constexpr bool remoteUpdateTakesType(int objectType) { return objectType == kRemoteUpdateSlotGate; }

// A single lazily-populated bucket object (opaque contents).
struct Bucket {
    std::uint64_t tag = 0;
};

// The slot array: 4-byte pointer slots; a NULL slot is lazily created on
// access (the create-on-null semantics of the three arrays).
class SlotArray {
public:
    explicit SlotArray(std::uint64_t createTag) : createTag_(createTag) {}

    // Returns the bucket for the index, creating it on first access.
    // Indices outside [0, kObjectTypeGate) are refused (the caller-side gate).
    Bucket* bucketFor(int objectType) {
        if (!bucketIndexAllowed(objectType)) {
            return nullptr;
        }
        std::unique_ptr<Bucket>& slot = slots_[static_cast<std::size_t>(objectType)];
        if (!slot) {
            slot = std::make_unique<Bucket>(Bucket{createTag_});
        }
        return slot.get();
    }

    // Reads without creating (the plain array read).
    const Bucket* peek(int objectType) const {
        if (!bucketIndexAllowed(objectType)) {
            return nullptr;
        }
        return slots_[static_cast<std::size_t>(objectType)].get();
    }

private:
    std::uint64_t createTag_;
    std::array<std::unique_ptr<Bucket>, kObjectTypeGate> slots_;
};

// The two named bucket arrays with their pinned identities.
class RemoteReceiveArrays {
public:
    SlotArray& creationDataArray() { return creationData_; }   // ffffe544 / ffe2aeb0
    SlotArray& remoteCreateArray() { return remoteCreate_; }   // ffffe53c / ffe2aeb4

private:
    SlotArray creationData_{0x00ffe2aeb0};
    SlotArray remoteCreate_{0x00ffe2aeb4};
};

}  // namespace blockheads::recovered
