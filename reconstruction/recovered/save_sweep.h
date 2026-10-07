// Recovered contract: the DynamicWorld five-container save sweep (E22/E40).
//
// Evidence (reverse-v3 level A; world_save.json / WORLD_SAVE.md):
//   - -[DynamicWorld saveGameWithWorldData:signOwnershipData:]
//     (imp 0x008b29bc) sweeps FIVE containers in the pinned order:
//       1. ffffe570 - the reliable queue family (the E21/E22 flush source);
//       2. ffffe574 - the unreliable queue family;
//       3. ffffe578 (+0x120 slice) - the dynamicWorldChanged container (the
//          E30 recorder target, 65 segments of 12-byte elements per E29);
//       4. ffffe57c - the third macro queue (E23; consumer role unestablished
//          and still documented as such);
//       5. ffffe580 - the snow container (the E32 snowChangedAtMacroPos:
//          recorder target);
//     per container: the element count via the (end - start) / 8 idiv idiom
//     (two words per pair; E40) and a per-element save call
//     (macroTileAtMacroPostion + savePhysicalBlockForMacroTile:... with the
//     reliability flags) - the save face of the same queue family that
//     world_change_queues models from the flush side.
//   - E40 saveDynamicObjects' own sweep additionally exercises the ffffe578
//     +0x120 slice with the client/0x2e/0x18 skip triple (modelled in
//     dynamic_world_changed).
//
// This module models ONLY the sweep bookkeeping: the five named containers in
// their pinned order, the pair-count idiom and the per-element callback
// contract. The tile/save calls are callbacks.
//
// Boundaries (do not promote beyond evidence):
//   - Container element type is the MacroPair family (8 bytes) per the queue
//     slices; the +0x120 slice of the ffffe578 container is abstracted into
//     the same container here (the slice offset is recorded as a constant).
//   - The ffffe57c consumer role remains unestablished (E23) - it appears in
//     the sweep but its element semantics are caller-owned.
//   - Save flags (sendReliably/dontSend/onlySaveIfClientsNeedIt) belong to
//     the world_change_queues flush contract and are NOT re-modelled.
#pragma once

#include <cstdint>
#include <functional>
#include <vector>

namespace blockheads::recovered {

inline constexpr std::int64_t kSweepReliableSlot = 0x00ffffe570;
inline constexpr std::int64_t kSweepUnreliableSlot = 0x00ffffe574;
inline constexpr std::int64_t kSweepDynamicChangedSlot = 0x00ffffe578;
inline constexpr std::int64_t kSweepDynamicChangedSlice = 0x120;  // the +0x120 slice (E22)
inline constexpr std::int64_t kSweepThirdQueueSlot = 0x00ffffe57c;
inline constexpr std::int64_t kSweepSnowSlot = 0x00ffffe580;

struct SweepPair {
    int x = 0;
    int y = 0;
};

enum class SweepContainer {
    kReliable = 0,
    kUnreliable = 1,
    kDynamicChanged = 2,
    kThirdQueue = 3,
    kSnow = 4,
};

class FiveContainerSweep {
public:
    static constexpr int kContainerCount = 5;

    std::vector<SweepPair>& container(SweepContainer which) {
        return containers_[static_cast<int>(which)];
    }

    const std::vector<SweepPair>& container(SweepContainer which) const {
        return containers_[static_cast<int>(which)];
    }

    // The sweep: containers in the pinned order, elements in insertion order
    // (the (end - start) / 8 count walks the vector start..end).
    // The callback receives (container, position, element).
    void sweep(const std::function<void(SweepContainer, std::size_t, const SweepPair&)>& save) const {
        static constexpr SweepContainer kOrder[kContainerCount] = {
            SweepContainer::kReliable,
            SweepContainer::kUnreliable,
            SweepContainer::kDynamicChanged,
            SweepContainer::kThirdQueue,
            SweepContainer::kSnow,
        };
        for (const SweepContainer which : kOrder) {
            const std::vector<SweepPair>& vec = container(which);
            for (std::size_t i = 0; i < vec.size(); ++i) {
                save(which, i, vec[i]);
            }
        }
    }

    std::size_t totalElements() const {
        std::size_t n = 0;
        for (const auto& vec : containers_) {
            n += vec.size();
        }
        return n;
    }

private:
    std::vector<SweepPair> containers_[kContainerCount];
};

}  // namespace blockheads::recovered
