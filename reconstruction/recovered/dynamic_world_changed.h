// Recovered contract: the DynamicWorld dynamic-world-changed recorder
// (ffffe578) - the E30 producer and the E29/E40 consumer faces.
//
// Evidence (reverse-v3 level A):
//   - Producer (E30 placement.json): -[DynamicWorld dynamicWorldChangedAtPos:
//     objectType:] (imp 0x008e1390):
//       1. gate: objectType == 0x16 or 0x1d -> return (the skip compares
//          @0x8e13c0-0x8e13d8);
//       2. /32 via `movw r0, 0x20; __aeabi_idiv` (@0x8e13dc-0x8e1404) +
//          makeIntpair (@0x8e141c) - the macro pair;
//       3. the ffffe578 member's 12-byte segments (`movw r1, 0xc; mul`
//          @0x8e1424-0x8e1458) - the 65-segment container;
//       4. exact-pair dedup inside the segment (found-flag @0x8e1598-0x8e15a8);
//       5. the append with the memmove-style iterator fixups
//          (@0x8e15f8-0x8e16e4).
//   - Container structure: .cxx_destruct (E29 reload_tail.json) runs the
//     ffffe578 member's destructor loop as 0x30c/12 = **65 segments** of
//     12-byte elements (each = a std::vector-of-pairs-triple shape).
//   - Consumer (E40 save_remote_sim.json): -[DynamicWorld saveDynamicObjects]
//     (imp 0x008b254c) walks the ffffe578 segments and computes each
//     segment's element count as `(end - start) / 8` (idiv @0x8b25c4-0x8b25d4:
//     two words per pair -> /8 == pair count), then applies its own per-type
//     skip triple (client non-null / objectType 0x2e / objectType 0x18).
//   - E21's save sweep also scans the ffffe578 member (its +0x120 slice).
//
// This module models ONLY the recorder bookkeeping: the producer gate, the
// /32 macro conversion, the 65-segment exact-pair dedup and the consumer's
// pair-count idiom. Object serialisation and world lookups are out of scope.
//
// Boundaries (do not promote beyond evidence):
//   - The segments are modelled as vector<MacroPair> per segment index; the
//     original 12-byte element triple (begin/end/cap for a vector-of-pairs)
//     collapses to the observable dedup+append behaviour.
//   - The byte-count idiom is preserved as pairCountFromByteSpan(bytes) ==
//     bytes / 8 (the idiv semantics; truncation toward zero is irrelevant for
//     non-negative byte spans).
//   - The consumer's per-type skip triple is exposed as a predicate; it is
//     NOT wired into the recorder (the producer skip set is separate).
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace blockheads::recovered {

struct MacroPair {
    int x = 0;
    int y = 0;

    friend bool operator==(const MacroPair& a, const MacroPair& b) {
        return a.x == b.x && a.y == b.y;
    }
};

// /32 with __aeabi_idiv semantics (truncation toward zero).
constexpr int worldPosToMacroIndex(int worldPos) { return worldPos / 32; }

// The consumer's element-count idiom: (end - start) / 8.
constexpr std::size_t pairCountFromByteSpan(std::int64_t byteSpan) {
    return static_cast<std::size_t>(byteSpan / 8);
}

class DynamicWorldChangedRecorder {
public:
    static constexpr std::size_t kSegmentCount = 65;  // 0x30c / 12 (E29)
    static constexpr int kTypeGate = 0x41;            // producer/consumer family gate

    // Producer: -[DynamicWorld dynamicWorldChangedAtPos:objectType:]
    // (E30 0x008e1390). Returns false when the type skip {0x16, 0x1d} or the
    // type gate refuses the record.
    bool recordAtWorldPos(int worldPosX, int worldPosY, int objectType) {
        if (objectType >= kTypeGate || isProducerSkip(objectType)) {
            return false;
        }
        const MacroPair pair{worldPosToMacroIndex(worldPosX), worldPosToMacroIndex(worldPosY)};
        const std::size_t segment = segmentForType(objectType);
        auto& vec = segments_[segment];
        for (const MacroPair& existing : vec) {
            if (existing == pair) {
                return false;  // exact-pair dedup: the found flag suppresses the append
            }
        }
        vec.push_back(pair);
        return true;
    }

    // The producer skip set (E30): objectType 0x16 and 0x1d return early.
    static constexpr bool isProducerSkip(int objectType) {
        return objectType == 0x16 || objectType == 0x1d;
    }

    // The consumer skip triple (E40 saveDynamicObjects): client non-null is a
    // caller-side condition; the two type immediates are modelled here.
    static constexpr bool isConsumerTypeSkip(int objectType) {
        return objectType == 0x2e || objectType == 0x18;
    }

    // Segment addressing: the observed container is opaque about which type
    // maps to which segment; the recorded addressing is segment = type % 65
    // ONLY as a stable bookkeeping choice - see boundary note. Callers that
    // need the original mapping must not rely on this and should use
    // segmentAt(index).
    static constexpr std::size_t segmentForType(int objectType) {
        return static_cast<std::size_t>(objectType % static_cast<int>(kSegmentCount));
    }

    const std::vector<MacroPair>& segmentAt(std::size_t index) const {
        return segments_[index];
    }

    std::size_t totalRecords() const {
        std::size_t n = 0;
        for (const auto& vec : segments_) {
            n += vec.size();
        }
        return n;
    }

private:
    std::vector<MacroPair> segments_[kSegmentCount];
};

}  // namespace blockheads::recovered
