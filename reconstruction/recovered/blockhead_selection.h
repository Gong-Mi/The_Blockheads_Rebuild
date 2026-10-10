// Recovered contract: the DynamicWorld active-blockhead selection (E42).
//
// Evidence (reverse-v3 level A; final_smalls.json / FINAL_SMALLS.md):
//   - -[DynamicWorld activeBlockheadIndex] (imp 0x008e2cbc): reads the
//     **ffffe55c** member directly - the selected-index getter.
//   - -[DynamicWorld selectedBlockheadChanged:] (imp 0x008e2cf8): reads the
//     ffffe4f8 collection count via ffe23204 and compares with the argument
//     (`cmp r1, r0; bhs` @0x8e2d60-0x8e2d64): in range -> the index stored
//     to ffffe55c (`str r2, [r0]` @0x8e2d84); out of range -> **0 stored**
//     (@0x8e2d8c-0x8e2da8).
//   - -[DynamicWorld activeBlockhead] (imp 0x008e2bac): the ffffe4f8 count
//     compared with the ffffe55c index; in range -> the object via ffe231cc;
//     out of range -> nil.
//
// This module models ONLY the selection bookkeeping: the selected index slot,
// the range-check-then-store setter (with the 0-on-out-of-range rule) and the
// resolver returning the selected element or nothing.
//
// Boundaries (do not promote beyond evidence):
//   - The ffffe4f8 collection is modelled as an ordered id vector (the
//     container class is out of scope).
//   - The comparison is on the collection COUNT (an index equal to count is
//     out of range; the bhs treats index >= count as invalid).
//   - The ffe231cc fetch is opaque; the slice returns the element reference.
#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace blockheads::recovered {

inline constexpr std::int64_t kSelectedIndexSlot = 0x00ffffe55c;  // the index slot (E42)

class BlockheadSelection {
public:
    // The ffffe4f8 member (ordered ids).
    std::vector<std::uint64_t>& blockheads() { return blockheads_; }
    const std::vector<std::uint64_t>& blockheads() const { return blockheads_; }

    // selectedBlockheadChanged: - range check against the collection count;
    // in range stores the index, otherwise stores 0.
    void selectedBlockheadChanged(int index) {
        if (index >= 0 && static_cast<std::size_t>(index) < blockheads_.size()) {
            selectedIndex_ = index;
        } else {
            selectedIndex_ = 0;  // the out-of-range 0-store (E42)
        }
    }

    // activeBlockheadIndex - the raw slot read.
    int activeBlockheadIndex() const { return selectedIndex_; }

    // activeBlockhead - the ffffe55c bounds check against the count; nil
    // when out of range (E42 0x8e2c28-0x8e2c34).
    std::optional<std::uint64_t> activeBlockhead() const {
        if (selectedIndex_ >= 0 && static_cast<std::size_t>(selectedIndex_) < blockheads_.size()) {
            return blockheads_[static_cast<std::size_t>(selectedIndex_)];
        }
        return std::nullopt;
    }

private:
    std::vector<std::uint64_t> blockheads_;
    int selectedIndex_ = 0;  // the ffffe55c default (zeroed member)
};

}  // namespace blockheads::recovered
