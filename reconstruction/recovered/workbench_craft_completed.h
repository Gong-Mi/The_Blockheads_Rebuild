// Recovered contract: the Workbench craft completion (-[craftCompleted],
// E75/E78 line).
//
// Evidence (reverse-v3 level A/B; imp 0x00aeb47c, 1891w, boundary 0x00aed208):
//   - The head bail: `if (self.currentBlockhead == nil) -> [self abortCraft]`
//     (@0xaeb4c8 -> 0xaeb518) and `if ([blockhead needsRemoved]) ->
//     [self abortCraft]` (@0xaeb4fc-0xaeb514 falls into the same block);
//     after the abortCraft call the code branches to the late shared tail
//     (`b 0xaed134` @0xaeb544). The normal path continues at 0xaeb548.
//   - The record: `[self craftableItem]` - the 124-byte CraftableItemRecord
//     fetch (stret + 0x7c memset @0xaeba40-0xaeba70); the slot loop runs
//     i in 0..f4-1 (cmp i, [fp,-0x198] = buf+72; bge @0xaeba88) reading
//     f2[i] at buf+8 (@0xaeba98-0xaebaa4) and f3[i] at buf+40
//     (@0xaebac0-0xaebacc).
//   - The paid slots (f2[i] == 11; `cmp r1, 0xb; beq` @0xaebaa8-0xaebab0)
//     skip the unit loop entirely (the target increments i).
//   - The unit loop: j in 0..f3[i]-1 (@0xaebae0-0xaebaf4); per unit:
//       * the predicate `[sourceItems[i] count] > 0` - selector ffe26480 on
//         sourceItems[i] (@0xaebb18-0xaebb50), booleanized unsigned
//         (`movhi r0, 1` @0xaebb58); false jumps straight to the slot
//         increment (0xaebb68 -> 0xaebd94 -> i++), ABANDONING the remaining
//         units of that slot;
//       * `preserveItemDataAInCraftedItem(rec.f2[i], rec.f0)` - the re-read
//         of f2[i] (@0xaebb84-0xaebb8c) and of f0 (`ldr r2, [fp,-0x1e0]`
//         @0xaebb84-0xaebb90; r0 = f2[i], r1 = f0); the sxtb result gates
//         only the record build (@0xaebb98-0xaebba0);
//       * the success build: a 124-byte copy of the record (@0xaebba4+:
//         the setCraftableItem:/dataA/objectAtIndex: chains, the two
//         memcpys @0xaebca8/0xaebcb8 and the 31-word copy loop
//         @0xaebcec-0xaebd10, then a call @0xaebd24);
//       * the consume: `removeObjectAtIndex:`-family call on sourceItems[i]
//         (@0xaebd28-0xaebd80, selector cell 0xaeccf0) - this runs on BOTH
//         the preserve-true and preserve-false paths (0xaebba0 beq lands
//         on it), then j++ (@0xaebd84-0xaebd8c).
//   - After the first pass the method continues into the second loop set
//     (@0xaec37c+: the same body with the counters at fp-0x2fc/fp-0x2f8)
//     and the tail (the CrystalManager strings, the AD interstitial
//     displayInterstitialForTag:, the achievements and
//     craftItemFinished:atWorkbench:allFinished:blockhead:).
//
// Boundaries (do not promote beyond evidence):
//   - The record-build internals (the copy chains, setCraftableItem:,
//     objectAtIndex:, the dataA read) are one callback; the consume is one
//     callback covering the removeObjectAtIndex:-family call.
//   - Everything after the first pass (the second loop set and the AD /
//     achievement tail; the shared landing at 0xaed134) is the finish
//     callback.
//   - The inert compare chain of 0x60/0x61/0x62/0x13 at 0xaeb9d0-0xaeba00
//     (all arms converge) is not modeled.
//   - The argument roles of preserveItemDataAInCraftedItem are pinned
//     positionally: first = the slot's recorded type (f2[i]), second = the
//     record's field 0 - matching the symbol's (ItemType, ItemType).
#pragma once

#include "workbench_craft_abort.h" // kAbortPaidItemType

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

// The Workbench access hooks for the completion handler. Empty hooks are
// skipped.
struct CraftCompletedHooks {
    std::function<bool()> current_blockhead_present; // nil -> abortCraft
    std::function<bool()> needs_removed;             // -> abortCraft
    std::function<void()> abort_craft;               // [self abortCraft]
    std::function<void()> finish;                    // the shared tail
    std::function<std::int32_t()> slot_count;        // f4 (buf+72)
    std::function<std::int32_t(int slot)> slot_item_type; // f2[i] (buf+8)
    std::function<std::int32_t(int slot)> slot_value;     // f3[i] (buf+40)
    std::function<std::int32_t()> record_f0;         // the record's field 0
    std::function<std::int32_t(int slot)> source_count;   // [sourceItems[i] count]
    // preserveItemDataAInCraftedItem(f2[i], f0): true gates the build.
    std::function<bool(int slot, std::int32_t slot_type, std::int32_t rec_f0)>
        preserve_data_a;
    std::function<void(int slot)> build_output_unit; // the record copy chain
    // The consume (removeObjectAtIndex:-family) - runs on both preserve
    // outcomes.
    std::function<void(int slot)> consume_source;
};

// Runs the completion handler's first pass in the observed order.
inline void workbench_craft_completed(const CraftCompletedHooks& h) {
    // The nil gate jumps straight to abortCraft (@0xaeb4c8 -> 0xaeb518)
    // WITHOUT consulting needsRemoved; a present blockhead always gets the
    // needsRemoved probe (@0xaeb4fc-0xaeb514).
    const bool missing = h.current_blockhead_present && !h.current_blockhead_present();
    const bool removed = !missing && h.needs_removed && h.needs_removed();
    if (missing || removed) {
        if (h.abort_craft) {
            h.abort_craft(); // @0xaeb4c8 / @0xaeb514 -> 0xaeb540
        }
        if (h.finish) {
            h.finish(); // b 0xaed134
        }
        return;
    }
    const std::int32_t slots = h.slot_count ? h.slot_count() : 0;
    for (std::int32_t i = 0; i < slots; ++i) { // cmp; bge @0xaeba8c
        if ((h.slot_item_type ? h.slot_item_type(i) : 0) == kAbortPaidItemType) {
            continue; // @0xaebaa8-0xaebab0 (the target increments i)
        }
        const std::int32_t units = h.slot_value ? h.slot_value(i) : 0;
        for (std::int32_t j = 0; j < units; ++j) { // cmp; bge @0xaebaf4
            const std::int32_t count = h.source_count ? h.source_count(i) : 0;
            if (!(count > 0)) { // movhi: unsigned (a length, never negative)
                break;          // @0xaebb68 -> the slot increment
            }
            const std::int32_t slot_type =
                h.slot_item_type ? h.slot_item_type(i) : 0; // re-read
            const std::int32_t f0 = h.record_f0 ? h.record_f0() : 0;
            const bool built = h.preserve_data_a
                                   ? h.preserve_data_a(i, slot_type, f0)
                                   : false;
            if (built && h.build_output_unit) {
                h.build_output_unit(i); // @0xaebba4-0xaebd24
            }
            if (h.consume_source) {
                h.consume_source(i); // @0xaebd28-0xaebd80 (both outcomes)
            }
            // j++ (@0xaebd84-0xaebd8c)
        }
    }
    if (h.finish) {
        h.finish(); // the second pass + the AD / achievement tail
    }
}

} // namespace blockheads::recovered
