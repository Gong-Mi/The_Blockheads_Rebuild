// Recovered contract: the Workbench hard abort
// (-[abortImmediatelyAndRestoreBlockheadItems], E78).
//
// Evidence (reverse-v3 level A/B; imp 0x00aeaac4, 622w, boundary 0x00aeb47c):
//   - The head: `if (self.currentBlockhead == nil) return;`
//     (@0xaeaafc-0xaeab04) then `if (!self.isInUse) return;`
//     (ldrsb @0xaeab20-0xaeab28). No fractionComplete reset on this path.
//   - The record: `[self craftableItem]` - the same 124-byte
//     CraftableItemRecord fetch (stret + 0x7c memset @0xaeab68-0xaeab98);
//     the slot loop runs i in 0..f4-1 (@0xaeabb0-0xaeabb4) over f2[i] at
//     buf+8 (@0xaeabc0-0xaeabcc) and f3[i] at buf+40 (@0xaeacdc-0xaeace8).
//   - The paid arm (f2[i] == 11, `cmp r1, 0xb` @0xaeabd0): identical to the
//     soft abort - the client gate (@0xaeac18-0xaeac24), the CrystalManager
//     watcher reset chain (@0xaeac6c-0xaeaccc), units = f3[i] * countLeft
//     (@0xaeacfc-0xaead00) and the strict 50000 cap
//     (cmp r0, 0xc350; bgt @0xaead08-0xaead0c); the bookkeeping chain
//     (@0xaead10-0xaeafc8) with the same +0x49 (73) addend @0xaeadf0.
//   - The plain arm: the enumeration runs UNCONDITIONALLY over
//     sourceItems[i] (@0xaeb06c countByEnumeratingWithState:objects:count-,
//     no nil pre-check) and each element goes
//     `[self.currentBlockhead addItemToInventory:element]`
//     (selector cell 0xaeb428 = ffe2656c; receiver = self.currentBlockhead
//     @0xaeb108-0xaeb110, arg = the enumerated element @0xaeb118-0xaeb134)
//     - the hard abort returns the stored sub-items to the Inventory.
//     The sub-array is then released and nilled (@0xaeb200-0xaeb220).
//   - The finalize is the same pinned chain as the soft abort:
//     craftAbortedForWorkbench:withBlockhead: (@0xaeb2c8) -> isInUse = 0
//     (@0xaeb2e4) -> craftItemFinished:atWorkbench: (@0xaeb310) ->
//     pos/objectType + dynamicWorldChangedAtPos:objectType: (@0xaeb380) ->
//     updateNeedsToBeSent = 1 (@0xaeb398) -> the closing reloc call
//     (@0xaeb3bc) -> countLeft = 0 (@0xaeb3d4).
//
// Boundaries (do not promote beyond evidence):
//   - The +0x49 addend and the string bookkeeping stay callback-side (the
//     chain is byte-for-byte the soft abort's).
//   - The release + nil of sourceItems[i] is part of the plain-arm
//     callback; the enumerated element's class is not inspected here.
//   - The closing reloc call (0xaeb3bc) stays unmodeled, as in the soft
//     abort slice.
#pragma once

#include "workbench_craft_abort.h" // kAbortPaidItemType / kAbortPaidUnitCap

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

// The Workbench access hooks for the hard abort. Empty hooks are skipped.
struct AbortImmediateHooks {
    std::function<bool()> current_blockhead_present; // nil gate @0xaeab04
    std::function<bool()> is_in_use;                 // ldrsb gate @0xaeab28
    std::function<std::int32_t()> slot_count;        // f4 (buf+72)
    std::function<std::int32_t(int slot)> slot_item_type; // f2[i] (buf+8)
    std::function<std::int32_t(int slot)> slot_value;     // f3[i] (buf+40)
    std::function<std::int32_t()> count_left;        // countLeft
    // The paid arm (f2[i] == 11) - shared shape with the soft abort.
    std::function<bool(int slot)> client_controlled;
    std::function<void()> watch_reset;               // the CrystalManager chain
    std::function<void(int slot, std::int32_t units)> paid_bookkeeping;
    // The plain arm: enumerate sourceItems[i] into the inventory, then
    // release + nil the sub-array.
    std::function<void(int slot)> restore_to_inventory;
    // The finalize.
    std::function<void()> craft_aborted;             // @0xaeb2c8
    std::function<void(bool)> set_is_in_use;         // false @0xaeb2e4
    std::function<void()> craft_item_finished;       // @0xaeb310
    std::function<void()> world_changed;             // @0xaeb380
    std::function<void(bool)> set_update_needs_to_be_sent; // true @0xaeb398
    std::function<void(std::int32_t)> set_count_left;      // 0 @0xaeb3d4
};

// Runs the hard abort in the observed order. Returns false when either head
// gate exits.
inline bool workbench_abort_immediately(const AbortImmediateHooks& h) {
    if (h.current_blockhead_present && !h.current_blockhead_present()) {
        return false; // @0xaeaafc-0xaeab04
    }
    if (h.is_in_use && !h.is_in_use()) {
        return false; // @0xaeab20-0xaeab28
    }
    const std::int32_t slots = h.slot_count ? h.slot_count() : 0;
    for (std::int32_t i = 0; i < slots; ++i) { // cmp; bge @0xaeabb4
        const std::int32_t type = h.slot_item_type ? h.slot_item_type(i) : 0;
        if (type == kAbortPaidItemType) {
            if (h.client_controlled && h.client_controlled(i)) {
                continue; // sxtb; bne @0xaeac24
            }
            if (h.watch_reset) {
                h.watch_reset(); // @0xaeac6c-0xaeaccc
            }
            const std::int32_t value = h.slot_value ? h.slot_value(i) : 0;
            const std::int32_t left = h.count_left ? h.count_left() : 0;
            const std::int32_t units = value * left;
            if (units > kAbortPaidUnitCap) {
                continue; // cmp; bgt @0xaead0c (50000 itself passes)
            }
            if (h.paid_bookkeeping) {
                h.paid_bookkeeping(i, units);
            }
            continue;
        }
        // The plain arm: the enumeration runs unconditionally (a nil
        // sub-array iterates zero times, then release + nil).
        if (h.restore_to_inventory) {
            h.restore_to_inventory(i); // @0xaeb06c-0xaeb220
        }
    }
    if (h.craft_aborted) {
        h.craft_aborted();
    }
    if (h.set_is_in_use) {
        h.set_is_in_use(false);
    }
    if (h.craft_item_finished) {
        h.craft_item_finished();
    }
    if (h.world_changed) {
        h.world_changed();
    }
    if (h.set_update_needs_to_be_sent) {
        h.set_update_needs_to_be_sent(true);
    }
    if (h.set_count_left) {
        h.set_count_left(0);
    }
    return true;
}

} // namespace blockheads::recovered
