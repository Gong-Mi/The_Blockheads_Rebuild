// Recovered contract: the Workbench craft abort (-[abortCraft], E78).
//
// Evidence (reverse-v3 level A/B; imp 0x00ae9b78, 979w, boundary 0x00aeaac4):
//   - The head gate: `[self.currentBlockhead needsRemoved]` (sxtb @0xae9bc4)
//     releases and nils craftingItemObject (`release` @0xae9c08, the nil
//     store @0xae9c24-0xae9c30).
//   - `fractionComplete = 0.0f` (@0xae9c54-0xae9c6c; the 0-word pool word
//     at 0xae9f68).
//   - The craft record is `[self craftableItem]` - the machine-checked
//     124-byte CraftableItemRecord (see craftable_item_record.h): the slot
//     loop runs i in 0..f4-1 (`cmp; bge` @0xae9f9c-0xae9fa4) reading
//     f2[i] at buf+8 (@0xae9fac-0xae9fbc) and f3[i] at buf+40
//     (@0xaea0cc-0xaea0d8).
//   - The paid arm (f2[i] == 11; `cmp r1, 0xb` @0xae9fc0):
//       * `[item isClientBlockheadBeingControlledByServer]` (sxtb
//         @0xaea008-0xaea014; non-zero skips the slot to 0xaea3b8);
//       * the CrystalManager watcher chain (@0xaea018-0xaea0bc:
//         [CrystalManager instance] -> uiManager -> worldUI ->
//         setCountWatcher:);
//       * units = f3[i] * countLeft (`mul r0, r0, r1` @0xaea0f0);
//       * the cap: `cmp r0, 0xc350; bgt` @0xaea0f8 - units ABOVE 50000
//         skip the slot; 50000 itself passes;
//       * the bookkeeping chain (stringWithFormat:/stringFromMD5/
//         amountString/amount/modify:modifyString:,
//         craftItemFinished:atWorkbench: contexts @0xaea100-0xaea3a4).
//       * The +0x49 (73) addend at 0xaea1e0 and the amount/string chains
//         stay callback-boundary.
//   - The plain arm (f2[i] != 11):
//       * sourceItems[i] != nil (`ldr r2, [r3, i*4]` on the sourceItems
//         ivar @0xaea3e0-0xaea3f4) -> the fast-enumeration drop arm:
//         countByEnumeratingWithState:objects:count: over sourceItems[i]
//         (@0xaea520), per element the itemType/dataA/dataB/subItems/
//         dynamicObjectSaveDict getters and the 9-argument
//         createFreeBlockAtPosition:ofType:dataA:dataB:subItems:
//         dynamicObjectSaveDict:hovers:playSound:priorityBlockhead: call
//         (@0xaea754), then release + nil the sub-array
//         (0xaea7d4-0xaea83c);
//       * nil -> the unit loop: j in 0..f3[i]*countLeft-1
//         (`cmp; bge` @0xaea444-0xaea44c) calling the same
//         createFreeBlockAtPosition:... per unit (@0xaea4a0-0xaea4e8),
//         so the drop count is exactly f3[i] * countLeft.
//   - The finalize (all pinned by rows): craftAbortedForWorkbench:
//     withBlockhead: (@0xaea8e4) -> isInUse = 0 (`strb r3, 0` @0xaea8f8)
//     -> craftItemFinished:atWorkbench: (@0xaea92c) -> the pos pair read
//     + [self objectType] + dynamicWorldChangedAtPos:objectType:
//     (@0xaea93c-0xaea99c) -> updateNeedsToBeSent = 1 (`strb r2, 1`
//     @0xaea9b4) -> countLeft = 0 (`str r2, 0` @0xaea9f0).
//
// Boundaries (do not promote beyond evidence):
//   - The pos tri-state comparisons (@0xae9d14-0xae9f14: +1 / 0 / -1
//     against the self.pos components, the local y+1) stay unmodeled.
//   - The +0x49 addend, the string bookkeeping and the closing reloc call
//     (0xaea9d8) stay callback-side.
//   - The receive-failure fallbacks (5x objc_msgSend_stret / memset) are
//     call-marshalling, not semantics.
#pragma once

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

// The pinned constants.
inline constexpr std::int32_t kAbortPaidItemType = 11;     // `cmp r1, 0xb`
inline constexpr std::int32_t kAbortPaidUnitCap = 50000;   // 0xc350

// The Workbench access hooks. Every store access is a callback; empty hooks
// are skipped.
struct AbortCraftHooks {
    std::function<bool()> needs_removed;             // @0xae9bc4
    std::function<void()> release_crafting_item;     // release + nil
    std::function<void(float)> set_fraction_complete; // 0.0f
    std::function<std::int32_t()> slot_count;        // f4 (buf+72)
    std::function<std::int32_t(int slot)> slot_item_type; // f2[i] (buf+8)
    std::function<std::int32_t(int slot)> slot_value;     // f3[i] (buf+40)
    std::function<std::int32_t()> count_left;        // countLeft
    // The paid arm (f2[i] == 11).
    std::function<bool(int slot)> client_controlled; // sxtb skip
    std::function<void()> watch_reset;               // the CrystalManager chain
    std::function<void(int slot, std::int32_t units)> paid_bookkeeping;
    // The plain arm (f2[i] != 11).
    std::function<bool(int slot)> sub_items_present; // sourceItems[i] != nil
    std::function<void(int slot)> restore_via_sub_items; // the enum drop arm
    std::function<void(int slot, std::int32_t index)> restore_unit; // per unit
    // The finalize.
    std::function<void()> craft_aborted;             // @0xaea8e4
    std::function<void(bool)> set_is_in_use;         // false @0xaea8f8
    std::function<void()> craft_item_finished;       // @0xaea92c
    std::function<void()> world_changed;             // @0xaea99c
    std::function<void(bool)> set_update_needs_to_be_sent; // true @0xaea9b4
    std::function<void(std::int32_t)> set_count_left;      // 0 @0xaea9f0
};

// Runs the soft abort in the observed order.
inline void workbench_abort_craft(const AbortCraftHooks& h) {
    if (h.needs_removed && h.needs_removed()) {
        if (h.release_crafting_item) {
            h.release_crafting_item(); // @0xae9c08-0xae9c30
        }
    }
    if (h.set_fraction_complete) {
        h.set_fraction_complete(0.0f); // @0xae9c6c
    }
    const std::int32_t slots = h.slot_count ? h.slot_count() : 0;
    for (std::int32_t i = 0; i < slots; ++i) { // cmp; bge @0xae9fa4
        const std::int32_t type = h.slot_item_type ? h.slot_item_type(i) : 0;
        if (type == kAbortPaidItemType) {
            if (h.client_controlled && h.client_controlled(i)) {
                continue; // sxtb; bne @0xaea014
            }
            if (h.watch_reset) {
                h.watch_reset(); // @0xaea018-0xaea0bc
            }
            const std::int32_t value = h.slot_value ? h.slot_value(i) : 0;
            const std::int32_t left = h.count_left ? h.count_left() : 0;
            const std::int32_t units = value * left;
            if (units > kAbortPaidUnitCap) {
                continue; // cmp; bgt @0xaea0f8 (50000 itself passes)
            }
            if (h.paid_bookkeeping) {
                h.paid_bookkeeping(i, units);
            }
            continue;
        }
        if (h.sub_items_present && h.sub_items_present(i)) {
            if (h.restore_via_sub_items) {
                h.restore_via_sub_items(i); // the enumerated drop arm
            }
        } else if (h.slot_value && h.restore_unit) {
            const std::int32_t value = h.slot_value(i);
            const std::int32_t left = h.count_left ? h.count_left() : 0;
            const std::int32_t units = value * left;
            for (std::int32_t j = 0; j < units; ++j) { // cmp; bge @0xaea44c
                h.restore_unit(i, j);            // one drop per unit
            }
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
}

} // namespace blockheads::recovered
