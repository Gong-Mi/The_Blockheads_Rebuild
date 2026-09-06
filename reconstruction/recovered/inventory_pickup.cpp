#include "inventory_pickup.h"
#include "inventory_rules.h"

namespace recovered::inventory_pickup {
// 0xc61c00..0xc638a0 local recovery. Entry gates, priority rejection, ordinary
// freeblock insert path and the failure block follow original instruction order.
// The freeblocks/tile lookup region (0xc61dd0..0xc626d8), ownership special-item
// branches and the 0x12a currency-split loop (0xc62900..0xc63440) are NOT
// recovered; production callers must supply a resolved freeblock and the
// pending path intentionally returns zero without side effects.
std::int8_t pickupFreeblockIfPossible(Runtime& r, Object self, Object freeblock,
                                      std::int8_t intentional) {
    // 0xc61c48..0xc61c6c: worldUIDragging(world) gate; nonzero rejects.
    const Object world = r.readWorld(self);
    if (r.worldUIDragging(world) != 0) return 0;
    // 0xc61c7c..0xc61cbc: state bytes at +0x60/+0x68; nonzero rejects.
    const Object state = r.stateStorageAddress(self);
    if (r.stateGateA(state) != 0 || r.stateGateB(state) != 0) return 0;
    // 0xc61cd0..0xc61cfc: priorityBlockhead send.
    const Object priority = r.priorityBlockhead(freeblock);
    // 0xc61d00..0xc61d84: with intentional==0, ignoringFreeblocksDueToDrop or
    // meditating forces priority==self; intentional nonzero skips this region
    // (the later priority != self check still applies).
    if (intentional == 0 &&
        (r.ignoringFreeblocksDueToDrop(self) != 0 || r.meditating(self) != 0)) {
        if (priority != self) return 0;
    }
    // 0xc61d88..0xc61db4: non-nil foreign priority rejects.
    if (priority != 0 && priority != self) return 0;
    // Lookup-region bytes are not recovered; a nil freeblock cannot continue.
    if (freeblock == 0) return 0;
    // 0xc626dc..0xc626fc: freeblock ordinary fields.
    const std::int32_t type = r.itemType(freeblock);
    const Object sub = r.subItems(freeblock);
    const std::uint16_t a = r.dataA(freeblock);
    const std::uint16_t b = r.dataB(freeblock);
    // 0xc627f0..0xc627f8: canPickUpItemOfType:subItems:dataA:dataB: must equal 1.
    if (r.sendCanPickUp(self, type, sub, a, b) != 1) {
        // 0xc637ac..0xc637e4: failure block; only self-priority gets the tip.
        if (priority == self) r.priorityBlockheadCannotPickup(freeblock);
        return 0;
    }
    // 0xc62820..0xc6282c: needsRemoved nonzero rejects (no duplicate pickup).
    if (r.needsRemoved(freeblock) != 0) {
        if (priority == self) r.priorityBlockheadCannotPickup(freeblock);
        return 0;
    }
    // Currency-split / special-item path is not recovered; refuse conservatively.
    if (r.pendingPathUnresolved()) return 0;
    // 0xc63440..0xc63580: construct InventoryItem preserving all original fields.
    const Object dynamic = r.dynamicObjectSaveDict(freeblock);
    const Object item = r.makeInventoryItem(type, a, b, sub, dynamic);
    if (item == 0) {
        if (priority == self) r.priorityBlockheadCannotPickup(freeblock);
        return 0;
    }
    // 0xc635b4: addItemToInventory:flash:1; original does not branch on the
    // returned slot (used only as the recording payload below).
    const std::int32_t addSlot = r.sendAddItemFlash(self, item, 1);
    // 0xc635d8: freeblock setNeedsRemoved:1
    r.setNeedsRemoved(freeblock, 1);
    // 0xc63618..0xc6379c: indexed record branch; equal path records once and
    // both paths reach the success return.
    if (r.recordComparator(self, freeblock, item, addSlot) != 0) {
        r.recordIndexed(self, freeblock, item, addSlot);
    }
    // 0xc637a0: movw r0, #1 success
    return 1;
}
} // namespace recovered::inventory_pickup