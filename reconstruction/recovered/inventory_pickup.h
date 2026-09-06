#pragma once
#include "inventory_capacity.h"
#include <cstdint>

namespace recovered::inventory_pickup {
using Object = inventory_capacity::Object;

// Portable receiver/runtime boundary, NOT an ObjC memory overlay. Every method
// is mandatory: nil messaging, selector identity, field re-reads and object
// lifetime must be supplied by the real runtime.
struct Runtime {
    virtual ~Runtime() = default;
    // Blockhead entry: DynamicObject.world ivar at +0x4, then worldUIDragging.
    virtual Object readWorld(Object self) = 0;
    virtual std::int8_t worldUIDragging(Object world) = 0;
    // INLINE Blockhead.state storage at self+0x38 (not *(self+0x38)).
    // Return the storage address; original reads signed bytes at +0x60/+0x68.
    virtual Object stateStorageAddress(Object self) = 0;
    virtual std::int8_t stateGateA(Object state) = 0;
    virtual std::int8_t stateGateB(Object state) = 0;
    // priorityBlockhead for the freeblock; zero is ObjC nil.
    virtual Object priorityBlockhead(Object freeblock) = 0;
    // Intentional-gate region 0xc61d00..0xc61d84: with intentional==0, a set
    // ignoringFreeblocksDueToDrop byte or nonzero meditating requires
    // priority==self to continue.
    virtual std::int8_t ignoringFreeblocksDueToDrop(Object self) = 0;
    virtual std::int8_t meditating(Object self) = 0;
    // Freeblock ordinary fields (each is a distinct selector read).
    virtual std::int32_t itemType(Object freeblock) = 0;
    virtual Object subItems(Object freeblock) = 0;
    virtual std::uint16_t dataA(Object freeblock) = 0;
    virtual std::uint16_t dataB(Object freeblock) = 0;
    virtual std::int8_t needsRemoved(Object freeblock) = 0;
    virtual Object dynamicObjectSaveDict(Object freeblock) = 0;
    // Dynamic selectors; do not bypass overrides with static calls.
    virtual std::int32_t sendCanPickUp(Object self, std::int32_t type, Object sub,
                                       std::uint16_t a, std::uint16_t b) = 0;
    virtual std::int32_t sendAddItemFlash(Object self, Object item, std::int8_t flash) = 0;
    virtual void setNeedsRemoved(Object freeblock, std::int8_t value) = 0;
    virtual void priorityBlockheadCannotPickup(Object freeblock) = 0;
    // Original initWithType:dataA:dataB:subItems:dynamicObjectSaveDict: result.
    virtual Object makeInventoryItem(std::int32_t type, std::uint16_t a, std::uint16_t b,
                                     Object sub, Object dynamic) = 0;
    // Original 0xc63664 comparator: nonzero selects the recording branch.
    virtual std::int32_t recordComparator(Object self, Object freeblock, Object item,
                                          std::int32_t addSlot) = 0;
    // Recording callback executed only on the equal branch, once.
    virtual void recordIndexed(Object self, Object freeblock, Object item,
                               std::int32_t addSlot) = 0;
    // NOT YET RECOVERED paths (original 0xc61d..0xc626 ownership/container and
    // 0xc629..0xc634 currency-split regions). The caller returns zero and no
    // side effect is performed on these paths; never claim they are complete.
    virtual bool pendingPathUnresolved() = 0;
};

// Original return is signed char: 1 = picked up, 0 = rejected. Caller MUST NOT
// treat it as an accepted item count or normalize to bool.
std::int8_t pickupFreeblockIfPossible(Runtime&, Object self, Object freeblock,
                                      std::int8_t intentional);
}