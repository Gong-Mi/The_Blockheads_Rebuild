#pragma once
#include "inventory_capacity.h"
#include <cstdint>

namespace recovered::inventory_add {
using Object = inventory_capacity::Object;
using EnumerationState = inventory_capacity::EnumerationState;

// Portable receiver/runtime boundary, NOT a native ObjC memory overlay.
// Every method is mandatory: nil messaging, exceptions, mutation and identity must
// be provided by the real runtime. No vector inventory adapter is implied.
struct Runtime {
    virtual ~Runtime() = default;
    virtual Object readWorld(Object self) = 0; // DynamicObject.world +0x4; re-read per use
    virtual std::int8_t readIsNet(Object self) = 0; // DynamicObject.isNet +0x34
    virtual Object readInventoryItems(Object self) = 0; // Blockhead.inventoryItems +0x298
    virtual void writeInventoryChanged(Object self, std::uint32_t index, std::uint8_t) = 0;
    virtual void writeSubInventoryChanged(Object self, std::uint32_t index,
                                          std::uint32_t subIndex, std::uint8_t) = 0;
    virtual Object objectAtIndex(Object array, std::uint32_t index) = 0;
    virtual std::uint32_t count(Object array) = 0;
    virtual std::int32_t itemType(Object item) = 0;
    virtual std::uint16_t dataA(Object item) = 0;
    virtual std::uint16_t dataB(Object item) = 0;
    virtual Object subItems(Object item) = 0;
    virtual std::uint32_t enumerate(Object array, EnumerationState& state,
                                   Object* buffer, std::uint32_t capacity) = 0;
    virtual void enumerationMutation(Object array) = 0;
    virtual void addObject(Object array, Object item) = 0;
    virtual void insertObjectAtIndex(Object array, Object item, std::uint32_t index) = 0;
    virtual void addObjectsFromArray(Object destination, Object source) = 0;
    virtual void removeAllObjects(Object array) = 0;
    // Identifier is the proved CFString payload, not a newly inferred achievement.
    virtual void reportAchievementWithIdentifier(Object world, const char* identifier) = 0;
    virtual void addItemToFoundList(Object world, Object item) = 0;
    virtual Object uiManager(Object world) = 0;
    virtual void flashInventory(Object ui, std::int32_t index, std::int32_t subIndex,
                                Object blockhead, std::uint32_t color) = 0;
    virtual std::int32_t checkIfCanWarpInSecondBlockheadAfterItemAdded(
        Object self, std::int32_t initialType, std::uint16_t currentDataB) = 0;
    // Three distinct selectors: do not bypass dynamic overrides with static calls.
    virtual std::int32_t sendAddItemFlash(Object self, Object item, std::int8_t flash) = 0;
    virtual std::int32_t sendAddItemFlashDisableWarp(Object self, Object item,
                                std::int8_t flash, std::int8_t disableWarp) = 0;
    virtual std::int32_t sendAddItemFlashDisableWarpForceSlot(Object self, Object item,
                std::int8_t flash, std::int8_t disableWarp, std::int32_t forceSlot) = 0;
};
// All overloads return outer slot/index or -1; NEVER an accepted count.
std::int32_t addItemToInventory(Runtime&, Object self, Object item);
std::int32_t addItemToInventory(Runtime&, Object self, Object item, std::int8_t flash);
std::int32_t addItemToInventory(Runtime&, Object self, Object item, std::int8_t flash,
                               std::int8_t disableWarpCheck);
std::int32_t addItemToInventory(Runtime&, Object self, Object item, std::int8_t flash,
                               std::int8_t disableWarpCheck, std::int32_t forceSlotIndex);
}
