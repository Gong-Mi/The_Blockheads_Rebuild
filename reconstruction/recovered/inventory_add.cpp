#include "inventory_add.h"
#include "inventory_rules.h"
#include <cstring>

namespace recovered::inventory_add {
namespace rules = blockheads::recovered;
namespace {
// ARM counters wrap at 32 bits; keep their signed interpretation explicit.
std::int32_t signedWord(std::uint32_t word) {
    std::int32_t result;
    std::memcpy(&result, &word, sizeof result);
    return result;
}

// NSFastEnumeration's mutation baseline is captured once, not once per batch.
// Read items/mutations from state again after callbacks (including a returning
// mutation handler). Runtime owns the validity/lifetime of these pointers.
template<class Visit>
bool scan(Runtime& r, Object array, Visit visit) {
    EnumerationState state{};
    Object buffer[16];
    auto used = r.enumerate(array, state, buffer, 16);
    if (!used) return false;
    const auto mutation = *state.mutations;
    std::uint32_t index = 0;
    do {
        for (std::uint32_t j = 0; j < used; ++j, ++index) {
            if (*state.mutations != mutation) r.enumerationMutation(array);
            if (visit(state.items[j], index)) return true;
        }
        used = r.enumerate(array, state, buffer, 16);
    } while (used);
    return false;
}

// c5fe78..c60070 and c605fc..c607f4: ordered insert only for
// positive usageIncrementPerUse; ties stay before the new item.
void appendOrInsert(Runtime& r, Object stack, Object item, std::int32_t type) {
    if (rules::usageIncrementPerUse(type, 2, 0, 0) > 0) {
        for (std::uint32_t j = 0; j < r.count(stack); ++j) {
            const auto old = r.objectAtIndex(stack, j);
            const auto oldA = r.dataA(old);
            const auto newA = r.dataA(item);
            if (oldA > newA) {
                r.insertObjectAtIndex(stack, item, j);
                return;
            }
        }
    }
    r.addObject(stack, item);
}
}

// c5f904, c5f960, c5f9d8: preserve three distinct dynamic selectors.
std::int32_t addItemToInventory(Runtime& r, Object self, Object item) {
    return r.sendAddItemFlash(self, item, 0);
}
std::int32_t addItemToInventory(Runtime& r, Object self, Object item,
                                std::int8_t flash) {
    return r.sendAddItemFlashDisableWarp(self, item, flash, 0);
}
std::int32_t addItemToInventory(Runtime& r, Object self, Object item,
                                std::int8_t flash, std::int8_t disableWarp) {
    return r.sendAddItemFlashDisableWarpForceSlot(self, item, flash, disableWarp, -1);
}

// c5fa6c..c61c00. This is an object-runtime contract, not a 30-slot
// prototype adapter. All ItemType numbers below belong to the pinned ARM ELF.
std::int32_t addItemToInventory(Runtime& r, Object self, Object item,
                                std::int8_t flash, std::int8_t disableWarp,
                                std::int32_t forceSlot) {
    const auto initialType = r.itemType(item);
    if (!rules::itemTypeIsValidInventoryItem(initialType)) return -1;
    const auto liquid = rules::itemTypeIsLiquid(initialType);
    if (initialType == 0x117) {
        const auto world = r.readWorld(self);
        r.reportAchievementWithIdentifier(world, "grp.titanium");
    } else if (initialType == 0x105) {
        const auto world = r.readWorld(self);
        r.reportAchievementWithIdentifier(world, "grp.mj.platinum");
    }
    if (r.readIsNet(self) == 0) {
        const auto world = r.readWorld(self);
        r.addItemToFoundList(world, item);
    }
    const auto outer = [&](std::uint32_t i) {
        const auto inventory = r.readInventoryItems(self);
        return r.objectAtIndex(inventory, i);
    };
    const auto allowed = [&](std::int32_t i) { return forceSlot == -1 || forceSlot == i; };
    const auto finish = [&](std::uint32_t i, std::int32_t sub) {
        if (flash != 0) {
            const auto world = r.readWorld(self);
            const auto ui = r.uiManager(world);
            r.flashInventory(ui, signedWord(i), sub, self, 0);
        }
        if (disableWarp == 0) {
            const auto b = r.dataB(item);
            (void)r.checkIfCanWarpInSecondBlockheadAfterItemAdded(self, initialType, b);
        }
        return signedWord(i);
    };

    if (rules::itemTypeIsStackable(initialType, 0, 0)) {
        // Pass 1: matching occupied outer stack, c5fc64..c601e0.
        for (std::uint32_t i = 1; i < 8; ++i) {
            if (!allowed(i)) continue;
            const auto stack = outer(i);
            if (r.count(stack) == 0) continue;
            if (r.count(stack) >= 99) continue; // separate dynamic read
            const auto oldType = r.itemType(r.objectAtIndex(stack, 0));
            const auto newType = r.itemType(item);
            if (oldType != newType) continue;
            const auto oldB = r.dataB(r.objectAtIndex(stack, 0));
            const auto newB = r.dataB(item);
            if (!rules::itemTypeIsStackable(initialType, oldB, newB)) continue;
            appendOrInsert(r, stack, item, initialType);
            r.writeInventoryChanged(self, i, 1);
            return finish(i, -1);
        }
        // Pass 2: matching occupied carried-container stack, c601e0..c60a10.
        for (std::uint32_t i = 1; i < 8; ++i) {
            if (!allowed(i)) continue;
            const auto stack = outer(i);
            if (r.count(stack) != 1) continue;
            const auto bag = r.objectAtIndex(stack, 0);
            if (!rules::itemTypeSubItemsCanBeModifiedWhileCarried(r.itemType(bag))) continue;
            const auto sub = r.subItems(bag);
            const bool added = scan(r, sub, [&](Object target, std::uint32_t j) {
                if (!r.count(target)) return false;
                // Deliberately different call order/type source from pass 1.
                const auto type = r.itemType(item);
                const auto oldB = r.dataB(r.objectAtIndex(target, 0));
                const auto newB = r.dataB(item);
                if (!rules::itemTypeIsStackable(type, oldB, newB)) return false;
                const auto oldType = r.itemType(r.objectAtIndex(target, 0));
                const auto newType = r.itemType(item);
                if (oldType != newType) return false;
                if (r.count(target) >= 99) return false;
                appendOrInsert(r, target, item, initialType);
                if (signedWord(j) < 4) r.writeSubInventoryChanged(self, i, j, 1);
                finish(i, signedWord(j));
                return true;
            });
            if (added) return signedWord(i);
        }
    }

    // Pass 3: empty outer stack, c60a10..c60cb8.
    if (!liquid) {
        for (std::uint32_t i = 1; i < 8; ++i) {
            if (!allowed(i)) continue;
            const auto stack = outer(i);
            if (r.count(stack) != 0) continue;
            r.addObject(stack, item);
            r.writeInventoryChanged(self, i, 1);
            return finish(i, -1);
        }
    }

    // Pass 4: incoming container absorbs a whole outer stack, c60cb8..c61698.
    // No force-slot gate. Empty incoming subslots precede compatible occupied
    // subslots; the empty path has no 99-count test and never sorts the transfer.
    if (rules::itemTypeSubItemsCanBeModifiedWhileCarried(initialType)) {
        for (std::uint32_t i = 1; i < 8; ++i) {
            const auto stack = outer(i);
            if (!r.count(stack)) continue;
            const auto firstType = r.itemType(r.objectAtIndex(stack, 0));
            if (inventory_capacity::subItemCapacityAtC5EAA8(firstType) != 0) continue;
            const auto carries = rules::itemTypeCarriesLiquids(initialType);
            const auto currentType = r.itemType(r.objectAtIndex(stack, 0));
            if (carries != rules::itemTypeIsLiquid(currentType)) continue;
            Object destination = 0;
            auto sub = r.subItems(item);
            scan(r, sub, [&](Object candidate, std::uint32_t) {
                if (r.count(candidate) != 0) return false;
                destination = candidate;
                return true;
            });
            if (!destination) {
                sub = r.subItems(item); // second enumeration sends subItems again
                scan(r, sub, [&](Object candidate, std::uint32_t) {
                    if (!r.count(candidate)) return false;
                    const auto destType = r.itemType(r.objectAtIndex(candidate, 0));
                    const auto sourceType = r.itemType(r.objectAtIndex(stack, 0));
                    if (destType != sourceType) return false;
                    if (r.itemType(r.objectAtIndex(stack, 0)) == 0x67) {
                        const auto destB = r.dataB(r.objectAtIndex(candidate, 0));
                        const auto sourceB = r.dataB(r.objectAtIndex(stack, 0));
                        if (destB != sourceB) return false;
                    }
                    const auto destCount = r.count(candidate);
                    const auto sourceCount = r.count(stack);
                    if (std::uint32_t(destCount + sourceCount) > 99) return false;
                    destination = candidate;
                    return true;
                });
            }
            if (!destination) continue;
            r.addObjectsFromArray(destination, stack);
            r.removeAllObjects(stack);
            r.addObject(stack, item);
            r.writeInventoryChanged(self, i, 1);
            return finish(i, -1);
        }
    }

    // Pass 5: empty carried-container stack, c61698..c61ba4.
    // Unlike pass 2, forceSlot is ignored; liquid/carries is checked instead.
    for (std::uint32_t i = 1; i < 8; ++i) {
        const auto stack = outer(i);
        if (r.count(stack) != 1) continue;
        const auto bag = r.objectAtIndex(stack, 0);
        if (!rules::itemTypeSubItemsCanBeModifiedWhileCarried(r.itemType(bag))) continue;
        if (liquid != rules::itemTypeCarriesLiquids(r.itemType(bag))) continue;
        const auto sub = r.subItems(bag);
        const bool added = scan(r, sub, [&](Object target, std::uint32_t j) {
            if (r.count(target) != 0) return false;
            r.addObject(target, item);
            if (signedWord(j) < 4) r.writeSubInventoryChanged(self, i, j, 1);
            finish(i, signedWord(j));
            return true;
        });
        if (added) return signedWord(i);
    }
    return -1;
}
}
