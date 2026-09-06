#include "inventory_capacity.h"
#include "inventory_rules.h"

namespace recovered::inventory_capacity {
using namespace blockheads::recovered;

// 0xc5ea38..0xc5ea90: direct money predicate not owned by inventory_rules.
static bool itemTypeIsMoney(std::int32_t t) {
    return t == 0xa6 || t == 0xa7 || t == 0x104;
}

// 0xc5eaa8..0xc5ec34: all signed decision-tree leaves, not a guessed bag size.
std::int32_t subItemCapacityAtC5EAA8(std::int32_t t) {
    switch (t) {
    case 1: case 12: case 0xa1: case 0xcf: return 4;
    case 0x2d: return 2;
    case 0x413: case 0x429: case 0x430: case 0x432: case 0x450: return 16;
    default: return 0;
    }
}

// Three original fast-enumeration sites, each with fresh zeroed state and a
// 16-object buffer. Items/mutations pointers are re-read, including after a
// mutation callback returns. No snapshot/vector conversion is equivalent.
template<class Visit>
static bool anyEnumerated(Runtime& r, Object array, Visit visit) {
    EnumerationState state{};
    std::array<Object, 16> buffer; // original buffer was not zero-initialized
    std::uint32_t n = r.enumerate(array, state, buffer.data(), 16);
    if (n == 0) return false;
    const std::uint32_t baseline = *state.mutations;
    do {
        for (std::uint32_t i = 0; i < n; ++i) {
            if (*state.mutations != baseline) r.enumerationMutation(array);
            if (visit(state.items[i])) return true;
        }
        n = r.enumerate(array, state, buffer.data(), 16);
    } while (n != 0);
    return false;
}

// Distinct sends are intentional: objectAtIndex: and itemType are NOT cached.
static std::int32_t firstType(Runtime& r, Object stack) {
    return r.itemType(r.objectAtIndex(stack, 0));
}
static std::uint16_t firstB(Runtime& r, Object stack) {
    return r.dataB(r.objectAtIndex(stack, 0));
}
// 0xc5d968..0xc5dac8 and 0xc5defc..0xc5e05c.
static bool stackGate(Runtime& r, Object stack, std::int32_t t, std::uint16_t b) {
    if (firstType(r, stack) != t) {
        if (t != 0x12a) return false;
        if (!itemTypeIsMoney(firstType(r, stack))) return false;
    }
    return itemTypeIsStackable(t, firstB(r, stack), b);
}
// 0xc5dacc..0xc5dbe0 and 0xc5e060..0xc5e174.
static bool moneyOrOrdinaryFit(Runtime& r, Object stack, std::int32_t t,
                               std::uint16_t a, std::uint16_t b) {
    if (t != 0x12a) return true;
    switch (firstType(r, stack)) {
    case 0x104: return a > 0;
    case 0xa7: return a > 0 || b >= 100;
    case 0xa6: return a > 0 || b > 0;
    default: return false;
    }
}

// -[Blockhead canPickUpItemOfType:subItems:] @0xc5d748.
std::int32_t canPickUpItemOfType(Runtime& r, Object self, std::int32_t t, Object sub) {
    return r.sendCanPickUp(self, t, sub, 0, 0);
}

// -[Blockhead canPickUpItemOfType:subItems:dataA:dataB:] @0xc5d7b8.
std::int32_t canPickUpItemOfType(Runtime& r, Object self, std::int32_t t,
                               Object incomingSub, std::uint16_t a, std::uint16_t b) {
    // 0xc5d7ec..0xc5d864: distinct 0 classification, not exhausted=-1.
    if (!itemTypeIsValidInventoryItem(t)) return 0;
    if (r.worldUIDragging(r.readWorld(self)) != 0) return 0;
    const bool liquid = itemTypeIsLiquid(t); // verified original helper always false
    for (std::uint32_t index = 1; index < 8; ++index) { // 0xc5d880,0xc5d888,0xc5e968
        const Object stack = r.objectAtIndex(r.readInventoryItems(self), index);
        if (!liquid && r.count(stack) == 0) return 1; // 0xc5d8dc..0xc5d924
        if (!liquid && r.count(stack) < 99 && stackGate(r, stack, t, b)) {
            if (moneyOrOrdinaryFit(r, stack, t, a, b)) return 1;
            // A passed stack gate with insufficient money skips the else-bag
            // branch, going directly to the incoming-container branch.
        } else { // 0xc5dbe4..0xc5e20c: existing container
            if (r.count(stack) != 0 &&
                itemTypeSubItemsCanBeModifiedWhileCarried(firstType(r, stack))) {
                const Object contents = r.subItems(r.objectAtIndex(stack, 0));
                if (r.count(contents) > 0 &&
                    itemTypeCarriesLiquids(firstType(r, stack)) == liquid) {
                    if (anyEnumerated(r, contents, [&](Object nestedStack) {
                        if (r.count(nestedStack) == 0) return true;
                        // ARM preserves this redundant unsigned index>0 gate.
                        if (index > 0 && r.count(nestedStack) < 99 &&
                            stackGate(r, nestedStack, t, b)) {
                            return moneyOrOrdinaryFit(r, nestedStack, t, a, b);
                        }
                        return false;
                    })) return 1;
                }
            }
        }
        // 0xc5e210..0xc5e95c: move an existing stack into an incoming bag.
        if (itemTypeSubItemsCanBeModifiedWhileCarried(t) && r.count(stack) > 0 &&
            subItemCapacityAtC5EAA8(firstType(r, stack)) == 0) {
            const bool carries = itemTypeCarriesLiquids(t);
            const bool existingLiquid = itemTypeIsLiquid(firstType(r, stack));
            if (carries != existingLiquid) continue;
            if (incomingSub == 0 || r.count(incomingSub) == 0) return 1;
            // First pass looks only for an empty stack; second pass enumerates
            // afresh. This is not a single combined scan.
            if (anyEnumerated(r, incomingSub, [&](Object s) {
                    return r.count(s) == 0;
                })) return 1;
            if (anyEnumerated(r, incomingSub, [&](Object s) {
                if (r.count(s) == 0) return false;
                const auto incomingType = firstType(r, s);
                const auto existingType = firstType(r, stack);
                if (incomingType != existingType) return false;
                if (firstType(r, stack) == 0x67) {
                    const auto incomingB = firstB(r, s);
                    const auto existingB = firstB(r, stack);
                    if (incomingB != existingB) return false;
                }
                const auto incomingCount = r.count(s);
                const auto existingCount = r.count(stack);
                // ARM add then unsigned cmp: preserve uint32 wraparound.
                return std::uint32_t(incomingCount + existingCount) <= 99;
            })) return 1;
        }
    }
    return -1; // 0xc5e97c mvn r0,#0, NOT bool false
}
}
