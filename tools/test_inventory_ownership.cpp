#include "../reconstruction/recovered/inventory_ownership.h"
#include <cassert>
#include <cstdint>
#include <iostream>
using namespace blockheads::recovered::ownership;
int main() {
    assert(itemTypeRequiresOwnershipToRemove(0x429) == 1);
    assert(itemTypeRequiresOwnershipToRemove(0x428) == 0);
    assert(itemTypeRequiresOwnershipToRemove(0xa5) == 1);
    assert(itemTypeRequiresOwnershipToRemove(0xa6) == 0);
    assert(workbenchKindForItemType(0xf) == 3);
    assert(workbenchKindForItemType(0x86) == 13);
    assert(workbenchKindForItemType(0x8b) == 13);
    assert(workbenchKindForItemType(0x8c) == 0);
    assert(itemTypeIsWorkbench(0xf) == 1);
    assert(itemTypeIsTorch(0x11) == 1);
    assert(itemTypeIsTorch(0x12) == 0);
    assert(itemTypeIsColumn(0x14c) == 1);
    assert(itemTypeIsStairs(0x14c) == 0);
    assert(itemTypeIsStairs(0x14d) == 1);
    assert(itemTypeIsColumn(0x14d) == 0);
    assert(itemTypeIsPainting(0xd4) == 1);
    assert(itemTypeIsPainting(0xdc) == 1);
    assert(itemTypeIsPainting(0xdd) == 0);
    for (auto type : {INT32_MIN, -65536, -1, 0, 65536, INT32_MAX}) {
        assert(workbenchKindForItemType(type) == 0);
        assert(itemTypeRequiresOwnershipToRemove(type) == 0);
    }
    std::cout << "PASS ownership helpers: original IDs, boundaries, dependency chain\n";
}
