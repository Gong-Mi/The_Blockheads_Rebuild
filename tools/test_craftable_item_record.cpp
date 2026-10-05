// Contract test for the recovered CraftableItem record.
#include "craftable_item_record.h"

#include <cassert>
#include <cstddef>
#include <cstdio>

using namespace blockheads::recovered;

int main() {
    assert(sizeof(CraftableItemRecord) == 124);

    // the layout the encoding implies, field by field
    assert(offsetof(CraftableItemRecord, f0) == 0);
    assert(offsetof(CraftableItemRecord, f1) == 4);
    assert(offsetof(CraftableItemRecord, f2) == 8);
    assert(offsetof(CraftableItemRecord, f3) == 40);
    assert(offsetof(CraftableItemRecord, f4) == 72);
    assert(offsetof(CraftableItemRecord, f5) == 76);
    assert(offsetof(CraftableItemRecord, f6) == 80);
    assert(offsetof(CraftableItemRecord, f7) == 84);
    assert(offsetof(CraftableItemRecord, f8) == 86);
    assert(offsetof(CraftableItemRecord, f9) == 88);
    assert(offsetof(CraftableItemRecord, f10) == 92);

    // the array fields are eight wide and the two narrow fields really are two bytes
    assert(sizeof(CraftableItemRecord::f2) == 32);
    assert(sizeof(CraftableItemRecord::f3) == 32);
    assert(sizeof(CraftableItemRecord::f10) == 32);
    assert(sizeof(CraftableItemRecord::f7) == 2);
    assert(sizeof(CraftableItemRecord::f8) == 2);
    // the two narrow fields share one aligned 4-byte slot, which is why f9 lands on 88
    assert(offsetof(CraftableItemRecord, f7) + 2 == offsetof(CraftableItemRecord, f8));
    assert(offsetof(CraftableItemRecord, f9) == 88);

    std::puts("craftable-item-record: PASS");
    return 0;
}
