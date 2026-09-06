// Local behavioral fixture for the recovered pickup ordinary path. NOT a
// production Foundation replacement and NOT original-app runtime coverage.
#include "../reconstruction/recovered/inventory_pickup.h"
#include "../reconstruction/recovered/inventory_rules.h"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <map>
#include <string>
#include <vector>
using namespace recovered::inventory_pickup;
namespace rules = blockheads::recovered;

struct Fixture final : Runtime {
    Object self = 1, freeblock = 2, madeItem = 3;
    std::int8_t gateA = 0, gateB = 0;
    Object priority = 0;
    std::int32_t type = 20, canPickUp = 1;
    std::uint16_t a = 0xf123, b = 0x8123;
    Object sub = 0, dynamic = 0;
    std::int8_t needs = 0;
    bool unresolved = false;
    std::int32_t comparator = 1, addResult = 7;
    int tipCalls = 0, addCalls = 0, removeCalls = 0, recordCalls = 0, itemCalls = 0;
    std::vector<std::string> events;
    std::int32_t madeType = -1; std::uint16_t madeA = 0, madeB = 0;
    Object madeSub = 0, madeDynamic = 0; std::int8_t madeFlash = -1;

    std::int8_t entryGateA(Object) override { events.push_back("gateA"); return gateA; }
    std::int8_t entryGateB(Object) override { events.push_back("gateB"); return gateB; }
    Object priorityBlockhead(Object) override { events.push_back("priority"); return priority; }
    std::int32_t itemType(Object f) override { assert(f == freeblock); events.push_back("itemType"); return type; }
    Object subItems(Object f) override { assert(f == freeblock); events.push_back("subItems"); return sub; }
    std::uint16_t dataA(Object f) override { assert(f == freeblock); events.push_back("dataA"); return a; }
    std::uint16_t dataB(Object f) override { assert(f == freeblock); events.push_back("dataB"); return b; }
    std::int8_t needsRemoved(Object f) override { assert(f == freeblock); events.push_back("needsRemoved"); return needs; }
    Object dynamicObjectSaveDict(Object f) override { assert(f == freeblock); events.push_back("dynamic"); return dynamic; }
    std::int32_t sendCanPickUp(Object s, std::int32_t t, Object su, std::uint16_t aa, std::uint16_t bb) override {
        assert(s == self && t == type && su == sub && aa == a && bb == b);
        events.push_back("canPickUp"); return canPickUp;
    }
    std::int32_t sendAddItemFlash(Object s, Object i, std::int8_t f) override {
        assert(s == self && i == madeItem && f == 1); ++addCalls;
        events.push_back("addItem"); madeFlash = f; return addResult;
    }
    void setNeedsRemoved(Object f, std::int8_t v) override {
        assert(f == freeblock && v == 1); ++removeCalls; events.push_back("setNeedsRemoved");
    }
    void priorityBlockheadCannotPickup(Object f) override {
        assert(f == freeblock); ++tipCalls; events.push_back("tip");
    }
    Object makeInventoryItem(std::int32_t t, std::uint16_t aa, std::uint16_t bb, Object s, Object d) override {
        ++itemCalls; madeType = t; madeA = aa; madeB = bb; madeSub = s; madeDynamic = d;
        events.push_back("makeItem"); return madeItem;
    }
    std::int32_t recordComparator(Object s, Object f, Object i, std::int32_t addSlot) override {
        assert(s == self && f == freeblock && i == madeItem && addSlot == addResult);
        events.push_back("recordComparator"); return comparator;
    }
    void recordIndexed(Object s, Object f, Object i, std::int32_t addSlot) override {
        assert(s == self && f == freeblock && i == madeItem && addSlot == addResult);
        ++recordCalls; events.push_back("recordIndexed");
    }
    bool pendingPathUnresolved() override { events.push_back("pending"); return unresolved; }
    std::int8_t run(std::int8_t intentional = 0) {
        return pickupFreeblockIfPossible(*this, self, freeblock, intentional);
    }
};

int main() {
    {   // gate bytes reject before any other read.
        Fixture f; f.gateA = -1;
        assert(f.run() == 0); assert((f.events == std::vector<std::string>{"gateA"}));
        Fixture g; g.gateB = 1;
        assert(g.run() == 0); assert((g.events == std::vector<std::string>{"gateA", "gateB"}));
    }
    {   // non-nil foreign priority rejects, intentional does not bypass.
        Fixture f; f.priority = 99;
        assert(f.run(1) == 0); assert(f.tipCalls == 0 && f.addCalls == 0 && f.removeCalls == 0);
    }
    {   // ordinary success path: exact message order and preserved fields.
        Fixture f; Object d = 0x1234ull;
        f.dynamic = d; f.sub = 88;
        assert(f.run() == 1);
        assert(f.itemCalls == 1 && f.madeType == 20 && f.madeA == 0xf123 && f.madeB == 0x8123);
        assert(f.madeSub == 88 && f.madeDynamic == d && f.madeFlash == 1);
        assert(f.addCalls == 1 && f.removeCalls == 1 && f.recordCalls == 1 && f.tipCalls == 0);
        assert((f.events == std::vector<std::string>{
            "gateA","gateB","priority","itemType","subItems","dataA","dataB",
            "canPickUp","needsRemoved","pending","dynamic","makeItem","addItem",
            "setNeedsRemoved","recordComparator","recordIndexed"}));
    }
    {   // canPickUp != 1 rejects without insertion; self priority gets tip.
        Fixture f; f.canPickUp = 2; f.priority = f.self;
        assert(f.run() == 0); assert(f.addCalls == 0 && f.removeCalls == 0 && f.recordCalls == 0);
        assert(f.tipCalls == 1 && f.events.back() == "tip");
    }
    {   // canPickUp == 0 (invalid/dragging) also rejects.
        Fixture f; f.canPickUp = 0;
        assert(f.run() == 0); assert(f.addCalls == 0 && f.tipCalls == 0);
    }
    {   // needsRemoved nonzero rejects duplicate pickup.
        Fixture f; f.needs = 1; f.priority = f.self;
        assert(f.run() == 0); assert(f.addCalls == 0 && f.removeCalls == 0 && f.tipCalls == 1);
    }
    {   // comparator zero skips the recording callback but still succeeds.
        Fixture f; f.comparator = 0;
        assert(f.run() == 1); assert(f.recordCalls == 0 && f.removeCalls == 1);
    }
    {   // unresolved pending path refuses without side effects.
        Fixture f; f.unresolved = true;
        assert(f.run() == 0); assert(f.addCalls == 0 && f.removeCalls == 0 && f.recordCalls == 0);
    }
    {   // nil freeblock refuses.
        Fixture f;
        assert(pickupFreeblockIfPossible(f, f.self, 0, 0) == 0);
        assert(f.addCalls == 0);
    }
    {   // failed item construction rejects; self priority gets tip.
        Fixture f; f.madeItem = 0; f.priority = f.self;
        assert(f.run() == 0); assert(f.tipCalls == 1 && f.addCalls == 0);
    }
    {   // repeated pickup after removal is blocked by needsRemoved gate.
        Fixture f; f.canPickUp = -1;
        assert(f.run() == 0 && f.tipCalls == 0);
    }
    std::cout << "PASS inventory pickup: ordinary path, gates, rejection and tip order\n";
    return 0;
}