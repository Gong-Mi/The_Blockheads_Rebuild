// Actual recovered Item -> capacity -> add -> plain Item bytes composition.
// Object arrays, world effects and NSObject success are explicit test boundaries;
// this is NOT an Android Player adapter or a Foundation implementation.
#include "inventory_add_fixture.h"
#include "../reconstruction/recovered/inventory_item.h"
namespace items = blockheads::recovered;
namespace capacity = recovered::inventory_capacity;

struct HeaderRuntime final : items::InventoryRuntime {
    bool initializeItem() override { return true; }
    std::array<std::uint8_t,8> headerStackImage(items::InventoryHeaderUse) override {
        return {0,0,0,0,0,0,0,0xa5}; // supplied stack byte, NOT a version/default field
    }
    std::optional<items::InventoryBytes> gzipInflate(const items::InventoryBytes&) override { throw std::logic_error("outside plain-header scenario"); }
    items::InventoryTail propertyListDecode(const std::optional<items::InventoryBytes>&,std::uint32_t) override { throw std::logic_error("outside plain-header scenario"); }
    std::optional<items::InventoryBytes> propertyListEncode(const items::InventoryTail&,std::uint32_t,std::uint32_t) override { throw std::logic_error("outside plain-header scenario"); }
    std::optional<items::InventoryBytes> gzipDeflate(const std::optional<items::InventoryBytes>&) override { throw std::logic_error("outside plain-header scenario"); }
    void appendData(items::InventoryBytes&,const std::optional<items::InventoryBytes>&) override { throw std::logic_error("outside plain-header scenario"); }
};
struct LiveItems final : Fixture {
    std::map<Object,items::InventoryItem::Ptr> typed;
    std::int32_t itemType(Object o) override { return typed.count(o)?typed.at(o)->itemType():Fixture::itemType(o); }
    std::uint16_t dataA(Object o) override { return typed.count(o)?typed.at(o)->dataA():Fixture::dataA(o); }
    std::uint16_t dataB(Object o) override { return typed.count(o)?typed.at(o)->dataB():Fixture::dataB(o); }
};
struct CapacityAdapter final : capacity::Runtime {
    explicit CapacityAdapter(LiveItems& f):f(f) {}
    LiveItems& f;
    Object readWorld(Object s) override { return f.readWorld(s); }
    Object readInventoryItems(Object s) override { return f.readInventoryItems(s); }
    std::int8_t worldUIDragging(Object w) override { assert(w==f.world); return 0; }
    Object objectAtIndex(Object a,std::uint32_t n) override { return f.objectAtIndex(a,n); }
    std::uint32_t count(Object a) override { return f.count(a); }
    std::int32_t itemType(Object a) override { return f.itemType(a); }
    std::uint16_t dataB(Object a) override { return f.dataB(a); }
    Object subItems(Object a) override { return f.subItems(a); }
    std::uint32_t enumerate(Object a,capacity::EnumerationState& s,Object* b,std::uint32_t n) override { return f.enumerate(a,s,b,n); }
    void enumerationMutation(Object a) override { f.enumerationMutation(a); }
    std::int32_t sendCanPickUp(Object s,std::int32_t t,Object sub,std::uint16_t a,std::uint16_t b) override {
        return capacity::canPickUpItemOfType(*this,s,t,sub,a,b);
    }
};
int main() {
    HeaderRuntime runtime;
    auto actual=items::InventoryItem::initWithType(runtime,20,0xf123,0x8123,nullptr,nullptr);
    assert(actual);
    LiveItems f;f.typed[f.item]=actual;CapacityAdapter adapter(f);
    assert(capacity::canPickUpItemOfType(adapter,f.self,actual->itemType(),0,actual->dataA(),actual->dataB())==1);
    assert(recovered::inventory_add::addItemToInventory(f,f.self,f.item,1,0,-1)==1);
    assert(f.nodes.at(f.outer(1)).values==std::vector<Object>{f.item});
    auto stored=f.typed.at(f.nodes.at(f.outer(1)).values.front());
    assert(stored==actual && stored->dataA()==0xf123 && stored->dataB()==0x8123);
    assert(f.saw("changed:1") && f.saw("flash:1:-1") && f.saw("warp:20:"+std::to_string(actual->dataB())));
    const auto bytes=stored->saveData(runtime);
    auto loaded=items::InventoryItem::initWithSaveData(runtime,bytes);
    assert(loaded->itemType()==20 && loaded->dataA()==0xf123 && loaded->dataB()==0x8123);
    assert(loaded->saveData(runtime)==bytes);

    LiveItems full;full.fill();full.typed[full.item]=actual;CapacityAdapter noSpace(full);
    assert(capacity::canPickUpItemOfType(noSpace,full.self,20,0,actual->dataA(),actual->dataB())==-1);
    // Classification is not an accepted count, and the freeblock caller must
    // check ==1; no insertion/removal is synthesized on exhausted classification.
    for(int i=1;i<8;++i) assert(full.nodes.at(full.outer(i)).values.size()==99);
    assert(!full.saw("found:3"));
    std::cout<<"PASS recovered inventory composition: real item/capacity/add/plain bytes; synthetic world/arrays\n";
}
