#include "../reconstruction/recovered/inventory_item.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <functional>
using namespace blockheads::recovered;
namespace {
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
struct Opaque final : InventoryRuntimeObject { int marker = 73; };
// Contract spy only: these tokens are NOT claimed to be gzip or a plist codec.
struct Runtime final : InventoryRuntime {
    bool initOK = true;
    int initializations = 0, inflates = 0, decodes = 0, encodes = 0, deflates = 0;
    InventoryTail decoded, encoded;
    InventoryBytes inflatedInput;
    std::vector<std::string> events;
    bool initializeItem() override { ++initializations; return initOK; }
    std::array<std::uint8_t, 8> headerStackImage(InventoryHeaderUse use) override {
        if (use == InventoryHeaderUse::Load) return {0x34,0x12,0x78,0x56,0xbc,0x9a,0xde,0xf0};
        return {0,0,0,0,0,0,0,0xa5};
    }
    std::optional<InventoryBytes> gzipInflate(const InventoryBytes& b) override {
        ++inflates; events.push_back("inflate"); inflatedInput=b; return InventoryBytes{0xca};
    }
    InventoryTail propertyListDecode(const std::optional<InventoryBytes>& b, std::uint32_t options) override {
        ++decodes; events.push_back("decode"); check(b == InventoryBytes{0xca} && options == 0,"decode args"); return decoded;
    }
    std::optional<InventoryBytes> propertyListEncode(const InventoryTail& t, std::uint32_t format, std::uint32_t options) override {
        ++encodes; events.push_back("encode"); check(format==100 && options==0,"XML format 100/options 0"); encoded=t; return InventoryBytes{0xcb};
    }
    std::optional<InventoryBytes> gzipDeflate(const std::optional<InventoryBytes>& b) override {
        ++deflates; events.push_back("deflate"); check(b == InventoryBytes{0xcb},"deflate input"); return InventoryBytes{0xcc,0xdd};
    }
    void appendData(InventoryBytes& dst, const std::optional<InventoryBytes>& b) override {
        events.push_back("append"); if (!b) throw std::invalid_argument("nil append external boundary");
        dst.insert(dst.end(),b->begin(),b->end());
    }
};
InventoryItem::Ptr item(Runtime& r, int type = 0) { return InventoryItem::initWithType(r,type,0x2345,0x6789,nullptr,nullptr); }
InventoryBytes header(unsigned type) { return {static_cast<std::uint8_t>(type),static_cast<std::uint8_t>(type>>8),0x45,0x23,0x89,0x67,0xfe,0xff}; }
template<class F> void rangeThrows(F f) { bool thrown=false; try { f(); } catch(const std::out_of_range&) { thrown=true; } check(thrown,"index==count must reach objectAtIndex failure"); }
}
int main() {
    int passed=0;
    auto test=[&](const char* name, const std::function<void()>& f) {
        try { f(); ++passed; std::cout << "PASS " << name << '\n'; }
        catch(const std::exception& e) { std::cerr << "FAIL " << name << ": " << e.what() << '\n'; throw; }
    };
    try {
        test("slot helper all numeric cases/default", [] {
            check(InventoryItem::subItemSlotCount(0x429)==16,"original @ac5c40/ac5cac: type 0x429 requires 16 slots");
            for (int t=-1;t<=0x451;++t) {
                int expected=0;
                if(t==1 || t==12 || t==161 || t==207) expected=4;
                if(t==45) expected=2;
                if(t==0x413 || t==0x429 || t==0x430 || t==0x432 || t==0x450) expected=16;
                check(InventoryItem::subItemSlotCount(t)==expected,"slot table/default mismatch");
            }
        });
        test("init preserves fields and opaque identity; no-slot ignores input", [] {
            Runtime r; auto d=std::make_shared<Opaque>(); auto input=std::make_shared<InventoryItem::Slots>();
            input->push_back(std::make_shared<InventoryItem::Slot>());
            auto x=InventoryItem::initWithType(r,-7,0xffff,0x8001,input,d);
            check(x->itemType()==-7 && x->dataA()==0xffff && x->dataB()==0x8001,"fields");
            check(x->dynamicObjectSaveDict()==d && !x->subItems() && x->selectedSubItemIndex()==0,"identity/defaults");
        });
        test("slot containers copied, child identities shared, missing padded, extra ignored", [] {
            Runtime r; auto child=item(r); auto source=std::make_shared<InventoryItem::Slots>();
            auto slot=std::make_shared<InventoryItem::Slot>(); slot->push_back(child); source->push_back(slot);
            auto x=InventoryItem::initWithType(r,45,1,2,source,nullptr);
            check(x->subItems()->size()==2 && x->subItems()->at(1)->empty(),"missing slot padding");
            check(x->subItems()->at(0)!=slot && x->subItems()->at(0)->at(0)==child,"shallow child copy");
            slot->clear(); check(x->subItems()->at(0)->size()==1,"separate mutable slot");
            source->resize(20,slot); auto y=InventoryItem::initWithType(r,45,1,2,source,nullptr);
            check(y->subItems()->size()==2,"extra inputs ignored");
        });
        test("super init nil exits before initialization", [] {
            Runtime r; r.initOK=false;
            check(!item(r) && !InventoryItem::initWithSaveData(r,{1}),"nil factory");
            check(r.inflates==0 && r.decodes==0,"nil early return");
        });
        test("getters setters preserve raw widths without clamping", [] {
            Runtime r; auto x=item(r,1); x->setDataA(65535); x->setDataB(32768); x->setSelectedSubItemIndex(255);
            check(x->dataA()==65535 && x->dataB()==32768 && x->selectedSubItemIndex()==255,"scalar accessors");
        });
        test("save 8-byte LE header, type truncation, external uninitialized byte", [] {
            Runtime r; auto x=item(r,0x12345678); x->setSelectedSubItemIndex(0xfe);
            check(x->saveData(r)==InventoryBytes({0x78,0x56,0x45,0x23,0x89,0x67,0xfe,0xa5}),"packed header");
            check(r.encodes==0,"no tail for plain item");
        });
        test("empty container serializes without s or codec", [] {
            Runtime r; auto x=item(r,1); check(x->saveData(r).size()==8 && r.encodes==0,"all-empty slots omitted");
        });
        test("dynamic nonnil identity produces d even empty opaque object", [] {
            Runtime r; auto d=std::make_shared<Opaque>(); auto x=InventoryItem::initWithType(r,1,0,0,nullptr,d);
            check(x->saveData(r).size()==10,"compressed extension");
            check(r.encoded.dynamicObject==d && !r.encoded.subItems,"d only");
            check(r.events==std::vector<std::string>({"encode","deflate","append"}),"encoding order");
        });
        test("nonempty slot recursively saves all slots in order", [] {
            Runtime r; auto x=item(r,45); x->subItems()->at(1)->push_back(item(r,99));
            auto bytes=x->saveData(r); check(bytes.size()==10,"tail appended");
            check(r.encoded.subItems && r.encoded.subItems->size()==2,"all slot positions");
            check(r.encoded.subItems->at(0).empty() && r.encoded.subItems->at(1).at(0).at(0)==99,"nested child bytes");
        });
        test("load full header no tail and absent s produces empty slots", [] {
            Runtime r; auto x=InventoryItem::initWithSaveData(r,header(45));
            check(x->itemType()==45 && x->dataA()==0x2345 && x->dataB()==0x6789 && x->selectedSubItemIndex()==254,"load fields");
            check(x->subItems()->size()==2 && x->subItems()->at(0)->empty() && r.inflates==0,"missing tail");
        });
        test("short load uses explicit missing stack bytes, never invented zero fill", [] {
            Runtime r; auto x=InventoryItem::initWithSaveData(r,{0x56});
            check(x->itemType()==0x1256 && x->dataA()==0x5678 && x->dataB()==0x9abc && x->selectedSubItemIndex()==0xde,"short original indeterminacy");
        });
        test("load extension inflate then plist; d retained; recursive child load", [] {
            Runtime r; auto d=std::make_shared<Opaque>(); r.decoded.dynamicObject=d;
            r.decoded.subItems=InventorySavedSlots{{},{header(7)}}; auto bytes=header(45); bytes.push_back(0x91);
            auto x=InventoryItem::initWithSaveData(r,bytes);
            check(x->dynamicObjectSaveDict()==d && x->subItems()->at(1)->at(0)->itemType()==7,"recursive load");
            check(r.inflatedInput==InventoryBytes{0x91} && r.events==std::vector<std::string>({"inflate","decode"}),"tail boundary/order");
        });
        test("present short s differs from absent s: out-of-range retained", [] {
            Runtime r; r.decoded.subItems=InventorySavedSlots{}; auto bytes=header(45); bytes.push_back(1);
            rangeThrows([&] { InventoryItem::initWithSaveData(r,bytes); });
        });
        test("slot update mutates same slot and recursively creates new items", [] {
            Runtime r; auto x=item(r,45); auto slot=x->subItems()->at(0); slot->push_back(item(r,8));
            x->updateSubItemSlot(r,{header(19),header(20)},0);
            check(slot==x->subItems()->at(0) && slot->size()==2 && slot->at(0)->itemType()==19,"clear then load/add");
            auto b=x->subItemSlotDataAtIndex(r,0); check(b && b->size()==2 && b->at(1).at(0)==20,"slot serialization");
        });
        test("unsigned strict-less bounds preserve negative/greater/equal cases", [] {
            Runtime r; auto x=item(r,45);
            check(!x->subItemSlotDataAtIndex(r,-1) && !x->subItemSlotDataAtIndex(r,3),"out-of-range nil");
            x->updateSubItemSlot(r,{header(1)},-1); x->updateSubItemSlot(r,{header(1)},3);
            rangeThrows([&] { x->subItemSlotDataAtIndex(r,2); });
            rangeThrows([&] { x->updateSubItemSlot(r,{},2); });
        });
        test("nil subItems index zero follows nil messaging, not array exception", [] {
            Runtime r; auto x=item(r); auto b=x->subItemSlotDataAtIndex(r,0);
            check(b && b->empty(),"nil slot exports empty mutable array");
            int before=r.initializations; x->updateSubItemSlot(r,{header(7)},0);
            check(r.initializations==before+1 && !x->subItems(),"nil target still constructs child then discards");
        });
        test("failed recursive initialization clears target before throwing", [] {
            Runtime r; auto x=item(r,45); auto slot=x->subItems()->at(0);
            slot->push_back(item(r,8)); r.initOK=false;
            bool thrown=false;
            try { x->updateSubItemSlot(r,{header(7)},0); }
            catch(const std::invalid_argument&) { thrown=true; }
            check(thrown && slot->empty(),"clear precedes alloc/init and addObject:nil failure");
        });
        test("every short-header length preserves only uncopied stack bytes", [] {
            for(std::size_t n=0;n<8;++n) {
                Runtime r; auto expected=r.headerStackImage(InventoryHeaderUse::Load);
                const InventoryBytes input{0x56,0x34,0x12,0x78,0x9a,0xbc,0xf1,0xf2};
                for(std::size_t i=0;i<n;++i) expected[i]=input[i];
                auto x=InventoryItem::initWithSaveData(r,InventoryBytes(input.begin(),input.begin()+n));
                check(x->itemType()==(expected[0]|(expected[1]<<8)),"partial type");
                check(x->dataA()==(expected[2]|(expected[3]<<8)),"partial A");
                check(x->dataB()==(expected[4]|(expected[5]<<8)),"partial B");
                check(x->selectedSubItemIndex()==expected[6] && r.inflates==0,"partial selected/no tail");
            }
        });
    } catch(...) { return 1; }
    std::cout << "InventoryItem: " << passed << " behavioral cases PASS (Foundation boundary spy; no original-runtime differential)\n";
}
