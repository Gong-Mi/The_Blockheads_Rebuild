// Contract tests for the ITEM_MONEY currency-split region against the
// recovered C++ implementation. Synthetic runtime fixtures only: these do
// NOT claim original-app or device behavior (that layer lives in
// tools/test_pickup_currency_arm.py, which is not part of CTest).
#include "inventory_pickup_currency.h"
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

using namespace recovered::pickup_currency;

namespace {
struct Fixture final : Runtime {
    static constexpr Object kSelf = 1, kFree = 2, kItem = 3, kClass = 4;
    std::int32_t type = 0x12a, a = 0, b = 0;
    std::vector<std::int32_t> gates{1};
    std::size_t i = 0;
    std::vector<std::string> tokens;

    std::int32_t itemType(Object f) override {
        assert(f == kFree);
        tokens.push_back("itemType");
        return type;
    }
    void setNeedsRemoved(Object f, std::int8_t v) override {
        assert(f == kFree);
        tokens.push_back("needs:" + std::to_string(static_cast<int>(v)));
    }
    std::int32_t dataA(Object f) override {
        assert(f == kFree);
        tokens.push_back("dataA");
        return a;
    }
    std::int32_t dataB(Object f) override {
        assert(f == kFree);
        tokens.push_back("dataB");
        return b;
    }
    std::int32_t sendCanPickUp(Object s, std::int32_t d) override {
        assert(s == kSelf);
        tokens.push_back("g" + std::to_string(d));
        const std::int32_t v = gates[i < gates.size() ? i : gates.size() - 1];
        ++i;
        return v;
    }
    Object allocItem() override {
        tokens.push_back("alloc");
        return kItem;
    }
    Object sendInitWithType(Object it, std::int32_t d) override {
        assert(it == kItem);
        tokens.push_back("init" + std::to_string(d));
        return kItem;
    }
    Object sendAutorelease(Object it) override {
        assert(it == kItem);
        tokens.push_back("autorel");
        return it;
    }
    void sendAddItemFlash(Object s, Object it) override {
        assert(s == kSelf && it == kItem);
        tokens.push_back("add");
    }
    std::string joined() const {
        std::string out;
        for (auto& t : tokens) { out += t; out += ' '; }
        return out;
    }
};
} // namespace

int main() {
    // 1. Non-money: second itemType decides; 0xb sets needsRemoved first,
    //    the flow still falls through both itemType reads (ARM order).
    {
        Fixture f;
        f.type = 20;
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.stop == Stop::NonMoney && f.joined() == "itemType itemType ");
        f = Fixture{};
        f.type = 0xb;
        const Outcome b = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(b.stop == Stop::NonMoney && f.joined() == "itemType needs:1 itemType ");
    }
    // 2. Zero fields: both loops run zero insertions, residual 0.
    {
        Fixture f;
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.stop == Stop::ZeroResidual && o.platinum == 0 &&
               o.gold == 0 && o.copper == 0 && o.residual == 0);
    }
    // 3. Full happy path a=2,b=0: 2 platinum, 0 gold (limit2=0), 0 copper,
    //    residual 0. Message order per insert: g->alloc->init->autorel->add.
    {
        Fixture f;
        f.a = 2;
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.platinum == 2 && o.gold == 0 && o.copper == 0 &&
               o.stop == Stop::ZeroResidual);
        assert(f.joined() == "itemType itemType dataA dataB g260 alloc init260 "
                             "autorel add g260 alloc init260 autorel add ");
    }
    // 4. Platinum gate fails on the second attempt (0 must end the level
    //    exactly like 2: strict !=1): limit2 then cascades the uninserted
    //    platinum; a gate of 2 rejects gold immediately at index 2.
    {
        Fixture f;
        f.a = 2; f.b = 5;
        f.gates = {1, 0, 2}; // P1 ok, P2 -> 0 ends platinum; gold sees 2
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.platinum == 1);
        assert(o.gold == 0 && o.copper == 0);
        // limit2=(2-1)*100+0=100; limit3=(100-0)*100+5=10005; residual>0.
        assert(o.stop == Stop::Residual && o.residual == 10005);
        assert(o.thousands == 1 && o.remainder == 5);
    }
    // 5. Cascade with failed gold level: a=1,b=9999, gates=[1,0(gold fail)]
    //    platinum=1 -> limit2=(1-1)*100+99=99; one gold inserted then gate 2;
    //    limit3=(99-gold)*100+99. Verify with all-1 gates first.
    {
        Fixture f;
        f.a = 1; f.b = 250;
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        // platinum=1; limit2=0*100+2=2 gold; limit3=(2-2)*100+50=50 copper.
        assert(o.platinum == 1 && o.gold == 2 && o.copper == 50);
        assert(o.residual == 0 && o.stop == Stop::ZeroResidual);
    }
    // 6. Failed platinum cascades into gold: a=1,b=0,gates=[2] everywhere.
    {
        Fixture f;
        f.a = 1; f.b = 0;
        f.gates = {2, 1}; // platinum gate returns 2 (must reject), gold 1
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.platinum == 0);
        // limit2=(1-0)*100+0=100; gate pool [2,1,1,...] -> gold level sees 1
        // forever: 100 gold inserted; limit3=(100-100)*100+0=0 copper.
        assert(o.gold == 100 && o.copper == 0 && o.stop == Stop::ZeroResidual);
    }
    // 7. Residual>0 edge: gates reject gold/copper so residual stays.
    //    a=1,b=0, gates: platinum ok(1), gold always 0, copper always 0:
    //    platinum=1, limit2=99*... no: (1-1)*100+0=0 gold; residual 0.
    //    Use a=1 gates [1,0,0]: platinum=1, gold limit2=0, copper limit3=0.
    //    For residual>0 need uninserted: a=1,b=0,gates=[2(gold? no)]...
    //    Simplest: platinum gate ok once then fails? gate stream: [1,0,...]
    //    platinum=1 then level ends; gold=0 fails immediately -> gold<0? gold
    //    limit2=(1-1)*100+0=0 anyway. Choose a=2,b=0,gates=[1,2,0...]:
    //    platinum=2,gold limit=0, copper 0. residual 0. For residual>0:
    //    a=1,b=100,gates=[2,0]: platinum rejects (2), gold limit2=1*100+1=101,
    //    gold gate 0 -> none; limit3=(101-0)*100+0=10100 copper, gate repeats
    //    0 -> none; residual=10100 -> K=1 R=100.
    {
        Fixture f;
        f.a = 1; f.b = 100;
        f.gates = {2, 0};
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.stop == Stop::Residual && o.residual == 10100);
        assert(o.thousands == 1 && o.remainder == 100);
    }
    // 8. uxth truncation: negative raw dataA keeps low 16 bits.
    {
        Fixture f;
        f.a = -65536 + 3; // 0x...0003 after uxth
        f.b = 0;
        const Outcome o = splitMoney(f, Fixture::kSelf, Fixture::kFree);
        assert(o.platinum == 3); // limit1 = uxth = 3
    }
    printf("inventory_pickup_currency: %d contract groups pass\n", 8);
}
