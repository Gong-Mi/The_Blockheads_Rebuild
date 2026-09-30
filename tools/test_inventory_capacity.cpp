// Synthetic object-runtime contracts, NOT fabricated original-app observations.
#include "../reconstruction/recovered/inventory_capacity.h"
#include "../reconstruction/recovered/inventory_rules.h"
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
using namespace recovered::inventory_capacity;

struct Fixture final : Runtime {
    struct Node {
        std::vector<Object> values;
        std::int32_t type = 0;
        std::uint16_t b = 0;
        Object sub = 0;
        std::uint32_t n = 0, mutation = 0;
    };
    std::map<Object, Node> nodes;
    Object next = 10, inventory = 0;
    std::int8_t dragging = 0;
    int worlds = 0, inventories = 0, mutationCalls = 0, enumStarts = 0, enumCalls = 0;
    std::vector<std::uint32_t> indices;
    std::vector<Object> counted;
    std::function<void(Object)> onCount;
    std::function<Object()> onInventory;
    std::int32_t dispatched = -17;
    Object sentSelf = 0, sentSub = 0;
    std::int32_t sentType = 0;
    std::uint16_t sentA = 9, sentB = 9;
    Object alloc(Node n) { Object id = next++; nodes.emplace(id, std::move(n)); return id; }
    Object array(std::vector<Object> v) {
        Node n; n.n = static_cast<std::uint32_t>(v.size()); n.values = std::move(v); return alloc(std::move(n));
    }
    Object stack(std::int32_t t, std::uint32_t count, std::uint16_t b = 0, Object sub = 0) {
        Node item; item.type = t; item.b = b; item.sub = sub;
        Object id = alloc(item); Object s = array({id}); nodes[s].n = count; return s;
    }
    Fixture() { Object full = stack(20, 99); inventory = array(std::vector<Object>(8, full)); }
    void all(Object s) { nodes[inventory].values.assign(8, s); }
    void slot(Object s, unsigned i = 1) { nodes[inventory].values.at(i) = s; }
    Object readWorld(Object self) override { assert(self == 1); ++worlds; return 2; }
    Object readInventoryItems(Object self) override {
        assert(self == 1); ++inventories; return onInventory ? onInventory() : inventory;
    }
    std::int8_t worldUIDragging(Object world) override { assert(world == 2); return dragging; }
    Object objectAtIndex(Object a, std::uint32_t i) override {
        if (a == inventory) indices.push_back(i);
        if (!a) return 0;
        return nodes.at(a).values.at(i);
    }
    std::uint32_t count(Object a) override {
        counted.push_back(a); if (onCount) onCount(a); return a ? nodes.at(a).n : 0;
    }
    std::int32_t itemType(Object a) override { return a ? nodes.at(a).type : 0; }
    std::uint16_t dataB(Object a) override { return a ? nodes.at(a).b : 0; }
    Object subItems(Object a) override { return a ? nodes.at(a).sub : 0; }
    std::uint32_t enumerate(Object a, EnumerationState& st, Object* buf, std::uint32_t cap) override {
        ++enumCalls; assert(cap == 16);
        if (!st.state) ++enumStarts;
        if (!a) return 0;
        auto& n = nodes.at(a);
        if (st.state >= n.values.size()) return 0;
        auto take = std::min<std::size_t>(2, n.values.size()-st.state);
        for (std::size_t i=0; i<take; ++i) buf[i] = n.values[st.state+i];
        st.state += take; st.items = buf; st.mutations = &n.mutation;
        return static_cast<std::uint32_t>(take);
    }
    void enumerationMutation(Object a) override { assert(a); ++mutationCalls; }
    std::int32_t sendCanPickUp(Object self, std::int32_t t, Object sub,
                             std::uint16_t a, std::uint16_t b) override {
        sentSelf=self; sentType=t; sentSub=sub; sentA=a; sentB=b; return dispatched;
    }
    std::int32_t run(std::int32_t t=20, Object sub=0, std::uint16_t a=0, std::uint16_t b=0) {
        return canPickUpItemOfType(*this,1,t,sub,a,b);
    }
};

int main() {
    int cases = 0;
    auto test = [&](const char* name, auto body) { body(); ++cases; std::cout << "PASS " << name << '\n'; };
    test("wrapper is dynamic dispatch and preserves signed return", [] {
        Fixture f; assert(canPickUpItemOfType(f,1,298,42)==-17);
        assert(f.sentSelf==1 && f.sentType==298 && f.sentSub==42 && f.sentA==0 && f.sentB==0);
        assert(f.worlds==0 && f.inventories==0);
    });
    test("invalid before world read; all three excluded IDs", [] {
        for (int t : {0,1,0x422,0x423,0x428,0x158,0x452}) {
            Fixture f; assert(f.run(t)==0 && f.worlds==0 && f.inventories==0);
        }
    });
    test("signed nonzero dragging gives zero before inventory", [] {
        Fixture f; f.dragging=-128; assert(f.run()==0 && f.worlds==1 && f.inventories==0);
    });
    test("exhausted is minus one and indexes are exactly 1..7", [] {
        Fixture f; f.slot(f.stack(20,0),0); assert(f.run()==-1);
        assert((f.indices==std::vector<std::uint32_t>{1,2,3,4,5,6,7})); assert(f.inventories==7);
    });
    test("empty slot and nil stack both fit", [] {
        for (bool nil : {false,true}) { Fixture f; f.slot(nil?0:f.stack(20,0)); assert(f.run()==1); }
    });
    test("99 fails 98 fits type mismatch fails", [] {
        Fixture f; f.slot(f.stack(20,98)); assert(f.run()==1);
        Fixture g; g.slot(g.stack(21,98)); assert(g.run()==-1);
    });
    test("inventory ivar re-read discovers replacement at slot 2", [] {
        Fixture f; auto second=f.array(f.nodes[f.inventory].values);
        f.nodes[second].values[2]=f.stack(20,0);
        f.onInventory=[&] {return f.inventories==1?f.inventory:second;};
        assert(f.run()==1 && f.inventories==2);
    });
    test("count is re-sent rather than cached", [] {
        Fixture f; auto s=f.stack(20,99); f.slot(s); int calls=0;
        f.onCount=[&](Object a) {if (a==s && ++calls==2) f.nodes[s].n=98;};
        assert(f.run()==1 && calls==2);
    });
    test("dataB stack restrictions and colored zero/nonzero parity", [] {
        for (int t : {0x67,0x5b,0x55}) {
            Fixture f; f.slot(f.stack(t,98,0)); assert(f.run(t,0,0,1)==-1);
            Fixture g; g.slot(g.stack(t,98,1)); assert(g.run(t,0,0,1)==1);
        }
        Fixture f; f.slot(f.stack(0x55,98,2)); assert(f.run(0x55,0,0,3)==1);
        Fixture g; g.slot(g.stack(20,98,2)); assert(g.run(20,0,0,3)==1);
    });
    test("money denomination boundaries and aggregate type cannot stack itself", [] {
        for (int denom : {0x104,0xa7,0xa6,0x12a,20}) {
            for (unsigned a : {0u,1u}) for(unsigned b : {0u,1u,99u,100u}) {
                Fixture f; f.slot(f.stack(denom,98));
                bool expected=(denom==0x104 && a>0) || (denom==0xa7 && (a>0||b>=100)) ||
                              (denom==0xa6 && (a>0||b>0));
                assert(f.run(0x12a,0,a,b)==(expected?1:-1));
            }
        }
    });
    test("existing bag empty contents fails; empty child fits", [] {
        Fixture f; f.slot(f.stack(12,1,0,f.array({}))); assert(f.run()==-1 && f.enumCalls==0);
        Fixture g; g.slot(g.stack(12,1,0,g.array({g.stack(20,0)}))); assert(g.run()==1 && g.enumStarts==1);
    });
    test("existing type1 bag and nested stack 98/99/mismatch", [] {
        for (unsigned n : {98u,99u}) for (int t : {20,21}) {
            Fixture f; f.slot(f.stack(1,1,0,f.array({f.stack(t,n)})));
            assert(f.run()==((n==98 && t==20)?1:-1));
        }
    });
    test("nested money has same thresholds", [] {
        for (int denom : {0x104,0xa7,0xa6}) for(unsigned a:{0u,1u}) for(unsigned b:{0u,1u,99u,100u}) {
            Fixture f; auto children=f.array({f.stack(denom,98)}); f.slot(f.stack(12,1,0,children));
            bool ok=a>0 || (denom==0xa7 && b>=100) || (denom==0xa6 && b>0);
            assert(f.run(0x12a,0,a,b)==(ok?1:-1));
        }
    });
    test("enumeration batches and callback on changed mutation counter", [] {
        Fixture f; auto s=f.stack(21,99); auto bag=f.array({s,s,f.stack(20,0)});
        f.slot(f.stack(12,1,0,bag)); bool changed=false;
        f.onCount=[&](Object a){if(a==s&&!changed){++f.nodes[bag].mutation;changed=true;}};
        assert(f.run()==1 && f.enumCalls==2 && f.mutationCalls==2);
    });
    test("incoming bag nil/empty subitems fit non-container stack", [] {
        Fixture f; assert(f.run(12)==1);
        Fixture g; assert(g.run(12,g.array({}))==1);
    });
    test("incoming bag cannot absorb known sub-item-capacity types", [] {
        for(int t:{1,12,0x2d,0xa1,0xcf,0x413,0x429,0x430,0x432,0x450}) {
            Fixture f; f.all(f.stack(t,99)); assert(f.run(12)==-1);
        }
    });
    test("incoming bag empty child found before merge pass", [] {
        Fixture f; auto sub=f.array({f.stack(21,99),f.stack(20,0)});
        assert(f.run(12,sub)==1 && f.enumStarts==1);
    });
    test("incoming bag merge uses two fresh scans and exact 99 inclusive", [] {
        for(unsigned n:{49u,50u}) {
            Fixture f; f.all(f.stack(20,50)); auto sub=f.array({f.stack(20,n)});
            assert(f.run(12,sub)==(n==49?1:-1));
            assert(f.enumStarts==(n==49?2:14));
        }
    });
    test("incoming bag merge type mismatch rejected", [] {
        Fixture f; f.all(f.stack(20,1)); assert(f.run(12,f.array({f.stack(21,1)}))==-1);
    });
    test("incoming bag only 0x67 checks dataB; 0x5b differs from regular stack gate", [] {
        for(int t:{0x67,0x5b}) for(unsigned b:{1u,2u}) {
            Fixture f; f.all(f.stack(t,1,1)); auto sub=f.array({f.stack(t,1,b)});
            assert(f.run(12,sub)==((t==0x67 && b!=1)?-1:1));
        }
    });
    test("incoming bag count addition wraps exactly like ARM32", [] {
        Fixture f; f.all(f.stack(20,100)); auto sub=f.array({f.stack(20,std::numeric_limits<std::uint32_t>::max())});
        assert(f.run(12,sub)==1);
    });
    test("helper capacity default negative/large and signed boundaries", [] {
        assert(subItemCapacityAtC5EAA8(-1)==0 && subItemCapacityAtC5EAA8(0x451)==0);
        assert(subItemCapacityAtC5EAA8(0x2d)==2 && subItemCapacityAtC5EAA8(0x450)==16);
    });
    test("real liquid predicates are constants, no imaginary liquid behavior", [] {
        for(int t=-1024;t<4096;++t) {
            assert(!blockheads::recovered::itemTypeIsLiquid(t));
            assert(!blockheads::recovered::itemTypeCarriesLiquids(t));
        }
    });
    std::cout << cases << " capacity scenario groups PASS\n";
    return 0;
}
