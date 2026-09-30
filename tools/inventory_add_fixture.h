#pragma once
#include "../reconstruction/recovered/inventory_add.h"
#include "../reconstruction/recovered/inventory_rules.h"
#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
using namespace recovered::inventory_add;
namespace rules = blockheads::recovered;

// Behavioral fixture runtime only, NOT a production Foundation replacement.
struct Fixture : Runtime {
    struct Node { std::int32_t type=0; std::uint16_t a=0,b=0; Object sub=0;
                  std::vector<Object> values; std::uint32_t mutation=0; };
    std::map<Object,Node> nodes;
    Object serial=100, self=1, item=2, world=3, ui=4, inventory=5;
    std::int8_t isNet=0;
    std::vector<std::string> log;
    std::function<void(const std::string&)> hook;
    bool mutationThrows=true;
    int wrapperKind=0; Object wrapperSelf=0,wrapperItem=0;
    int wrapperFlash=0,wrapperWarp=0,wrapperForce=0,result=37;
    Object make(std::int32_t type=0) { Object n=serial++;nodes[n].type=type;return n; }
    Object slot(std::initializer_list<Object> list={}) { auto n=make();nodes[n].values=list;return n; }
    Fixture() { nodes[item].type=4; // Original type 2 is excluded by itemTypeIsValidFillItem.
        assert(rules::itemTypeIsValidInventoryItem(4)); for(int i=0;i<8;++i)nodes[inventory].values.push_back(slot()); }
    void event(std::string s) {log.push_back(s);if(hook)hook(s);}
    std::string id(Object x) {return std::to_string(x);}
    Object outer(int i) {return nodes[inventory].values.at(i);}
    void fill() {for(int i=1;i<8;++i)nodes[outer(i)].values.assign(99,make(3));}
    Object bag(int i,int n=4) { auto b=make(12),sub=slot();nodes[b].sub=sub;
        for(int j=0;j<n;++j)nodes[sub].values.push_back(slot());nodes[outer(i)].values={b};return b; }
    bool saw(const std::string& s) {return std::find(log.begin(),log.end(),s)!=log.end();}
    Object readWorld(Object s) override {assert(s==self);event("world");return world;}
    std::int8_t readIsNet(Object s) override {assert(s==self);event("isNet");return isNet;}
    Object readInventoryItems(Object s) override {assert(s==self);event("inventory");return inventory;}
    void writeInventoryChanged(Object s,std::uint32_t i,std::uint8_t v) override {assert(s==self&&v==1);event("changed:"+std::to_string(i));}
    void writeSubInventoryChanged(Object s,std::uint32_t i,std::uint32_t j,std::uint8_t v) override {assert(s==self&&v==1);event("subChanged:"+std::to_string(i)+":"+std::to_string(j));}
    Object objectAtIndex(Object o,std::uint32_t i) override {event("at:"+id(o)+":"+std::to_string(i));return o?nodes.at(o).values.at(i):0;}
    std::uint32_t count(Object o) override {event("count:"+id(o));return o?nodes.at(o).values.size():0;}
    std::int32_t itemType(Object o) override {event("type:"+id(o));return o?nodes.at(o).type:0;}
    std::uint16_t dataA(Object o) override {event("a:"+id(o));return o?nodes.at(o).a:0;}
    std::uint16_t dataB(Object o) override {event("b:"+id(o));return o?nodes.at(o).b:0;}
    Object subItems(Object o) override {event("sub:"+id(o));return o?nodes.at(o).sub:0;}
    std::uint32_t enumerate(Object o,EnumerationState& state,Object* buffer,std::uint32_t capacity) override {
        assert(capacity==16);event("enumerate:"+id(o));if(!o)return 0;
        auto& n=nodes.at(o);auto used=std::min<std::size_t>(capacity,n.values.size()-state.state);
        std::copy_n(n.values.begin()+state.state,used,buffer);state.state+=used;
        state.items=buffer;state.mutations=&n.mutation;return used;
    }
    void enumerationMutation(Object o) override {event("mutation:"+id(o));if(mutationThrows)throw std::runtime_error("mutation");}
    void addObject(Object o,Object x) override {event("add:"+id(o)+":"+id(x));if(o){nodes.at(o).values.push_back(x);++nodes.at(o).mutation;}}
    void insertObjectAtIndex(Object o,Object x,std::uint32_t i) override {event("insert:"+id(o)+":"+std::to_string(i));auto& n=nodes.at(o);n.values.insert(n.values.begin()+i,x);++n.mutation;}
    void addObjectsFromArray(Object o,Object s) override {event("addAll:"+id(o)+":"+id(s));auto v=nodes.at(s).values;auto& n=nodes.at(o);n.values.insert(n.values.end(),v.begin(),v.end());++n.mutation;}
    void removeAllObjects(Object o) override {event("clear:"+id(o));nodes.at(o).values.clear();++nodes.at(o).mutation;}
    void reportAchievementWithIdentifier(Object w,const char* s) override {event("achievement:"+id(w)+":"+s);}
    void addItemToFoundList(Object w,Object i) override {assert(i==item);event("found:"+id(w));}
    Object uiManager(Object w) override {event("ui:"+id(w));return ui;}
    void flashInventory(Object u,std::int32_t i,std::int32_t j,Object s,std::uint32_t c) override {assert(u==ui&&s==self&&c==0);event("flash:"+std::to_string(i)+":"+std::to_string(j));}
    std::int32_t checkIfCanWarpInSecondBlockheadAfterItemAdded(Object s,std::int32_t t,std::uint16_t b) override {assert(s==self);event("warp:"+std::to_string(t)+":"+std::to_string(b));return -99;}
    std::int32_t record(int kind,Object s,Object i,int f,int w,int force){wrapperKind=kind;wrapperSelf=s;wrapperItem=i;wrapperFlash=f;wrapperWarp=w;wrapperForce=force;return result;}
    std::int32_t sendAddItemFlash(Object s,Object i,std::int8_t f) override{return record(1,s,i,f,100,100);}
    std::int32_t sendAddItemFlashDisableWarp(Object s,Object i,std::int8_t f,std::int8_t w) override{return record(2,s,i,f,w,100);}
    std::int32_t sendAddItemFlashDisableWarpForceSlot(Object s,Object i,std::int8_t f,std::int8_t w,std::int32_t force) override{return record(3,s,i,f,w,force);}
    int run(int force=-1,int flash=0,int warp=0){return addItemToInventory(*this,self,item,flash,warp,force);}
};

