#include "inventory_add_fixture.h"

int main(){
    {Fixture f;assert(addItemToInventory(f,f.self,f.item)==37);assert(f.wrapperKind==1&&f.wrapperFlash==0&&f.wrapperSelf==f.self&&f.wrapperItem==f.item);
     f.result=-7;assert(addItemToInventory(f,f.self,f.item,std::int8_t(-128))==-7);assert(f.wrapperKind==2&&f.wrapperFlash==-128&&f.wrapperWarp==0);
     f.result=0;assert(addItemToInventory(f,f.self,f.item,std::int8_t(2),std::int8_t(-1))==0);assert(f.wrapperKind==3&&f.wrapperFlash==2&&f.wrapperWarp==-1&&f.wrapperForce==-1);assert(f.log.empty());}
    {Fixture f;f.nodes[f.item].type=0;assert(f.run()==-1);assert(f.log==std::vector<std::string>{"type:2"});}
    {Fixture f;assert(f.run(6,2)==6);assert(f.nodes[f.outer(6)].values==std::vector<Object>{f.item});assert(f.saw("changed:6")&&f.saw("flash:6:-1")&&f.saw("warp:4:0"));}
    {Fixture f;f.isNet=-1;assert(f.run(-1,0,-1)==1);assert(!f.saw("found:3")&&!f.saw("warp:4:0"));}
    {Fixture f;f.fill();f.nodes[f.item].type=0x117;assert(f.run()==-1);assert(f.saw("achievement:3:grp.titanium")&&f.saw("found:3"));}
    {Fixture f;f.fill();f.nodes[f.item].type=0x105;assert(f.run()==-1);assert(f.saw("achievement:3:grp.mj.platinum"));}
    {Fixture f;auto old=f.make(4);f.nodes[f.outer(5)].values={old};assert(f.run()==5);assert(f.nodes[f.outer(5)].values.size()==2);assert(f.nodes[f.outer(1)].values.empty());}
    {Fixture f;auto old=f.make(4);f.nodes[f.outer(5)].values.assign(99,old);assert(f.run()==1);}
    {Fixture f;auto b=f.bag(7),sub=f.nodes[b].sub,s=f.nodes[sub].values[2];f.nodes[s].values={f.make(4)};
     assert(f.run(-1,1)==7);assert(f.nodes[s].values.back()==f.item);assert(f.saw("subChanged:7:2")&&f.saw("flash:7:2"));assert(!f.saw("changed:7"));}
    {Fixture f;f.fill();auto b=f.bag(3),sub=f.nodes[b].sub,s=f.nodes[sub].values[0];
     assert(f.run(99,1)==3);assert(f.nodes[s].values==std::vector<Object>{f.item});assert(f.saw("subChanged:3:0"));}
    {Fixture f;f.fill();auto b=f.bag(4,18),sub=f.nodes[b].sub;
     for(int j=0;j<17;++j)f.nodes[f.nodes[sub].values[j]].values={f.make(3)};
     assert(f.run(99,1)==4);assert(f.saw("flash:4:17")&&!f.saw("subChanged:4:17"));}
    {Fixture f;f.fill();f.nodes[f.item].type=12;auto sub=f.slot(),empty=f.slot();f.nodes[sub].values={empty};f.nodes[f.item].sub=sub;
     // Incoming bag absorption ignores forceSlotIndex; consumes entire top stack.
     auto old=f.nodes[f.outer(1)].values;assert(f.run(99,1)==1);assert(f.nodes[empty].values==old);assert(f.nodes[f.outer(1)].values==std::vector<Object>{f.item});
     auto add=std::find(f.log.begin(),f.log.end(),"addAll:"+f.id(empty)+":"+f.id(f.outer(1)));
     auto clear=std::find(f.log.begin(),f.log.end(),"clear:"+f.id(f.outer(1)));assert(add<clear);}
    {Fixture f;f.fill();f.nodes[f.item].type=12;auto sub=f.slot(),s=f.slot({f.make(3)});f.nodes[sub].values={s};f.nodes[f.item].sub=sub;
     auto o=f.outer(2);f.nodes[o].values.resize(98);assert(f.run(99)==2);assert(f.nodes[s].values.size()==99);}
    {Fixture f;f.fill();f.nodes[f.item].type=12;auto sub=f.slot(),s=f.slot({f.make(0x67)});f.nodes[sub].values={s};f.nodes[f.item].sub=sub;f.nodes[f.nodes[s].values[0]].b=2;
     auto o=f.outer(1),old=f.make(0x67);f.nodes[old].b=3;f.nodes[o].values={old};assert(f.run(99)==-1);}
    {Fixture f;f.hook=[&](const std::string&s){if(s=="found:3")f.world=9;if(s=="ui:9")f.nodes[f.item].b=44;};assert(f.run(-1,1)==1);assert(f.saw("ui:9")&&f.saw("warp:4:44"));}
    {Fixture f;auto old=f.make(4);f.nodes[f.outer(1)].values={old};int counts=0;
     f.hook=[&](const std::string&s){if(s=="count:"+f.id(f.outer(1))&&++counts==2)f.nodes[f.outer(1)].values.assign(99,old);};
     assert(f.run()==2);assert(counts==4); /* pass 1 twice, passes 2 and 3 once */}
    {Fixture f;f.fill();auto b=f.bag(3),sub=f.nodes[b].sub;
     for(auto s:f.nodes[sub].values)f.nodes[s].values={f.make(3)};
     auto first=f.nodes[sub].values[0];bool once=false;
     f.hook=[&](const std::string&s){if(!once&&s=="count:"+f.id(first)){once=true;++f.nodes[sub].mutation;}};
     bool threw=false;try{f.run(99);}catch(const std::runtime_error&){threw=true;}assert(threw&&f.saw("mutation:"+f.id(sub)));}
    // Find a real positive usage rule rather than using a fabricated helper.
    {int type=0;for(int t=2;t<500;++t)if(rules::itemTypeIsValidInventoryItem(t)&&rules::itemTypeIsStackable(t,0,0)&&rules::usageIncrementPerUse(t,2,0,0)>0){type=t;break;}
     assert(type);Fixture f;f.nodes[f.item].type=type;f.nodes[f.item].a=20;auto a=f.make(type),b=f.make(type);f.nodes[a].a=10;f.nodes[b].a=30;f.nodes[f.outer(4)].values={a,b};
     assert(f.run()==4);assert((f.nodes[f.outer(4)].values==std::vector<Object>{a,f.item,b}));}
    // Original invalid type 2 must not regress to the old fixture assumption.
    {Fixture f;f.nodes[f.item].type=2;assert(f.run()==-1);assert(f.log==std::vector<std::string>{"type:2"});}
    {Fixture f;f.item=0;assert(f.run()==-1);assert(f.log==std::vector<std::string>{"type:0"});}
    {Fixture f;assert(f.run(0)==-1);assert(f.saw("found:3"));assert(!f.saw("warp:4:0"));}
    // Force filters occupied-sub pass 2, but not empty-sub pass 5.
    {Fixture f;f.fill();auto b=f.bag(3),sub=f.nodes[b].sub;
     auto matching=f.nodes[sub].values[0],empty=f.nodes[sub].values[1];
     f.nodes[matching].values={f.make(4)};assert(f.run(99)==3);
     assert(f.nodes[matching].values.size()==1&&f.nodes[empty].values==std::vector<Object>{f.item});}
    // First empty outer wins before incoming-container absorption.
    {Fixture f;f.nodes[f.item].type=12;auto sub=f.slot(),empty=f.slot();f.nodes[sub].values={empty};f.nodes[f.item].sub=sub;
     f.nodes[f.outer(1)].values={f.make(3)};assert(f.run()==2);assert(f.nodes[empty].values.empty());}
    // Empty absorption is not capped at 99 and reports only the outer change.
    {Fixture f;f.fill();f.nodes[f.item].type=12;auto sub=f.slot(),empty=f.slot();f.nodes[sub].values={empty};f.nodes[f.item].sub=sub;
     f.nodes[f.outer(1)].values.assign(100,f.make(3));assert(f.run(99,1)==1);
     assert(f.nodes[empty].values.size()==100&&f.saw("flash:1:-1")&&!f.saw("subChanged:1:0"));}
    for(int index:{3,4}) {Fixture f;f.fill();auto b=f.bag(3,5),sub=f.nodes[b].sub;
     for(int j=0;j<index;++j)f.nodes[f.nodes[sub].values[j]].values={f.make(3)};
     assert(f.run(99,1)==3);assert(f.saw("flash:3:"+std::to_string(index)));
     assert(f.saw("subChanged:3:"+std::to_string(index))==(index<4));}
    // A callback changes type after initial classification. Pass 1 compares
    // fresh types, while the warp argument remains the original type.
    {Fixture f;f.nodes[f.outer(4)].values={f.make(3)};
     f.hook=[&](const std::string&s){if(s=="found:3")f.nodes[f.item].type=3;};
     assert(f.run()==4);assert(f.saw("warp:4:0"));}
    {Fixture f;f.nodes[f.item].type=0x117;
     f.hook=[&](const std::string&s){if(s=="achievement:3:grp.titanium")f.world=9;};
     assert(f.run(-1,1)==1);assert(f.saw("found:9")&&f.saw("ui:9"));}
    // Returning mutation handlers do not reset the baseline at a batch boundary.
    {Fixture f;f.fill();auto b=f.bag(3,18),sub=f.nodes[b].sub;
     for(int j=0;j<17;++j)f.nodes[f.nodes[sub].values[j]].values={f.make(3)};
     auto first=f.nodes[sub].values[0];f.mutationThrows=false;bool once=false;
     f.hook=[&](const std::string&s){if(!once&&s=="count:"+f.id(first)){once=true;++f.nodes[sub].mutation;}};
     assert(f.run(99)==3);assert(std::count(f.log.begin(),f.log.end(),"mutation:"+f.id(sub))==17);}
    std::cout<<"inventory_add: wrapper dispatch, five passes, re-reads, mutation and effects passed\n";
}
