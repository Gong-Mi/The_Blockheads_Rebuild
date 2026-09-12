#include "inventory_rules.h"
#include <cassert>
#include <cstdint>
#include <climits>
#include <iostream>
using namespace blockheads::recovered;
// C adapter used only by the optional original-ARM instruction differential.
extern "C" std::int32_t inventory_rule_probe(std::int32_t fn, std::int32_t type,
        std::uint32_t a, std::uint32_t b, std::uint32_t c) {
    switch(fn) {
    case 0: return itemTypeIsValidFillItem(type);
    case 1: return itemTypeIsValidInventoryItem(type);
    case 2: return itemTypeIsLiquid(type);
    case 3: return itemTypeCarriesLiquids(type);
    case 4: return itemTypeSubItemsCanBeModifiedWhileCarried(type);
    case 5: return itemTypeCanBeColored(type);
    case 6: return itemTypeIsStackable(type,static_cast<std::uint16_t>(a),static_cast<std::uint16_t>(b));
    case 7: return usageIncrementPerUse(type,static_cast<std::int32_t>(a),static_cast<std::int8_t>(b),static_cast<std::int8_t>(c));
    default: return INT32_MIN;
    }
}
#ifndef INVENTORY_RULES_SHARED_TEST
#ifdef NDEBUG
#error inventory rules tests require assertions
#endif
int main() {
    for(int t=-4;t<0x460;++t) {
        assert(itemTypeIsLiquid(t)==0 && itemTypeCarriesLiquids(t)==0);
        assert(itemTypeSubItemsCanBeModifiedWhileCarried(t)==(t==1||t==12));
        for(auto v:{0u,1u,32768u,65535u}) {
            assert(itemTypeIsStackable(t,v,v)==!(t==1||t==12));
        }
        assert(usageIncrementPerUse(t,0,1,1)==0);
    }
    assert(itemTypeIsValidFillItem(-1)==1 && itemTypeIsValidFillItem(INT32_MIN)==1);
    assert(itemTypeIsValidFillItem(0)==0 && itemTypeIsValidFillItem(0x157)==1);
    assert(itemTypeIsValidFillItem(0x158)==0 && itemTypeIsValidFillItem(0x3ff)==0);
    assert(itemTypeIsValidFillItem(0x400)==1 && itemTypeIsValidFillItem(0x451)==1);
    assert(itemTypeIsValidFillItem(0x452)==0 && itemTypeIsValidFillItem(INT32_MAX)==0);
    for(int t:{0x422,0x423,0x428}) {
        assert(itemTypeIsValidFillItem(t)==1 && itemTypeIsValidInventoryItem(t)==0);
    }
    for(int t:{0x67,0x5b}) {
        assert(itemTypeIsStackable(t,0xffff,0xfffe)==0);
        assert(itemTypeIsStackable(t,0xffff,0xffff)==1);
    }
    for(int t:{0x55,0x54,0x75,0x73,0x7a,0x82,0x7c,0x7e,0x7f,0xa9,0xaa}) {
        assert(itemTypeCanBeColored(t)==1);
        assert(itemTypeIsStackable(t,0,1)==0);
        assert(itemTypeIsStackable(t,1,65535)==1);
    }
    assert(itemTypeIsStackable(3,0,65535)==1);
    assert(usageIncrementPerUse(0x142,2,0,0)==1024);
    assert(usageIncrementPerUse(0x142,3,-128,-128)==8192);
    assert(usageIncrementPerUse(0x11d,1,1,0)==1);
    assert(usageIncrementPerUse(0x2a,1,1,0)==10);
    assert(usageIncrementPerUse(0x2a,3,1,0)==40);
    assert(usageIncrementPerUse(0x2a,2,1,1)==164);
    assert(usageIncrementPerUse(INT32_MAX,2,1,1)==-1);
    std::cout<<"PASS inventory rules: complete helper contracts\n";
}
#endif
