#include "inventory_rules.h"
#include <algorithm>

namespace blockheads::recovered {
std::int8_t itemTypeIsValidFillItem(std::int32_t type) {
    // 0x00580cdc..0x00580e5c: equality exclusions followed by SIGNED bounds.
    switch(type) {
    case 0: case 0xb: case 1: case 2: case 5: case 0xa: case 0x12:
    case 0x1a: case 0x13: case 9: case 0x2d: case 0x40f: case 0x411:
    case 0x410: case 0x417: case 0x41d: case 0x403: case 0x40b:
    case 0x405: case 0x40d: case 0x416: case 0x431:
        return 0;
    default: break;
    }
    if (type >= 0x158 && type < 0x400) return 0;
    return type < 0x452 ? 1 : 0;
}
std::int8_t itemTypeIsValidInventoryItem(std::int32_t type) {
    // 0x00c5e9ac..0x00c5ea20
    return itemTypeIsValidFillItem(type) && type != 0x422 && type != 0x423 && type != 0x428;
}
std::int8_t itemTypeIsLiquid(std::int32_t) {
    // Full six-instruction body at 0x00c5ea20 returns zero for every type.
    return 0;
}
std::int8_t itemTypeCarriesLiquids(std::int32_t) {
    // Full six-instruction body at 0x00c5ea90 returns zero for every type.
    return 0;
}
std::int8_t itemTypeSubItemsCanBeModifiedWhileCarried(std::int32_t type) {
    // 0x004eb960..0x004eb9a4
    return type == 0xc || type == 1;
}
std::int8_t itemTypeCanBeColored(std::int32_t type) {
    // 0x004d6128..0x004d6220
    switch(type) {
    case 0x55: case 0x54: case 0x75: case 0x73: case 0x7a: case 0x82:
    case 0x7c: case 0x7e: case 0x7f: case 0xa9: case 0xaa: return 1;
    default: return 0;
    }
}
std::int8_t itemTypeIsStackable(std::int32_t type, std::uint16_t first, std::uint16_t second) {
    // 0x004ea3cc..0x004ea4c0; mutable subitems take precedence over equality.
    if (itemTypeSubItemsCanBeModifiedWhileCarried(type)) return 0;
    if (first == second) return 1;
    if (type == 0x67 || type == 0x5b) return 0;
    if (!itemTypeCanBeColored(type)) return 1;
    return (first != 0) == (second != 0);
}
std::int32_t usageIncrementPerUse(std::int32_t type, std::int32_t mode,
                                  std::int8_t flag2, std::int8_t flag3) {
    // 0x005e9c30..0x005e9fa4: mode==0 precedes even unknown-type handling.
    if (mode == 0) return 0;
    std::int32_t increment = -1;
    switch(type) {
    case 0x9c: increment=0x200; break;
    case 0x4a: case 0xaf: increment=0x100; break;
    case 0x67: case 0x68: increment=0x80; break;
    case 0x142: increment=0x400; break;
    case 0x2a: case 0x101: increment=0x29; break;
    case 8: case 0x19: case 0x10: case 7: case 0x5e: case 6: case 0x59: case 0x5a:
        increment=0x40; break;
    case 0x21: case 0x22: case 0x5f: case 0x27: case 0x40:
        increment=0x20; break;
    case 0x2b: case 0x28: case 0x31: case 0x60: case 0x32: case 0xd1:
        increment=0x10; break;
    case 0x42: case 0x43: case 0x44: case 0x61: case 0x46:
        increment=8; break;
    case 0x5d: case 0x62: increment=4; break;
    case 0x11d: case 0x11e: increment=3; break;
    default: break;
    }
    if (increment <= 0) return increment;
    if (flag3 != 0) increment *= 4;
    else if (flag2 != 0) increment /= 2;
    if (mode == 3) increment *= 2;
    else if (mode == 1) increment /= 2;
    return std::max(1, increment);
}
}
