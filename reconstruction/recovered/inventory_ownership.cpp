#include "inventory_ownership.h"
namespace blockheads::recovered::ownership {
std::int32_t workbenchKindForItemType(std::int32_t t) {
    // 0x5deeb8..0x5df240: signed decision tree and two PC-relative tables.
    switch (t) {
    case 0xf: return 3;
    case 0x86: case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b: return 13;
    case 0xdd: return 24;
    case 0x10e: return 26;
    case 0x12c: return 29;
    case 0x401: return 8;
    case 0x407: return 9;
    case 0x408: return 5;
    case 0x409: return 4;
    case 0x40a: return 7;
    case 0x41a: return 2;
    case 0x41c: return 6;
    case 0x41f: return 10;
    case 0x420: return 11;
    case 0x425: return 12;
    case 0x42f: return 14;
    case 0x435: return 15;
    case 0x436: return 16;
    case 0x437: return 17;
    case 0x438: return 18;
    case 0x439: return 19;
    case 0x43a: return 20;
    case 0x43b: return 21;
    case 0x43c: return 22;
    case 0x43d: return 23;
    case 0x43e: return 25;
    case 0x445: return 27;
    case 0x447: return 28;
    case 0x448: return 30;
    case 0x449: return 31;
    default: return 0;
    }
}
std::int8_t itemTypeIsWorkbench(std::int32_t t) {
    return workbenchKindForItemType(t) != 0 ? 1 : 0;
}
std::int8_t itemTypeIsTorch(std::int32_t t) {
    switch (t) {
    case 0x11: case 0xb7: case 0x2f: case 0x96: case 0xfe: case 0x102:
    case 0x4b: case 0x4c: case 0x56: case 0x57: case 0x58:
    case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x9d: return 1;
    default: return 0;
    }
}
std::int8_t itemTypeIsStairs(std::int32_t t) {
    switch (t) {
    case 0xe5: case 0xe6: case 0x14d: case 0x153: case 0x154: case 0x155:
    case 0x156: case 0x157: case 0xe7: case 0xe8: case 0xe9: case 0xea: case 0xeb:
    case 0xf5: case 0xf6: case 0xf7: case 0xf8: case 0xf9: case 0xfa: case 0xfb:
    case 0xfc: case 0x109: case 0x10b: case 0x107: case 0x119: case 0x11b: case 0xfd: return 1;
    default: return 0;
    }
}
std::int8_t itemTypeIsColumn(std::int32_t t) {
    switch (t) {
    case 0xde: case 0xdf: case 0x14c: case 0x14e: case 0x14f: case 0x150:
    case 0x151: case 0x152: case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xe4:
    case 0xec: case 0xed: case 0xee: case 0xef: case 0xf0: case 0xf1: case 0xf2:
    case 0xf3: case 0x10a: case 0x10c: case 0x108: case 0x11a: case 0x11c: case 0xf4: return 1;
    default: return 0;
    }
}
std::int8_t itemTypeIsPainting(std::int32_t t) {
    return t >= 0xd4 && t <= 0xdc ? 1 : 0;
}
std::int8_t itemTypeRequiresOwnershipToRemove(std::int32_t t) {
    // Preserve helper call order; all helpers are pure in the pinned binary.
    switch (t) {
    case 0x429: case 0xcf: case 0xa4: case 0xa5: case 0xa8: return 1;
    }
    if (itemTypeIsWorkbench(t)) return 1;
    switch (t) {
    case 0x413: case 0x430: case 0x450: case 0x432: case 0xd2: case 0xce:
    case 0x3f: case 0x14b: case 0xaa: case 0xcc: case 0xd0: case 0xa3:
    case 0x12d: case 0xa1: case 0xa9: case 0xcd: case 0xc8: case 0x35:
    case 0x3a: case 0xae: case 0x34: case 0x130: case 0x45: case 0x440:
    case 0x43f: return 1;
    }
    if (itemTypeIsTorch(t)) return 1;
    if (itemTypeIsStairs(t)) return 1;
    if (itemTypeIsColumn(t)) return 1;
    if (itemTypeIsPainting(t)) return 1;
    return t == 0xb2 ? 1 : 0;
}
}
