#!/usr/bin/env python3
"""Hash-gated recovery of the World closure sweep part 1 (E114).

The World class closure sweep (part 1): the mid-size operational
bodies (custom slots, found-list, Game Center, sun color, motion
feed) and the UI/gate/forwarder tail:
70 bodies, 6190 instruction words, from the pinned original libApplication.so
(1.7.6, armeabi-v7a).  Every instruction word is re-verified; tool refuses to
emit on drift.

Verification rules (each one is a claim this file makes about its own evidence):
  * coverage    - the checked-in listing must cover [start, end) exactly once per word,
                  and every word is re-read from the pinned ELF.
  * PIC base    - recomputed from the `add rX, pc, rY` anchor and its pool literal;
                  must equal 0x0105faf4.
  * cells       - selector cells: the slot is base + signed(pool value) and the C string
                  it points at must be the named selector.  Import cells: the slot must be
                  a PLT/GOT slot whose relocation names the import, or - for functions
                  reached through an ABS32 relocation - a relocation whose symbol names
                  it (the route used is recorded per cell).  Ivar cells: the slot
                  holds a pointer to OBJC_IVAR_$_<Class>.<name> in .dynsym plus the
                  offset word.  Class cells: the slot either holds the OBJC_CLASS_$_
                  symbol value (.dynsym) or - for classes imported from the system
                  frameworks - carries an ABS32 relocation whose symbol is the class;
                  both routes are checked, the relocation route is named when used.
  * calls       - the set of bl/blx rows inside the body must equal the spec's set, and
                  every `bl <name>` route's computed target must match ROUTE_TARGETS.
  * branches    - the set of conditional/unconditional b* rows whose destination lands
                  inside the body must equal the spec's set.  Rows outside the body are
                  literal-pool words that mask as branches; they are recorded in
                  `disjoint_branch_rows` instead of being silently dropped.
  * anchors     - the listed instruction texts must match the listing byte for byte.

Machine-generated spec tables + hand-written semantics; see
reconstruction/reverse-v3/native/WORLD_CLOSE1.md for the prose and boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl 0x55468c': 0x0055468c,
    'bl 0x559f78': 0x00559f78,
    'bl 0x5ab510': 0x005ab510,
    'bl 0x5d2cc8': 0x005d2cc8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.std::__1::__tree_std::__1::pair_int__unsigned_char___std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__unsigned_char_____.___tree__': 0x005deab4,
    'bl method.std::__1::map_int__unsigned_char__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__unsigned_char_____._map__': 0x005dab34,
    'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__': 0x0057598c,
    'bl sym.clampi_int__int__int_': 0x004c0b70,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.__android_log_print': 0x001c290c,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_copyStruct': 0x001c2888,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_': 0x004ea3cc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wx_00',
        method='World -[setCustomSlotAtIndex:toItemType:count:]',
        types='v20@0:4i8i12i16',
        start=6119296,
        end=6120848,
        disasm='disasm_worldtileloader_wx_00.txt',
        base_add=6119312,
        base_literal=6120844,
        boundary='ARM.exidx end 0x005d6590 (listing bound); next ObjC IMP 0x005d6590 World -[setSunColorRule:]',
        selectors={
                 0x5d6540: (15198340, 'arrayWithArray:'),
                 0x5d6548: (15195624, 'objectForKey:'),
                 0x5d655c: (15195580, 'dictionaryWithObjectsAndKeys:'),
                 0x5d6560: (15195572, 'numberWithInt:'),
                 0x5d656c: (15195604, 'count'),
                 0x5d6570: (15195688, 'array'),
                 0x5d6574: (15195824, 'customRulesChanged'),
                 0x5d6580: (15195584, 'setObject:forKey:'),
                 0x5d6584: (15198344, 'replaceObjectAtIndex:withObject:'),
                 0x5d6588: (15195700, 'addObject:'),
        },
        imports={
                 0x5d6538: (17151968, '__stack_chk_guard'),
                 0x5d653c: (17151904, 'objc_msgSend'),
                 0x5d6544: (16233864, '__CFConstantStringClassReference'),
                 0x5d6554: (16233880, '__CFConstantStringClassReference'),
                 0x5d6558: (16231400, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d654c: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5d6578: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5d657c: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={
                 0x5d6550: (15245300, 'OBJC_CLASS_$_NSMutableArray'),
                 0x5d6564: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5d6568: (15245328, 'OBJC_CLASS_$_NSDictionary'),
        },
        instructions=[(6119296, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6120844, 'adceq sb, r8, ip, asr fp')],
        calls=[(6119380, 'bl sym.clampi_int__int__int_'), (6119416, 'bl sym.itemTypeIsStackable_ItemType__unsigned_short__unsigned_short_'), (6119692, 'blx r3'), (6119732, 'blx r3'), (6119792, 'blx r5'), (6119856, 'blx lr'), (6119888, 'blx r3'), (6119952, 'blx r2'), (6120024, 'blx r3'), (6120232, 'blx r3'), (6120268, 'blx ip'), (6120328, 'blx r5'), (6120368, 'blx r3'), (6120508, 'blx lr'), (6120552, 'blx ip'), (6120636, 'bl 0x559f78'), (6120704, 'bl sym.imp.memcpy'), (6120724, 'blx r2'), (6120756, 'bl sym.imp.__stack_chk_fail')],
        branches=[(6119428, 'bne', 6119440), (6119908, 'beq', 6119964), (6119960, 'bne', 6120392), (6120052, 'bge', 6120388), (6120384, 'b', 6120044), (6120388, 'b', 6120392), (6120744, 'bne', 6120756)],
        semantics=('[World -[setCustomSlotAtIndex:toItemType:count:]] (imp 0x005d5f80, 388w): the custom-slot editor - NSMutableArray arrayWithArray:/replaceObjectAtIndex:withObject: slot table update (dictionaryWithObjectsAndKeys:/numberWithInt: entries), clampi + itemTypeIsStackable clamping behind the expertMode gate and the 0x559f78 helper; constants 0x63/0x40.\n'),
    ),
    dict(
        name='wx_01',
        method='World -[privateAddItemToFoundList:addBasketContents:]',
        types='c16@0:4@8c12',
        start=6127404,
        end=6128780,
        disasm='disasm_worldtileloader_wx_01.txt',
        base_add=6127420,
        base_literal=6128776,
        boundary='ARM.exidx end 0x005d848c (listing bound); next ObjC IMP 0x005d848c World -[addItemToFoundList:]',
        selectors={
                 0x5d8458: (15196752, 'containsIndex:'),
                 0x5d8460: (15196312, 'itemType'),
                 0x5d8464: (15196176, 'addIndex:'),
                 0x5d8468: (15198360, 'foundListContainsEggWithDodoBreed:'),
                 0x5d846c: (15196912, 'dataB'),
                 0x5d8470: (15198364, 'addDodoEggToFoundListWithBreed:'),
                 0x5d8474: (15196916, 'subItems'),
                 0x5d8478: (15195604, 'count'),
                 0x5d847c: (15195800, 'objectAtIndex:'),
                 0x5d8480: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5d8484: (15198368, 'privateAddItemToFoundList:addBasketContents:'),
        },
        imports={
                 0x5d8454: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d845c: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
        },
        classes={},
        instructions=[(6127404, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6128776, 'invalid')],
        calls=[(6127508, 'blx lr'), (6127552, 'blx ip'), (6127644, 'blx r3'), (6127736, 'blx ip'), (6127764, 'blx r3'), (6127860, 'blx lr'), (6127888, 'blx r3'), (6127980, 'blx r3'), (6128048, 'blx r2'), (6128132, 'blx ip'), (6128156, 'blx r2'), (6128248, 'bl sym.imp.memset'), (6128296, 'blx lr'), (6128396, 'bl sym.imp.objc_enumerationMutation'), (6128504, 'blx r4'), (6128656, 'blx ip')],
        branches=[(6127564, 'bne', 6127656), (6127664, 'bne', 6127904), (6127776, 'bne', 6127900), (6127900, 'b', 6127904), (6127912, 'beq', 6128712), (6127924, 'bne', 6128712), (6128060, 'bhs', 6128708), (6128164, 'bls', 6128688), (6128308, 'beq', 6128680), (6128388, 'beq', 6128400), (6128524, 'bne', 6128548), (6128584, 'blo', 6128352), (6128676, 'bne', 6128352), (6128680, 'b', 6128684), (6128684, 'b', 6128688), (6128688, 'b', 6128692), (6128704, 'b', 6128000), (6128708, 'b', 6128712)],
        semantics=('[World -[privateAddItemToFoundList:addBasketContents:]] (imp 0x005d7f2c, 344w): the recursive found-list add - containsIndex: dedup guard, addIndex: into foundItemsList, subItems recursion through itself and the itemType/dataB egg path (foundListContainsEggWithDodoBreed:/addDodoEggToFoundListWithBreed:); 0x10/0x20.\n'),
    ),
    dict(
        name='wx_02',
        method='World -[getCurrentCreditTimeString]',
        types='@8@0:4',
        start=6106236,
        end=6106312,
        disasm='disasm_worldtileloader_wx_02.txt',
        base_add=6106252,
        base_literal=6106308,
        boundary='ARM.exidx end 0x005d2cc8 (listing bound); next ObjC IMP 0x005d3158 World -[cloudTopupSucceeded:]',
        selectors={},
        imports={},
        ivars={
                 0x5d2cc0: (17155988, 'OBJC_IVAR_$_World.clientsideCredit', 3300),
        },
        classes={},
        instructions=[(6106236, 'push {fp, lr}'), (6106308, 'adceq ip, r8, r0, ror 28')],
        calls=[(6106292, 'bl 0x5d2cc8')],
        branches=[],
        semantics=('[World -[getCurrentCreditTimeString]] (imp 0x005d2c7c, 19w): one-call delegate computing the credit time string via helper 0x5d2cc8 from clientsideCredit.\n'),
    ),
    dict(
        name='wx_03',
        method='World -[addChestItemsToFoundList:]',
        types='v12@0:4@8',
        start=6128988,
        end=6130036,
        disasm='disasm_worldtileloader_wx_03.txt',
        base_add=6129004,
        base_literal=6130032,
        boundary='ARM.exidx end 0x005d8974 (listing bound); next ObjC IMP 0x005d8974 World -[addDodoEggToFoundListWithBreed:]',
        selectors={
                 0x5d8960: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5d8964: (15198368, 'privateAddItemToFoundList:addBasketContents:'),
        },
        imports={
                 0x5d895c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8968: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d896c: (17155968, 'OBJC_IVAR_$_World.foundItemsListNeedsToBeSentToServer', 3380),
        },
        classes={},
        instructions=[(6128988, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6130032, 'adceq r7, r8, r0, lsl 11')],
        calls=[(6129096, 'bl sym.imp.memset'), (6129144, 'blx lr'), (6129244, 'bl sym.imp.objc_enumerationMutation'), (6129356, 'bl sym.imp.memset'), (6129404, 'blx lr'), (6129504, 'bl sym.imp.objc_enumerationMutation'), (6129612, 'blx r4'), (6129764, 'blx ip'), (6129892, 'blx ip')],
        branches=[(6129156, 'beq', 6129916), (6129236, 'beq', 6129248), (6129416, 'beq', 6129788), (6129496, 'beq', 6129508), (6129632, 'bne', 6129656), (6129692, 'blo', 6129460), (6129784, 'bne', 6129460), (6129788, 'b', 6129792), (6129792, 'b', 6129796), (6129820, 'blo', 6129200), (6129912, 'bne', 6129200), (6129916, 'b', 6129920), (6129956, 'beq', 6130004), (6129968, 'beq', 6130004)],
        semantics=('[World -[addChestItemsToFoundList:]] (imp 0x005d855c, 262w): the chest-contents sweep - fast enumeration calling privateAddItemToFoundList:addBasketContents: per entry, marking foundItemsListNeedsToBeSentToServer behind the client gate.\n'),
    ),
    dict(
        name='wx_04',
        method='World -[reportAchievementWithIdentifier:]',
        types='v12@0:4@8',
        start=6047672,
        end=6048520,
        disasm='disasm_worldtileloader_wx_04.txt',
        base_add=6047688,
        base_literal=6048516,
        boundary='ARM.exidx end 0x005c4b08 (listing bound); next ObjC IMP 0x005c4b60 World -[achievementsButtonTapped]',
        selectors={
                 0x5c4abc: (15195860, 'autorelease'),
                 0x5c4ac0: (15197916, 'initWithIdentifier:'),
                 0x5c4ac4: (15195752, 'alloc'),
                 0x5c4acc: (15197912, 'setBool:forKey:'),
                 0x5c4ad0: (15195916, 'standardUserDefaults'),
                 0x5c4adc: (15195708, 'stringWithFormat:'),
                 0x5c4ae4: (15197908, 'playerID'),
                 0x5c4ae8: (15197904, 'localPlayer'),
                 0x5c4af4: (15197924, 'reportAchievements:withCompletionHandler:'),
                 0x5c4af8: (15196516, 'arrayWithObject:'),
                 0x5c4b00: (15197920, 'setPercentComplete:'),
        },
        imports={
                 0x5c4ab8: (17151904, 'objc_msgSend'),
                 0x5c4ad8: (16232904, '__CFConstantStringClassReference'),
                 0x5c4af0: (17136332, '_NSConcreteGlobalBlock'),
        },
        ivars={},
        classes={
                 0x5c4ac8: (15245528, 'OBJC_CLASS_$_GKAchievement'),
                 0x5c4ad4: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
                 0x5c4ae0: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5c4aec: (15245524, 'OBJC_CLASS_$_GKLocalPlayer'),
                 0x5c4afc: (15245308, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(6047672, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6048516, 'adceq fp, sb, r4, lsr 6')],
        calls=[(6047964, 'blx lr'), (6047980, 'blx r2'), (6048044, 'blx r5'), (6048080, 'blx r3'), (6048108, 'blx ip'), (6048140, 'blx r3'), (6048160, 'blx r3'), (6048176, 'blx r2'), (6048332, 'blx r8'), (6048384, 'blx r3'), (6048420, 'blx ip')],
        branches=[(6048196, 'beq', 6048424)],
        semantics=('[World -[reportAchievementWithIdentifier:]] (imp 0x005c47b8, 212w): the Game Center bridge - GKAchievement initWithIdentifier: + setPercentComplete: (0x64 = 100) + GKLocalPlayer reportAchievements:withCompletionHandler: (the _NSConcreteGlobalBlock completion) plus the NSUserDefaults setBool:forKey: latch (stringWithFormat:/playerID).\n'),
    ),
    dict(
        name='wx_05',
        method='World -[sendUpdatedSunColor]',
        types='v8@0:4',
        start=6121744,
        end=6122680,
        disasm='disasm_worldtileloader_wx_05.txt',
        base_add=6121760,
        base_literal=6122676,
        boundary='ARM.exidx end 0x005d6cb8 (listing bound); next ObjC IMP 0x005d6cb8 World -[sendUpdatedCustomSlots]',
        selectors={
                 0x5d6c78: (15195684, 'dictionary'),
                 0x5d6c80: (15195552, 'dataWithBytes:length:'),
                 0x5d6c88: (15195644, 'sendDataToServer:reliable:'),
                 0x5d6c8c: (15195612, 'appendData:'),
                 0x5d6c90: (15195608, 'gzipDeflate'),
                 0x5d6c94: (15196864, 'dataWithPropertyList:format:options:error:'),
                 0x5d6c9c: (15195624, 'objectForKey:'),
                 0x5d6ca8: (15195708, 'stringWithFormat:'),
                 0x5d6cb0: (15195584, 'setObject:forKey:'),
        },
        imports={
                 0x5d6c74: (17151904, 'objc_msgSend'),
                 0x5d6ca4: (16233944, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d6c6c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d6c70: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
                 0x5d6ca0: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
        },
        classes={
                 0x5d6c7c: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5d6c84: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5d6c98: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x5d6cac: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6121744, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6122676, 'adceq sb, r8, ip, asr 3')],
        calls=[(6121972, 'blx r5'), (6122008, 'blx r3'), (6122160, 'blx r4'), (6122204, 'blx ip'), (6122292, 'blx ip'), (6122496, 'blx r8'), (6122512, 'blx r2'), (6122540, 'blx r3'), (6122588, 'blx lr')],
        branches=[(6121808, 'beq', 6122596), (6121844, 'beq', 6122596), (6122044, 'bge', 6122316), (6122224, 'beq', 6122296), (6122296, 'b', 6122300), (6122312, 'b', 6122036), (6122324, 'beq', 6122592), (6122592, 'b', 6122596)],
        semantics=('[World -[sendUpdatedSunColor]] (imp 0x005d6910, 234w): the sun-color broadcast - customRulesDict entry build + NSPropertyListSerialization plist + gzipDeflate + sendDataToServer:reliable: behind the client/isAdmin gate; 0x42/0x64.\n'),
    ),
    dict(
        name='wx_06',
        method='World -[setSunColorRule:]',
        types='v24@0:4{MJColor=ffff}8',
        start=6120848,
        end=6121744,
        disasm='disasm_worldtileloader_wx_06.txt',
        base_add=6120864,
        base_literal=6121740,
        boundary='ARM.exidx end 0x005d6910 (listing bound); next ObjC IMP 0x005d6910 World -[sendUpdatedSunColor]',
        selectors={
                 0x5d68dc: (15195824, 'customRulesChanged'),
                 0x5d68f0: (15195584, 'setObject:forKey:'),
                 0x5d68f4: (15195572, 'numberWithInt:'),
        },
        imports={
                 0x5d68d4: (17151968, '__stack_chk_guard'),
                 0x5d68d8: (17151904, 'objc_msgSend'),
                 0x5d68ec: (16233928, '__CFConstantStringClassReference'),
                 0x5d68fc: (16233912, '__CFConstantStringClassReference'),
                 0x5d6900: (16233896, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d68e0: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5d68e4: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5d68e8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
        },
        classes={
                 0x5d68f8: (15245292, 'OBJC_CLASS_$_NSNumber'),
        },
        instructions=[(6120848, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6121740, 'adceq sb, r8, ip, asr 10')],
        calls=[(6120964, 'bl sym.clampi_int__int__int_'), (6121000, 'bl sym.clampi_int__int__int_'), (6121036, 'bl sym.clampi_int__int__int_'), (6121256, 'blx r4'), (6121292, 'blx ip'), (6121348, 'blx r3'), (6121384, 'blx ip'), (6121440, 'blx r3'), (6121476, 'blx ip'), (6121560, 'bl 0x559f78'), (6121628, 'bl sym.imp.memcpy'), (6121648, 'blx r2'), (6121680, 'bl sym.imp.__stack_chk_fail')],
        branches=[(6121668, 'bne', 6121680)],
        semantics=('[World -[setSunColorRule:]] (imp 0x005d6590, 224w): the sun-color rule editor - clampi x3 at the 0xff RGB bound + numberWithInt:/setObject:forKey: into customRulesDict + customRulesChanged; 0x559f78; 0xff/0x40.\n'),
    ),
    dict(
        name='wx_07',
        method='World -[blockheadAvailablePromptDismissedWithToThePortal]',
        types='v8@0:4',
        start=6062724,
        end=6063612,
        disasm='disasm_worldtileloader_wx_07.txt',
        base_add=6062740,
        base_literal=6063608,
        boundary='ARM.exidx end 0x005c85fc (listing bound); next ObjC IMP 0x005c85fc World -[chatButton]',
        selectors={
                 0x5c85bc: (15196764, 'worldUI'),
                 0x5c85c4: (15197692, 'selectBlockheadButtonAtIndex:'),
                 0x5c85d0: (15196416, 'workbenchAtPos:'),
                 0x5c85d8: (15196632, 'center:'),
                 0x5c85e4: (15197548, 'craftUI'),
                 0x5c85e8: (15197444, 'workbenchTapped:hasCancel:'),
                 0x5c85ec: (15197544, 'setSelectedIndex:'),
                 0x5c85f4: (15197956, 'zoomToPoint:'),
        },
        imports={
                 0x5c85e0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c85b4: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5c85c0: (17156728, 'OBJC_IVAR_$_World.showBlockheadAvailablePromptBlockheadWithCorrrectFoodIndex', 3176),
                 0x5c85c8: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
                 0x5c85cc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c85d4: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x5c85dc: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
        },
        classes={},
        instructions=[(6062724, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6063608, 'adceq r7, sb, r8, asr r8')],
        calls=[(6062804, 'bl loc.imp.objc_msgSend'), (6062840, 'bl loc.imp.objc_msgSend'), (6062932, 'bl loc.imp.objc_msgSend'), (6063108, 'blx ip'), (6063156, 'blx lr'), (6063216, 'blx r2'), (6063296, 'bl loc.imp.objc_msgSend_stret'), (6063332, 'bl sym.imp.memset'), (6063440, 'bl method.Vector2.Vector2_float__float_'), (6063528, 'bl loc.imp.objc_msgSend')],
        branches=[(6062952, 'beq', 6063360), (6063272, 'beq', 6063304), (6063300, 'b', 6063336), (6063356, 'b', 6063468)],
        semantics=('[World -[blockheadAvailablePromptDismissedWithToThePortal]] (imp 0x005c8284, 222w): the available-prompt dismiss action - worldUI selectBlockheadButtonAtIndex: + workbenchAtPos: + camera centering (Vector2 ctor + zoomToPoint:) + craftUI workbenchTapped:hasCancel:/setSelectedIndex:; showBlockheadAvailablePromptBlockheadWithCorrrectFoodIndex slot.\n'),
    ),
    dict(
        name='wx_08',
        method='World -[queueBlockheadAIActionToTile:atPos:forBlockhead:]',
        types='v24@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12@20',
        start=5943924,
        end=5944592,
        disasm='disasm_worldtileloader_wx_08.txt',
        base_add=5944008,
        base_literal=5944552,
        boundary='ARM.exidx end 0x005ab510 (listing bound); next ObjC IMP 0x005ab5bc World -[scrollToTap:]',
        selectors={
                 0x5ab4e4: (15197304, 'currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:'),
                 0x5ab4ec: (15197308, 'tileIsProtectedAtPos:againstBlockhead:'),
                 0x5ab500: (15196428, 'interactionObjectAtPos:'),
                 0x5ab504: (15196300, 'uniqueID'),
                 0x5ab508: (15197312, 'queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:isAI:'),
        },
        imports={},
        ivars={
                 0x5ab4f8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5943924, 'push {r4, r5, fp, lr}'), (5944588, 'adceq r4, fp, r8, ror 12')],
        calls=[(5944060, 'bl loc.imp.objc_msgSend'), (5944072, 'bl 0x5ab510'), (5944156, 'bl loc.imp.objc_msgSend'), (5944256, 'bl loc.imp.objc_msgSend'), (5944384, 'bl loc.imp.objc_msgSend'), (5944400, 'bl loc.imp.objc_msgSend'), (5944532, 'bl loc.imp.objc_msgSend')],
        branches=[(5944084, 'beq', 5944268), (5944172, 'beq', 5944264), (5944264, 'b', 5944268), (5944308, 'bne', 5944416), (5944412, 'b', 5944436), (5944432, 'b', 5944436)],
        semantics=('[World -[queueBlockheadAIActionToTile:atPos:forBlockhead:]] (imp 0x005ab274, 167w): the AI-action queuer - currentInteractionTypeForTile:...allowProtectedActions: + tileIsProtectedAtPos:againstBlockhead: + interactionObjectAtPos: gates then queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:...; helper 0x5ab510.\n'),
    ),
    dict(
        name='wx_09',
        method='World -[sendUpdatedCustomSlots]',
        types='v8@0:4',
        start=6122680,
        end=6123464,
        disasm='disasm_worldtileloader_wx_09.txt',
        base_add=6122696,
        base_literal=6123460,
        boundary='ARM.exidx end 0x005d6fc8 (listing bound); next ObjC IMP 0x005d6fc8 World -[sandFractionForPos:]',
        selectors={
                 0x5d6f94: (15195644, 'sendDataToServer:reliable:'),
                 0x5d6f98: (15195612, 'appendData:'),
                 0x5d6f9c: (15195608, 'gzipDeflate'),
                 0x5d6fa0: (15196864, 'dataWithPropertyList:format:options:error:'),
                 0x5d6fac: (15195580, 'dictionaryWithObjectsAndKeys:'),
                 0x5d6fb0: (15195624, 'objectForKey:'),
                 0x5d6fbc: (15195552, 'dataWithBytes:length:'),
        },
        imports={
                 0x5d6f90: (17151904, 'objc_msgSend'),
                 0x5d6fa8: (16233864, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d6f88: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d6f8c: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
                 0x5d6fb4: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
        },
        classes={
                 0x5d6fa4: (15245468, 'OBJC_CLASS_$_NSPropertyListSerialization'),
                 0x5d6fb8: (15245328, 'OBJC_CLASS_$_NSDictionary'),
                 0x5d6fc0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6122680, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6123460, 'adceq r8, r8, r4, lsr 28')],
        calls=[(6123132, 'blx ip'), (6123196, 'blx lr'), (6123240, 'blx lr'), (6123296, 'blx lr'), (6123312, 'blx r2'), (6123340, 'blx r3'), (6123388, 'blx lr')],
        branches=[(6122744, 'beq', 6123392), (6122780, 'beq', 6123392)],
        semantics=('[World -[sendUpdatedCustomSlots]] (imp 0x005d6cb8, 196w): the custom-slots broadcast - dictionaryWithObjectsAndKeys: + plist serialize + gzipDeflate + sendDataToServer:reliable: behind the isAdmin/client gate; 0x64/0x42.\n'),
    ),
    dict(
        name='wx_10',
        method='World -[startObservingMotionEvents]',
        types='v8@0:4',
        start=5663048,
        end=5663764,
        disasm='disasm_worldtileloader_wx_10.txt',
        base_add=5663064,
        base_literal=5663760,
        boundary='ARM.exidx end 0x00566c14 (listing bound); next ObjC IMP 0x00566c14 World -[stopObservingMotionEvents]',
        selectors={
                 0x566bec: (15196248, 'startAccelerometerUpdates'),
                 0x566bf8: (15195732, 'retain'),
                 0x566bfc: (15196236, 'scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:'),
                 0x566c00: (15196244, 'motionUpdatePingAccelerometer'),
                 0x566c08: (15196240, 'startDeviceMotionUpdates'),
                 0x566c0c: (15196232, 'motionUpdatePingDeviceMotion'),
        },
        imports={
                 0x566be8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x566be0: (17156400, 'OBJC_IVAR_$_World.isObservingMotionEvents', 17),
                 0x566be4: (17156404, 'OBJC_IVAR_$_World.supportsGyro', 16),
                 0x566bf0: (17156336, 'OBJC_IVAR_$_World.motionManager', 4),
                 0x566bf4: (17156408, 'OBJC_IVAR_$_World.motionUpdateTimer', 20),
        },
        classes={
                 0x566c04: (15245440, 'OBJC_CLASS_$_NSTimer'),
        },
        instructions=[(5663048, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5663760, 'umlaleq sb, pc, r4, r1')],
        calls=[(5663356, 'blx r6'), (5663372, 'blx r2'), (5663428, 'blx ip'), (5663616, 'blx r6'), (5663632, 'blx r2'), (5663688, 'blx ip')],
        branches=[(5663108, 'bne', 5663696), (5663172, 'beq', 5663436), (5663432, 'b', 5663692), (5663692, 'b', 5663696)],
        semantics=('[World -[startObservingMotionEvents]] (imp 0x00566948, 179w): starts the motion feed - NSTimer scheduledTimerWithTimeInterval:target:selector:(motionUpdatePingAccelerometer)repeats: + motionManager startAccelerometerUpdates/startDeviceMotionUpdates; isObservingMotionEvents/supportsGyro/motionUpdateTimer.\n'),
    ),
    dict(
        name='wx_11',
        method='World -[sendNewPrivacySettingToServer:]',
        types='v12@0:4I8',
        start=6100892,
        end=6101608,
        disasm='disasm_worldtileloader_wx_11.txt',
        base_add=6100908,
        base_literal=6101604,
        boundary='ARM.exidx end 0x005d1a68 (listing bound); next ObjC IMP 0x005d1a68 World -[serverPrivacySetting]',
        selectors={
                 0x5d1a34: (15198264, 'sendNewPasswordToServer:'),
                 0x5d1a44: (15195644, 'sendDataToServer:reliable:'),
                 0x5d1a48: (15195612, 'appendData:'),
                 0x5d1a50: (15195584, 'setObject:forKey:'),
                 0x5d1a54: (15195684, 'dictionary'),
                 0x5d1a5c: (15195552, 'dataWithBytes:length:'),
        },
        imports={
                 0x5d1a2c: (16233560, '__CFConstantStringClassReference'),
                 0x5d1a30: (17151904, 'objc_msgSend'),
                 0x5d1a38: (16233592, '__CFConstantStringClassReference'),
                 0x5d1a3c: (16233576, '__CFConstantStringClassReference'),
                 0x5d1a4c: (16233608, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d1a24: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d1a28: (17156036, 'OBJC_IVAR_$_World.isOwner', 3208),
                 0x5d1a40: (17156092, 'OBJC_IVAR_$_World.serverPrivacySetting', 3296),
        },
        classes={
                 0x5d1a58: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5d1a60: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6100892, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6101604, 'adceq lr, r8, r0, asr 6')],
        calls=[(6101124, 'blx r3'), (6101272, 'blx r6'), (6101308, 'blx r3'), (6101352, 'blx ip'), (6101360, 'bl 0x55468c'), (6101456, 'blx ip'), (6101504, 'blx lr')],
        branches=[(6100960, 'beq', 6101532), (6100996, 'beq', 6101532), (6101024, 'bne', 6101048), (6101044, 'b', 6101132), (6101056, 'bne', 6101080), (6101076, 'b', 6101128), (6101128, 'b', 6101132)],
        semantics=('[World -[sendNewPrivacySettingToServer:]] (imp 0x005d179c, 179w): the privacy-setting packet - dictionary + setObject:forKey: + dataWithBytes:length: + sendDataToServer:reliable:; helper 0x55468c (sixth appearance); 0x39 (57).\n'),
    ),
    dict(
        name='wx_12',
        method='World -[sendNewPasswordToServer:]',
        types='v12@0:4@8',
        start=6100100,
        end=6100772,
        disasm='disasm_worldtileloader_wx_12.txt',
        base_add=6100116,
        base_literal=6100768,
        boundary='ARM.exidx end 0x005d1724 (listing bound); next ObjC IMP 0x005d1724 World -[serverPassword]',
        selectors={
                 0x5d16f4: (15195552, 'dataWithBytes:length:'),
                 0x5d16fc: (15195612, 'appendData:'),
                 0x5d1704: (15195584, 'setObject:forKey:'),
                 0x5d1708: (15195684, 'dictionary'),
                 0x5d1714: (15195732, 'retain'),
                 0x5d1718: (15195860, 'autorelease'),
                 0x5d171c: (15195644, 'sendDataToServer:reliable:'),
        },
        imports={
                 0x5d16f0: (17151904, 'objc_msgSend'),
                 0x5d1700: (16233544, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d16e8: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d16ec: (17156036, 'OBJC_IVAR_$_World.isOwner', 3208),
                 0x5d1710: (17155932, 'OBJC_IVAR_$_World.serverPassword', 3288),
        },
        classes={
                 0x5d16f8: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x5d170c: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(6100100, 'push {r4, r5, r6, r7, fp, lr}'), (6100768, 'adceq lr, r8, r8, asr r6')],
        calls=[(6100284, 'blx lr'), (6100380, 'blx r2'), (6100424, 'blx ip'), (6100432, 'bl 0x55468c'), (6100484, 'blx r3'), (6100612, 'blx r4'), (6100648, 'blx r3'), (6100680, 'blx r3')],
        branches=[(6100168, 'beq', 6100704), (6100204, 'beq', 6100704), (6100304, 'beq', 6100488)],
        semantics=('[World -[sendNewPasswordToServer:]] (imp 0x005d1484, 168w): the new-password packet - NSMutableDictionary/NSMutableData build + sendDataToServer:reliable:; helper 0x55468c; serverPassword; 0x38 (56).\n'),
    ),
    dict(
        name='wx_13',
        method='World -[viewOrEditWelcomeMessage]',
        types='v8@0:4',
        start=6091888,
        end=6092528,
        disasm='disasm_worldtileloader_wx_13.txt',
        base_add=6091904,
        base_literal=6092524,
        boundary='ARM.exidx end 0x005cf6f0 (listing bound); next ObjC IMP 0x005cf6f0 World -[setNewWelcomeMessage:]',
        selectors={
                 0x5cf6c4: (15196184, 'viewServerWelcomeMessage:customRules:allowEdit:'),
                 0x5cf6d4: (15195644, 'sendDataToServer:reliable:'),
                 0x5cf6d8: (15195552, 'dataWithBytes:length:'),
                 0x5cf6e0: (15198200, 'disable'),
                 0x5cf6e4: (15197116, 'pauseUI'),
        },
        imports={
                 0x5cf6c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cf6b8: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5cf6bc: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5cf6c8: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5cf6cc: (17155944, 'OBJC_IVAR_$_World.welcomeMessage', 3272),
                 0x5cf6e8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={
                 0x5cf6dc: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6091888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6092524, 'adceq r0, sb, ip, ror 12')],
        calls=[(6092160, 'blx r2'), (6092176, 'blx r2'), (6092220, 'blx ip'), (6092272, 'blx lr'), (6092456, 'blx lr')],
        branches=[(6091952, 'beq', 6092280), (6092276, 'b', 6092464), (6092316, 'beq', 6092460), (6092460, 'b', 6092464)],
        semantics=('[World -[viewOrEditWelcomeMessage]] (imp 0x005cf470, 160w): opens the welcome-message editor - viewServerWelcomeMessage:customRules:allowEdit: in the pauseUI disable/enable bracket + sendDataToServer:reliable: relay; 0x35 (53).\n'),
    ),
    dict(
        name='wx_14',
        method='World -[blockheadFilesReturnedFromServer:]',
        types='v12@0:4@8',
        start=6130380,
        end=6131004,
        disasm='disasm_worldtileloader_wx_14.txt',
        base_add=6130396,
        base_literal=6131000,
        boundary='ARM.exidx end 0x005d8d3c (listing bound); next ObjC IMP 0x005d8d3c World -[startBulkDatabaseUpdate]',
        selectors={
                 0x5d8d24: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5d8d28: (15198376, 'setData:forKey:'),
                 0x5d8d30: (15196836, 'gzipInflate'),
                 0x5d8d34: (15195624, 'objectForKey:'),
        },
        imports={
                 0x5d8d20: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8d2c: (17156056, 'OBJC_IVAR_$_World.mainDatabase', 3396),
        },
        classes={},
        instructions=[(6130380, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6131000, 'adceq r7, r8, r0, lsl r0')],
        calls=[(6130484, 'bl sym.imp.memset'), (6130532, 'blx lr'), (6130632, 'bl sym.imp.objc_enumerationMutation'), (6130764, 'blx r5'), (6130788, 'blx r2'), (6130836, 'blx lr'), (6130940, 'blx ip')],
        branches=[(6130544, 'beq', 6130964), (6130624, 'beq', 6130636), (6130868, 'blo', 6130588), (6130960, 'bne', 6130588), (6130964, 'b', 6130968)],
        semantics=('[World -[blockheadFilesReturnedFromServer:]] (imp 0x005d8acc, 156w): the blockhead-file intake - gzipInflate + enumeration writing each file via setData:forKey: into mainDatabase; 0x10/0x20.\n'),
    ),
    dict(
        name='wx_15',
        method='World -[stopObservingMotionEvents]',
        types='v8@0:4',
        start=5663764,
        end=5664356,
        disasm='disasm_worldtileloader_wx_15.txt',
        base_add=5663780,
        base_literal=5664352,
        boundary='ARM.exidx end 0x00566e64 (listing bound); next ObjC IMP 0x00566e64 World -[startSimulatingIfNeeded]',
        selectors={
                 0x566e4c: (15195768, 'release'),
                 0x566e50: (15196256, 'invalidate'),
                 0x566e54: (15196260, 'stopAccelerometerUpdates'),
                 0x566e5c: (15196252, 'stopDeviceMotionUpdates'),
        },
        imports={
                 0x566e48: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x566e3c: (17156400, 'OBJC_IVAR_$_World.isObservingMotionEvents', 17),
                 0x566e40: (17156404, 'OBJC_IVAR_$_World.supportsGyro', 16),
                 0x566e44: (17156408, 'OBJC_IVAR_$_World.motionUpdateTimer', 20),
                 0x566e58: (17156336, 'OBJC_IVAR_$_World.motionManager', 4),
        },
        classes={},
        instructions=[(5663764, 'push {r4, r5, r6, sl, fp, lr}'), (5664352, 'adceq r8, pc, r8, asr 29')],
        calls=[(5663996, 'blx r3'), (5664032, 'blx r3'), (5664068, 'blx r3'), (5664204, 'blx r3'), (5664240, 'blx r3'), (5664276, 'blx r3')],
        branches=[(5663824, 'beq', 5664308), (5663888, 'beq', 5664100), (5664096, 'b', 5664304), (5664304, 'b', 5664308)],
        semantics=('[World -[stopObservingMotionEvents]] (imp 0x00566c14, 148w): stops the motion feed - motionUpdateTimer invalidate/release + motionManager stopAccelerometerUpdates/stopDeviceMotionUpdates; isObservingMotionEvents flag off.\n'),
    ),
    dict(
        name='wx_16',
        method='World -[serverFillReply:]',
        types='v12@0:4@8',
        start=6054356,
        end=6054932,
        disasm='disasm_worldtileloader_wx_16.txt',
        base_add=6054372,
        base_literal=6054928,
        boundary='ARM.exidx end 0x005c6414 (listing bound); next ObjC IMP 0x005c6414 World -[markCircumNavigateX:]',
        selectors={
                 0x5c6400: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5c6404: (15195692, 'blockheads'),
                 0x5c640c: (15197960, 'fillReceiptsReturned:'),
        },
        imports={
                 0x5c63fc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c6408: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6054356, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6054928, 'adceq sb, sb, r8, lsl 18')],
        calls=[(6054520, 'blx r5'), (6054544, 'bl sym.imp.memset'), (6054592, 'blx lr'), (6054692, 'bl sym.imp.objc_enumerationMutation'), (6054772, 'blx ip'), (6054872, 'blx ip')],
        branches=[(6054604, 'beq', 6054896), (6054684, 'beq', 6054696), (6054800, 'blo', 6054648), (6054892, 'bne', 6054648), (6054896, 'b', 6054900)],
        semantics=('[World -[serverFillReply:]] (imp 0x005c61d4, 144w): the fill-receipt dispatch - enumerates blockheads and calls fillReceiptsReturned: per blockhead; 0x10/0x20.\n'),
    ),
    dict(
        name='wx_17',
        method='World -[welcomeMessageRecievedFromServer:]',
        types='v12@0:4@8',
        start=6092888,
        end=6093388,
        disasm='disasm_worldtileloader_wx_17.txt',
        base_add=6092904,
        base_literal=6093384,
        boundary='ARM.exidx end 0x005cfa4c (listing bound); next ObjC IMP 0x005cfa4c World -[welcomeMessage]',
        selectors={
                 0x5cfa24: (15195624, 'objectForKey:'),
                 0x5cfa28: (15198208, 'enable'),
                 0x5cfa2c: (15197116, 'pauseUI'),
                 0x5cfa38: (15196184, 'viewServerWelcomeMessage:customRules:allowEdit:'),
        },
        imports={
                 0x5cfa1c: (16228904, '__CFConstantStringClassReference'),
                 0x5cfa20: (17151904, 'objc_msgSend'),
                 0x5cfa40: (16228872, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cfa30: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5cfa34: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
                 0x5cfa3c: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
        },
        classes={},
        instructions=[(6092888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6093384, 'adceq r0, sb, r4, lsl 5')],
        calls=[(6093044, 'blx r4'), (6093060, 'blx r2'), (6093084, 'blx r3'), (6093252, 'blx lr'), (6093328, 'blx r5')],
        branches=[(6093104, 'bne', 6093140)],
        semantics=('[World -[welcomeMessageRecievedFromServer:]] (imp 0x005cf858, 125w): the welcome-message intake - objectForKey: decode + pauseUI enable + viewServerWelcomeMessage:customRules:allowEdit: behind the isAdmin gate.\n'),
    ),
    dict(
        name='wx_18',
        method='World -[showBlockheadAvailablePrompt:forBlockhead:]',
        types='v16@0:4i8@12',
        start=6062228,
        end=6062724,
        disasm='disasm_worldtileloader_wx_18.txt',
        base_add=6062244,
        base_literal=6062720,
        boundary='ARM.exidx end 0x005c8284 (listing bound); next ObjC IMP 0x005c8284 World -[blockheadAvailablePromptDismissedWithToThePortal]',
        selectors={
                 0x5c8264: (15195692, 'blockheads'),
                 0x5c8270: (15195604, 'count'),
                 0x5c8274: (15195800, 'objectAtIndex:'),
                 0x5c8278: (15198040, 'showBlockheadAvailablePrompt:'),
        },
        imports={
                 0x5c8260: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c825c: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5c8268: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c826c: (17156728, 'OBJC_IVAR_$_World.showBlockheadAvailablePromptBlockheadWithCorrrectFoodIndex', 3176),
        },
        classes={},
        instructions=[(6062228, 'push {r4, sl, fp, lr}'), (6062720, 'adceq r7, sb, r8, asr 20')],
        calls=[(6062404, 'blx r3'), (6062468, 'blx r2'), (6062532, 'blx r3'), (6062672, 'blx r3')],
        branches=[(6062296, 'beq', 6062304), (6062300, 'b', 6062676), (6062480, 'bhs', 6062604), (6062544, 'bne', 6062584), (6062580, 'b', 6062604), (6062584, 'b', 6062588), (6062600, 'b', 6062420)],
        semantics=('[World -[showBlockheadAvailablePrompt:forBlockhead:]] (imp 0x005c8094, 124w): the prompt picker - blockheads count/objectAtIndex: + showBlockheadAvailablePrompt: with showBlockheadAvailablePromptBlockheadWithCorrrectFoodIndex; expertMode gate.\n'),
    ),
    dict(
        name='wx_19',
        method='World -[sendUpdatedFoundItemsListToServer]',
        types='v8@0:4',
        start=6126932,
        end=6127404,
        disasm='disasm_worldtileloader_wx_19.txt',
        base_add=6126948,
        base_literal=6127400,
        boundary='ARM.exidx end 0x005d7f2c (listing bound); next ObjC IMP 0x005d7f2c World -[privateAddItemToFoundList:addBasketContents:]',
        selectors={
                 0x5d7f10: (15195644, 'sendDataToServer:reliable:'),
                 0x5d7f14: (15195612, 'appendData:'),
                 0x5d7f18: (15195552, 'dataWithBytes:length:'),
                 0x5d7f20: (15198356, 'serializedData'),
        },
        imports={
                 0x5d7f0c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d7f04: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d7f08: (17155968, 'OBJC_IVAR_$_World.foundItemsListNeedsToBeSentToServer', 3380),
                 0x5d7f24: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
        },
        classes={
                 0x5d7f1c: (15245284, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(6126932, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6127400, 'adceq r7, r8, r8, lsl 27')],
        calls=[(6127208, 'blx ip'), (6127252, 'blx ip'), (6127280, 'blx r3'), (6127328, 'blx lr')],
        branches=[(6126996, 'beq', 6127356)],
        semantics=('[World -[sendUpdatedFoundItemsListToServer]] (imp 0x005d7d54, 118w): the found-list sync - NSMutableData appendData:/dataWithBytes:length: over foundItemsList serializedData + sendDataToServer:reliable: behind the client gate, clearing foundItemsListNeedsToBeSentToServer; 0x4c.\n'),
    ),
    dict(
        name='wx_20',
        method='World -[tutorialAlertDismissedWithContinue:]',
        types='v12@0:4c8',
        start=6086588,
        end=6087028,
        disasm='disasm_worldtileloader_wx_20.txt',
        base_add=6086604,
        base_literal=6087024,
        boundary='ARM.exidx end 0x005ce174 (listing bound); next ObjC IMP 0x005ce174 World -[showTutorialPopupWithTitle:message:]',
        selectors={
                 0x5ce154: (15198148, 'lastState'),
                 0x5ce15c: (15198156, 'tutorialAlertDismissedWithContinue'),
                 0x5ce160: (15198152, 'setTutorialTipText:'),
                 0x5ce164: (15195544, 'instance'),
                 0x5ce16c: (15195768, 'release'),
        },
        imports={
                 0x5ce150: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ce158: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
        },
        classes={
                 0x5ce168: (15245420, 'OBJC_CLASS_$_TipManager'),
        },
        instructions=[(6086588, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6087024, 'adceq r1, sb, r0, lsr 22')],
        calls=[(6086696, 'blx r2'), (6086840, 'blx r7'), (6086892, 'blx r3'), (6086912, 'blx r3'), (6086980, 'blx r2')],
        branches=[(6086632, 'beq', 6086712), (6086708, 'beq', 6086920), (6086916, 'b', 6086984)],
        semantics=('[World -[tutorialAlertDismissedWithContinue:]] (imp 0x005cdfbc, 110w): the tutorial alert dismissal - tutorial lastState + tutorialAlertDismissedWithContinue + TipManager setTutorialTipText:.\n'),
    ),
    dict(
        name='wx_21',
        method='World -[pauseResumeButtonTapped]',
        types='v8@0:4',
        start=5989392,
        end=5989820,
        disasm='disasm_worldtileloader_wx_21.txt',
        base_add=5989408,
        base_literal=5989816,
        boundary='ARM.exidx end 0x005b65bc (listing bound); next ObjC IMP 0x005b65bc World -[pauseExitToMenuButtonTapped]',
        selectors={
                 0x5b6594: (15197560, 'hidePauseUIIfAble'),
                 0x5b659c: (15197564, 'shouldDisplayInterstitial'),
                 0x5b65a8: (15197568, 'displayInterstitialForTag:'),
                 0x5b65b4: (15195676, 'setPaused:'),
        },
        imports={
                 0x5b6590: (17151904, 'objc_msgSend'),
                 0x5b65a4: (16232504, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5b6598: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b65b0: (17156492, 'OBJC_IVAR_$_World.pauseIdleTimer', 3264),
        },
        classes={},
        instructions=[(5989392, 'push {r4, r5, fp, lr}'), (5989816, 'adceq sb, sl, ip, asr 13')],
        calls=[(5989468, 'blx r3'), (5989544, 'blx r2'), (5989640, 'blx ip'), (5989740, 'blx ip')],
        branches=[(5989480, 'beq', 5989768), (5989556, 'beq', 5989648)],
        semantics=('[World -[pauseResumeButtonTapped]] (imp 0x005b6410, 107w): the pause/resume button - setPaused: + hidePauseUIIfAble + shouldDisplayInterstitial -> displayInterstitialForTag:; pauseIdleTimer pool reset.\n'),
    ),
    dict(
        name='wx_22',
        method='World -[imagePickerFinishedWithImage:]',
        types='v12@0:4@8',
        start=6090768,
        end=6091192,
        disasm='disasm_worldtileloader_wx_22.txt',
        base_add=6090784,
        base_literal=6091188,
        boundary='ARM.exidx end 0x005cf1b8 (listing bound); next ObjC IMP 0x005cf1b8 World -[appendDebugLog:]',
        selectors={
                 0x5cf194: (15198188, 'setStatusBarHidden:'),
                 0x5cf198: (15196168, 'sharedApplication'),
                 0x5cf1a0: (15198184, 'pauseResumeButtonTapped'),
                 0x5cf1a4: (15198172, 'setHidePauseUI:'),
                 0x5cf1b0: (15198180, 'imagePickerFinishedWithImage:'),
        },
        imports={
                 0x5cf190: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cf1a8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5cf1ac: (17156740, 'OBJC_IVAR_$_World.imagePickerDelegate', 3440),
        },
        classes={
                 0x5cf19c: (15245432, 'OBJC_CLASS_$_UIApplication'),
        },
        instructions=[(6090768, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6091188, 'adceq r0, sb, ip, asr 21')],
        calls=[(6090996, 'blx lr'), (6091064, 'blx r4'), (6091084, 'blx r2'), (6091116, 'blx r3'), (6091140, 'blx r3')],
        branches=[],
        semantics=('[World -[imagePickerFinishedWithImage:]] (imp 0x005cf010, 106w): the image-picker return - UIApplication setStatusBarHidden: + pauseResume restore + hidePauseUI toggling through imagePickerDelegate.\n'),
    ),
    dict(
        name='wx_23',
        method='World -[setDpadControl:]',
        types='v12@0:4c8',
        start=6126024,
        end=6126432,
        disasm='disasm_worldtileloader_wx_23.txt',
        base_add=6126040,
        base_literal=6126428,
        boundary='ARM.exidx end 0x005d7b60 (listing bound); next ObjC IMP 0x005d7b60 World -[dpadControl]',
        selectors={
                 0x5d7b44: (15196180, 'startObservingMotionEvents'),
                 0x5d7b48: (15196196, 'stopObservingMotionEvents'),
                 0x5d7b50: (15197912, 'setBool:forKey:'),
                 0x5d7b54: (15195916, 'standardUserDefaults'),
        },
        imports={
                 0x5d7b40: (17151904, 'objc_msgSend'),
                 0x5d7b4c: (16231224, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d7b3c: (17156304, 'OBJC_IVAR_$_World.dpadControl', 3372),
        },
        classes={
                 0x5d7b58: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(6126024, 'push {r4, r5, fp, lr}'), (6126428, 'adceq r8, r8, r4, lsl r1')],
        calls=[(6126192, 'blx r2'), (6126240, 'blx r2'), (6126328, 'blx r2'), (6126384, 'blx lr')],
        branches=[(6126092, 'beq', 6126388), (6126148, 'beq', 6126200), (6126196, 'b', 6126244)],
        semantics=('[World -[setDpadControl:]] (imp 0x005d79c8, 102w): the dpad toggle - startObservingMotionEvents/stopObservingMotionEvents pair + NSUserDefaults setBool:forKey: persistence.\n'),
    ),
    dict(
        name='wx_24',
        method='World -[appendDebugLog:]',
        types='v12@0:4@8',
        start=6091192,
        end=6091572,
        disasm='disasm_worldtileloader_wx_24.txt',
        base_add=6091208,
        base_literal=6091568,
        boundary='ARM.exidx end 0x005cf334 (listing bound); next ObjC IMP 0x005cf334 World -[pvpEnabled]',
        selectors={
                 0x5cf314: (15198196, 'appendDebugLog:'),
                 0x5cf320: (15198192, 'appendFormat:'),
        },
        imports={
                 0x5cf310: (17151904, 'objc_msgSend'),
                 0x5cf31c: (16233272, '__CFConstantStringClassReference'),
                 0x5cf328: (16233256, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cf318: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5cf324: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x5cf32c: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
        },
        classes={},
        instructions=[(6091192, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6091568, 'adceq r0, sb, r4, lsr 18')],
        calls=[(6091404, 'blx ip'), (6091484, 'blx ip'), (6091524, 'blx ip')],
        branches=[],
        semantics=('[World -[appendDebugLog:]] (imp 0x005cf1b8, 95w): the debug-log forwarder - appendFormat: into the world log with the free/usedPhysicalBlocks counts.\n'),
    ),
    dict(
        name='wx_25',
        method='World -[setNewWelcomeMessage:]',
        types='v12@0:4@8',
        start=6092528,
        end=6092888,
        disasm='disasm_worldtileloader_wx_25.txt',
        base_add=6092544,
        base_literal=6092884,
        boundary='ARM.exidx end 0x005cf858 (listing bound); next ObjC IMP 0x005cf858 World -[welcomeMessageRecievedFromServer:]',
        selectors={
                 0x5cf848: (15195732, 'retain'),
                 0x5cf84c: (15195860, 'autorelease'),
                 0x5cf850: (15198204, 'sendNewWelcomeMessageToServer:'),
        },
        imports={
                 0x5cf844: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cf838: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5cf83c: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5cf840: (17155944, 'OBJC_IVAR_$_World.welcomeMessage', 3272),
        },
        classes={},
        instructions=[(6092528, 'push {r4, sl, fp, lr}'), (6092884, 'adceq r0, sb, ip, ror 7')],
        calls=[(6092668, 'blx r3'), (6092788, 'blx r2'), (6092820, 'blx r3')],
        branches=[(6092596, 'beq', 6092676), (6092672, 'b', 6092848), (6092712, 'beq', 6092844), (6092844, 'b', 6092848)],
        semantics=('[World -[setNewWelcomeMessage:]] (imp 0x005cf6f0, 90w): stores the welcome message (retain/autorelease) and calls sendNewWelcomeMessageToServer: behind the client/server gate.\n'),
    ),
    dict(
        name='wx_26',
        method='World -[startImagePickerWithDelegate:forRect:cropSize:]',
        types='v36@0:4@8{CGRect={CGPoint=ff}{CGSize=ff}}12{CGSize=ff}28',
        start=6090428,
        end=6090768,
        disasm='disasm_worldtileloader_wx_26.txt',
        base_add=6090508,
        base_literal=6090744,
        boundary='ARM.exidx end 0x005cf010 (listing bound); next ObjC IMP 0x005cf010 World -[imagePickerFinishedWithImage:]',
        selectors={
                 0x5ceffc: (15196464, 'pauseButtonTapped'),
                 0x5cf004: (15198172, 'setHidePauseUI:'),
                 0x5cf00c: (15198176, 'startImagePickerWithDelegate:forRect:cropSize:'),
        },
        imports={},
        ivars={
                 0x5ceff4: (17156740, 'OBJC_IVAR_$_World.imagePickerDelegate', 3440),
                 0x5cf000: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6090428, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6090764, 'invalid')],
        calls=[(6090540, 'bl loc.imp.objc_msgSend'), (6090580, 'bl loc.imp.objc_msgSend'), (6090728, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[startImagePickerWithDelegate:forRect:cropSize:]] (imp 0x005ceebc, 85w): the image-picker starter - pauseButtonTapped + hidePauseUI: + startImagePickerWithDelegate:forRect:cropSize: (3 objc_msgSend).\n'),
    ),
    dict(
        name='wx_27',
        method='World -[setDpadDirectControlDisabled:]',
        types='v12@0:4c8',
        start=6126492,
        end=6126764,
        disasm='disasm_worldtileloader_wx_27.txt',
        base_add=6126508,
        base_literal=6126760,
        boundary='ARM.exidx end 0x005d7cac (listing bound); next ObjC IMP 0x005d7cac World -[dpadDirectControlDisabled]',
        selectors={
                 0x5d7c9c: (15197912, 'setBool:forKey:'),
                 0x5d7ca0: (15195916, 'standardUserDefaults'),
        },
        imports={
                 0x5d7c94: (16231240, '__CFConstantStringClassReference'),
                 0x5d7c98: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d7c90: (17156300, 'OBJC_IVAR_$_World.dpadDirectControlDisabled', 3373),
        },
        classes={
                 0x5d7ca4: (15245352, 'OBJC_CLASS_$_NSUserDefaults'),
        },
        instructions=[(6126492, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6126760, 'adceq r7, r8, r0, asr 30')],
        calls=[(6126668, 'blx r2'), (6126724, 'blx lr')],
        branches=[(6126560, 'beq', 6126728)],
        semantics=('[World -[setDpadDirectControlDisabled:]] (imp 0x005d7b9c, 68w): bare flag setter - NSUserDefaults setBool:forKey: for dpadDirectControlDisabled.\n'),
    ),
    dict(
        name='wx_28',
        method='World -[abortInProgressPathIfForBlockhead:]',
        types='v12@0:4@8',
        start=6036688,
        end=6036956,
        disasm='disasm_worldtileloader_wx_28.txt',
        base_add=6036704,
        base_literal=6036952,
        boundary='ARM.exidx end 0x005c1ddc (listing bound); next ObjC IMP 0x005c1ddc World -[waterMovedFrom:fromTile:to:toTile:amount:]',
        selectors={
                 0x5c1dc8: (15196372, 'inProgress'),
                 0x5c1dd0: (15196380, 'pathUser'),
                 0x5c1dd4: (15196388, 'abortPath'),
        },
        imports={
                 0x5c1dc4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c1dcc: (17156260, 'OBJC_IVAR_$_World.pathCreator', 424),
        },
        classes={},
        instructions=[(6036688, 'push {r4, sl, fp, lr}'), (6036952, 'adceq sp, sb, ip, lsl 28')],
        calls=[(6036768, 'blx ip'), (6036844, 'blx r2'), (6036920, 'blx r2')],
        branches=[(6036780, 'beq', 6036924), (6036856, 'bne', 6036924)],
        semantics=('[World -[abortInProgressPathIfForBlockhead:]] (imp 0x005c1cd0, 67w): the path abort - inProgress/pathUser checks then abortPath on pathCreator.\n'),
    ),
    dict(
        name='wx_29',
        method='World -[incentivizedVideoViewComplete:]',
        types='v12@0:4c8',
        start=6065552,
        end=6065816,
        disasm='disasm_worldtileloader_wx_29.txt',
        base_add=6065568,
        base_literal=6065812,
        boundary='ARM.exidx end 0x005c8e98 (listing bound); next ObjC IMP 0x005c8e98 World -[zoomToPortalAtPosition:]',
        selectors={
                 0x5c8e84: (15198068, 'incentivizedVideoViewComplete:'),
                 0x5c8e88: (15197452, 'craftProgressUI'),
                 0x5c8e90: (15198064, 'tcUI'),
        },
        imports={
                 0x5c8e80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c8e8c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6065552, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6065812, 'adceq r6, sb, ip, asr 26')],
        calls=[(6065672, 'blx ip'), (6065708, 'blx ip'), (6065744, 'blx r3'), (6065780, 'blx ip')],
        branches=[],
        semantics=('[World -[incentivizedVideoViewComplete:]] (imp 0x005c8d90, 66w): the rewarded-video completion - uiManager forward with craftProgressUI/tcUI refresh (3 msgSend).\n'),
    ),
    dict(
        name='wx_30',
        method='World -[welcomeMessageDictRecieved:fromClient:]',
        types='v16@0:4@8@12',
        start=6091632,
        end=6091888,
        disasm='disasm_worldtileloader_wx_30.txt',
        base_add=6091648,
        base_literal=6091884,
        boundary='ARM.exidx end 0x005cf470 (listing bound); next ObjC IMP 0x005cf470 World -[viewOrEditWelcomeMessage]',
        selectors={
                 0x5cf45c: (15195732, 'retain'),
                 0x5cf464: (15195624, 'objectForKey:'),
                 0x5cf468: (15195768, 'release'),
        },
        imports={
                 0x5cf458: (17151904, 'objc_msgSend'),
                 0x5cf460: (16233288, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5cf454: (17155944, 'OBJC_IVAR_$_World.welcomeMessage', 3272),
        },
        classes={},
        instructions=[(6091632, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6091884, 'adceq r0, sb, ip, ror 14')],
        calls=[(6091788, 'blx r4'), (6091812, 'blx r3'), (6091828, 'blx r2')],
        branches=[],
        semantics=('[World -[welcomeMessageDictRecieved:fromClient:]] (imp 0x005cf370, 64w): the welcome-dict intake - objectForKey: decode with retain/release into welcomeMessage.\n'),
    ),
    dict(
        name='wx_31',
        method='World -[textFieldShouldReturn:]',
        types='c12@0:4@8',
        start=6103192,
        end=6103436,
        disasm='disasm_worldtileloader_wx_31.txt',
        base_add=6103208,
        base_literal=6103432,
        boundary='ARM.exidx end 0x005d218c (listing bound); next ObjC IMP 0x005d218c World -[reportButtonTappedForPlayer:]',
        selectors={
                 0x5d217c: (15196216, 'textFieldAtIndex:'),
                 0x5d2184: (15196204, 'dismissWithClickedButtonIndex:animated:'),
        },
        imports={
                 0x5d2178: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d2180: (17156396, 'OBJC_IVAR_$_World.messageEntryAlertView', 3436),
        },
        classes={},
        instructions=[(6103192, 'push {r4, r5, fp, lr}'), (6103432, 'adceq sp, r8, r4, asr 20')],
        calls=[(6103296, 'blx lr'), (6103396, 'blx lr')],
        branches=[(6103308, 'bne', 6103400)],
        semantics=('[World -[textFieldShouldReturn:]] (imp 0x005d2098, 61w): the message-entry return - textFieldAtIndex: + dismissWithClickedButtonIndex:animated: on messageEntryAlertView.\n'),
    ),
    dict(
        name='wx_32',
        method='World -[showTutorialPopupWithTitle:message:]',
        types='v16@0:4@8@12',
        start=6087028,
        end=6087264,
        disasm='disasm_worldtileloader_wx_32.txt',
        base_add=6087044,
        base_literal=6087260,
        boundary='ARM.exidx end 0x005ce260 (listing bound); next ObjC IMP 0x005ce260 World -[transactionDataRecieved:fromClient:]',
        selectors={
                 0x5ce24c: (15198160, 'showTutorialPopupWithTitle:message:lastMessage:'),
                 0x5ce250: (15198148, 'lastState'),
        },
        imports={
                 0x5ce248: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5ce254: (17156044, 'OBJC_IVAR_$_World.tutorial', 232),
        },
        classes={},
        instructions=[(6087028, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6087260, 'adceq r1, sb, r8, ror 18')],
        calls=[(6087180, 'blx lr'), (6087228, 'blx lr')],
        branches=[],
        semantics=('[World -[showTutorialPopupWithTitle:message:]] (imp 0x005ce174, 59w): the tutorial popup forwarder - showTutorialPopupWithTitle:message:lastMessage: with the tutorial lastState.\n'),
    ),
    dict(
        name='wx_33',
        method='World -[showWorldCreditUI]',
        types='v8@0:4',
        start=6106000,
        end=6106236,
        disasm='disasm_worldtileloader_wx_33.txt',
        base_add=6106016,
        base_literal=6106232,
        boundary='ARM.exidx end 0x005d2c7c (listing bound); next ObjC IMP 0x005d2c7c World -[getCurrentCreditTimeString]',
        selectors={
                 0x5d2c68: (15198300, 'selectAddCreditOption:'),
                 0x5d2c6c: (15197116, 'pauseUI'),
                 0x5d2c74: (15196464, 'pauseButtonTapped'),
        },
        imports={
                 0x5d2c64: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d2c70: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6106000, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6106232, 'adceq ip, r8, ip, asr 30')],
        calls=[(6106112, 'blx r3'), (6106164, 'blx ip'), (6106200, 'blx ip')],
        branches=[],
        semantics=('[World -[showWorldCreditUI]] (imp 0x005d2b90, 59w): the world-credit UI - pauseUI pauseButtonTapped + selectAddCreditOption:.\n'),
    ),
    dict(
        name='wx_34',
        method='World -[playersChanged]',
        types='v8@0:4',
        start=6063964,
        end=6064196,
        disasm='disasm_worldtileloader_wx_34.txt',
        base_add=6063980,
        base_literal=6064192,
        boundary='ARM.exidx end 0x005c8844 (listing bound); next ObjC IMP 0x005c8844 World -[updatePhysicalBlockToLatestVersion:]',
        selectors={
                 0x5c882c: (15198052, 'playersChanged'),
                 0x5c8834: (15198048, 'setPlayersChanged:'),
                 0x5c8838: (15196764, 'worldUI'),
        },
        imports={
                 0x5c8828: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c8830: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5c883c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6063964, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6064192, 'adceq r7, sb, r0, lsl 7')],
        calls=[(6064096, 'blx r3'), (6064120, 'blx r3'), (6064156, 'blx r3')],
        branches=[],
        semantics=('[World -[playersChanged]] (imp 0x005c875c, 58w): the players-changed notifier - dynamicWorld playersChanged/setPlayersChanged: + worldUI refresh.\n'),
    ),
    dict(
        name='wx_35',
        method='World -[pauseExitToMenuButtonTapped]',
        types='v8@0:4',
        start=5989820,
        end=5990040,
        disasm='disasm_worldtileloader_wx_35.txt',
        base_add=5989836,
        base_literal=5990036,
        boundary='ARM.exidx end 0x005b6698 (listing bound); next ObjC IMP 0x005b6698 World -[fullyLoadAndUpdateIfNeededForMacroBlock:includingPos:clientLightBlockIndex:forBlockhead:]',
        selectors={
                 0x5b6688: (15197572, 'exitWorld'),
        },
        imports={
                 0x5b6684: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(5989820, 'push {r4, r5, r6, sl, fp, lr}'), (5990036, 'adceq sb, sl, r0, lsr 10')],
        calls=[(5989884, 'bl sym.imp.__android_log_print'), (5989980, 'blx lr'), (5989996, 'bl sym.imp.__android_log_print')],
        branches=[],
        semantics=('[World -[pauseExitToMenuButtonTapped]] (imp 0x005b65bc, 55w): __android_log_print x2 then exitWorld - the Android log-bridge stub around the exit path.\n'),
    ),
    dict(
        name='wx_36',
        method='World -[canAddWorldCredit]',
        types='c8@0:4',
        start=6105784,
        end=6106000,
        disasm='disasm_worldtileloader_wx_36.txt',
        base_add=6105800,
        base_literal=6105996,
        boundary='ARM.exidx end 0x005d2b90 (listing bound); next ObjC IMP 0x005d2b90 World -[showWorldCreditUI]',
        selectors={
                 0x5d2b78: (15195740, 'isCloudMatch'),
        },
        imports={
                 0x5d2b74: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d2b7c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d2b88: (17155988, 'OBJC_IVAR_$_World.clientsideCredit', 3300),
        },
        classes={},
        instructions=[(6105784, 'push {r4, sl, fp, lr}'), (6105996, 'adceq sp, r8, r4, lsr 32')],
        calls=[(6105868, 'blx ip')],
        branches=[(6105888, 'beq', 6105952)],
        semantics=('[World -[canAddWorldCredit]] (imp 0x005d2ab8, 54w): the credit gate - client check + the [0x5d2b84] pool float threshold against clientsideCredit + isCloudMatch.\n'),
    ),
    dict(
        name='wx_37',
        method='World -[.cxx_destruct]',
        types='v8@0:4',
        start=6138508,
        end=6138724,
        disasm='disasm_worldtileloader_wx_37.txt',
        base_add=6138524,
        base_literal=6138672,
        boundary='ARM.exidx end 0x005dab64 (listing bound); next ObjC IMP 0x005dab64 World -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x5dab24: (17156364, 'OBJC_IVAR_$_World.usedPhysicalBlocks', 456),
                 0x5dab28: (17156368, 'OBJC_IVAR_$_World.freePhysicalBlocks', 476),
                 0x5dab2c: (17156624, 'OBJC_IVAR_$_World.latestMapData', 3192),
        },
        classes={},
        instructions=[(6138508, 'push {fp, lr}'), (6138720, 'pop {fp, pc}')],
        calls=[(6138572, 'bl method.std::__1::map_int__unsigned_char__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__unsigned_char_____._map__'), (6138608, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (6138644, 'bl method.std::__1::unordered_set_PhysicalBlock__std::__1::hash_PhysicalBlock___std::__1::equal_to_PhysicalBlock___std::__1::allocator_PhysicalBlock___._unordered_set__'), (6138700, 'bl method.std::__1::__tree_std::__1::pair_int__unsigned_char___std::__1::__map_value_compare_int__unsigned_char__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__unsigned_char_____.___tree__')],
        branches=[],
        semantics=('[World -[.cxx_destruct]] (imp 0x005daa8c, 54w): the C++ member destructor - std::unordered_set<PhysicalBlock> dtor x2 (used/freePhysicalBlocks) + std::map<int, unsigned char> dtor x1 (latestMapData) - completing the member set E113\'s .cxx_construct opens.\n'),
    ),
    dict(
        name='wx_38',
        method='World -[connected]',
        types='c8@0:4',
        start=5582168,
        end=5582376,
        disasm='disasm_worldtileloader_wx_38.txt',
        base_add=5582184,
        base_literal=5582372,
        boundary='ARM.exidx end 0x00552e28 (listing bound); next ObjC IMP 0x00552e28 World -[startPinchOrPan]',
        selectors={
                 0x552e14: (15195536, 'currentReachabilityStatus'),
                 0x552e1c: (15195532, 'reachabilityWithHostName:'),
        },
        imports={
                 0x552e0c: (16228504, '__CFConstantStringClassReference'),
                 0x552e10: (17151904, 'objc_msgSend'),
                 0x552e18: (16228488, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x552e20: (15245276, 'OBJC_CLASS_$_Reachability'),
        },
        instructions=[(5582168, 'push {r4, r5, r6, r7, fp, lr}'), (5582372, 'adcseq ip, r0, r4, lsl 27')],
        calls=[(5582272, 'blx ip'), (5582296, 'blx r2'), (5582312, 'bl sym.imp.NSLog')],
        branches=[],
        semantics=('[World -[connected]] (imp 0x00552d58, 52w): the connectivity check - Reachability reachabilityWithHostName: + currentReachabilityStatus + NSLog.\n'),
    ),
    dict(
        name='wx_39',
        method='World -[addItemToFoundList:]',
        types='v12@0:4@8',
        start=6128780,
        end=6128988,
        disasm='disasm_worldtileloader_wx_39.txt',
        base_add=6128796,
        base_literal=6128984,
        boundary='ARM.exidx end 0x005d855c (listing bound); next ObjC IMP 0x005d855c World -[addChestItemsToFoundList:]',
        selectors={
                 0x5d8550: (15198368, 'privateAddItemToFoundList:addBasketContents:'),
        },
        imports={
                 0x5d854c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8548: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d8554: (17155968, 'OBJC_IVAR_$_World.foundItemsListNeedsToBeSentToServer', 3380),
        },
        classes={},
        instructions=[(6128780, 'push {r4, r5, r6, sl, fp, lr}'), (6128984, 'adceq r7, r8, r0, asr r6')],
        calls=[(6128876, 'blx r5')],
        branches=[(6128912, 'beq', 6128960), (6128924, 'beq', 6128960)],
        semantics=('[World -[addItemToFoundList:]] (imp 0x005d848c, 52w): forwards to privateAddItemToFoundList:addBasketContents: with addBasketContents:0 behind the client gate.\n'),
    ),
    dict(
        name='wx_40',
        method='World -[cancelAllActionsAtPos:orWithInteractionObjectID:]',
        types='v24@0:4{?=ii}8Q16',
        start=5943724,
        end=5943924,
        disasm='disasm_worldtileloader_wx_40.txt',
        base_add=5943780,
        base_literal=5943912,
        boundary='ARM.exidx end 0x005ab274 (listing bound); next ObjC IMP 0x005ab274 World -[queueBlockheadAIActionToTile:atPos:forBlockhead:]',
        selectors={
                 0x5ab26c: (15196444, 'activeBlockhead'),
                 0x5ab270: (15197300, 'cancelAnyActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:'),
        },
        imports={},
        ivars={
                 0x5ab264: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5943724, 'push {r4, r5, r6, sl, fp, lr}'), (5943920, 'invalid')],
        calls=[(5943808, 'bl loc.imp.objc_msgSend'), (5943892, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[cancelAllActionsAtPos:orWithInteractionObjectID:]] (imp 0x005ab1ac, 50w): cancels the active blockhead\'s action at the pos/object via cancelAnyActionAtGoalPos:orWithInteractionObjectID:goalInteraction:craftCountOrExtraData:.\n'),
    ),
    dict(
        name='wx_41',
        method='World -[shareURL:message:fromRect:]',
        types='v32@0:4@8@12{CGRect={CGPoint=ff}{CGSize=ff}}16',
        start=6107976,
        end=6108176,
        disasm='disasm_worldtileloader_wx_41.txt',
        base_add=6108048,
        base_literal=6108168,
        boundary='ARM.exidx end 0x005d3410 (listing bound); next ObjC IMP 0x005d3410 World -[worldUI]',
        selectors={
                 0x5d340c: (15198312, 'presentShareUIForURL:message:rectFromScreenCenter:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6107976, 'push {r4, r5, r6, sl, fp, lr}'), (6108172, 'invalid')],
        calls=[(6108152, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[shareURL:message:fromRect:]] (imp 0x005d3348, 50w): the share-sheet forwarder - presentShareUIForURL:message:rectFromScreenCenter:.\n'),
    ),
    dict(
        name='wx_42',
        method='World -[openOwnerPortal]',
        types='v8@0:4',
        start=6108276,
        end=6108472,
        disasm='disasm_worldtileloader_wx_42.txt',
        base_add=6108292,
        base_literal=6108468,
        boundary='ARM.exidx end 0x005d3538 (listing bound); next ObjC IMP 0x005d3538 World -[signOwnershipPlayerListRecievedFromServer:]',
        selectors={
                 0x5d3524: (15198316, 'openOwnerPortalWithUserName:'),
                 0x5d3528: (15198100, 'localPlayerName'),
        },
        imports={
                 0x5d3520: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d352c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5d3530: (17156748, 'OBJC_IVAR_$_World.cloudInterface', 236),
        },
        classes={},
        instructions=[(6108276, 'push {r4, r5, r6, sl, fp, lr}'), (6108468, 'adceq ip, r8, r8, ror 12')],
        calls=[(6108404, 'blx r3'), (6108436, 'blx r3')],
        branches=[],
        semantics=('[World -[openOwnerPortal]] (imp 0x005d3474, 49w): opens the owner portal - CloudInterface openOwnerPortalWithUserName: with localPlayerName.\n'),
    ),
    dict(
        name='wx_43',
        method='World -[saveSunlightChangedAtPos:]',
        types='v16@0:4{?=ii}8',
        start=6021836,
        end=6022008,
        disasm='disasm_worldtileloader_wx_43.txt',
        base_add=6021876,
        base_literal=6022000,
        boundary='ARM.exidx end 0x005be378 (listing bound); next ObjC IMP 0x005be378 World -[endCalibration]',
        selectors={
                 0x5be374: (15197712, 'lightChangedAtMacroPos:sendReliably:'),
        },
        imports={},
        ivars={
                 0x5be36c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6021836, 'push {fp, lr}'), (6022004, 'invalid')],
        calls=[(6021944, 'bl sym.makeIntpair_int__int_'), (6021984, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[saveSunlightChangedAtPos:]] (imp 0x005be2cc, 43w): the sunlight-change sync - makeIntpair + lightChangedAtMacroPos:sendReliably: on dynamicWorld.\n'),
    ),
    dict(
        name='wx_44',
        method='World -[newServerPasswordSet:]',
        types='v12@0:4@8',
        start=6099928,
        end=6100100,
        disasm='disasm_worldtileloader_wx_44.txt',
        base_add=6099944,
        base_literal=6100096,
        boundary='ARM.exidx end 0x005d1484 (listing bound); next ObjC IMP 0x005d1484 World -[sendNewPasswordToServer:]',
        selectors={
                 0x5d1478: (15195732, 'retain'),
                 0x5d147c: (15195768, 'release'),
        },
        imports={
                 0x5d1474: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d1470: (17155932, 'OBJC_IVAR_$_World.serverPassword', 3288),
        },
        classes={},
        instructions=[(6099928, 'push {r4, r5, r6, sl, fp, lr}'), (6100096, 'adceq lr, r8, r4, lsl 14')],
        calls=[(6100028, 'blx lr'), (6100048, 'blx r2')],
        branches=[],
        semantics=('[World -[newServerPasswordSet:]] (imp 0x005d13d8, 43w): stores serverPassword (retain/release).\n'),
    ),
    dict(
        name='wx_45',
        method='World -[pauseButtonTapped]',
        types='v8@0:4',
        start=5989224,
        end=5989392,
        disasm='disasm_worldtileloader_wx_45.txt',
        base_add=5989240,
        base_literal=5989388,
        boundary='ARM.exidx end 0x005b6410 (listing bound); next ObjC IMP 0x005b6410 World -[pauseResumeButtonTapped]',
        selectors={
                 0x5b6400: (15197552, 'displayPauseUIIfAble'),
                 0x5b6408: (15197556, 'pauseUpdates'),
        },
        imports={
                 0x5b63fc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b6404: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5989224, 'push {fp, lr}'), (5989388, 'adceq sb, sl, r4, ror r7')],
        calls=[(5989300, 'blx r3'), (5989360, 'blx r2')],
        branches=[(5989316, 'beq', 5989364)],
        semantics=('[World -[pauseButtonTapped]] (imp 0x005b6368, 42w): the pause button - uiManager displayPauseUIIfAble + dynamicWorld pauseUpdates.\n'),
    ),
    dict(
        name='wx_46',
        method='World -[playerIsMuted:]',
        types='c12@0:4@8',
        start=6094336,
        end=6094500,
        disasm='disasm_worldtileloader_wx_46.txt',
        base_add=6094352,
        base_literal=6094496,
        boundary='ARM.exidx end 0x005cfea4 (listing bound); next ObjC IMP 0x005cfea4 World -[setPlayerMuted:withID:]',
        selectors={
                 0x5cfe94: (15198220, 'containsObject:'),
                 0x5cfe9c: (15198216, 'initMuteList'),
        },
        imports={
                 0x5cfe90: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5cfe98: (17156356, 'OBJC_IVAR_$_World.mutedPlayers', 3284),
        },
        classes={},
        instructions=[(6094336, 'push {r4, r5, r6, sl, fp, lr}'), (6094496, 'invalid')],
        calls=[(6094424, 'blx ip'), (6094464, 'blx ip')],
        branches=[],
        semantics=('[World -[playerIsMuted:]] (imp 0x005cfe00, 41w): the mute check - initMuteList lazy + containsObject: on mutedPlayers.\n'),
    ),
    dict(
        name='wx_47',
        method='World -[worldUIDragging]',
        types='c8@0:4',
        start=6020524,
        end=6020668,
        disasm='disasm_worldtileloader_wx_47.txt',
        base_add=6020540,
        base_literal=6020664,
        boundary='ARM.exidx end 0x005bde3c (listing bound); next ObjC IMP 0x005bde3c World -[stopFollowingOrTranslatingToGoal]',
        selectors={
                 0x5bde2c: (15197700, 'dragActive'),
                 0x5bde30: (15196764, 'worldUI'),
        },
        imports={
                 0x5bde28: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bde34: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6020524, 'push {r4, r5, fp, lr}'), (6020664, 'adceq r1, sl, r0, lsr sp')],
        calls=[(6020616, 'blx r3'), (6020632, 'blx r2')],
        branches=[],
        semantics=('[World -[worldUIDragging]] (imp 0x005bddac, 36w): the drag-state read - uiManager worldUI + dragActive.\n'),
    ),
    dict(
        name='wx_48',
        method='World -[currentTotalBlockheadCountIncludingNet]',
        types='i8@0:4',
        start=6063712,
        end=6063852,
        disasm='disasm_worldtileloader_wx_48.txt',
        base_add=6063728,
        base_literal=6063848,
        boundary='ARM.exidx end 0x005c86ec (listing bound); next ObjC IMP 0x005c86ec World -[isControllingBlockheadsForClientPlayer:]',
        selectors={
                 0x5c86dc: (15195604, 'count'),
                 0x5c86e0: (15196652, 'allBlockheadsIncludingNet'),
        },
        imports={
                 0x5c86d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c86e4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6063712, 'push {r4, r5, fp, lr}'), (6063848, 'adceq r7, sb, ip, ror r4')],
        calls=[(6063804, 'blx r3'), (6063820, 'blx r2')],
        branches=[],
        semantics=('[World -[currentTotalBlockheadCountIncludingNet]] (imp 0x005c8660, 35w): the blockhead count - allBlockheadsIncludingNet count.\n'),
    ),
    dict(
        name='wx_49',
        method='World -[customRulesChanged]',
        types='v8@0:4',
        start=6116996,
        end=6117136,
        disasm='disasm_worldtileloader_wx_49.txt',
        base_add=6117012,
        base_literal=6117132,
        boundary='ARM.exidx end 0x005d5710 (listing bound); next ObjC IMP 0x005d5710 World -[setCustomRule:forOptionNamed:]',
        selectors={
                 0x5d5700: (15195824, 'customRulesChanged'),
                 0x5d5704: (15196640, 'regenerateUI'),
        },
        imports={
                 0x5d56fc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d5708: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6116996, 'push {r4, r5, fp, lr}'), (6117132, 'adceq sl, r8, r8, asr r4')],
        calls=[(6117088, 'blx r3'), (6117104, 'blx r2')],
        branches=[],
        semantics=('[World -[customRulesChanged]] (imp 0x005d5684, 35w): the rules-changed notifier - uiManager customRulesChanged/regenerateUI.\n'),
    ),
    dict(
        name='wx_50',
        method='World -[foundListContainsEggWithDodoBreed:]',
        types='c12@0:4i8',
        start=6130156,
        end=6130280,
        disasm='disasm_worldtileloader_wx_50.txt',
        base_add=6130172,
        base_literal=6130276,
        boundary='ARM.exidx end 0x005d8a68 (listing bound); next ObjC IMP 0x005d8a68 World -[hideChatView]',
        selectors={
                 0x5d8a5c: (15196752, 'containsIndex:'),
        },
        imports={
                 0x5d8a58: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8a60: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
        },
        classes={},
        instructions=[(6130156, 'push {r4, sl, fp, lr}'), (6130276, 'invalid')],
        calls=[(6130248, 'blx ip')],
        branches=[],
        semantics=('[World -[foundListContainsEggWithDodoBreed:]] (imp 0x005d89ec, 31w): foundItemsList containsIndex: query.\n'),
    ),
    dict(
        name='wx_51',
        method='World -[customRuleForOptionNamed:]',
        types='@12@0:4@8',
        start=6116876,
        end=6116996,
        disasm='disasm_worldtileloader_wx_51.txt',
        base_add=6116892,
        base_literal=6116992,
        boundary='ARM.exidx end 0x005d5684 (listing bound); next ObjC IMP 0x005d5684 World -[customRulesChanged]',
        selectors={
                 0x5d5678: (15195624, 'objectForKey:'),
        },
        imports={
                 0x5d5674: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d567c: (17155952, 'OBJC_IVAR_$_World.customRulesDict', 224),
        },
        classes={},
        instructions=[(6116876, 'push {r4, sl, fp, lr}'), (6116992, 'invalid')],
        calls=[(6116968, 'blx ip')],
        branches=[],
        semantics=('[World -[customRuleForOptionNamed:]] (imp 0x005d560c, 30w): customRulesDict objectForKey: getter.\n'),
    ),
    dict(
        name='wx_52',
        method='World -[addDodoEggToFoundListWithBreed:]',
        types='v12@0:4i8',
        start=6130036,
        end=6130156,
        disasm='disasm_worldtileloader_wx_52.txt',
        base_add=6130052,
        base_literal=6130152,
        boundary='ARM.exidx end 0x005d89ec (listing bound); next ObjC IMP 0x005d89ec World -[foundListContainsEggWithDodoBreed:]',
        selectors={
                 0x5d89e0: (15196176, 'addIndex:'),
        },
        imports={
                 0x5d89dc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d89e4: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
        },
        classes={},
        instructions=[(6130036, 'push {r4, sl, fp, lr}'), (6130152, 'adceq r7, r8, r8, ror 2')],
        calls=[(6130128, 'blx ip')],
        branches=[],
        semantics=('[World -[addDodoEggToFoundListWithBreed:]] (imp 0x005d8974, 30w): foundItemsList addIndex:.\n'),
    ),
    dict(
        name='wx_53',
        method='World -[isControllingBlockheadsForClientPlayer:]',
        types='c12@0:4@8',
        start=6063852,
        end=6063964,
        disasm='disasm_worldtileloader_wx_53.txt',
        base_add=6063868,
        base_literal=6063960,
        boundary='ARM.exidx end 0x005c875c (listing bound); next ObjC IMP 0x005c875c World -[playersChanged]',
        selectors={
                 0x5c8750: (15196540, 'isControllingBlockheadsForClientPlayer:'),
        },
        imports={
                 0x5c874c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c8754: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(6063852, 'push {r4, sl, fp, lr}'), (6063960, 'invalid')],
        calls=[(6063932, 'blx ip')],
        branches=[],
        semantics=('[World -[isControllingBlockheadsForClientPlayer:]] (imp 0x005c86ec, 28w): forwards to dynamicWorld isControllingBlockheadsForClientPlayer:.\n'),
    ),
    dict(
        name='wx_54',
        method='World -[updatePhysicalBlockToLatestVersion:]',
        types='v12@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8',
        start=6064196,
        end=6064304,
        disasm='disasm_worldtileloader_wx_54.txt',
        base_add=6064212,
        base_literal=6064300,
        boundary='ARM.exidx end 0x005c88b0 (listing bound); next ObjC IMP 0x005c88b0 World -[tileIsLitForClient:atPos:tile:]',
        selectors={
                 0x5c88a4: (15198056, 'updatePhysicalBlockToLatestVersion:'),
        },
        imports={
                 0x5c88a0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c88a8: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
        },
        classes={},
        instructions=[(6064196, 'push {r4, sl, fp, lr}'), (6064300, 'umlaleq r7, sb, r8, r2')],
        calls=[(6064276, 'blx ip')],
        branches=[],
        semantics=('[World -[updatePhysicalBlockToLatestVersion:]] (imp 0x005c8844, 27w): forwards to worldTileLoader updatePhysicalBlockToLatestVersion:.\n'),
    ),
    dict(
        name='wx_55',
        method='World -[showDieConfirmationForBlockhead:]',
        types='v12@0:4@8',
        start=6090240,
        end=6090348,
        disasm='disasm_worldtileloader_wx_55.txt',
        base_add=6090256,
        base_literal=6090344,
        boundary='ARM.exidx end 0x005cee6c (listing bound); next ObjC IMP 0x005cee6c World -[dieConfirmationConfirmed:]',
        selectors={
                 0x5cee60: (15198164, 'showDieConfirmationForBlockhead:'),
        },
        imports={
                 0x5cee5c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6090240, 'push {r4, sl, fp, lr}'), (6090344, 'invalid')],
        calls=[(6090320, 'blx ip')],
        branches=[],
        semantics=('[World -[showDieConfirmationForBlockhead:]] (imp 0x005cee00, 27w): forwards showDieConfirmationForBlockhead: to the delegate.\n'),
    ),
    dict(
        name='wx_56',
        method='World -[addItemsFromServerFoundItemsList:]',
        types='v12@0:4@8',
        start=6126824,
        end=6126932,
        disasm='disasm_worldtileloader_wx_56.txt',
        base_add=6126840,
        base_literal=6126928,
        boundary='ARM.exidx end 0x005d7d54 (listing bound); next ObjC IMP 0x005d7d54 World -[sendUpdatedFoundItemsListToServer]',
        selectors={
                 0x5d7d48: (15195868, 'addIndexes:'),
        },
        imports={
                 0x5d7d44: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d7d4c: (17156032, 'OBJC_IVAR_$_World.foundItemsList', 3376),
        },
        classes={},
        instructions=[(6126824, 'push {r4, sl, fp, lr}'), (6126928, 'invalid')],
        calls=[(6126904, 'blx ip')],
        branches=[],
        semantics=('[World -[addItemsFromServerFoundItemsList:]] (imp 0x005d7ce8, 27w): foundItemsList addIndexes:.\n'),
    ),
    dict(
        name='wx_57',
        method='World -[archiveLightBlocksForClient:]',
        types='v12@0:4@8',
        start=6131468,
        end=6131576,
        disasm='disasm_worldtileloader_wx_57.txt',
        base_add=6131484,
        base_literal=6131572,
        boundary='ARM.exidx end 0x005d8f78 (listing bound); next ObjC IMP 0x005d8f78 World -[doRepairForTileAtPos:]',
        selectors={
                 0x5d8f6c: (15198384, 'archiveLightBlocksForClient:'),
        },
        imports={
                 0x5d8f68: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d8f70: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
        },
        classes={},
        instructions=[(6131468, 'push {r4, sl, fp, lr}'), (6131572, 'invalid')],
        calls=[(6131548, 'blx ip')],
        branches=[],
        semantics=('[World -[archiveLightBlocksForClient:]] (imp 0x005d8f0c, 27w): forwards to worldTileLoader archiveLightBlocksForClient:.\n'),
    ),
    dict(
        name='wx_58',
        method='World -[setPinchScale:]',
        types='v16@0:4d8',
        start=6136636,
        end=6136744,
        disasm='disasm_worldtileloader_wx_58.txt',
        base_add=6136652,
        base_literal=6136740,
        boundary='ARM.exidx end 0x005da3a8 (listing bound); next ObjC IMP 0x005da3a8 World -[dragInProgress]',
        selectors={},
        imports={},
        ivars={
                 0x5da3a0: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
        },
        classes={},
        instructions=[(6136636, 'push {r4, r5, fp, lr}'), (6136740, 'adceq r5, r8, r0, lsr 15')],
        calls=[(6136724, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[World -[setPinchScale:]] (imp 0x005da33c, 27w): the pinch-scale setter - objc_copyStruct 8-byte copy into pinchScale.\n'),
    ),
    dict(
        name='wx_59',
        method='World -[mapVisible]',
        types='c8@0:4',
        start=6065448,
        end=6065552,
        disasm='disasm_worldtileloader_wx_59.txt',
        base_add=6065464,
        base_literal=6065548,
        boundary='ARM.exidx end 0x005c8d90 (listing bound); next ObjC IMP 0x005c8d90 World -[incentivizedVideoViewComplete:]',
        selectors={
                 0x5c8d84: (15197184, 'mapDisplayed'),
        },
        imports={
                 0x5c8d80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c8d88: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6065448, 'push {fp, lr}'), (6065548, 'invalid')],
        calls=[(6065520, 'blx r3')],
        branches=[],
        semantics=('[World -[mapVisible]] (imp 0x005c8d28, 26w): the map-visibility read - uiManager mapDisplayed.\n'),
    ),
    dict(
        name='wx_60',
        method='World -[banPlayerWithNameFromPlayerButton:]',
        types='v12@0:4@8',
        start=6098012,
        end=6098116,
        disasm='disasm_worldtileloader_wx_60.txt',
        base_add=6098028,
        base_literal=6098112,
        boundary='ARM.exidx end 0x005d0cc4 (listing bound); next ObjC IMP 0x005d0cc4 World -[kickPlayerWithNameFromPlayerButton:]',
        selectors={
                 0x5d0cbc: (15198256, 'kickOrBanPlayerFromButtonIsBan:withName:'),
        },
        imports={
                 0x5d0cb8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6098012, 'push {r4, sl, fp, lr}'), (6098112, 'adceq lr, r8, r0, lsl 29')],
        calls=[(6098092, 'blx lr')],
        branches=[],
        semantics=('[World -[banPlayerWithNameFromPlayerButton:]] (imp 0x005d0c5c, 26w): forwards to kickOrBanPlayerFromButtonIsBan:withName: with isBan:1.\n'),
    ),
    dict(
        name='wx_61',
        method='World -[kickPlayerWithNameFromPlayerButton:]',
        types='v12@0:4@8',
        start=6098116,
        end=6098220,
        disasm='disasm_worldtileloader_wx_61.txt',
        base_add=6098132,
        base_literal=6098216,
        boundary='ARM.exidx end 0x005d0d2c (listing bound); next ObjC IMP 0x005d0d2c World -[isCloudGame]',
        selectors={
                 0x5d0d24: (15198256, 'kickOrBanPlayerFromButtonIsBan:withName:'),
        },
        imports={
                 0x5d0d20: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6098116, 'push {r4, sl, fp, lr}'), (6098216, 'adceq lr, r8, r8, lsl lr')],
        calls=[(6098196, 'blx lr')],
        branches=[],
        semantics=('[World -[kickPlayerWithNameFromPlayerButton:]] (imp 0x005d0cc4, 26w): forwards to kickOrBanPlayerFromButtonIsBan:withName: with isBan:0.\n'),
    ),
    dict(
        name='wx_62',
        method='World -[hasRewardedVideoAvailable]',
        types='c8@0:4',
        start=6123596,
        end=6123700,
        disasm='disasm_worldtileloader_wx_62.txt',
        base_add=6123612,
        base_literal=6123696,
        boundary='ARM.exidx end 0x005d70b4 (listing bound); next ObjC IMP 0x005d70b4 World -[verifyClientCustomRulesData:]',
        selectors={
                 0x5d70a8: (15198348, 'hasRewardedVideoAvailable'),
        },
        imports={
                 0x5d70a4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6123596, 'push {fp, lr}'), (6123696, 'umlaleq r8, r8, r0, sl')],
        calls=[(6123668, 'blx r3')],
        branches=[],
        semantics=('[World -[hasRewardedVideoAvailable]] (imp 0x005d704c, 26w): the rewarded-video availability query through the delegate.\n'),
    ),
    dict(
        name='wx_63',
        method='World -[iapStarted]',
        types='v8@0:4',
        start=6039440,
        end=6039540,
        disasm='disasm_worldtileloader_wx_63.txt',
        base_add=6039456,
        base_literal=6039536,
        boundary='ARM.exidx end 0x005c2858; body trimmed at the next IMP 0x005c27f4 World -[startIncentivizedVideo]',
        selectors={
                 0x5c27e8: (15197828, 'iapStarted'),
        },
        imports={
                 0x5c27e4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6039440, 'push {fp, lr}'), (6039536, 'adceq sp, sb, ip, asr 6')],
        calls=[(6039512, 'blx r3')],
        branches=[],
        semantics=('[World -[iapStarted]] (imp 0x005c2790, 25w): the IAP-started notifier forward (listing trimmed at the next IMP).\n'),
    ),
    dict(
        name='wx_64',
        method='World -[startIncentivizedVideo]',
        types='v8@0:4',
        start=6039540,
        end=6039640,
        disasm='disasm_worldtileloader_wx_64.txt',
        base_add=6039556,
        base_literal=6039636,
        boundary='ARM.exidx end 0x005c2858 (listing bound); next ObjC IMP 0x005c2858 World -[doubleTimePurchaseTapped]',
        selectors={
                 0x5c284c: (15197832, 'startIncentivizedVideo'),
        },
        imports={
                 0x5c2848: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6039540, 'push {fp, lr}'), (6039636, 'adceq sp, sb, r8, ror 5')],
        calls=[(6039612, 'blx r3')],
        branches=[],
        semantics=('[World -[startIncentivizedVideo]] (imp 0x005c27f4, 25w): the rewarded-video starter forward.\n'),
    ),
    dict(
        name='wx_65',
        method='World -[achievementsButtonTapped]',
        types='v8@0:4',
        start=6048608,
        end=6048708,
        disasm='disasm_worldtileloader_wx_65.txt',
        base_add=6048624,
        base_literal=6048704,
        boundary='ARM.exidx end 0x005c4c28; body trimmed at the next IMP 0x005c4bc4 World -[instructionsButtonTapped]',
        selectors={
                 0x5c4bb8: (15197928, 'achievementsButtonTapped'),
        },
        imports={
                 0x5c4bb4: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6048608, 'push {fp, lr}'), (6048704, 'adceq sl, sb, ip, ror pc')],
        calls=[(6048680, 'blx r3')],
        branches=[],
        semantics=('[World -[achievementsButtonTapped]] (imp 0x005c4b60, 25w): the achievements button forward (listing trimmed at the next IMP).\n'),
    ),
    dict(
        name='wx_66',
        method='World -[instructionsButtonTapped]',
        types='v8@0:4',
        start=6048708,
        end=6048808,
        disasm='disasm_worldtileloader_wx_66.txt',
        base_add=6048724,
        base_literal=6048804,
        boundary='ARM.exidx end 0x005c4c28 (listing bound); next ObjC IMP 0x005c4c28 World -[zoomToActiveNetBlockheadForPlayer:]',
        selectors={
                 0x5c4c1c: (15197932, 'instructionsButtonTapped'),
        },
        imports={
                 0x5c4c18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6048708, 'push {fp, lr}'), (6048804, 'adceq sl, sb, r8, lsl pc')],
        calls=[(6048780, 'blx r3')],
        branches=[],
        semantics=('[World -[instructionsButtonTapped]] (imp 0x005c4bc4, 25w): the instructions button forward.\n'),
    ),
    dict(
        name='wx_67',
        method='World -[chatButton]',
        types='v8@0:4',
        start=6063612,
        end=6063712,
        disasm='disasm_worldtileloader_wx_67.txt',
        base_add=6063628,
        base_literal=6063708,
        boundary='ARM.exidx end 0x005c8660 (listing bound); next ObjC IMP 0x005c8660 World -[currentTotalBlockheadCountIncludingNet]',
        selectors={
                 0x5c8654: (15198044, 'showChatUI'),
        },
        imports={
                 0x5c8650: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6063612, 'push {fp, lr}'), (6063708, 'adceq r7, sb, r0, ror 9')],
        calls=[(6063684, 'blx r3')],
        branches=[],
        semantics=('[World -[chatButton]] (imp 0x005c85fc, 25w): the chat button - showChatUI forward.\n'),
    ),
    dict(
        name='wx_68',
        method='World -[worldUI]',
        types='@8@0:4',
        start=6108176,
        end=6108276,
        disasm='disasm_worldtileloader_wx_68.txt',
        base_add=6108192,
        base_literal=6108272,
        boundary='ARM.exidx end 0x005d3474 (listing bound); next ObjC IMP 0x005d3474 World -[openOwnerPortal]',
        selectors={
                 0x5d3468: (15196764, 'worldUI'),
        },
        imports={
                 0x5d3464: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d346c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6108176, 'push {fp, lr}'), (6108272, 'adceq ip, r8, ip, asr 13')],
        calls=[(6108248, 'blx r3')],
        branches=[],
        semantics=('[World -[worldUI]] (imp 0x005d3410, 25w): uiManager worldUI getter wrapper.\n'),
    ),
    dict(
        name='wx_69',
        method='World -[hideChatView]',
        types='v8@0:4',
        start=6130280,
        end=6130380,
        disasm='disasm_worldtileloader_wx_69.txt',
        base_add=6130296,
        base_literal=6130376,
        boundary='ARM.exidx end 0x005d8acc (listing bound); next ObjC IMP 0x005d8acc World -[blockheadFilesReturnedFromServer:]',
        selectors={
                 0x5d8ac0: (15198372, 'hideChatView'),
        },
        imports={
                 0x5d8abc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6130280, 'push {fp, lr}'), (6130376, 'adceq r7, r8, r4, ror r0')],
        calls=[(6130352, 'blx r3')],
        branches=[],
        semantics=('[World -[hideChatView]] (imp 0x005d8a68, 25w): the hide-chat forward.\n'),
    ),
]


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(data))

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in elf.iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)
    relocs = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        syms = elf.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            if r['r_info_sym']:
                relocs[r['r_offset']] = syms.get_symbol(r['r_info_sym']).name

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for mm in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(mm.group(1), 16)] = mm.group(2).split(';')[0].strip()

        base = None
        if spec['base_add'] is not None:
            base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
            if base != EXPECTED_BASE:
                raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> {slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            if entry is None:
                got = relocs.get(slot, '')
                if got != expected_symbol:
                    raise ValueError(f"{spec['name']}: class reloc drifted at {cell:#x}: {got!r}")
                selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                              'route': 'ABS32 relocation symbol'}
                continue
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                          'route': 'dynsym entry at slot word'}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            route = 'PLT/GOT relocation (R_ARM_JUMP_SLOT / GLOB_DAT)'
            if got is None:
                got = relocs.get(slot)
                route = 'ABS32 relocation symbol'
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r} ({route})")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got, 'route': route}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            symbol = dynsym.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar {cell:#x} drifted: {symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'symbol': symbol, 'offset': offset}

        inrange = {a: ins for a, ins in rows.items() if spec['start'] <= a < spec['end']}
        listed = {a for a, ins in inrange.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, _ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call set drifted: {sorted(listed ^ expected_sites)}")
        calls = []
        for site, route in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: route drifted at {site:#x}: {rows[site]!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expected = ROUTE_TARGETS.get(route)
                if expected is None or target != expected:
                    raise ValueError(f"{spec['name']}: bl target drifted at {site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None})

        listed_branches = set()
        disjoint = []
        for a, ins in inrange.items():
            m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
            if not m or m.group(1) in ('bl', 'blx'):
                continue
            dest = int(m.group(2), 16)
            if spec['start'] <= dest < spec['end']:
                listed_branches.add((a, m.group(1), dest))
            else:
                disjoint.append({'address': f'0x{a:08x}', 'mnemonic': m.group(1),
                                 'destination': f'0x{dest:08x}'})
        expected_branches = {(a, mn, dest) for a, mn, dest in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: {sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at {address:#x}: "
                                 f"{rows.get(address)!r} != {expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}' if base else None,
            'selectors': selectors,
            'ivars': ivars,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'disjoint_branch_rows': disjoint,
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'World closure sweep part 1 (E114): the operational mids and the UI/gate tail; 70 bodies',
        'claim': ('a fully-read sweep of the World operational mids and UI/gate tail; the helper selectors and delegate contracts are recorded at call-site level'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_close1.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_close1.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
