#!/usr/bin/env python3
"""Hash-gated recovery of the World craft-interaction chain (E105).

The World-side workbench interaction completion chain: the
craft-completion and warp-in giants (census-grade), the craft/configure
router and the dynamic-object tap family:
10 bodies, 5444 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_CRAFT.md for the prose and boundaries.
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
    'bl 0x564c54': 0x00564c54,
    'bl 0x5ab510': 0x005ab510,
    'bl 0xfe6ff9b8': 0xfe6ff9b8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.itemTypeCanBeColored_ItemType_': 0x004d6128,
    'bl sym.itemTypeIsPainting_ItemType_': 0x005b902c,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='cb_00',
        method='World -[warpInBlockhead:atWorkbench:withBlockhead:]',
        types='v20@0:4@8@12@16',
        start=6012368,
        end=6018700,
        disasm='disasm_worldtileloader_cb_00.txt',
        base_add=6012384,
        base_literal=6016096,
        boundary='ARM.exidx end 0x005bd68c (listing bound); next ObjC IMP 0x005bd68c World -[removeDynamicObjectTappedAtDynamicObject:withBlockhead:]',
        selectors={
                 0x5bcc68: (15197584, 'pos'),
                 0x5bcc78: (15195584, 'setObject:forKey:'),
                 0x5bcc7c: (15195684, 'dictionary'),
                 0x5bcc88: (15195572, 'numberWithInt:'),
                 0x5bd0d0: (15197600, 'requestUniqueIDFromServerWithDict:'),
                 0x5bd188: (15197612, 'setActiveBlockhead:dontFollow:'),
                 0x5bd18c: (15196444, 'activeBlockhead'),
                 0x5bd190: (15196764, 'worldUI'),
                 0x5bd198: (15197608, 'loadNewBlockheadAtPos:craftableItemObject:uniqueID:'),
                 0x5bd250: (15196308, 'craftableItem'),
                 0x5bd364: (15196476, 'isEqualToString:'),
                 0x5bd368: (15196592, 'stringFromMD5'),
                 0x5bd370: (15195708, 'stringWithFormat:'),
                 0x5bd378: (15196780, 'amountString'),
                 0x5bd37c: (15195544, 'instance'),
                 0x5bd384: (15196772, 'amount'),
                 0x5bd5ec: (15196768, 'setCountWatcher:'),
                 0x5bd5f0: (15197584, 'pos'),
                 0x5bd5fc: (15196764, 'worldUI'),
                 0x5bd604: (15197608, 'loadNewBlockheadAtPos:craftableItemObject:uniqueID:'),
                 0x5bd608: (15195604, 'count'),
                 0x5bd60c: (15195692, 'blockheads'),
                 0x5bd614: (15197604, 'reportAchievementWithIdentifier:'),
                 0x5bd624: (15197692, 'selectBlockheadButtonAtIndex:'),
                 0x5bd630: (15197568, 'displayInterstitialForTag:'),
                 0x5bd638: (15197688, 'subtractItemsFromInventoryOfType:count:dataB:'),
                 0x5bd644: (15195544, 'instance'),
                 0x5bd648: (15196768, 'setCountWatcher:'),
                 0x5bd64c: (15196476, 'isEqualToString:'),
                 0x5bd650: (15196592, 'stringFromMD5'),
                 0x5bd658: (15195708, 'stringWithFormat:'),
                 0x5bd660: (15196772, 'amount'),
                 0x5bd66c: (15196776, 'modify:modifyString:'),
                 0x5bd670: (15196780, 'amountString'),
                 0x5bd678: (15196876, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x5bd684: (15197356, 'setDisplayed:'),
                 0x5bd688: (15196628, 'addBlockheadUI'),
        },
        imports={
                 0x5bcc70: (16232520, '__CFConstantStringClassReference'),
                 0x5bcc74: (17151904, 'objc_msgSend'),
                 0x5bcc84: (16232536, '__CFConstantStringClassReference'),
                 0x5bd014: (16232552, '__CFConstantStringClassReference'),
                 0x5bd018: (16232712, '__CFConstantStringClassReference'),
                 0x5bd36c: (16232120, '__CFConstantStringClassReference'),
                 0x5bd5f8: (17151904, 'objc_msgSend'),
                 0x5bd610: (16232648, '__CFConstantStringClassReference'),
                 0x5bd618: (16232632, '__CFConstantStringClassReference'),
                 0x5bd61c: (16232616, '__CFConstantStringClassReference'),
                 0x5bd620: (16232600, '__CFConstantStringClassReference'),
                 0x5bd62c: (16232728, '__CFConstantStringClassReference'),
                 0x5bd654: (16232120, '__CFConstantStringClassReference'),
                 0x5bd668: (16232104, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5bcc64: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5bd0cc: (17156668, 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer', 3064),
                 0x5bd0d4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5bd194: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5bd5f4: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5bd600: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={
                 0x5bcc6c: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5bcc80: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
                 0x5bd374: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5bd380: (15245464, 'OBJC_CLASS_$_CrystalManager'),
                 0x5bd63c: (15245464, 'OBJC_CLASS_$_CrystalManager'),
                 0x5bd664: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6012368, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6018696, 'invalid')],
        calls=[(6012560, 'blx lr'), (6012604, 'blx ip'), (6012672, 'bl loc.imp.objc_msgSend_stret'), (6012708, 'bl sym.imp.memset'), (6012816, 'blx lr'), (6012852, 'blx ip'), (6012920, 'bl loc.imp.objc_msgSend_stret'), (6012956, 'bl sym.imp.memset'), (6013040, 'blx r3'), (6013076, 'blx ip'), (6013160, 'blx ip'), (6013228, 'blx r3'), (6013364, 'bl loc.imp.objc_msgSend_stret'), (6013400, 'bl sym.imp.memset'), (6013592, 'bl loc.imp.objc_msgSend'), (6013628, 'blx r3'), (6013676, 'blx ip'), (6013716, 'blx ip'), (6013776, 'bl loc.imp.objc_msgSend_stret'), (6013812, 'bl sym.imp.memset'), (6014084, 'blx sl'), (6014100, 'blx r2'), (6014136, 'blx r3'), (6014152, 'blx r2'), (6014192, 'blx lr'), (6014208, 'blx r2'), (6014240, 'blx r3'), (6014336, 'blx lr'), (6014352, 'blx r2'), (6014464, 'bl loc.imp.objc_msgSend'), (6014512, 'bl loc.imp.objc_msgSend'), (6014544, 'bl loc.imp.objc_msgSend'), (6014716, 'bl loc.imp.objc_msgSend'), (6014732, 'bl loc.imp.objc_msgSend'), (6014816, 'bl loc.imp.objc_msgSend'), (6014832, 'bl loc.imp.objc_msgSend'), (6014860, 'bl loc.imp.objc_msgSend'), (6014892, 'bl loc.imp.objc_msgSend'), (6014916, 'bl loc.imp.objc_msgSend'), (6014932, 'bl loc.imp.objc_msgSend'), (6015000, 'blx ip'), (6015016, 'blx r2'), (6015048, 'blx r3'), (6015144, 'blx lr'), (6015160, 'blx r2'), (6015316, 'blx ip'), (6015356, 'blx r3'), (6015548, 'bl loc.imp.objc_msgSend_stret'), (6015584, 'bl sym.imp.memset'), (6015736, 'bl loc.imp.objc_msgSend'), (6015888, 'bl loc.imp.objc_msgSend_stret'), (6015924, 'bl sym.imp.memset'), (6016076, 'bl loc.imp.objc_msgSend'), (6016252, 'bl loc.imp.objc_msgSend'), (6016300, 'bl loc.imp.objc_msgSend'), (6016332, 'bl loc.imp.objc_msgSend'), (6016516, 'bl loc.imp.objc_msgSend'), (6016532, 'bl loc.imp.objc_msgSend'), (6016616, 'bl loc.imp.objc_msgSend'), (6016632, 'bl loc.imp.objc_msgSend'), (6016660, 'bl loc.imp.objc_msgSend'), (6016696, 'bl loc.imp.objc_msgSend'), (6016720, 'bl loc.imp.objc_msgSend'), (6016736, 'bl loc.imp.objc_msgSend'), (6016804, 'blx ip'), (6016820, 'blx r2'), (6016852, 'blx r3'), (6016948, 'blx lr'), (6016964, 'blx r2'), (6017132, 'blx ip'), (6017148, 'blx r2'), (6017220, 'blx ip'), (6017320, 'blx ip'), (6017336, 'blx r2'), (6017408, 'blx ip'), (6017520, 'blx ip'), (6017536, 'blx r2'), (6017608, 'blx ip'), (6017700, 'blx ip'), (6017716, 'blx r2'), (6017788, 'blx ip'), (6017884, 'bl loc.imp.objc_msgSend_stret'), (6017960, 'bl sym.imp.memset'), (6018176, 'bl loc.imp.objc_msgSend'), (6018212, 'blx r3'), (6018260, 'blx ip'), (6018276, 'blx r2'), (6018304, 'blx r3'), (6018400, 'blx ip'), (6018504, 'blx lr'), (6018528, 'blx r3')],
        branches=[(6012448, 'beq', 6013260), (6012656, 'beq', 6012680), (6012676, 'b', 6012712), (6012904, 'beq', 6012928), (6012924, 'b', 6012960), (6013092, 'beq', 6013164), (6013256, 'b', 6018412), (6013280, 'bne', 6013724), (6013348, 'beq', 6013372), (6013368, 'b', 6013404), (6013720, 'b', 6018308), (6013760, 'beq', 6013784), (6013780, 'b', 6013816), (6013840, 'bge', 6017052), (6013876, 'bne', 6015192), (6014252, 'beq', 6014368), (6014364, 'bne', 6014376), (6014412, 'ble', 6014420), (6014416, 'b', 6018532), (6014572, 'ble', 6015188), (6015060, 'beq', 6015176), (6015172, 'bne', 6015184), (6015184, 'b', 6015188), (6015188, 'b', 6017024), (6015380, 'ble', 6017020), (6015404, 'bge', 6015780), (6015440, 'beq', 6015760), (6015492, 'bge', 6015756), (6015532, 'beq', 6015556), (6015552, 'b', 6015588), (6015752, 'b', 6015456), (6015756, 'b', 6015760), (6015760, 'b', 6015764), (6015776, 'b', 6015392), (6015832, 'bge', 6016140), (6015872, 'beq', 6015896), (6015892, 'b', 6015928), (6016092, 'b', 6015788), (6016160, 'bge', 6017016), (6016196, 'bne', 6016996), (6016372, 'bgt', 6016992), (6016864, 'beq', 6016980), (6016976, 'bne', 6016988), (6016988, 'b', 6016992), (6016992, 'b', 6016996), (6016996, 'b', 6017000), (6017012, 'b', 6016148), (6017016, 'b', 6018532), (6017020, 'b', 6017024), (6017024, 'b', 6017028), (6017040, 'b', 6013828), (6017156, 'bne', 6017240), (6017224, 'b', 6017804), (6017344, 'bne', 6017440), (6017412, 'b', 6017800), (6017544, 'bne', 6017620), (6017612, 'b', 6017796), (6017724, 'bne', 6017792), (6017792, 'b', 6017796), (6017796, 'b', 6017800), (6017800, 'b', 6017804), (6017868, 'beq', 6017932), (6017888, 'b', 6017964), (6018316, 'beq', 6018408), (6018408, 'b', 6018412)],
        semantics=('[World warpInBlockhead:atWorkbench:withBlockhead:] (imp 0x005bbdd0, 1583w): the warp-in-a-new-blockhead flow at a workbench (census-grade reading): 91 call rows - objc_msgSend x26 + objc_msgSend_stret x7 + memset x7 + register blx x51; 37 selector cells - requestUniqueIDFromServerWithDict:, loadNewBlockheadAtPos:craftableItemObject:uniqueID:, setActiveBlockhead:dontFollow:, createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead: (the blockhead spawn), subtractItemsFromInventoryOfType:count:dataB:, reportAchievementWithIdentifier:, selectBlockheadButtonAtIndex:, displayInterstitialForTag:; the CrystalManager instance + amount/amountString/setCountWatcher: cluster (store payment) and the stringWithFormat:/stringFromMD5/isEqualToString: product-string family each appear on both halves; constants 0xc350 (50000 - the same object ceiling as the E103 unique-ID grant) and 0x7c; not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='cb_01',
        method='World -[craftItemFinished:atWorkbench:allFinished:blockhead:]',
        types='v24@0:4@8@12c16@20',
        start=5992360,
        end=5997232,
        disasm='disasm_worldtileloader_cb_01.txt',
        base_add=5992376,
        base_literal=5996216,
        boundary='ARM.exidx end 0x005b82b0 (listing bound); next ObjC IMP 0x005b82b0 World -[craftAbortedForWorkbench:withBlockhead:]',
        selectors={
                 0x5b7ebc: (15197584, 'pos'),
                 0x5b8024: (15196308, 'craftableItem'),
                 0x5b802c: (15196576, 'displayed'),
                 0x5b8030: (15197548, 'craftUI'),
                 0x5b8038: (15197588, 'upgradeToNextLevel'),
                 0x5b803c: (15197596, 'setWorkbench:blockhead:'),
                 0x5b8040: (15196444, 'activeBlockhead'),
                 0x5b8048: (15197592, 'workbench'),
                 0x5b8200: (15197584, 'pos'),
                 0x5b820c: (15197616, 'addSimulationEventOfType:forBlockhead:extraData:'),
                 0x5b8210: (15196944, 'type'),
                 0x5b821c: (15196876, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x5b8230: (15197604, 'reportAchievementWithIdentifier:'),
                 0x5b8234: (15197620, 'addExpectedCraftItem:'),
                 0x5b823c: (15197624, 'freeBlockCreationItemSaveDict'),
                 0x5b8244: (15195604, 'count'),
                 0x5b8248: (15195692, 'blockheads'),
                 0x5b825c: (15197612, 'setActiveBlockhead:dontFollow:'),
                 0x5b8260: (15196444, 'activeBlockhead'),
                 0x5b8264: (15196764, 'worldUI'),
                 0x5b826c: (15197608, 'loadNewBlockheadAtPos:craftableItemObject:uniqueID:'),
                 0x5b827c: (15195584, 'setObject:forKey:'),
                 0x5b8280: (15195684, 'dictionary'),
                 0x5b828c: (15195572, 'numberWithInt:'),
                 0x5b8298: (15197600, 'requestUniqueIDFromServerWithDict:'),
                 0x5b82a0: (15195576, 'numberWithBool:'),
                 0x5b82a8: (15197356, 'setDisplayed:'),
                 0x5b82ac: (15197452, 'craftProgressUI'),
        },
        imports={
                 0x5b8028: (17151904, 'objc_msgSend'),
                 0x5b8208: (17151904, 'objc_msgSend'),
                 0x5b822c: (16232664, '__CFConstantStringClassReference'),
                 0x5b824c: (16232648, '__CFConstantStringClassReference'),
                 0x5b8250: (16232632, '__CFConstantStringClassReference'),
                 0x5b8254: (16232616, '__CFConstantStringClassReference'),
                 0x5b8258: (16232600, '__CFConstantStringClassReference'),
                 0x5b8278: (16232520, '__CFConstantStringClassReference'),
                 0x5b8288: (16232536, '__CFConstantStringClassReference'),
                 0x5b8290: (16232584, '__CFConstantStringClassReference'),
                 0x5b829c: (16232568, '__CFConstantStringClassReference'),
                 0x5b82a4: (16232552, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5b8034: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b8044: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b8204: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x5b8214: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b8240: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5b8268: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b8294: (17156668, 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer', 3064),
        },
        classes={
                 0x5b8274: (15245292, 'OBJC_CLASS_$_NSNumber'),
                 0x5b8284: (15245288, 'OBJC_CLASS_$_NSMutableDictionary'),
        },
        instructions=[(5992360, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5997228, 'invalid')],
        calls=[(5992464, 'bl loc.imp.objc_msgSend_stret'), (5992500, 'bl sym.imp.memset'), (5992568, 'bl loc.imp.objc_msgSend_stret'), (5992604, 'bl sym.imp.memset'), (5992712, 'blx r5'), (5992748, 'blx r3'), (5992764, 'blx r2'), (5992924, 'blx sl'), (5992972, 'blx ip'), (5992988, 'blx r2'), (5993036, 'blx ip'), (5993072, 'blx ip'), (5993240, 'blx lr'), (5993284, 'blx ip'), (5993352, 'bl loc.imp.objc_msgSend_stret'), (5993388, 'bl sym.imp.memset'), (5993496, 'blx lr'), (5993532, 'blx ip'), (5993600, 'bl loc.imp.objc_msgSend_stret'), (5993636, 'bl sym.imp.memset'), (5993820, 'blx ip'), (5993856, 'blx ip'), (5993900, 'blx ip'), (5993936, 'blx ip'), (5993972, 'blx r3'), (5994004, 'bl sym.imp.NSLog'), (5994092, 'blx ip'), (5994108, 'blx r2'), (5994180, 'blx ip'), (5994268, 'blx ip'), (5994284, 'blx r2'), (5994356, 'blx ip'), (5994444, 'blx ip'), (5994460, 'blx r2'), (5994532, 'blx ip'), (5994620, 'blx ip'), (5994636, 'blx r2'), (5994708, 'blx ip'), (5994804, 'bl loc.imp.objc_msgSend_stret'), (5994840, 'bl sym.imp.memset'), (5995032, 'bl loc.imp.objc_msgSend'), (5995068, 'blx r3'), (5995116, 'blx ip'), (5995156, 'blx ip'), (5995260, 'blx ip'), (5995376, 'blx ip'), (5995380, 'bl 0x564c54'), (5995764, 'bl loc.imp.objc_msgSend'), (5995856, 'bl loc.imp.objc_msgSend'), (5995960, 'bl loc.imp.objc_msgSend'), (5996208, 'bl loc.imp.objc_msgSend'), (5996240, 'bl 0xfe6ff9b8'), (5996420, 'bl loc.imp.objc_msgSend'), (5996440, 'blx r2'), (5996572, 'bl loc.imp.objc_msgSend'), (5996660, 'blx r2'), (5996676, 'bl sym.itemTypeCanBeColored_ItemType_'), (5996812, 'bl loc.imp.objc_msgSend'), (5996912, 'blx r2'), (5997020, 'blx lr'), (5997044, 'blx r3')],
        branches=[(5992448, 'beq', 5992472), (5992468, 'b', 5992504), (5992552, 'beq', 5992576), (5992572, 'b', 5992608), (5992616, 'bne', 5993080), (5992776, 'beq', 5993076), (5993076, 'b', 5996832), (5993088, 'bne', 5995164), (5993128, 'beq', 5994012), (5993336, 'beq', 5993360), (5993356, 'b', 5993392), (5993584, 'beq', 5993608), (5993604, 'b', 5993640), (5994008, 'b', 5995160), (5994116, 'bne', 5994188), (5994184, 'b', 5994724), (5994292, 'bne', 5994364), (5994360, 'b', 5994720), (5994468, 'bne', 5994540), (5994536, 'b', 5994716), (5994644, 'bne', 5994712), (5994712, 'b', 5994716), (5994716, 'b', 5994720), (5994720, 'b', 5994724), (5994788, 'beq', 5994812), (5994808, 'b', 5994844), (5995160, 'b', 5996828), (5995196, 'beq', 5995264), (5995288, 'bge', 5995980), (5995312, 'bne', 5995736), (5995428, 'ble', 5995724), (5995472, 'ble', 5995712), (5995516, 'ble', 5995700), (5995560, 'ble', 5995688), (5995604, 'ble', 5995676), (5995648, 'ble', 5995664), (5995660, 'b', 5995672), (5995672, 'b', 5995684), (5995684, 'b', 5995696), (5995696, 'b', 5995708), (5995708, 'b', 5995720), (5995720, 'b', 5995732), (5995732, 'b', 5995736), (5995976, 'b', 5995276), (5995988, 'beq', 5996088), (5996004, 'beq', 5996088), (5996016, 'beq', 5996088), (5996032, 'beq', 5996088), (5996044, 'beq', 5996088), (5996056, 'beq', 5996088), (5996068, 'beq', 5996088), (5996084, 'bne', 5996256), (5996212, 'b', 5996824), (5996268, 'bne', 5996620), (5996448, 'bne', 5996576), (5996576, 'b', 5996820), (5996668, 'bne', 5996816), (5996688, 'beq', 5996816), (5996816, 'b', 5996820), (5996820, 'b', 5996824), (5996824, 'b', 5996828), (5996828, 'b', 5996832), (5996840, 'beq', 5997048), (5996924, 'bne', 5997048)],
        semantics=('[World craftItemFinished:atWorkbench:allFinished:blockhead:] (imp 0x005b6fa8, 1218w): the craft-completion handler (census-grade reading): 61 call rows - objc_msgSend x8 + objc_msgSend_stret x5 + memset x5 + register blx x38 + NSLog x1 + itemTypeCanBeColored x1; 28 selector cells - upgradeToNextLevel, setWorkbench:blockhead:, addSimulationEventOfType:forBlockhead:extraData:, addExpectedCraftItem:, freeBlockCreationItemSaveDict, the createFreeBlockAtPosition: spawn, the new-blockhead family (loadNewBlockheadAtPos:craftableItemObject:uniqueID: + requestUniqueIDFromServerWithDict: + setActiveBlockhead:dontFollow:) and setDisplayed: on craftProgressUI; immediates 0x12b/0x105/0x117/0x49/0x33/0x20/0x24/0x1f/0x13e/0x13a/0x44f; not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='cb_02',
        method='World -[craftOrConfigureItem:atWorkbench:withBlockhead:count:]',
        types='v24@0:4@8@12@16i20',
        start=5998840,
        end=6000684,
        disasm='disasm_worldtileloader_cb_02.txt',
        base_add=5998856,
        base_literal=6000680,
        boundary='ARM.exidx end 0x005b902c (listing bound); next ObjC IMP 0x005b90c0 World -[blockheadReachedInteractionObjectDestination:pathExtraData:]',
        selectors={
                 0x5b8ff8: (15196308, 'craftableItem'),
                 0x5b9000: (15196944, 'type'),
                 0x5b9004: (15197652, 'craftItem:atWorkbench:withBlockhead:count:'),
                 0x5b9008: (15197540, 'showTimeCrystalUITapped'),
                 0x5b9010: (15197356, 'setDisplayed:'),
                 0x5b9014: (15197644, 'workbenchChoiceUI'),
                 0x5b9018: (15197548, 'craftUI'),
                 0x5b901c: (15197648, 'paintMixUI'),
                 0x5b9020: (15197352, 'setWorkbench:blockhead:craftableItemObject:'),
                 0x5b9024: (15196628, 'addBlockheadUI'),
        },
        imports={
                 0x5b8ffc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b8ff4: (17156668, 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer', 3064),
                 0x5b900c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5998840, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6000680, 'adceq r7, sl, r4, ror 3')],
        calls=[(5999000, 'bl loc.imp.objc_msgSend_stret'), (5999036, 'bl sym.imp.memset'), (5999216, 'blx sl'), (5999260, 'blx r4'), (5999296, 'blx r3'), (5999320, 'blx r3'), (5999356, 'blx r3'), (5999380, 'blx r3'), (5999416, 'blx r3'), (5999440, 'blx r3'), (5999516, 'bl loc.imp.objc_msgSend_stret'), (5999552, 'bl sym.imp.memset'), (5999620, 'bl loc.imp.objc_msgSend_stret'), (5999656, 'bl sym.imp.memset'), (5999664, 'bl sym.itemTypeIsPainting_ItemType_'), (5999720, 'blx r2'), (5999784, 'bl loc.imp.objc_msgSend_stret'), (5999820, 'bl sym.imp.memset'), (5999828, 'bl sym.itemTypeCanBeColored_ItemType_'), (5999896, 'bl loc.imp.objc_msgSend_stret'), (5999932, 'bl sym.imp.memset'), (6000116, 'blx sl'), (6000160, 'blx r4'), (6000196, 'blx r3'), (6000220, 'blx r3'), (6000256, 'blx r3'), (6000280, 'blx r3'), (6000316, 'blx r3'), (6000340, 'blx r3'), (6000416, 'bl loc.imp.objc_msgSend_stret'), (6000452, 'bl sym.imp.memset'), (6000528, 'blx r2'), (6000608, 'blx ip')],
        branches=[(5998924, 'beq', 5998932), (5998928, 'b', 6000620), (5998944, 'beq', 5999448), (5998984, 'beq', 5999008), (5999004, 'b', 5999040), (5999048, 'bne', 5999448), (5999444, 'b', 6000620), (5999460, 'beq', 6000348), (5999500, 'beq', 5999524), (5999520, 'b', 5999556), (5999564, 'beq', 5999844), (5999604, 'beq', 5999628), (5999624, 'b', 5999660), (5999676, 'bne', 5999844), (5999728, 'bne', 6000348), (5999768, 'beq', 5999792), (5999788, 'b', 5999824), (5999840, 'beq', 6000348), (5999880, 'beq', 5999904), (5999900, 'b', 5999936), (5999948, 'bne', 6000348), (6000344, 'b', 6000616), (6000360, 'beq', 6000536), (6000400, 'beq', 6000424), (6000420, 'b', 6000456), (6000464, 'bne', 6000536), (6000532, 'b', 6000612), (6000612, 'b', 6000616), (6000616, 'b', 6000620)],
        semantics=('[World craftOrConfigureItem:atWorkbench:withBlockhead:count:] (imp 0x005b88f8, 461w): the workbench tap router - reads craftableItem/type and routes between craftItem:atWorkbench:withBlockhead:count:, showTimeCrystalUITapped, the choice UI (workbenchChoiceUI / craftUI / paintMixUI setDisplayed:) and setWorkbench:blockhead:craftableItemObject:; itemTypeIsPainting + itemTypeCanBeColored decide the paint path; 33 calls incl. six stret/memset record pairs.\n'),
    ),
    dict(
        name='cb_03',
        method='World -[craftItem:atWorkbench:withBlockhead:count:]',
        types='v24@0:4@8@12@16i20',
        start=5997520,
        end=5998840,
        disasm='disasm_worldtileloader_cb_03.txt',
        base_add=5997536,
        base_literal=5998836,
        boundary='ARM.exidx end 0x005b88f8 (listing bound); next ObjC IMP 0x005b88f8 World -[craftOrConfigureItem:atWorkbench:withBlockhead:count:]',
        selectors={
                 0x5b88b0: (15197628, 'floatPos'),
                 0x5b88b4: (15197632, 'zoomUIToOnscreen:dimensions:'),
                 0x5b88bc: (15197584, 'pos'),
                 0x5b88c4: (15197636, 'hideAnyHideableUI'),
                 0x5b88d4: (15196444, 'activeBlockhead'),
                 0x5b88d8: (15197304, 'currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:'),
                 0x5b88e0: (15197308, 'tileIsProtectedAtPos:againstBlockhead:'),
                 0x5b88ec: (15196300, 'uniqueID'),
                 0x5b88f0: (15197640, 'queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI:'),
        },
        imports={
                 0x5b88c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b88a8: (17156668, 'OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer', 3064),
                 0x5b88ac: (17155876, 'OBJC_IVAR_$_World.windowInfo', 152),
                 0x5b88c8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b88cc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={},
        instructions=[(5997520, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5998836, 'adceq r7, sl, ip, lsl 14')],
        calls=[(5997784, 'bl loc.imp.objc_msgSend_stret'), (5997820, 'bl sym.imp.memset'), (5997840, 'bl method.Vector2.Vector2_float__float_'), (5997860, 'bl method.Vector2.operator_Vector2_'), (5997884, 'bl method.Vector2.Vector2_float__float_'), (5997936, 'bl loc.imp.objc_msgSend'), (5998016, 'blx r3'), (5998064, 'bl loc.imp.objc_msgSend_stret'), (5998104, 'bl sym.imp.memset'), (5998120, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5998176, 'bl loc.imp.objc_msgSend'), (5998256, 'bl loc.imp.objc_msgSend'), (5998268, 'bl 0x5ab510'), (5998356, 'bl loc.imp.objc_msgSend'), (5998392, 'bl loc.imp.objc_msgSend'), (5998452, 'bl loc.imp.objc_msgSend'), (5998532, 'bl loc.imp.objc_msgSend'), (5998584, 'bl loc.imp.objc_msgSend'), (5998640, 'bl loc.imp.objc_msgSend'), (5998744, 'bl loc.imp.objc_msgSend')],
        branches=[(5997604, 'beq', 5997612), (5997608, 'b', 5998752), (5997664, 'bmi', 5997724), (5997720, 'bpl', 5997940), (5997768, 'beq', 5997792), (5997788, 'b', 5997824), (5998048, 'beq', 5998076), (5998068, 'b', 5998108), (5998280, 'beq', 5998544), (5998408, 'beq', 5998540), (5998540, 'b', 5998544)],
        semantics=('[World craftItem:atWorkbench:withBlockhead:count:] (imp 0x005b83d0, 330w): sends the blockhead to craft - Vector2 floatPos/pos math, zoomUIToOnscreen:dimensions:, hideAnyHideableUI, then queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI: behind the currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions: and tileIsProtectedAtPos:againstBlockhead: gates; helper 0x5ab510; constant 0x19f (415).\n'),
    ),
    dict(
        name='cb_04',
        method='World -[craftAbortedForWorkbench:withBlockhead:]',
        types='v16@0:4@8@12',
        start=5997232,
        end=5997520,
        disasm='disasm_worldtileloader_cb_04.txt',
        base_add=5997248,
        base_literal=5997516,
        boundary='ARM.exidx end 0x005b83d0 (listing bound); next ObjC IMP 0x005b83d0 World -[craftItem:atWorkbench:withBlockhead:count:]',
        selectors={
                 0x5b83b8: (15196444, 'activeBlockhead'),
                 0x5b83c0: (15197356, 'setDisplayed:'),
                 0x5b83c4: (15197452, 'craftProgressUI'),
        },
        imports={
                 0x5b83b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b83bc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b83c8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(5997232, 'push {r4, r5, fp, lr}'), (5997516, 'adceq r7, sl, ip, lsr 16')],
        calls=[(5997332, 'blx lr'), (5997456, 'blx lr'), (5997480, 'blx r3')],
        branches=[(5997344, 'beq', 5997364), (5997360, 'bne', 5997484)],
        semantics=('[World craftAbortedForWorkbench:withBlockhead:] (imp 0x005b82b0, 72w): craft-abort cleanup - hides the progress UI via setDisplayed: on craftProgressUI when the active blockhead matches; dynamicWorld/uiManager lookups.\n'),
    ),
    dict(
        name='cb_05',
        method='World -[teleportToWorkbench:withBlockhead:craftableItemObject:]',
        types='v20@0:4@8@12@16',
        start=6010420,
        end=6012368,
        disasm='disasm_worldtileloader_cb_05.txt',
        base_add=6010436,
        base_literal=6012364,
        boundary='ARM.exidx end 0x005bbdd0 (listing bound); next ObjC IMP 0x005bbdd0 World -[warpInBlockhead:atWorkbench:withBlockhead:]',
        selectors={
                 0x5bbd70: (15196308, 'craftableItem'),
                 0x5bbd78: (15196476, 'isEqualToString:'),
                 0x5bbd7c: (15196592, 'stringFromMD5'),
                 0x5bbd84: (15195708, 'stringWithFormat:'),
                 0x5bbd8c: (15196780, 'amountString'),
                 0x5bbd90: (15195544, 'instance'),
                 0x5bbd98: (15196772, 'amount'),
                 0x5bbd9c: (15197696, 'teleportBlockhead:toWorkbench:'),
                 0x5bbda4: (15196768, 'setCountWatcher:'),
                 0x5bbda8: (15196764, 'worldUI'),
                 0x5bbdb0: (15196776, 'modify:modifyString:'),
                 0x5bbdb8: (15197356, 'setDisplayed:'),
                 0x5bbdbc: (15197548, 'craftUI'),
                 0x5bbdc4: (15197568, 'displayInterstitialForTag:'),
        },
        imports={
                 0x5bbd74: (17151904, 'objc_msgSend'),
                 0x5bbd80: (16232120, '__CFConstantStringClassReference'),
                 0x5bbdb4: (16232104, '__CFConstantStringClassReference'),
                 0x5bbdc0: (16232728, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5bbda0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5bbdac: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={
                 0x5bbd88: (15245304, 'OBJC_CLASS_$_NSString'),
                 0x5bbd94: (15245464, 'OBJC_CLASS_$_CrystalManager'),
        },
        instructions=[(6010420, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6012364, 'adceq r4, sl, r8, lsr 9')],
        calls=[(6010524, 'bl loc.imp.objc_msgSend_stret'), (6010560, 'bl sym.imp.memset'), (6010768, 'blx sl'), (6010784, 'blx r2'), (6010820, 'blx r3'), (6010836, 'blx r2'), (6010876, 'blx lr'), (6010892, 'blx r2'), (6010924, 'blx r3'), (6011020, 'blx lr'), (6011036, 'blx r2'), (6011156, 'blx ip'), (6011272, 'blx r5'), (6011320, 'blx ip'), (6011352, 'blx r3'), (6011612, 'blx sl'), (6011628, 'blx r2'), (6011684, 'blx ip'), (6011700, 'blx r2'), (6011736, 'blx r3'), (6011760, 'blx ip'), (6011792, 'blx r3'), (6011808, 'blx r2'), (6011856, 'blx lr'), (6011872, 'blx r2'), (6011904, 'blx r3'), (6012000, 'blx lr'), (6012016, 'blx r2'), (6012136, 'blx lr'), (6012160, 'blx r3'), (6012256, 'blx ip')],
        branches=[(6010508, 'beq', 6010532), (6010528, 'b', 6010564), (6010936, 'beq', 6011052), (6011048, 'bne', 6011060), (6011072, 'ble', 6011080), (6011076, 'b', 6012264), (6011168, 'beq', 6012164), (6011364, 'ble', 6012044), (6011916, 'beq', 6012032), (6012028, 'bne', 6012040), (6012040, 'b', 6012044), (6012172, 'beq', 6012264)],
        semantics=('[World teleportToWorkbench:withBlockhead:craftableItemObject:] (imp 0x005bb634, 487w): the teleport-to-workbench store flow - CrystalManager instance + amount/amountString with stringWithFormat:/stringFromMD5/isEqualToString: product strings, teleportBlockhead:toWorkbench:, setCountWatcher:, worldUI modify:modifyString: and displayInterstitialForTag: (the ad interstitial).\n'),
    ),
    dict(
        name='cb_06',
        method='World -[useDynamicObjectTappedAtDynamicObject:selectedOption:]',
        types='v16@0:4@8i12',
        start=6001512,
        end=6004240,
        disasm='disasm_worldtileloader_cb_06.txt',
        base_add=6001528,
        base_literal=6004236,
        boundary='ARM.exidx end 0x005b9e10 (listing bound); next ObjC IMP 0x005b9e10 World -[requestUniqueIDFromServerWithDict:]',
        selectors={
                 0x5b9da8: (15195596, 'isKindOfClass:'),
                 0x5b9dac: (15195592, 'class'),
                 0x5b9db4: (15197636, 'hideAnyHideableUI'),
                 0x5b9dcc: (15197584, 'pos'),
                 0x5b9dd8: (15196444, 'activeBlockhead'),
                 0x5b9ddc: (15196300, 'uniqueID'),
                 0x5b9de0: (15197312, 'queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:isAI:'),
                 0x5b9df4: (15197304, 'currentInteractionTypeForTile:atPos:pickupRejectedDueToInventoryFull:includeActions:faceIndex:allowProtectedActions:'),
                 0x5b9dfc: (15197308, 'tileIsProtectedAtPos:againstBlockhead:'),
                 0x5b9e08: (15197684, 'showUIForTappedWorkbench:'),
        },
        imports={
                 0x5b9da4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b9db8: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b9dd0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5b9db0: (15245488, 'OBJC_CLASS_$_Workbench'),
                 0x5b9dbc: (15245492, 'OBJC_CLASS_$_InteractionObject'),
                 0x5b9dc0: (15245496, 'OBJC_CLASS_$_Boat'),
                 0x5b9dc4: (15245500, 'OBJC_CLASS_$_TrainCar'),
                 0x5b9dc8: (15245480, 'OBJC_CLASS_$_NPC'),
        },
        instructions=[(6001512, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6004236, 'adceq r6, sl, r4, ror r7')],
        calls=[(6001672, 'blx lr'), (6001708, 'blx r2'), (6001740, 'blx r3'), (6001824, 'blx r3'), (6001908, 'blx ip'), (6001940, 'blx r3'), (6002008, 'bl loc.imp.objc_msgSend_stret'), (6002044, 'bl sym.imp.memset'), (6002060, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6002116, 'bl loc.imp.objc_msgSend'), (6002196, 'bl loc.imp.objc_msgSend'), (6002208, 'bl 0x5ab510'), (6002296, 'bl loc.imp.objc_msgSend'), (6002332, 'bl loc.imp.objc_msgSend'), (6002392, 'bl loc.imp.objc_msgSend'), (6002472, 'bl loc.imp.objc_msgSend'), (6002524, 'bl loc.imp.objc_msgSend'), (6002580, 'bl loc.imp.objc_msgSend'), (6002672, 'bl loc.imp.objc_msgSend'), (6002760, 'blx ip'), (6002792, 'blx r3'), (6002860, 'bl loc.imp.objc_msgSend_stret'), (6002896, 'bl sym.imp.memset'), (6002940, 'bl loc.imp.objc_msgSend'), (6002988, 'bl loc.imp.objc_msgSend'), (6003072, 'bl loc.imp.objc_msgSend'), (6003160, 'blx ip'), (6003192, 'blx r3'), (6003260, 'bl loc.imp.objc_msgSend_stret'), (6003296, 'bl sym.imp.memset'), (6003340, 'bl loc.imp.objc_msgSend'), (6003388, 'bl loc.imp.objc_msgSend'), (6003484, 'bl loc.imp.objc_msgSend'), (6003572, 'blx ip'), (6003604, 'blx r3'), (6003672, 'bl loc.imp.objc_msgSend_stret'), (6003708, 'bl sym.imp.memset'), (6003764, 'bl loc.imp.objc_msgSend'), (6003812, 'bl loc.imp.objc_msgSend'), (6003904, 'bl loc.imp.objc_msgSend'), (6003956, 'bl loc.imp.objc_msgSend'), (6004004, 'bl loc.imp.objc_msgSend'), (6004096, 'bl loc.imp.objc_msgSend')],
        branches=[(6001752, 'beq', 6001832), (6001828, 'b', 6004124), (6001952, 'beq', 6002684), (6001992, 'beq', 6002016), (6002012, 'b', 6002048), (6002220, 'beq', 6002484), (6002348, 'beq', 6002480), (6002480, 'b', 6002484), (6002680, 'b', 6004120), (6002804, 'beq', 6003084), (6002844, 'beq', 6002868), (6002864, 'b', 6002900), (6003080, 'b', 6004116), (6003204, 'beq', 6003496), (6003244, 'beq', 6003268), (6003264, 'b', 6003300), (6003492, 'b', 6004112), (6003616, 'beq', 6004108), (6003656, 'beq', 6003680), (6003676, 'b', 6003712), (6003720, 'beq', 6003916), (6003912, 'b', 6004104), (6004104, 'b', 6004108), (6004108, 'b', 6004112), (6004112, 'b', 6004116), (6004116, 'b', 6004120), (6004120, 'b', 6004124)],
        semantics=('[World useDynamicObjectTappedAtDynamicObject:selectedOption:] (imp 0x005b9368, 682w): the dynamic-object tap router - class checks (Workbench / InteractionObject / Boat / TrainCar / NPC) route to per-type arms, each building a queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:... record (stret+memset pairs x3) behind the currentInteractionTypeForTile:... and tileIsProtectedAtPos:againstBlockhead: gates; the Workbench arm ends in showUIForTappedWorkbench:; shared helper 0x5ab510.\n'),
    ),
    dict(
        name='cb_07',
        method='World -[removeDynamicObjectTappedAtDynamicObject:withBlockhead:]',
        types='v16@0:4@8@12',
        start=6018700,
        end=6019860,
        disasm='disasm_worldtileloader_cb_07.txt',
        base_add=6018716,
        base_literal=6019856,
        boundary='ARM.exidx end 0x005bdb14 (listing bound); next ObjC IMP 0x005bdb14 World -[addFuelTappedAtInteractionObject:withBlockhead:]',
        selectors={
                 0x5bdad0: (15197584, 'pos'),
                 0x5bdad8: (15197636, 'hideAnyHideableUI'),
                 0x5bdae0: (15195596, 'isKindOfClass:'),
                 0x5bdae4: (15195592, 'class'),
                 0x5bdb04: (15196444, 'activeBlockhead'),
                 0x5bdb08: (15196300, 'uniqueID'),
                 0x5bdb0c: (15197640, 'queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI:'),
        },
        imports={
                 0x5bdad4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5bdadc: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5bdafc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5bdae8: (15245480, 'OBJC_CLASS_$_NPC'),
                 0x5bdaec: (15245496, 'OBJC_CLASS_$_Boat'),
                 0x5bdaf0: (15245500, 'OBJC_CLASS_$_TrainCar'),
                 0x5bdaf4: (15245504, 'OBJC_CLASS_$_Sign'),
                 0x5bdaf8: (15245508, 'OBJC_CLASS_$_Painting'),
        },
        instructions=[(6018700, 'push {r4, r5, r6, r7, fp, lr}'), (6019856, 'adceq r2, sl, r0, asr r4')],
        calls=[(6018804, 'blx r5'), (6018852, 'bl loc.imp.objc_msgSend_stret'), (6018888, 'bl sym.imp.memset'), (6018976, 'blx ip'), (6019008, 'blx r3'), (6019112, 'blx ip'), (6019144, 'blx r3'), (6019248, 'blx ip'), (6019280, 'blx r3'), (6019384, 'blx ip'), (6019416, 'blx r3'), (6019520, 'blx ip'), (6019552, 'blx r3'), (6019632, 'bl loc.imp.objc_msgSend'), (6019688, 'bl loc.imp.objc_msgSend'), (6019776, 'bl loc.imp.objc_msgSend')],
        branches=[(6018836, 'beq', 6018860), (6018856, 'b', 6018892), (6019020, 'beq', 6019036), (6019032, 'b', 6019592), (6019156, 'beq', 6019172), (6019168, 'b', 6019588), (6019292, 'beq', 6019308), (6019304, 'b', 6019584), (6019428, 'beq', 6019444), (6019440, 'b', 6019580), (6019564, 'beq', 6019576), (6019576, 'b', 6019580), (6019580, 'b', 6019584), (6019584, 'b', 6019588), (6019588, 'b', 6019592)],
        semantics=('[World removeDynamicObjectTappedAtDynamicObject:withBlockhead:] (imp 0x005bd68c, 290w): the remove-object tap flow - class dispatch chain (NPC / Boat / TrainCar / Sign / Painting) then queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI: for the removal walk.\n'),
    ),
    dict(
        name='cb_08',
        method='World -[addFuelTappedAtInteractionObject:withBlockhead:]',
        types='v16@0:4@8@12',
        start=6019860,
        end=6020464,
        disasm='disasm_worldtileloader_cb_08.txt',
        base_add=6019876,
        base_literal=6020460,
        boundary='ARM.exidx end 0x005bdd70 (listing bound); next ObjC IMP 0x005bdd70 World -[distanceOrderedFoodTypes]',
        selectors={
                 0x5bdd3c: (15195596, 'isKindOfClass:'),
                 0x5bdd40: (15195592, 'class'),
                 0x5bdd4c: (15197584, 'pos'),
                 0x5bdd50: (15197636, 'hideAnyHideableUI'),
                 0x5bdd60: (15196444, 'activeBlockhead'),
                 0x5bdd64: (15196300, 'uniqueID'),
                 0x5bdd68: (15197640, 'queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI:'),
        },
        imports={
                 0x5bdd38: (17151904, 'objc_msgSend'),
                 0x5bdd48: (16232744, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5bdd54: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5bdd58: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5bdd44: (15245488, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(6019860, 'push {r4, r5, r6, r7, fp, lr}'), (6020460, 'adceq r1, sl, r8, asr 31')],
        calls=[(6019968, 'blx lr'), (6020000, 'blx r3'), (6020028, 'bl sym.imp.NSLog'), (6020112, 'blx r3'), (6020160, 'bl loc.imp.objc_msgSend_stret'), (6020196, 'bl sym.imp.memset'), (6020248, 'bl loc.imp.objc_msgSend'), (6020304, 'bl loc.imp.objc_msgSend'), (6020392, 'bl loc.imp.objc_msgSend')],
        branches=[(6020012, 'bne', 6020036), (6020032, 'b', 6020400), (6020144, 'beq', 6020168), (6020164, 'b', 6020200)],
        semantics=('[World addFuelTappedAtInteractionObject:withBlockhead:] (imp 0x005bdb14, 151w): the fuel-tap flow - a Workbench isKindOfClass gate with an NSLog miss path, pos/hideAnyHideableUI, then queueActionWithGoalPos:goalInteraction:pathType:interactionObjectID:craftableItemObject:craftCountOrExtraData:disableCancelCheck:isAI:.\n'),
    ),
    dict(
        name='cb_09',
        method='World -[blockheadReachedInteractionObjectDestination:pathExtraData:]',
        types='v16@0:4@8@12',
        start=6000832,
        end=6001512,
        disasm='disasm_worldtileloader_cb_09.txt',
        base_add=6000848,
        base_literal=6001508,
        boundary='ARM.exidx end 0x005b9368 (listing bound); next ObjC IMP 0x005b9368 World -[useDynamicObjectTappedAtDynamicObject:selectedOption:]',
        selectors={
                 0x5b9338: (15195624, 'objectForKey:'),
                 0x5b933c: (15197656, 'needsRemoved'),
                 0x5b9340: (15197660, 'canBeUsedByBlockhead:'),
                 0x5b9344: (15197664, 'canUseDynamicObject:'),
                 0x5b9348: (15197668, 'isInUse'),
                 0x5b934c: (15196444, 'activeBlockhead'),
                 0x5b9354: (15197676, 'startInteractionWithBlockhead:'),
                 0x5b9358: (15197680, 'showUIForActiveBlockheadReachingInteractionObject:'),
                 0x5b9360: (15197672, 'stopInteracting'),
        },
        imports={
                 0x5b9330: (16232680, '__CFConstantStringClassReference'),
                 0x5b9334: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b9350: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b935c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6000832, 'push {r4, r5, r6, sl, fp, lr}'), (6001508, 'adceq r6, sl, ip, lsl sl')],
        calls=[(6000916, 'blx r5'), (6000980, 'blx r2'), (6001044, 'blx r3'), (6001108, 'blx r3'), (6001164, 'blx r2'), (6001220, 'blx r2'), (6001308, 'blx lr'), (6001360, 'blx ip'), (6001444, 'blx r3')],
        branches=[(6000936, 'beq', 6001180), (6000992, 'bne', 6001180), (6001056, 'beq', 6001180), (6001120, 'beq', 6001180), (6001176, 'beq', 6001228), (6001224, 'b', 6001448), (6001372, 'bne', 6001448)],
        semantics=('[World blockheadReachedInteractionObjectDestination:pathExtraData:] (imp 0x005b90c0, 170w): the arrival handler - objectForKey: on the pathExtraData dict, then the needsRemoved / canBeUsedByBlockhead: / canUseDynamicObject: / isInUse gates decide between startInteractionWithBlockhead:, showUIForActiveBlockheadReachingInteractionObject: and stopInteracting.\n'),
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
        'batch': 'World craft-interaction chain (E105): the workbench completion/warp-in giants and the dynamic-object taps; 10 bodies',
        'claim': ('a census-plus-targeted static map of the World-side workbench interaction chain; the per-branch logic inside the two giants is read at histogram level, and the CrystalManager / Workbench / blockhead message contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_craft.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_craft.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
