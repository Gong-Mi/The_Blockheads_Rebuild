#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench crafting engine: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 5964 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_CRAFTING.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.preserveItemDataAInCraftedItem_ItemType__ItemType_': 0x00aed208,
}

SPECS = [
    dict(
        name='wc_craftcompleted',
        method='Workbench -[craftCompleted]',
        types='v8@0:4',
        start=11449468,
        end=11457032,
        disasm='disasm_worldtileloader_wc_craftcompleted.txt',
        base_add=11449492,
        base_literal=11451820,
        boundary='ARM.exidx end 0x00aed208 (listing bound); next ObjC IMP 0x00aed318 Workbench -[totalItemsLeftToCraft]',
        selectors={
                 0xaebdb8: (15228948, 'needsRemoved'),
                 0xaebdbc: (15229028, 'abortCraft'),
                 0xaebdc0: (15228952, 'pos'),
                 0xaebdd4: (15228872, 'objectType'),
                 0xaebdd8: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaec73c: (15228780, 'craftableItem'),
                 0xaecadc: (15228788, 'count'),
                 0xaecb4c: (15229032, 'setCraftableItem:'),
                 0xaecbb4: (15229000, 'dataA'),
                 0xaecbb8: (15228864, 'objectAtIndex:'),
                 0xaeccf0: (15229036, 'removeObjectAtIndex:'),
                 0xaecde8: (15229040, 'craftItemFinished:atWorkbench:allFinished:blockhead:'),
                 0xaecec4: (15228968, 'setCountWatcher:'),
                 0xaecec8: (15228964, 'worldUI'),
                 0xaececc: (15228880, 'uiManager'),
                 0xaecf34: (15228960, 'instance'),
                 0xaed004: (15228988, 'isEqualToString:'),
                 0xaed008: (15228976, 'stringFromMD5'),
                 0xaed010: (15228784, 'stringWithFormat:'),
                 0xaed018: (15228984, 'amountString'),
                 0xaed01c: (15228980, 'modify:modifyString:'),
                 0xaed024: (15228972, 'amount'),
                 0xaed14c: (15229040, 'craftItemFinished:atWorkbench:allFinished:blockhead:'),
                 0xaed15c: (15228960, 'instance'),
                 0xaed164: (15228984, 'amountString'),
                 0xaed16c: (15229056, 'displayInterstitialForTag:'),
                 0xaed170: (15229052, 'viewController'),
                 0xaed174: (15229048, 'delegate'),
                 0xaed178: (15229044, 'sharedApplication'),
                 0xaed180: (15228956, 'isClientBlockheadBeingControlledByServer'),
                 0xaed188: (15228704, 'release'),
                 0xaed190: (15229020, 'craftItemFinished:atWorkbench:'),
                 0xaed19c: (15229060, 'reportAchievementWithIdentifier:'),
                 0xaed1e0: (15228788, 'count'),
                 0xaed1ec: (15229032, 'setCraftableItem:'),
                 0xaed1f0: (15229000, 'dataA'),
                 0xaed1f4: (15228864, 'objectAtIndex:'),
                 0xaed1fc: (15229036, 'removeObjectAtIndex:'),
        },
        imports={
                 0xaebdb4: (17151904, 'objc_msgSend'),
                 0xaed00c: (16366440, '__CFConstantStringClassReference'),
                 0xaed020: (16366424, '__CFConstantStringClassReference'),
                 0xaed140: (17151904, 'objc_msgSend'),
                 0xaed168: (16366456, '__CFConstantStringClassReference'),
                 0xaed198: (16366712, '__CFConstantStringClassReference'),
                 0xaed1a0: (16366696, '__CFConstantStringClassReference'),
                 0xaed1a4: (16366680, '__CFConstantStringClassReference'),
                 0xaed1a8: (16366664, '__CFConstantStringClassReference'),
                 0xaed1ac: (16366648, '__CFConstantStringClassReference'),
                 0xaed1b0: (16366632, '__CFConstantStringClassReference'),
                 0xaed1b4: (16366616, '__CFConstantStringClassReference'),
                 0xaed1b8: (16366600, '__CFConstantStringClassReference'),
                 0xaed1bc: (16366584, '__CFConstantStringClassReference'),
                 0xaed1c0: (16366568, '__CFConstantStringClassReference'),
                 0xaed1c4: (16366552, '__CFConstantStringClassReference'),
                 0xaed1c8: (16366536, '__CFConstantStringClassReference'),
                 0xaed1cc: (16366520, '__CFConstantStringClassReference'),
                 0xaed1d0: (16366504, '__CFConstantStringClassReference'),
                 0xaed1d4: (16366488, '__CFConstantStringClassReference'),
                 0xaed1d8: (16366472, '__CFConstantStringClassReference'),
                 0xaed1dc: (16366728, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xaebdb0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaebdc4: (17165460, 'OBJC_IVAR_$_Workbench.fractionComplete', 264),
                 0xaebdc8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaebdd0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaec740: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaecae0: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
                 0xaecd5c: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xaecdec: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xaecdf0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaecdf4: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xaecec0: (17165400, 'OBJC_IVAR_$_Workbench.hurryCost', 204),
                 0xaed13c: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaed144: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaed148: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xaed150: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xaed154: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaed158: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xaed184: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xaed18c: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaed194: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xaed1e4: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
        },
        classes={
                 0xaecf38: (15249660, 'OBJC_CLASS_$_CrystalManager'),
                 0xaed014: (15249636, 'OBJC_CLASS_$_NSString'),
                 0xaed160: (15249660, 'OBJC_CLASS_$_CrystalManager'),
                 0xaed17c: (15249664, 'OBJC_CLASS_$_UIApplication'),
        },
        instructions=[(11449468, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11456704, 'b 0xaed0c4'), (11457028, 'andeq r0, r0, r4, ror r0')],
        calls=[(11449608, 'blx r2'), (11449664, 'blx r2'), (11449820, 'bl loc.imp.objc_msgSend'), (11449856, 'bl loc.imp.objc_msgSend'), (11449948, 'bl loc.imp.objc_msgSend_stret'), (11449984, 'bl sym.imp.memset'), (11450112, 'bl loc.imp.objc_msgSend_stret'), (11450148, 'bl sym.imp.memset'), (11450280, 'bl loc.imp.objc_msgSend_stret'), (11450316, 'bl sym.imp.memset'), (11450444, 'bl loc.imp.objc_msgSend_stret'), (11450480, 'bl sym.imp.memset'), (11450608, 'bl loc.imp.objc_msgSend_stret'), (11450644, 'bl sym.imp.memset'), (11450748, 'bl loc.imp.objc_msgSend_stret'), (11450784, 'bl sym.imp.memset'), (11450956, 'bl loc.imp.objc_msgSend_stret'), (11450992, 'bl sym.imp.memset'), (11451212, 'blx r2'), (11451284, 'bl sym.preserveItemDataAInCraftedItem_ItemType__ItemType_'), (11451488, 'blx r5'), (11451504, 'blx r2'), (11451560, 'bl sym.imp.memcpy'), (11451576, 'bl sym.imp.memcpy'), (11451684, 'bl loc.imp.objc_msgSend'), (11451776, 'blx r3'), (11452112, 'blx ip'), (11452284, 'blx r3'), (11452332, 'blx ip'), (11452348, 'blx r2'), (11452380, 'blx r3'), (11452680, 'blx r2'), (11452696, 'blx r2'), (11452768, 'blx lr'), (11452784, 'blx r2'), (11452820, 'blx r3'), (11452860, 'blx ip'), (11452892, 'blx r3'), (11452908, 'blx r2'), (11452972, 'blx r4'), (11452988, 'blx r2'), (11453020, 'blx r3'), (11453116, 'blx lr'), (11453132, 'blx r2'), (11453412, 'blx r2'), (11453484, 'bl sym.preserveItemDataAInCraftedItem_ItemType__ItemType_'), (11453688, 'blx r5'), (11453704, 'blx r2'), (11453760, 'bl sym.imp.memcpy'), (11453776, 'bl sym.imp.memcpy'), (11453884, 'bl loc.imp.objc_msgSend'), (11453976, 'blx r3'), (11454260, 'blx lr'), (11454436, 'blx r2'), (11454452, 'blx r2'), (11454468, 'blx r2'), (11454488, 'blx r3'), (11454564, 'blx r2'), (11454768, 'blx lr'), (11454828, 'blx lr'), (11454988, 'blx ip'), (11455088, 'blx ip'), (11455188, 'blx ip'), (11455300, 'blx ip'), (11455404, 'blx ip'), (11455516, 'blx ip'), (11455616, 'blx ip'), (11455720, 'blx ip'), (11455828, 'blx ip'), (11455968, 'blx ip'), (11456084, 'blx ip'), (11456184, 'blx ip'), (11456300, 'blx ip'), (11456408, 'blx ip'), (11456508, 'blx ip'), (11456656, 'blx ip'), (11456812, 'blx ip')],
        branches=[(11449544, 'beq', 11449624), (11449620, 'beq', 11449672), (11449668, 'b', 11456820), (11449932, 'beq', 11449956), (11449952, 'b', 11449988), (11450024, 'ble', 11450040), (11450036, 'b', 11450204), (11450096, 'beq', 11450120), (11450116, 'b', 11450152), (11450188, 'bge', 11450200), (11450200, 'b', 11450204), (11450264, 'beq', 11450288), (11450284, 'b', 11450320), (11450356, 'ble', 11450372), (11450368, 'b', 11450536), (11450428, 'beq', 11450452), (11450448, 'b', 11450484), (11450520, 'bge', 11450532), (11450532, 'b', 11450536), (11450592, 'beq', 11450616), (11450612, 'b', 11450648), (11450672, 'bne', 11450808), (11450732, 'beq', 11450756), (11450752, 'b', 11450788), (11450796, 'bne', 11450808), (11450816, 'beq', 11450880), (11450828, 'beq', 11450880), (11450840, 'beq', 11450880), (11450852, 'beq', 11450880), (11450864, 'beq', 11450880), (11450876, 'bne', 11450884), (11450880, 'b', 11450884), (11450940, 'beq', 11450964), (11450960, 'b', 11450996), (11451020, 'bge', 11451868), (11451056, 'beq', 11451800), (11451124, 'bge', 11451232), (11451240, 'beq', 11451796), (11451296, 'beq', 11451688), (11451664, 'bne', 11451628), (11451792, 'b', 11451104), (11451796, 'b', 11451800), (11451800, 'b', 11451804), (11451816, 'b', 11451008), (11452140, 'beq', 11454500), (11452416, 'ble', 11453160), (11453032, 'beq', 11453148), (11453144, 'bne', 11453156), (11453156, 'b', 11453160), (11453160, 'b', 11453164), (11453196, 'ble', 11454276), (11453220, 'bge', 11454020), (11453256, 'beq', 11454000), (11453324, 'bge', 11453432), (11453440, 'beq', 11453996), (11453496, 'beq', 11453888), (11453864, 'bne', 11453828), (11453992, 'b', 11453304), (11453996, 'b', 11454000), (11454000, 'b', 11454004), (11454016, 'b', 11453208), (11454264, 'b', 11453164), (11454320, 'beq', 11454496), (11454496, 'b', 11454500), (11454620, 'bne', 11454880), (11454892, 'beq', 11456820), (11454904, 'bne', 11454996), (11454992, 'b', 11456720), (11455004, 'bne', 11455096), (11455092, 'b', 11456716), (11455104, 'bne', 11455208), (11455192, 'b', 11456712), (11455216, 'bne', 11455312), (11455304, 'b', 11456708), (11455320, 'bne', 11455424), (11455408, 'b', 11456704), (11455432, 'bne', 11455524), (11455520, 'b', 11456700), (11455532, 'bne', 11455628), (11455620, 'b', 11456696), (11455636, 'bne', 11455736), (11455724, 'b', 11456692), (11455744, 'bne', 11455840), (11455832, 'b', 11456688), (11455872, 'bne', 11455992), (11455884, 'beq', 11455992), (11455972, 'b', 11456684), (11456000, 'bne', 11456092), (11456088, 'b', 11456680), (11456100, 'bne', 11456208), (11456188, 'b', 11456676), (11456216, 'bne', 11456316), (11456304, 'b', 11456672), (11456324, 'bne', 11456416), (11456412, 'b', 11456668), (11456424, 'bne', 11456552), (11456512, 'b', 11456664), (11456560, 'beq', 11456576), (11456572, 'bne', 11456660), (11456660, 'b', 11456664), (11456664, 'b', 11456668), (11456668, 'b', 11456672), (11456672, 'b', 11456676), (11456676, 'b', 11456680), (11456680, 'b', 11456684), (11456684, 'b', 11456688), (11456688, 'b', 11456692), (11456692, 'b', 11456696), (11456696, 'b', 11456700), (11456700, 'b', 11456704), (11456704, 'b', 11456708), (11456708, 'b', 11456712), (11456712, 'b', 11456716), (11456716, 'b', 11456720), (11456728, 'beq', 11456816), (11456816, 'b', 11456820)],
        semantics=("[Workbench craftCompleted] (imp 0x00aeb47c, 1891w): the crafting completion handler. Census: **7x objc_msgSend_stret + 7x memset + 4x memcpy + 4 objc** - it builds the crafted-item records (the stret/memset/copy family) and calls **`preserveItemDataAInCraftedItem(ItemType, ItemType)` x2** (@the item-transfer arms): the crafted output inherits the input's dataA (the per-item data preservation contract of the crafting system). Key pool: ffffc8a0 x20 (the position) + **ffffcffd0 x10** (the crafting record) + the fffff194/180/188/168/184/164/1a0 state block (fraction fffff1a0 among them).\n"),
    ),
    dict(
        name='wc_craftitem',
        method='Workbench -[craftItem:withBlockhead:craftProgressUI:count:]',
        types='c24@0:4@8@12@16i20',
        start=11514212,
        end=11520124,
        disasm='disasm_worldtileloader_wc_craftitem.txt',
        base_add=11514228,
        base_literal=11516988,
        boundary='ARM.exidx end 0x00afc87c (listing bound); next ObjC IMP 0x00afc87c Workbench -[startManagingFuelWithBlockhead:]',
        selectors={
                 0xafc1d0: (15228848, 'retain'),
                 0xafc1d4: (15228804, 'autorelease'),
                 0xafc1e0: (15228704, 'release'),
                 0xafc1e4: (15228780, 'craftableItem'),
                 0xafc210: (15228756, 'worldTime'),
                 0xafc21c: (15228956, 'isClientBlockheadBeingControlledByServer'),
                 0xafc220: (15228988, 'isEqualToString:'),
                 0xafc224: (15228976, 'stringFromMD5'),
                 0xafc22c: (15228784, 'stringWithFormat:'),
                 0xafc234: (15228984, 'amountString'),
                 0xafc238: (15228960, 'instance'),
                 0xafc68c: (15228972, 'amount'),
                 0xafc7ac: (15228848, 'retain'),
                 0xafc7bc: (15229056, 'displayInterstitialForTag:'),
                 0xafc7c0: (15229052, 'viewController'),
                 0xafc7c4: (15229048, 'delegate'),
                 0xafc7c8: (15229044, 'sharedApplication'),
                 0xafc7d0: (15229232, 'addToCrystalDiscrepency:'),
                 0xafc7d8: (15229236, 'startInteractionWithBlockhead:'),
                 0xafc7dc: (15228812, 'setInteractionWorkbench:'),
                 0xafc7ec: (15228872, 'objectType'),
                 0xafc7f0: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xafc7f4: (15228788, 'count'),
                 0xafc7fc: (15229228, 'subtractItemsFromInventoryOfType:count:dataB:'),
                 0xafc804: (15228956, 'isClientBlockheadBeingControlledByServer'),
                 0xafc814: (15228960, 'instance'),
                 0xafc818: (15228880, 'uiManager'),
                 0xafc81c: (15228964, 'worldUI'),
                 0xafc820: (15228968, 'setCountWatcher:'),
                 0xafc824: (15228988, 'isEqualToString:'),
                 0xafc828: (15228976, 'stringFromMD5'),
                 0xafc830: (15228784, 'stringWithFormat:'),
                 0xafc838: (15228972, 'amount'),
                 0xafc844: (15228980, 'modify:modifyString:'),
                 0xafc848: (15228984, 'amountString'),
                 0xafc84c: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xafc858: (15228996, 'itemType'),
                 0xafc85c: (15229000, 'dataA'),
                 0xafc860: (15229004, 'dataB'),
                 0xafc864: (15229008, 'subItems'),
                 0xafc868: (15229012, 'dynamicObjectSaveDict'),
                 0xafc86c: (15228992, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xafc874: (15228704, 'release'),
        },
        imports={
                 0xafc1cc: (17151904, 'objc_msgSend'),
                 0xafc228: (16366440, '__CFConstantStringClassReference'),
                 0xafc7a8: (17151904, 'objc_msgSend'),
                 0xafc7b8: (16366456, '__CFConstantStringClassReference'),
                 0xafc82c: (16366440, '__CFConstantStringClassReference'),
                 0xafc840: (16366424, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xafbc40: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xafc1c8: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xafc1d8: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
                 0xafc1e8: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xafc1ec: (17165344, 'OBJC_IVAR_$_Workbench.requiresElectricity', 224),
                 0xafc1f0: (17165364, 'OBJC_IVAR_$_Workbench.fuelCounter', 216),
                 0xafc1f4: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xafc1f8: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xafc1fc: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xafc200: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xafc204: (17165472, 'OBJC_IVAR_$_Workbench.craftProgressUI', 184),
                 0xafc208: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xafc20c: (17165388, 'OBJC_IVAR_$_Workbench.lastWorldTime', 256),
                 0xafc214: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xafc218: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xafc7b0: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xafc7b4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xafc7e0: (17165460, 'OBJC_IVAR_$_Workbench.fractionComplete', 264),
                 0xafc7e4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xafc7e8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xafc800: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
                 0xafc808: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
        },
        classes={
                 0xafc230: (15249636, 'OBJC_CLASS_$_NSString'),
                 0xafc23c: (15249660, 'OBJC_CLASS_$_CrystalManager'),
                 0xafc7cc: (15249664, 'OBJC_CLASS_$_UIApplication'),
                 0xafc80c: (15249660, 'OBJC_CLASS_$_CrystalManager'),
                 0xafc83c: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11514212, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11520120, 'subseq r4, r6, ip, ror r1')],
        calls=[(11514396, 'blx r3'), (11514428, 'blx r3'), (11514548, 'bl loc.imp.objc_msgSend'), (11514672, 'bl loc.imp.objc_msgSend_stret'), (11514708, 'bl sym.imp.memset'), (11515016, 'blx r2'), (11515396, 'blx r2'), (11515616, 'blx sl'), (11515632, 'blx r2'), (11515668, 'blx r3'), (11515684, 'blx r2'), (11515724, 'blx lr'), (11515740, 'blx r2'), (11515772, 'blx r3'), (11515868, 'blx lr'), (11515884, 'blx r2'), (11516048, 'bl loc.imp.objc_msgSend'), (11516096, 'bl loc.imp.objc_msgSend'), (11516112, 'bl loc.imp.objc_msgSend'), (11516144, 'bl loc.imp.objc_msgSend'), (11516348, 'bl loc.imp.objc_msgSend'), (11516364, 'bl loc.imp.objc_msgSend'), (11516472, 'bl loc.imp.objc_msgSend'), (11516488, 'bl loc.imp.objc_msgSend'), (11516516, 'bl loc.imp.objc_msgSend'), (11516568, 'bl loc.imp.objc_msgSend'), (11516592, 'bl loc.imp.objc_msgSend'), (11516608, 'bl loc.imp.objc_msgSend'), (11516700, 'blx ip'), (11516716, 'blx r2'), (11516748, 'blx r3'), (11516844, 'blx lr'), (11516860, 'blx r2'), (11517120, 'blx r2'), (11517136, 'blx r2'), (11517152, 'blx r2'), (11517172, 'blx r3'), (11517380, 'bl loc.imp.objc_msgSend'), (11517400, 'bl loc.imp.objc_msgSend'), (11517472, 'blx r3'), (11517732, 'blx r6'), (11517832, 'bl sym.imp.objc_enumerationMutation'), (11517920, 'bl loc.imp.objc_msgSend'), (11517952, 'bl loc.imp.objc_msgSend'), (11517984, 'bl loc.imp.objc_msgSend'), (11518016, 'bl loc.imp.objc_msgSend'), (11518048, 'bl loc.imp.objc_msgSend'), (11518156, 'bl loc.imp.objc_msgSend'), (11518256, 'blx ip'), (11518356, 'bl loc.imp.objc_msgSend'), (11518648, 'blx r2'), (11518732, 'bl loc.imp.objc_msgSend'), (11518780, 'bl loc.imp.objc_msgSend'), (11518796, 'bl loc.imp.objc_msgSend'), (11518828, 'bl loc.imp.objc_msgSend'), (11519044, 'bl loc.imp.objc_msgSend'), (11519060, 'bl loc.imp.objc_msgSend'), (11519168, 'bl loc.imp.objc_msgSend'), (11519184, 'bl loc.imp.objc_msgSend'), (11519212, 'bl loc.imp.objc_msgSend'), (11519268, 'bl loc.imp.objc_msgSend'), (11519292, 'bl loc.imp.objc_msgSend'), (11519308, 'bl loc.imp.objc_msgSend'), (11519400, 'blx ip'), (11519416, 'blx r2'), (11519448, 'blx r3'), (11519544, 'blx lr'), (11519560, 'blx r2'), (11519700, 'bl loc.imp.objc_msgSend'), (11519724, 'bl loc.imp.objc_msgSend'), (11519748, 'bl loc.imp.objc_msgSend'), (11519848, 'bl loc.imp.objc_msgSend'), (11519884, 'bl loc.imp.objc_msgSend')],
        branches=[(11514296, 'beq', 11514312), (11514308, 'b', 11519896), (11514472, 'bge', 11514600), (11514596, 'b', 11514464), (11514656, 'beq', 11514680), (11514676, 'b', 11514712), (11514720, 'bne', 11514788), (11514764, 'beq', 11514784), (11514776, 'b', 11519896), (11514784, 'b', 11514788), (11515248, 'beq', 11515284), (11515316, 'bge', 11516996), (11515352, 'bne', 11516968), (11515408, 'bne', 11516892), (11515784, 'beq', 11515900), (11515896, 'bne', 11515908), (11515976, 'ble', 11515992), (11515988, 'b', 11519896), (11516196, 'ble', 11516888), (11516760, 'beq', 11516876), (11516872, 'bne', 11516884), (11516884, 'b', 11516888), (11516888, 'b', 11516964), (11516964, 'b', 11516968), (11516968, 'b', 11516972), (11516984, 'b', 11515304), (11517004, 'beq', 11517180), (11517200, 'bge', 11519656), (11517236, 'beq', 11519636), (11517496, 'ble', 11519632), (11517572, 'bgt', 11518528), (11517744, 'beq', 11518280), (11517824, 'beq', 11517836), (11518184, 'blo', 11517788), (11518276, 'bne', 11517788), (11518280, 'b', 11518284), (11518404, 'b', 11517560), (11518548, 'bge', 11519616), (11518584, 'bne', 11519596), (11518660, 'bne', 11519592), (11518892, 'bgt', 11519588), (11519460, 'beq', 11519576), (11519572, 'bne', 11519584), (11519584, 'b', 11519588), (11519588, 'b', 11519592), (11519592, 'b', 11519596), (11519596, 'b', 11519600), (11519612, 'b', 11518536), (11519624, 'b', 11519896), (11519632, 'b', 11519636), (11519636, 'b', 11519640), (11519652, 'b', 11517188)],
        semantics=('[Workbench craftItem:withBlockhead:craftProgressUI:count:] (imp 0x00afb164, 1478w): the craft start - **39 objc_msgSend** (the heaviest objc census of the class: the blockhead/UI interactions), one stret + one **fast-enumeration** (`objc_enumerationMutation`); the craft-dict keys **fff3c074/c064** + the fffff18c x10/194/180/12c/130 state (the craft definition, item counts, type).\n'),
    ),
    dict(
        name='wc_bhownership',
        method='Workbench -[blockheadWouldLikeToTakeOwnership:withSaveDict:]',
        types='v16@0:4@8@12',
        start=11432520,
        end=11436496,
        disasm='disasm_worldtileloader_wc_bhownership.txt',
        base_add=11432536,
        base_literal=11436488,
        boundary='ARM.exidx end 0x00ae81d0 (listing bound); next ObjC IMP 0x00ae81d0 Workbench -[getSaveDict]',
        selectors={
                 0xae80e4: (15228736, 'intValue'),
                 0xae80ec: (15228724, 'objectForKey:'),
                 0xae80f4: (15228732, 'boolValue'),
                 0xae8100: (15228728, 'floatValue'),
                 0xae8118: (15228848, 'retain'),
                 0xae811c: (15228704, 'release'),
                 0xae8128: (15228776, 'initWithCraftableItem:'),
                 0xae812c: (15228712, 'alloc'),
                 0xae8134: (15228772, 'bytes'),
                 0xae813c: (15228768, 'initWithSaveDict:'),
                 0xae8148: (15228780, 'craftableItem'),
                 0xae8164: (15228884, 'displayCraftProgressUIIfActiveBlockhead:workbench:'),
                 0xae8168: (15228880, 'uiManager'),
                 0xae8174: (15228812, 'setInteractionWorkbench:'),
                 0xae8184: (15228872, 'objectType'),
                 0xae8188: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xae8194: (15228788, 'count'),
                 0xae819c: (15228784, 'stringWithFormat:'),
                 0xae81a4: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xae81b0: (15228792, 'init'),
                 0xae81b4: (15228808, 'addObject:'),
                 0xae81b8: (15228804, 'autorelease'),
                 0xae81c4: (15228800, 'initWithSaveData:'),
        },
        imports={
                 0xae80e0: (17151904, 'objc_msgSend'),
                 0xae80e8: (16366184, '__CFConstantStringClassReference'),
                 0xae80f8: (16366168, '__CFConstantStringClassReference'),
                 0xae8104: (16366152, '__CFConstantStringClassReference'),
                 0xae810c: (16366136, '__CFConstantStringClassReference'),
                 0xae8114: (16366120, '__CFConstantStringClassReference'),
                 0xae8120: (16366264, '__CFConstantStringClassReference'),
                 0xae8124: (16366296, '__CFConstantStringClassReference'),
                 0xae8138: (16366280, '__CFConstantStringClassReference'),
                 0xae8150: (16366344, '__CFConstantStringClassReference'),
                 0xae8158: (16366328, '__CFConstantStringClassReference'),
                 0xae8160: (16366312, '__CFConstantStringClassReference'),
                 0xae8198: (16366360, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae80d0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xae80d4: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xae80d8: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xae80dc: (17165400, 'OBJC_IVAR_$_Workbench.hurryCost', 204),
                 0xae80f0: (17165404, 'OBJC_IVAR_$_Workbench.hurrying', 200),
                 0xae80fc: (17165408, 'OBJC_IVAR_$_Workbench.hurrySeconds', 196),
                 0xae8108: (17165412, 'OBJC_IVAR_$_Workbench.hurryTimer', 192),
                 0xae8110: (17165416, 'OBJC_IVAR_$_Workbench.craftProgressCount', 188),
                 0xae814c: (17165432, 'OBJC_IVAR_$_Workbench.countCreated', 236),
                 0xae8154: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
                 0xae815c: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xae816c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae8178: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xae817c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae8180: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xae818c: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
        },
        classes={
                 0xae8130: (15249632, 'OBJC_CLASS_$_CraftableItemObject'),
                 0xae8140: (15249628, 'OBJC_CLASS_$_PaintingCraftableItemObject'),
                 0xae8144: (15249624, 'OBJC_CLASS_$_BlockheadCraftableItemObject'),
                 0xae81a0: (15249636, 'OBJC_CLASS_$_NSString'),
                 0xae81a8: (15249640, 'OBJC_CLASS_$_NSMutableArray'),
                 0xae81bc: (15249644, 'OBJC_CLASS_$_InventoryItem'),
        },
        instructions=[(11432520, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11436492, 'andeq r0, r0, r4, ror r0')],
        calls=[(11432924, 'blx r4'), (11432968, 'blx r3'), (11432984, 'blx r2'), (11433032, 'blx r3'), (11433048, 'blx r2'), (11433096, 'blx r3'), (11433112, 'blx r2'), (11433160, 'blx r3'), (11433176, 'blx r2'), (11433220, 'blx r3'), (11433236, 'blx r2'), (11433384, 'blx r3'), (11433472, 'blx r3'), (11433568, 'blx ip'), (11433584, 'blx r2'), (11433676, 'blx r2'), (11433696, 'blx r3'), (11433808, 'blx r2'), (11433828, 'blx r3'), (11433928, 'blx r2'), (11433948, 'blx r3'), (11434040, 'blx r3'), (11434180, 'blx r4'), (11434204, 'bl sym.imp.memcpy'), (11434236, 'blx r3'), (11434264, 'bl sym.imp.memcpy'), (11434372, 'bl loc.imp.objc_msgSend'), (11434512, 'bl loc.imp.objc_msgSend_stret'), (11434548, 'bl sym.imp.memset'), (11434704, 'blx r3'), (11434720, 'blx r2'), (11434764, 'blx r3'), (11434780, 'blx r2'), (11434824, 'blx r3'), (11434840, 'blx r2'), (11434956, 'bl loc.imp.objc_msgSend'), (11435132, 'blx r4'), (11435164, 'blx r3'), (11435188, 'blx r2'), (11435312, 'bl loc.imp.objc_msgSend'), (11435328, 'bl loc.imp.objc_msgSend'), (11435384, 'bl sym.imp.memset'), (11435432, 'blx lr'), (11435532, 'bl sym.imp.objc_enumerationMutation'), (11435640, 'bl loc.imp.objc_msgSend'), (11435660, 'bl loc.imp.objc_msgSend'), (11435732, 'blx ip'), (11435764, 'blx r3'), (11435864, 'blx ip'), (11436032, 'bl loc.imp.objc_msgSend'), (11436132, 'bl loc.imp.objc_msgSend'), (11436168, 'bl loc.imp.objc_msgSend'), (11436204, 'blx r3'), (11436228, 'blx ip')],
        branches=[(11432592, 'bne', 11436232), (11433312, 'beq', 11433412), (11433492, 'beq', 11433980), (11433600, 'bne', 11433724), (11433720, 'b', 11433976), (11433732, 'bne', 11433856), (11433852, 'b', 11433972), (11433972, 'b', 11433976), (11433976, 'b', 11434400), (11434060, 'beq', 11434396), (11434352, 'bne', 11434316), (11434396, 'b', 11434400), (11434436, 'beq', 11435924), (11434496, 'beq', 11434520), (11434516, 'b', 11434552), (11434888, 'bge', 11435920), (11435012, 'beq', 11435900), (11435196, 'bls', 11435896), (11435444, 'beq', 11435888), (11435524, 'beq', 11435536), (11435792, 'blo', 11435488), (11435884, 'bne', 11435488), (11435888, 'b', 11435892), (11435892, 'b', 11435896), (11435896, 'b', 11435900), (11435900, 'b', 11435904), (11435916, 'b', 11434876), (11435920, 'b', 11435924)],
        semantics=("[Workbench blockheadWouldLikeToTakeOwnership:withSaveDict:] (imp 0x00ae7248, 994w): the ownership transfer - 9 objc + 2 memcpy + 2 memset + stret + fast-enumeration; the save keys **fff3bf74/bf64/bf54** (the same fff3bf5x/7x family as the E77 save ctor) + fffff180 x8/194/164/168/16c/170 state: the blockhead's request carries its own save dict which is decoded into the transfer record.\n"),
    ),
    dict(
        name='wc_abortcraft',
        method='Workbench -[abortCraft]',
        types='v8@0:4',
        start=11443064,
        end=11446980,
        disasm='disasm_worldtileloader_wc_abortcraft.txt',
        base_add=11443080,
        base_literal=11446976,
        boundary='ARM.exidx end 0x00aeaac4 (listing bound); next ObjC IMP 0x00aeaac4 Workbench -[abortImmediatelyAndRestoreBlockheadItems]',
        selectors={
                 0xaeaa00: (15228948, 'needsRemoved'),
                 0xaeaa08: (15228704, 'release'),
                 0xaeaa0c: (15228952, 'pos'),
                 0xaeaa18: (15228780, 'craftableItem'),
                 0xaeaa2c: (15229016, 'craftAbortedForWorkbench:withBlockhead:'),
                 0xaeaa34: (15229020, 'craftItemFinished:atWorkbench:'),
                 0xaeaa3c: (15228872, 'objectType'),
                 0xaeaa40: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaeaa54: (15228992, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xaeaa58: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xaeaa64: (15228996, 'itemType'),
                 0xaeaa68: (15229000, 'dataA'),
                 0xaeaa6c: (15229004, 'dataB'),
                 0xaeaa70: (15229008, 'subItems'),
                 0xaeaa74: (15229012, 'dynamicObjectSaveDict'),
                 0xaeaa7c: (15228956, 'isClientBlockheadBeingControlledByServer'),
                 0xaeaa88: (15228960, 'instance'),
                 0xaeaa8c: (15228880, 'uiManager'),
                 0xaeaa90: (15228964, 'worldUI'),
                 0xaeaa94: (15228968, 'setCountWatcher:'),
                 0xaeaa98: (15228988, 'isEqualToString:'),
                 0xaeaa9c: (15228976, 'stringFromMD5'),
                 0xaeaaa4: (15228784, 'stringWithFormat:'),
                 0xaeaaac: (15228972, 'amount'),
                 0xaeaab8: (15228980, 'modify:modifyString:'),
                 0xaeaabc: (15228984, 'amountString'),
        },
        imports={
                 0xaea9fc: (17151904, 'objc_msgSend'),
                 0xaeaaa0: (16366440, '__CFConstantStringClassReference'),
                 0xaeaab4: (16366424, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xaeaa04: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaeaa10: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaeaa14: (17165460, 'OBJC_IVAR_$_Workbench.fractionComplete', 264),
                 0xaeaa1c: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaeaa20: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xaeaa24: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaeaa30: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaeaa38: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaeaa44: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
                 0xaeaa4c: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
        },
        classes={
                 0xaeaa80: (15249660, 'OBJC_CLASS_$_CrystalManager'),
                 0xaeaab0: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11443064, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11446976, 'subseq r5, r7, r4, ror 30')],
        calls=[(11443140, 'blx r3'), (11443224, 'blx r3'), (11443404, 'bl loc.imp.objc_msgSend_stret'), (11443440, 'bl sym.imp.memset'), (11443568, 'bl loc.imp.objc_msgSend_stret'), (11443604, 'bl sym.imp.memset'), (11443736, 'bl loc.imp.objc_msgSend_stret'), (11443772, 'bl sym.imp.memset'), (11443900, 'bl loc.imp.objc_msgSend_stret'), (11443936, 'bl sym.imp.memset'), (11444064, 'bl loc.imp.objc_msgSend_stret'), (11444104, 'bl sym.imp.memset'), (11444232, 'blx r2'), (11444316, 'bl loc.imp.objc_msgSend'), (11444364, 'bl loc.imp.objc_msgSend'), (11444380, 'bl loc.imp.objc_msgSend'), (11444412, 'bl loc.imp.objc_msgSend'), (11444628, 'bl loc.imp.objc_msgSend'), (11444644, 'bl loc.imp.objc_msgSend'), (11444752, 'bl loc.imp.objc_msgSend'), (11444768, 'bl loc.imp.objc_msgSend'), (11444796, 'bl loc.imp.objc_msgSend'), (11444852, 'bl loc.imp.objc_msgSend'), (11444876, 'bl loc.imp.objc_msgSend'), (11444892, 'bl loc.imp.objc_msgSend'), (11444984, 'blx ip'), (11445000, 'blx r2'), (11445032, 'blx r3'), (11445128, 'blx lr'), (11445144, 'blx r2'), (11445480, 'bl loc.imp.objc_msgSend'), (11445660, 'blx r6'), (11445760, 'bl sym.imp.objc_enumerationMutation'), (11445848, 'bl loc.imp.objc_msgSend'), (11445880, 'bl loc.imp.objc_msgSend'), (11445912, 'bl loc.imp.objc_msgSend'), (11445944, 'bl loc.imp.objc_msgSend'), (11445976, 'bl loc.imp.objc_msgSend'), (11446100, 'bl loc.imp.objc_msgSend'), (11446200, 'blx ip'), (11446300, 'bl loc.imp.objc_msgSend'), (11446500, 'bl loc.imp.objc_msgSend'), (11446572, 'bl loc.imp.objc_msgSend'), (11446648, 'bl loc.imp.objc_msgSend'), (11446684, 'bl loc.imp.objc_msgSend'), (11446744, 'blx lr')],
        branches=[(11443152, 'beq', 11443252), (11443388, 'beq', 11443412), (11443408, 'b', 11443444), (11443480, 'ble', 11443496), (11443492, 'b', 11443660), (11443552, 'beq', 11443576), (11443572, 'b', 11443608), (11443644, 'bge', 11443656), (11443656, 'b', 11443660), (11443720, 'beq', 11443744), (11443740, 'b', 11443776), (11443812, 'ble', 11443828), (11443824, 'b', 11443992), (11443884, 'beq', 11443908), (11443904, 'b', 11443940), (11443976, 'bge', 11443988), (11443988, 'b', 11443992), (11444048, 'beq', 11444076), (11444068, 'b', 11444108), (11444132, 'bge', 11446356), (11444168, 'bne', 11445184), (11444244, 'bne', 11445176), (11444476, 'bgt', 11445172), (11445044, 'beq', 11445160), (11445156, 'bne', 11445168), (11445168, 'b', 11445172), (11445172, 'b', 11445180), (11445176, 'b', 11445180), (11445180, 'b', 11446336), (11445240, 'bne', 11445504), (11445324, 'bge', 11445500), (11445496, 'b', 11445256), (11445500, 'b', 11445504), (11445672, 'beq', 11446224), (11445752, 'beq', 11445764), (11446128, 'blo', 11445716), (11446220, 'bne', 11445716), (11446224, 'b', 11446228), (11446336, 'b', 11446340), (11446352, 'b', 11444120)],
        semantics=('[Workbench abortCraft] (imp 0x00ae9b78, 979w): the soft abort - **24 objc + 5x stret + 5x memset + fast-enumeration**; the crafting record chain ffffcffd0 x11 + ffffc89c x6 + fffff188 x4/194/1a0 (the progress fractions) + the fff3c074/c064 keys: the partially-crafted items are restored to the blockhead per the progress fraction (the abort keeps the partial products).\n'),
    ),
    dict(
        name='wc_abortrestore',
        method='Workbench -[abortImmediatelyAndRestoreBlockheadItems]',
        types='v8@0:4',
        start=11446980,
        end=11449468,
        disasm='disasm_worldtileloader_wc_abortrestore.txt',
        base_add=11446996,
        base_literal=11449464,
        boundary='ARM.exidx end 0x00aeb47c (listing bound); next ObjC IMP 0x00aeb47c Workbench -[craftCompleted]',
        selectors={
                 0xaeb3e8: (15228780, 'craftableItem'),
                 0xaeb3f4: (15228704, 'release'),
                 0xaeb404: (15229016, 'craftAbortedForWorkbench:withBlockhead:'),
                 0xaeb408: (15229020, 'craftItemFinished:atWorkbench:'),
                 0xaeb414: (15228872, 'objectType'),
                 0xaeb418: (15228876, 'dynamicWorldChangedAtPos:objectType:'),
                 0xaeb41c: (15228796, 'countByEnumeratingWithState:objects:count:'),
                 0xaeb428: (15229024, 'addItemToInventory:'),
                 0xaeb430: (15228956, 'isClientBlockheadBeingControlledByServer'),
                 0xaeb440: (15228960, 'instance'),
                 0xaeb444: (15228880, 'uiManager'),
                 0xaeb448: (15228964, 'worldUI'),
                 0xaeb44c: (15228968, 'setCountWatcher:'),
                 0xaeb450: (15228988, 'isEqualToString:'),
                 0xaeb454: (15228976, 'stringFromMD5'),
                 0xaeb45c: (15228784, 'stringWithFormat:'),
                 0xaeb464: (15228972, 'amount'),
                 0xaeb470: (15228980, 'modify:modifyString:'),
                 0xaeb474: (15228984, 'amountString'),
        },
        imports={
                 0xaeb3f0: (17151904, 'objc_msgSend'),
                 0xaeb458: (16366440, '__CFConstantStringClassReference'),
                 0xaeb46c: (16366424, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xaeb3e0: (17156804, 'OBJC_IVAR_$_InteractionObject.currentBlockhead', 56),
                 0xaeb3e4: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xaeb3ec: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
                 0xaeb3f8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xaeb3fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xaeb40c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xaeb410: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xaeb420: (17165448, 'OBJC_IVAR_$_Workbench.sourceItems', 140),
                 0xaeb434: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
        },
        classes={
                 0xaeb438: (15249660, 'OBJC_CLASS_$_CrystalManager'),
                 0xaeb468: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11446980, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11449464, 'subseq r5, r7, r8, lsl r0')],
        calls=[(11447156, 'bl loc.imp.objc_msgSend_stret'), (11447192, 'bl sym.imp.memset'), (11447320, 'blx r2'), (11447404, 'bl loc.imp.objc_msgSend'), (11447452, 'bl loc.imp.objc_msgSend'), (11447468, 'bl loc.imp.objc_msgSend'), (11447500, 'bl loc.imp.objc_msgSend'), (11447716, 'bl loc.imp.objc_msgSend'), (11447732, 'bl loc.imp.objc_msgSend'), (11447840, 'bl loc.imp.objc_msgSend'), (11447856, 'bl loc.imp.objc_msgSend'), (11447884, 'bl loc.imp.objc_msgSend'), (11447940, 'bl loc.imp.objc_msgSend'), (11447964, 'bl loc.imp.objc_msgSend'), (11447980, 'bl loc.imp.objc_msgSend'), (11448072, 'blx ip'), (11448088, 'blx r2'), (11448120, 'blx r3'), (11448216, 'blx lr'), (11448232, 'blx r2'), (11448428, 'blx r6'), (11448528, 'bl sym.imp.objc_enumerationMutation'), (11448628, 'blx r3'), (11448732, 'blx ip'), (11448832, 'bl loc.imp.objc_msgSend'), (11449032, 'bl loc.imp.objc_msgSend'), (11449104, 'bl loc.imp.objc_msgSend'), (11449180, 'bl loc.imp.objc_msgSend'), (11449216, 'bl loc.imp.objc_msgSend'), (11449276, 'blx lr')],
        branches=[(11447044, 'beq', 11449304), (11447080, 'beq', 11449304), (11447140, 'beq', 11447164), (11447160, 'b', 11447196), (11447220, 'bge', 11448888), (11447256, 'bne', 11448272), (11447332, 'bne', 11448264), (11447564, 'bgt', 11448260), (11448132, 'beq', 11448248), (11448244, 'bne', 11448256), (11448256, 'b', 11448260), (11448260, 'b', 11448268), (11448264, 'b', 11448268), (11448268, 'b', 11448868), (11448440, 'beq', 11448756), (11448520, 'beq', 11448532), (11448660, 'blo', 11448484), (11448752, 'bne', 11448484), (11448756, 'b', 11448760), (11448868, 'b', 11448872), (11448884, 'b', 11447208)],
        semantics=('[Workbench abortImmediatelyAndRestoreBlockheadItems] (imp 0x00aeaac4, 622w): the hard abort - 17 objc + stret + fast-enumeration; the same record/state family (ffffcffd0 x5, fffff188 x3, ffffc8d8, the fff3c074/c064 keys): the immediate variant returns the stored items without the completion path.\n'),
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
        'batch': 'Workbench crafting engine cluster (E78): craftCompleted, the craft start, the ownership transfer and the two aborts; 5 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the wire-format markers, the '
                  'NSLog key strings, the C++ container member layouts and the packet helper at 0x8b84c8 are '
                  'outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'workbench_crafting.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_crafting.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
