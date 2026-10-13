#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: the Tree base class: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 4378 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TREE_BASE.md for the prose and boundaries.
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
    'bl 0x4c0bc4': 0x004c0bc4,
    'bl 0x4c5730': 0x004c5730,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl sym.baseGrowthRateForTreeType_TreeType_': 0x004c1e84,
    'bl sym.clampi_int__int__int_': 0x004c0b70,
    'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_': 0x004c0bd4,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsTreeTrunk_Tile_': 0x00a11390,
}

SPECS = [
    dict(
        name='tr_rmmacro',
        method='Tree -[removeFromMacroBlock]',
        types='v8@0:4',
        start=4981536,
        end=4981716,
        disasm='disasm_worldtileloader_tr_rmmacro.txt',
        base_add=4981552,
        base_literal=4981712,
        boundary='ARM.exidx end 0x004c03d4 (listing bound); next ObjC IMP 0x004c03d4 Tree -[initStaticTreeWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x4c03c0: (15192632, 'removeFromMacroBlock'),
                 0x4c03cc: (15192628, 'removeAllOwnedTiles:'),
        },
        imports={
                 0x4c03bc: (17151900, 'objc_msgSendSuper2'),
                 0x4c03c8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x4c03c4: (15252528, 'OBJC_CLASS_$_Tree'),
        },
        instructions=[(4981536, 'push {r4, r5, r6, r7, fp, lr}'), (4981712, 'ldrhteq pc, [sb], ip')],
        calls=[(4981640, 'blx r6'), (4981680, 'blx r2')],
        branches=[],
        semantics=('[Tree removeFromMacroBlock] (imp 0x004c0320, 45w): the removal hook over the shared chain.\n'),
    ),
    dict(
        name='tr_initstatic',
        method='Tree -[initStaticTreeWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        types='@36@0:4@8@12{?=ii}16@24@28@32',
        start=4981716,
        end=4982328,
        disasm='disasm_worldtileloader_tr_initstatic.txt',
        base_add=4981732,
        base_literal=4982324,
        boundary='ARM.exidx end 0x004c0638 (listing bound); next ObjC IMP 0x004c0638 Tree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        selectors={
                 0x4c0610: (15192636, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x4c062c: (15192640, 'release'),
                 0x4c0630: (15192632, 'removeFromMacroBlock'),
        },
        imports={
                 0x4c0628: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c0614: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c0618: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c061c: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x4c0620: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x4c0624: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={
                 0x4c0608: (15252528, 'OBJC_CLASS_$_Tree'),
        },
        instructions=[(4981716, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4982324, 'adcseq pc, sb, r8, lsl 14')],
        calls=[(4981908, 'bl loc.imp.objc_msgSendSuper2'), (4982080, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4982184, 'blx ip'), (4982204, 'blx r2'), (4982228, 'bl sym.imp.__wrap_calloc')],
        branches=[(4981936, 'bne', 4981952), (4981948, 'b', 4982268), (4982100, 'beq', 4982120), (4982116, 'beq', 4982220), (4982216, 'b', 4982268)],
        semantics=('[Tree initStaticTreeWithWorld:dynamicWorld:atPosition:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:] (imp 0x004c03d4, 153w): the static-tree initializer - super2 + `tileAtWorldPositionLoaded` + **`__wrap_calloc`** (the static tree allocates its own backing block at placement).\n'),
    ),
    dict(
        name='tr_ctor',
        method='Tree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=4982328,
        end=4983664,
        disasm='disasm_worldtileloader_tr_ctor.txt',
        base_add=4982344,
        base_literal=4983660,
        boundary='ARM.exidx end 0x004c0b70 (listing bound); next ObjC IMP 0x004c1f84 Tree -[isGrowingInCompost]',
        selectors={
                 0x4c0b20: (15192636, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0x4c0b50: (15192644, 'treeType'),
                 0x4c0b64: (15192640, 'release'),
                 0x4c0b68: (15192632, 'removeFromMacroBlock'),
        },
        imports={
                 0x4c0b4c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c0b28: (17155040, 'OBJC_IVAR_$_Tree.growthCounter', 68),
                 0x4c0b2c: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x4c0b30: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
                 0x4c0b34: (17155044, 'OBJC_IVAR_$_Tree.growthRateGene', 56),
                 0x4c0b38: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0x4c0b40: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c0b44: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c0b48: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0x4c0b60: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={
                 0x4c0b18: (15252528, 'OBJC_CLASS_$_Tree'),
        },
        instructions=[(4982328, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4982576, 'bl loc.imp.objc_msgSendSuper2'), (4982600, 'cmp r1, r0'), (4982632, 'bl sym.clampi_int__int__int_'), (4982676, 'bl sym.clampi_int__int__int_'), (4983660, 'adcseq pc, sb, r4, lsr 9')],
        calls=[(4982576, 'bl loc.imp.objc_msgSendSuper2'), (4982632, 'bl sym.clampi_int__int__int_'), (4982676, 'bl sym.clampi_int__int__int_'), (4982812, 'bl 0x4c0bc4'), (4982932, 'bl loc.imp.objc_msgSend'), (4983000, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (4983060, 'blx r2'), (4983064, 'bl sym.baseGrowthRateForTreeType_TreeType_'), (4983176, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4983280, 'blx ip'), (4983300, 'blx r2'), (4983392, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4983524, 'bl sym.imp.__wrap_calloc')],
        branches=[(4982604, 'bne', 4982620), (4982616, 'b', 4983564), (4982808, 'beq', 4982860), (4983196, 'beq', 4983216), (4983212, 'beq', 4983316), (4983312, 'b', 4983564), (4983412, 'beq', 4983516), (4983428, 'beq', 4983464), (4983444, 'beq', 4983464), (4983460, 'bne', 4983512), (4983512, 'b', 4983516)],
        semantics=('[Tree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x004c0638, 1619w): the tree BASE ctor - super2 with the wide frame (@0x4c0730) + nil gate (@0x4c0748); the two gene halfwords are clamped **`clampi(1, 0xff)` x2** (@0x4c0768/0x4c0794, stored via strh @0x4c078c/0x4c07d0 into the ffffc8f4/c8f0/c8e0/c8e4/c8ec cells); the growth math calls **`growthVigorForTreeTypeAtPos`** AND **`baseGrowthRateForTreeType...`** (the second vigor-family symbol!) with the shared local helper **0x4c0bc4** (the tree frame helper, reused across worldChanged/checkdead/kill family).\n'),
    ),
    dict(
        name='tr_compost',
        method='Tree -[isGrowingInCompost]',
        types='c8@0:4',
        start=4988804,
        end=4989020,
        disasm='disasm_worldtileloader_tr_compost.txt',
        base_add=4988820,
        base_literal=4989016,
        boundary='ARM.exidx end 0x004c205c (listing bound); next ObjC IMP 0x004c205c Tree -[fruitItemType]',
        selectors={},
        imports={},
        ivars={
                 0x4c2050: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c2054: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(4988804, 'push {fp, lr}'), (4989016, 'adcseq sp, sb, r8, asr fp')],
        calls=[(4988900, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(4988920, 'beq', 4988988), (4988936, 'beq', 4988972), (4988952, 'beq', 4988972), (4988968, 'bne', 4988984), (4988980, 'b', 4988996), (4988984, 'b', 4988988)],
        semantics=('[Tree isGrowingInCompost] (imp 0x004c1f84, 54w): the compost predicate (helper + chain).\n'),
    ),
    dict(
        name='tr_fruititem',
        method='Tree -[fruitItemType]',
        types='i8@0:4',
        start=4989020,
        end=4989076,
        disasm='disasm_worldtileloader_tr_fruititem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c2094 (listing bound); next ObjC IMP 0x004c2078 Tree -[shouldAddFallenFruits]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(4989020, 'sub sp, sp, 8'), (4989072, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree fruitItemType] (imp 0x004c205c, 7w): the base fruit-item accessor (subclass override).\n'),
    ),
    dict(
        name='tr_shouldfall',
        method='Tree -[shouldAddFallenFruits]',
        types='c8@0:4',
        start=4989048,
        end=4989076,
        disasm='disasm_worldtileloader_tr_shouldfall.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c2094 (listing bound); next ObjC IMP 0x004c2094 Tree -[fruitShouldFallInSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(4989048, 'sub sp, sp, 8'), (4989072, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree shouldAddFallenFruits] (imp 0x004c2078, 7w): the base predicate (subclass override).\n'),
    ),
    dict(
        name='tr_fruitseason',
        method='Tree -[fruitShouldFallInSeason:]',
        types='c12@0:4i8',
        start=4989076,
        end=4989108,
        disasm='disasm_worldtileloader_tr_fruitseason.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c20b4 (listing bound); next ObjC IMP 0x004c20b4 Tree -[addFallenFruits]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(4989076, 'sub sp, sp, 0xc'), (4989104, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree fruitShouldFallInSeason:] (imp 0x004c2094, 8w): the base season gate.\n'),
    ),
    dict(
        name='tr_fallenfruits',
        method='Tree -[addFallenFruits]',
        types='v8@0:4',
        start=4989108,
        end=4990312,
        disasm='disasm_worldtileloader_tr_fallenfruits.txt',
        base_add=4989124,
        base_literal=4990308,
        boundary='ARM.exidx end 0x004c2568 (listing bound); next ObjC IMP 0x004c2568 Tree -[growInTimeSinceSaved:]',
        selectors={
                 0x4c2524: (15192648, 'worldTime'),
                 0x4c2534: (15192652, 'tileIsKindOfSelf:'),
                 0x4c2540: (15192656, 'fruitShouldFallInSeason:'),
                 0x4c2554: (15192660, 'fruitItemType'),
                 0x4c2558: (15192664, 'maxHeightGeneVariation'),
                 0x4c255c: (15192668, 'growthRateGeneVariation'),
                 0x4c2560: (15192672, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x4c2520: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c251c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c2528: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c252c: (17155056, 'OBJC_IVAR_$_Tree.fruitCount', 128),
                 0x4c2530: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x4c2538: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x4c2548: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x4c254c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(4989108, 'push {r4, sl, fp, lr}'), (4990308, 'adcseq sp, sb, r8, lsr 20')],
        calls=[(4989224, 'blx ip'), (4989276, 'bl sym.seasonForWorldX_int__double__World_'), (4989440, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4989512, 'blx r3'), (4989712, 'bl sym.imp.__modsi3'), (4989740, 'blx r3'), (4989844, 'bl sym.makeIntpair_int__int_'), (4989896, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (4989924, 'bl sym.tileIsSolid_Tile_'), (4990000, 'bl sym.makeIntpair_int__int_'), (4990020, 'bl loc.imp.objc_msgSend'), (4990052, 'bl loc.imp.objc_msgSend'), (4990084, 'bl loc.imp.objc_msgSend'), (4990168, 'bl loc.imp.objc_msgSend')],
        branches=[(4989336, 'bge', 4990228), (4989460, 'beq', 4990208), (4989524, 'beq', 4990204), (4989588, 'bne', 4990204), (4989592, 'b', 4989596), (4989752, 'beq', 4990200), (4989788, 'blt', 4990200), (4989808, 'bge', 4990196), (4989916, 'beq', 4990176), (4989936, 'beq', 4990176), (4990172, 'b', 4990196), (4990176, 'b', 4990180), (4990192, 'b', 4989800), (4990196, 'b', 4990200), (4990200, 'b', 4990204), (4990204, 'b', 4990208), (4990208, 'b', 4990212), (4990224, 'b', 4989300)],
        semantics=("[Tree addFallenFruits] (imp 0x004c20b4, 301w): the fallen-fruit spawner - objc x4 + `tileAtWorldPositionLoaded` x2 + `makeIntpair` x2 + **`seasonForWorldX(int, double, World*)`** + `__modsi3` + `tileIsSolid`: each fruit's drop is season-gated, random-modded and solid-checked.\n"),
    ),
    dict(
        name='tr_ctorsave',
        method='Tree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        types='@32@0:4@8@12@16@20@24@28',
        start=4995488,
        end=4996072,
        disasm='disasm_worldtileloader_tr_ctorsave.txt',
        base_add=4995504,
        base_literal=4996068,
        boundary='ARM.exidx end 0x004c3be8 (listing bound); next ObjC IMP 0x004c3be8 Tree -[dealloc]',
        selectors={
                 0x4c3bb8: (15192720, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0x4c3bc4: (15192728, 'growInTimeSinceSaved:'),
                 0x4c3bc8: (15192708, 'doubleValue'),
                 0x4c3bd0: (15192696, 'objectForKey:'),
                 0x4c3bd4: (15192724, 'loadSaveDictValues:'),
        },
        imports={
                 0x4c3bb4: (17151900, 'objc_msgSendSuper2'),
                 0x4c3bc0: (17151904, 'objc_msgSend'),
                 0x4c3bcc: (16201240, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x4c3bd8: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
                 0x4c3bdc: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x4c3be0: (17155032, 'OBJC_IVAR_$_Tree.treeDensityNoiseFunction', 76),
        },
        classes={
                 0x4c3bbc: (15252528, 'OBJC_CLASS_$_Tree'),
        },
        instructions=[(4995488, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (4996068, 'adcseq ip, sb, ip, lsr r1')],
        calls=[(4995652, 'blx r8'), (4995764, 'bl sym.imp.__wrap_calloc'), (4995908, 'blx r8'), (4995948, 'blx r3'), (4995964, 'blx r2'), (4995996, 'blx ip')],
        branches=[(4995680, 'bne', 4995696), (4995692, 'b', 4996008)],
        semantics=('[Tree initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:] (imp 0x004c39a0, 146w): the save-dict ctor - super2 + the decode chain.\n'),
    ),
    dict(
        name='tr_dealloc',
        method='Tree -[dealloc]',
        types='v8@0:4',
        start=4996072,
        end=4996268,
        disasm='disasm_worldtileloader_tr_dealloc.txt',
        base_add=4996088,
        base_literal=4996264,
        boundary='ARM.exidx end 0x004c3cac (listing bound); next ObjC IMP 0x004c3cac Tree -[getSaveDict]',
        selectors={
                 0x4c3ca0: (15192732, 'dealloc'),
        },
        imports={
                 0x4c3c9c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x4c3c98: (17155036, 'OBJC_IVAR_$_Tree.treeFruits', 124),
        },
        classes={
                 0x4c3ca4: (15252528, 'OBJC_CLASS_$_Tree'),
        },
        instructions=[(4996072, 'push {fp, lr}'), (4996264, 'ldrshteq fp, [sb], r4')],
        calls=[(4996168, 'bl sym.imp.__wrap_free'), (4996236, 'blx r3')],
        branches=[(4996136, 'beq', 4996172)],
        semantics=('[Tree dealloc] (imp 0x004c3be8, 49w): the teardown + super.\n'),
    ),
    dict(
        name='tr_worldchanged',
        method='Tree -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=4999540,
        end=5003056,
        disasm='disasm_worldtileloader_tr_worldchanged.txt',
        base_add=4999556,
        base_literal=5003052,
        boundary='ARM.exidx end 0x004c5730 (listing bound); next ObjC IMP 0x004c576c Tree -[incrementHeight]',
        selectors={
                 0x4c56d4: (15192652, 'tileIsKindOfSelf:'),
                 0x4c56e0: (15192792, 'expertMode'),
                 0x4c56ec: (15192796, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
                 0x4c56f8: (15192772, 'isRequiredSoilType:'),
                 0x4c5700: (15192648, 'worldTime'),
                 0x4c5708: (15192776, 'killAllOwnedTiles'),
                 0x4c5710: (15192780, 'objectType'),
                 0x4c5714: (15192784, 'dynamicWorldChangedAtPos:objectType:'),
                 0x4c5718: (15192788, 'killAllOwnedTilesAboveY:'),
        },
        imports={
                 0x4c56d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c56c4: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x4c56c8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c56cc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c56d8: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x4c56f4: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x4c5704: (17155080, 'OBJC_IVAR_$_Tree.timeDied', 112),
                 0x4c570c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4c5720: (17155040, 'OBJC_IVAR_$_Tree.growthCounter', 68),
                 0x4c5728: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(4999540, 'push {r4, r5, r6, r7, fp, lr}'), (5003052, 'adcseq fp, sb, r8, ror 2')],
        calls=[(5000156, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5000232, 'blx r3'), (5000348, 'bl loc.imp.objc_msgSend'), (5000396, 'bl loc.imp.objc_msgSend'), (5000472, 'bl loc.imp.objc_msgSend'), (5000508, 'bl loc.imp.objc_msgSend'), (5000672, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5000744, 'blx r3'), (5000872, 'bl loc.imp.objc_msgSend'), (5000976, 'bl loc.imp.objc_msgSend'), (5001012, 'bl loc.imp.objc_msgSend'), (5001100, 'blx r3'), (5001288, 'bl loc.imp.objc_msgSend'), (5001324, 'bl loc.imp.objc_msgSend'), (5001352, 'blx r3'), (5001424, 'bl 0x4c5730'), (5001512, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5001584, 'blx r3'), (5001768, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5001924, 'blx r3'), (5002048, 'blx r3'), (5002072, 'bl 0x4c0bc4'), (5002220, 'blx r5'), (5002376, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5002532, 'blx r3'), (5002656, 'blx r3'), (5002680, 'bl 0x4c0bc4'), (5002828, 'blx r5')],
        branches=[(4999812, 'beq', 5002940), (4999912, 'bgt', 5002876), (4999956, 'blt', 5002876), (4999996, 'bne', 5001388), (5000032, 'bne', 5000524), (5000076, 'bne', 5000524), (5000176, 'beq', 5000520), (5000244, 'bne', 5000516), (5000280, 'bne', 5000512), (5000512, 'b', 5000516), (5000516, 'b', 5000520), (5000520, 'b', 5000524), (5000572, 'bge', 5001384), (5000692, 'beq', 5001364), (5000756, 'bne', 5001360), (5000768, 'bne', 5001132), (5000804, 'bne', 5001016), (5001128, 'b', 5001384), (5001356, 'b', 5001384), (5001360, 'b', 5001364), (5001364, 'b', 5001368), (5001380, 'b', 5000536), (5001384, 'b', 5002872), (5001460, 'bge', 5002868), (5001532, 'beq', 5002864), (5001596, 'bne', 5002864), (5001636, 'ble', 5002248), (5001716, 'bge', 5002244), (5001788, 'beq', 5002224), (5001852, 'bne', 5002224), (5001856, 'b', 5001860), (5001872, 'bne', 5002224), (5001936, 'beq', 5002224), (5002068, 'bne', 5002116), (5002224, 'b', 5002228), (5002240, 'b', 5001652), (5002244, 'b', 5002860), (5002324, 'ble', 5002856), (5002396, 'beq', 5002832), (5002460, 'bne', 5002832), (5002464, 'b', 5002468), (5002480, 'bne', 5002832), (5002544, 'beq', 5002832), (5002676, 'bne', 5002724), (5002832, 'b', 5002836), (5002852, 'b', 5002260), (5002856, 'b', 5002860), (5002860, 'b', 5002864), (5002864, 'b', 5002868), (5002868, 'b', 5002872), (5002872, 'b', 5002876), (5002876, 'b', 5002880), (5002936, 'b', 4999660)],
        semantics=('[Tree worldChanged:] (imp 0x004c4974, 879w): the support re-check - objc x9 + `tileAtWorldPositionLoaded` x5 + the shared helper **0x4c0bc4** x2 + the incrementHeight-family helper 0x4c5730: the tree validates its trunk/stalk and re-derives height.\n'),
    ),
    dict(
        name='tr_incheight',
        method='Tree -[incrementHeight]',
        types='v8@0:4',
        start=5003116,
        end=5003184,
        disasm='disasm_worldtileloader_tr_incheight.txt',
        base_add=5003124,
        base_literal=5003180,
        boundary='ARM.exidx end 0x004c57b0 (listing bound); next ObjC IMP 0x004c57b0 Tree -[update:accurateDT:isSimulation:]',
        selectors={},
        imports={},
        ivars={
                 0x4c57a8: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={},
        instructions=[(5003116, 'sub sp, sp, 8'), (5003180, 'adcseq sl, sb, r8, ror r3')],
        calls=[],
        branches=[],
        semantics=('[Tree incrementHeight] (imp 0x004c576c, 17w): the height increment (thin, the slot write + clamp).\n'),
    ),
    dict(
        name='tr_update',
        method='Tree -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=5003184,
        end=5007512,
        disasm='disasm_worldtileloader_tr_update.txt',
        base_add=5003200,
        base_literal=5007164,
        boundary='ARM.exidx end 0x004c6898 (listing bound); next ObjC IMP 0x004c6898 Tree -[updateGrowth:]',
        selectors={
                 0x4c682c: (15192780, 'objectType'),
                 0x4c6830: (15192784, 'dynamicWorldChangedAtPos:objectType:'),
                 0x4c6838: (15192688, 'isGrowingInCompost'),
                 0x4c683c: (15192676, 'isStaticTree'),
                 0x4c6848: (15192800, 'timeOfDayFraction'),
                 0x4c6860: (15192680, 'incrementHeight'),
                 0x4c6864: (15192684, 'updateGrowth:'),
                 0x4c686c: (15192692, 'sowTreeNearParent:adult:adultMaxAge:'),
                 0x4c6878: (15192648, 'worldTime'),
                 0x4c6880: (15192776, 'killAllOwnedTiles'),
                 0x4c6890: (15192804, 'checkIfDeadTilesNeedRemoved'),
                 0x4c6894: (15192628, 'removeAllOwnedTiles:'),
        },
        imports={
                 0x4c6834: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c6740: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x4c6804: (17155100, 'OBJC_IVAR_$_Tree.ageCounter', 100),
                 0x4c6810: (17155068, 'OBJC_IVAR_$_Tree.dead', 104),
                 0x4c6814: (17155100, 'OBJC_IVAR_$_Tree.ageCounter', 100),
                 0x4c6818: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0x4c681c: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0x4c6824: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4c6828: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c6840: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c6844: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x4c684c: (17155040, 'OBJC_IVAR_$_Tree.growthCounter', 68),
                 0x4c6850: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0x4c6854: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0x4c6858: (17155104, 'OBJC_IVAR_$_Tree.noLightDieTimer', 132),
                 0x4c685c: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
                 0x4c687c: (17155080, 'OBJC_IVAR_$_Tree.timeDied', 112),
                 0x4c6888: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x4c688c: (17155092, 'OBJC_IVAR_$_Tree.removeCheckCount', 120),
        },
        classes={},
        instructions=[(5003184, 'push {r4, r5, r6, sl, fp, lr}'), (5007464, 'muleq r1, pc, r6'), (5007508, 'invalid')],
        calls=[(5003536, 'bl loc.imp.objc_msgSend'), (5003572, 'bl loc.imp.objc_msgSend'), (5003668, 'blx r2'), (5003780, 'blx r2'), (5003896, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5004024, 'blx r2'), (5004176, 'bl sym.imp.__aeabi_idiv'), (5004200, 'bl sym.imp.__aeabi_idiv'), (5004232, 'bl sym.imp.__aeabi_idiv'), (5004248, 'bl sym.imp.__aeabi_idiv'), (5004352, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5004464, 'blx r2'), (5004612, 'bl sym.imp.__aeabi_idiv'), (5004636, 'bl sym.imp.__aeabi_idiv'), (5004668, 'bl sym.imp.__aeabi_idiv'), (5004684, 'bl sym.imp.__aeabi_idiv'), (5004928, 'blx r2'), (5005320, 'bl loc.imp.objc_msgSend'), (5005368, 'bl loc.imp.objc_msgSend'), (5005444, 'bl loc.imp.objc_msgSend'), (5005480, 'bl loc.imp.objc_msgSend'), (5005840, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5006052, 'blx r3'), (5006248, 'blx lr'), (5006340, 'blx r2'), (5006464, 'blx lr'), (5006548, 'bl loc.imp.objc_msgSend'), (5006584, 'bl loc.imp.objc_msgSend'), (5006632, 'blx r2'), (5006712, 'bl loc.imp.objc_msgSend'), (5006760, 'bl loc.imp.objc_msgSend'), (5006836, 'bl loc.imp.objc_msgSend'), (5006872, 'bl loc.imp.objc_msgSend'), (5007016, 'blx r3'), (5007156, 'blx ip'), (5007336, 'blx r2')],
        branches=[(5003268, 'bne', 5006896), (5003356, 'blt', 5003740), (5003624, 'ble', 5003736), (5003680, 'beq', 5003736), (5003736, 'b', 5003740), (5003792, 'bne', 5006892), (5003932, 'beq', 5004276), (5004064, 'bpl', 5004084), (5004076, 'b', 5004096), (5004372, 'beq', 5004816), (5004504, 'bpl', 5004520), (5004516, 'b', 5004532), (5004744, 'bpl', 5004792), (5004756, 'b', 5004800), (5004884, 'ble', 5004956), (5005060, 'bne', 5005088), (5005072, 'bne', 5005088), (5005084, 'beq', 5005488), (5005104, 'bne', 5005128), (5005148, 'beq', 5005244), (5005228, 'ble', 5005240), (5005240, 'b', 5005244), (5005252, 'beq', 5005484), (5005484, 'b', 5006888), (5005756, 'blt', 5006884), (5005860, 'beq', 5005888), (5005876, 'bne', 5005888), (5005944, 'bge', 5006592), (5005956, 'bne', 5006592), (5006116, 'bge', 5006140), (5006128, 'b', 5006148), (5006296, 'bne', 5006468), (5006352, 'bne', 5006468), (5006588, 'b', 5006880), (5006644, 'bne', 5006876), (5006876, 'b', 5006880), (5006880, 'b', 5006884), (5006884, 'b', 5006888), (5006888, 'b', 5006892), (5006892, 'b', 5007352), (5006928, 'bne', 5007348), (5007068, 'ble', 5007172), (5007160, 'b', 5007344), (5007248, 'ble', 5007340), (5007340, 'b', 5007344), (5007344, 'b', 5007348), (5007348, 'b', 5007352)],
        semantics=('[Tree update:accurateDT:isSimulation:] (imp 0x004c57b0, 1082w): the per-tick - objc x12 + **`__aeabi_idiv` x8** (the intensive fraction math: age/height/time ratios) + `tileAtWorldPositionLoaded` x3; 1 unclassified pool word = the **0x1869f (99999) sentinel** (@0x4c6868).\n'),
    ),
    dict(
        name='tr_growth',
        method='Tree -[updateGrowth:]',
        types='v12@0:4c8',
        start=5007512,
        end=5007592,
        disasm='disasm_worldtileloader_tr_growth.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c68e8 (listing bound); next ObjC IMP 0x004c68b0 Tree -[tileIsKindOfSelf:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5007512, 'sub sp, sp, 0xc'), (5007588, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree updateGrowth:] (imp 0x004c6898, 20w): the base growth hook (subclasses override; the base is near-empty).\n'),
    ),
    dict(
        name='tr_kindself',
        method='Tree -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=5007536,
        end=5007592,
        disasm='disasm_worldtileloader_tr_kindself.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c68e8 (listing bound); next ObjC IMP 0x004c68d0 Tree -[makeTileDead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5007536, 'sub sp, sp, 0xc'), (5007588, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree tileIsKindOfSelf:] (imp 0x004c68b0, 14w): the base membership (thin dispatch).\n'),
    ),
    dict(
        name='tr_makedead',
        method='Tree -[makeTileDead:]',
        types='v12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=5007568,
        end=5007592,
        disasm='disasm_worldtileloader_tr_makedead.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c68e8 (listing bound); next ObjC IMP 0x004c68e8 Tree -[killAllOwnedTiles]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5007568, 'sub sp, sp, 0xc'), (5007588, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree makeTileDead:] (imp 0x004c68d0, 6w): the base dead-marker hook (empty; subclasses implement).\n'),
    ),
    dict(
        name='tr_killtiles',
        method='Tree -[killAllOwnedTiles]',
        types='v8@0:4',
        start=5007592,
        end=5008208,
        disasm='disasm_worldtileloader_tr_killtiles.txt',
        base_add=5007608,
        base_literal=5008204,
        boundary='ARM.exidx end 0x004c6b50 (listing bound); next ObjC IMP 0x004c6b50 Tree -[checkIfDeadTilesNeedRemoved]',
        selectors={
                 0x4c6b3c: (15192808, 'makeTileDead:'),
                 0x4c6b48: (15192812, 'worldContentsChangedAtPos:'),
        },
        imports={},
        ivars={
                 0x4c6b28: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c6b2c: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
                 0x4c6b30: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c6b34: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x4c6b44: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(5007592, 'push {fp, lr}'), (5008204, 'ldrshteq sb, [sb], r4')],
        calls=[(5007904, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5008040, 'bl loc.imp.objc_msgSend'), (5008088, 'bl sym.makeIntpair_int__int_'), (5008116, 'bl loc.imp.objc_msgSend')],
        branches=[(5007716, 'bge', 5008160), (5007852, 'bge', 5008140), (5007924, 'beq', 5008120), (5007988, 'bne', 5008120), (5007992, 'b', 5007996), (5008008, 'bne', 5008120), (5008120, 'b', 5008124), (5008136, 'b', 5007784), (5008140, 'b', 5008144), (5008156, 'b', 5007652)],
        semantics=("[Tree killAllOwnedTiles] (imp 0x004c68e8, 154w): the owned-tiles sweep - objc x2 + `tileAtWorldPositionLoaded` + `makeIntpair` + the shared helper **0x4c0bc4**: walks the tree's owned tiles and kills them.\n"),
    ),
    dict(
        name='tr_checkdead',
        method='Tree -[checkIfDeadTilesNeedRemoved]',
        types='v8@0:4',
        start=5008208,
        end=5009416,
        disasm='disasm_worldtileloader_tr_checkdead.txt',
        base_add=5008224,
        base_literal=5009412,
        boundary='ARM.exidx end 0x004c7008 (listing bound); next ObjC IMP 0x004c7008 Tree -[killAllOwnedTilesAboveY:]',
        selectors={
                 0x4c6fd8: (15192648, 'worldTime'),
                 0x4c6ff4: (15192792, 'expertMode'),
                 0x4c7000: (15192796, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
        },
        imports={
                 0x4c6fd4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c6fc8: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
                 0x4c6fcc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c6fd0: (17155080, 'OBJC_IVAR_$_Tree.timeDied', 112),
                 0x4c6fdc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c6fe0: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={},
        instructions=[(5008208, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5008476, 'vcvt.s32.f64 s4, d0'), (5009412, 'adcseq r8, sb, ip, lsl 31')],
        calls=[(5008352, 'blx r6'), (5008764, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5008956, 'bl sym.tileIsTreeTrunk_Tile_'), (5009116, 'blx r3'), (5009140, 'bl 0x4c0bc4'), (5009280, 'blx r5')],
        branches=[(5008500, 'b', 5008512), (5008576, 'bge', 5009328), (5008712, 'bge', 5009308), (5008784, 'beq', 5009288), (5008848, 'bne', 5009288), (5008852, 'b', 5008856), (5008868, 'bne', 5009288), (5009004, 'ble', 5009284), (5009136, 'bne', 5009184), (5009284, 'b', 5009288), (5009288, 'b', 5009292), (5009304, 'b', 5008644), (5009308, 'b', 5009312), (5009324, 'b', 5008512)],
        semantics=('[Tree checkIfDeadTilesNeedRemoved] (imp 0x004c6b50, 302w): the dead-tile reaper - the **f64 age-fraction math**: `vmov.f64 d0, 1` + the pool constant (vldr d1) + `movw ip, 0x3c` (60!) + `vdiv.f64; vsub.f64; vmul.f64; vadd.f64; vcvt.s32.f64` (@0x4c6c44-0x4c6c5c) over the ffffc91c/c914/c89c/c8a0 cells + `tileIsTreeTrunk(Tile*)` + the helper 0x4c0bc4: the removal fraction = (1 - elapsed/60) family.\n'),
    ),
    dict(
        name='tr_killabove',
        method='Tree -[killAllOwnedTilesAboveY:]',
        types='v12@0:4i8',
        start=5009416,
        end=5010260,
        disasm='disasm_worldtileloader_tr_killabove.txt',
        base_add=5009432,
        base_literal=5010256,
        boundary='ARM.exidx end 0x004c7354 (listing bound); next ObjC IMP 0x004c7354 Tree -[removeAllOwnedTiles:]',
        selectors={
                 0x4c733c: (15192652, 'tileIsKindOfSelf:'),
                 0x4c7340: (15192792, 'expertMode'),
                 0x4c734c: (15192796, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
        },
        imports={
                 0x4c7338: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c7324: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
                 0x4c7328: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c732c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c7330: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={},
        instructions=[(5009416, 'push {r4, r5, fp, lr}'), (5010256, 'ldrsbteq r8, [sb], r4')],
        calls=[(5009716, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5009872, 'blx r3'), (5009996, 'blx r3'), (5010020, 'bl 0x4c0bc4'), (5010160, 'blx r5')],
        branches=[(5009528, 'bge', 5010204), (5009664, 'bge', 5010184), (5009736, 'beq', 5010164), (5009800, 'bne', 5010164), (5009804, 'b', 5009808), (5009820, 'bne', 5010164), (5009884, 'beq', 5010164), (5010016, 'bne', 5010064), (5010164, 'b', 5010168), (5010180, 'b', 5009596), (5010184, 'b', 5010188), (5010200, 'b', 5009464)],
        semantics=('[Tree killAllOwnedTilesAboveY:] (imp 0x004c7008, 211w): the above-Y sweep (the same helper 0x4c0bc4 + tileAtWorldPositionLoaded family, bounded by the Y argument).\n'),
    ),
    dict(
        name='tr_removeall',
        method='Tree -[removeAllOwnedTiles:]',
        types='v12@0:4c8',
        start=5010260,
        end=5011160,
        disasm='disasm_worldtileloader_tr_removeall.txt',
        base_add=5010276,
        base_literal=5011156,
        boundary='ARM.exidx end 0x004c76d8 (listing bound); next ObjC IMP 0x004c76d8 Tree -[updateAllOwnedTilesToNewIDSize]',
        selectors={
                 0x4c76c0: (15192652, 'tileIsKindOfSelf:'),
                 0x4c76c4: (15192792, 'expertMode'),
                 0x4c76d0: (15192796, 'removeTileAtWorldX:worldY:createContentsFreeblockCount:createForegroundContentsFreeblockCount:removeBlockhead:'),
        },
        imports={
                 0x4c76bc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4c76a8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c76ac: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
                 0x4c76b0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c76b4: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={},
        instructions=[(5010260, 'push {r4, r5, fp, lr}'), (5011156, 'adcseq r8, sb, r8, lsl 15')],
        calls=[(5010576, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5010732, 'blx r3'), (5010888, 'blx r3'), (5010912, 'bl 0x4c0bc4'), (5011060, 'blx r5')],
        branches=[(5010388, 'bge', 5011104), (5010524, 'bge', 5011084), (5010596, 'beq', 5011064), (5010660, 'bne', 5011064), (5010664, 'b', 5010668), (5010680, 'bne', 5011064), (5010744, 'beq', 5011064), (5010812, 'beq', 5010956), (5010908, 'bne', 5010956), (5011064, 'b', 5011068), (5011080, 'b', 5010456), (5011084, 'b', 5011088), (5011100, 'b', 5010324)],
        semantics=('[Tree removeAllOwnedTiles:] (imp 0x004c7354, 225w): the remove-all sweep (helper 0x4c0bc4 + the position walk; the argument gates).\n'),
    ),
    dict(
        name='tr_updateidsize',
        method='Tree -[updateAllOwnedTilesToNewIDSize]',
        types='v8@0:4',
        start=5011160,
        end=5011676,
        disasm='disasm_worldtileloader_tr_updateidsize.txt',
        base_add=5011176,
        base_literal=5011672,
        boundary='ARM.exidx end 0x004c78dc (listing bound); next ObjC IMP 0x004c78dc Tree -[isRequiredSoilType:]',
        selectors={},
        imports={},
        ivars={
                 0x4c78c0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4c78c4: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
                 0x4c78c8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4c78cc: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={},
        instructions=[(5011160, 'push {fp, lr}'), (5011672, 'adcseq r8, sb, r4, lsl 8')],
        calls=[(5011472, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(5011284, 'bge', 5011640), (5011420, 'bge', 5011620), (5011492, 'beq', 5011600), (5011548, 'bne', 5011600), (5011552, 'b', 5011556), (5011600, 'b', 5011604), (5011616, 'b', 5011352), (5011620, 'b', 5011624), (5011636, 'b', 5011220)],
        semantics=('[Tree updateAllOwnedTilesToNewIDSize] (imp 0x004c76d8, 129w): the ID-size migration - `tileAtWorldPositionLoaded` + the tile-byte rewrite per owned tile (the ID size change path).\n'),
    ),
    dict(
        name='tr_soiltype',
        method='Tree -[isRequiredSoilType:]',
        types='c12@0:4i8',
        start=5011676,
        end=5011832,
        disasm='disasm_worldtileloader_tr_soiltype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c7978 (listing bound); next ObjC IMP 0x004c7978 Tree -[treeType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5011676, 'sub sp, sp, 0x10'), (5011828, 'bx lr')],
        calls=[],
        branches=[(5011708, 'beq', 5011812), (5011728, 'beq', 5011812), (5011748, 'beq', 5011812), (5011768, 'beq', 5011812), (5011788, 'beq', 5011812)],
        semantics=('[Tree isRequiredSoilType:] (imp 0x004c78dc, 39w): the base soil membership - cmp against **{0x1b, 0x1c, 0x30, 0x31, 0x32}** (@the compares: the same set as the Plant base - tree soils + the dead-tree markers).\n'),
    ),
    dict(
        name='tr_treetype',
        method='Tree -[treeType]',
        types='i8@0:4',
        start=5011832,
        end=5011860,
        disasm='disasm_worldtileloader_tr_treetype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c7994 (listing bound); next ObjC IMP 0x004c7994 Tree -[maxHeightGeneVariation]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5011832, 'sub sp, sp, 8'), (5011856, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree treeType] (imp 0x004c7978, 7w): the base tree-type (subclass override).\n'),
    ),
    dict(
        name='tr_maxheightgene',
        method='Tree -[maxHeightGeneVariation]',
        types='S8@0:4',
        start=5011860,
        end=5012212,
        disasm='disasm_worldtileloader_tr_maxheightgene.txt',
        base_add=5011876,
        base_literal=5012032,
        boundary='ARM.exidx end 0x004c7af4 (listing bound); next ObjC IMP 0x004c7a44 Tree -[growthRateGeneVariation]',
        selectors={},
        imports={},
        ivars={
                 0x4c7a3c: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0x4c7aec: (17155044, 'OBJC_IVAR_$_Tree.growthRateGene', 56),
        },
        classes={},
        instructions=[(5011860, 'push {fp, lr}'), (5012208, 'umlalseq r8, sb, r8, r0')],
        calls=[(5011916, 'bl 0x4c0bc4'), (5012000, 'bl sym.clampi_int__int__int_'), (5012092, 'bl 0x4c0bc4'), (5012176, 'bl sym.clampi_int__int__int_')],
        branches=[],
        semantics=("[Tree maxHeightGeneVariation] (imp 0x004c7994, 88w): the gene variation - the helper + clamp family (cf. the Plant's 0xff clampi).\n"),
    ),
    dict(
        name='tr_growthgene',
        method='Tree -[growthRateGeneVariation]',
        types='S8@0:4',
        start=5012036,
        end=5012212,
        disasm='disasm_worldtileloader_tr_growthgene.txt',
        base_add=5012052,
        base_literal=5012208,
        boundary='ARM.exidx end 0x004c7af4 (listing bound); next ObjC IMP 0x004c7af4 Tree -[height]',
        selectors={},
        imports={},
        ivars={
                 0x4c7aec: (17155044, 'OBJC_IVAR_$_Tree.growthRateGene', 56),
        },
        classes={},
        instructions=[(5012036, 'push {fp, lr}'), (5012208, 'umlalseq r8, sb, r8, r0')],
        calls=[(5012092, 'bl 0x4c0bc4'), (5012176, 'bl sym.clampi_int__int__int_')],
        branches=[],
        semantics=('[Tree growthRateGeneVariation] (imp 0x004c7a44, 44w): the mirror.\n'),
    ),
    dict(
        name='tr_height',
        method='Tree -[height]',
        types='i8@0:4',
        start=5012212,
        end=5012328,
        disasm='disasm_worldtileloader_tr_height.txt',
        base_add=5012220,
        base_literal=5012268,
        boundary='ARM.exidx end 0x004c7b68 (listing bound); next ObjC IMP 0x004c7b30 Tree -[isStaticTree]',
        selectors={},
        imports={},
        ivars={
                 0x4c7b28: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
        },
        classes={},
        instructions=[(5012212, 'sub sp, sp, 8'), (5012324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree height] (imp 0x004c7af4, 29w): the height accessor (the slot read).\n'),
    ),
    dict(
        name='tr_isstatic',
        method='Tree -[isStaticTree]',
        types='c8@0:4',
        start=5012272,
        end=5012328,
        disasm='disasm_worldtileloader_tr_isstatic.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c7b68 (listing bound); next ObjC IMP 0x004c7b4c Tree -[occupiesNormalContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5012272, 'sub sp, sp, 8'), (5012324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree isStaticTree] (imp 0x004c7b30, 14w): returns **0** - the base Tree is not a static tree.\n'),
    ),
    dict(
        name='tr_occupiesnormal',
        method='Tree -[occupiesNormalContents]',
        types='c8@0:4',
        start=5012300,
        end=5012328,
        disasm='disasm_worldtileloader_tr_occupiesnormal.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004c7b68 (listing bound); next ObjC IMP 0x004c7df4 CraftProgressUI -[loadResources]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5012300, 'sub sp, sp, 8'), (5012324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Tree occupiesNormalContents] (imp 0x004c7b4c, 7w): returns **1**.\n'),
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
        'batch': 'Tree base class (E89): the ctor, statics, the owned-tiles family and the f64 reaper; 28 bodies',
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
                        default=NATIVE / 'tree_base.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale tree_base.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
