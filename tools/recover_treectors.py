#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: the tree ctor family: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 6331 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TREE_CTORS.md for the prose and boundaries.
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
    'bl 0x7deb18': 0x007deb18,
    'bl 0x809c2c': 0x00809c2c,
    'bl 0x9bd3a0': 0x009bd3a0,
    'bl 0xa965f4': 0x00a965f4,
    'bl 0xa99938': 0x00a99938,
    'bl 0xb533ac': 0x00b533ac,
    'bl 0xb64f38': 0x00b64f38,
    'bl 0xd0df1c': 0x00d0df1c,
    'bl 0xd4b4e4': 0x00d4b4e4,
    'bl 0xdb5fa4': 0x00db5fa4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_': 0x004c0bd4,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='cf_ctor',
        method='CoffeeTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=8249792,
        end=8252184,
        disasm='disasm_worldtileloader_cf_ctor.txt',
        base_add=8249808,
        base_literal=8252180,
        boundary='ARM.exidx end 0x007deb18 (listing bound); next ObjC IMP 0x007deb28 CoffeeTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x7deac0: (15210720, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0x7deae8: (15210724, 'worldWidthMacro'),
                 0x7deaec: (15210728, 'getX:Y:octaves:'),
                 0x7deb0c: (15210732, 'incrementHeight'),
                 0x7deb10: (15210736, 'updateGrowth:'),
        },
        imports={
                 0x7deae4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7deac4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7deac8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7deacc: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0x7dead0: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0x7deadc: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x7deaf0: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x7deaf4: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x7deaf8: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0x7deafc: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0x7deb00: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0x7deb08: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0x7deab8: (15252824, 'OBJC_CLASS_$_CoffeeTree'),
        },
        instructions=[(8249792, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8252180, 'addeq r1, r8, ip, lsl sb')],
        calls=[(8250108, 'bl loc.imp.objc_msgSendSuper2'), (8250280, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8250436, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8250588, 'bl 0x7deb18'), (8250620, 'bl sym.imp.__modsi3'), (8250872, 'blx r2'), (8251000, 'blx lr'), (8251088, 'blx ip'), (8251120, 'bl sym.imp.__wrap_fmodf'), (8251596, 'blx r3'), (8251788, 'blx lr')],
        branches=[(8250136, 'bne', 8250152), (8250148, 'b', 8252068), (8250456, 'beq', 8250568), (8250472, 'beq', 8250508), (8250488, 'beq', 8250508), (8250504, 'bne', 8250564), (8250564, 'b', 8250568), (8250584, 'beq', 8250656), (8250636, 'bge', 8250648), (8250648, 'b', 8250672), (8251276, 'bge', 8251332), (8251340, 'beq', 8251808), (8251660, 'bge', 8251684), (8251672, 'b', 8251692), (8251804, 'b', 8251256), (8251852, 'bgt', 8252060), (8252056, 'b', 8251816)],
        semantics=("[CoffeeTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x007de1c0, 598w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**growthVigorForTreeTypeAtPos** call + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Helper 0x7deb18; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='lt_ctor',
        method='LimeTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=8426104,
        end=8428588,
        disasm='disasm_worldtileloader_lt_ctor.txt',
        base_add=8426120,
        base_literal=8428584,
        boundary='ARM.exidx end 0x00809c2c (listing bound); next ObjC IMP 0x00809c3c LimeTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x809bd8: (15211588, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0x809bec: (15211592, 'worldWidthMacro'),
                 0x809c00: (15211596, 'getX:Y:octaves:'),
                 0x809c20: (15211600, 'incrementHeight'),
                 0x809c24: (15211604, 'updateGrowth:'),
        },
        imports={
                 0x809bfc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x809bdc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x809be0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x809be4: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0x809bf0: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0x809bf8: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x809c04: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x809c08: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x809c0c: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0x809c10: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0x809c14: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0x809c1c: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0x809bd0: (15252836, 'OBJC_CLASS_$_LimeTree'),
        },
        instructions=[(8426104, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8428584, 'addeq r6, r5, r4, ror 16')],
        calls=[(8426420, 'bl loc.imp.objc_msgSendSuper2'), (8426564, 'bl loc.imp.objc_msgSend'), (8426592, 'bl sym.imp.__wrap_fmodf'), (8426724, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8426880, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8427032, 'bl 0x809c2c'), (8427064, 'bl sym.imp.__modsi3'), (8427372, 'blx r4'), (8427468, 'blx ip'), (8427556, 'blx lr'), (8428000, 'blx r3'), (8428192, 'blx lr')],
        branches=[(8426448, 'bne', 8426464), (8426460, 'b', 8428472), (8426900, 'beq', 8427012), (8426916, 'beq', 8426952), (8426932, 'beq', 8426952), (8426948, 'bne', 8427008), (8427008, 'b', 8427012), (8427028, 'beq', 8427104), (8427080, 'bge', 8427092), (8427092, 'b', 8427120), (8427680, 'bge', 8427736), (8427744, 'beq', 8428212), (8428064, 'bge', 8428088), (8428076, 'b', 8428096), (8428208, 'b', 8427660), (8428256, 'bgt', 8428464), (8428460, 'b', 8428220)],
        semantics=("[LimeTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00809278, 621w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**growthVigorForTreeTypeAtPos** call + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants a/0x3f00/0x7f/0x20 + helper 0x809c2c; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='at_ctor',
        method='AppleTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=10209904,
        end=10212256,
        disasm='disasm_worldtileloader_at_ctor.txt',
        base_add=10209920,
        base_literal=10212252,
        boundary='ARM.exidx end 0x009bd3a0 (listing bound); next ObjC IMP 0x009bd3b0 AppleTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x9bd340: (15221096, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0x9bd364: (15221104, 'getX:Y:octaves:'),
                 0x9bd36c: (15221100, 'worldWidthMacro'),
                 0x9bd394: (15221108, 'incrementHeight'),
                 0x9bd398: (15221112, 'updateGrowth:'),
        },
        imports={
                 0x9bd360: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9bd344: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9bd348: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9bd34c: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0x9bd350: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0x9bd35c: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0x9bd368: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0x9bd370: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0x9bd374: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0x9bd378: (17163660, 'OBJC_IVAR_$_AppleTree.availableFood', 136),
                 0x9bd384: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0x9bd388: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0x9bd390: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0x9bd338: (15252972, 'OBJC_CLASS_$_AppleTree'),
        },
        instructions=[(10209904, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10210220, 'bl loc.imp.objc_msgSendSuper2'), (10210392, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (10210548, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10210688, 'ldrsb r0, [fp, -0x49]'), (10210768, 'ldr r0, [0x009bd358]'), (10212252, 'rsbeq r3, sl, ip, rrx')],
        calls=[(10210220, 'bl loc.imp.objc_msgSendSuper2'), (10210392, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (10210548, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10210700, 'bl 0x9bd3a0'), (10210732, 'bl sym.imp.__modsi3'), (10210996, 'blx lr'), (10211084, 'blx ip'), (10211172, 'blx lr'), (10211580, 'blx r3'), (10211764, 'blx lr'), (10212044, 'bl 0x9bd3a0')],
        branches=[(10210248, 'bne', 10210264), (10210260, 'b', 10212132), (10210568, 'beq', 10210680), (10210584, 'beq', 10210620), (10210600, 'beq', 10210620), (10210616, 'bne', 10210676), (10210676, 'b', 10210680), (10210696, 'beq', 10210768), (10210748, 'bge', 10210760), (10210760, 'b', 10210784), (10211260, 'bge', 10211316), (10211324, 'beq', 10211792), (10211644, 'bge', 10211660), (10211656, 'b', 10211668), (10211780, 'b', 10211240), (10211836, 'bgt', 10212044), (10212040, 'b', 10211800)],
        semantics=("[AppleTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x009bca70, 588w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**`growthVigorForTreeTypeAtPos(TreeType, intpair, World*)`** call (@0x9bcc58) + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (loaded @0x9bcdd0); the final max-age fraction via the f64/f32 divides. The unclassified cell 0x1869f is the 99999 pool word (the max-age continuation sentinel).)"),
    ),
    dict(
        name='ot_ctor',
        method='OrangeTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=11099200,
        end=11101684,
        disasm='disasm_worldtileloader_ot_ctor.txt',
        base_add=11099216,
        base_literal=11101680,
        boundary='ARM.exidx end 0x00a965f4 (listing bound); next ObjC IMP 0x00a96604 OrangeTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xa965a0: (15226148, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xa965b4: (15226152, 'worldWidthMacro'),
                 0xa965c8: (15226156, 'getX:Y:octaves:'),
                 0xa965e8: (15226160, 'incrementHeight'),
                 0xa965ec: (15226164, 'updateGrowth:'),
        },
        imports={
                 0xa965c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa965a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa965a8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa965ac: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xa965b8: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xa965c0: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xa965cc: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xa965d0: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xa965d4: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xa965d8: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xa965dc: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xa965e4: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xa96598: (15253068, 'OBJC_CLASS_$_OrangeTree'),
        },
        instructions=[(11099200, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11101680, 'invalid')],
        calls=[(11099516, 'bl loc.imp.objc_msgSendSuper2'), (11099660, 'bl loc.imp.objc_msgSend'), (11099688, 'bl sym.imp.__wrap_fmodf'), (11099820, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (11099976, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11100128, 'bl 0xa965f4'), (11100160, 'bl sym.imp.__modsi3'), (11100468, 'blx r4'), (11100564, 'blx ip'), (11100652, 'blx lr'), (11101096, 'blx r3'), (11101288, 'blx lr')],
        branches=[(11099544, 'bne', 11099560), (11099556, 'b', 11101568), (11099996, 'beq', 11100108), (11100012, 'beq', 11100048), (11100028, 'beq', 11100048), (11100044, 'bne', 11100104), (11100104, 'b', 11100108), (11100124, 'beq', 11100200), (11100176, 'bge', 11100188), (11100188, 'b', 11100216), (11100776, 'bge', 11100832), (11100840, 'beq', 11101308), (11101160, 'bge', 11101184), (11101172, 'b', 11101192), (11101304, 'b', 11100756), (11101352, 'bgt', 11101560), (11101556, 'b', 11101316)],
        semantics=("[OrangeTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00a95c40, 621w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**growthVigorForTreeTypeAtPos** call + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants 0x3f00/0x7f/0x20 + helper 0xa965f4; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='cn_ctor',
        method='CoconutTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=11112608,
        end=11114808,
        disasm='disasm_worldtileloader_cn_ctor.txt',
        base_add=11112624,
        base_literal=11114804,
        boundary='ARM.exidx end 0x00a99938 (listing bound); next ObjC IMP 0x00a99948 CoconutTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xa998e8: (15226240, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xa99908: (15226248, 'getX:Y:octaves:'),
                 0xa99910: (15226244, 'worldWidthMacro'),
                 0xa9992c: (15226252, 'incrementHeight'),
                 0xa99930: (15226256, 'updateGrowth:'),
        },
        imports={
                 0xa99904: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa998ec: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa998f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa998f4: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xa998f8: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xa99900: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xa9990c: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xa99914: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xa99918: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xa9991c: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xa99920: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xa99928: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xa998e0: (15253072, 'OBJC_CLASS_$_CoconutTree'),
        },
        instructions=[(11112608, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11114804, 'subseq r6, ip, ip, lsr sl')],
        calls=[(11112924, 'bl loc.imp.objc_msgSendSuper2'), (11113164, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11113316, 'bl 0xa99938'), (11113348, 'bl sym.imp.__modsi3'), (11113632, 'blx lr'), (11113728, 'blx ip'), (11113816, 'blx lr'), (11114224, 'blx r3'), (11114412, 'blx lr')],
        branches=[(11112952, 'bne', 11112968), (11112964, 'b', 11114700), (11113184, 'beq', 11113296), (11113200, 'beq', 11113236), (11113216, 'beq', 11113236), (11113232, 'bne', 11113292), (11113292, 'b', 11113296), (11113312, 'beq', 11113384), (11113364, 'bge', 11113376), (11113376, 'b', 11113400), (11113904, 'bge', 11113960), (11113968, 'beq', 11114440), (11114288, 'bge', 11114308), (11114300, 'b', 11114316), (11114428, 'b', 11113884), (11114484, 'bgt', 11114692), (11114688, 'b', 11114448)],
        semantics=("[CoconutTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00a990a0, 550w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (its OWN growth path (no vigor call; helper 0xa99938) + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants 0xff/0x40; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='ct_ctor',
        method='CactusTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=11872336,
        end=11875244,
        disasm='disasm_worldtileloader_ct_ctor.txt',
        base_add=11872352,
        base_literal=11875240,
        boundary='ARM.exidx end 0x00b533ac (listing bound); next ObjC IMP 0x00b533bc CactusTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xb53340: (15231484, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xb53370: (15231492, 'getX:Y:octaves:'),
                 0xb53378: (15231488, 'worldWidthMacro'),
                 0xb533a0: (15231496, 'incrementHeight'),
                 0xb533a4: (15231500, 'updateGrowth:'),
        },
        imports={
                 0xb5336c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb53344: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb53348: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb5334c: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xb53354: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xb5335c: (17165904, 'OBJC_IVAR_$_CactusTree.splitHeightA', 136),
                 0xb53360: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb53364: (17165908, 'OBJC_IVAR_$_CactusTree.splitHeightB', 140),
                 0xb53368: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xb53374: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xb5337c: (17165912, 'OBJC_IVAR_$_CactusTree.splitDirection', 144),
                 0xb53384: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xb53388: (17165916, 'OBJC_IVAR_$_CactusTree.availableFood', 148),
                 0xb53390: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xb53394: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xb5339c: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xb53338: (15253160, 'OBJC_CLASS_$_CactusTree'),
        },
        instructions=[(11872336, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11875240, 'subseq sp, r0, ip, lsl 5')],
        calls=[(11872652, 'bl loc.imp.objc_msgSendSuper2'), (11872752, 'bl 0xb533ac'), (11872920, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11873072, 'bl 0xb533ac'), (11873104, 'bl sym.imp.__modsi3'), (11873196, 'bl 0xb533ac'), (11873252, 'bl sym.imp.__modsi3'), (11873360, 'bl 0xb533ac'), (11873416, 'bl sym.imp.__modsi3'), (11873676, 'bl 0xb533ac'), (11873964, 'blx r4'), (11874060, 'blx ip'), (11874148, 'blx lr'), (11874556, 'blx r3'), (11874744, 'blx lr'), (11875020, 'bl 0xb533ac')],
        branches=[(11872680, 'bne', 11872696), (11872692, 'b', 11875108), (11872940, 'beq', 11873052), (11872956, 'beq', 11872992), (11872972, 'beq', 11872992), (11872988, 'bne', 11873048), (11873048, 'b', 11873052), (11873068, 'beq', 11873148), (11873120, 'bge', 11873132), (11873132, 'b', 11873164), (11873324, 'ble', 11873360), (11873488, 'ble', 11873524), (11873580, 'ble', 11873676), (11874236, 'bge', 11874292), (11874300, 'beq', 11874768), (11874620, 'bge', 11874640), (11874632, 'b', 11874648), (11874760, 'b', 11874216), (11874812, 'bgt', 11875020), (11875016, 'b', 11874776)],
        semantics=("[CactusTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00b52850, 727w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (its OWN growth path (no vigor call; helper 0xb533ac; the **0x3fffffff pool word** = the half-max sentinel) + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants 0xff/0x63/0x20/0x384 (=900); soil set {0x30/31/32}.)"),
    ),
    dict(
        name='pt_ctor',
        method='PineTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=11944912,
        end=11947832,
        disasm='disasm_worldtileloader_pt_ctor.txt',
        base_add=11944928,
        base_literal=11947828,
        boundary='ARM.exidx end 0x00b64f38 (listing bound); next ObjC IMP 0x00b64f48 PineTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xb64ec8: (15232132, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xb64ee8: (15232140, 'getX:Y:octaves:'),
                 0xb64ef0: (15232136, 'worldWidthMacro'),
                 0xb64f0c: (15232152, 'npcExistsAtPos:ignoreNPC:'),
                 0xb64f10: (15232156, 'tutorialActive'),
                 0xb64f18: (15232160, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xb64f2c: (15232144, 'incrementHeight'),
                 0xb64f30: (15232148, 'updateGrowth:'),
        },
        imports={
                 0xb64ee4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb64ecc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb64ed0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb64ed4: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xb64ed8: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xb64ee0: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xb64eec: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xb64ef4: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xb64ef8: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xb64efc: (17166152, 'OBJC_IVAR_$_PineTree.availableFood', 136),
                 0xb64f04: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xb64f1c: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xb64f20: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xb64f28: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xb64ec0: (15253176, 'OBJC_CLASS_$_PineTree'),
        },
        instructions=[(11944912, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11947828, 'subeq fp, pc, ip, lsl 14')],
        calls=[(11945228, 'bl loc.imp.objc_msgSendSuper2'), (11945468, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11945620, 'bl 0xb64f38'), (11945652, 'bl sym.imp.__modsi3'), (11945936, 'blx lr'), (11946040, 'blx ip'), (11946132, 'blx lr'), (11946540, 'blx r3'), (11946728, 'blx lr'), (11947032, 'bl 0xb64f38'), (11947112, 'bl 0xb64f38'), (11947312, 'bl sym.makeIntpair_int__int_'), (11947364, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11947476, 'bl loc.imp.objc_msgSend'), (11947552, 'blx r2'), (11947664, 'bl loc.imp.objc_msgSend')],
        branches=[(11945256, 'bne', 11945272), (11945268, 'b', 11947688), (11945488, 'beq', 11945600), (11945504, 'beq', 11945540), (11945520, 'beq', 11945540), (11945536, 'bne', 11945596), (11945596, 'b', 11945600), (11945616, 'beq', 11945688), (11945668, 'bge', 11945680), (11945680, 'b', 11945704), (11946220, 'bge', 11946276), (11946284, 'beq', 11946776), (11946604, 'bge', 11946624), (11946616, 'b', 11946632), (11946744, 'b', 11946200), (11946820, 'bgt', 11947032), (11947024, 'b', 11946784), (11947108, 'blt', 11947680), (11947228, 'bpl', 11947680), (11947384, 'beq', 11947676), (11947400, 'bne', 11947676), (11947488, 'bne', 11947672), (11947564, 'bne', 11947672), (11947672, 'b', 11947676), (11947676, 'b', 11947680)],
        semantics=("[PineTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00b643d0, 730w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (its OWN growth path (no vigor call; helper 0xb64f38 + **makeIntpair**) + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants 0xff/0x7f; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='pt_ctorsave',
        method='PineTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        types='@32@0:4@8@12@16@20@24@28',
        start=11947848,
        end=11948476,
        disasm='disasm_worldtileloader_pt_ctorsave.txt',
        base_add=11947864,
        base_literal=11948472,
        boundary='ARM.exidx end 0x00b651bc (listing bound); next ObjC IMP 0x00b651bc PineTree -[getSaveDict]',
        selectors={
                 0xb65190: (15232164, 'initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:'),
                 0xb651a0: (15232176, 'worldTime'),
                 0xb651a8: (15232172, 'floatValue'),
                 0xb651b0: (15232168, 'objectForKey:'),
        },
        imports={
                 0xb6518c: (17151900, 'objc_msgSendSuper2'),
                 0xb6519c: (17151904, 'objc_msgSend'),
                 0xb651ac: (16375320, '__CFConstantStringClassReference'),
                 0xb651b4: (16375304, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xb65198: (17166152, 'OBJC_IVAR_$_PineTree.availableFood', 136),
                 0xb651a4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xb65194: (15253176, 'OBJC_CLASS_$_PineTree'),
        },
        instructions=[(11947848, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11948028, 'blx r8'), (11948052, 'cmp r1, r0'), (11948472, 'umaaleq sl, pc, r4, fp')],
        calls=[(11948028, 'blx r8'), (11948212, 'blx r8'), (11948228, 'blx r2'), (11948276, 'blx r3'), (11948292, 'blx r2'), (11948336, 'blx r3')],
        branches=[(11948056, 'bne', 11948072), (11948068, 'b', 11948416)],
        semantics=('[PineTree initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:] (imp 0x00b64f48, 157w): the save-dict ctor - super2 (@0xb64ffc) + nil gate (@0xb65014); the decode chain binds the pine save keys **fff3e324/e314** + the fffff454 cell + ffffbca8/bcac + ffe271b0/b4/b8/bc + ffffc89c/c8a0; the noise-function blocks ride the frame.\n'),
    ),
    dict(
        name='ch_ctor',
        method='CherryTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=13686384,
        end=13688604,
        disasm='disasm_worldtileloader_ch_ctor.txt',
        base_add=13686400,
        base_literal=13688600,
        boundary='ARM.exidx end 0x00d0df1c (listing bound); next ObjC IMP 0x00d0df2c CherryTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xd0dec8: (15238260, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xd0deec: (15238268, 'getX:Y:octaves:'),
                 0xd0def4: (15238264, 'worldWidthMacro'),
                 0xd0df10: (15238272, 'incrementHeight'),
                 0xd0df14: (15238276, 'updateGrowth:'),
        },
        imports={
                 0xd0dee8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd0decc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd0ded0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd0ded4: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xd0ded8: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xd0dee4: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xd0def0: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xd0def8: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd0defc: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xd0df00: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xd0df04: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xd0df0c: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xd0dec0: (15253256, 'OBJC_CLASS_$_CherryTree'),
        },
        instructions=[(13686384, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13688600, 'eorseq r2, r5, ip, ror 8')],
        calls=[(13686700, 'bl loc.imp.objc_msgSendSuper2'), (13686872, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (13687028, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13687180, 'bl 0xd0df1c'), (13687212, 'bl sym.imp.__modsi3'), (13687480, 'blx lr'), (13687608, 'blx lr'), (13688016, 'blx r3'), (13688200, 'blx lr')],
        branches=[(13686728, 'bne', 13686744), (13686740, 'b', 13688492), (13687048, 'beq', 13687160), (13687064, 'beq', 13687100), (13687080, 'beq', 13687100), (13687096, 'bne', 13687156), (13687156, 'b', 13687160), (13687176, 'beq', 13687248), (13687228, 'bge', 13687240), (13687240, 'b', 13687264), (13687696, 'bge', 13687752), (13687760, 'beq', 13688232), (13688080, 'bge', 13688096), (13688092, 'b', 13688104), (13688216, 'b', 13687676), (13688276, 'bgt', 13688484), (13688480, 'b', 13688240)],
        semantics=("[CherryTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00d0d670, 555w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**growthVigorForTreeTypeAtPos** call + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants 0x7f/0x20 + helper 0xd0df1c; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='mg_ctor',
        method='MangoTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=13937464,
        end=13939940,
        disasm='disasm_worldtileloader_mg_ctor.txt',
        base_add=13937480,
        base_literal=13939936,
        boundary='ARM.exidx end 0x00d4b4e4 (listing bound); next ObjC IMP 0x00d4b4f4 MangoTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xd4b490: (15239716, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xd4b4a4: (15239720, 'worldWidthMacro'),
                 0xd4b4b8: (15239724, 'getX:Y:octaves:'),
                 0xd4b4d8: (15239728, 'incrementHeight'),
                 0xd4b4dc: (15239732, 'updateGrowth:'),
        },
        imports={
                 0xd4b4b4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd4b494: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd4b498: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd4b49c: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xd4b4a8: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xd4b4b0: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xd4b4bc: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xd4b4c0: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xd4b4c4: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xd4b4c8: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xd4b4cc: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xd4b4d4: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xd4b488: (15253280, 'OBJC_CLASS_$_MangoTree'),
        },
        instructions=[(13937464, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13939936, 'eorseq r4, r1, r4, lsr 31')],
        calls=[(13937780, 'bl loc.imp.objc_msgSendSuper2'), (13937924, 'bl loc.imp.objc_msgSend'), (13937952, 'bl sym.imp.__wrap_fmodf'), (13938084, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (13938240, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13938392, 'bl 0xd4b4e4'), (13938424, 'bl sym.imp.__modsi3'), (13938732, 'blx r4'), (13938828, 'blx ip'), (13938916, 'blx lr'), (13939356, 'blx r3'), (13939548, 'blx lr')],
        branches=[(13937808, 'bne', 13937824), (13937820, 'b', 13939828), (13938260, 'beq', 13938372), (13938276, 'beq', 13938312), (13938292, 'beq', 13938312), (13938308, 'bne', 13938368), (13938368, 'b', 13938372), (13938388, 'beq', 13938464), (13938440, 'bge', 13938452), (13938452, 'b', 13938480), (13939036, 'bge', 13939092), (13939100, 'beq', 13939568), (13939420, 'bge', 13939444), (13939432, 'b', 13939452), (13939564, 'b', 13939016), (13939612, 'bgt', 13939820), (13939816, 'b', 13939576)],
        semantics=("[MangoTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00d4ab38, 619w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**growthVigorForTreeTypeAtPos** call + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constants 0x3f00/0x20 + helper 0xd4b4e4; soil set {0x30/31/32}.)"),
    ),
    dict(
        name='mp_ctor',
        method='MapleTree -[initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:]',
        types='@52@0:4@8@12{?=ii}16@24s28s32@36@40c44f48',
        start=14374608,
        end=14376868,
        disasm='disasm_worldtileloader_mp_ctor.txt',
        base_add=14374624,
        base_literal=14376864,
        boundary='ARM.exidx end 0x00db5fa4 (listing bound); next ObjC IMP 0x00db5fb4 MapleTree -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xdb5f50: (15241052, 'initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:'),
                 0xdb5f74: (15241060, 'getX:Y:octaves:'),
                 0xdb5f7c: (15241056, 'worldWidthMacro'),
                 0xdb5f98: (15241064, 'incrementHeight'),
                 0xdb5f9c: (15241068, 'updateGrowth:'),
        },
        imports={
                 0xdb5f70: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xdb5f54: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xdb5f58: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xdb5f5c: (17155084, 'OBJC_IVAR_$_Tree.maxHeight', 88),
                 0xdb5f60: (17155048, 'OBJC_IVAR_$_Tree.maxHeightGene', 54),
                 0xdb5f6c: (17155096, 'OBJC_IVAR_$_Tree.treeSeasonOffset', 84),
                 0xdb5f78: (17155028, 'OBJC_IVAR_$_Tree.seasonOffsetNoiseFunction', 80),
                 0xdb5f80: (17155064, 'OBJC_IVAR_$_Tree.height', 60),
                 0xdb5f84: (17155076, 'OBJC_IVAR_$_Tree.age', 96),
                 0xdb5f88: (17155072, 'OBJC_IVAR_$_Tree.maxAge', 92),
                 0xdb5f8c: (17155052, 'OBJC_IVAR_$_Tree.growthRate', 72),
                 0xdb5f94: (17155088, 'OBJC_IVAR_$_Tree.maxHeightReached', 64),
        },
        classes={
                 0xdb5f48: (15253328, 'OBJC_CLASS_$_MapleTree'),
        },
        instructions=[(14374608, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14376864, 'eoreq sl, sl, ip, lsl 8')],
        calls=[(14374924, 'bl loc.imp.objc_msgSendSuper2'), (14375096, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (14375252, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14375404, 'bl 0xdb5fa4'), (14375436, 'bl sym.imp.__modsi3'), (14375700, 'blx lr'), (14375788, 'blx ip'), (14375876, 'blx lr'), (14376284, 'blx r3'), (14376468, 'blx lr')],
        branches=[(14374952, 'bne', 14374968), (14374964, 'b', 14376756), (14375272, 'beq', 14375384), (14375288, 'beq', 14375324), (14375304, 'beq', 14375324), (14375320, 'bne', 14375380), (14375380, 'b', 14375384), (14375400, 'beq', 14375472), (14375452, 'bge', 14375464), (14375464, 'b', 14375488), (14375964, 'bge', 14376020), (14376028, 'beq', 14376496), (14376348, 'bge', 14376364), (14376360, 'b', 14376372), (14376484, 'b', 14375944), (14376540, 'bgt', 14376748), (14376744, 'b', 14376504)],
        semantics=("[MapleTree initWithWorld:dynamicWorld:atPosition:cache:maxHeight:growthRate:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultTree:adultMaxAge:] (imp 0x00db56d0, 565w): the placed ctor - **super2** with the wide 10-arg frame (the sxth/strb-normalized maxHeight/growthRate + the two noise-function blocks + adultTree byte + adultMaxAge halfword at sp+0x4..0x1c, @the super2 call) + **nil gate** (**growthVigorForTreeTypeAtPos** call + the growth math via vcvt.f32.u32/vdiv.f32 + vmul/vadd/vcvt.s32; the soil check **tileAtWorldPositionLoaded + tile byte {0x30/'0', 0x31, 0x32}** (the shared soil set); the **adultTree gate** (ldrsb) + the **__modsi3 random clamp** (cmp>=1); the **0x1869f (99999) sentinel** rides the pool for the non-adult max-age (as the pool word); the final max-age fraction via the f64/f32 divides. Constant 0x7f + helper 0xdb5fa4; soil set {0x30/31/32}.)"),
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
        'batch': 'Tree ctor family (E86): the ten placed ctors + the pine save ctor - vigor/soil/sentinel contract; 11 bodies',
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
                        default=NATIVE / 'tree_ctors.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale tree_ctors.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
