#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: KelpPlant, the swaying water kelp: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 5280 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/KELP_PLANT.md for the prose and boundaries.
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
    'bl 0x814f44': 0x00814f44,
    'bl 0x818cec': 0x00818cec,
    'bl 0x818d60': 0x00818d60,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSendSuper2_stret': 0x001c335c,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.fillArbitraryQuadBuffer_float__int___GLKMatrix4__float___GLKVector3___GLKVector3___GLKVector3___GLKVector3__float__float__float__float__int__int_': 0x00d96f5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.macroPosForWorldPos_intpair__World_': 0x00a16594,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
    'bl sym.updateArbitraryQuadVertsAndMatrix_float__int___GLKMatrix4___GLKVector3___GLKVector3___GLKVector3___GLKVector3_': 0x00d98190,
}

SPECS = [
    dict(
        name='k_objecttype',
        method='KelpPlant -[objectType]',
        types='i8@0:4',
        start=8473172,
        end=8473200,
        disasm='disasm_worldtileloader_k_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00814a70 (listing bound); next ObjC IMP 0x00814a70 KelpPlant -[initSubDerivedItems]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8473172, 'sub sp, sp, 8'), (8473196, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant objectType] (imp 0x00814a54, 7w): the object-type constant.\n'),
    ),
    dict(
        name='k_initsubderived',
        method='KelpPlant -[initSubDerivedItems]',
        types='v8@0:4',
        start=8473200,
        end=8474436,
        disasm='disasm_worldtileloader_k_initsubderived.txt',
        base_add=8473216,
        base_literal=8474432,
        boundary='ARM.exidx end 0x00814f44 (listing bound); next ObjC IMP 0x00814f54 KelpPlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        selectors={
                 0x814f08: (15212024, 'macroTiles'),
                 0x814f14: (15212028, 'worldContentsChangedAtPos:'),
                 0x814f1c: (15212032, 'maxAgeGeneVariation'),
        },
        imports={
                 0x814f18: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x814ef8: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
                 0x814efc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x814f04: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x814f0c: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x814f10: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x814f20: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x814f2c: (17161148, 'OBJC_IVAR_$_KelpPlant.checkWeatherCount', 100),
                 0x814f30: (17161152, 'OBJC_IVAR_$_KelpPlant.waveTimer', 172),
                 0x814f38: (17161156, 'OBJC_IVAR_$_KelpPlant.aboveGatherProgress', 108),
        },
        classes={},
        instructions=[(8473200, 'push {r4, r5, fp, lr}'), (8474432, 'addeq fp, r4, ip, rrx')],
        calls=[(8473332, 'bl loc.imp.objc_msgSend'), (8473376, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8473436, 'bl sym.makeIntpair_int__int_'), (8473468, 'bl loc.imp.objc_msgSend'), (8473512, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8473564, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8473632, 'bl sym.makeIntpair_int__int_'), (8473660, 'bl loc.imp.objc_msgSend'), (8473756, 'blx r2'), (8473960, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8474136, 'bl 0x814f44')],
        branches=[(8473688, 'bne', 8473780), (8473980, 'beq', 8474076), (8473996, 'beq', 8474032), (8474012, 'beq', 8474032), (8474028, 'bne', 8474072), (8474072, 'b', 8474076), (8474264, 'bge', 8474336), (8474332, 'b', 8474256)],
        semantics=('[KelpPlant initSubDerivedItems] (imp 0x00814a70, 309w): the derived init - objc x3 + **`reloadDrawBlockDynamicObjectQuad` x2** + makeIntpair x2 + tileAtWorldPositionLoaded x2 + the helper 0x814f44 + consts 0x51/0x3c (60).\n'),
    ),
    dict(
        name='k_ctor',
        method='KelpPlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        types='@48@0:4@8@12{?=ii}16@24S28S32@36@40c44',
        start=8474452,
        end=8477672,
        disasm='disasm_worldtileloader_k_ctor.txt',
        base_add=8474468,
        base_literal=8477668,
        boundary='ARM.exidx end 0x00815be8 (listing bound); next ObjC IMP 0x00815be8 KelpPlant -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x815b74: (15212036, 'initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:'),
                 0x815b84: (15212040, 'getWeatherFractionForPos:'),
                 0x815b88: (15212044, 'worldTime'),
                 0x815b8c: (15212048, 'getDayNightFractionForX:atWorldTime:'),
                 0x815b94: (15212056, 'release'),
                 0x815b98: (15212052, 'removeFromMacroBlock'),
                 0x815b9c: (15212060, 'isRequiredSoilType:'),
                 0x815ba4: (15212072, 'initSubDerivedItems'),
                 0x815bac: (15212068, 'getX:Y:octaves:'),
                 0x815bb4: (15212064, 'worldWidthMacro'),
                 0x815bd8: (15212028, 'worldContentsChangedAtPos:'),
                 0x815bdc: (15212076, 'tileIsKindOfSelf:'),
        },
        imports={
                 0x815b90: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x815b78: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x815b7c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x815ba0: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x815ba8: (17155496, 'OBJC_IVAR_$_Plant.seasonOffset', 68),
                 0x815bb0: (17155500, 'OBJC_IVAR_$_Plant.seasonOffsetNoiseFunction', 64),
                 0x815bb8: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x815bbc: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x815bc8: (17161160, 'OBJC_IVAR_$_KelpPlant.availableFood', 180),
                 0x815bd4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x815b6c: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8474452, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8477668, 'addeq sl, r4, r8, lsl 23')],
        calls=[(8474752, 'bl loc.imp.objc_msgSendSuper2'), (8474892, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8475036, 'bl loc.imp.objc_msgSend'), (8475108, 'bl loc.imp.objc_msgSend'), (8475148, 'bl loc.imp.objc_msgSend'), (8475200, 'bl loc.imp.objc_msgSend'), (8475248, 'bl sym.seasonForWorldX_int__double__World_'), (8475348, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (8475444, 'blx ip'), (8475464, 'blx r2'), (8475488, 'bl sym.tileIsWater_Tile_'), (8475568, 'blx ip'), (8475588, 'blx r2'), (8475688, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8475764, 'blx r3'), (8475844, 'blx ip'), (8475864, 'blx r2'), (8476124, 'blx r3'), (8476220, 'blx ip'), (8476308, 'blx lr'), (8476380, 'blx r3'), (8476512, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8476584, 'blx r3'), (8476704, 'bl sym.makeIntpair_int__int_'), (8476732, 'bl loc.imp.objc_msgSend'), (8476772, 'bl 0x814f44'), (8477040, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8477052, 'bl sym.tileIsWater_Tile_'), (8477156, 'bl sym.makeIntpair_int__int_'), (8477228, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (8477384, 'bl sym.makeIntpair_int__int_'), (8477412, 'bl loc.imp.objc_msgSend'), (8477448, 'bl 0x814f44')],
        branches=[(8474780, 'bne', 8474796), (8474792, 'b', 8477536), (8474912, 'beq', 8475612), (8474924, 'beq', 8475484), (8475376, 'bpl', 8475480), (8475476, 'b', 8477536), (8475480, 'b', 8475484), (8475500, 'bne', 8475608), (8475600, 'b', 8477536), (8475608, 'b', 8475612), (8475708, 'beq', 8475780), (8475776, 'bne', 8475880), (8475876, 'b', 8477536), (8476424, 'bge', 8476760), (8476532, 'beq', 8476736), (8476596, 'beq', 8476736), (8476736, 'b', 8476740), (8476752, 'b', 8476416), (8476768, 'beq', 8477448), (8476956, 'bpl', 8477444), (8477064, 'beq', 8477420), (8477080, 'bne', 8477420), (8477244, 'ble', 8477420), (8477416, 'b', 8477424), (8477420, 'b', 8477444), (8477424, 'b', 8477428), (8477440, 'b', 8476864), (8477444, 'b', 8477448)],
        semantics=('[KelpPlant initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:] (imp 0x00814f54, 805w): the kelp ctor - super2 + **`currentTemperatureForTileAt...` x2** (the temperature gate) + **`tileIsWater` x2** (the water substrate gate - both gates at placement!) + tileAtWorldPositionLoaded x4 + makeIntpair x3 + objc x6 + the helper 0x814f44 x2 + consts 0x20/0x10/0x51/0x384.\n'),
    ),
    dict(
        name='k_ctornet',
        method='KelpPlant -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=8480096,
        end=8480480,
        disasm='disasm_worldtileloader_k_ctornet.txt',
        base_add=8480112,
        base_literal=8480476,
        boundary='ARM.exidx end 0x008166e0 (listing bound); next ObjC IMP 0x008166e0 KelpPlant -[getSaveDict]',
        selectors={
                 0x8166c4: (15212116, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x8166d0: (15212072, 'initSubDerivedItems'),
                 0x8166d8: (15212120, 'getBytes:length:'),
        },
        imports={
                 0x8166c0: (17151900, 'objc_msgSendSuper2'),
                 0x8166cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8166d4: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
        },
        classes={
                 0x8166c8: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8480096, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8480476, 'addeq sb, r4, ip, ror r5')],
        calls=[(8480248, 'blx r6'), (8480380, 'blx lr'), (8480424, 'blx r3')],
        branches=[(8480276, 'bne', 8480292), (8480288, 'b', 8480436)],
        semantics=('[KelpPlant initWithWorld:dynamicWorld:cache:netData:] (imp 0x00816560, 96w): the netData ctor.\n'),
    ),
    dict(
        name='k_creationdata',
        method='KelpPlant -[plantCreationNetData]',
        types='{PlantCreationNetData={DynamicObjectNetData=QIIC[7C]}SSSSsC[5C]}8@0:4',
        start=8481120,
        end=8481260,
        disasm='disasm_worldtileloader_k_creationdata.txt',
        base_add=8481136,
        base_literal=8481256,
        boundary='ARM.exidx end 0x008169ec (listing bound); next ObjC IMP 0x008169ec KelpPlant -[dealloc]',
        selectors={
                 0x8169dc: (15212140, 'plantCreationNetData'),
        },
        imports={},
        ivars={
                 0x8169e4: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
        },
        classes={
                 0x8169e0: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8481120, 'push {fp, lr}'), (8481256, 'addeq sb, r4, ip, ror r1')],
        calls=[(8481196, 'bl loc.imp.objc_msgSendSuper2_stret')],
        branches=[],
        semantics=('[KelpPlant plantCreationNetData] (imp 0x00816960, 35w): the creation record.\n'),
    ),
    dict(
        name='k_dealloc',
        method='KelpPlant -[dealloc]',
        types='v8@0:4',
        start=8481260,
        end=8481368,
        disasm='disasm_worldtileloader_k_dealloc.txt',
        base_add=8481276,
        base_literal=8481364,
        boundary='ARM.exidx end 0x00816a58 (listing bound); next ObjC IMP 0x00816a58 KelpPlant -[remoteUpdate:]',
        selectors={
                 0x816a4c: (15212144, 'dealloc'),
        },
        imports={
                 0x816a48: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x816a50: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8481260, 'push {r4, sl, fp, lr}'), (8481364, 'strdeq sb, sl, [r4], r0')],
        calls=[(8481340, 'blx ip')],
        branches=[],
        semantics=('[KelpPlant dealloc] (imp 0x008169ec, 27w): teardown + super.\n'),
    ),
    dict(
        name='k_remoteupdate',
        method='KelpPlant -[remoteUpdate:]',
        types='v12@0:4@8',
        start=8481368,
        end=8482356,
        disasm='disasm_worldtileloader_k_remoteupdate.txt',
        base_add=8481384,
        base_literal=8482352,
        boundary='ARM.exidx end 0x00816e34 (listing bound); next ObjC IMP 0x00816e34 KelpPlant -[update:accurateDT:isSimulation:]',
        selectors={
                 0x816e00: (15212148, 'remoteUpdate:'),
                 0x816e10: (15212120, 'getBytes:length:'),
                 0x816e20: (15212024, 'macroTiles'),
                 0x816e2c: (15212028, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x816dfc: (17151900, 'objc_msgSendSuper2'),
                 0x816e0c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x816e08: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x816e18: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x816e1c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x816e24: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x816e04: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8481368, 'push {r4, r5, fp, lr}'), (8482352, 'addeq sb, r4, r4, lsl 1')],
        calls=[(8481460, 'blx lr'), (8481528, 'blx ip'), (8481768, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8481948, 'bl sym.makeIntpair_int__int_'), (8481976, 'bl loc.imp.objc_msgSend'), (8482116, 'bl loc.imp.objc_msgSend'), (8482160, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8482212, 'bl sym.makeIntpair_int__int_'), (8482244, 'bl loc.imp.objc_msgSend'), (8482288, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_')],
        branches=[(8481560, 'beq', 8482292), (8481636, 'bge', 8481652), (8481648, 'b', 8481660), (8481680, 'bge', 8482000), (8481788, 'beq', 8481980), (8481804, 'bge', 8481824), (8481820, 'b', 8481856), (8481836, 'bne', 8481852), (8481852, 'b', 8481856), (8481980, 'b', 8481984), (8481996, 'b', 8481576)],
        semantics=("[KelpPlant remoteUpdate:] (imp 0x00816a58, 247w): the network update - objc x3 + makeIntpair x2 + **`reloadDrawBlockDynamicObjectQuad` x2** + tileAtWorldPositionLoaded + consts 0x28/0x51 (the SAME shape as the vine's remoteUpdate - the shared plant-subclass net contract).\n"),
    ),
    dict(
        name='k_update',
        method='KelpPlant -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=8482356,
        end=8486028,
        disasm='disasm_worldtileloader_k_update.txt',
        base_add=8482372,
        base_literal=8486024,
        boundary='ARM.exidx end 0x00817c8c (listing bound); next ObjC IMP 0x00817c8c KelpPlant -[dieOfOldAge]',
        selectors={
                 0x817c04: (15212152, 'update:accurateDT:isSimulation:'),
                 0x817c30: (15212104, 'objectType'),
                 0x817c34: (15212108, 'dynamicWorldChangedAtPos:objectType:'),
                 0x817c3c: (15212156, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x817c50: (15212160, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
                 0x817c6c: (15212028, 'worldContentsChangedAtPos:'),
                 0x817c74: (15212024, 'macroTiles'),
                 0x817c84: (15212112, 'dieOfOldAge'),
        },
        imports={
                 0x817c00: (17151900, 'objc_msgSendSuper2'),
                 0x817c80: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x817c0c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x817c10: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x817c14: (17161168, 'OBJC_IVAR_$_Plant.frozen', 76),
                 0x817c18: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x817c1c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x817c20: (17161160, 'OBJC_IVAR_$_KelpPlant.availableFood', 180),
                 0x817c24: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x817c28: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x817c48: (17161148, 'OBJC_IVAR_$_KelpPlant.checkWeatherCount', 100),
                 0x817c58: (17161164, 'OBJC_IVAR_$_KelpPlant.growthTimer', 176),
                 0x817c5c: (17155516, 'OBJC_IVAR_$_Plant.growthRate', 92),
                 0x817c64: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x817c70: (17161156, 'OBJC_IVAR_$_KelpPlant.aboveGatherProgress', 108),
                 0x817c78: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x817c7c: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
        },
        classes={
                 0x817c08: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8482356, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8486024, 'addeq r8, r4, r8, lsr 25')],
        calls=[(8482512, 'blx lr'), (8482668, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8482980, 'bl loc.imp.objc_msgSend'), (8483016, 'bl loc.imp.objc_msgSend'), (8483056, 'bl 0x814f44'), (8483088, 'bl sym.imp.__modsi3'), (8483176, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8483188, 'bl sym.tileIsWater_Tile_'), (8483324, 'bl loc.imp.objc_msgSend'), (8483572, 'bl loc.imp.objc_msgSend'), (8483608, 'bl loc.imp.objc_msgSend'), (8483648, 'bl 0x814f44'), (8483680, 'bl sym.imp.__modsi3'), (8483768, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8483780, 'bl sym.tileIsWater_Tile_'), (8483916, 'bl loc.imp.objc_msgSend'), (8484112, 'bl sym.tileIsWater_Tile_'), (8484240, 'bl loc.imp.objc_msgSend'), (8484392, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8484404, 'bl sym.tileIsWater_Tile_'), (8484520, 'bl sym.makeIntpair_int__int_'), (8484568, 'bl loc.imp.objc_msgSend'), (8485100, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8485112, 'bl sym.tileIsWater_Tile_'), (8485292, 'bl sym.makeIntpair_int__int_'), (8485320, 'bl loc.imp.objc_msgSend'), (8485464, 'bl loc.imp.objc_msgSend'), (8485508, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8485556, 'bl sym.makeIntpair_int__int_'), (8485588, 'bl loc.imp.objc_msgSend'), (8485632, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8485696, 'bl loc.imp.objc_msgSend'), (8485732, 'bl loc.imp.objc_msgSend'), (8485872, 'blx r2')],
        branches=[(8482548, 'beq', 8482556), (8482552, 'b', 8485880), (8482588, 'beq', 8482596), (8482592, 'b', 8485880), (8482708, 'bne', 8483936), (8482760, 'bpl', 8482816), (8482812, 'b', 8483932), (8482848, 'blt', 8483340), (8483052, 'ble', 8483096), (8483200, 'beq', 8483332), (8483332, 'b', 8483928), (8483424, 'ble', 8483468), (8483644, 'ble', 8483688), (8483792, 'beq', 8483924), (8483924, 'b', 8483928), (8483928, 'b', 8483932), (8483932, 'b', 8483936), (8483992, 'blt', 8484676), (8484044, 'beq', 8484072), (8484124, 'bne', 8484256), (8484140, 'beq', 8484256), (8484156, 'beq', 8484256), (8484248, 'b', 8485880), (8484304, 'bge', 8484672), (8484416, 'bne', 8484580), (8484432, 'beq', 8484580), (8484448, 'beq', 8484580), (8484576, 'b', 8484672), (8484592, 'beq', 8484644), (8484608, 'bne', 8484644), (8484644, 'b', 8484648), (8484660, 'b', 8484268), (8484672, 'b', 8484676), (8484708, 'bne', 8485880), (8484744, 'bge', 8485768), (8484956, 'ble', 8485764), (8485124, 'beq', 8485760), (8485140, 'beq', 8485160), (8485156, 'bne', 8485760), (8485760, 'b', 8485764), (8485764, 'b', 8485768), (8485828, 'ble', 8485876), (8485876, 'b', 8485880)],
        semantics=('[KelpPlant update:accurateDT:isSimulation:] (imp 0x00816e34, 918w): the giant tick - objc x13 + **`tileIsWater` x5** (the kelp tracks its water column!) + tileAtWorldPositionLoaded x5 + makeIntpair x3 + **`reloadDrawBlockDynamicObjectQuad`** + `__modsi3` x2 + consts **0x708 (1800)/0x384/0xe1 (225)/0x51 (81)** (the growth/sway time bases) + the helper 0x814f44 x2.\n'),
    ),
    dict(
        name='k_dieofoldage',
        method='KelpPlant -[dieOfOldAge]',
        types='v8@0:4',
        start=8486028,
        end=8487248,
        disasm='disasm_worldtileloader_k_dieofoldage.txt',
        base_add=8486044,
        base_literal=8487244,
        boundary='ARM.exidx end 0x00818150 (listing bound); next ObjC IMP 0x00818150 KelpPlant -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x818108: (15212164, 'sowPlantNearParent:'),
                 0x818118: (15212160, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
                 0x81812c: (15212024, 'macroTiles'),
                 0x818138: (15212104, 'objectType'),
                 0x81813c: (15212108, 'dynamicWorldChangedAtPos:objectType:'),
                 0x818140: (15212076, 'tileIsKindOfSelf:'),
                 0x818148: (15212028, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x818104: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x81810c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x818110: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x81811c: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x818120: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x818128: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x818130: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x818134: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(8486028, 'push {r4, r5, r6, sl, fp, lr}'), (8487244, 'addeq r7, r4, r0, asr lr')],
        calls=[(8486060, 'bl 0x814f44'), (8486232, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8486304, 'blx r3'), (8486424, 'bl sym.makeIntpair_int__int_'), (8486452, 'bl loc.imp.objc_msgSend'), (8486592, 'bl loc.imp.objc_msgSend'), (8486636, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8486696, 'bl sym.makeIntpair_int__int_'), (8486728, 'bl loc.imp.objc_msgSend'), (8486772, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8486900, 'bl loc.imp.objc_msgSend'), (8486936, 'bl loc.imp.objc_msgSend'), (8487104, 'bl loc.imp.objc_msgSend'), (8487160, 'blx r3')],
        branches=[(8486092, 'ble', 8486972), (8486144, 'bge', 8486476), (8486252, 'beq', 8486456), (8486316, 'beq', 8486456), (8486456, 'b', 8486460), (8486472, 'b', 8486108), (8486964, 'b', 8487164)],
        semantics=('[KelpPlant dieOfOldAge] (imp 0x00817c8c, 305w): the age death - objc x6 + makeIntpair x2 + **`reloadDrawBlockDynamicObjectQuad` x2** + the helper 0x814f44 + tileAtWorldPositionLoaded.\n'),
    ),
    dict(
        name='k_draw',
        method='KelpPlant -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=8487248,
        end=8490220,
        disasm='disasm_worldtileloader_k_draw.txt',
        base_add=8487268,
        base_literal=8490216,
        boundary='ARM.exidx end 0x00818cec (listing bound); next ObjC IMP 0x00818d9c KelpPlant -[tileIsKindOfSelf:]',
        selectors={
                 0x818cbc: (15212024, 'macroTiles'),
        },
        imports={
                 0x818cb8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x818ca0: (17161172, 'OBJC_IVAR_$_KelpPlant.savedDrawBuffers', 184),
                 0x818ca8: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x818cb0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x818cb4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x818cc8: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x818cd0: (17161176, 'OBJC_IVAR_$_KelpPlant.savedDrawBufferIndexes', 192),
                 0x818cd8: (17161168, 'OBJC_IVAR_$_Plant.frozen', 76),
                 0x818cdc: (17161152, 'OBJC_IVAR_$_KelpPlant.waveTimer', 172),
                 0x818ce0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(8487248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8490216, 'addeq r7, r4, r8, lsl 19')],
        calls=[(8488000, 'bl sym.macroPosForWorldPos_intpair__World_'), (8488104, 'blx r2'), (8488148, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (8488744, 'bl method.Vector2.operator_float__'), (8488780, 'bl method.Vector2.operator_float__'), (8488808, 'bl 0x818cec'), (8489020, 'bl sym.imp.sinf'), (8489140, 'bl sym.imp.sinf'), (8489480, 'bl 0x818d60'), (8489512, 'bl 0x818d60'), (8489544, 'bl 0x818d60'), (8489576, 'bl 0x818d60'), (8489960, 'bl sym.updateArbitraryQuadVertsAndMatrix_float__int___GLKMatrix4___GLKVector3___GLKVector3___GLKVector3___GLKVector3_')],
        branches=[(8487840, 'bge', 8490128), (8487900, 'beq', 8490108), (8488012, 'bne', 8488156), (8488168, 'beq', 8490052), (8488188, 'beq', 8490052), (8488256, 'bne', 8490052), (8488344, 'bge', 8488360), (8488356, 'b', 8488368), (8488488, 'bge', 8488504), (8488500, 'b', 8488512), (8488632, 'blt', 8489996), (8488668, 'bne', 8488720), (8488856, 'bge', 8489992), (8489056, 'ble', 8489192), (8489164, 'b', 8489212), (8489208, 'b', 8489212), (8489988, 'b', 8488844), (8489992, 'b', 8490048), (8490048, 'b', 8490104), (8490104, 'b', 8490108), (8490108, 'b', 8490112), (8490124, 'b', 8487832)],
        semantics=('[KelpPlant draw:...] (imp 0x00818150, 743w): the kelp render - **`sinf` x2** (the WAVE SWAY animation!) + **`macroTileAtMacroPostion(int, int)`** (the macro-tile resolver) + **`updateArbitraryQuadV...`** (the arbitrary-quad updater) + `macroPosForWorldPos` + Vector float* x2 + the helper 0x818d60 x4 + const 0xbf00 (-0.5f bits); the kelp bends with the sine.\n'),
    ),
    dict(
        name='k_kindself',
        method='KelpPlant -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=8490396,
        end=8490448,
        disasm='disasm_worldtileloader_k_kindself.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00818dd0 (listing bound); next ObjC IMP 0x00818dd0 KelpPlant -[plantType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8490396, 'sub sp, sp, 0xc'), (8490444, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant tileIsKindOfSelf:] (imp 0x00818d9c, 13w): membership.\n'),
    ),
    dict(
        name='k_planttype',
        method='KelpPlant -[plantType]',
        types='i8@0:4',
        start=8490448,
        end=8490476,
        disasm='disasm_worldtileloader_k_planttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00818dec (listing bound); next ObjC IMP 0x00818dec KelpPlant -[isRequiredSoilType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8490448, 'sub sp, sp, 8'), (8490472, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant plantType] (imp 0x00818dd0, 7w): the plant-type constant.\n'),
    ),
    dict(
        name='k_soiltype',
        method='KelpPlant -[isRequiredSoilType:]',
        types='c12@0:4i8',
        start=8490476,
        end=8490612,
        disasm='disasm_worldtileloader_k_soiltype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00818e74 (listing bound); next ObjC IMP 0x00818e74 KelpPlant -[gatherProgressForTile:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8490476, 'sub sp, sp, 0x10'), (8490608, 'bx lr')],
        calls=[],
        branches=[(8490508, 'beq', 8490592), (8490528, 'beq', 8490592), (8490548, 'beq', 8490592), (8490568, 'beq', 8490592)],
        semantics=("[KelpPlant isRequiredSoilType:] (imp 0x00818dec, 34w): the soil membership (the water plant's own set).\n"),
    ),
    dict(
        name='k_gatherprogress',
        method='KelpPlant -[gatherProgressForTile:]',
        types='i16@0:4{?=ii}8',
        start=8490612,
        end=8490876,
        disasm='disasm_worldtileloader_k_gatherprogress.txt',
        base_add=8490624,
        base_literal=8490872,
        boundary='ARM.exidx end 0x00818f7c (listing bound); next ObjC IMP 0x00818f7c KelpPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        selectors={},
        imports={},
        ivars={
                 0x818f68: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x818f6c: (17155532, 'OBJC_IVAR_$_Plant.gatherProgress', 80),
                 0x818f74: (17161156, 'OBJC_IVAR_$_KelpPlant.aboveGatherProgress', 108),
        },
        classes={},
        instructions=[(8490612, 'push {fp, lr}'), (8490872, 'addeq r6, r4, ip, ror 24')],
        calls=[],
        branches=[(8490680, 'ble', 8490812), (8490724, 'bge', 8490812), (8490808, 'b', 8490844)],
        semantics=('[KelpPlant gatherProgressForTile:] (imp 0x00818e74, 66w): the gather progress.\n'),
    ),
    dict(
        name='k_harvested',
        method='KelpPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        types='i24@0:4{?=ii}8@16i20',
        start=8490876,
        end=8493144,
        disasm='disasm_worldtileloader_k_harvested.txt',
        base_add=8490892,
        base_literal=8493140,
        boundary='ARM.exidx end 0x00819858 (listing bound); next ObjC IMP 0x00819858 KelpPlant -[setGatherProgress:forTile:]',
        selectors={
                 0x819808: (15212104, 'objectType'),
                 0x81980c: (15212108, 'dynamicWorldChangedAtPos:objectType:'),
                 0x819818: (15212028, 'worldContentsChangedAtPos:'),
                 0x819828: (15212024, 'macroTiles'),
                 0x819830: (15212176, 'removePlantWithoutCreatingFreeblocks'),
                 0x819834: (15212076, 'tileIsKindOfSelf:'),
                 0x819840: (15212032, 'maxAgeGeneVariation'),
                 0x819844: (15212168, 'growthRateGeneVariation'),
                 0x819848: (15212172, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x81982c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8197f8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x8197fc: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x819800: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x819810: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x81981c: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x819820: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(8490876, 'push {r4, r5, r6, sl, fp, lr}'), (8493140, 'addeq r6, r4, r0, ror 22')],
        calls=[(8491348, 'bl loc.imp.objc_msgSend'), (8491384, 'bl loc.imp.objc_msgSend'), (8491472, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8491592, 'bl loc.imp.objc_msgSend'), (8491624, 'bl loc.imp.objc_msgSend'), (8491724, 'bl loc.imp.objc_msgSend'), (8491832, 'bl loc.imp.objc_msgSend'), (8492008, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8492080, 'blx r3'), (8492096, 'bl 0x814f44'), (8492204, 'bl sym.makeIntpair_int__int_'), (8492224, 'bl loc.imp.objc_msgSend'), (8492256, 'bl loc.imp.objc_msgSend'), (8492344, 'bl loc.imp.objc_msgSend'), (8492452, 'bl sym.makeIntpair_int__int_'), (8492480, 'bl loc.imp.objc_msgSend'), (8492624, 'bl sym.makeIntpair_int__int_'), (8492672, 'bl loc.imp.objc_msgSend'), (8492716, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8492776, 'bl loc.imp.objc_msgSend'), (8492820, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8493028, 'blx r2')],
        branches=[(8490972, 'bne', 8493036), (8491012, 'blt', 8493036), (8491064, 'bpl', 8491120), (8491116, 'b', 8491140), (8491136, 'b', 8491140), (8491204, 'bpl', 8491220), (8491216, 'b', 8491236), (8491420, 'bge', 8492508), (8491492, 'bne', 8491836), (8491516, 'bge', 8491760), (8491752, 'b', 8491504), (8491920, 'bge', 8492504), (8492028, 'beq', 8492484), (8492092, 'beq', 8492484), (8492108, 'ble', 8492348), (8492484, 'b', 8492488), (8492500, 'b', 8491884), (8492504, 'b', 8492508), (8492888, 'bge', 8492904), (8492900, 'b', 8492912), (8492984, 'bne', 8493032), (8493032, 'b', 8493036)],
        semantics=('[KelpPlant tileHarvested:removeBlockhead:correctToolMultiplier:] (imp 0x00818f7c, 567w): the harvest - objc x12 + makeIntpair x3 + **`reloadDrawBlockDynamicObjectQuad` x2** + the helper 0x814f44 + consts 0x384/0x90 (144)/0x10 (1 unclassified = the 0x3fffffff sentinel @0x819838).\n'),
    ),
    dict(
        name='k_setgather',
        method='KelpPlant -[setGatherProgress:forTile:]',
        types='v20@0:4i8{?=ii}12',
        start=8493144,
        end=8493484,
        disasm='disasm_worldtileloader_k_setgather.txt',
        base_add=8493156,
        base_literal=8493480,
        boundary='ARM.exidx end 0x008199ac (listing bound); next ObjC IMP 0x008199ac KelpPlant -[numberOfOccupiedTilesAbove]',
        selectors={},
        imports={},
        ivars={
                 0x819994: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x819998: (17155532, 'OBJC_IVAR_$_Plant.gatherProgress', 80),
                 0x81999c: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x8199a4: (17161156, 'OBJC_IVAR_$_KelpPlant.aboveGatherProgress', 108),
        },
        classes={},
        instructions=[(8493144, 'push {r4, lr}'), (8493480, 'addeq r6, r4, r8, lsl 5')],
        calls=[],
        branches=[(8493220, 'ble', 8493420), (8493288, 'bgt', 8493416), (8493332, 'bge', 8493416), (8493416, 'b', 8493452)],
        semantics=('[KelpPlant setGatherProgress:forTile:] (imp 0x00819858, 85w): the gather write.\n'),
    ),
    dict(
        name='k_tilesabove',
        method='KelpPlant -[numberOfOccupiedTilesAbove]',
        types='i8@0:4',
        start=8493484,
        end=8493572,
        disasm='disasm_worldtileloader_k_tilesabove.txt',
        base_add=8493492,
        base_literal=8493540,
        boundary='ARM.exidx end 0x00819a04 (listing bound); next ObjC IMP 0x008199e8 KelpPlant -[droppedItemType]',
        selectors={},
        imports={},
        ivars={
                 0x8199e0: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
        },
        classes={},
        instructions=[(8493484, 'sub sp, sp, 8'), (8493568, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant numberOfOccupiedTilesAbove] (imp 0x008199ac, 22w): the above count.\n'),
    ),
    dict(
        name='k_droppeditem',
        method='KelpPlant -[droppedItemType]',
        types='i8@0:4',
        start=8493544,
        end=8493572,
        disasm='disasm_worldtileloader_k_droppeditem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00819a04 (listing bound); next ObjC IMP 0x00819a04 KelpPlant -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8493544, 'sub sp, sp, 8'), (8493568, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant droppedItemType] (imp 0x008199e8, 7w): the dropped item.\n'),
    ),
    dict(
        name='k_staticquadcount',
        method='KelpPlant -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=8493572,
        end=8494296,
        disasm='disasm_worldtileloader_k_staticquadcount.txt',
        base_add=8493588,
        base_literal=8494292,
        boundary='ARM.exidx end 0x00819cd8 (listing bound); next ObjC IMP 0x00819cd8 KelpPlant -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={
                 0x819cc4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x819cc8: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x819cd0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(8493572, 'push {r4, sl, fp, lr}'), (8494292, 'ldrdeq r6, r7, [r4], r8')],
        calls=[(8493644, 'bl sym.imp.__aeabi_idiv'), (8493920, 'bl sym.macroPosForWorldPos_intpair__World_')],
        branches=[(8493664, 'beq', 8493680), (8493676, 'b', 8494264), (8493748, 'ble', 8493764), (8493760, 'b', 8494264), (8493832, 'bge', 8493848), (8493844, 'b', 8494264), (8493936, 'beq', 8493980), (8493956, 'bne', 8493964), (8493960, 'b', 8493976), (8493972, 'b', 8494264), (8493976, 'b', 8493980), (8494032, 'bge', 8494048), (8494044, 'b', 8494056), (8494176, 'bge', 8494192), (8494188, 'b', 8494200)],
        semantics=('[KelpPlant staticGeometryDrawQuadCountForMacroPos:] (imp 0x00819a04, 181w): the quad count - `macroPosForWorldPos` + `__aeabi_idiv`.\n'),
    ),
    dict(
        name='k_adddrawquad',
        method='KelpPlant -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=8494296,
        end=8496880,
        disasm='disasm_worldtileloader_k_adddrawquad.txt',
        base_add=8494316,
        base_literal=8496876,
        boundary='ARM.exidx end 0x0081a6f0 (listing bound); next ObjC IMP 0x0081a6f0 KelpPlant -[removeFromMacroBlock]',
        selectors={},
        imports={},
        ivars={
                 0x81a6c8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x81a6cc: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
                 0x81a6d4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x81a6d8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x81a6e0: (17161172, 'OBJC_IVAR_$_KelpPlant.savedDrawBuffers', 184),
                 0x81a6e4: (17161176, 'OBJC_IVAR_$_KelpPlant.savedDrawBufferIndexes', 192),
                 0x81a6e8: (17161152, 'OBJC_IVAR_$_KelpPlant.waveTimer', 172),
        },
        classes={},
        instructions=[(8494296, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8496876, 'addeq r5, r4, r0, lsl 28')],
        calls=[(8494388, 'bl sym.imp.__aeabi_idiv'), (8494664, 'bl sym.macroPosForWorldPos_intpair__World_'), (8495108, 'bl method.Vector2.operator_float__'), (8495144, 'bl method.Vector2.operator_float__'), (8495172, 'bl 0x818cec'), (8495244, 'bl sym.imp.__modsi3'), (8495260, 'bl sym.imp.__aeabi_idiv'), (8495476, 'bl sym.imp.__modsi3'), (8495776, 'bl sym.imp.sinf'), (8495896, 'bl sym.imp.sinf'), (8496208, 'bl 0x818d60'), (8496240, 'bl 0x818d60'), (8496272, 'bl 0x818d60'), (8496304, 'bl 0x818d60'), (8496752, 'bl sym.fillArbitraryQuadBuffer_float__int___GLKMatrix4__float___GLKVector3___GLKVector3___GLKVector3___GLKVector3__float__float__float__float__int__int_')],
        branches=[(8494408, 'beq', 8494424), (8494420, 'b', 8496792), (8494492, 'ble', 8494508), (8494504, 'b', 8496792), (8494576, 'bgt', 8494592), (8494588, 'b', 8496792), (8494688, 'beq', 8494740), (8494708, 'bne', 8494724), (8494720, 'b', 8494736), (8494732, 'b', 8496792), (8494736, 'b', 8494740), (8494792, 'bge', 8494808), (8494804, 'b', 8494816), (8494936, 'bge', 8494952), (8494948, 'b', 8494960), (8495432, 'bge', 8496784), (8495484, 'bne', 8495532), (8495568, 'bne', 8495616), (8495812, 'ble', 8495976), (8495920, 'b', 8495996), (8495992, 'b', 8495996), (8496780, 'b', 8495420)],
        semantics=('[KelpPlant addDrawQuadData:fromIndex:forMacroPos:] (imp 0x00819cd8, 646w): the quad emitter - **`fillArbitraryQuadBuffer`** + **`sinf` x2** (the same sway) + macroPosForWorldPos + the helper 0x818d60 x4 + `__aeabi_idiv` x2 + `__modsi3` x2 + consts 0x20/0xbf00/0xf9.\n'),
    ),
    dict(
        name='k_rmmacro',
        method='KelpPlant -[removeFromMacroBlock]',
        types='v8@0:4',
        start=8496880,
        end=8497296,
        disasm='disasm_worldtileloader_k_rmmacro.txt',
        base_add=8496896,
        base_literal=8497292,
        boundary='ARM.exidx end 0x0081a890 (listing bound); next ObjC IMP 0x0081a890 KelpPlant -[availableFood]',
        selectors={
                 0x81a870: (15212052, 'removeFromMacroBlock'),
                 0x81a884: (15212024, 'macroTiles'),
        },
        imports={
                 0x81a86c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x81a878: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x81a880: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x81a888: (17161144, 'OBJC_IVAR_$_KelpPlant.numberOfOccupiedTilesAbove', 200),
        },
        classes={
                 0x81a874: (15252852, 'OBJC_CLASS_$_KelpPlant'),
        },
        instructions=[(8496880, 'push {r4, sl, fp, lr}'), (8497292, 'addeq r5, r4, ip, ror 7')],
        calls=[(8497000, 'bl loc.imp.objc_msgSend'), (8497044, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8497104, 'bl sym.makeIntpair_int__int_'), (8497136, 'bl loc.imp.objc_msgSend'), (8497180, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (8497248, 'blx r3')],
        branches=[],
        semantics=('[KelpPlant removeFromMacroBlock] (imp 0x0081a6f0, 104w): the removal hook - objc x2 + **`reloadDrawBlockDynamicObjectQuad` x2** + makeIntpair x1.\n'),
    ),
    dict(
        name='k_availfood',
        method='KelpPlant -[availableFood]',
        types='f8@0:4',
        start=8497296,
        end=8497444,
        disasm='disasm_worldtileloader_k_availfood.txt',
        base_add=8497320,
        base_literal=8497364,
        boundary='ARM.exidx end 0x0081a924 (listing bound); next ObjC IMP 0x0081a8d8 KelpPlant -[setAvailableFood:]',
        selectors={},
        imports={},
        ivars={
                 0x81a8d0: (17161160, 'OBJC_IVAR_$_KelpPlant.availableFood', 180),
                 0x81a91c: (17161160, 'OBJC_IVAR_$_KelpPlant.availableFood', 180),
        },
        classes={},
        instructions=[(8497296, 'sub sp, sp, 0xc'), (8497440, 'strdeq r5, r6, [r4], r4')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant availableFood] (imp 0x0081a890, 37w): the food float read.\n'),
    ),
    dict(
        name='k_setavailfood',
        method='KelpPlant -[setAvailableFood:]',
        types='v12@0:4f8',
        start=8497368,
        end=8497444,
        disasm='disasm_worldtileloader_k_setavailfood.txt',
        base_add=8497400,
        base_literal=8497440,
        boundary='ARM.exidx end 0x0081a924 (listing bound); next ObjC IMP 0x0081aa84 PassengerCar -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={
                 0x81a91c: (17161160, 'OBJC_IVAR_$_KelpPlant.availableFood', 180),
        },
        classes={},
        instructions=[(8497368, 'sub sp, sp, 0xc'), (8497440, 'strdeq r5, r6, [r4], r4')],
        calls=[],
        branches=[],
        semantics=('[KelpPlant setAvailableFood:] (imp 0x0081a8d8, 19w): the food float write.\n'),
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
        'batch': 'KelpPlant (E93): the water kelp - dual gates, sinf sway, arbitrary-quad updater; 23 bodies',
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
                        default=NATIVE / 'kelp_plant.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale kelp_plant.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
