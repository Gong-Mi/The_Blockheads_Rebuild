#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: VinePlant, the water-growing vine: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 4102 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/VINE_PLANT.md for the prose and boundaries.
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
    'bl 0x4f688c': 0x004f688c,
    'bl 0x4fa2e8': 0x004fa2e8,
    'bl 0x4fa35c': 0x004fa35c,
    'bl 0x4fa398': 0x004fa398,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSendSuper2_stret': 0x001c335c,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.fillArbitraryQuadBuffer_float__int___GLKMatrix4__float___GLKVector3___GLKVector3___GLKVector3___GLKVector3__float__float__float__float__int__int_': 0x00d96f5c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.macroPosForWorldPos_intpair__World_': 0x00a16594,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='v_objecttype',
        method='VinePlant -[objectType]',
        types='i8@0:4',
        start=5200108,
        end=5200136,
        disasm='disasm_worldtileloader_v_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f5908 (listing bound); next ObjC IMP 0x004f5908 VinePlant -[initSubDerivedItems]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5200108, 'sub sp, sp, 8'), (5200132, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[VinePlant objectType] (imp 0x004f58ec, 7w): the object-type constant.\n'),
    ),
    dict(
        name='v_initsubderived',
        method='VinePlant -[initSubDerivedItems]',
        types='v8@0:4',
        start=5200136,
        end=5201076,
        disasm='disasm_worldtileloader_v_initsubderived.txt',
        base_add=5200152,
        base_literal=5201072,
        boundary='ARM.exidx end 0x004f5cb4 (listing bound); next ObjC IMP 0x004f5cb4 VinePlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        selectors={
                 0x4f5c84: (15193788, 'macroTiles'),
                 0x4f5c90: (15193792, 'worldContentsChangedAtPos:'),
                 0x4f5c98: (15193796, 'maxAgeGeneVariation'),
        },
        imports={
                 0x4f5c94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f5c74: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
                 0x4f5c78: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f5c80: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f5c88: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f5c8c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4f5c9c: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x4f5ca8: (17155492, 'OBJC_IVAR_$_VinePlant.belowGatherProgress', 112),
        },
        classes={},
        instructions=[(5200136, 'push {r4, r5, fp, lr}'), (5201072, 'ldrsbteq sl, [r6], r4')],
        calls=[(5200268, 'bl loc.imp.objc_msgSend'), (5200312, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5200372, 'bl sym.makeIntpair_int__int_'), (5200404, 'bl loc.imp.objc_msgSend'), (5200448, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5200500, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5200568, 'bl sym.makeIntpair_int__int_'), (5200596, 'bl loc.imp.objc_msgSend'), (5200692, 'blx r2')],
        branches=[(5200624, 'bne', 5200716), (5200836, 'beq', 5200872), (5200852, 'beq', 5200872), (5200868, 'bne', 5200912), (5200932, 'bge', 5201004), (5201000, 'b', 5200924)],
        semantics=('[VinePlant initSubDerivedItems] (imp 0x004f5908, 235w): the derived init - objc x3 + **`reloadDrawBlockDynamicObjectQuad` x2** + makeIntpair x2 + tileAtWorldPositionLoaded + consts 0x7c/0x6d60/0xff.\n'),
    ),
    dict(
        name='v_ctor',
        method='VinePlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        types='@48@0:4@8@12{?=ii}16@24S28S32@36@40c44',
        start=5201076,
        end=5204108,
        disasm='disasm_worldtileloader_v_ctor.txt',
        base_add=5201092,
        base_literal=5204104,
        boundary='ARM.exidx end 0x004f688c (listing bound); next ObjC IMP 0x004f68a0 VinePlant -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x4f6818: (15193800, 'initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:'),
                 0x4f6828: (15193804, 'getWeatherFractionForPos:'),
                 0x4f682c: (15193808, 'worldTime'),
                 0x4f6830: (15193812, 'getDayNightFractionForX:atWorldTime:'),
                 0x4f6838: (15193824, 'isRequiredSoilType:'),
                 0x4f683c: (15193820, 'release'),
                 0x4f6840: (15193816, 'removeFromMacroBlock'),
                 0x4f6848: (15193836, 'initSubDerivedItems'),
                 0x4f6850: (15193832, 'getX:Y:octaves:'),
                 0x4f6858: (15193828, 'worldWidthMacro'),
                 0x4f6874: (15193792, 'worldContentsChangedAtPos:'),
                 0x4f6880: (15193840, 'tileIsKindOfSelf:'),
        },
        imports={
                 0x4f6834: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f681c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f6820: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f6844: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f684c: (17155496, 'OBJC_IVAR_$_Plant.seasonOffset', 68),
                 0x4f6854: (17155500, 'OBJC_IVAR_$_Plant.seasonOffsetNoiseFunction', 64),
                 0x4f685c: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x4f6860: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x4f6870: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4f6878: (17155508, 'OBJC_IVAR_$_VinePlant.availableFood', 100),
        },
        classes={
                 0x4f6810: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5201076, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5204104, 'adcseq sb, r6, r8, lsr 28')],
        calls=[(5201376, 'bl loc.imp.objc_msgSendSuper2'), (5201516, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5201660, 'bl loc.imp.objc_msgSend'), (5201732, 'bl loc.imp.objc_msgSend'), (5201772, 'bl loc.imp.objc_msgSend'), (5201824, 'bl loc.imp.objc_msgSend'), (5201872, 'bl sym.seasonForWorldX_int__double__World_'), (5201972, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (5202068, 'blx ip'), (5202088, 'blx r2'), (5202160, 'blx r3'), (5202240, 'blx ip'), (5202260, 'blx r2'), (5202528, 'blx r3'), (5202624, 'blx ip'), (5202712, 'blx lr'), (5202784, 'blx r3'), (5202916, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5202988, 'blx r3'), (5203108, 'bl sym.makeIntpair_int__int_'), (5203136, 'bl loc.imp.objc_msgSend'), (5203176, 'bl 0x4f688c'), (5203444, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5203472, 'bl sym.tileIsWater_Tile_'), (5203592, 'bl sym.makeIntpair_int__int_'), (5203664, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (5203820, 'bl sym.makeIntpair_int__int_'), (5203848, 'bl loc.imp.objc_msgSend'), (5203884, 'bl 0x4f688c')],
        branches=[(5201404, 'bne', 5201420), (5201416, 'b', 5203972), (5201536, 'beq', 5202284), (5201548, 'beq', 5202108), (5202000, 'bpl', 5202104), (5202100, 'b', 5203972), (5202104, 'b', 5202108), (5202172, 'bne', 5202280), (5202272, 'b', 5203972), (5202280, 'b', 5202284), (5202828, 'bge', 5203164), (5202936, 'beq', 5203140), (5203000, 'beq', 5203140), (5203140, 'b', 5203144), (5203156, 'b', 5202820), (5203172, 'beq', 5203884), (5203360, 'bpl', 5203880), (5203464, 'beq', 5203856), (5203484, 'bne', 5203856), (5203500, 'beq', 5203856), (5203516, 'bne', 5203856), (5203680, 'ble', 5203856), (5203852, 'b', 5203860), (5203856, 'b', 5203880), (5203860, 'b', 5203864), (5203876, 'b', 5203268), (5203880, 'b', 5203884)],
        semantics=('[VinePlant initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:] (imp 0x004f5cb4, 758w): the vine ctor - super2 + **`currentTemperatureForTileAtWorld...` x2** (the vine is temperature-gated!) + `tileAtWorldPositionLoaded` x3 + `makeIntpair` x3 + objc x6 + the helper 0x4f688c x2 + consts 0x20/0x10/0x7c/0x384.\n'),
    ),
    dict(
        name='v_ctornet',
        method='VinePlant -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=5206852,
        end=5207236,
        disasm='disasm_worldtileloader_v_ctornet.txt',
        base_add=5206868,
        base_literal=5207232,
        boundary='ARM.exidx end 0x004f74c4 (listing bound); next ObjC IMP 0x004f74c4 VinePlant -[getSaveDict]',
        selectors={
                 0x4f74a8: (15193880, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x4f74b4: (15193836, 'initSubDerivedItems'),
                 0x4f74bc: (15193884, 'getBytes:length:'),
        },
        imports={
                 0x4f74a4: (17151900, 'objc_msgSendSuper2'),
                 0x4f74b0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f74b8: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
        },
        classes={
                 0x4f74ac: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5206852, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5207232, 'umlalseq r8, r6, r8, r7')],
        calls=[(5207004, 'blx r6'), (5207136, 'blx lr'), (5207180, 'blx r3')],
        branches=[(5207032, 'bne', 5207048), (5207044, 'b', 5207192)],
        semantics=('[VinePlant initWithWorld:dynamicWorld:cache:netData:] (imp 0x004f7344, 96w): the netData ctor.\n'),
    ),
    dict(
        name='v_remoteupdate',
        method='VinePlant -[remoteUpdate:]',
        types='v12@0:4@8',
        start=5207876,
        end=5208864,
        disasm='disasm_worldtileloader_v_remoteupdate.txt',
        base_add=5207892,
        base_literal=5208860,
        boundary='ARM.exidx end 0x004f7b20 (listing bound); next ObjC IMP 0x004f7b20 VinePlant -[dealloc]',
        selectors={
                 0x4f7aec: (15193904, 'remoteUpdate:'),
                 0x4f7afc: (15193884, 'getBytes:length:'),
                 0x4f7b0c: (15193788, 'macroTiles'),
                 0x4f7b18: (15193792, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x4f7ae8: (17151900, 'objc_msgSendSuper2'),
                 0x4f7af8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f7af4: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f7b04: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f7b08: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f7b10: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0x4f7af0: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5207876, 'push {r4, r5, fp, lr}'), (5208860, 'umlalseq r8, r6, r8, r3')],
        calls=[(5207968, 'blx lr'), (5208036, 'blx ip'), (5208276, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5208456, 'bl sym.makeIntpair_int__int_'), (5208484, 'bl loc.imp.objc_msgSend'), (5208624, 'bl loc.imp.objc_msgSend'), (5208668, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5208720, 'bl sym.makeIntpair_int__int_'), (5208752, 'bl loc.imp.objc_msgSend'), (5208796, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_')],
        branches=[(5208068, 'beq', 5208800), (5208144, 'bge', 5208160), (5208156, 'b', 5208168), (5208188, 'bge', 5208508), (5208296, 'beq', 5208488), (5208312, 'bge', 5208332), (5208328, 'b', 5208364), (5208344, 'bne', 5208360), (5208360, 'b', 5208364), (5208488, 'b', 5208492), (5208504, 'b', 5208084)],
        semantics=('[VinePlant remoteUpdate:] (imp 0x004f7744, 247w): the network update - objc x3 + makeIntpair x2 + **`reloadDrawBlockDynamicObjectQuad` x2** + tileAtWorldPositionLoaded + consts 0x28/0x7c.\n'),
    ),
    dict(
        name='v_dealloc',
        method='VinePlant -[dealloc]',
        types='v8@0:4',
        start=5208864,
        end=5208972,
        disasm='disasm_worldtileloader_v_dealloc.txt',
        base_add=5208880,
        base_literal=5208968,
        boundary='ARM.exidx end 0x004f7b8c (listing bound); next ObjC IMP 0x004f7b8c VinePlant -[plantCreationNetData]',
        selectors={
                 0x4f7b80: (15193908, 'dealloc'),
        },
        imports={
                 0x4f7b7c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x4f7b84: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5208864, 'push {r4, sl, fp, lr}'), (5208968, 'ldrhteq r7, [r6], ip')],
        calls=[(5208944, 'blx ip')],
        branches=[],
        semantics=('[VinePlant dealloc] (imp 0x004f7b20, 27w): teardown + super.\n'),
    ),
    dict(
        name='v_creationdata',
        method='VinePlant -[plantCreationNetData]',
        types='{PlantCreationNetData={DynamicObjectNetData=QIIC[7C]}SSSSsC[5C]}8@0:4',
        start=5208972,
        end=5209328,
        disasm='disasm_worldtileloader_v_creationdata.txt',
        base_add=5208988,
        base_literal=5209108,
        boundary='ARM.exidx end 0x004f7cf0 (listing bound); next ObjC IMP 0x004f7c18 VinePlant -[isGrowingInCompost]',
        selectors={
                 0x4f7c08: (15193912, 'plantCreationNetData'),
        },
        imports={},
        ivars={
                 0x4f7c10: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f7ce0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f7ce4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x4f7c0c: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5208972, 'push {fp, lr}'), (5209324, 'andeq r0, r0, r0')],
        calls=[(5209048, 'bl loc.imp.objc_msgSendSuper2_stret'), (5209204, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(5209224, 'beq', 5209292), (5209240, 'beq', 5209276), (5209256, 'beq', 5209276), (5209272, 'bne', 5209288), (5209284, 'b', 5209300), (5209288, 'b', 5209292)],
        semantics=('[VinePlant plantCreationNetData] (imp 0x004f7b8c, 89w): the creation record builder.\n'),
    ),
    dict(
        name='v_compost',
        method='VinePlant -[isGrowingInCompost]',
        types='c8@0:4',
        start=5209112,
        end=5209328,
        disasm='disasm_worldtileloader_v_compost.txt',
        base_add=5209128,
        base_literal=5209320,
        boundary='ARM.exidx end 0x004f7cf0 (listing bound); next ObjC IMP 0x004f7cf0 VinePlant -[update:accurateDT:isSimulation:]',
        selectors={},
        imports={},
        ivars={
                 0x4f7ce0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f7ce4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(5209112, 'push {fp, lr}'), (5209324, 'andeq r0, r0, r0')],
        calls=[(5209204, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(5209224, 'beq', 5209292), (5209240, 'beq', 5209276), (5209256, 'beq', 5209276), (5209272, 'bne', 5209288), (5209284, 'b', 5209300), (5209288, 'b', 5209292)],
        semantics=('[VinePlant isGrowingInCompost] (imp 0x004f7c18, 54w): the compost predicate.\n'),
    ),
    dict(
        name='v_update',
        method='VinePlant -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=5209328,
        end=5211816,
        disasm='disasm_worldtileloader_v_update.txt',
        base_add=5209344,
        base_literal=5211812,
        boundary='ARM.exidx end 0x004f86a8 (listing bound); next ObjC IMP 0x004f86a8 VinePlant -[dieOfOldAge]',
        selectors={
                 0x4f863c: (15193916, 'update:accurateDT:isSimulation:'),
                 0x4f8660: (15193920, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
                 0x4f867c: (15193792, 'worldContentsChangedAtPos:'),
                 0x4f8684: (15193788, 'macroTiles'),
                 0x4f8688: (15193868, 'objectType'),
                 0x4f868c: (15193872, 'dynamicWorldChangedAtPos:objectType:'),
                 0x4f869c: (15193876, 'dieOfOldAge'),
        },
        imports={
                 0x4f8638: (17151900, 'objc_msgSendSuper2'),
                 0x4f8698: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f8644: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x4f8648: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x4f864c: (17155524, 'OBJC_IVAR_$_VinePlant.checkWeatherCount', 104),
                 0x4f8650: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f8654: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f8658: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f8664: (17155512, 'OBJC_IVAR_$_VinePlant.growthTimer', 176),
                 0x4f8668: (17155516, 'OBJC_IVAR_$_Plant.growthRate', 92),
                 0x4f8670: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x4f8674: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4f8680: (17155492, 'OBJC_IVAR_$_VinePlant.belowGatherProgress', 112),
                 0x4f8690: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x4f8694: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
        },
        classes={
                 0x4f8640: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5209328, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5211812, 'adcseq r7, r6, ip, ror 27')],
        calls=[(5209484, 'blx lr'), (5209640, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5209744, 'bl sym.tileIsWater_Tile_'), (5209840, 'bl loc.imp.objc_msgSend'), (5209988, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5210000, 'bl sym.tileIsWater_Tile_'), (5210084, 'bl sym.makeIntpair_int__int_'), (5210132, 'bl loc.imp.objc_msgSend'), (5210604, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5210748, 'bl sym.imp.__aeabi_idiv'), (5210784, 'bl sym.imp.__aeabi_idiv'), (5210908, 'bl sym.tileIsWater_Tile_'), (5211108, 'bl sym.makeIntpair_int__int_'), (5211136, 'bl loc.imp.objc_msgSend'), (5211280, 'bl loc.imp.objc_msgSend'), (5211324, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5211376, 'bl sym.makeIntpair_int__int_'), (5211408, 'bl loc.imp.objc_msgSend'), (5211452, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5211516, 'bl loc.imp.objc_msgSend'), (5211552, 'bl loc.imp.objc_msgSend'), (5211692, 'blx r2')],
        branches=[(5209520, 'beq', 5209528), (5209524, 'b', 5211696), (5209560, 'beq', 5209568), (5209564, 'b', 5211696), (5209704, 'blt', 5210200), (5209756, 'beq', 5209852), (5209848, 'b', 5211696), (5209900, 'bge', 5210196), (5210012, 'beq', 5210144), (5210140, 'b', 5210196), (5210144, 'b', 5210148), (5210160, 'b', 5209864), (5210196, 'b', 5210200), (5210232, 'bge', 5211588), (5210444, 'ble', 5211584), (5210648, 'beq', 5210872), (5210884, 'beq', 5211580), (5210900, 'beq', 5211580), (5210920, 'bne', 5211580), (5210936, 'beq', 5210956), (5210952, 'bne', 5211580), (5210972, 'ble', 5211580), (5211580, 'b', 5211584), (5211584, 'b', 5211588), (5211648, 'ble', 5211696)],
        semantics=('[VinePlant update:accurateDT:isSimulation:] (imp 0x004f7cf0, 622w): the tick - objc x7 + **`tileIsWater` x3** (the vine grows over WATER!) + `tileAtWorldPositionLoaded` x3 + makeIntpair x3 + **`reloadDrawBlockDynamicObjectQuad`** + `__aeabi_idiv` x2 + consts 0x384/0xff/0x400/0x7c.\n'),
    ),
    dict(
        name='v_dieofoldage',
        method='VinePlant -[dieOfOldAge]',
        types='v8@0:4',
        start=5211816,
        end=5212780,
        disasm='disasm_worldtileloader_v_dieofoldage.txt',
        base_add=5211832,
        base_literal=5212776,
        boundary='ARM.exidx end 0x004f8a6c (listing bound); next ObjC IMP 0x004f8a6c VinePlant -[tileIsKindOfSelf:]',
        selectors={
                 0x4f8a28: (15193924, 'sowPlantNearParent:'),
                 0x4f8a38: (15193920, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
                 0x4f8a50: (15193868, 'objectType'),
                 0x4f8a54: (15193872, 'dynamicWorldChangedAtPos:objectType:'),
                 0x4f8a5c: (15193840, 'tileIsKindOfSelf:'),
                 0x4f8a64: (15193792, 'worldContentsChangedAtPos:'),
        },
        imports={
                 0x4f8a24: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f8a2c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4f8a30: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f8a3c: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f8a40: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x4f8a44: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x4f8a4c: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x4f8a58: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(5211816, 'push {r4, r5, r6, sl, fp, lr}'), (5212776, 'adcseq r7, r6, r4, lsr r4')],
        calls=[(5211848, 'bl 0x4f688c'), (5212020, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5212092, 'blx r3'), (5212212, 'bl sym.makeIntpair_int__int_'), (5212240, 'bl loc.imp.objc_msgSend'), (5212436, 'bl loc.imp.objc_msgSend'), (5212472, 'bl loc.imp.objc_msgSend'), (5212636, 'bl loc.imp.objc_msgSend'), (5212692, 'blx r3')],
        branches=[(5211880, 'ble', 5212504), (5211932, 'bge', 5212264), (5212040, 'beq', 5212244), (5212104, 'beq', 5212244), (5212244, 'b', 5212248), (5212260, 'b', 5211896), (5212500, 'b', 5212696)],
        semantics=("[VinePlant dieOfOldAge] (imp 0x004f86a8, 241w): the age death - objc x4 + the helper 0x4f688c + `tileAtWorldPositionLoaded` + makeIntpair (the vine's death routine, plant-specific).\n"),
    ),
    dict(
        name='v_kindself',
        method='VinePlant -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=5212780,
        end=5212832,
        disasm='disasm_worldtileloader_v_kindself.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f8aa0 (listing bound); next ObjC IMP 0x004f8aa0 VinePlant -[plantType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5212780, 'sub sp, sp, 0xc'), (5212828, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[VinePlant tileIsKindOfSelf:] (imp 0x004f8a6c, 13w): membership (the +0xb slot family).\n'),
    ),
    dict(
        name='v_planttype',
        method='VinePlant -[plantType]',
        types='i8@0:4',
        start=5212832,
        end=5212860,
        disasm='disasm_worldtileloader_v_planttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f8abc (listing bound); next ObjC IMP 0x004f8abc VinePlant -[isRequiredSoilType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5212832, 'sub sp, sp, 8'), (5212856, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[VinePlant plantType] (imp 0x004f8aa0, 7w): the plant-type constant.\n'),
    ),
    dict(
        name='v_soiltype',
        method='VinePlant -[isRequiredSoilType:]',
        types='c12@0:4i8',
        start=5212860,
        end=5213016,
        disasm='disasm_worldtileloader_v_soiltype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f8b58 (listing bound); next ObjC IMP 0x004f8b58 VinePlant -[gatherProgressForTile:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5212860, 'sub sp, sp, 0x10'), (5213012, 'bx lr')],
        calls=[],
        branches=[(5212892, 'beq', 5212996), (5212912, 'beq', 5212996), (5212932, 'beq', 5212996), (5212952, 'beq', 5212996), (5212972, 'beq', 5212996)],
        semantics=("[VinePlant isRequiredSoilType:] (imp 0x004f8abc, 39w): the soil membership (cmp chain; the vine's own set).\n"),
    ),
    dict(
        name='v_gatherprogress',
        method='VinePlant -[gatherProgressForTile:]',
        types='i16@0:4{?=ii}8',
        start=5213016,
        end=5213284,
        disasm='disasm_worldtileloader_v_gatherprogress.txt',
        base_add=5213028,
        base_literal=5213280,
        boundary='ARM.exidx end 0x004f8c64 (listing bound); next ObjC IMP 0x004f8c64 VinePlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        selectors={},
        imports={},
        ivars={
                 0x4f8c50: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f8c54: (17155532, 'OBJC_IVAR_$_Plant.gatherProgress', 80),
                 0x4f8c5c: (17155492, 'OBJC_IVAR_$_VinePlant.belowGatherProgress', 112),
        },
        classes={},
        instructions=[(5213016, 'push {fp, lr}'), (5213280, 'adcseq r6, r6, r8, lsl 31')],
        calls=[],
        branches=[(5213088, 'ble', 5213220), (5213132, 'bge', 5213220), (5213216, 'b', 5213252)],
        semantics=('[VinePlant gatherProgressForTile:] (imp 0x004f8b58, 67w): the gather progress (the slot read; 3 branches).\n'),
    ),
    dict(
        name='v_harvested',
        method='VinePlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        types='i24@0:4{?=ii}8@16i20',
        start=5213284,
        end=5215596,
        disasm='disasm_worldtileloader_v_harvested.txt',
        base_add=5213300,
        base_literal=5215592,
        boundary='ARM.exidx end 0x004f956c (listing bound); next ObjC IMP 0x004f956c VinePlant -[setGatherProgress:forTile:]',
        selectors={
                 0x4f951c: (15193868, 'objectType'),
                 0x4f9520: (15193872, 'dynamicWorldChangedAtPos:objectType:'),
                 0x4f952c: (15193792, 'worldContentsChangedAtPos:'),
                 0x4f953c: (15193788, 'macroTiles'),
                 0x4f9544: (15193936, 'removePlantWithoutCreatingFreeblocks'),
                 0x4f9548: (15193840, 'tileIsKindOfSelf:'),
                 0x4f9554: (15193796, 'maxAgeGeneVariation'),
                 0x4f9558: (15193928, 'growthRateGeneVariation'),
                 0x4f955c: (15193932, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x4f9540: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x4f950c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f9510: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x4f9514: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x4f9524: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4f9530: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f9534: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(5213284, 'push {r4, r5, r6, sl, fp, lr}'), (5215592, 'adcseq r6, r6, r8, ror lr')],
        calls=[(5213756, 'bl loc.imp.objc_msgSend'), (5213792, 'bl loc.imp.objc_msgSend'), (5213880, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5214000, 'bl loc.imp.objc_msgSend'), (5214032, 'bl loc.imp.objc_msgSend'), (5214132, 'bl loc.imp.objc_msgSend'), (5214240, 'bl loc.imp.objc_msgSend'), (5214416, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5214488, 'blx r3'), (5214504, 'bl 0x4f688c'), (5214576, 'bl sym.makeIntpair_int__int_'), (5214584, 'bl sym.tileIsSolid_Tile_'), (5214712, 'bl loc.imp.objc_msgSend'), (5214744, 'bl loc.imp.objc_msgSend'), (5214832, 'bl loc.imp.objc_msgSend'), (5214936, 'bl sym.makeIntpair_int__int_'), (5214964, 'bl loc.imp.objc_msgSend'), (5215228, 'bl loc.imp.objc_msgSend'), (5215272, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5215320, 'bl sym.makeIntpair_int__int_'), (5215352, 'bl loc.imp.objc_msgSend'), (5215396, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5215480, 'blx r2')],
        branches=[(5213380, 'bne', 5215488), (5213420, 'bgt', 5215488), (5213472, 'bpl', 5213528), (5213524, 'b', 5213548), (5213544, 'b', 5213548), (5213612, 'bpl', 5213628), (5213624, 'b', 5213644), (5213828, 'bge', 5214992), (5213900, 'bne', 5214244), (5213924, 'bge', 5214168), (5214160, 'b', 5213912), (5214332, 'bge', 5214988), (5214436, 'beq', 5214968), (5214500, 'beq', 5214968), (5214516, 'ble', 5214836), (5214596, 'beq', 5214640), (5214968, 'b', 5214972), (5214984, 'b', 5214296), (5214988, 'b', 5214992), (5215084, 'bge', 5215100), (5215096, 'b', 5215108), (5215436, 'bne', 5215484), (5215484, 'b', 5215488)],
        semantics=('[VinePlant tileHarvested:removeBlockhead:correctToolMultiplier:] (imp 0x004f8c64, 578w): the harvest - objc x12 + makeIntpair x3 + **`reloadDrawBlockDynamicObjectQuad` x2** + `tileIsSolid` + the helper 0x4f688c + consts 0x384/0x127/0x10 (1 unclassified = the 0x3fffffff half-max sentinel @0x4f954c).\n'),
    ),
    dict(
        name='v_setgather',
        method='VinePlant -[setGatherProgress:forTile:]',
        types='v20@0:4i8{?=ii}12',
        start=5215596,
        end=5215936,
        disasm='disasm_worldtileloader_v_setgather.txt',
        base_add=5215608,
        base_literal=5215932,
        boundary='ARM.exidx end 0x004f96c0 (listing bound); next ObjC IMP 0x004f96c0 VinePlant -[numberOfOccupiedTilesBelow]',
        selectors={},
        imports={},
        ivars={
                 0x4f96a8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f96ac: (17155532, 'OBJC_IVAR_$_Plant.gatherProgress', 80),
                 0x4f96b0: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f96b8: (17155492, 'OBJC_IVAR_$_VinePlant.belowGatherProgress', 112),
        },
        classes={},
        instructions=[(5215596, 'push {r4, lr}'), (5215932, 'adcseq r6, r6, r4, ror r5')],
        calls=[],
        branches=[(5215672, 'bge', 5215872), (5215740, 'bgt', 5215868), (5215784, 'bge', 5215868), (5215868, 'b', 5215904)],
        semantics=('[VinePlant setGatherProgress:forTile:] (imp 0x004f956c, 85w): the gather write.\n'),
    ),
    dict(
        name='v_tilesbelow',
        method='VinePlant -[numberOfOccupiedTilesBelow]',
        types='i8@0:4',
        start=5215936,
        end=5215996,
        disasm='disasm_worldtileloader_v_tilesbelow.txt',
        base_add=5215944,
        base_literal=5215992,
        boundary='ARM.exidx end 0x004f96fc (listing bound); next ObjC IMP 0x004f96fc VinePlant -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0x4f96f4: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
        },
        classes={},
        instructions=[(5215936, 'sub sp, sp, 8'), (5215992, 'adcseq r6, r6, r4, lsr 8')],
        calls=[],
        branches=[],
        semantics=('[VinePlant numberOfOccupiedTilesBelow] (imp 0x004f96c0, 15w): the below count.\n'),
    ),
    dict(
        name='v_setneedsremoved',
        method='VinePlant -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=5215996,
        end=5216136,
        disasm='disasm_worldtileloader_v_setneedsremoved.txt',
        base_add=5216012,
        base_literal=5216132,
        boundary='ARM.exidx end 0x004f9788 (listing bound); next ObjC IMP 0x004f9788 VinePlant -[droppedItemType]',
        selectors={
                 0x4f977c: (15193940, 'setNeedsRemoved:'),
        },
        imports={
                 0x4f9778: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x4f9780: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5215996, 'push {r4, r5, fp, lr}'), (5216132, 'adcseq r6, r6, r0, ror 7')],
        calls=[(5216108, 'blx lr')],
        branches=[],
        semantics=('[VinePlant setNeedsRemoved:] (imp 0x004f96fc, 35w): the removed-flag chain.\n'),
    ),
    dict(
        name='v_droppeditem',
        method='VinePlant -[droppedItemType]',
        types='i8@0:4',
        start=5216136,
        end=5216164,
        disasm='disasm_worldtileloader_v_droppeditem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x004f97a4 (listing bound); next ObjC IMP 0x004f97a4 VinePlant -[staticGeometryForegroundDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(5216136, 'sub sp, sp, 8'), (5216160, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[VinePlant droppedItemType] (imp 0x004f9788, 7w): the dropped item.\n'),
    ),
    dict(
        name='v_fgquadcount',
        method='VinePlant -[staticGeometryForegroundDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=5216164,
        end=5216888,
        disasm='disasm_worldtileloader_v_fgquadcount.txt',
        base_add=5216180,
        base_literal=5216884,
        boundary='ARM.exidx end 0x004f9a78 (listing bound); next ObjC IMP 0x004f9a78 VinePlant -[addForegroundDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={
                 0x4f9a64: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4f9a68: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4f9a70: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(5216164, 'push {r4, sl, fp, lr}'), (5216884, 'adcseq r6, r6, r8, lsr r3')],
        calls=[(5216236, 'bl sym.imp.__aeabi_idiv'), (5216512, 'bl sym.macroPosForWorldPos_intpair__World_')],
        branches=[(5216256, 'beq', 5216272), (5216268, 'b', 5216856), (5216368, 'ble', 5216384), (5216380, 'b', 5216856), (5216424, 'bge', 5216440), (5216436, 'b', 5216856), (5216528, 'beq', 5216572), (5216548, 'bne', 5216556), (5216552, 'b', 5216568), (5216564, 'b', 5216856), (5216568, 'b', 5216572), (5216652, 'bge', 5216668), (5216664, 'b', 5216676), (5216768, 'bge', 5216784), (5216780, 'b', 5216792)],
        semantics=('[VinePlant staticGeometryForegroundDrawQuadCountForMacroPos:] (imp 0x004f97a4, 181w): the foreground quad count - `macroPosForWorldPos` + `__aeabi_idiv` (the count derivation).\n'),
    ),
    dict(
        name='v_addfgquad',
        method='VinePlant -[addForegroundDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=5216888,
        end=5219048,
        disasm='disasm_worldtileloader_v_addfgquad.txt',
        base_add=5216908,
        base_literal=5219044,
        boundary='ARM.exidx end 0x004fa2e8 (listing bound); next ObjC IMP 0x004fa3d4 VinePlant -[removeFromMacroBlock]',
        selectors={},
        imports={},
        ivars={
                 0x4fa2d0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4fa2d4: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
                 0x4fa2dc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4fa2e0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(5216888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5219044, 'adcseq r6, r6, r0, rrx')],
        calls=[(5216980, 'bl sym.imp.__aeabi_idiv'), (5217256, 'bl sym.macroPosForWorldPos_intpair__World_'), (5217604, 'bl method.Vector2.operator_float__'), (5217640, 'bl method.Vector2.operator_float__'), (5217668, 'bl 0x4fa2e8'), (5217740, 'bl sym.imp.__modsi3'), (5217756, 'bl sym.imp.__aeabi_idiv'), (5218132, 'bl 0x4fa35c'), (5218140, 'bl sym.imp.__modsi3'), (5218448, 'bl 0x4fa398'), (5218468, 'bl 0x4fa398'), (5218488, 'bl 0x4fa398'), (5218508, 'bl 0x4fa398'), (5218956, 'bl sym.fillArbitraryQuadBuffer_float__int___GLKMatrix4__float___GLKVector3___GLKVector3___GLKVector3___GLKVector3__float__float__float__float__int__int_')],
        branches=[(5217000, 'beq', 5217016), (5217012, 'b', 5218996), (5217112, 'ble', 5217128), (5217124, 'b', 5218996), (5217168, 'bge', 5217184), (5217180, 'b', 5218996), (5217272, 'beq', 5217316), (5217292, 'bne', 5217300), (5217296, 'b', 5217312), (5217308, 'b', 5218996), (5217312, 'b', 5217316), (5217396, 'bge', 5217412), (5217408, 'b', 5217420), (5217512, 'bge', 5217528), (5217524, 'b', 5217536), (5217928, 'bge', 5218988), (5217976, 'bne', 5218028), (5218024, 'b', 5218204), (5218044, 'bne', 5218128), (5218092, 'b', 5218200), (5218148, 'bne', 5218196), (5218196, 'b', 5218200), (5218200, 'b', 5218204), (5218984, 'b', 5217916)],
        semantics=('[VinePlant addForegroundDrawQuadData:fromIndex:forMacroPos:] (imp 0x004f9a78, 540w): the foreground quad emitter - **`fillArbitraryQuadBuffer`** (the arbitrary-quad fill variant!) + **`macroPosForWorldPos(intpair, World*)`** + the helpers 0x4fa398 x4 / 0x4fa2e8 / 0x4fa35c + `__aeabi_idiv` x2 + `__modsi3` x2 + consts 0x20/0xbf00 (-0.5f bits)/0x1be.\n'),
    ),
    dict(
        name='v_rmmacro',
        method='VinePlant -[removeFromMacroBlock]',
        types='v8@0:4',
        start=5219284,
        end=5219696,
        disasm='disasm_worldtileloader_v_rmmacro.txt',
        base_add=5219300,
        base_literal=5219692,
        boundary='ARM.exidx end 0x004fa570 (listing bound); next ObjC IMP 0x004fa570 VinePlant -[availableFood]',
        selectors={
                 0x4fa550: (15193816, 'removeFromMacroBlock'),
                 0x4fa564: (15193788, 'macroTiles'),
        },
        imports={
                 0x4fa54c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x4fa558: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x4fa560: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x4fa568: (17155484, 'OBJC_IVAR_$_VinePlant.numberOfOccupiedTilesBelow', 180),
        },
        classes={
                 0x4fa554: (15252544, 'OBJC_CLASS_$_VinePlant'),
        },
        instructions=[(5219284, 'push {r4, sl, fp, lr}'), (5219692, 'adcseq r5, r6, r8, lsl 14')],
        calls=[(5219404, 'bl loc.imp.objc_msgSend'), (5219448, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5219504, 'bl sym.makeIntpair_int__int_'), (5219536, 'bl loc.imp.objc_msgSend'), (5219580, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (5219648, 'blx r3')],
        branches=[],
        semantics=('[VinePlant removeFromMacroBlock] (imp 0x004fa3d4, 103w): the removal hook.\n'),
    ),
    dict(
        name='v_availfood',
        method='VinePlant -[availableFood]',
        types='f8@0:4',
        start=5219696,
        end=5219844,
        disasm='disasm_worldtileloader_v_availfood.txt',
        base_add=5219720,
        base_literal=5219764,
        boundary='ARM.exidx end 0x004fa604 (listing bound); next ObjC IMP 0x004fa5b8 VinePlant -[setAvailableFood:]',
        selectors={},
        imports={},
        ivars={
                 0x4fa5b0: (17155508, 'OBJC_IVAR_$_VinePlant.availableFood', 100),
                 0x4fa5fc: (17155508, 'OBJC_IVAR_$_VinePlant.availableFood', 100),
        },
        classes={},
        instructions=[(5219696, 'sub sp, sp, 0xc'), (5219840, 'adcseq r5, r6, r4, lsl r5')],
        calls=[],
        branches=[],
        semantics=('[VinePlant availableFood] (imp 0x004fa570, 37w): the food float read.\n'),
    ),
    dict(
        name='v_setavailfood',
        method='VinePlant -[setAvailableFood:]',
        types='v12@0:4f8',
        start=5219768,
        end=5219844,
        disasm='disasm_worldtileloader_v_setavailfood.txt',
        base_add=5219800,
        base_literal=5219840,
        boundary='ARM.exidx end 0x004fa604 (listing bound); next ObjC IMP 0x004fa764 NetPlayerUI -[initWithWindowInfo:netPlayerButton:cache:localPlayerIsMod:showReportButton:]',
        selectors={},
        imports={},
        ivars={
                 0x4fa5fc: (17155508, 'OBJC_IVAR_$_VinePlant.availableFood', 100),
        },
        classes={},
        instructions=[(5219768, 'sub sp, sp, 0xc'), (5219840, 'adcseq r5, r6, r4, lsl r5')],
        calls=[],
        branches=[],
        semantics=('[VinePlant setAvailableFood:] (imp 0x004fa5b8, 19w): the food float write.\n'),
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
        'batch': 'VinePlant (E92): the water vine - temperature gate, water substrates, arbitrary-quad emitter; 24 bodies',
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
                        default=NATIVE / 'vine_plant.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale vine_plant.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
