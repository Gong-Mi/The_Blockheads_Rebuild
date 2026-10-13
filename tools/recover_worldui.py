#!/usr/bin/env python3
"""Hash-gated recovery of the World store, repair and idle-timer line (E110).

The World store/repair/idle line: the time-crystal button and repair
engine, the tile-protection policy, the double-time prompt and the
idle-timer keeper:
14 bodies, 2645 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORLD_UI.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.backWallRemovesWithRepairTool_Tile_': 0x00a12410,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.macroPosForWorldPos_intpair__World_': 0x00a16594,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsAir_Tile_': 0x00a12300,
    'bl sym.tileIsNotUnminedBlockSoCanBeRemovedOnRepair_Tile_': 0x00a13778,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='wu_00',
        method='World -[timeCrystalButtonTapped]',
        types='v8@0:4',
        start=5987156,
        end=5989224,
        disasm='disasm_worldtileloader_wu_00.txt',
        base_add=5987172,
        base_literal=5989220,
        boundary='ARM.exidx end 0x005b6368 (listing bound); next ObjC IMP 0x005b6368 World -[pauseButtonTapped]',
        selectors={
                 0x5b62f4: (15195604, 'count'),
                 0x5b62f8: (15195692, 'blockheads'),
                 0x5b6300: (15196624, 'requiresMotionEvents'),
                 0x5b6304: (15196444, 'activeBlockhead'),
                 0x5b6308: (15196268, 'regenerating'),
                 0x5b630c: (15196320, 'onTradeMission'),
                 0x5b6318: (15196416, 'workbenchAtPos:'),
                 0x5b6320: (15196632, 'center:'),
                 0x5b6328: (15197548, 'craftUI'),
                 0x5b6330: (15197444, 'workbenchTapped:hasCancel:'),
                 0x5b6334: (15197544, 'setSelectedIndex:'),
                 0x5b633c: (15196488, 'isCloudGame'),
                 0x5b6360: (15197540, 'showTimeCrystalUITapped'),
        },
        imports={
                 0x5b62f0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5b62fc: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5b6310: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
                 0x5b631c: (17155884, 'OBJC_IVAR_$_World.translationGoal', 632),
                 0x5b6324: (17155872, 'OBJC_IVAR_$_World.pinchScale', 400),
                 0x5b632c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5b6338: (17155896, 'OBJC_IVAR_$_World.expertMode', 228),
                 0x5b6340: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
                 0x5b6348: (17156484, 'OBJC_IVAR_$_World.followingBlockhead', 3345),
                 0x5b634c: (17155860, 'OBJC_IVAR_$_World.accurateTranslation', 624),
                 0x5b6350: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
        },
        classes={},
        instructions=[(5987156, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5989220, 'adceq sb, sl, r8, lsl 31')],
        calls=[(5987252, 'blx r3'), (5987268, 'blx r2'), (5987360, 'blx ip'), (5987376, 'blx r2'), (5987472, 'blx ip'), (5987488, 'blx r2'), (5987584, 'blx ip'), (5987600, 'blx r2'), (5987676, 'blx r2'), (5987800, 'bl loc.imp.objc_msgSend'), (5988048, 'blx ip'), (5988148, 'blx r3'), (5988196, 'blx lr'), (5988256, 'blx r2'), (5988336, 'bl loc.imp.objc_msgSend_stret'), (5988372, 'bl sym.imp.memset'), (5988480, 'bl method.Vector2.Vector2_float__float_'), (5988608, 'bl method.Vector2.operator_float__'), (5988644, 'bl method.Vector2.operator_float__'), (5988696, 'bl sym.imp.__aeabi_idiv'), (5988800, 'bl method.Vector2.operator_float__'), (5988876, 'bl method.Vector2.operator_float__'), (5988912, 'bl method.Vector2.operator_float__'), (5988968, 'bl sym.imp.__aeabi_idiv'), (5989072, 'bl method.Vector2.operator_float__')],
        branches=[(5987276, 'beq', 5987616), (5987388, 'bne', 5987616), (5987500, 'bne', 5987616), (5987612, 'beq', 5987684), (5987680, 'b', 5989096), (5987820, 'beq', 5988400), (5988312, 'beq', 5988344), (5988340, 'b', 5988376), (5988396, 'b', 5988508), (5988720, 'ble', 5988824), (5988820, 'b', 5989096), (5988992, 'bpl', 5989092), (5989092, 'b', 5989096)],
        semantics=('[World timeCrystalButtonTapped] (imp 0x005b5b54, 517w): the time-crystal button flow - counts the blockheads and gates on requiresMotionEvents/activeBlockhead, finds workbenchAtPos:, centers the camera on it (Vector2 operator float* x6 with translationGoal/pinchScale/accurateTranslation/worldWidthMacro math, __aeabi_idiv x2, Vector2 ctor) and opens the UI (craftUI workbenchTapped:hasCancel:, setSelectedIndex:, isCloudGame, showTimeCrystalUITapped).\n'),
    ),
    dict(
        name='wu_01',
        method='World -[doRepairForTileAtPos:]',
        types='v16@0:4{?=ii}8',
        start=6131576,
        end=6133532,
        disasm='disasm_worldtileloader_wu_01.txt',
        base_add=6131592,
        base_literal=6133528,
        boundary='ARM.exidx end 0x005d971c (listing bound); next ObjC IMP 0x005d971c World -[setRepairMode:]',
        selectors={
                 0x5d96d0: (15198388, 'doRepairForTileAtPos:'),
                 0x5d96dc: (15196416, 'workbenchAtPos:'),
                 0x5d96e4: (15196100, 'placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:'),
                 0x5d96e8: (15195776, 'level'),
                 0x5d96f4: (15196812, 'loadSnowSurfaceBlockAtPos:loadSnow:'),
                 0x5d96fc: (15196816, 'loadSurfaceBlockAtPos:'),
                 0x5d9710: (15196756, 'updateSunLightForTile:atPos:world:'),
                 0x5d9714: (15196712, 'worldChangedAtPos:sendReliably:'),
        },
        imports={},
        ivars={
                 0x5d96c4: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5d96c8: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5d96d4: (17155912, 'OBJC_IVAR_$_World.startPortalPos', 144),
        },
        classes={
                 0x5d9708: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(6131576, 'push {r4, r5, fp, lr}'), (6133528, 'adceq r6, r8, r4, ror 22')],
        calls=[(6131668, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6131752, 'bl loc.imp.objc_msgSend'), (6131760, 'bl sym.tileIsNotUnminedBlockSoCanBeRemovedOnRepair_Tile_'), (6131804, 'bl sym.backWallRemovesWithRepairTool_Tile_'), (6132228, 'bl loc.imp.objc_msgSend'), (6132364, 'bl loc.imp.objc_msgSend'), (6132444, 'bl loc.imp.objc_msgSend'), (6132472, 'bl loc.imp.objc_msgSend'), (6132652, 'bl sym.tileIsAir_Tile_'), (6132684, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6132712, 'bl sym.tileIsSolid_Tile_'), (6132732, 'bl sym.tileIsWater_Tile_'), (6132836, 'bl loc.imp.objc_msgSend'), (6132856, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6132884, 'bl sym.tileIsWater_Tile_'), (6132976, 'bl loc.imp.objc_msgSend'), (6133000, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6133028, 'bl sym.tileIsWater_Tile_'), (6133120, 'bl loc.imp.objc_msgSend'), (6133144, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6133172, 'bl sym.tileIsWater_Tile_'), (6133264, 'bl loc.imp.objc_msgSend'), (6133360, 'bl loc.imp.objc_msgSend'), (6133432, 'bl loc.imp.objc_msgSend')],
        branches=[(6131648, 'bne', 6131656), (6131652, 'b', 6133436), (6131688, 'beq', 6133436), (6131772, 'beq', 6131836), (6131816, 'beq', 6131832), (6131832, 'b', 6131836), (6131976, 'bne', 6132648), (6132016, 'blt', 6132080), (6132060, 'bgt', 6132080), (6132076, 'b', 6132644), (6132120, 'bne', 6132640), (6132248, 'bne', 6132452), (6132488, 'bhi', 6132632), (6132548, 'b', 6132636), (6132564, 'b', 6132636), (6132580, 'b', 6132636), (6132596, 'b', 6132636), (6132612, 'b', 6132636), (6132628, 'b', 6132636), (6132632, 'b', 6132636), (6132636, 'b', 6132640), (6132640, 'b', 6132644), (6132644, 'b', 6132648), (6132664, 'beq', 6133280), (6132704, 'beq', 6132840), (6132724, 'bne', 6132764), (6132744, 'beq', 6132840), (6132760, 'ble', 6132840), (6132876, 'beq', 6132984), (6132896, 'beq', 6132984), (6132912, 'ble', 6132984), (6132980, 'b', 6133276), (6133020, 'beq', 6133128), (6133040, 'beq', 6133128), (6133056, 'ble', 6133128), (6133124, 'b', 6133272), (6133164, 'beq', 6133268), (6133184, 'beq', 6133268), (6133200, 'ble', 6133268), (6133268, 'b', 6133272), (6133272, 'b', 6133276), (6133276, 'b', 6133280)],
        semantics=('[World doRepairForTileAtPos:] (imp 0x005d8f78, 489w): the repair engine - five tileAtWorldPositionLoaded probes gated by tileIsWater x4 / tileIsNotUnminedBlockSoCanBeRemovedOnRepair / backWallRemovesWithRepairTool / tileIsAir / tileIsSolid; repairs through WorldHelper (placeWorkbenchOfType:atPos:saveDict:placedByClient:placedByBlockhead:placedByClientName:), reloads the surface (loadSnowSurfaceBlockAtPos:/loadSurfaceBlockAtPos:), relights (updateSunLightForTile:atPos:world:) and broadcasts (worldChangedAtPos:sendReliably:); constants 0x2f/0x19/0x21/0x22/0x23/0x24/0x25.\n'),
    ),
    dict(
        name='wu_02',
        method='World -[tileIsProtectedAtPos:againstClient:]',
        types='c20@0:4{?=ii}8@16',
        start=6113048,
        end=6116104,
        disasm='disasm_worldtileloader_wu_02.txt',
        base_add=6113064,
        base_literal=6116100,
        boundary='ARM.exidx end 0x005d5308 (listing bound); next ObjC IMP 0x005d5308 World -[tileIsProtectedAtPos:againstBlockhead:]',
        selectors={
                 0x5d52b0: (15196728, 'playerIsAdminWithID:'),
                 0x5d52b8: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5d52bc: (15195624, 'objectForKey:'),
                 0x5d52c4: (15195708, 'stringWithFormat:'),
                 0x5d52d8: (15195848, 'intValue'),
                 0x5d52e0: (15195988, 'worldWidthMacro'),
                 0x5d5300: (15198332, 'safeCaseInsensitiveCompare:'),
        },
        imports={
                 0x5d52ac: (17151904, 'objc_msgSend'),
                 0x5d52c0: (16232888, '__CFConstantStringClassReference'),
                 0x5d52d4: (16233816, '__CFConstantStringClassReference'),
                 0x5d52dc: (16233768, '__CFConstantStringClassReference'),
                 0x5d52f4: (16233832, '__CFConstantStringClassReference'),
                 0x5d52f8: (16233784, '__CFConstantStringClassReference'),
                 0x5d52fc: (16233800, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x5d52a0: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x5d52a4: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5d52a8: (17156328, 'OBJC_IVAR_$_World.isAdmin', 3209),
                 0x5d52b4: (17155948, 'OBJC_IVAR_$_World.ownershipSignPositions', 3324),
                 0x5d52cc: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
        },
        classes={
                 0x5d52c8: (15245304, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6113048, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6116100, 'adceq fp, r8, r4, asr 7')],
        calls=[(6113292, 'blx r3'), (6113744, 'blx r3'), (6113876, 'bl sym.makeIntpair_int__int_'), (6113940, 'bl sym.macroPosForWorldPos_intpair__World_'), (6114360, 'blx sl'), (6114392, 'blx r3'), (6114416, 'bl sym.imp.memset'), (6114464, 'blx lr'), (6114564, 'bl sym.imp.objc_enumerationMutation'), (6114700, 'blx ip'), (6114716, 'blx r2'), (6114760, 'blx r3'), (6114848, 'blx ip'), (6114864, 'blx r2'), (6114936, 'bl loc.imp.objc_msgSend'), (6114960, 'bl sym.imp.__aeabi_idiv'), (6115028, 'bl loc.imp.objc_msgSend'), (6115120, 'bl loc.imp.objc_msgSend'), (6115136, 'bl sym.imp.__aeabi_idiv'), (6115204, 'bl loc.imp.objc_msgSend'), (6115412, 'blx ip'), (6115428, 'blx r2'), (6115472, 'blx r3'), (6115560, 'blx ip'), (6115576, 'blx r2'), (6115692, 'blx r3'), (6115764, 'blx r3'), (6115904, 'blx ip')],
        branches=[(6113132, 'beq', 6113184), (6113168, 'bne', 6113184), (6113180, 'b', 6113548), (6113220, 'beq', 6113408), (6113304, 'beq', 6113320), (6113316, 'b', 6115988), (6113352, 'beq', 6113400), (6113388, 'bne', 6113400), (6113400, 'b', 6113404), (6113404, 'b', 6113544), (6113440, 'beq', 6113456), (6113452, 'b', 6115988), (6113488, 'beq', 6113536), (6113524, 'bne', 6113536), (6113536, 'b', 6113540), (6113540, 'b', 6113544), (6113544, 'b', 6113548), (6113584, 'bne', 6113624), (6113596, 'beq', 6113612), (6113608, 'b', 6115988), (6113620, 'b', 6115988), (6113660, 'beq', 6113776), (6113672, 'bne', 6113776), (6113756, 'beq', 6113772), (6113768, 'b', 6115988), (6113772, 'b', 6113776), (6113796, 'beq', 6115956), (6113824, 'bge', 6114000), (6113844, 'bge', 6113980), (6113976, 'b', 6113836), (6113980, 'b', 6113984), (6113996, 'b', 6113816), (6114016, 'bge', 6115952), (6114476, 'beq', 6115928), (6114556, 'beq', 6114568), (6114772, 'beq', 6114872), (6114972, 'blt', 6115060), (6115056, 'b', 6115260), (6115148, 'bge', 6115236), (6115232, 'b', 6115252), (6115280, 'bgt', 6115804), (6115304, 'blt', 6115804), (6115484, 'beq', 6115584), (6115604, 'bgt', 6115800), (6115628, 'blt', 6115800), (6115712, 'beq', 6115788), (6115772, 'bne', 6115788), (6115784, 'b', 6115988), (6115796, 'b', 6115800), (6115800, 'b', 6115804), (6115804, 'b', 6115808), (6115832, 'blo', 6114520), (6115924, 'bne', 6114520), (6115928, 'b', 6115932), (6115932, 'b', 6115936), (6115948, 'b', 6114008), (6115952, 'b', 6115956), (6115964, 'beq', 6115980), (6115976, 'b', 6115988)],
        semantics=('[World tileIsProtectedAtPos:againstClient:] (imp 0x005d4718, 764w): the protection policy - playerIsAdminWithID: check, customRules read, then the ownershipSignPositions enumeration (fast enumeration + objc_enumerationMutation; stringWithFormat:/safeCaseInsensitiveCompare:/intValue per sign) resolving the macro pos (makeIntpair + macroPosForWorldPos + worldWidthMacro + __aeabi_idiv x2); constants 0x10/0x20/0xf.\n'),
    ),
    dict(
        name='wu_03',
        method='World -[showDoubleTimePromptIfGoodTime]',
        types='v8@0:4',
        start=6056088,
        end=6057648,
        disasm='disasm_worldtileloader_wu_03.txt',
        base_add=6056104,
        base_literal=6057644,
        boundary='ARM.exidx end 0x005c6eb0 (listing bound); next ObjC IMP 0x005c6eb0 World -[highestPoint]',
        selectors={
                 0x5c6e54: (15196576, 'displayed'),
                 0x5c6e58: (15197452, 'craftProgressUI'),
                 0x5c6e64: (15197964, 'hungerUI'),
                 0x5c6e68: (15196628, 'addBlockheadUI'),
                 0x5c6e6c: (15197644, 'workbenchChoiceUI'),
                 0x5c6e70: (15197548, 'craftUI'),
                 0x5c6e74: (15196636, 'blockheadUI'),
                 0x5c6e78: (15195616, 'gameBlockingUIDisplayed'),
                 0x5c6e88: (15197968, 'doubleTimePriceString'),
                 0x5c6e8c: (15197972, 'showDoubleTimePromptIfGoodTime:'),
                 0x5c6e94: (15195604, 'count'),
                 0x5c6e98: (15195692, 'blockheads'),
                 0x5c6ea0: (15197976, 'displaySecondBlockheadTipIfGoodTime'),
                 0x5c6ea4: (15195544, 'instance'),
        },
        imports={
                 0x5c6e50: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5c6e5c: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5c6e60: (17156412, 'OBJC_IVAR_$_World.isSimulating', 3140),
                 0x5c6e7c: (17156488, 'OBJC_IVAR_$_World.translatingToGoal', 640),
                 0x5c6e84: (17156312, 'OBJC_IVAR_$_World.doubleTimeUnlocked', 3072),
                 0x5c6e9c: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
        },
        classes={
                 0x5c6ea8: (15245420, 'OBJC_CLASS_$_TipManager'),
        },
        instructions=[(6056088, 'push {r4, r5, r6, sl, fp, lr}'), (6057644, 'adceq sb, sb, r4, asr 4')],
        calls=[(6056192, 'blx r3'), (6056208, 'blx r2'), (6056340, 'blx ip'), (6056356, 'blx r2'), (6056452, 'blx ip'), (6056468, 'blx r2'), (6056564, 'blx ip'), (6056580, 'blx r2'), (6056676, 'blx ip'), (6056692, 'blx r2'), (6056788, 'blx ip'), (6056804, 'blx r2'), (6056880, 'blx r2'), (6056932, 'bl 0x564c54'), (6057092, 'blx lr'), (6057108, 'blx r2'), (6057200, 'blx r3'), (6057316, 'blx ip'), (6057332, 'blx r2'), (6057428, 'blx ip'), (6057444, 'blx r2'), (6057524, 'blx ip'), (6057540, 'blx r2')],
        branches=[(6056220, 'beq', 6057224), (6056256, 'bne', 6057224), (6056368, 'bne', 6057224), (6056480, 'bne', 6057224), (6056592, 'bne', 6057224), (6056704, 'bne', 6057224), (6056816, 'bne', 6057224), (6056892, 'bne', 6057220), (6056928, 'bne', 6057220), (6056960, 'bne', 6057216), (6056996, 'bne', 6057212), (6057128, 'beq', 6057208), (6057208, 'b', 6057212), (6057212, 'b', 6057216), (6057216, 'b', 6057220), (6057220, 'b', 6057224), (6057232, 'bne', 6057544), (6057344, 'beq', 6057544), (6057452, 'bhs', 6057544)],
        semantics=('[World showDoubleTimePromptIfGoodTime] (imp 0x005c6898, 390w): the double-time prompt - gates on every UI surface (craftProgressUI/hungerUI/addBlockheadUI/workbenchChoiceUI/craftUI/blockheadUI displayed + gameBlockingUIDisplayed), reads doubleTimePriceString, calls showDoubleTimePromptIfGoodTime back through the uiManager and displaySecondBlockheadTipIfGoodTime; helper 0x564c54; TipManager instance.\n'),
    ),
    dict(
        name='wu_04',
        method='World -[updateIdleTimerDisabled]',
        types='v8@0:4',
        start=6020764,
        end=6021836,
        disasm='disasm_worldtileloader_wu_04.txt',
        base_add=6020780,
        base_literal=6021832,
        boundary='ARM.exidx end 0x005be2cc (listing bound); next ObjC IMP 0x005be2cc World -[saveSunlightChangedAtPos:]',
        selectors={
                 0x5be294: (15195604, 'count'),
                 0x5be2a0: (15195616, 'gameBlockingUIDisplayed'),
                 0x5be2a8: (15195620, 'countByEnumeratingWithState:objects:count:'),
                 0x5be2ac: (15195692, 'blockheads'),
                 0x5be2b4: (15197704, 'idle'),
                 0x5be2bc: (15197708, 'setIdleTimerDisabled:'),
                 0x5be2c0: (15196168, 'sharedApplication'),
        },
        imports={
                 0x5be290: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5be28c: (17155916, 'OBJC_IVAR_$_World.server', 964),
                 0x5be298: (17155964, 'OBJC_IVAR_$_World.serverClients', 956),
                 0x5be29c: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5be2a4: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
                 0x5be2b0: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x5be2b8: (17156676, 'OBJC_IVAR_$_World.idleTimerDisabled', 933),
        },
        classes={
                 0x5be2c4: (15245432, 'OBJC_CLASS_$_UIApplication'),
        },
        instructions=[(6020764, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6021832, 'adceq r1, sl, r0, asr 24')],
        calls=[(6020900, 'blx r2'), (6021024, 'blx r2'), (6021152, 'bl sym.imp.memset'), (6021188, 'blx r3'), (6021232, 'blx lr'), (6021332, 'bl sym.imp.objc_enumerationMutation'), (6021404, 'blx r2'), (6021532, 'blx ip'), (6021708, 'blx lr'), (6021760, 'blx lr')],
        branches=[(6020836, 'beq', 6020912), (6020908, 'bhi', 6020952), (6020948, 'beq', 6020964), (6020960, 'b', 6021568), (6021036, 'bne', 6021564), (6021244, 'beq', 6021556), (6021324, 'beq', 6021336), (6021416, 'bne', 6021432), (6021428, 'b', 6021560), (6021432, 'b', 6021436), (6021460, 'blo', 6021288), (6021552, 'bne', 6021288), (6021556, 'b', 6021560), (6021560, 'b', 6021564), (6021564, 'b', 6021568), (6021604, 'beq', 6021764)],
        semantics=('[World updateIdleTimerDisabled] (imp 0x005bde9c, 268w): the idle-timer keeper - UIApplication sharedApplication setIdleTimerDisabled: gated on gameBlockingUIDisplayed and the blockheads/serverClients enumeration; idleTimerDisabled ivar; constants 0x10/0x20.\n'),
    ),
    dict(
        name='wu_05',
        method='World -[doubleTimeRestoreTapped]',
        types='v8@0:4',
        start=6039780,
        end=6039976,
        disasm='disasm_worldtileloader_wu_05.txt',
        base_add=6039796,
        base_literal=6039972,
        boundary='ARM.exidx end 0x005c29a8 (listing bound); next ObjC IMP 0x005c29c0 World -[doPortalScreenshot]',
        selectors={
                 0x5c2990: (15197828, 'iapStarted'),
                 0x5c2998: (15197840, 'restoreCompletedTransactions'),
                 0x5c299c: (15197836, 'defaultQueue'),
        },
        imports={
                 0x5c298c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x5c29a0: (15245516, 'OBJC_CLASS_$_SKPaymentQueue'),
        },
        instructions=[(6039780, 'push {r4, r5, r6, r7, fp, lr}'), (6039972, 'invalid')],
        calls=[(6039884, 'blx r3'), (6039900, 'blx r2'), (6039936, 'blx r3')],
        branches=[],
        semantics=('[World doubleTimeRestoreTapped] (imp 0x005c28e4, 49w): the restore-purchases button - SKPaymentQueue defaultQueue restoreCompletedTransactions + iapStarted.\n'),
    ),
    dict(
        name='wu_06',
        method='World -[tileIsProtectedAtPos:againstBlockhead:]',
        types='c20@0:4{?=ii}8@16',
        start=6116104,
        end=6116272,
        disasm='disasm_worldtileloader_wu_06.txt',
        base_add=6116148,
        base_literal=6116264,
        boundary='ARM.exidx end 0x005d53b0 (listing bound); next ObjC IMP 0x005d53b0 World -[displayOwnershipAreas]',
        selectors={
                 0x5d53a4: (15198336, 'localNetID'),
                 0x5d53ac: (15196716, 'tileIsProtectedAtPos:againstClient:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6116104, 'push {fp, lr}'), (6116268, 'invalid')],
        calls=[(6116176, 'bl loc.imp.objc_msgSend'), (6116244, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World tileIsProtectedAtPos:againstBlockhead:] (imp 0x005d5308, 42w): forwards to tileIsProtectedAtPos:againstClient: with localNetID.\n'),
    ),
    dict(
        name='wu_07',
        method='World -[setRepairMode:]',
        types='v12@0:4c8',
        start=6133532,
        end=6133636,
        disasm='disasm_worldtileloader_wu_07.txt',
        base_add=6133544,
        base_literal=6133632,
        boundary='ARM.exidx end 0x005d9784 (listing bound); next ObjC IMP 0x005d9784 World -[repairMode]',
        selectors={},
        imports={},
        ivars={
                 0x5d9778: (17156652, 'OBJC_IVAR_$_World.renderRepairModeConfirm', 3414),
                 0x5d977c: (17156648, 'OBJC_IVAR_$_World.repairMode', 3413),
        },
        classes={},
        instructions=[(6133532, 'push {r4, lr}'), (6133632, 'adceq r6, r8, r4, asr 7')],
        calls=[],
        branches=[],
        semantics=('[World setRepairMode:] (imp 0x005d971c, 26w): bare ivar setter (repairMode; renderRepairModeConfirm flag).\n'),
    ),
    dict(
        name='wu_08',
        method='World -[timeCrystalCloseButtonTapped]',
        types='v8@0:4',
        start=6125836,
        end=6125936,
        disasm='disasm_worldtileloader_wu_08.txt',
        base_add=6125852,
        base_literal=6125932,
        boundary='ARM.exidx end 0x005d79c8; body trimmed at the next IMP 0x005d7970 World -[windStrength]',
        selectors={
                 0x5d7964: (15198352, 'timeCrystalCloseButtonTapped'),
        },
        imports={
                 0x5d7960: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5d7968: (17155956, 'OBJC_IVAR_$_World.uiManager', 240),
        },
        classes={},
        instructions=[(6125836, 'push {fp, lr}'), (6125932, 'invalid')],
        calls=[(6125908, 'blx r3')],
        branches=[],
        semantics=('[World timeCrystalCloseButtonTapped] (imp 0x005d790c, 25w): uiManager forward (listing trimmed at the next IMP).\n'),
    ),
    dict(
        name='wu_09',
        method='World -[resetPauseIdleTimer]',
        types='v8@0:4',
        start=5948240,
        end=5948320,
        disasm='disasm_worldtileloader_wu_09.txt',
        base_add=5948248,
        base_literal=5948312,
        boundary='ARM.exidx end 0x005ac3a0 (listing bound); next ObjC IMP 0x005ac3a0 World -[tap:]',
        selectors={},
        imports={},
        ivars={
                 0x5ac394: (17156492, 'OBJC_IVAR_$_World.pauseIdleTimer', 3264),
        },
        classes={},
        instructions=[(5948240, 'sub sp, sp, 0xc'), (5948316, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[World resetPauseIdleTimer] (imp 0x005ac350, 20w): resets pauseIdleTimer to the pool constant.\n'),
    ),
    dict(
        name='wu_10',
        method='World -[startCloudTopup]',
        types='v8@0:4',
        start=6107744,
        end=6107820,
        disasm='disasm_worldtileloader_wu_10.txt',
        base_add=6107760,
        base_literal=6107816,
        boundary='ARM.exidx end 0x005d32ac (listing bound); next ObjC IMP 0x005d32ac World -[IAPForWorldTopupSucceeeded:transactionID:]',
        selectors={
                 0x5d32a4: (15197828, 'iapStarted'),
        },
        imports={
                 0x5d32a0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6107744, 'push {fp, lr}'), (6107816, 'adceq ip, r8, ip, ror r8')],
        calls=[(6107796, 'blx r3')],
        branches=[],
        semantics=('[World startCloudTopup] (imp 0x005d3260, 19w): iapStarted forward.\n'),
    ),
    dict(
        name='wu_11',
        method='World -[doubleTimeUnlocked]',
        types='c8@0:4',
        start=6135436,
        end=6135496,
        disasm='disasm_worldtileloader_wu_11.txt',
        base_add=6135444,
        base_literal=6135492,
        boundary='ARM.exidx end 0x005d9ec8 (listing bound); next ObjC IMP 0x005d9ec8 World -[worldName]',
        selectors={},
        imports={},
        ivars={
                 0x5d9ec0: (17156312, 'OBJC_IVAR_$_World.doubleTimeUnlocked', 3072),
        },
        classes={},
        instructions=[(6135436, 'sub sp, sp, 8'), (6135492, 'adceq r5, r8, r8, asr ip')],
        calls=[],
        branches=[],
        semantics=('[World doubleTimeUnlocked] (imp 0x005d9e8c, 15w): bare ivar getter.\n'),
    ),
    dict(
        name='wu_12',
        method='World -[repairMode]',
        types='c8@0:4',
        start=6133636,
        end=6133696,
        disasm='disasm_worldtileloader_wu_12.txt',
        base_add=6133644,
        base_literal=6133692,
        boundary='ARM.exidx end 0x005d97c0 (listing bound); next ObjC IMP 0x005d97c0 World -[appDatabase]',
        selectors={},
        imports={},
        ivars={
                 0x5d97b8: (17156648, 'OBJC_IVAR_$_World.repairMode', 3413),
        },
        classes={},
        instructions=[(6133636, 'sub sp, sp, 8'), (6133692, 'adceq r6, r8, r0, ror 6')],
        calls=[],
        branches=[],
        semantics=('[World repairMode] (imp 0x005d9784, 15w): bare ivar getter.\n'),
    ),
    dict(
        name='wu_13',
        method='World -[cloudTopupFailed:]',
        types='v12@0:4i8',
        start=6107720,
        end=6107744,
        disasm='disasm_worldtileloader_wu_13.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x005d3260 (listing bound); next ObjC IMP 0x005d3260 World -[startCloudTopup]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6107720, 'sub sp, sp, 0xc'), (6107740, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[World cloudTopupFailed:] (imp 0x005d3248, 6w): near-empty stub (6 words, no calls).\n'),
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
        'batch': 'World store, repair and idle-timer line (E110): the time-crystal/repair/idle family; 14 bodies',
        'claim': ('a fully-read static map of the World store/repair/idle line; the StoreKit / UIApplication contracts and the IAP server flow are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'world_ui.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale world_ui.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
