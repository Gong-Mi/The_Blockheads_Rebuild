#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: NormalPlant, the first plant subclass: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 5090 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/NORMAL_PLANT.md for the prose and boundaries.
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
    'bl 0xa66604': 0x00a66604,
    'bl 0xa69eec': 0x00a69eec,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clampi_int__int__int_': 0x004c0b70,
    'bl sym.contentsTypeForPlantType_PlantType__bool_': 0x00a653d8,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0x00d948fc,
    'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_': 0x00854138,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='np_objecttype',
        method='NormalPlant -[objectType]',
        types='i8@0:4',
        start=10900268,
        end=10900296,
        disasm='disasm_worldtileloader_np_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a65348 (listing bound); next ObjC IMP 0x00a65348 NormalPlant -[maxAgeBase]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900268, 'sub sp, sp, 8'), (10900292, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant objectType] (imp 0x00a6532c, 7w): the object-type constant.\n'),
    ),
    dict(
        name='np_maxagebase',
        method='NormalPlant -[maxAgeBase]',
        types='f8@0:4',
        start=10900296,
        end=10900344,
        disasm='disasm_worldtileloader_np_maxagebase.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a65378 (listing bound); next ObjC IMP 0x00a65378 NormalPlant -[contentsType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900296, 'sub sp, sp, 0x10'), (10900340, 'strbtmi r0, [r1], -r0')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant maxAgeBase] (imp 0x00a65348, 12w): the base max-age constant.\n'),
    ),
    dict(
        name='np_contentstype',
        method='NormalPlant -[contentsType]',
        types='i8@0:4',
        start=10900344,
        end=10900440,
        disasm='disasm_worldtileloader_np_contentstype.txt',
        base_add=10900360,
        base_literal=10900436,
        boundary='ARM.exidx end 0x00a653d8 (listing bound); next ObjC IMP 0x00a654f4 NormalPlant -[flowerContentsType]',
        selectors={
                 0xa653d0: (15225108, 'plantType'),
        },
        imports={
                 0xa653cc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10900344, 'push {fp, lr}'), (10900436, 'subseq sl, pc, r4, ror 14')],
        calls=[(10900404, 'blx ip'), (10900416, 'bl sym.contentsTypeForPlantType_PlantType__bool_')],
        branches=[],
        semantics=('[NormalPlant contentsType] (imp 0x00a65378, 95w): the tile-contents variant (95w - the plant contents classifier).\n'),
    ),
    dict(
        name='np_flowercontents',
        method='NormalPlant -[flowerContentsType]',
        types='i8@0:4',
        start=10900724,
        end=10900820,
        disasm='disasm_worldtileloader_np_flowercontents.txt',
        base_add=10900740,
        base_literal=10900816,
        boundary='ARM.exidx end 0x00a65554 (listing bound); next ObjC IMP 0x00a65554 NormalPlant -[minAllowedTemperature]',
        selectors={
                 0xa6554c: (15225108, 'plantType'),
        },
        imports={
                 0xa65548: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10900724, 'push {fp, lr}'), (10900816, 'subseq sl, pc, r8, ror 11')],
        calls=[(10900784, 'blx ip'), (10900796, 'bl sym.contentsTypeForPlantType_PlantType__bool_')],
        branches=[],
        semantics=('[NormalPlant flowerContentsType] (imp 0x00a654f4, 24w): the flowering-stage contents variant.\n'),
    ),
    dict(
        name='np_mintemp',
        method='NormalPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=10900820,
        end=10900932,
        disasm='disasm_worldtileloader_np_mintemp.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a655c4 (listing bound); next ObjC IMP 0x00a65570 NormalPlant -[seedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900820, 'sub sp, sp, 8'), (10900928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant minAllowedTemperature] (imp 0x00a65554, 7w): the temperature gate constant.\n'),
    ),
    dict(
        name='np_seeditem',
        method='NormalPlant -[seedItemType]',
        types='i8@0:4',
        start=10900848,
        end=10900932,
        disasm='disasm_worldtileloader_np_seeditem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a655c4 (listing bound); next ObjC IMP 0x00a6558c NormalPlant -[folliageItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900848, 'sub sp, sp, 8'), (10900928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant seedItemType] (imp 0x00a65570, 7w): the seed item constant.\n'),
    ),
    dict(
        name='np_folliageitem',
        method='NormalPlant -[folliageItemType]',
        types='i8@0:4',
        start=10900876,
        end=10900932,
        disasm='disasm_worldtileloader_np_folliageitem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a655c4 (listing bound); next ObjC IMP 0x00a655a8 NormalPlant -[renderImageType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900876, 'sub sp, sp, 8'), (10900928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant folliageItemType] (imp 0x00a6558c, 7w): the foliage item constant.\n'),
    ),
    dict(
        name='np_renderimage',
        method='NormalPlant -[renderImageType]',
        types='i8@0:4',
        start=10900904,
        end=10900932,
        disasm='disasm_worldtileloader_np_renderimage.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a655c4 (listing bound); next ObjC IMP 0x00a655c4 NormalPlant -[foodToRemoveWhenSpawningNPC]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900904, 'sub sp, sp, 8'), (10900928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant renderImageType] (imp 0x00a655a8, 7w): the render-image selector.\n'),
    ),
    dict(
        name='np_foodremove',
        method='NormalPlant -[foodToRemoveWhenSpawningNPC]',
        types='f8@0:4',
        start=10900932,
        end=10900980,
        disasm='disasm_worldtileloader_np_foodremove.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a655f4 (listing bound); next ObjC IMP 0x00a655f4 NormalPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900932, 'sub sp, sp, 0x10'), (10900976, 'strbtmi r0, [r1], -0')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant foodToRemoveWhenSpawningNPC] (imp 0x00a655c4, 12w): the NPC-spawn food cost.\n'),
    ),
    dict(
        name='np_floweringseason',
        method='NormalPlant -[floweringSeason:]',
        types='c12@0:4i8',
        start=10900980,
        end=10901044,
        disasm='disasm_worldtileloader_np_floweringseason.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a65634 (listing bound); next ObjC IMP 0x00a65614 NormalPlant -[canDieSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900980, 'sub sp, sp, 0xc'), (10901040, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant floweringSeason:] (imp 0x00a655f4, 8w): the flowering season gate.\n'),
    ),
    dict(
        name='np_candie',
        method='NormalPlant -[canDieSeason:]',
        types='c12@0:4i8',
        start=10901012,
        end=10901044,
        disasm='disasm_worldtileloader_np_candie.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a65634 (listing bound); next ObjC IMP 0x00a65634 NormalPlant -[npcSpawnType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10901012, 'sub sp, sp, 0xc'), (10901040, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant canDieSeason:] (imp 0x00a65614, 8w): the die-season gate.\n'),
    ),
    dict(
        name='np_npcspawn',
        method='NormalPlant -[npcSpawnType]',
        types='i8@0:4',
        start=10901044,
        end=10901100,
        disasm='disasm_worldtileloader_np_npcspawn.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6566c (listing bound); next ObjC IMP 0x00a65650 NormalPlant -[emitsLight]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10901044, 'sub sp, sp, 8'), (10901096, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant npcSpawnType] (imp 0x00a65634, 7w): the NPC spawn type constant.\n'),
    ),
    dict(
        name='np_emitslight',
        method='NormalPlant -[emitsLight]',
        types='c8@0:4',
        start=10901072,
        end=10901100,
        disasm='disasm_worldtileloader_np_emitslight.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6566c (listing bound); next ObjC IMP 0x00a6566c NormalPlant -[lightFactor]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10901072, 'sub sp, sp, 8'), (10901096, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant emitsLight] (imp 0x00a65650, 7w): the light-emission flag.\n'),
    ),
    dict(
        name='np_lightfactor',
        method='NormalPlant -[lightFactor]',
        types='f8@0:4',
        start=10901100,
        end=10901144,
        disasm='disasm_worldtileloader_np_lightfactor.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a65698 (listing bound); next ObjC IMP 0x00a65698 NormalPlant -[lightColor]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10901100, 'sub sp, sp, 0x10'), (10901140, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant lightFactor] (imp 0x00a6566c, 11w): the light factor.\n'),
    ),
    dict(
        name='np_lightcolor',
        method='NormalPlant -[lightColor]',
        types='{Vector=[4f]}8@0:4',
        start=10901144,
        end=10901920,
        disasm='disasm_worldtileloader_np_lightcolor.txt',
        base_add=10901236,
        base_literal=10901916,
        boundary='ARM.exidx end 0x00a659a0 (listing bound); next ObjC IMP 0x00a656e4 NormalPlant -[initSubDerivedItems]',
        selectors={
                 0xa65984: (15225112, 'macroTiles'),
                 0xa65988: (15225116, 'contentsType'),
                 0xa65994: (15225120, 'maxAgeBase'),
                 0xa65998: (15225108, 'plantType'),
        },
        imports={},
        ivars={
                 0xa65970: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa65974: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa65978: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0xa6598c: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
        },
        classes={},
        instructions=[(10901144, 'push {fp, lr}'), (10901912, 'invalid')],
        calls=[(10901200, 'bl method.Vector.Vector_float__float__float__float_'), (10901336, 'bl loc.imp.objc_msgSend'), (10901380, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10901432, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10901456, 'bl loc.imp.objc_msgSend'), (10901532, 'bl loc.imp.objc_msgSend'), (10901568, 'bl loc.imp.objc_msgSend'), (10901624, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (10901748, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(10901768, 'beq', 10901864), (10901784, 'beq', 10901820), (10901800, 'beq', 10901820), (10901816, 'bne', 10901860), (10901860, 'b', 10901864)],
        semantics=('[NormalPlant lightColor] (imp 0x00a65698, 19w): the light color.\n'),
    ),
    dict(
        name='np_initsubderived',
        method='NormalPlant -[initSubDerivedItems]',
        types='v8@0:4',
        start=10901220,
        end=10901920,
        disasm='disasm_worldtileloader_np_initsubderived.txt',
        base_add=10901236,
        base_literal=10901916,
        boundary='ARM.exidx end 0x00a659a0 (listing bound); next ObjC IMP 0x00a659a0 NormalPlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        selectors={
                 0xa65984: (15225112, 'macroTiles'),
                 0xa65988: (15225116, 'contentsType'),
                 0xa65994: (15225120, 'maxAgeBase'),
                 0xa65998: (15225108, 'plantType'),
        },
        imports={},
        ivars={
                 0xa65970: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa65974: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa65978: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0xa6598c: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
        },
        classes={},
        instructions=[(10901220, 'push {fp, lr}'), (10901912, 'invalid')],
        calls=[(10901336, 'bl loc.imp.objc_msgSend'), (10901380, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10901432, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10901456, 'bl loc.imp.objc_msgSend'), (10901532, 'bl loc.imp.objc_msgSend'), (10901568, 'bl loc.imp.objc_msgSend'), (10901624, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (10901748, 'bl sym.tileAtWorldPositionLoaded_int__int__World_')],
        branches=[(10901768, 'beq', 10901864), (10901784, 'beq', 10901820), (10901800, 'beq', 10901820), (10901816, 'bne', 10901860), (10901860, 'b', 10901864)],
        semantics=("[NormalPlant initSubDerivedItems] (imp 0x00a656e4, 175w): the derived-state init - objc x4 + `tileAtWorldPositionLoaded` x2 + **`reloadDrawBlockDynamicObjectQuad`** + **`growthVigorForPlantTypeAtPos(...)`** (the PLANT vigor family symbol - the plant counterpart of the tree's growthVigor!).\n"),
    ),
    dict(
        name='np_ctor',
        method='NormalPlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        types='@48@0:4@8@12{?=ii}16@24S28S32@36@40c44',
        start=10901920,
        end=10905092,
        disasm='disasm_worldtileloader_np_ctor.txt',
        base_add=10901936,
        base_literal=10905088,
        boundary='ARM.exidx end 0x00a66604 (listing bound); next ObjC IMP 0x00a66614 NormalPlant -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0xa66578: (15225124, 'initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:'),
                 0xa66588: (15225132, 'worldTime'),
                 0xa6658c: (15225136, 'getDayNightFractionForX:atWorldTime:'),
                 0xa66594: (15225128, 'getWeatherFractionForPos:'),
                 0xa66598: (15225140, 'minAllowedTemperature'),
                 0xa665a0: (15225160, 'initSubDerivedItems'),
                 0xa665a8: (15225156, 'getX:Y:octaves:'),
                 0xa665b0: (15225152, 'worldWidthMacro'),
                 0xa665c0: (15225164, 'emitsLight'),
                 0xa665cc: (15225172, 'lightColor'),
                 0xa665d4: (15225168, 'lightFactor'),
                 0xa665e0: (15225176, 'alloc'),
                 0xa665ec: (15225180, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xa665f4: (15225112, 'macroTiles'),
                 0xa665f8: (15225148, 'release'),
                 0xa665fc: (15225144, 'removeFromMacroBlock'),
        },
        imports={
                 0xa66584: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6657c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa66580: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa665a4: (17155496, 'OBJC_IVAR_$_Plant.seasonOffset', 68),
                 0xa665ac: (17155500, 'OBJC_IVAR_$_Plant.seasonOffsetNoiseFunction', 64),
                 0xa665b4: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0xa665b8: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0xa665c4: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
                 0xa665d0: (17164552, 'OBJC_IVAR_$_NormalPlant.lastLightFactor', 128),
                 0xa665e4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa665e8: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa665f0: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
        },
        classes={
                 0xa66570: (15253048, 'OBJC_CLASS_$_NormalPlant'),
                 0xa665d8: (15249120, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(10901920, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10905088, 'subseq sl, pc, ip, lsr r1')],
        calls=[(10902220, 'bl loc.imp.objc_msgSendSuper2'), (10902348, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10902528, 'bl loc.imp.objc_msgSend'), (10902628, 'blx r2'), (10902668, 'blx r3'), (10902740, 'blx r2'), (10902792, 'bl sym.seasonForWorldX_int__double__World_'), (10902924, 'bl sym.imp.__aeabi_idiv'), (10902960, 'bl sym.imp.__aeabi_idiv'), (10903156, 'bl sym.tileIsWater_Tile_'), (10903312, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (10903364, 'blx r2'), (10903456, 'blx ip'), (10903476, 'blx r2'), (10903748, 'blx r2'), (10903844, 'blx ip'), (10903932, 'blx lr'), (10904004, 'blx r3'), (10904020, 'bl 0xa66604'), (10904096, 'bl 0xa66604'), (10904212, 'blx r3'), (10904296, 'blx ip'), (10904368, 'bl loc.imp.objc_msgSend_stret'), (10904412, 'bl sym.imp.memset'), (10904448, 'bl loc.imp.objc_msgSend'), (10904564, 'bl sym.makeIntpair_int__int_'), (10904612, 'bl method.Vector.operator_float__'), (10904632, 'bl method.Vector.operator_float__'), (10904652, 'bl method.Vector.operator_float__'), (10904672, 'bl method.Vector.operator_float__'), (10904788, 'bl loc.imp.objc_msgSend'), (10904868, 'bl loc.imp.objc_msgSend'), (10904912, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10902248, 'bne', 10902264), (10902260, 'b', 10904924), (10902272, 'beq', 10903532), (10902368, 'beq', 10903528), (10902840, 'beq', 10903152), (10903052, 'bpl', 10903068), (10903064, 'b', 10903080), (10903168, 'bne', 10903392), (10903188, 'bmi', 10903392), (10903388, 'bpl', 10903524), (10903488, 'b', 10904924), (10903524, 'b', 10903528), (10903528, 'b', 10903532), (10904016, 'beq', 10904096), (10904224, 'beq', 10904916), (10904352, 'beq', 10904384), (10904372, 'b', 10904416)],
        semantics=('[NormalPlant initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:] (imp 0x00a659a0, 793w): the placed ctor - super2 (@the super2 site) + the frame args (consts 0x400/0xff/0x20/0x10) + `tileAtWorldPositionLoaded` + **`seasonForWorldX`** (the season query in the ctor!) + the local helper 0xa66604 x2 + `__aeabi_idiv` x2 + Vector `operator float*` x4 (the position math).\n'),
    ),
    dict(
        name='np_ctorsave',
        method='NormalPlant -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        types='@32@0:4@8@12@16@20@24@28',
        start=10905108,
        end=10906232,
        disasm='disasm_worldtileloader_np_ctorsave.txt',
        base_add=10905124,
        base_literal=10906228,
        boundary='ARM.exidx end 0x00a66a78 (listing bound); next ObjC IMP 0x00a66a78 NormalPlant -[initWithWorld:dynamicWorld:cache:netData:]',
        selectors={
                 0xa66a1c: (15225184, 'initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:'),
                 0xa66a2c: (15225160, 'initSubDerivedItems'),
                 0xa66a38: (15225188, 'tileIsKindOfSelf:'),
                 0xa66a3c: (15225164, 'emitsLight'),
                 0xa66a44: (15225196, 'floatValue'),
                 0xa66a4c: (15225192, 'objectForKey:'),
                 0xa66a58: (15225176, 'alloc'),
                 0xa66a68: (15225200, 'initWithWorld:dynamicWorld:saveDict:cache:parentObject:'),
                 0xa66a70: (15225112, 'macroTiles'),
        },
        imports={
                 0xa66a18: (17151900, 'objc_msgSendSuper2'),
                 0xa66a28: (17151904, 'objc_msgSend'),
                 0xa66a48: (16348184, '__CFConstantStringClassReference'),
                 0xa66a60: (16348200, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa66a24: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0xa66a30: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa66a34: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa66a40: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
                 0xa66a5c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa66a64: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa66a6c: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
        },
        classes={
                 0xa66a20: (15253048, 'OBJC_CLASS_$_NormalPlant'),
                 0xa66a50: (15249120, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(10905108, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10906228, 'subseq sb, pc, r8, asr 9')],
        calls=[(10905288, 'blx r8'), (10905376, 'blx r2'), (10905484, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10905556, 'blx r3'), (10905712, 'blx r5'), (10905728, 'blx r2'), (10905772, 'blx r3'), (10905820, 'bl loc.imp.objc_msgSend'), (10905916, 'bl loc.imp.objc_msgSend'), (10905984, 'bl loc.imp.objc_msgSend'), (10906068, 'bl loc.imp.objc_msgSend'), (10906112, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10905316, 'bne', 10905332), (10905328, 'b', 10906124), (10905404, 'beq', 10905608), (10905504, 'beq', 10905604), (10905568, 'bne', 10905604), (10905604, 'b', 10905608), (10905784, 'beq', 10906116)],
        semantics=('[NormalPlant initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:] (imp 0x00a66614, 281w): the save-dict ctor - super2 + the decode chain.\n'),
    ),
    dict(
        name='np_ctornet',
        method='NormalPlant -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=10906232,
        end=10906516,
        disasm='disasm_worldtileloader_np_ctornet.txt',
        base_add=10906248,
        base_literal=10906512,
        boundary='ARM.exidx end 0x00a66b94 (listing bound); next ObjC IMP 0x00a66b94 NormalPlant -[dealloc]',
        selectors={
                 0xa66b80: (15225204, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xa66b8c: (15225160, 'initSubDerivedItems'),
        },
        imports={
                 0xa66b7c: (17151900, 'objc_msgSendSuper2'),
                 0xa66b88: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa66b84: (15253048, 'OBJC_CLASS_$_NormalPlant'),
        },
        instructions=[(10906232, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10906512, 'subseq sb, pc, r4, rrx')],
        calls=[(10906384, 'blx r6'), (10906468, 'blx r2')],
        branches=[(10906412, 'bne', 10906428), (10906424, 'b', 10906480)],
        semantics=('[NormalPlant initWithWorld:dynamicWorld:cache:netData:] (imp 0x00a66a78, 71w): the netData ctor.\n'),
    ),
    dict(
        name='np_dealloc',
        method='NormalPlant -[dealloc]',
        types='v8@0:4',
        start=10906516,
        end=10906748,
        disasm='disasm_worldtileloader_np_dealloc.txt',
        base_add=10906532,
        base_literal=10906744,
        boundary='ARM.exidx end 0x00a66c7c (listing bound); next ObjC IMP 0x00a66c7c NormalPlant -[setNeedsRemoved:]',
        selectors={
                 0xa66c64: (15225208, 'dealloc'),
                 0xa66c74: (15225148, 'release'),
        },
        imports={
                 0xa66c60: (17151900, 'objc_msgSendSuper2'),
                 0xa66c70: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa66c6c: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
        },
        classes={
                 0xa66c68: (15253048, 'OBJC_CLASS_$_NormalPlant'),
        },
        instructions=[(10906516, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10906744, 'subseq r8, pc, r8, asr 30')],
        calls=[(10906644, 'blx r7'), (10906708, 'blx ip')],
        branches=[],
        semantics=('[NormalPlant dealloc] (imp 0x00a66b94, 58w): the teardown + super.\n'),
    ),
    dict(
        name='np_setneedsremoved',
        method='NormalPlant -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=10906748,
        end=10907156,
        disasm='disasm_worldtileloader_np_setneedsremoved.txt',
        base_add=10906764,
        base_literal=10907152,
        boundary='ARM.exidx end 0x00a66e14 (listing bound); next ObjC IMP 0x00a66e14 NormalPlant -[getSaveDict]',
        selectors={
                 0xa66de8: (15225212, 'setNeedsRemoved:'),
                 0xa66df4: (15225164, 'emitsLight'),
                 0xa66e00: (15225216, 'removeFromTiles'),
                 0xa66e0c: (15225112, 'macroTiles'),
        },
        imports={
                 0xa66de4: (17151900, 'objc_msgSendSuper2'),
                 0xa66df0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa66df8: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
                 0xa66e04: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa66e08: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xa66dec: (15253048, 'OBJC_CLASS_$_NormalPlant'),
        },
        instructions=[(10906748, 'push {r4, r5, fp, lr}'), (10907152, 'subseq r8, pc, r0, ror 28')],
        calls=[(10906864, 'blx lr'), (10906920, 'blx r2'), (10906976, 'bl loc.imp.objc_msgSend'), (10907052, 'bl loc.imp.objc_msgSend'), (10907096, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10906876, 'beq', 10907100), (10906932, 'beq', 10907100)],
        semantics=('[NormalPlant setNeedsRemoved:] (imp 0x00a66c7c, 102w): the removal chain - super-style + the tile cleanup (see rmmacro).\n'),
    ),
    dict(
        name='np_setflowering',
        method='NormalPlant -[setFlowering:]',
        types='v12@0:4c8',
        start=10907700,
        end=10908368,
        disasm='disasm_worldtileloader_np_setflowering.txt',
        base_add=10907716,
        base_literal=10908364,
        boundary='ARM.exidx end 0x00a672d0 (listing bound); next ObjC IMP 0x00a672d0 NormalPlant -[remoteUpdate:]',
        selectors={
                 0xa672c0: (15225232, 'flowerContentsType'),
                 0xa672c8: (15225112, 'macroTiles'),
        },
        imports={
                 0xa672bc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa672b0: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0xa672b4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa672b8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(10907700, 'push {fp, lr}'), (10908364, 'subseq r8, pc, r8, lsr 21')],
        calls=[(10907904, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10907948, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (10908004, 'blx r2'), (10908096, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10908172, 'blx r2'), (10908280, 'bl loc.imp.objc_msgSend'), (10908324, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10907768, 'beq', 10908328), (10907824, 'beq', 10908020), (10907924, 'beq', 10908016), (10907940, 'bne', 10908016), (10907960, 'beq', 10908016), (10908016, 'b', 10908204), (10908116, 'beq', 10908200), (10908184, 'bne', 10908200), (10908200, 'b', 10908204)],
        semantics=('[NormalPlant setFlowering:] (imp 0x00a67034, 167w): the flowering transition - `tileAtWorldPositionLoaded` x2 + **`tileIsAirWaterOrSnow`** (the substrate check) + **`reloadDrawBlockDynamicObjectQuad`** (the flowering change invalidates the render quads!) + objc x1.\n'),
    ),
    dict(
        name='np_remoteupdate',
        method='NormalPlant -[remoteUpdate:]',
        types='v12@0:4@8',
        start=10908368,
        end=10908692,
        disasm='disasm_worldtileloader_np_remoteupdate.txt',
        base_add=10908384,
        base_literal=10908688,
        boundary='ARM.exidx end 0x00a67414 (listing bound); next ObjC IMP 0x00a67414 NormalPlant -[lightGlowQuadCount]',
        selectors={
                 0xa673f0: (15225236, 'remoteUpdate:'),
                 0xa673fc: (15225164, 'emitsLight'),
                 0xa6740c: (15225112, 'macroTiles'),
        },
        imports={
                 0xa673ec: (17151900, 'objc_msgSendSuper2'),
                 0xa673f8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa67400: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa67408: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xa673f4: (15253048, 'OBJC_CLASS_$_NormalPlant'),
        },
        instructions=[(10908368, 'push {r4, r5, fp, lr}'), (10908688, 'subseq r8, pc, ip, lsl 16')],
        calls=[(10908460, 'blx lr'), (10908504, 'blx r2'), (10908596, 'bl loc.imp.objc_msgSend'), (10908640, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10908516, 'beq', 10908644)],
        semantics=('[NormalPlant remoteUpdate:] (imp 0x00a672d0, 81w): the network update.\n'),
    ),
    dict(
        name='np_glowquadcount',
        method='NormalPlant -[lightGlowQuadCount]',
        types='i8@0:4',
        start=10908692,
        end=10908876,
        disasm='disasm_worldtileloader_np_glowquadcount.txt',
        base_add=10908708,
        base_literal=10908872,
        boundary='ARM.exidx end 0x00a674cc (listing bound); next ObjC IMP 0x00a674cc NormalPlant -[addLightGlowQuadData:fromIndex:]',
        selectors={
                 0xa674bc: (15225164, 'emitsLight'),
                 0xa674c0: (15225240, 'lightGlowQuadCount'),
        },
        imports={
                 0xa674b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa674c4: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
        },
        classes={},
        instructions=[(10908692, 'push {fp, lr}'), (10908872, 'subseq r8, pc, r8, asr 13')],
        calls=[(10908748, 'blx r3'), (10908836, 'blx r2')],
        branches=[(10908760, 'bne', 10908776), (10908772, 'b', 10908844)],
        semantics=("[NormalPlant lightGlowQuadCount] (imp 0x00a67414, 46w): the glow-count hook (the emitsLight-gated arm) - the plant's light-contribution count.\n"),
    ),
    dict(
        name='np_addglowquad',
        method='NormalPlant -[addLightGlowQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=10908876,
        end=10909088,
        disasm='disasm_worldtileloader_np_addglowquad.txt',
        base_add=10908892,
        base_literal=10909080,
        boundary='ARM.exidx end 0x00a675a0 (listing bound); next ObjC IMP 0x00a675a0 NormalPlant -[update:accurateDT:isSimulation:]',
        selectors={
                 0xa6758c: (15225164, 'emitsLight'),
                 0xa67590: (15225244, 'addLightGlowQuadData:fromIndex:'),
        },
        imports={
                 0xa67588: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa67594: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
        },
        classes={},
        instructions=[(10908876, 'push {r4, sl, fp, lr}'), (10909084, 'andeq r0, r0, r0')],
        calls=[(10908940, 'blx lr'), (10909044, 'blx ip')],
        branches=[(10908952, 'bne', 10908968), (10908964, 'b', 10909052)],
        semantics=('[NormalPlant addLightGlowQuadData:fromIndex:] (imp 0x00a674cc, 53w): the glow-quad emitter - the light contribution data (paired with the count above).\n'),
    ),
    dict(
        name='np_update',
        method='NormalPlant -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=10909088,
        end=10916032,
        disasm='disasm_worldtileloader_np_update.txt',
        base_add=10909104,
        base_literal=10912588,
        boundary='ARM.exidx end 0x00a690c0 (listing bound); next ObjC IMP 0x00a690c0 NormalPlant -[tileIsKindOfSelf:]',
        selectors={
                 0xa68354: (15225248, 'update:accurateDT:isSimulation:'),
                 0xa68368: (15225164, 'emitsLight'),
                 0xa68370: (15225168, 'lightFactor'),
                 0xa68374: (15225172, 'lightColor'),
                 0xa6837c: (15225148, 'release'),
                 0xa68380: (15225144, 'removeFromMacroBlock'),
                 0xa68384: (15225216, 'removeFromTiles'),
                 0xa68834: (15225176, 'alloc'),
                 0xa6891c: (15225180, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xa68924: (15225112, 'macroTiles'),
                 0xa68bd0: (15225256, 'npcSpawnType'),
                 0xa68bd4: (15225252, 'foodToRemoveWhenSpawningNPC'),
                 0xa68bdc: (15225260, 'npcExistsAtPos:ignoreNPC:'),
                 0xa68be4: (15225264, 'loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xa68bec: (15225268, 'objectType'),
                 0xa68bf0: (15225272, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa68bf8: (15225132, 'worldTime'),
                 0xa68bfc: (15225136, 'getDayNightFractionForX:atWorldTime:'),
                 0xa68c04: (15225128, 'getWeatherFractionForPos:'),
                 0xa69038: (15225112, 'macroTiles'),
                 0xa69040: (15225268, 'objectType'),
                 0xa69044: (15225272, 'dynamicWorldChangedAtPos:objectType:'),
                 0xa69048: (15225132, 'worldTime'),
                 0xa6904c: (15225140, 'minAllowedTemperature'),
                 0xa69064: (15225280, 'canDieSeason:'),
                 0xa69068: (15225292, 'floweringSeason:'),
                 0xa69070: (15225232, 'flowerContentsType'),
                 0xa69078: (15225296, 'seedItemType'),
                 0xa6907c: (15225300, 'maxAgeGeneVariation'),
                 0xa69080: (15225304, 'growthRateGeneVariation'),
                 0xa69084: (15225308, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xa6908c: (15225284, 'worldContentsChangedAtPos:'),
                 0xa690a4: (15225288, 'sowPlantNearParent:'),
                 0xa690ac: (15225276, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
                 0xa690b0: (15225188, 'tileIsKindOfSelf:'),
        },
        imports={
                 0xa68350: (17151900, 'objc_msgSendSuper2'),
                 0xa68364: (17151904, 'objc_msgSend'),
                 0xa6902c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6835c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xa68360: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa6836c: (17164552, 'OBJC_IVAR_$_NormalPlant.lastLightFactor', 128),
                 0xa68378: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
                 0xa68838: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa68844: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa68848: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa68910: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa68914: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa68918: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa6892c: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
                 0xa68bcc: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
                 0xa68bf4: (17164560, 'OBJC_IVAR_$_NormalPlant.checkWeatherCount', 112),
                 0xa69030: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa69034: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa6903c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa69054: (17164564, 'OBJC_IVAR_$_NormalPlant.killCount', 116),
                 0xa69058: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0xa6905c: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0xa69060: (17155496, 'OBJC_IVAR_$_Plant.seasonOffset', 68),
                 0xa6906c: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0xa69094: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa69098: (17163020, 'OBJC_IVAR_$_Plant.hasFloweredThisSeason', 84),
        },
        classes={
                 0xa68358: (15253048, 'OBJC_CLASS_$_NormalPlant'),
                 0xa6882c: (15249120, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(10909088, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10916024, 'subseq r7, pc, r8, ror 7')],
        calls=[(10909244, 'blx lr'), (10909368, 'blx r2'), (10909436, 'blx r2'), (10909616, 'blx lr'), (10909652, 'blx r3'), (10909688, 'blx r3'), (10909784, 'bl loc.imp.objc_msgSend_stret'), (10909820, 'bl sym.imp.memset'), (10909872, 'bl loc.imp.objc_msgSend'), (10909980, 'bl sym.makeIntpair_int__int_'), (10910028, 'bl method.Vector.operator_float__'), (10910056, 'bl method.Vector.operator_float__'), (10910084, 'bl method.Vector.operator_float__'), (10910112, 'bl method.Vector.operator_float__'), (10910236, 'bl loc.imp.objc_msgSend'), (10910356, 'bl loc.imp.objc_msgSend'), (10910388, 'bl loc.imp.objc_msgSend'), (10910480, 'bl loc.imp.objc_msgSend'), (10910524, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (10910604, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10910804, 'blx lr'), (10910856, 'blx r3'), (10910868, 'bl 0xa66604'), (10911036, 'bl loc.imp.objc_msgSend'), (10911132, 'bl loc.imp.objc_msgSend'), (10911192, 'bl loc.imp.objc_msgSend'), (10911284, 'bl loc.imp.objc_msgSend'), (10911320, 'bl loc.imp.objc_msgSend'), (10911568, 'bl loc.imp.objc_msgSend'), (10911668, 'blx r2'), (10911708, 'blx r3'), (10911780, 'blx r2'), (10911832, 'bl sym.seasonForWorldX_int__double__World_'), (10911964, 'bl sym.imp.__aeabi_idiv'), (10912000, 'bl sym.imp.__aeabi_idiv'), (10912196, 'bl sym.tileIsWater_Tile_'), (10912352, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (10912404, 'blx r2'), (10912572, 'bl loc.imp.objc_msgSend'), (10912860, 'blx r2'), (10912912, 'bl sym.seasonForWorldX_int__double__World_'), (10913076, 'bl sym.imp.__modsi3'), (10913184, 'blx r3'), (10913200, 'bl 0xa66604'), (10913312, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10913384, 'blx r3'), (10913496, 'bl sym.makeIntpair_int__int_'), (10913524, 'bl loc.imp.objc_msgSend'), (10913656, 'bl loc.imp.objc_msgSend'), (10913692, 'bl loc.imp.objc_msgSend'), (10913784, 'bl loc.imp.objc_msgSend'), (10913828, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10914000, 'bl loc.imp.objc_msgSend'), (10914056, 'blx r3'), (10914144, 'blx r3'), (10914300, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10914328, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (10914368, 'bl loc.imp.objc_msgSend'), (10914488, 'bl loc.imp.objc_msgSend'), (10914524, 'bl loc.imp.objc_msgSend'), (10914588, 'bl sym.makeIntpair_int__int_'), (10914616, 'bl loc.imp.objc_msgSend'), (10914708, 'bl loc.imp.objc_msgSend'), (10914752, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10914960, 'bl sym.makeIntpair_int__int_'), (10914980, 'bl loc.imp.objc_msgSend'), (10915012, 'bl loc.imp.objc_msgSend'), (10915044, 'bl loc.imp.objc_msgSend'), (10915128, 'bl loc.imp.objc_msgSend'), (10915192, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10915256, 'blx r3'), (10915368, 'bl sym.makeIntpair_int__int_'), (10915396, 'bl loc.imp.objc_msgSend'), (10915508, 'bl loc.imp.objc_msgSend'), (10915544, 'bl loc.imp.objc_msgSend'), (10915636, 'bl loc.imp.objc_msgSend'), (10915680, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10915824, 'bl loc.imp.objc_msgSend'), (10915860, 'bl loc.imp.objc_msgSend')],
        branches=[(10909280, 'beq', 10909288), (10909284, 'b', 10915876), (10909320, 'beq', 10909328), (10909324, 'b', 10915876), (10909380, 'beq', 10910268), (10909492, 'ble', 10910260), (10909768, 'beq', 10909792), (10909788, 'b', 10909824), (10910260, 'b', 10910532), (10910304, 'beq', 10910528), (10910528, 'b', 10910532), (10910660, 'bpl', 10910732), (10910712, 'b', 10911328), (10910864, 'beq', 10911324), (10910904, 'ble', 10911324), (10910920, 'beq', 10911204), (10910936, 'bne', 10911204), (10911048, 'bne', 10911200), (10911200, 'b', 10911204), (10911324, 'b', 10911328), (10911384, 'blt', 10912724), (10911880, 'beq', 10912192), (10912092, 'bpl', 10912108), (10912104, 'b', 10912120), (10912208, 'bne', 10912432), (10912228, 'bmi', 10912432), (10912428, 'bpl', 10912688), (10912488, 'blt', 10912584), (10912580, 'b', 10915876), (10912584, 'b', 10912720), (10912720, 'b', 10912724), (10912772, 'ble', 10915876), (10913132, 'ble', 10914096), (10913196, 'beq', 10914096), (10913232, 'ble', 10913868), (10913332, 'beq', 10913528), (10913396, 'beq', 10913528), (10913832, 'b', 10914060), (10914060, 'b', 10915872), (10914156, 'beq', 10914824), (10914192, 'bne', 10914760), (10914320, 'bne', 10914756), (10914340, 'beq', 10914756), (10914756, 'b', 10914760), (10914760, 'b', 10915868), (10914856, 'beq', 10915684), (10915268, 'bne', 10915400), (10915716, 'beq', 10915864), (10915864, 'b', 10915868), (10915868, 'b', 10915872), (10915872, 'b', 10915876)],
        semantics=("[NormalPlant update:accurateDT:isSimulation:] (imp 0x00a675a0, 1736w): the giant tick (79 calls) - objc x32 (the plant's interactions) + `makeIntpair` x5 + `tileAtWorldPositionLoaded` x4 + **`reloadDrawBlockDynamicObjectQuad`** (the plant's render-quad invalidation - the veg-line sibling of the light-glow/geometry reloads) + Vector float* x4; consts **0x10/0x708 (1800)/0x400/0xff/0x100** (the growth time bases).\n"),
    ),
    dict(
        name='np_kindself',
        method='NormalPlant -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=10916032,
        end=10916256,
        disasm='disasm_worldtileloader_np_kindself.txt',
        base_add=10916048,
        base_literal=10916252,
        boundary='ARM.exidx end 0x00a691a0 (listing bound); next ObjC IMP 0x00a691a0 NormalPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        selectors={
                 0xa69194: (15225116, 'contentsType'),
                 0xa69198: (15225232, 'flowerContentsType'),
        },
        imports={
                 0xa69190: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(10916032, 'push {r4, sl, fp, lr}'), (10916252, 'subseq r6, pc, ip, lsl sl')],
        calls=[(10916120, 'blx lr'), (10916196, 'blx r2')],
        branches=[(10916140, 'beq', 10916220)],
        semantics=('[NormalPlant tileIsKindOfSelf:] (imp 0x00a690c0, 56w): the membership (the +0xb slot family).\n'),
    ),
    dict(
        name='np_harvested',
        method='NormalPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        types='i24@0:4{?=ii}8@16i20',
        start=10916256,
        end=10918024,
        disasm='disasm_worldtileloader_np_harvested.txt',
        base_add=10916272,
        base_literal=10918020,
        boundary='ARM.exidx end 0x00a69888 (listing bound); next ObjC IMP 0x00a69888 NormalPlant -[numberOfOccupiedTilesAbove]',
        selectors={
                 0xa69840: (15225120, 'maxAgeBase'),
                 0xa69844: (15225312, 'expertMode'),
                 0xa69858: (15225296, 'seedItemType'),
                 0xa69864: (15225308, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0xa6986c: (15225316, 'folliageItemType'),
                 0xa69870: (15225320, 'removePlantWithoutCreatingFreeblocks'),
                 0xa6987c: (15225300, 'maxAgeGeneVariation'),
                 0xa69880: (15225304, 'growthRateGeneVariation'),
        },
        imports={
                 0xa6983c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa69838: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0xa69848: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa6984c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa69854: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa6985c: (17155480, 'OBJC_IVAR_$_Plant.maxAgeGene', 54),
                 0xa69860: (17163016, 'OBJC_IVAR_$_Plant.growthRateGene', 56),
                 0xa69868: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(10916256, 'push {r4, r5, r6, r7, fp, lr}'), (10918020, 'subseq r6, pc, ip, lsr sb')],
        calls=[(10916504, 'blx r2'), (10916576, 'bl sym.clampi_int__int__int_'), (10916644, 'blx r3'), (10916752, 'bl sym.makeIntpair_int__int_'), (10916772, 'bl loc.imp.objc_msgSend'), (10916916, 'bl loc.imp.objc_msgSend'), (10917036, 'blx r2'), (10917308, 'bl sym.makeIntpair_int__int_'), (10917328, 'bl loc.imp.objc_msgSend'), (10917360, 'bl loc.imp.objc_msgSend'), (10917392, 'bl loc.imp.objc_msgSend'), (10917504, 'bl loc.imp.objc_msgSend'), (10917632, 'blx r2'), (10917752, 'bl loc.imp.objc_msgSend'), (10917848, 'bl loc.imp.objc_msgSend'), (10917924, 'blx r2')],
        branches=[(10916364, 'bpl', 10916428), (10916424, 'b', 10916532), (10916656, 'beq', 10916672), (10916668, 'ble', 10916932), (10916964, 'beq', 10917540), (10917048, 'beq', 10917196), (10917080, 'bge', 10917096), (10917092, 'b', 10917104), (10917128, 'ble', 10917152), (10917140, 'b', 10917188), (10917220, 'bge', 10917536), (10917532, 'b', 10917208), (10917536, 'b', 10917540), (10917588, 'ble', 10917884), (10917640, 'beq', 10917884), (10917668, 'bge', 10917880), (10917876, 'b', 10917656), (10917880, 'b', 10917884)],
        semantics=('[NormalPlant tileHarvested:removeBlockhead:correctToolMultiplier:] (imp 0x00a691a0, 442w): the harvest handler - objc x8 + makeIntpair x2 + **`clampi`** x1 + the const **0x384 (900)** (the same constant seen in the cactus ctor - the planting/harvest fraction).\n'),
    ),
    dict(
        name='np_tilesabove',
        method='NormalPlant -[numberOfOccupiedTilesAbove]',
        types='i8@0:4',
        start=10918024,
        end=10918112,
        disasm='disasm_worldtileloader_np_tilesabove.txt',
        base_add=10918032,
        base_literal=10918108,
        boundary='ARM.exidx end 0x00a698e0 (listing bound); next ObjC IMP 0x00a698e0 NormalPlant -[droppedItemType]',
        selectors={},
        imports={},
        ivars={
                 0xa698d8: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(10918024, 'sub sp, sp, 8'), (10918108, 'subseq r6, pc, ip, asr r2')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant numberOfOccupiedTilesAbove] (imp 0x00a69888, 22w): the above count.\n'),
    ),
    dict(
        name='np_droppeditem',
        method='NormalPlant -[droppedItemType]',
        types='i8@0:4',
        start=10918112,
        end=10918360,
        disasm='disasm_worldtileloader_np_droppeditem.txt',
        base_add=10918128,
        base_literal=10918356,
        boundary='ARM.exidx end 0x00a699d8 (listing bound); next ObjC IMP 0x00a699d8 NormalPlant -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={
                 0xa699cc: (15225316, 'folliageItemType'),
                 0xa699d0: (15225296, 'seedItemType'),
        },
        imports={
                 0xa699c8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa699c4: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(10918112, 'push {fp, lr}'), (10918352, 'invalid')],
        calls=[(10918216, 'blx r2'), (10918268, 'blx r2'), (10918320, 'blx r2')],
        branches=[(10918172, 'bne', 10918228), (10918224, 'bne', 10918280), (10918276, 'b', 10918328)],
        semantics=('[NormalPlant droppedItemType] (imp 0x00a698e0, 62w): the dropped-item derivation (helper + consts).\n'),
    ),
    dict(
        name='np_staticquadcount',
        method='NormalPlant -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=10918360,
        end=10918400,
        disasm='disasm_worldtileloader_np_staticquadcount.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a69a00 (listing bound); next ObjC IMP 0x00a69a00 NormalPlant -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10918360, 'sub sp, sp, 0x10'), (10918396, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant staticGeometryDrawQuadCountForMacroPos:] (imp 0x00a699d8, 10w): returns the static quad count constant.\n'),
    ),
    dict(
        name='np_adddrawquad',
        method='NormalPlant -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=10918400,
        end=10919660,
        disasm='disasm_worldtileloader_np_adddrawquad.txt',
        base_add=10918420,
        base_literal=10919656,
        boundary='ARM.exidx end 0x00a69eec (listing bound); next ObjC IMP 0x00a69f60 NormalPlant -[removeFromMacroBlock]',
        selectors={
                 0xa69ec4: (15225120, 'maxAgeBase'),
                 0xa69ecc: (15225324, 'renderImageType'),
        },
        imports={
                 0xa69ec0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa69ec8: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0xa69ed0: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa69ed4: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0xa69ee0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(10918400, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10919652, 'subseq r5, pc, r8, ror sp')],
        calls=[(10918480, 'bl method.Vector2.operator_float__'), (10918516, 'bl method.Vector2.operator_float__'), (10918548, 'bl 0xa69eec'), (10918684, 'blx r5'), (10918700, 'bl sym.imp.__modsi3'), (10918716, 'bl sym.imp.__aeabi_idiv'), (10918892, 'blx r3'), (10919564, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_')],
        branches=[(10918936, 'bpl', 10918952), (10918948, 'b', 10918960), (10919048, 'beq', 10919100)],
        semantics=("[NormalPlant addDrawQuadData:fromIndex:forMacroPos:] (imp 0x00a69a00, 315w): the quad emitter - **`fillQuadBuffer`** x1 + Vector float* x2 + `__modsi3` + `__aeabi_idiv` + the local helper 0xa69eec + consts 0x6666 (=0.9f pool bits)/0x20: the plant's leaf/flower quad emit.\n"),
    ),
    dict(
        name='np_rmmacro',
        method='NormalPlant -[removeFromMacroBlock]',
        types='v8@0:4',
        start=10919776,
        end=10920320,
        disasm='disasm_worldtileloader_np_rmmacro.txt',
        base_add=10919792,
        base_literal=10920316,
        boundary='ARM.exidx end 0x00a6a180 (listing bound); next ObjC IMP 0x00a6a180 NormalPlant -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={
                 0xa6a150: (15225164, 'emitsLight'),
                 0xa6a15c: (15225144, 'removeFromMacroBlock'),
                 0xa6a160: (15225148, 'release'),
                 0xa6a16c: (15225112, 'macroTiles'),
        },
        imports={
                 0xa6a14c: (17151904, 'objc_msgSend'),
                 0xa6a170: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa6a154: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
                 0xa6a164: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa6a168: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xa6a174: (15253048, 'OBJC_CLASS_$_NormalPlant'),
        },
        instructions=[(10919776, 'push {fp, lr}'), (10920316, 'subseq r5, pc, ip, ror fp')],
        calls=[(10919832, 'blx r3'), (10919896, 'bl loc.imp.objc_msgSend'), (10919928, 'bl loc.imp.objc_msgSend'), (10920020, 'bl loc.imp.objc_msgSend'), (10920064, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (10920144, 'bl loc.imp.objc_msgSend'), (10920188, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10920256, 'blx r3')],
        branches=[(10919844, 'beq', 10920068)],
        semantics=('[NormalPlant removeFromMacroBlock] (imp 0x00a69f60, 136w): the removal hook - the macro-block presence clear (helper + chain).\n'),
    ),
    dict(
        name='np_addartistlight',
        method='NormalPlant -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=10920320,
        end=10920436,
        disasm='disasm_worldtileloader_np_addartistlight.txt',
        base_add=10920336,
        base_literal=10920432,
        boundary='ARM.exidx end 0x00a6a1f4 (listing bound); next ObjC IMP 0x00a6a1f4 NormalPlant -[availableFood]',
        selectors={
                 0xa6a1e8: (15225328, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0xa6a1e4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6a1ec: (17164556, 'OBJC_IVAR_$_NormalPlant.light', 124),
        },
        classes={},
        instructions=[(10920320, 'push {r4, r5, fp, lr}'), (10920432, 'subseq r5, pc, ip, asr sb')],
        calls=[(10920408, 'blx lr')],
        branches=[],
        semantics=('[NormalPlant addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] (imp 0x00a6a180, 29w): the light-contribution register (thin).\n'),
    ),
    dict(
        name='np_availfood',
        method='NormalPlant -[availableFood]',
        types='f8@0:4',
        start=10920436,
        end=10920584,
        disasm='disasm_worldtileloader_np_availfood.txt',
        base_add=10920460,
        base_literal=10920504,
        boundary='ARM.exidx end 0x00a6a288 (listing bound); next ObjC IMP 0x00a6a23c NormalPlant -[setAvailableFood:]',
        selectors={},
        imports={},
        ivars={
                 0xa6a234: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
                 0xa6a280: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
        },
        classes={},
        instructions=[(10920436, 'sub sp, sp, 0xc'), (10920580, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant availableFood] (imp 0x00a6a1f4, 37w): the food float read.\n'),
    ),
    dict(
        name='np_setavailfood',
        method='NormalPlant -[setAvailableFood:]',
        types='v12@0:4f8',
        start=10920508,
        end=10920584,
        disasm='disasm_worldtileloader_np_setavailfood.txt',
        base_add=10920540,
        base_literal=10920580,
        boundary='ARM.exidx end 0x00a6a288 (listing bound); next ObjC IMP 0x00a6a3e8 Dodo -[npcType]',
        selectors={},
        imports={},
        ivars={
                 0xa6a280: (17164548, 'OBJC_IVAR_$_NormalPlant.availableFood', 120),
        },
        classes={},
        instructions=[(10920508, 'sub sp, sp, 0xc'), (10920580, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant setAvailableFood:] (imp 0x00a6a23c, 19w): the food float write.\n'),
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
        'batch': 'NormalPlant (E90): the first plant subclass - growth/vigor, the render-quad tie, the light family and the flowering gate; 36 bodies',
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
                        default=NATIVE / 'normal_plant.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale normal_plant.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
