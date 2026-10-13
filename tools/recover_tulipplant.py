#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The plants line: TulipPlant, the color-genetics flower: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 5691 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TULIP_PLANT.md for the prose and boundaries.
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
    'bl 0x9a0710': 0x009a0710,
    'bl 0x9a09e8': 0x009a09e8,
    'bl 0x9a41e4': 0x009a41e4,
    'bl 0x9a43cc': 0x009a43cc,
    'bl 0x9a5354': 0x009a5354,
    'bl 0x9a5c50': 0x009a5c50,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSendSuper2_stret': 0x001c335c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float_': 0x004da9cc,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.drawShaderQuad': 0x007c43dc,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0x00d948fc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='tl_objecttype',
        method='TulipPlant -[objectType]',
        types='i8@0:4',
        start=10090832,
        end=10090860,
        disasm='disasm_worldtileloader_tl_objecttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0099f96c (listing bound); next ObjC IMP 0x0099f96c TulipPlant -[initSubDerivedItems]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10090832, 'sub sp, sp, 8'), (10090856, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant objectType] (imp 0x0099f950, 7w): the object-type constant.\n'),
    ),
    dict(
        name='tl_initsubderived',
        method='TulipPlant -[initSubDerivedItems]',
        types='v8@0:4',
        start=10090860,
        end=10094352,
        disasm='disasm_worldtileloader_tl_initsubderived.txt',
        base_add=10090880,
        base_literal=10094348,
        boundary='ARM.exidx end 0x009a0710 (listing bound); next ObjC IMP 0x009a09f8 TulipPlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        selectors={
                 0x9a06a8: (15220368, 'textureNamed:'),
                 0x9a06b8: (15220364, 'shaderNamed:attributes:uniforms:'),
                 0x9a06d0: (15220360, 'arrayWithObjects:'),
                 0x9a06f0: (15220356, 'macroTiles'),
        },
        imports={
                 0x9a06a0: (16342376, '__CFConstantStringClassReference'),
                 0x9a06a4: (17151904, 'objc_msgSend'),
                 0x9a06b4: (16342248, '__CFConstantStringClassReference'),
                 0x9a06bc: (16342296, '__CFConstantStringClassReference'),
                 0x9a06c0: (16342312, '__CFConstantStringClassReference'),
                 0x9a06c4: (16342328, '__CFConstantStringClassReference'),
                 0x9a06c8: (16342344, '__CFConstantStringClassReference'),
                 0x9a06cc: (16342360, '__CFConstantStringClassReference'),
                 0x9a06d8: (16342264, '__CFConstantStringClassReference'),
                 0x9a06dc: (16342280, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x9a0698: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
                 0x9a069c: (17163516, 'OBJC_IVAR_$_TulipPlant.texture', 156),
                 0x9a06ac: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x9a06b0: (17163520, 'OBJC_IVAR_$_TulipPlant.shader', 152),
                 0x9a06e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9a06e4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a06e8: (17155488, 'OBJC_IVAR_$_Plant.maxAge', 88),
                 0x9a06f4: (17163524, 'OBJC_IVAR_$_TulipPlant.randomRotation', 160),
                 0x9a06fc: (17163528, 'OBJC_IVAR_$_TulipPlant.bottomColor', 136),
                 0x9a0700: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
                 0x9a0708: (17163536, 'OBJC_IVAR_$_TulipPlant.topColor', 120),
        },
        classes={
                 0x9a06d4: (15248448, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(10090860, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10094348, 'rsbeq r0, ip, ip, ror 2')],
        calls=[(10091004, 'bl loc.imp.objc_msgSend'), (10091048, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10091124, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10091528, 'blx r4'), (10091600, 'blx r6'), (10091644, 'blx lr'), (10091704, 'blx ip'), (10091756, 'bl method.Vector.Vector_float__float__float__float_'), (10091808, 'bl method.Vector.Vector_float__float__float__float_'), (10091860, 'bl method.Vector.Vector_float__float__float__float_'), (10091912, 'bl method.Vector.Vector_float__float__float__float_'), (10092040, 'bl 0x9a0710'), (10092048, 'bl method.Vector.operator_float__'), (10092092, 'bl method.Vector.operator_float__'), (10092136, 'bl method.Vector.operator_float__'), (10092200, 'bl method.Vector.Vector_float__float__float__float_'), (10092336, 'bl 0x9a0710'), (10092344, 'bl method.Vector.operator_float__'), (10092388, 'bl method.Vector.operator_float__'), (10092432, 'bl method.Vector.operator_float__'), (10092496, 'bl method.Vector.Vector_float__float__float__float_'), (10092644, 'bl 0x9a0710'), (10092652, 'bl method.Vector.operator_float__'), (10092696, 'bl method.Vector.operator_float__'), (10092740, 'bl method.Vector.operator_float__'), (10092804, 'bl method.Vector.Vector_float__float__float__float_'), (10092940, 'bl 0x9a0710'), (10092948, 'bl method.Vector.operator_float__'), (10092992, 'bl method.Vector.operator_float__'), (10093036, 'bl method.Vector.operator_float__'), (10093100, 'bl method.Vector.Vector_float__float__float__float_'), (10093260, 'bl sym.clamp_float__float__float_'), (10093344, 'bl sym.clamp_float__float__float_'), (10093440, 'bl method.Vector.operator_float_'), (10093456, 'bl method.Vector.operator_float_'), (10093496, 'bl method.Vector.operator_Vector_'), (10093576, 'bl method.Vector.operator_float__'), (10093616, 'bl method.Vector.operator_float__'), (10093652, 'bl method.Vector.operator_float__'), (10093704, 'bl method.Vector.Vector_float__float__float__float_'), (10093816, 'bl method.Vector.operator_float_'), (10093832, 'bl method.Vector.operator_float_'), (10093872, 'bl method.Vector.operator_Vector_'), (10093952, 'bl method.Vector.operator_float__'), (10094004, 'bl method.Vector.operator_float__'), (10094056, 'bl method.Vector.operator_float__'), (10094120, 'bl method.Vector.Vector_float__float__float__float_'), (10094164, 'bl 0x9a09e8')],
        branches=[(10091984, 'beq', 10092244), (10091988, 'b', 10091996), (10092024, 'beq', 10092240), (10092240, 'b', 10092244), (10092288, 'beq', 10092540), (10092320, 'beq', 10092536), (10092536, 'b', 10092540), (10092588, 'beq', 10092848), (10092624, 'beq', 10092844), (10092844, 'b', 10092848), (10092896, 'beq', 10093144), (10092920, 'beq', 10093140), (10093140, 'b', 10093144)],
        semantics=('[TulipPlant initSubDerivedItems] (imp 0x0099f96c, 873w): the derived init (48 calls) - Vector float* x18 + Vector ctors (x10 four-float!) + **`clamp_float` x2** + the helper 0x9a0710 x4 + float() x4 + operator+(Vector) x2 + objc: the color/age derivation with clamps.\n'),
    ),
    dict(
        name='tl_ctor',
        method='TulipPlant -[initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:]',
        types='@48@0:4@8@12{?=ii}16@24S28S32@36@40c44',
        start=10095096,
        end=10097512,
        disasm='disasm_worldtileloader_tl_ctor.txt',
        base_add=10095112,
        base_literal=10097508,
        boundary='ARM.exidx end 0x009a1368 (listing bound); next ObjC IMP 0x009a1368 TulipPlant -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        selectors={
                 0x9a1300: (15220372, 'initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:'),
                 0x9a131c: (15220380, 'worldTime'),
                 0x9a1320: (15220384, 'getDayNightFractionForX:atWorldTime:'),
                 0x9a1328: (15220376, 'getWeatherFractionForPos:'),
                 0x9a1334: (15220404, 'initSubDerivedItems'),
                 0x9a1340: (15220400, 'getX:Y:octaves:'),
                 0x9a1348: (15220396, 'worldWidthMacro'),
                 0x9a135c: (15220392, 'release'),
                 0x9a1360: (15220388, 'removeFromMacroBlock'),
        },
        imports={
                 0x9a1318: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9a1304: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
                 0x9a1308: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
                 0x9a130c: (17163540, 'OBJC_IVAR_$_TulipPlant.mateColorGenes', 116),
                 0x9a1310: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9a1314: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a1338: (17155496, 'OBJC_IVAR_$_Plant.seasonOffset', 68),
                 0x9a1344: (17155500, 'OBJC_IVAR_$_Plant.seasonOffsetNoiseFunction', 64),
                 0x9a134c: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x9a1358: (17163544, 'OBJC_IVAR_$_TulipPlant.availableFood', 100),
        },
        classes={
                 0x9a12f8: (15252956, 'OBJC_CLASS_$_TulipPlant'),
        },
        instructions=[(10095096, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10097508, 'rsbeq pc, fp, r4, ror 1')],
        calls=[(10095396, 'bl loc.imp.objc_msgSendSuper2'), (10095608, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10095788, 'bl loc.imp.objc_msgSend'), (10095888, 'blx r2'), (10095928, 'blx r3'), (10096000, 'blx r2'), (10096052, 'bl sym.seasonForWorldX_int__double__World_'), (10096184, 'bl sym.imp.__aeabi_idiv'), (10096220, 'bl sym.imp.__aeabi_idiv'), (10096416, 'bl sym.tileIsWater_Tile_'), (10096572, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (10096668, 'blx ip'), (10096688, 'blx r2'), (10096960, 'blx r2'), (10097056, 'blx ip'), (10097144, 'blx lr'), (10097216, 'blx r3'), (10097232, 'bl 0x9a09e8'), (10097300, 'bl 0x9a09e8')],
        branches=[(10095424, 'bne', 10095440), (10095436, 'b', 10097388), (10095532, 'beq', 10096744), (10095628, 'beq', 10096740), (10096100, 'beq', 10096412), (10096312, 'bpl', 10096328), (10096324, 'b', 10096340), (10096428, 'bne', 10096604), (10096448, 'bmi', 10096604), (10096600, 'bpl', 10096736), (10096700, 'b', 10097388), (10096736, 'b', 10096740), (10096740, 'b', 10096744), (10097228, 'beq', 10097300)],
        semantics=('[TulipPlant initWithWorld:dynamicWorld:atPosition:cache:maxAgeGene:growthRateGene:treeDensityNoiseFunction:seasonOffsetNoiseFunction:adultPlant:] (imp 0x009a09f8, 604w): the ctor - super2 + `seasonForWorldX` + the water/tile probes (`tileIsW...`) + `__aeabi_idiv` x2 + the helper 0x9a09e8 x2 + consts 0x400/0xff/0x384 (the gene domain).\n'),
    ),
    dict(
        name='tl_ctorsave',
        method='TulipPlant -[initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:]',
        types='@32@0:4@8@12@16@20@24@28',
        start=10097512,
        end=10098308,
        disasm='disasm_worldtileloader_tl_ctorsave.txt',
        base_add=10097528,
        base_literal=10098304,
        boundary='ARM.exidx end 0x009a1684 (listing bound); next ObjC IMP 0x009a1684 TulipPlant -[initWithWorld:dynamicWorld:cache:netData:]',
        selectors={
                 0x9a1644: (15220408, 'initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:'),
                 0x9a1650: (15220404, 'initSubDerivedItems'),
                 0x9a1658: (15220420, 'intValue'),
                 0x9a1660: (15220412, 'objectForKey:'),
                 0x9a1678: (15220416, 'floatValue'),
        },
        imports={
                 0x9a1640: (17151900, 'objc_msgSendSuper2'),
                 0x9a164c: (17151904, 'objc_msgSend'),
                 0x9a165c: (16342440, '__CFConstantStringClassReference'),
                 0x9a1668: (16342424, '__CFConstantStringClassReference'),
                 0x9a1670: (16342408, '__CFConstantStringClassReference'),
                 0x9a167c: (16342392, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x9a1654: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
                 0x9a1664: (17163540, 'OBJC_IVAR_$_TulipPlant.mateColorGenes', 116),
                 0x9a166c: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
                 0x9a1674: (17163544, 'OBJC_IVAR_$_TulipPlant.availableFood', 100),
        },
        classes={
                 0x9a1648: (15252956, 'OBJC_CLASS_$_TulipPlant'),
        },
        instructions=[(10097512, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10098304, 'rsbeq lr, fp, r4, ror r7')],
        calls=[(10097692, 'blx r8'), (10097976, 'blx r6'), (10097992, 'blx r2'), (10098040, 'blx r3'), (10098056, 'blx r2'), (10098100, 'blx r3'), (10098116, 'blx r2'), (10098160, 'blx r3'), (10098176, 'blx r2'), (10098216, 'blx r3')],
        branches=[(10097720, 'bne', 10097736), (10097732, 'b', 10098228)],
        semantics=('[TulipPlant initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:seasonOffsetNoiseFunction:] (imp 0x009a1368, 199w): the save-dict ctor - super2 + the decode chain (10 calls).\n'),
    ),
    dict(
        name='tl_ctornet',
        method='TulipPlant -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=10098308,
        end=10098772,
        disasm='disasm_worldtileloader_tl_ctornet.txt',
        base_add=10098324,
        base_literal=10098768,
        boundary='ARM.exidx end 0x009a1854 (listing bound); next ObjC IMP 0x009a1854 TulipPlant -[getSaveDict]',
        selectors={
                 0x9a1830: (15220424, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x9a183c: (15220404, 'initSubDerivedItems'),
                 0x9a184c: (15220428, 'getBytes:length:'),
        },
        imports={
                 0x9a182c: (17151900, 'objc_msgSendSuper2'),
                 0x9a1838: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9a1840: (17163540, 'OBJC_IVAR_$_TulipPlant.mateColorGenes', 116),
                 0x9a1844: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
                 0x9a1848: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
        },
        classes={
                 0x9a1834: (15252956, 'OBJC_CLASS_$_TulipPlant'),
        },
        instructions=[(10098308, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10098768, 'rsbeq lr, fp, r8, asr r4')],
        calls=[(10098460, 'blx r6'), (10098616, 'blx r5'), (10098708, 'blx lr')],
        branches=[(10098488, 'bne', 10098504), (10098500, 'b', 10098720)],
        semantics=('[TulipPlant initWithWorld:dynamicWorld:cache:netData:] (imp 0x009a1684, 116w): the netData ctor.\n'),
    ),
    dict(
        name='tl_creationdata',
        method='TulipPlant -[plantCreationNetData]',
        types='{PlantCreationNetData={DynamicObjectNetData=QIIC[7C]}SSSSsC[5C]}8@0:4',
        start=10099544,
        end=10100000,
        disasm='disasm_worldtileloader_tl_creationdata.txt',
        base_add=10099560,
        base_literal=10099744,
        boundary='ARM.exidx end 0x009a1d20 (listing bound); next ObjC IMP 0x009a1c24 TulipPlant -[setFlowering:]',
        selectors={
                 0x9a1c0c: (15220448, 'plantCreationNetData'),
                 0x9a1d14: (15220356, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x9a1c14: (17163540, 'OBJC_IVAR_$_TulipPlant.mateColorGenes', 116),
                 0x9a1c18: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
                 0x9a1c1c: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
                 0x9a1d04: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a1d0c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a1d10: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x9a1c10: (15252956, 'OBJC_CLASS_$_TulipPlant'),
        },
        instructions=[(10099544, 'push {fp, lr}'), (10099996, 'andeq r0, r0, r0')],
        calls=[(10099620, 'bl loc.imp.objc_msgSendSuper2_stret'), (10099916, 'bl loc.imp.objc_msgSend'), (10099960, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10099812, 'beq', 10099964)],
        semantics=('[TulipPlant plantCreationNetData] (imp 0x009a1b58, 114w): the creation record.\n'),
    ),
    dict(
        name='tl_setflowering',
        method='TulipPlant -[setFlowering:]',
        types='v12@0:4c8',
        start=10099748,
        end=10100000,
        disasm='disasm_worldtileloader_tl_setflowering.txt',
        base_add=10099764,
        base_literal=10099992,
        boundary='ARM.exidx end 0x009a1d20 (listing bound); next ObjC IMP 0x009a1d20 TulipPlant -[update:accurateDT:isSimulation:]',
        selectors={
                 0x9a1d14: (15220356, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x9a1d04: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a1d0c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a1d10: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(10099748, 'push {fp, lr}'), (10099996, 'andeq r0, r0, r0')],
        calls=[(10099916, 'bl loc.imp.objc_msgSend'), (10099960, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_')],
        branches=[(10099812, 'beq', 10099964)],
        semantics=('[TulipPlant setFlowering:] (imp 0x009a1c24, 63w): the flowering transition.\n'),
    ),
    dict(
        name='tl_update',
        method='TulipPlant -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=10100000,
        end=10103552,
        disasm='disasm_worldtileloader_tl_update.txt',
        base_add=10100016,
        base_literal=10103548,
        boundary='ARM.exidx end 0x009a2b00 (listing bound); next ObjC IMP 0x009a2b00 TulipPlant -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x9a2a74: (15220452, 'update:accurateDT:isSimulation:'),
                 0x9a2a98: (15220380, 'worldTime'),
                 0x9a2a9c: (15220384, 'getDayNightFractionForX:atWorldTime:'),
                 0x9a2aa4: (15220376, 'getWeatherFractionForPos:'),
                 0x9a2ac4: (15220356, 'macroTiles'),
                 0x9a2acc: (15220460, 'objectType'),
                 0x9a2ad0: (15220464, 'dynamicWorldChangedAtPos:objectType:'),
                 0x9a2adc: (15220472, 'findBreedingPlantNearPlant:'),
                 0x9a2ae4: (15220468, 'worldContentsChangedAtPos:'),
                 0x9a2af0: (15220476, 'colorGenes'),
                 0x9a2af8: (15220456, 'tileHarvested:removeBlockhead:correctToolMultiplier:'),
        },
        imports={
                 0x9a2a70: (17151900, 'objc_msgSendSuper2'),
                 0x9a2a94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9a2a7c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x9a2a80: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x9a2a84: (17163544, 'OBJC_IVAR_$_TulipPlant.availableFood', 100),
                 0x9a2a88: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9a2a8c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a2a90: (17163548, 'OBJC_IVAR_$_TulipPlant.checkWeatherCount', 104),
                 0x9a2aac: (17163552, 'OBJC_IVAR_$_TulipPlant.killCount', 108),
                 0x9a2ab0: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x9a2ab4: (17155496, 'OBJC_IVAR_$_Plant.seasonOffset', 68),
                 0x9a2ab8: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a2abc: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x9a2ac8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9a2ad4: (17163020, 'OBJC_IVAR_$_Plant.hasFloweredThisSeason', 84),
                 0x9a2ae8: (17163540, 'OBJC_IVAR_$_TulipPlant.mateColorGenes', 116),
                 0x9a2aec: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
        },
        classes={
                 0x9a2a78: (15252956, 'OBJC_CLASS_$_TulipPlant'),
        },
        instructions=[(10100000, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10103548, 'strhteq sp, [fp], -0xdc')],
        calls=[(10100156, 'blx lr'), (10100312, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (10100712, 'bl loc.imp.objc_msgSend'), (10100812, 'blx r2'), (10100852, 'blx r3'), (10100924, 'blx r2'), (10100976, 'bl sym.seasonForWorldX_int__double__World_'), (10101108, 'bl sym.imp.__aeabi_idiv'), (10101144, 'bl sym.imp.__aeabi_idiv'), (10101348, 'bl sym.tileIsWater_Tile_'), (10101504, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (10101676, 'bl loc.imp.objc_msgSend'), (10101900, 'blx r2'), (10101952, 'bl sym.seasonForWorldX_int__double__World_'), (10102088, 'bl sym.imp.__modsi3'), (10102368, 'bl loc.imp.objc_msgSend'), (10102412, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10102488, 'bl loc.imp.objc_msgSend'), (10102524, 'bl loc.imp.objc_msgSend'), (10102588, 'bl sym.makeIntpair_int__int_'), (10102616, 'bl loc.imp.objc_msgSend'), (10102684, 'blx ip'), (10102752, 'blx r2'), (10103032, 'bl loc.imp.objc_msgSend'), (10103076, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10103148, 'bl loc.imp.objc_msgSend'), (10103184, 'bl loc.imp.objc_msgSend'), (10103352, 'bl loc.imp.objc_msgSend'), (10103388, 'bl loc.imp.objc_msgSend')],
        branches=[(10100192, 'beq', 10100200), (10100196, 'b', 10103400), (10100232, 'beq', 10100240), (10100236, 'b', 10103400), (10100368, 'bpl', 10100424), (10100420, 'b', 10100472), (10100528, 'blt', 10101760), (10101024, 'beq', 10101344), (10101236, 'bpl', 10101260), (10101248, 'b', 10101272), (10101360, 'bne', 10101536), (10101380, 'bmi', 10101536), (10101532, 'bpl', 10101724), (10101592, 'blt', 10101688), (10101684, 'b', 10103400), (10101688, 'b', 10101756), (10101756, 'b', 10101760), (10101812, 'ble', 10103400), (10102104, 'beq', 10102132), (10102116, 'beq', 10102132), (10102128, 'bne', 10102860), (10102164, 'bne', 10102848), (10102704, 'beq', 10102792), (10102776, 'b', 10102844), (10102844, 'b', 10102848), (10102848, 'b', 10103396), (10102892, 'beq', 10103212), (10103244, 'beq', 10103392), (10103392, 'b', 10103396), (10103396, 'b', 10103400)],
        semantics=('[TulipPlant update:accurateDT:isSimulation:] (imp 0x009a1d20, 888w): the tick - objc x11 + **`seasonForWorldX` x2** + `__aeabi_idiv` x2 + **`reloadDrawBlockDynamicObjectQuad` x2** + tileAtWorldPositionLoaded + consts 0x708 (1800)/0x384/0x400/0xff/**0x1c2 (450)**/0x100.\n'),
    ),
    dict(
        name='tl_draw',
        method='TulipPlant -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=10103552,
        end=10109412,
        disasm='disasm_worldtileloader_tl_draw.txt',
        base_add=10103576,
        base_literal=10106540,
        boundary='ARM.exidx end 0x009a41e4 (listing bound); next ObjC IMP 0x009a498c TulipPlant -[tileIsKindOfSelf:]',
        selectors={
                 0x9a36c0: (15220396, 'worldWidthMacro'),
                 0x9a4198: (15220396, 'worldWidthMacro'),
                 0x9a41ac: (15220356, 'macroTiles'),
                 0x9a41b0: (15220492, 'dayColor'),
                 0x9a41b4: (15220420, 'intValue'),
                 0x9a41b8: (15220488, 'objectAtIndex:'),
                 0x9a41bc: (15220484, 'uniformLocations'),
                 0x9a41c4: (15220480, 'program'),
                 0x9a41d0: (15220496, 'name'),
        },
        imports={
                 0x9a41a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9a36b0: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a36b4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a36bc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9a3ff8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x9a4190: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a4194: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x9a41c0: (17163520, 'OBJC_IVAR_$_TulipPlant.shader', 152),
                 0x9a41d4: (17163516, 'OBJC_IVAR_$_TulipPlant.texture', 156),
                 0x9a41dc: (17163528, 'OBJC_IVAR_$_TulipPlant.bottomColor', 136),
                 0x9a41e0: (17163536, 'OBJC_IVAR_$_TulipPlant.topColor', 120),
        },
        classes={},
        instructions=[(10103552, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10109408, 'invalid')],
        calls=[(10104272, 'bl loc.imp.objc_msgSend'), (10104296, 'bl sym.imp.__aeabi_idiv'), (10104364, 'bl loc.imp.objc_msgSend'), (10104484, 'bl loc.imp.objc_msgSend'), (10104500, 'bl sym.imp.__aeabi_idiv'), (10104568, 'bl loc.imp.objc_msgSend'), (10104692, 'bl loc.imp.objc_msgSend'), (10104716, 'bl sym.imp.__aeabi_idiv'), (10104784, 'bl loc.imp.objc_msgSend'), (10104904, 'bl loc.imp.objc_msgSend'), (10104920, 'bl sym.imp.__aeabi_idiv'), (10104988, 'bl loc.imp.objc_msgSend'), (10105252, 'bl method.Vector2.operator_float__'), (10105312, 'bl loc.imp.objc_msgSend'), (10105336, 'bl sym.imp.__aeabi_idiv'), (10105424, 'bl loc.imp.objc_msgSend'), (10105456, 'bl method.Vector2.operator_float__'), (10105504, 'bl method.Vector2.operator_float__'), (10105568, 'bl loc.imp.objc_msgSend'), (10105584, 'bl sym.imp.__aeabi_idiv'), (10105672, 'bl loc.imp.objc_msgSend'), (10105704, 'bl method.Vector2.operator_float__'), (10105836, 'blx r2'), (10105880, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (10105968, 'blx r2'), (10105972, 'bl sym.imp.__wrap_glUseProgram'), (10106100, 'blx r6'), (10106120, 'blx r3'), (10106136, 'blx r2'), (10106144, 'bl sym.imp.__wrap_glUniform1i'), (10106224, 'bl loc.imp.objc_msgSend_stret'), (10106264, 'bl sym.imp.memset'), (10106872, 'bl method.Vector.Vector_float__float__float_'), (10106880, 'bl method.Vector.operator_float__'), (10106936, 'bl method.Vector.operator_float__'), (10106968, 'bl method.Vector.operator_float__'), (10107012, 'bl method.Vector.operator_float__'), (10107044, 'bl method.Vector.operator_float__'), (10107088, 'bl method.Vector.operator_float__'), (10107144, 'bl method.Vector.Vector_float__float__float_'), (10107200, 'bl loc.imp.objc_msgSend'), (10107228, 'bl loc.imp.objc_msgSend'), (10107252, 'bl loc.imp.objc_msgSend'), (10107268, 'bl method.Vector.operator_float__'), (10107284, 'bl method.Vector.operator_float__'), (10107300, 'bl method.Vector.operator_float__'), (10107340, 'bl sym.imp.__wrap_glUniform4f'), (10107372, 'bl loc.imp.objc_msgSend'), (10107392, 'bl loc.imp.objc_msgSend'), (10107408, 'bl loc.imp.objc_msgSend'), (10107448, 'bl method.Vector.operator_float__'), (10107480, 'bl method.Vector.operator_float__'), (10107512, 'bl method.Vector.operator_float__'), (10107544, 'bl sym.imp.__wrap_glUniform4f'), (10107576, 'bl loc.imp.objc_msgSend'), (10107596, 'bl loc.imp.objc_msgSend'), (10107612, 'bl loc.imp.objc_msgSend'), (10107652, 'bl method.Vector.operator_float__'), (10107684, 'bl method.Vector.operator_float__'), (10107716, 'bl method.Vector.operator_float__'), (10107748, 'bl sym.imp.__wrap_glUniform4f'), (10107888, 'bl method.Vector2.operator_float__'), (10107912, 'bl method.Vector2.operator_float__'), (10108136, 'bl 0x9a41e4'), (10108836, 'bl 0x9a43cc'), (10108988, 'blx r3'), (10109008, 'blx r3'), (10109024, 'blx r2'), (10109056, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10109132, 'blx r3'), (10109152, 'bl sym.imp.__wrap_glBindTexture'), (10109160, 'bl sym.imp.__wrap_glEnable'), (10109172, 'bl sym.pushDepthMaskState'), (10109304, 'bl sym.drawShaderQuad'), (10109312, 'bl sym.imp.__wrap_glDisable'), (10109316, 'bl sym.popDepthMaskState')],
        branches=[(10104172, 'bne', 10104180), (10104176, 'b', 10109320), (10104308, 'blt', 10104396), (10104392, 'b', 10104600), (10104512, 'bge', 10104596), (10104596, 'b', 10104600), (10104728, 'blt', 10104816), (10104812, 'b', 10105020), (10104932, 'bge', 10105016), (10105016, 'b', 10105020), (10105056, 'blt', 10105180), (10105096, 'bgt', 10105180), (10105136, 'blt', 10105180), (10105176, 'ble', 10105184), (10105180, 'b', 10109320), (10105360, 'ble', 10105480), (10105476, 'b', 10105728), (10105608, 'bpl', 10105724), (10105724, 'b', 10105728), (10105900, 'bne', 10105908), (10105904, 'b', 10109320), (10106204, 'beq', 10106232), (10106228, 'b', 10106268), (10106420, 'bpl', 10106440), (10106436, 'b', 10106452), (10106520, 'bpl', 10106604), (10106536, 'b', 10106616), (10106672, 'ble', 10106780), (10108908, 'b', 10108928)],
        semantics=('[TulipPlant draw:...] (imp 0x009a2b00, 1465w): the colored draw - objc x21 + Vector float* x15 + `__aeabi_idiv` x6 + **`glUniform4f` x3** (!) + Vector ctors + tileAtWorldPosition + consts 0x10/0x400/**0x3f80 (1.0f bits)**/0x6666/0xde1/0xbe2: the tulip uploads its color as a uniform (the color-genes-driven petals!).\n'),
    ),
    dict(
        name='tl_kindself',
        method='TulipPlant -[tileIsKindOfSelf:]',
        types='c12@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8',
        start=10111372,
        end=10111424,
        disasm='disasm_worldtileloader_tl_kindself.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009a49c0 (listing bound); next ObjC IMP 0x009a49c0 TulipPlant -[plantType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10111372, 'sub sp, sp, 0xc'), (10111420, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant tileIsKindOfSelf:] (imp 0x009a498c, 13w): membership.\n'),
    ),
    dict(
        name='tl_planttype',
        method='TulipPlant -[plantType]',
        types='i8@0:4',
        start=10111424,
        end=10111452,
        disasm='disasm_worldtileloader_tl_planttype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009a49dc (listing bound); next ObjC IMP 0x009a49dc TulipPlant -[isRequiredSoilType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10111424, 'sub sp, sp, 8'), (10111448, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant plantType] (imp 0x009a49c0, 7w): the plant-type constant.\n'),
    ),
    dict(
        name='tl_soiltype',
        method='TulipPlant -[isRequiredSoilType:]',
        types='c12@0:4i8',
        start=10111452,
        end=10111608,
        disasm='disasm_worldtileloader_tl_soiltype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009a4a78 (listing bound); next ObjC IMP 0x009a4a78 TulipPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10111452, 'sub sp, sp, 0x10'), (10111604, 'bx lr')],
        calls=[],
        branches=[(10111484, 'beq', 10111588), (10111504, 'beq', 10111588), (10111524, 'beq', 10111588), (10111544, 'beq', 10111588), (10111564, 'beq', 10111588)],
        semantics=('[TulipPlant isRequiredSoilType:] (imp 0x009a49dc, 39w): the soil membership.\n'),
    ),
    dict(
        name='tl_harvested',
        method='TulipPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]',
        types='i24@0:4{?=ii}8@16i20',
        start=10111608,
        end=10112796,
        disasm='disasm_worldtileloader_tl_harvested.txt',
        base_add=10111624,
        base_literal=10112792,
        boundary='ARM.exidx end 0x009a4f1c (listing bound); next ObjC IMP 0x009a4f1c TulipPlant -[numberOfOccupiedTilesAbove]',
        selectors={
                 0x9a4ef0: (15220512, 'removePlantWithoutCreatingFreeblocks'),
                 0x9a4f00: (15220504, 'colorGenesVariation'),
                 0x9a4f04: (15220508, 'mixGenesVariation'),
                 0x9a4f08: (15220500, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x9a4eec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9a4ed8: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a4ee0: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
                 0x9a4ef4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x9a4efc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a4f10: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
                 0x9a4f14: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
        },
        classes={},
        instructions=[(10111608, 'push {r4, r5, fp, lr}'), (10112792, 'rsbeq fp, fp, r4, rrx')],
        calls=[(10112060, 'bl 0x9a09e8'), (10112224, 'bl sym.makeIntpair_int__int_'), (10112364, 'bl loc.imp.objc_msgSend'), (10112492, 'bl sym.makeIntpair_int__int_'), (10112512, 'bl loc.imp.objc_msgSend'), (10112544, 'bl loc.imp.objc_msgSend'), (10112644, 'bl loc.imp.objc_msgSend'), (10112704, 'blx r2')],
        branches=[(10111692, 'beq', 10111716), (10111712, 'b', 10111856), (10111764, 'bpl', 10111828), (10111824, 'b', 10111848), (10111844, 'b', 10111848), (10111920, 'bpl', 10111936), (10111932, 'b', 10111952), (10112024, 'beq', 10112092), (10112036, 'ble', 10112060), (10112056, 'b', 10112088), (10112072, 'ble', 10112084), (10112084, 'b', 10112088), (10112088, 'b', 10112116), (10112100, 'ble', 10112112), (10112112, 'b', 10112116), (10112140, 'bge', 10112384), (10112380, 'b', 10112128), (10112404, 'bge', 10112664), (10112660, 'b', 10112392)],
        semantics=('[TulipPlant tileHarvested:removeBlockhead:correctToolMultiplier:] (imp 0x009a4a78, 297w): the harvest - objc x8 + makeIntpair-family probes; 1 unclassified = the 0x3fffffff sentinel (@0x9a4ee8).\n'),
    ),
    dict(
        name='tl_tilesabove',
        method='TulipPlant -[numberOfOccupiedTilesAbove]',
        types='i8@0:4',
        start=10112796,
        end=10112912,
        disasm='disasm_worldtileloader_tl_tilesabove.txt',
        base_add=10112804,
        base_literal=10112880,
        boundary='ARM.exidx end 0x009a4f90 (listing bound); next ObjC IMP 0x009a4f74 TulipPlant -[droppedItemType]',
        selectors={},
        imports={},
        ivars={
                 0x9a4f6c: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
        },
        classes={},
        instructions=[(10112796, 'sub sp, sp, 8'), (10112908, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant numberOfOccupiedTilesAbove] (imp 0x009a4f1c, 29w): the above count.\n'),
    ),
    dict(
        name='tl_droppeditem',
        method='TulipPlant -[droppedItemType]',
        types='i8@0:4',
        start=10112884,
        end=10112912,
        disasm='disasm_worldtileloader_tl_droppeditem.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009a4f90 (listing bound); next ObjC IMP 0x009a4f90 TulipPlant -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10112884, 'sub sp, sp, 8'), (10112908, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant droppedItemType] (imp 0x009a4f74, 7w): the dropped item.\n'),
    ),
    dict(
        name='tl_staticquadcount',
        method='TulipPlant -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=10112912,
        end=10112952,
        disasm='disasm_worldtileloader_tl_staticquadcount.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009a4fb8 (listing bound); next ObjC IMP 0x009a4fb8 TulipPlant -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10112912, 'sub sp, sp, 0x10'), (10112948, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant staticGeometryDrawQuadCountForMacroPos:] (imp 0x009a4f90, 10w): the static count constant.\n'),
    ),
    dict(
        name='tl_adddrawquad',
        method='TulipPlant -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=10112952,
        end=10113876,
        disasm='disasm_worldtileloader_tl_adddrawquad.txt',
        base_add=10112972,
        base_literal=10113872,
        boundary='ARM.exidx end 0x009a5354 (listing bound); next ObjC IMP 0x009a53c8 TulipPlant -[removeFromMacroBlock]',
        selectors={},
        imports={},
        ivars={
                 0x9a5340: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a5344: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x9a5348: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(10112952, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10113872, 'rsbeq sl, fp, r0, lsr 22')],
        calls=[(10113032, 'bl method.Vector2.operator_float__'), (10113068, 'bl method.Vector2.operator_float__'), (10113100, 'bl 0x9a5354'), (10113800, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_')],
        branches=[(10113152, 'beq', 10113164)],
        semantics=('[TulipPlant addDrawQuadData:fromIndex:forMacroPos:] (imp 0x009a4fb8, 231w): the quad emitter.\n'),
    ),
    dict(
        name='tl_rmmacro',
        method='TulipPlant -[removeFromMacroBlock]',
        types='v8@0:4',
        start=10113992,
        end=10114256,
        disasm='disasm_worldtileloader_tl_rmmacro.txt',
        base_add=10114008,
        base_literal=10114252,
        boundary='ARM.exidx end 0x009a54d0 (listing bound); next ObjC IMP 0x009a54d0 TulipPlant -[canBreed]',
        selectors={
                 0x9a54b4: (15220388, 'removeFromMacroBlock'),
                 0x9a54c8: (15220356, 'macroTiles'),
        },
        imports={
                 0x9a54b0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x9a54bc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x9a54c4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0x9a54b8: (15252956, 'OBJC_CLASS_$_TulipPlant'),
        },
        instructions=[(10113992, 'push {fp, lr}'), (10114252, 'rsbeq sl, fp, r4, lsl r7')],
        calls=[(10114100, 'bl loc.imp.objc_msgSend'), (10114144, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (10114212, 'blx r3')],
        branches=[],
        semantics=('[TulipPlant removeFromMacroBlock] (imp 0x009a53c8, 66w): the removal hook.\n'),
    ),
    dict(
        name='tl_canbreed',
        method='TulipPlant -[canBreed]',
        types='c8@0:4',
        start=10114256,
        end=10114428,
        disasm='disasm_worldtileloader_tl_canbreed.txt',
        base_add=10114264,
        base_literal=10114424,
        boundary='ARM.exidx end 0x009a557c (listing bound); next ObjC IMP 0x009a557c TulipPlant -[mixGenesVariation]',
        selectors={},
        imports={},
        ivars={
                 0x9a5570: (17155528, 'OBJC_IVAR_$_Plant.flowering', 85),
                 0x9a5574: (17155504, 'OBJC_IVAR_$_Plant.age', 72),
        },
        classes={},
        instructions=[(10114256, 'sub sp, sp, 0x14'), (10114424, 'rsbeq sl, fp, r4, lsl r6')],
        calls=[],
        branches=[(10114316, 'bne', 10114384)],
        semantics=("[TulipPlant canBreed] (imp 0x009a54d0, 43w): the breeding predicate with const **0x1c2 (450)** (the same as the update's time base - the breed-age gate).\n"),
    ),
    dict(
        name='tl_mixgenes',
        method='TulipPlant -[mixGenesVariation]',
        types='S8@0:4',
        start=10114428,
        end=10114928,
        disasm='disasm_worldtileloader_tl_mixgenes.txt',
        base_add=10114444,
        base_literal=10114924,
        boundary='ARM.exidx end 0x009a5770 (listing bound); next ObjC IMP 0x009a5770 TulipPlant -[colorGenesVariation]',
        selectors={},
        imports={},
        ivars={
                 0x9a5764: (17163532, 'OBJC_IVAR_$_TulipPlant.mixGenes', 114),
        },
        classes={},
        instructions=[(10114428, 'push {fp, lr}'), (10114924, 'rsbeq sl, fp, r0, ror 10')],
        calls=[(10114552, 'bl 0x9a09e8'), (10114684, 'bl 0x9a09e8')],
        branches=[(10114592, 'bpl', 10114628), (10114604, 'ble', 10114624), (10114624, 'b', 10114684), (10114644, 'ble', 10114680), (10114656, 'bge', 10114676), (10114676, 'b', 10114680), (10114680, 'b', 10114684), (10114724, 'bpl', 10114760), (10114736, 'ble', 10114756), (10114756, 'b', 10114816), (10114776, 'ble', 10114812), (10114788, 'bge', 10114808), (10114808, 'b', 10114812), (10114812, 'b', 10114816)],
        semantics=('[TulipPlant mixGenesVariation] (imp 0x009a557c, 125w): the gene mixer - the **0xffff (16-bit) gene mask** + const 0xc + the helper 0x9a09e8 x2: the parent genes combine into the child mask.\n'),
    ),
    dict(
        name='tl_colorgenevar',
        method='TulipPlant -[colorGenesVariation]',
        types='S8@0:4',
        start=10114928,
        end=10116176,
        disasm='disasm_worldtileloader_tl_colorgenevar.txt',
        base_add=10114944,
        base_literal=10116172,
        boundary='ARM.exidx end 0x009a5c50 (listing bound); next ObjC IMP 0x009a5d24 TulipPlant -[availableFood]',
        selectors={},
        imports={},
        ivars={
                 0x9a5c3c: (17163540, 'OBJC_IVAR_$_TulipPlant.mateColorGenes', 116),
                 0x9a5c40: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
        },
        classes={},
        instructions=[(10114928, 'push {r4, sl, fp, lr}'), (10116172, 'rsbeq sl, fp, ip, ror 6')],
        calls=[(10115252, 'bl 0x9a09e8'), (10115320, 'bl 0x9a5c50'), (10115336, 'bl 0x9a5c50'), (10115368, 'bl 0x9a5c50'), (10115384, 'bl 0x9a5c50'), (10115416, 'bl 0x9a09e8'), (10115484, 'bl 0x9a5c50'), (10115500, 'bl 0x9a5c50'), (10115532, 'bl 0x9a5c50'), (10115548, 'bl 0x9a5c50'), (10115584, 'bl 0x9a09e8'), (10115592, 'bl sym.imp.__modsi3'), (10115620, 'bl 0x9a09e8'), (10115916, 'bl 0x9a09e8'), (10115924, 'bl sym.imp.__modsi3')],
        branches=[(10115248, 'beq', 10115584), (10115292, 'ble', 10115416), (10115312, 'ble', 10115364), (10115348, 'bge', 10115360), (10115360, 'b', 10115412), (10115396, 'bge', 10115408), (10115408, 'b', 10115412), (10115412, 'b', 10115416), (10115456, 'ble', 10115580), (10115476, 'ble', 10115528), (10115512, 'bge', 10115524), (10115524, 'b', 10115576), (10115560, 'bge', 10115572), (10115572, 'b', 10115576), (10115576, 'b', 10115580), (10115580, 'b', 10115584), (10115600, 'bne', 10116024), (10115660, 'bpl', 10115916), (10115696, 'bpl', 10115904), (10115732, 'bpl', 10115892), (10115768, 'bpl', 10115880), (10115804, 'bpl', 10115868), (10115840, 'bpl', 10115856), (10115852, 'b', 10115864), (10115864, 'b', 10115876), (10115876, 'b', 10115888), (10115888, 'b', 10115900), (10115900, 'b', 10115912), (10115912, 'b', 10115916), (10115940, 'bne', 10115956), (10115952, 'b', 10116020), (10115964, 'bne', 10115980), (10115976, 'b', 10116016), (10115988, 'bne', 10116004), (10116000, 'b', 10116012), (10116012, 'b', 10116016), (10116016, 'b', 10116020), (10116020, 'b', 10116024)],
        semantics=('[TulipPlant colorGenesVariation] (imp 0x009a5770, 312w): the COLOR GENETICS - the helper 0x9a5c50 x8 + 0x9a09e8 x5 + `__modsi3` x2 with consts 0xc (12)/0x64 (100): the color genes vary on a 0..100 scale (the flower color mixing!).\n'),
    ),
    dict(
        name='tl_availfood',
        method='TulipPlant -[availableFood]',
        types='f8@0:4',
        start=10116388,
        end=10116536,
        disasm='disasm_worldtileloader_tl_availfood.txt',
        base_add=10116412,
        base_literal=10116456,
        boundary='ARM.exidx end 0x009a5db8 (listing bound); next ObjC IMP 0x009a5d6c TulipPlant -[setAvailableFood:]',
        selectors={},
        imports={},
        ivars={
                 0x9a5d64: (17163544, 'OBJC_IVAR_$_TulipPlant.availableFood', 100),
                 0x9a5db0: (17163544, 'OBJC_IVAR_$_TulipPlant.availableFood', 100),
        },
        classes={},
        instructions=[(10116388, 'sub sp, sp, 0xc'), (10116532, 'rsbeq sb, fp, r0, ror 26')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant availableFood] (imp 0x009a5d24, 37w): the food float read.\n'),
    ),
    dict(
        name='tl_setavailfood',
        method='TulipPlant -[setAvailableFood:]',
        types='v12@0:4f8',
        start=10116460,
        end=10116536,
        disasm='disasm_worldtileloader_tl_setavailfood.txt',
        base_add=10116492,
        base_literal=10116532,
        boundary='ARM.exidx end 0x009a5db8 (listing bound); next ObjC IMP 0x009a5db8 TulipPlant -[colorGenes]',
        selectors={},
        imports={},
        ivars={
                 0x9a5db0: (17163544, 'OBJC_IVAR_$_TulipPlant.availableFood', 100),
        },
        classes={},
        instructions=[(10116460, 'sub sp, sp, 0xc'), (10116532, 'rsbeq sb, fp, r0, ror 26')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant setAvailableFood:] (imp 0x009a5d6c, 19w): the food float write.\n'),
    ),
    dict(
        name='tl_colorgene',
        method='TulipPlant -[colorGenes]',
        types='S8@0:4',
        start=10116536,
        end=10116596,
        disasm='disasm_worldtileloader_tl_colorgene.txt',
        base_add=10116544,
        base_literal=10116592,
        boundary='ARM.exidx end 0x009a5df4 (listing bound); next ObjC IMP 0x009a5df4 TulipPlant -[setColorGenes:]',
        selectors={},
        imports={},
        ivars={
                 0x9a5dec: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
        },
        classes={},
        instructions=[(10116536, 'sub sp, sp, 8'), (10116592, 'rsbeq sb, fp, ip, lsr 26')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant colorGenes] (imp 0x009a5db8, 15w): the color-gene slot read (the ivar).\n'),
    ),
    dict(
        name='tl_setcolorgene',
        method='TulipPlant -[setColorGenes:]',
        types='v12@0:4S8',
        start=10116596,
        end=10116668,
        disasm='disasm_worldtileloader_tl_setcolorgene.txt',
        base_add=10116624,
        base_literal=10116664,
        boundary='ARM.exidx end 0x009a5e3c (listing bound); next ObjC IMP 0x009a5e3c TulipPlant -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x9a5e34: (17163512, 'OBJC_IVAR_$_TulipPlant.colorGenes', 112),
        },
        classes={},
        instructions=[(10116596, 'sub sp, sp, 0xc'), (10116664, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[TulipPlant setColorGenes:] (imp 0x009a5df4, 18w): the color-gene slot write.\n'),
    ),
    dict(
        name='tl_cxxconstruct',
        method='TulipPlant -[.cxx_construct]',
        types='@8@0:4',
        start=10116668,
        end=10117044,
        disasm='disasm_worldtileloader_tl_cxxconstruct.txt',
        base_add=10116684,
        base_literal=10116788,
        boundary='ARM.exidx end 0x009a5fb4 (listing bound); next ObjC IMP 0x009a5fe4 CPTexture2D -[contentSize]',
        selectors={},
        imports={},
        ivars={
                 0x9a5eac: (17163528, 'OBJC_IVAR_$_TulipPlant.bottomColor', 136),
                 0x9a5eb0: (17163536, 'OBJC_IVAR_$_TulipPlant.topColor', 120),
        },
        classes={},
        instructions=[(10116668, 'push {fp, lr}'), (10117040, 'cmnmi pc, 0')],
        calls=[(10116720, 'bl method.Vector.Vector__'), (10116756, 'bl method.Vector.Vector__'), (10116876, 'bl sym.clamp_float__float__float_'), (10116920, 'bl sym.clamp_float__float__float_'), (10116964, 'bl sym.clamp_float__float__float_'), (10117008, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=('[TulipPlant .cxx_construct] (imp 0x009a5e3c, 94w): the C++ member init - **`clamp_float` x4** + `Vector::Vector()` x2: the color vector member is constructed clamped (the [0,1] component domain).\n'),
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
        'batch': 'TulipPlant (E94): the color-genetics flower - the gene mixer, the clamped color vector and the uniform coloring; 26 bodies',
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
                        default=NATIVE / 'tulip_plant.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale tulip_plant.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
