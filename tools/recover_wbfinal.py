#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench true closure (the class done): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 10326 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_FINAL.md for the prose and boundaries.
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
    'bl 0xae3538': 0x00ae3538,
    'bl 0xae3c5c': 0x00ae3c5c,
    'bl 0xaf9850': 0x00af9850,
    'bl 0xaf98c4': 0x00af98c4,
    'bl 0xaf9c5c': 0x00af9c5c,
    'bl 0xafa040': 0x00afa040,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_': 0x00d948fc,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_': 0x00a19670,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0x00a19598,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='wz_adddrawquad',
        method='Workbench -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=11544072,
        end=11558596,
        disasm='disasm_worldtileloader_wz_adddrawquad.txt',
        base_add=11544116,
        base_literal=11548152,
        boundary='ARM.exidx end 0x00b05ec4 (listing bound); next ObjC IMP 0x00b05ec4 Workbench -[staticGeometryDrawCubeCount]',
        selectors={
                 0xb03ee4: (15228648, 'expertMode'),
                 0xb05eb8: (15229180, 'energyFraction'),
        },
        imports={
                 0xb03660: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb035fc: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb03600: (17165488, 'OBJC_IVAR_$_Workbench.savedDrawBuffer', 296),
                 0xb03608: (17165492, 'OBJC_IVAR_$_Workbench.savedDrawBufferIndex', 300),
                 0xb0360c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xb03610: (17165356, 'OBJC_IVAR_$_Workbench.animationLoopIndex', 240),
                 0xb03614: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xb03618: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xb03620: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xb03ee8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb03eec: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb04704: (17165496, 'OBJC_IVAR_$_Workbench.lastRenderDisplayedHadFuel', 309),
                 0xb049e4: (17165500, 'OBJC_IVAR_$_Workbench.lastRenderedIndicatorFractionRounded', 304),
                 0xb050c0: (17156812, 'OBJC_IVAR_$_InteractionObject.isInUse', 68),
                 0xb050c4: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xb050c8: (17165504, 'OBJC_IVAR_$_Workbench.lastRenderDisplayedInUse', 308),
                 0xb054d4: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb054d8: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xb054e8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xb054f0: (17165508, 'OBJC_IVAR_$_Workbench.rotationAnimationTimer', 248),
                 0xb05e9c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb05ea0: (17165488, 'OBJC_IVAR_$_Workbench.savedDrawBuffer', 296),
                 0xb05ea8: (17165492, 'OBJC_IVAR_$_Workbench.savedDrawBufferIndex', 300),
                 0xb05eac: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xb05eb0: (17165508, 'OBJC_IVAR_$_Workbench.rotationAnimationTimer', 248),
                 0xb05eb4: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xb05ebc: (17165500, 'OBJC_IVAR_$_Workbench.lastRenderedIndicatorFractionRounded', 304),
        },
        classes={},
        instructions=[(11544072, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11548196, 'invalid'), (11556068, 'invalid'), (11558592, 'subseq sl, r5, ip, asr 19')],
        calls=[(11544292, 'bl method.Vector2.operator_float__'), (11544328, 'bl method.Vector2.operator_float__'), (11544356, 'bl 0xaf9850'), (11545004, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11545888, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11546308, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11546384, 'blx r2'), (11547052, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11547228, 'bl method.Vector2.operator_float__'), (11547264, 'bl method.Vector2.operator_float__'), (11547292, 'bl 0xaf9850'), (11548132, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11548592, 'bl method.Vector2.operator_float__'), (11548628, 'bl method.Vector2.operator_float__'), (11548656, 'bl 0xaf9850'), (11549380, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11549468, 'bl method.Vector2.operator_float__'), (11549500, 'bl method.Vector2.operator_float__'), (11549536, 'bl 0xaf9850'), (11550416, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11550904, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11551356, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11551780, 'bl method.Vector2.operator_float__'), (11551824, 'bl method.Vector2.operator_float__'), (11551856, 'bl 0xaf9850'), (11551944, 'bl method.Vector2.operator_float__'), (11551980, 'bl method.Vector2.operator_float__'), (11552024, 'bl 0xaf9850'), (11552480, 'bl 0xaf98c4'), (11552508, 'bl sym.imp.memcpy'), (11553228, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11553684, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11553772, 'bl method.Vector2.operator_float__'), (11553804, 'bl method.Vector2.operator_float__'), (11553840, 'bl 0xaf9850'), (11554208, 'bl 0xaf9c5c'), (11554984, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11555172, 'bl method.Vector2.operator_float__'), (11555204, 'bl method.Vector2.operator_float__'), (11555240, 'bl 0xaf9850'), (11555272, 'bl loc.imp.objc_msgSend'), (11556032, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11556232, 'bl method.Vector2.operator_float__'), (11556264, 'bl method.Vector2.operator_float__'), (11556304, 'bl 0xaf9850'), (11556672, 'bl 0xaf9c5c'), (11557484, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_'), (11557516, 'bl method.Vector2.operator_float__'), (11557548, 'bl method.Vector2.operator_float__'), (11557584, 'bl 0xaf9850'), (11557744, 'bl loc.imp.objc_msgSend'), (11558504, 'bl sym.fillQuadBuffer_float__int___GLKMatrix4__float__float__float__float__float__float__float__float__float__int__int_')],
        branches=[(11544204, 'bne', 11547072), (11545052, 'beq', 11545908), (11545056, 'b', 11545120), (11545904, 'b', 11546324), (11546396, 'beq', 11547068), (11546432, 'ble', 11547068), (11547068, 'b', 11558540), (11547104, 'beq', 11547144), (11547140, 'bne', 11548260), (11547340, 'bhi', 11547472), (11547392, 'b', 11547476), (11547404, 'b', 11547476), (11547416, 'b', 11547476), (11547428, 'b', 11547476), (11547440, 'b', 11547476), (11547472, 'b', 11547476), (11548148, 'b', 11558536), (11548292, 'beq', 11548440), (11548328, 'beq', 11548440), (11548364, 'beq', 11548440), (11548400, 'beq', 11548440), (11548436, 'bne', 11551384), (11548528, 'beq', 11550480), (11549428, 'bne', 11550432), (11550432, 'b', 11551376), (11550952, 'bne', 11551372), (11551372, 'b', 11551376), (11551376, 'b', 11558532), (11551416, 'beq', 11551600), (11551452, 'beq', 11551600), (11551488, 'beq', 11551600), (11551524, 'beq', 11551600), (11551560, 'beq', 11551600), (11551596, 'bne', 11555052), (11551688, 'beq', 11553260), (11551724, 'blt', 11553260), (11551900, 'bne', 11552560), (11552512, 'b', 11552608), (11552592, 'bne', 11552604), (11552604, 'b', 11552608), (11553244, 'b', 11553700), (11553732, 'bne', 11555000), (11555000, 'b', 11558528), (11555084, 'bne', 11556112), (11556048, 'b', 11558524), (11556144, 'bne', 11558520), (11558520, 'b', 11558524), (11558524, 'b', 11558528), (11558528, 'b', 11558532), (11558532, 'b', 11558536), (11558536, 'b', 11558540)],
        semantics=('[Workbench addDrawQuadData:fromIndex:forMacroPos:] (imp 0x00b02608, 3631w): the workbench quad emitter - census (52 calls): **15x `fillQuadBuffer(...)`** (the E41/E44/E73 family) + 20x Vector2::operator float* + the helper family **0xaf9850 x10** (the same helper the E80 draw giant calls 9x) + 0xaf9c5c x2 + 0xaf98c4 + memcpy; the float pool repeats the draw band: **-0.99 x7 / -0.98 x2** (the part offsets). The two unclassified cells share 0xffdb8c2c (below the window).\n'),
    ),
    dict(
        name='wz_adddrawcube',
        method='Workbench -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=11558800,
        end=11578188,
        disasm='disasm_worldtileloader_wz_adddrawcube.txt',
        base_add=11558840,
        base_literal=11561608,
        boundary='ARM.exidx end 0x00b0ab4c (listing bound); next ObjC IMP 0x00b0ab4c Workbench -[rendersDynamicObjectQuad]',
        selectors={
                 0xb06ab4: (15229300, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'),
                 0xb07dcc: (15229300, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'),
                 0xb091f0: (15229300, 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'),
        },
        imports={},
        ivars={
                 0xb06a8c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb06a90: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb06a98: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb06ab0: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xb07dc8: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0xb091d8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb091dc: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb091ec: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={
                 0xb06a9c: (15249684, 'OBJC_CLASS_$_DrawCube'),
                 0xb091e8: (15249684, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(11558800, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11578184, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        calls=[(11559048, 'bl 0xaf9850'), (11559556, 'bl 0xaf98c4'), (11559944, 'bl 0xaf9c5c'), (11560532, 'bl 0xaf98c4'), (11560868, 'bl 0xaf9c5c'), (11561384, 'bl 0xaf98c4'), (11561472, 'bl sym.texCoordsForImageIndex_int_'), (11561520, 'bl sym.texCoordsForImageIndex_int_'), (11561568, 'bl sym.texCoordsForImageIndex_int_'), (11561668, 'bl sym.texCoordsForImageIndex_int_'), (11562520, 'bl loc.imp.objc_msgSend'), (11563164, 'bl loc.imp.objc_msgSend'), (11563808, 'bl loc.imp.objc_msgSend'), (11564220, 'bl 0xaf98c4'), (11564596, 'bl 0xafa040'), (11565400, 'bl loc.imp.objc_msgSend'), (11565572, 'bl 0xaf9850'), (11565584, 'bl sym.texCoordsForImageIndex_int_'), (11565596, 'bl sym.texCoordsForImageIndex_int_'), (11565608, 'bl sym.texCoordsForImageIndex_int_'), (11566340, 'bl loc.imp.objc_msgSend'), (11567020, 'bl loc.imp.objc_msgSend'), (11567740, 'bl loc.imp.objc_msgSend'), (11568408, 'bl loc.imp.objc_msgSend'), (11569104, 'bl loc.imp.objc_msgSend'), (11569768, 'bl loc.imp.objc_msgSend'), (11570424, 'bl loc.imp.objc_msgSend'), (11571112, 'bl loc.imp.objc_msgSend'), (11571868, 'bl loc.imp.objc_msgSend'), (11572040, 'bl 0xaf9850'), (11572052, 'bl sym.texCoordsForImageIndex_int_'), (11572064, 'bl sym.texCoordsForImageIndex_int_'), (11572800, 'bl loc.imp.objc_msgSend'), (11573532, 'bl loc.imp.objc_msgSend'), (11574196, 'bl loc.imp.objc_msgSend'), (11574864, 'bl loc.imp.objc_msgSend'), (11575528, 'bl loc.imp.objc_msgSend'), (11576180, 'bl loc.imp.objc_msgSend'), (11576828, 'bl loc.imp.objc_msgSend'), (11577476, 'bl loc.imp.objc_msgSend'), (11578144, 'bl loc.imp.objc_msgSend')],
        branches=[(11558932, 'bne', 11565424), (11560004, 'b', 11560012), (11561424, 'beq', 11561560), (11561428, 'b', 11561432), (11561440, 'beq', 11561512), (11561444, 'b', 11561448), (11561456, 'bne', 11561660), (11561460, 'b', 11561464), (11561508, 'b', 11561704), (11561556, 'b', 11561704), (11561604, 'b', 11561704), (11565460, 'bne', 11571892), (11566528, 'b', 11566544), (11571648, 'b', 11571700), (11571928, 'bne', 11578168)],
        semantics=("[Workbench addDrawCubeData:fromIndex:] (imp 0x00b05f90, 4847w): the workbench cube emitter - census (41 calls): **22x objc_msgSend** + **9x `texCoordsForImageIndex(int)`** (the SAME symbol as the SteamTrain's loadDerivedStuff in E69 - the shared sprite-UV source) + helpers 0xaf98c4 x4 / 0xaf9850 x3 / 0xaf9c5c / 0xafa040; float pool: **+/-0.2, 0.05, 0.1, -1.2, 0.6, 0.3, -0.7, 0.35, -0.35, 0.8** (the cube-corner geometry).\n"),
    ),
    dict(
        name='wz_ctor_placed',
        method='Workbench -[initWithWorld:dynamicWorld:atPosition:cache:type:flipped:saveDict:placedByClient:clientName:]',
        types='@48@0:4@8@12{?=ii}16@24i28c32@36@40@44',
        start=11420352,
        end=11423448,
        disasm='disasm_worldtileloader_wz_ctor_placed.txt',
        base_add=11420368,
        base_literal=11423444,
        boundary='ARM.exidx end 0x00ae4ed8 (listing bound); next ObjC IMP 0x00ae4ed8 Workbench -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xae4e40: (15228720, 'initWithWorld:dynamicWorld:atPosition:cache:item:flipped:saveDict:placedByClient:clientName:'),
                 0xae4e60: (15228740, 'unsignedIntValue'),
                 0xae4e68: (15228724, 'objectForKey:'),
                 0xae4e70: (15228736, 'intValue'),
                 0xae4e78: (15228732, 'boolValue'),
                 0xae4e80: (15228728, 'floatValue'),
                 0xae4e9c: (15228744, 'updateSunLightRemovedForTile:atPos:world:'),
                 0xae4ea0: (15228748, 'updatePortalLight'),
                 0xae4eac: (15228712, 'alloc'),
                 0xae4eb8: (15228716, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xae4ec0: (15228680, 'macroTiles'),
                 0xae4ecc: (15228756, 'worldTime'),
                 0xae4ed0: (15228752, 'initSubDerivedItems'),
        },
        imports={
                 0xae4e5c: (17151904, 'objc_msgSend'),
                 0xae4e64: (16366056, '__CFConstantStringClassReference'),
                 0xae4e74: (16366040, '__CFConstantStringClassReference'),
                 0xae4e7c: (16366024, '__CFConstantStringClassReference'),
                 0xae4e84: (16366008, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae4e44: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae4e48: (17165364, 'OBJC_IVAR_$_Workbench.fuelCounter', 216),
                 0xae4e4c: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
                 0xae4e50: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212),
                 0xae4e54: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222),
                 0xae4e58: (17165384, 'OBJC_IVAR_$_Workbench.fireSpreadTimer', 208),
                 0xae4e6c: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xae4e88: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae4e8c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xae4eb0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae4eb4: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xae4ebc: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xae4ec8: (17165388, 'OBJC_IVAR_$_Workbench.lastWorldTime', 256),
        },
        classes={
                 0xae4e38: (15253120, 'OBJC_CLASS_$_Workbench'),
                 0xae4e94: (15249620, 'OBJC_CLASS_$_WorldHelper'),
                 0xae4ea4: (15249616, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11420352, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11420632, 'bl loc.imp.objc_msgSendSuper2'), (11420656, 'cmp r1, r0'), (11420692, 'movw r3, 1'), (11423444, 'subseq fp, r7, ip, lsl r8')],
        calls=[(11420632, 'bl loc.imp.objc_msgSendSuper2'), (11420764, 'bl 0xae3538'), (11420884, 'bl 0xae3c5c'), (11421372, 'blx r4'), (11421388, 'blx r2'), (11421436, 'blx r3'), (11421452, 'blx r2'), (11421496, 'blx r3'), (11421512, 'blx r2'), (11421556, 'blx r3'), (11421572, 'blx r2'), (11421708, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (11422040, 'bl sym.makeIntpair_int__int_'), (11422104, 'bl loc.imp.objc_msgSend'), (11422164, 'bl 0xae3538'), (11422256, 'bl loc.imp.objc_msgSend'), (11422460, 'bl loc.imp.objc_msgSend'), (11422540, 'bl loc.imp.objc_msgSend'), (11422584, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (11422668, 'bl loc.imp.objc_msgSend'), (11422872, 'bl loc.imp.objc_msgSend'), (11422952, 'bl loc.imp.objc_msgSend'), (11422996, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (11423120, 'blx r2'), (11423204, 'blx r2'), (11423240, 'blx r3')],
        branches=[(11420660, 'bne', 11420676), (11420672, 'b', 11423276), (11420776, 'beq', 11420848), (11420880, 'bne', 11420968), (11420964, 'b', 11421116), (11421000, 'bne', 11421040), (11421036, 'b', 11421112), (11421072, 'bne', 11421108), (11421108, 'b', 11421112), (11421112, 'b', 11421116), (11421128, 'beq', 11421596), (11421628, 'bne', 11422108), (11421728, 'beq', 11421964), (11421780, 'bhi', 11421928), (11421840, 'b', 11421932), (11421856, 'b', 11421932), (11421872, 'b', 11421932), (11421888, 'b', 11421932), (11421904, 'b', 11421932), (11421920, 'b', 11421932), (11421928, 'b', 11421932), (11421944, 'bne', 11421960), (11421960, 'b', 11421964), (11422176, 'beq', 11423008), (11422212, 'beq', 11422592), (11422588, 'b', 11423004), (11422624, 'bne', 11423000), (11423000, 'b', 11423004), (11423004, 'b', 11423128), (11423040, 'beq', 11423080), (11423076, 'bne', 11423124), (11423124, 'b', 11423128)],
        semantics=('[Workbench initWithWorld:dynamicWorld:atPosition:cache:type:flipped:saveDict:placedByClient:clientName:] (imp 0x00ae42c0, 774w): the full placed ctor - super2 with the wide 8-arg frame (@0xae43d8, the arg stores fp-0x41=flipped/stuff at sp+0xc..0x1c) + nil gate (@0xae43f0); the type goes through fffff120 and **fffff140** receives the `movw r3, 1` byte (@0xae4414+); the ffe2643c chain runs the placement.\n'),
    ),
    dict(
        name='wz_initsubderived',
        method='Workbench -[initSubDerivedItems]',
        types='v8@0:4',
        start=11417140,
        end=11418716,
        disasm='disasm_worldtileloader_wz_initsubderived.txt',
        base_add=11417156,
        base_literal=11418712,
        boundary='ARM.exidx end 0x00ae3c5c (listing bound); next ObjC IMP 0x00ae3c6c Workbench -[getLightRGB]',
        selectors={
                 0xae3bd4: (15228676, 'rendersDynamicObjectQuad'),
                 0xae3be4: (15228668, 'shaderNamed:attributes:uniforms:'),
                 0xae3bf4: (15228664, 'arrayWithObjects:'),
                 0xae3c10: (15228672, 'textureNamed:'),
                 0xae3c1c: (15228660, 'initLevelStuff'),
                 0xae3c2c: (15228680, 'macroTiles'),
                 0xae3c30: (15228684, 'rendersDynamicObjectCubes'),
                 0xae3c38: (15228688, 'isClient'),
                 0xae3c54: (15228692, 'updateTileGraphicForWorkbenchOfType:atPos:level:'),
        },
        imports={
                 0xae3bd0: (17151904, 'objc_msgSend'),
                 0xae3be0: (16365976, '__CFConstantStringClassReference'),
                 0xae3be8: (16365928, '__CFConstantStringClassReference'),
                 0xae3bec: (16365944, '__CFConstantStringClassReference'),
                 0xae3bf0: (16365992, '__CFConstantStringClassReference'),
                 0xae3bfc: (16365896, '__CFConstantStringClassReference'),
                 0xae3c00: (16365912, '__CFConstantStringClassReference'),
                 0xae3c0c: (16365960, '__CFConstantStringClassReference'),
                 0xae3c18: (16365880, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xae3bd8: (17165356, 'OBJC_IVAR_$_Workbench.animationLoopIndex', 240),
                 0xae3bdc: (17165360, 'OBJC_IVAR_$_Workbench.worldObjectShader', 104),
                 0xae3c04: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xae3c08: (17156844, 'OBJC_IVAR_$_InteractionObject.texture', 64),
                 0xae3c14: (17156776, 'OBJC_IVAR_$_InteractionObject.shader', 60),
                 0xae3c20: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xae3c28: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xae3c3c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xae3c40: (17165364, 'OBJC_IVAR_$_Workbench.fuelCounter', 216),
                 0xae3c4c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xae3c50: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
        },
        classes={
                 0xae3bf8: (15249612, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(11417140, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11417236, 'ldr r0, [0x00ae3bf4]'), (11418712, 'subseq ip, r7, r8, lsr 9')],
        calls=[(11417448, 'blx lr'), (11417516, 'blx r4'), (11417564, 'blx lr'), (11417608, 'blx lr'), (11417668, 'blx ip'), (11417756, 'blx r4'), (11417812, 'blx r4'), (11417856, 'blx lr'), (11417880, 'bl 0xae3c5c'), (11417932, 'bl sym.imp.__modsi3'), (11417972, 'blx r3'), (11418064, 'bl loc.imp.objc_msgSend'), (11418108, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (11418152, 'blx r2'), (11418244, 'bl loc.imp.objc_msgSend'), (11418288, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (11418292, 'bl 0xae3c5c'), (11418412, 'blx r3'), (11418564, 'bl loc.imp.objc_msgSend')],
        branches=[(11417984, 'beq', 11418112), (11418164, 'beq', 11418292), (11418424, 'bne', 11418568)],
        semantics=('[Workbench initSubDerivedItems] (imp 0x00ae3634, 394w): the sub-state derivation - binds a THIRD save-key sub-family **fff3bea4/be74/be84/beb4/be54/be64/be94/be44** (sibling of the E77 bf5x/7x and E78 c074 families) + the **ffffc8b8** and **ffffcff8/cfb4** state cells + ffe26400/04/08/0c + ffe2b5d8; the derived fuel/crafting state is built through the ffffbca8 chain.\n'),
    ),
    dict(
        name='wz_craftableitems',
        method='Workbench -[craftableItems]',
        types='^^{CraftableItem}8@0:4',
        start=11514152,
        end=11514212,
        disasm='disasm_worldtileloader_wz_craftableitems.txt',
        base_add=11514160,
        base_literal=11514208,
        boundary='ARM.exidx end 0x00afb164 (listing bound); next ObjC IMP 0x00afb164 Workbench -[craftItem:withBlockhead:craftProgressUI:count:]',
        selectors={},
        imports={},
        ivars={
                 0xafb15c: (17165328, 'OBJC_IVAR_$_Workbench.craftableItems', 132),
        },
        classes={},
        instructions=[(11514152, 'sub sp, sp, 8'), (11514208, 'ldrheq r4, [r6], -0x9c')],
        calls=[],
        branches=[],
        semantics=('[Workbench craftableItems] (imp 0x00afb128, 15w): reads through the **fffff11c cell** - the craftable-items array is the SAME owned heap pointer that initLevelStuff mallocs (E79) and dealloc frees (E77).\n'),
    ),
    dict(
        name='wz_hurrycost',
        method='Workbench -[hurryCostForCraftTimeRemaining:totalCraftTime:]',
        types='i16@0:4i8i12',
        start=11582500,
        end=11582628,
        disasm='disasm_worldtileloader_wz_hurrycost.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0bca4 Workbench -[numberOfCraftableItems]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11582500, 'push {fp, lr}'), (11582540, 'sub r0, r0, 1'), (11582556, 'add r0, r0, 1'), (11582624, 'pop {fp, pc}')],
        calls=[(11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench hurryCostForCraftTimeRemaining:totalCraftTime:] (imp 0x00b0bc24, 32w): the cost formula - `movw lr, 0xa` (10) + **`sub r0, r0, 1`; `__aeabi_idiv` (÷10); `add r0, r0, 1`** (@0xb0bc4c-0xb0bc5c) = **ceil(remaining / 10)** - the hurry cost per 10-second block.\n'),
    ),
    dict(
        name='wz_rmmacro',
        method='Workbench -[removeFromMacroBlock]',
        types='v8@0:4',
        start=11579072,
        end=11579996,
        disasm='disasm_worldtileloader_wz_rmmacro.txt',
        base_add=11579088,
        base_literal=11579992,
        boundary='ARM.exidx end 0x00b0b25c (listing bound); next ObjC IMP 0x00b0b25c Workbench -[blockheadUnloaded:]',
        selectors={
                 0xb0b214: (15228676, 'rendersDynamicObjectQuad'),
                 0xb0b220: (15228700, 'removeFromMacroBlock'),
                 0xb0b224: (15228704, 'release'),
                 0xb0b230: (15228680, 'macroTiles'),
                 0xb0b238: (15228684, 'rendersDynamicObjectCubes'),
                 0xb0b24c: (15229304, 'portalIsBeingRemovedAtPos:'),
        },
        imports={
                 0xb0b210: (17151904, 'objc_msgSend'),
                 0xb0b250: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xb0b218: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
                 0xb0b228: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xb0b22c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb0b240: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0b244: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={
                 0xb0b254: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11579072, 'push {fp, lr}'), (11579204, 'str r3, [r0, r2]'), (11579320, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (11579992, 'subseq r4, r5, ip, lsl ip')],
        calls=[(11579152, 'bl loc.imp.objc_msgSend'), (11579184, 'bl loc.imp.objc_msgSend'), (11579276, 'bl loc.imp.objc_msgSend'), (11579320, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (11579364, 'blx r2'), (11579456, 'bl loc.imp.objc_msgSend'), (11579500, 'bl sym.reloadDrawBlockDynamicObjectQuadsForTile_intpair__MacroTile__World_'), (11579544, 'blx r2'), (11579636, 'bl loc.imp.objc_msgSend'), (11579680, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'), (11579840, 'bl loc.imp.objc_msgSend'), (11579908, 'blx r3')],
        branches=[(11579376, 'beq', 11579504), (11579556, 'beq', 11579684), (11579716, 'beq', 11579756), (11579752, 'bne', 11579844)],
        semantics=("[Workbench removeFromMacroBlock] (imp 0x00b0aec0, 231w): the removal - the fffff148 + ffe26428/2c/14 chain clears the state (@0xb0af44 stores 0) then **`reloadDrawBlockLightGlowQuadsForTile(intpair, MacroTile*, World*)`** (@0xb0afb8!) - the workbench removal ALSO invalidates the tile's light-glow quads. With E77's ctor and setNeedsRemoved hits, the light-glow symbol is now pinned at three workbench sites.\n"),
    ),
    dict(
        name='wz_lightpos',
        method='Workbench -[lightPos]',
        types='{Vector=[4f]}8@0:4',
        start=11580700,
        end=11581000,
        disasm='disasm_worldtileloader_wz_lightpos.txt',
        base_add=11580716,
        base_literal=11580996,
        boundary='ARM.exidx end 0x00b0b648 (listing bound); next ObjC IMP 0x00b0b648 Workbench -[occupiesNormalContents]',
        selectors={},
        imports={},
        ivars={
                 0xb0b63c: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0b640: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(11580700, 'push {fp, lr}'), (11580812, 'beq 0xb0b5b4'), (11580972, 'bl method.Vector.Vector_float__float__float_'), (11580996, 'subseq r4, r5, r0, asr 11')],
        calls=[(11580760, 'bl method.Vector2.operator_float__'), (11580876, 'bl method.Vector2.operator_float__'), (11580928, 'bl method.Vector2.operator_float__'), (11580972, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(11580812, 'beq', 11580852), (11580848, 'bne', 11580904)],
        semantics=('[Workbench lightPos] (imp 0x00b0b51c, 75w): macro pos + `Vector2::operator float*` then the type arms: **1 / 0xd (13)** (@0xb0b58c-0xb0b5b0) take the `vadd` + `movw r1, 1` branch; the default runs `mvn r1, 0` (-1) and packs `Vector::Vector(float, float, float)` (@0xb0b62c) - the light position per workbench type.\n'),
    ),
    dict(
        name='wz_addartistlight',
        method='Workbench -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=11581028,
        end=11581144,
        disasm='disasm_worldtileloader_wz_addartistlight.txt',
        base_add=11581044,
        base_literal=11581140,
        boundary='ARM.exidx end 0x00b0b6d8 (listing bound); next ObjC IMP 0x00b0b6d8 Workbench -[canBeUsedInExpertModeWhenNotOwned]',
        selectors={
                 0xb0b6cc: (15229312, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0xb0b6c8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb0b6d0: (17165372, 'OBJC_IVAR_$_Workbench.light', 100),
        },
        classes={},
        instructions=[(11581028, 'push {r4, r5, fp, lr}'), (11581116, 'blx lr'), (11581140, 'subseq r4, r5, r8, ror r4')],
        calls=[(11581116, 'blx lr')],
        branches=[],
        semantics=('[Workbench addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] (imp 0x00b0b664, 29w): thin via ffffbcac + ffe2668c + fffff148 (`blx lr` @0xb0b6bc) - the workbench registers its artificial-light contribution (the E68 consumer).\n'),
    ),
    dict(
        name='wz_staticquadcount',
        method='Workbench -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=11543084,
        end=11544072,
        disasm='disasm_worldtileloader_wz_staticquadcount.txt',
        base_add=11543100,
        base_literal=11544068,
        boundary='ARM.exidx end 0x00b02608 (listing bound); next ObjC IMP 0x00b02608 Workbench -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={
                 0xb025f8: (15228648, 'expertMode'),
        },
        imports={
                 0xb025f4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb025f0: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb025fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xb02600: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
        },
        classes={},
        instructions=[(11543084, 'push {r4, sl, fp, lr}'), (11543236, 'blx r2'), (11543292, 'add r0, r0, 1'), (11544068, 'ldrheq sp, [r5], -0x80')],
        calls=[(11543236, 'blx r2')],
        branches=[(11543160, 'bne', 11543304), (11543248, 'beq', 11543300), (11543284, 'ble', 11543300), (11543300, 'b', 11544036), (11543336, 'beq', 11543376), (11543372, 'bne', 11543392), (11543388, 'b', 11544032), (11543424, 'beq', 11543572), (11543460, 'beq', 11543572), (11543496, 'beq', 11543572), (11543532, 'beq', 11543572), (11543568, 'bne', 11543636), (11543616, 'bne', 11543632), (11543632, 'b', 11544028), (11543668, 'beq', 11543852), (11543704, 'beq', 11543852), (11543740, 'beq', 11543852), (11543776, 'beq', 11543852), (11543812, 'beq', 11543852), (11543848, 'bne', 11543916), (11543896, 'bne', 11543912), (11543912, 'b', 11544024), (11543948, 'bne', 11543968), (11543964, 'b', 11544020), (11544000, 'bne', 11544016), (11544016, 'b', 11544020), (11544020, 'b', 11544024), (11544024, 'b', 11544028), (11544028, 'b', 11544032), (11544032, 'b', 11544036)],
        semantics=('[Workbench staticGeometryDrawQuadCountForMacroPos:] (imp 0x00b0222c, 247w): **type == 3** enters the counted arm: the ffe263f4 helper (@0xb0b2c4... @0xb022c4) + the **fffff130 level** read with `cmp r0, 0; ble` then **`add r0, r0, 1`** (@0xb022f0-0xb022fc) - the quad count = level + 1 for positive levels; other types fall to their own arms (the head continues at 1/0xd @0xb02324+).\n'),
    ),
    dict(
        name='wz_staticcubecount',
        method='Workbench -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=11558596,
        end=11558800,
        disasm='disasm_worldtileloader_wz_staticcubecount.txt',
        base_add=11558604,
        base_literal=11558792,
        boundary='ARM.exidx end 0x00b05f90 (listing bound); next ObjC IMP 0x00b05f90 Workbench -[addDrawCubeData:fromIndex:]',
        selectors={},
        imports={},
        ivars={
                 0xb05f84: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11558596, 'sub sp, sp, 0x14'), (11558660, 'movw r0, 4'), (11558756, 'movw r0, 9'), (11558796, 'andeq r0, r0, r0')],
        calls=[],
        branches=[(11558656, 'bne', 11558672), (11558668, 'b', 11558776), (11558704, 'bne', 11558720), (11558716, 'b', 11558776), (11558752, 'bne', 11558768), (11558764, 'b', 11558776)],
        semantics=("[Workbench staticGeometryDrawCubeCount] (imp 0x00b05ec4, 51w): **type 0x18 (24) -> 4; 0x1a (26) -> 9; 0x1d (29) -> 9** (@0xb05f04/0xb05f34/0xb05f64) - the cube-count table of the cube-rendering types (matching rendersDynamicObjectCubes' set).\n"),
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
        'batch': 'Workbench true closure (E84): the geometry emitters, the placed ctor, the light-glow removal and the last tables; 11 bodies',
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
                        default=NATIVE / 'workbench_final.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_final.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
