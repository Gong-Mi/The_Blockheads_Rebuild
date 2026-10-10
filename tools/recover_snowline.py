#!/usr/bin/env python3
"""Hash-gated recovery of the Snow surface + ice melt (E118).

The snow-surface + ice-melt line opens: SnowSurfaceBlock (19 bodies),
the Column/Stairs melt pair and the two DynamicWorld snow hooks:
25 bodies, 5866 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/SNOWLINE.md for the prose and boundaries.
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
    'bl 0xd8d5b4': 0x00d8d5b4,
    'bl 0xd9119c': 0x00d9119c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_': 0x00a15404,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0x00a19598,
    'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_': 0x00a1915c,
    'bl sym.seasonForWorldX_int__double__World_': 0x00a14a48,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
    'bl sym.tileIsAir_Tile_': 0x00a12300,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='sl_00',
        method='SnowSurfaceBlock -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=14227672,
        end=14227872,
        disasm='disasm_worldtileloader_sl_00.txt',
        base_add=14227688,
        base_literal=14227868,
        boundary='ARM.exidx end 0x00d919a0 (listing bound); next ObjC IMP 0x00d919a0 SnowSurfaceBlock -[partialContent]',
        selectors={
                 0xd9198c: (15240576, 'removeAllSnow'),
                 0xd91994: (15240572, 'setNeedsRemoved:'),
        },
        imports={
                 0xd91988: (17151904, 'objc_msgSend'),
                 0xd91990: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0xd91998: (15253304, 'OBJC_CLASS_$_SnowSurfaceBlock'),
        },
        instructions=[(14227672, 'push {r4, sl, fp, lr}'), (14227868, 'eoreq lr, ip, r4, lsl 4')],
        calls=[(14227760, 'blx r2'), (14227836, 'blx r3')],
        branches=[(14227716, 'beq', 14227764)],
        semantics=('[SnowSurfaceBlock -[setNeedsRemoved:]] (imp 0x00d918d8, 50w): the removal setter - on a true flag runs removeAllSnow first, then the super setNeedsRemoved:.\n'),
    ),
    dict(
        name='sl_01',
        method='SnowSurfaceBlock -[dealloc]',
        types='v8@0:4',
        start=14211512,
        end=14211708,
        disasm='disasm_worldtileloader_sl_01.txt',
        base_add=14211528,
        base_literal=14211704,
        boundary='ARM.exidx end 0x00d8da7c (listing bound); next ObjC IMP 0x00d8da7c SnowSurfaceBlock -[getSaveDict]',
        selectors={
                 0xd8da64: (15240532, 'dealloc'),
                 0xd8da70: (15240528, 'release'),
        },
        imports={
                 0xd8da60: (17151900, 'objc_msgSendSuper2'),
                 0xd8da6c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd8da74: (17169000, 'OBJC_IVAR_$_SnowSurfaceBlock.saveDictCached', 64),
        },
        classes={
                 0xd8da68: (15253304, 'OBJC_CLASS_$_SnowSurfaceBlock'),
        },
        instructions=[(14211512, 'push {r4, r5, r6, r7, fp, lr}'), (14211704, 'eoreq r2, sp, r4, lsr 2')],
        calls=[(14211628, 'blx r5'), (14211668, 'blx r2')],
        branches=[],
        semantics=('[SnowSurfaceBlock -[dealloc]] (imp 0x00d8d9b8, 49w): releases saveDictCached, then the super dealloc.\n'),
    ),
    dict(
        name='sl_02',
        method='SnowSurfaceBlock -[initWithWorld:dynamicWorld:atPosition:cache:]',
        types='@28@0:4@8@12{?=ii}16@24',
        start=14210528,
        end=14211228,
        disasm='disasm_worldtileloader_sl_02.txt',
        base_add=14210544,
        base_literal=14211224,
        boundary='ARM.exidx end 0x00d8d89c (listing bound); next ObjC IMP 0x00d8d89c SnowSurfaceBlock -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xd8d874: (15240504, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xd8d87c: (15240508, 'initSubDerivedItems'),
                 0xd8d88c: (15240512, 'worldTime'),
                 0xd8d890: (15240516, 'timeOfDayFraction'),
                 0xd8d894: (15240520, 'weatherFraction'),
        },
        imports={},
        ivars={
                 0xd8d878: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd8d884: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd8d888: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xd8d86c: (15253304, 'OBJC_CLASS_$_SnowSurfaceBlock'),
        },
        instructions=[(14210528, 'push {r4, r5, r6, sl, fp, lr}'), (14211224, 'invalid')],
        calls=[(14210704, 'bl loc.imp.objc_msgSendSuper2'), (14210772, 'bl loc.imp.objc_msgSend'), (14210840, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14210884, 'bl sym.makeIntpair_int__int_'), (14210932, 'bl loc.imp.objc_msgSend'), (14210980, 'bl sym.seasonForWorldX_int__double__World_'), (14211020, 'bl loc.imp.objc_msgSend'), (14211060, 'bl loc.imp.objc_msgSend'), (14211124, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_')],
        branches=[(14210732, 'bne', 14210748), (14210744, 'b', 14211168)],
        semantics=('[SnowSurfaceBlock -[initWithWorld:dynamicWorld:atPosition:cache:]] (imp 0x00d8d5e0, 175w): the placement ctor - the initSubDerivedItems super chain, then seeds SnowSurfaceBlock.temperature from the world clock/weather chain (timeOfDayFraction/worldTime/weatherFraction).\n'),
    ),
    dict(
        name='sl_03',
        method='SnowSurfaceBlock -[initWithWorld:dynamicWorld:saveDict:cache:]',
        types='@24@0:4@8@12@16@20',
        start=14211228,
        end=14211512,
        disasm='disasm_worldtileloader_sl_03.txt',
        base_add=14211244,
        base_literal=14211508,
        boundary='ARM.exidx end 0x00d8d9b8 (listing bound); next ObjC IMP 0x00d8d9b8 SnowSurfaceBlock -[dealloc]',
        selectors={
                 0xd8d9a4: (15240524, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0xd8d9b0: (15240508, 'initSubDerivedItems'),
        },
        imports={
                 0xd8d9a0: (17151900, 'objc_msgSendSuper2'),
                 0xd8d9ac: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xd8d9a8: (15253304, 'OBJC_CLASS_$_SnowSurfaceBlock'),
        },
        instructions=[(14211228, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14211508, 'eoreq r2, sp, r0, asr 4')],
        calls=[(14211380, 'blx r6'), (14211464, 'blx r2')],
        branches=[(14211408, 'bne', 14211424), (14211420, 'b', 14211476)],
        semantics=('[SnowSurfaceBlock -[initWithWorld:dynamicWorld:saveDict:cache:]] (imp 0x00d8d89c, 71w): the load ctor - the super saveDict chain + initSubDerivedItems.\n'),
    ),
    dict(
        name='sl_04',
        method='SnowSurfaceBlock -[getSaveDict]',
        types='@8@0:4',
        start=14211708,
        end=14211768,
        disasm='disasm_worldtileloader_sl_04.txt',
        base_add=14211716,
        base_literal=14211764,
        boundary='ARM.exidx end 0x00d8dab8 (listing bound); next ObjC IMP 0x00d8dab8 SnowSurfaceBlock -[removeFromMacroBlock]',
        selectors={},
        imports={},
        ivars={
                 0xd8dab0: (17169000, 'OBJC_IVAR_$_SnowSurfaceBlock.saveDictCached', 64),
        },
        classes={},
        instructions=[(14211708, 'sub sp, sp, 8'), (14211764, 'eoreq r2, sp, r8, rrx')],
        calls=[],
        branches=[],
        semantics=('[SnowSurfaceBlock -[getSaveDict]] (imp 0x00d8da7c, 15w): returns the cached dict (saveDictCached).\n'),
    ),
    dict(
        name='sl_05',
        method='SnowSurfaceBlock -[objectType]',
        types='i8@0:4',
        start=14210500,
        end=14210528,
        disasm='disasm_worldtileloader_sl_05.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d8d5e0 (listing bound); next ObjC IMP 0x00d8d5e0 SnowSurfaceBlock -[initWithWorld:dynamicWorld:atPosition:cache:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(14210500, 'sub sp, sp, 8'), (14210524, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[SnowSurfaceBlock -[objectType]] (imp 0x00d8d5c4, 7w): returns 0x1d (29) - the SnowSurfaceBlock dynamic-object type (cross-checked against the rebuild\'s dynamic_object_type_table.inc).\n'),
    ),
    dict(
        name='sl_06',
        method='SnowSurfaceBlock -[initSubDerivedItems]',
        types='v8@0:4',
        start=14210232,
        end=14210484,
        disasm='disasm_worldtileloader_sl_06.txt',
        base_add=14210248,
        base_literal=14210480,
        boundary='ARM.exidx end 0x00d8d5b4 (listing bound); next ObjC IMP 0x00d8d5c4 SnowSurfaceBlock -[objectType]',
        selectors={
                 0xd8d594: (15240496, 'getSaveDict'),
                 0xd8d5ac: (15240500, 'retain'),
        },
        imports={
                 0xd8d590: (17151900, 'objc_msgSendSuper2'),
                 0xd8d5a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd8d59c: (17168996, 'OBJC_IVAR_$_SnowSurfaceBlock.rainRandomTimer', 68),
                 0xd8d5a4: (17169000, 'OBJC_IVAR_$_SnowSurfaceBlock.saveDictCached', 64),
        },
        classes={
                 0xd8d598: (15253304, 'OBJC_CLASS_$_SnowSurfaceBlock'),
        },
        instructions=[(14210232, 'push {r4, sl, fp, lr}'), (14210480, 'eoreq r2, sp, r4, lsr 12')],
        calls=[(14210316, 'blx ip'), (14210368, 'blx r2'), (14210392, 'bl 0xd8d5b4')],
        branches=[],
        semantics=('[SnowSurfaceBlock -[initSubDerivedItems]] (imp 0x00d8d4b8, 63w): caches the save dict (getSaveDict + retain) and seeds rainRandomTimer.\n'),
    ),
    dict(
        name='sl_07',
        method='SnowSurfaceBlock -[removeFromMacroBlock]',
        types='v8@0:4',
        start=14211768,
        end=14211880,
        disasm='disasm_worldtileloader_sl_07.txt',
        base_add=14211784,
        base_literal=14211872,
        boundary='ARM.exidx end 0x00d8db28 (listing bound); next ObjC IMP 0x00d8db28 SnowSurfaceBlock -[updateInTimeSinceSaved]',
        selectors={
                 0xd8db18: (15240536, 'removeFromMacroBlock'),
        },
        imports={
                 0xd8db14: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0xd8db1c: (15253304, 'OBJC_CLASS_$_SnowSurfaceBlock'),
        },
        instructions=[(14211768, 'push {r4, sl, fp, lr}'), (14211876, 'andeq r0, r0, r0')],
        calls=[(14211848, 'blx ip')],
        branches=[],
        semantics=('[SnowSurfaceBlock -[removeFromMacroBlock]] (imp 0x00d8dab8, 28w): the super removeFromMacroBlock call only.\n'),
    ),
    dict(
        name='sl_08',
        method='SnowSurfaceBlock -[updateInTimeSinceSaved]',
        types='v8@0:4',
        start=14211880,
        end=14214448,
        disasm='disasm_worldtileloader_sl_08.txt',
        base_add=14211896,
        base_literal=14214440,
        boundary='ARM.exidx end 0x00d8e530 (listing bound); next ObjC IMP 0x00d8e530 SnowSurfaceBlock -[update:accurateDT:isSimulation:]',
        selectors={
                 0xd8e4ec: (15240512, 'worldTime'),
                 0xd8e4f8: (15240544, 'getDayNightFractionForX:atWorldTime:'),
                 0xd8e4fc: (15240548, 'getWeatherFractionForPos:'),
                 0xd8e508: (15240556, 'updateGroundFrozen:tile:'),
                 0xd8e50c: (15240552, 'updateSnowContent:tile:'),
                 0xd8e514: (15240540, 'getWeatherFractionForPos:atWorldTime:'),
        },
        imports={
                 0xd8e4e8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd8e4dc: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xd8e4e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd8e4e4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd8e4f0: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd8e504: (17169008, 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent', 60),
        },
        classes={},
        instructions=[(14211880, 'push {r4, r5, r6, r7, fp, lr}'), (14214444, 'andeq r0, r0, r0')],
        calls=[(14212000, 'bl sym.makeIntpair_int__int_'), (14212052, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14212132, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14212176, 'bl sym.tileIsWater_Tile_'), (14212196, 'bl sym.tileIsWater_Tile_'), (14212300, 'blx r3'), (14212504, 'bl loc.imp.objc_msgSend'), (14212592, 'bl loc.imp.objc_msgSend'), (14212688, 'bl sym.seasonForWorldX_int__double__World_'), (14212752, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (14213892, 'bl sym.seasonForWorldX_int__double__World_'), (14213980, 'bl loc.imp.objc_msgSend'), (14214064, 'bl loc.imp.objc_msgSend'), (14214128, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (14214324, 'blx ip'), (14214352, 'blx ip')],
        branches=[(14211940, 'beq', 14211948), (14211944, 'b', 14214356), (14212152, 'beq', 14214356), (14212168, 'beq', 14214356), (14212188, 'bne', 14214356), (14212208, 'bne', 14214356), (14212224, 'beq', 14214356), (14212332, 'bge', 14213776), (14212812, 'ble', 14213160), (14212856, 'ble', 14213156), (14212908, 'bpl', 14212924), (14212920, 'b', 14212932), (14213108, 'bpl', 14213152), (14213152, 'b', 14213156), (14213156, 'b', 14213696), (14213196, 'bpl', 14213692), (14213216, 'ble', 14213688), (14213260, 'bpl', 14213688), (14213276, 'ble', 14213688), (14213364, 'bpl', 14213384), (14213376, 'b', 14213392), (14213524, 'bpl', 14213540), (14213536, 'b', 14213548), (14213648, 'ble', 14213684), (14213684, 'b', 14213688), (14213688, 'b', 14213692), (14213692, 'b', 14213696), (14213696, 'b', 14213700), (14213712, 'b', 14212324), (14214200, 'ble', 14214244)],
        semantics=('[SnowSurfaceBlock -[updateInTimeSinceSaved]] (imp 0x00d8db28, 642w): the offline catch-up - replays up to 4 stacked time units of the melt/freeze evolution (per-unit seasonForWorldX/currentTemperatureForTileAtWorldPos + the melt formula constants 0.001/0.2/0.002, the temp>0 / temp>5.0 gates, 0x12c (300) in the rate chain, particles per unit); 16 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='sl_09',
        method='SnowSurfaceBlock -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=14214448,
        end=14220160,
        disasm='disasm_worldtileloader_sl_09.txt',
        base_add=14214464,
        base_literal=14218556,
        boundary='ARM.exidx end 0x00d8fb80 (listing bound); next ObjC IMP 0x00d8fb80 SnowSurfaceBlock -[updateRain:dt:]',
        selectors={
                 0xd8f5bc: (15240560, 'isClient'),
                 0xd8f5c8: (15240564, 'macroTiles'),
                 0xd8f804: (15240548, 'getWeatherFractionForPos:'),
                 0xd8f808: (15240512, 'worldTime'),
                 0xd8f8e8: (15240544, 'getDayNightFractionForX:atWorldTime:'),
                 0xd8f9b8: (15240568, 'fillTile:atPos:withType:'),
                 0xd8fb18: (15240560, 'isClient'),
                 0xd8fb2c: (15240572, 'setNeedsRemoved:'),
                 0xd8fb34: (15240568, 'fillTile:atPos:withType:'),
                 0xd8fb58: (15240552, 'updateSnowContent:tile:'),
                 0xd8fb5c: (15240592, 'spreadGrass:tile:'),
                 0xd8fb60: (15240556, 'updateGroundFrozen:tile:'),
                 0xd8fb64: (15240576, 'removeAllSnow'),
                 0xd8fb6c: (15240580, 'dayColor'),
                 0xd8fb78: (15240584, 'instance'),
                 0xd8fb7c: (15240588, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
        },
        imports={
                 0xd8f5b8: (17151904, 'objc_msgSend'),
                 0xd8fb14: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd8f548: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xd8f54c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd8f5c0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd8f5c4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd8f988: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd8fb1c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd8fb20: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd8fb24: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd8fb28: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd8fb48: (17169008, 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent', 60),
        },
        classes={
                 0xd8fb70: (15251436, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(14214448, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14220156, 'invalid')],
        calls=[(14214592, 'bl sym.makeIntpair_int__int_'), (14214648, 'bl sym.makeIntpair_int__int_'), (14214724, 'blx r2'), (14214816, 'blx r2'), (14214860, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (14214944, 'blx r3'), (14214988, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (14215048, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14215096, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14215176, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14215344, 'bl loc.imp.objc_msgSend'), (14215416, 'bl loc.imp.objc_msgSend'), (14215456, 'bl loc.imp.objc_msgSend'), (14215548, 'bl loc.imp.objc_msgSend'), (14215596, 'bl sym.seasonForWorldX_int__double__World_'), (14215660, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (14215788, 'blx r2'), (14215972, 'bl loc.imp.objc_msgSend'), (14216036, 'bl sym.tileIsWater_Tile_'), (14216144, 'bl loc.imp.objc_msgSend'), (14216200, 'bl sym.makeIntpair_int__int_'), (14216256, 'bl sym.makeIntpair_int__int_'), (14216308, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14216356, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14216368, 'bl sym.tileIsWater_Tile_'), (14216476, 'bl loc.imp.objc_msgSend'), (14216484, 'bl sym.tileIsWater_Tile_'), (14216592, 'bl loc.imp.objc_msgSend'), (14216616, 'bl sym.tileIsWater_Tile_'), (14216692, 'blx ip'), (14216704, 'bl sym.tileIsWater_Tile_'), (14216792, 'blx lr'), (14216828, 'blx r3'), (14216988, 'bl loc.imp.objc_msgSend'), (14217064, 'bl 0xd8d5b4'), (14217164, 'bl 0xd8d5b4'), (14217236, 'bl method.Vector.Vector_float__float__float_'), (14217316, 'bl loc.imp.objc_msgSend_stret'), (14217352, 'bl sym.imp.memset'), (14217748, 'bl method.Vector.Vector_float__float__float_'), (14217756, 'bl method.Vector.operator_float__'), (14217808, 'bl method.Vector.operator_float__'), (14217840, 'bl method.Vector.operator_float__'), (14217884, 'bl method.Vector.operator_float__'), (14217916, 'bl method.Vector.operator_float__'), (14217960, 'bl method.Vector.operator_float__'), (14218008, 'bl method.Vector.Vector_float__float__float_'), (14218048, 'bl method.Vector.Vector_float__float__float__float_'), (14218088, 'bl sym.Vector::operator_Vector_'), (14218132, 'bl sym.imp.__aeabi_idiv'), (14218180, 'bl loc.imp.objc_msgSend'), (14218220, 'bl 0xd8d5b4'), (14218276, 'bl 0xd8d5b4'), (14218324, 'bl method.Vector.Vector_float__float__float_'), (14218536, 'bl loc.imp.objc_msgSend'), (14218580, 'bl sym.tileIsAir_Tile_'), (14218672, 'blx ip'), (14218764, 'blx r2'), (14219256, 'blx ip'), (14219920, 'blx ip'), (14220000, 'blx ip'), (14220028, 'blx ip')],
        branches=[(14214532, 'beq', 14214540), (14214536, 'b', 14220044), (14214736, 'beq', 14215000), (14214996, 'b', 14215104), (14215196, 'beq', 14215232), (14215212, 'beq', 14215232), (14215228, 'bne', 14215236), (14215232, 'b', 14220044), (14215708, 'bne', 14216612), (14215724, 'ble', 14216612), (14215800, 'bne', 14216608), (14215852, 'ble', 14215980), (14215976, 'b', 14216604), (14216028, 'bpl', 14216600), (14216048, 'beq', 14216148), (14216380, 'beq', 14216480), (14216496, 'beq', 14216596), (14216596, 'b', 14216600), (14216600, 'b', 14216604), (14216604, 'b', 14216608), (14216608, 'b', 14216700), (14216628, 'beq', 14216696), (14216696, 'b', 14216700), (14216716, 'beq', 14218576), (14216840, 'bne', 14216996), (14216892, 'bpl', 14216992), (14216992, 'b', 14216996), (14217008, 'ble', 14218564), (14217300, 'beq', 14217324), (14217320, 'b', 14217356), (14217472, 'bpl', 14217488), (14217484, 'b', 14217496), (14217536, 'bpl', 14217564), (14217548, 'b', 14217572), (14217612, 'ble', 14217680), (14218144, 'bge', 14218560), (14218552, 'b', 14218104), (14218560, 'b', 14218564), (14218564, 'b', 14220044), (14218592, 'beq', 14218704), (14218608, 'beq', 14218704), (14218676, 'b', 14220040), (14218776, 'bne', 14220036), (14218792, 'beq', 14220032), (14218832, 'ble', 14219276), (14218876, 'bgt', 14218896), (14218892, 'ble', 14219260), (14218944, 'bpl', 14218960), (14218956, 'b', 14218968), (14219144, 'bpl', 14219188), (14219260, 'b', 14219932), (14219312, 'bpl', 14219928), (14219332, 'ble', 14219924), (14219376, 'bpl', 14219924), (14219392, 'ble', 14219924), (14219480, 'bpl', 14219500), (14219492, 'b', 14219508), (14219640, 'bpl', 14219708), (14219652, 'b', 14219716), (14219816, 'ble', 14219852), (14219924, 'b', 14219928), (14219928, 'b', 14219932), (14220032, 'b', 14220036), (14220036, 'b', 14220040), (14220040, 'b', 14220044)],
        semantics=('[SnowSurfaceBlock -[update:accurateDT:isSimulation:]] (imp 0x00d8e530, 1428w): the snow-surface tick - temperature = currentTemperatureForTileAtWorldPos(tile, pos, dayNight/weather/season/worldTime args); water freeze batches via fillTile:atPos:withType: with the 0x422/0x423 tile-type constants over the own tile + neighbours; the melt (temp>0: partialContent -= ((0.02 + max(weather-0.2, 0.001)*0.2) * (temp+1)) * 0.01 * 4, floor 0.002); the accumulation (temp<0 and coverage byte7>239: ramp=(byte7-240)/1 clamped [0,1], incr=(weather-0.2)*0.005*ramp, cap 0.6); the snow particles (ParticleEmitter.instance addParticleAtPos:velocity:color:gravityType:life:scale:, count= (s16@0x14+4)/4, PRNG helper 0xd8d5b4 scaled 2^31); spreadGrass/updateGroundFrozen/updateSnowContent delegation + the isClient gates - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='sl_10',
        method='SnowSurfaceBlock -[updateRain:dt:]',
        types='v16@0:4f8f12',
        start=14220160,
        end=14222264,
        disasm='disasm_worldtileloader_sl_10.txt',
        base_add=14220176,
        base_literal=14222256,
        boundary='ARM.exidx end 0x00d903b8 (listing bound); next ObjC IMP 0x00d903b8 SnowSurfaceBlock -[spreadGrass:tile:]',
        selectors={
                 0xd90394: (15240580, 'dayColor'),
                 0xd903a8: (15240584, 'instance'),
                 0xd903ac: (15240588, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
        },
        imports={},
        ivars={
                 0xd90380: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd90384: (17168996, 'OBJC_IVAR_$_SnowSurfaceBlock.rainRandomTimer', 68),
                 0xd90388: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd9038c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0xd903a0: (15251436, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(14220160, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14222260, 'andeq r0, r0, r0')],
        calls=[(14220336, 'bl 0xd8d5b4'), (14220484, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14220548, 'bl sym.tileIsAirOrSnow_Tile_'), (14220616, 'bl sym.makeIntpair_int__int_'), (14220668, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14220744, 'bl 0xd8d5b4'), (14220844, 'bl 0xd8d5b4'), (14220916, 'bl method.Vector.Vector_float__float__float_'), (14220996, 'bl loc.imp.objc_msgSend_stret'), (14221032, 'bl sym.imp.memset'), (14221436, 'bl method.Vector.Vector_float__float__float_'), (14221444, 'bl method.Vector.operator_float__'), (14221496, 'bl method.Vector.operator_float__'), (14221528, 'bl method.Vector.operator_float__'), (14221572, 'bl method.Vector.operator_float__'), (14221604, 'bl method.Vector.operator_float__'), (14221648, 'bl method.Vector.operator_float__'), (14221696, 'bl method.Vector.Vector_float__float__float_'), (14221736, 'bl method.Vector.Vector_float__float__float__float_'), (14221776, 'bl sym.Vector::operator_Vector_'), (14221836, 'bl loc.imp.objc_msgSend'), (14221876, 'bl 0xd8d5b4'), (14221912, 'bl 0xd8d5b4'), (14221956, 'bl method.Vector.Vector_float__float__float_'), (14222164, 'bl loc.imp.objc_msgSend')],
        branches=[(14220224, 'ble', 14222200), (14220264, 'ble', 14222200), (14220332, 'bpl', 14222196), (14220504, 'bne', 14220512), (14220508, 'b', 14222200), (14220524, 'blt', 14222192), (14220540, 'bne', 14222192), (14220560, 'beq', 14222192), (14220688, 'beq', 14222188), (14220980, 'beq', 14221004), (14221000, 'b', 14221036), (14221152, 'bpl', 14221172), (14221164, 'b', 14221180), (14221220, 'bpl', 14221252), (14221232, 'b', 14221260), (14221300, 'ble', 14221368), (14221800, 'bge', 14222184), (14222180, 'b', 14221792), (14222184, 'b', 14222188), (14222188, 'b', 14222192), (14222192, 'b', 14222196), (14222196, 'b', 14222200)],
        semantics=('[SnowSurfaceBlock -[updateRain:dt:]] (imp 0x00d8fb80, 526w): the per-frame precipitation particles - rainRandomTimer-paced ParticleEmitter.instance addParticleAtPos:velocity:color:gravityType:life:scale: spawns (dayColor tint, temperature-gated); 25 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='sl_11',
        method='SnowSurfaceBlock -[spreadGrass:tile:]',
        types='v16@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}12',
        start=14222264,
        end=14223948,
        disasm='disasm_worldtileloader_sl_11.txt',
        base_add=14222280,
        base_literal=14223944,
        boundary='ARM.exidx end 0x00d90a4c (listing bound); next ObjC IMP 0x00d90a4c SnowSurfaceBlock -[updateGroundFrozen:tile:]',
        selectors={
                 0xd90a20: (15240560, 'isClient'),
                 0xd90a30: (15240564, 'macroTiles'),
                 0xd90a40: (15240596, 'snowChangedAtMacroPos:'),
        },
        imports={
                 0xd90a1c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd90a24: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd90a28: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd90a2c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd90a34: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(14222264, 'push {r4, r5, r6, r7, fp, lr}'), (14223944, 'eoreq pc, ip, r4, lsr 14')],
        calls=[(14222348, 'blx lr'), (14222520, 'bl 0xd8d5b4'), (14222760, 'bl sym.makeIntpair_int__int_'), (14222788, 'bl loc.imp.objc_msgSend'), (14222860, 'bl 0xd8d5b4'), (14222924, 'bl 0xd8d5b4'), (14223112, 'blx r3'), (14223156, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (14223512, 'blx r2'), (14223556, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (14223584, 'bl sym.tileIsSolid_Tile_'), (14223844, 'bl sym.makeIntpair_int__int_'), (14223872, 'bl loc.imp.objc_msgSend')],
        branches=[(14222360, 'beq', 14222368), (14222364, 'b', 14223892), (14222404, 'ble', 14223892), (14222420, 'bgt', 14222472), (14222436, 'bgt', 14222472), (14222452, 'bgt', 14222472), (14222468, 'ble', 14223892), (14222484, 'beq', 14222520), (14222500, 'bne', 14222812), (14222516, 'bne', 14222812), (14222556, 'bpl', 14222792), (14222572, 'bne', 14222588), (14222600, 'bne', 14222652), (14222616, 'bne', 14222652), (14222632, 'bne', 14222648), (14222648, 'b', 14222652), (14222792, 'b', 14223888), (14222824, 'beq', 14222860), (14222840, 'bne', 14223884), (14222856, 'bne', 14223884), (14223176, 'beq', 14223880), (14223192, 'beq', 14223212), (14223208, 'bne', 14223880), (14223316, 'bge', 14223408), (14223432, 'bge', 14223632), (14223576, 'beq', 14223600), (14223596, 'beq', 14223612), (14223608, 'b', 14223632), (14223612, 'b', 14223616), (14223628, 'b', 14223420), (14223640, 'bne', 14223876), (14223656, 'bne', 14223672), (14223684, 'bne', 14223736), (14223700, 'bne', 14223736), (14223716, 'bne', 14223732), (14223732, 'b', 14223736), (14223876, 'b', 14223880), (14223880, 'b', 14223884), (14223884, 'b', 14223888), (14223888, 'b', 14223892)],
        semantics=('[SnowSurfaceBlock -[spreadGrass:tile:]] (imp 0x00d903b8, 421w): the thaw recovery - temperature > 0 and the cover bytes (byte7/+0xe/+0x10/+0x12) <= 0x40 gate a probabilistic (PRNG 0xd8d5b4 vs the threshold double) conversion of the frosted surface codes \'0\'->\'1\' (byte0; plus the byte1==2 arm) and fire snowChangedAtMacroPos:.\n'),
    ),
    dict(
        name='sl_12',
        method='SnowSurfaceBlock -[updateGroundFrozen:tile:]',
        types='v16@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}12',
        start=14223948,
        end=14225028,
        disasm='disasm_worldtileloader_sl_12.txt',
        base_add=14223964,
        base_literal=14225024,
        boundary='ARM.exidx end 0x00d90e84 (listing bound); next ObjC IMP 0x00d90e84 SnowSurfaceBlock -[updateSnowContent:tile:]',
        selectors={
                 0xd90e5c: (15240560, 'isClient'),
                 0xd90e70: (15240596, 'snowChangedAtMacroPos:'),
        },
        imports={
                 0xd90e58: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd90e60: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd90e64: (17169004, 'OBJC_IVAR_$_SnowSurfaceBlock.temperature', 56),
                 0xd90e6c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(14223948, 'push {r4, r5, fp, lr}'), (14225024, 'mlaeq ip, r0, r0, pc')],
        calls=[(14224032, 'blx lr'), (14224288, 'bl sym.makeIntpair_int__int_'), (14224316, 'bl loc.imp.objc_msgSend'), (14224488, 'bl sym.makeIntpair_int__int_'), (14224516, 'bl loc.imp.objc_msgSend'), (14224732, 'bl sym.makeIntpair_int__int_'), (14224760, 'bl loc.imp.objc_msgSend'), (14224932, 'bl sym.makeIntpair_int__int_'), (14224960, 'bl loc.imp.objc_msgSend')],
        branches=[(14224044, 'beq', 14224052), (14224048, 'b', 14224976), (14224088, 'bmi', 14224124), (14224104, 'bne', 14224528), (14224120, 'ble', 14224528), (14224136, 'bne', 14224324), (14224164, 'bne', 14224180), (14224320, 'b', 14224524), (14224336, 'bne', 14224520), (14224364, 'bne', 14224380), (14224520, 'b', 14224524), (14224524, 'b', 14224976), (14224564, 'ble', 14224972), (14224580, 'bne', 14224768), (14224608, 'bne', 14224624), (14224764, 'b', 14224968), (14224780, 'bne', 14224964), (14224808, 'bne', 14224824), (14224964, 'b', 14224968), (14224968, 'b', 14224972), (14224972, 'b', 14224976)],
        semantics=('[SnowSurfaceBlock -[updateGroundFrozen:tile:]] (imp 0x00d90a4c, 270w): the ground-frozen state machine - isClient gate; temperature < 0 freezes (the 0x1b/0x1c and 0x31/0x32 pairs written into BOTH fg/bg), temperature > 0 thaws them; a tile with byte0==5 carrying snow (byte4>0) also enters the freeze path; every flip fires snowChangedAtMacroPos: with the macro pos (x>>5, (y-1)>>5).\n'),
    ),
    dict(
        name='sl_13',
        method='SnowSurfaceBlock -[updateSnowContent:tile:]',
        types='v16@0:4c8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}12',
        start=14225028,
        end=14225820,
        disasm='disasm_worldtileloader_sl_13.txt',
        base_add=14225044,
        base_literal=14225816,
        boundary='ARM.exidx end 0x00d9119c (listing bound); next ObjC IMP 0x00d911d8 SnowSurfaceBlock -[removeAllSnow]',
        selectors={
                 0xd91174: (15240560, 'isClient'),
                 0xd91188: (15240564, 'macroTiles'),
                 0xd91194: (15240596, 'snowChangedAtMacroPos:'),
        },
        imports={
                 0xd91170: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd91178: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xd91180: (17169008, 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent', 60),
                 0xd91184: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd9118c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(14225028, 'push {r4, r5, r6, sl, fp, lr}'), (14225816, 'eoreq lr, ip, r8, asr ip')],
        calls=[(14225160, 'blx r2'), (14225292, 'bl 0xd9119c'), (14225420, 'blx r3'), (14225476, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_'), (14225616, 'bl sym.makeIntpair_int__int_'), (14225644, 'bl loc.imp.objc_msgSend')],
        branches=[(14225080, 'beq', 14225176), (14225096, 'beq', 14225176), (14225172, 'beq', 14225180), (14225176, 'b', 14225768), (14225252, 'bne', 14225268), (14225264, 'beq', 14225768), (14225300, 'ble', 14225480), (14225496, 'beq', 14225648), (14225660, 'beq', 14225680), (14225676, 'bne', 14225764), (14225692, 'ble', 14225728), (14225708, 'beq', 14225724), (14225724, 'b', 14225760), (14225740, 'beq', 14225756), (14225756, 'b', 14225760), (14225760, 'b', 14225764), (14225764, 'b', 14225768)],
        semantics=('[SnowSurfaceBlock -[updateSnowContent:tile:]] (imp 0x00d90e84, 198w): the snow amount write - target = (int)(partialContent * 255.0); the surface types 3/4 are exempt; a change writes tile byte4 and re-reloads the draw geometry (reloadDrawBlockGeometryForTile, sxtb arg 0) + fires snowChangedAtMacroPos:; the grass/type-5 tail arm.\n'),
    ),
    dict(
        name='sl_14',
        method='SnowSurfaceBlock -[removeAllSnow]',
        types='v8@0:4',
        start=14225880,
        end=14226388,
        disasm='disasm_worldtileloader_sl_14.txt',
        base_add=14225896,
        base_literal=14226384,
        boundary='ARM.exidx end 0x00d913d4 (listing bound); next ObjC IMP 0x00d913d4 SnowSurfaceBlock -[removeIfFloating]',
        selectors={
                 0xd913c8: (15240564, 'macroTiles'),
                 0xd913cc: (15240552, 'updateSnowContent:tile:'),
        },
        imports={
                 0xd913c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd913b4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd913b8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd913c0: (17169008, 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent', 60),
        },
        classes={},
        instructions=[(14225880, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14226384, 'eoreq lr, ip, r4, lsl 18')],
        calls=[(14226016, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14226200, 'blx r5'), (14226288, 'blx r2'), (14226344, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(14226036, 'beq', 14226348), (14226052, 'beq', 14226348), (14226068, 'ble', 14226348), (14226084, 'beq', 14226348)],
        semantics=('[SnowSurfaceBlock -[removeAllSnow]] (imp 0x00d911d8, 127w): the snow clear - walks the macro tiles and drives updateSnowContent:tile: to zero, then reloads.\n'),
    ),
    dict(
        name='sl_15',
        method='SnowSurfaceBlock -[removeIfFloating]',
        types='c8@0:4',
        start=14226388,
        end=14226824,
        disasm='disasm_worldtileloader_sl_15.txt',
        base_add=14226404,
        base_literal=14226820,
        boundary='ARM.exidx end 0x00d918d8; body trimmed at the next IMP 0x00d91588 SnowSurfaceBlock -[worldChanged:]',
        selectors={
                 0xd9157c: (15240572, 'setNeedsRemoved:'),
                 0xd91580: (15240576, 'removeAllSnow'),
        },
        imports={
                 0xd91578: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd91570: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xd91574: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(14226388, 'push {fp, lr}'), (14226820, 'eoreq lr, ip, r8, lsl 14')],
        calls=[(14226492, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14226504, 'bl sym.tileIsSolid_Tile_'), (14226524, 'bl sym.tileIsWater_Tile_'), (14226612, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14226712, 'blx ip'), (14226772, 'blx r2')],
        branches=[(14226516, 'bne', 14226780), (14226536, 'bne', 14226732), (14226632, 'beq', 14226728), (14226648, 'beq', 14226728), (14226724, 'b', 14226788), (14226728, 'b', 14226776), (14226776, 'b', 14226780)],
        semantics=('[SnowSurfaceBlock -[removeIfFloating]] (imp 0x00d913d4, 109w): the floating cleanup - when the support is gone: removeAllSnow + setNeedsRemoved:.\n'),
    ),
    dict(
        name='sl_16',
        method='SnowSurfaceBlock -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=14226824,
        end=14227672,
        disasm='disasm_worldtileloader_sl_16.txt',
        base_add=14226840,
        base_literal=14227668,
        boundary='ARM.exidx end 0x00d918d8 (listing bound); next ObjC IMP 0x00d918d8 SnowSurfaceBlock -[setNeedsRemoved:]',
        selectors={
                 0xd918c8: (15240600, 'removeIfFloating'),
                 0xd918d0: (15240572, 'setNeedsRemoved:'),
        },
        imports={
                 0xd918c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd918bc: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0xd918c0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xd918cc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(14226824, 'push {fp, lr}'), (14227668, 'eoreq lr, ip, r4, asr r5')],
        calls=[(14227320, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (14227348, 'bl sym.tileIsSolid_Tile_'), (14227368, 'bl sym.tileIsWater_Tile_'), (14227444, 'blx ip'), (14227540, 'blx r2')],
        branches=[(14226888, 'beq', 14226896), (14226892, 'b', 14227636), (14227132, 'beq', 14227636), (14227204, 'bne', 14227572), (14227244, 'bne', 14227456), (14227340, 'beq', 14227452), (14227360, 'bne', 14227384), (14227380, 'beq', 14227452), (14227448, 'b', 14227636), (14227452, 'b', 14227568), (14227496, 'bne', 14227564), (14227552, 'beq', 14227560), (14227556, 'b', 14227636), (14227560, 'b', 14227564), (14227564, 'b', 14227568), (14227568, 'b', 14227572), (14227572, 'b', 14227576), (14227632, 'b', 14226980)],
        semantics=('[SnowSurfaceBlock -[worldChanged:]] (imp 0x00d91588, 212w): the invalidation handler - 18 branches over the neighbour states with the removeIfFloating/ setNeedsRemoved: follow-ups.\n'),
    ),
    dict(
        name='sl_17',
        method='SnowSurfaceBlock -[partialContent]',
        types='f8@0:4',
        start=14227872,
        end=14227944,
        disasm='disasm_worldtileloader_sl_17.txt',
        base_add=14227896,
        base_literal=14227940,
        boundary='ARM.exidx end 0x00d91a34; body trimmed at the next IMP 0x00d919e8 SnowSurfaceBlock -[setPartialContent:]',
        selectors={},
        imports={},
        ivars={
                 0xd919e0: (17169008, 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent', 60),
        },
        classes={},
        instructions=[(14227872, 'sub sp, sp, 0xc'), (14227940, 'eoreq lr, ip, r4, lsr r1')],
        calls=[],
        branches=[],
        semantics=('[SnowSurfaceBlock -[partialContent]] (imp 0x00d919a0, 18w): bare getter (the snow target float).\n'),
    ),
    dict(
        name='sl_18',
        method='SnowSurfaceBlock -[setPartialContent:]',
        types='v12@0:4f8',
        start=14227944,
        end=14228020,
        disasm='disasm_worldtileloader_sl_18.txt',
        base_add=14227976,
        base_literal=14228016,
        boundary='ARM.exidx end 0x00d91a34 (listing bound); next ObjC IMP 0x00d98d78 DrawCube -[initWithWidth:height:depth:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:calculateNormals:]',
        selectors={},
        imports={},
        ivars={
                 0xd91a2c: (17169008, 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent', 60),
        },
        classes={},
        instructions=[(14227944, 'sub sp, sp, 0xc'), (14228016, 'eoreq lr, ip, r4, ror 1')],
        calls=[],
        branches=[],
        semantics=('[SnowSurfaceBlock -[setPartialContent:]] (imp 0x00d919e8, 19w): bare setter.\n'),
    ),
    dict(
        name='sl_19',
        method='Column -[updateConfiguration]',
        types='v8@0:4',
        start=8602128,
        end=8602936,
        disasm='disasm_worldtileloader_sl_19.txt',
        base_add=8602144,
        base_literal=8602932,
        boundary='ARM.exidx end 0x00834538 (listing bound); next ObjC IMP 0x00834538 Column -[initSubDerivedItems]',
        selectors={
                 0x834524: (15212692, 'objectType'),
                 0x834528: (15212696, 'dynamicWorldChangedAtPos:objectType:'),
                 0x834530: (15212700, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x834508: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x83450c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x834510: (17161372, 'OBJC_IVAR_$_Column.currentConfiguration', 64),
                 0x834514: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x834518: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x834520: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(8602128, 'push {fp, lr}'), (8602932, 'addeq fp, r2, ip, asr 17')],
        calls=[(8602240, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8602376, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8602716, 'bl loc.imp.objc_msgSend'), (8602752, 'bl loc.imp.objc_msgSend'), (8602832, 'bl loc.imp.objc_msgSend'), (8602876, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_')],
        branches=[(8602260, 'beq', 8602292), (8602276, 'bne', 8602288), (8602288, 'b', 8602292), (8602396, 'beq', 8602428), (8602412, 'bne', 8602424), (8602424, 'b', 8602428), (8602444, 'bne', 8602484), (8602456, 'bne', 8602472), (8602468, 'b', 8602480), (8602480, 'b', 8602508), (8602492, 'bne', 8602504), (8602504, 'b', 8602508), (8602544, 'beq', 8602880), (8602608, 'bne', 8602756)],
        semantics=('[Column -[updateConfiguration]] (imp 0x00834210, 202w): the column layout config - probes the marker 0x64 above and below (tileAtWorldPositionLoaded x, y-1 / y+1), config = 4 - 2*above - below; unchanged exits; else writes currentConfiguration + updateNeedsToBeSent and (when !isNet) fires dynamicWorldChangedAtPos:objectType:, then reloadDrawBlockDynamicObjectStaticGeometryForTile.\n'),
    ),
    dict(
        name='sl_20',
        method='Column -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=8608608,
        end=8609696,
        disasm='disasm_worldtileloader_sl_20.txt',
        base_add=8608624,
        base_literal=8609692,
        boundary='ARM.exidx end 0x00835fa0 (listing bound); next ObjC IMP 0x00835fa0 Column -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x835f64: (15212808, 'isClient'),
                 0x835f84: (15212812, 'getWeatherFractionForPos:'),
                 0x835f88: (15212816, 'worldTime'),
                 0x835f8c: (15212820, 'getDayNightFractionForX:atWorldTime:'),
                 0x835f90: (15212828, 'removeStandardObject:'),
                 0x835f98: (15212824, 'fillTile:atPos:withType:'),
        },
        imports={
                 0x835f60: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x835f68: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x835f6c: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x835f70: (17161368, 'OBJC_IVAR_$_Column.itemType', 56),
                 0x835f74: (17161376, 'OBJC_IVAR_$_Column.iceMeltTimer', 68),
                 0x835f7c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x835f80: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(8608608, 'push {r4, r5, r6, r7, fp, lr}'), (8609692, 'addeq sb, r2, ip, ror pc')],
        calls=[(8608708, 'blx r3'), (8609008, 'bl loc.imp.objc_msgSend'), (8609080, 'bl loc.imp.objc_msgSend'), (8609120, 'bl loc.imp.objc_msgSend'), (8609176, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8609264, 'bl loc.imp.objc_msgSend'), (8609312, 'bl sym.seasonForWorldX_int__double__World_'), (8609376, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (8609572, 'bl loc.imp.objc_msgSend'), (8609612, 'blx ip')],
        branches=[(8608720, 'bne', 8609624), (8608756, 'bne', 8609624), (8608792, 'bne', 8609624), (8608872, 'ble', 8609620), (8609412, 'ble', 8609616), (8609616, 'b', 8609620), (8609620, 'b', 8609624)],
        semantics=('[Column -[update:accurateDT:isSimulation:]] (imp 0x00835b60, 272w): the ice-column melt - gates (the ffffc8d4 flag / the currentBlockhead-relic / itemType == 0xf4 (244 = Ice Column)); iceMeltTimer += dt and only past 5.0 seconds acts: reset the timer, compute currentTemperatureForTileAtWorldPos (dayNight/weather/season/worldTime chain), and when temperature > 1.0 melt: fillTile:atPos:withType: with the 0x423 tile-type constant (the community-documented half block of water) + removeStandardObject:.\n'),
    ),
    dict(
        name='sl_21',
        method='Stairs -[updateConfiguration]',
        types='v8@0:4',
        start=7125984,
        end=7127740,
        disasm='disasm_worldtileloader_sl_21.txt',
        base_add=7126000,
        base_literal=7127736,
        boundary='ARM.exidx end 0x006cc2bc (listing bound); next ObjC IMP 0x006cc2bc Stairs -[initSubDerivedItems]',
        selectors={
                 0x6cc2a8: (15203304, 'objectType'),
                 0x6cc2ac: (15203308, 'dynamicWorldChangedAtPos:objectType:'),
                 0x6cc2b4: (15203312, 'macroTiles'),
        },
        imports={},
        ivars={
                 0x6cc28c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6cc290: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x6cc294: (17158340, 'OBJC_IVAR_$_Stairs.currentConfiguration', 60),
                 0x6cc298: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x6cc29c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x6cc2a4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(7125984, 'push {r4, sl, fp, lr}'), (7127736, 'ldrsheq r3, [sb], ip')],
        calls=[(7126104, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7126132, 'bl sym.tileIsSolid_Tile_'), (7126228, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7126348, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7126508, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7126656, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7126796, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7126824, 'bl sym.tileIsSolid_Tile_'), (7126936, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7127064, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7127076, 'bl sym.tileIsSolid_Tile_'), (7127180, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7127192, 'bl sym.tileIsSolid_Tile_'), (7127520, 'bl loc.imp.objc_msgSend'), (7127556, 'bl loc.imp.objc_msgSend'), (7127636, 'bl loc.imp.objc_msgSend'), (7127680, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_')],
        branches=[(7126124, 'beq', 7126416), (7126144, 'beq', 7126412), (7126248, 'beq', 7126408), (7126264, 'beq', 7126404), (7126368, 'beq', 7126400), (7126384, 'beq', 7126396), (7126396, 'b', 7126400), (7126400, 'b', 7126404), (7126404, 'b', 7126408), (7126408, 'b', 7126412), (7126412, 'b', 7126416), (7126424, 'beq', 7126564), (7126528, 'beq', 7126560), (7126544, 'bne', 7126556), (7126556, 'b', 7126560), (7126560, 'b', 7126564), (7126572, 'beq', 7126712), (7126676, 'beq', 7126708), (7126692, 'bne', 7126704), (7126704, 'b', 7126708), (7126708, 'b', 7126712), (7126816, 'beq', 7126852), (7126836, 'bne', 7126848), (7126848, 'b', 7126852), (7126860, 'beq', 7127228), (7126956, 'beq', 7127224), (7126972, 'beq', 7127224), (7126984, 'beq', 7127104), (7127088, 'bne', 7127100), (7127100, 'b', 7127220), (7127204, 'bne', 7127216), (7127216, 'b', 7127220), (7127220, 'b', 7127224), (7127224, 'b', 7127228), (7127236, 'beq', 7127276), (7127248, 'beq', 7127264), (7127260, 'b', 7127272), (7127272, 'b', 7127312), (7127284, 'beq', 7127300), (7127296, 'b', 7127308), (7127308, 'b', 7127312), (7127348, 'beq', 7127684), (7127412, 'bne', 7127560)],
        semantics=('[Stairs -[updateConfiguration]] (imp 0x006cbbe0, 439w): the stair layout config - the sl_19 sibling with the richer arm/neighbour classification (17 calls, 43 branches; same currentConfiguration/isNet/dynamicWorldChangedAtPos:objectType: family) - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='sl_22',
        method='Stairs -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=7134412,
        end=7135500,
        disasm='disasm_worldtileloader_sl_22.txt',
        base_add=7134428,
        base_literal=7135496,
        boundary='ARM.exidx end 0x006ce10c (listing bound); next ObjC IMP 0x006ce10c Stairs -[freeblockCreationItemType]',
        selectors={
                 0x6ce0d0: (15203428, 'isClient'),
                 0x6ce0f0: (15203432, 'getWeatherFractionForPos:'),
                 0x6ce0f4: (15203436, 'worldTime'),
                 0x6ce0f8: (15203440, 'getDayNightFractionForX:atWorldTime:'),
                 0x6ce0fc: (15203448, 'removeStandardObject:'),
                 0x6ce104: (15203444, 'fillTile:atPos:withType:'),
        },
        imports={
                 0x6ce0cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6ce0d4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x6ce0d8: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x6ce0dc: (17158336, 'OBJC_IVAR_$_Stairs.itemType', 56),
                 0x6ce0e0: (17158344, 'OBJC_IVAR_$_Stairs.iceMeltTimer', 68),
                 0x6ce0e8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6ce0ec: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(7134412, 'push {r4, r5, r6, r7, fp, lr}'), (7135496, 'addseq r1, sb, r0, lsl lr')],
        calls=[(7134512, 'blx r3'), (7134812, 'bl loc.imp.objc_msgSend'), (7134884, 'bl loc.imp.objc_msgSend'), (7134924, 'bl loc.imp.objc_msgSend'), (7134980, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7135068, 'bl loc.imp.objc_msgSend'), (7135116, 'bl sym.seasonForWorldX_int__double__World_'), (7135180, 'bl sym.currentTemperatureForTileAtWorldPos_Tile__intpair__float__float__float__World_'), (7135376, 'bl loc.imp.objc_msgSend'), (7135416, 'blx ip')],
        branches=[(7134524, 'bne', 7135428), (7134560, 'bne', 7135428), (7134596, 'bne', 7135428), (7134676, 'ble', 7135424), (7135216, 'ble', 7135420), (7135420, 'b', 7135424), (7135424, 'b', 7135428)],
        semantics=('[Stairs -[update:accurateDT:isSimulation:]] (imp 0x006cdccc, 272w): the stair melt - the sl_20 sibling (Stairs.itemType/iceMeltTimer; the same 244/5.0s/temp>1.0/fillTile:atPos:withType: chain).\n'),
    ),
    dict(
        name='sl_23',
        method='DynamicWorld -[snowChangedAtMacroPos:]',
        types='v16@0:4{?=ii}8',
        start=9313264,
        end=9314072,
        disasm='disasm_worldtileloader_sl_23.txt',
        base_add=9313280,
        base_literal=9314068,
        boundary='ARM.exidx end 0x008e1f18 (listing bound); next ObjC IMP 0x008e1f18 DynamicWorld -[lightChangedAtMacroPos:sendReliably:sendAtAll:]',
        selectors={},
        imports={},
        ivars={
                 0x8e1f10: (17162356, 'OBJC_IVAR_$_DynamicWorld.snowChangedMacroPositions', 6096),
        },
        classes={},
        instructions=[(9313264, 'push {r4, r5, r6, sl, fp, lr}'), (9314068, 'rsbseq sp, r7, ip, ror 29')],
        calls=[(9314048, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9313584, 'beq', 9313728), (9313632, 'bne', 9313664), (9313648, 'bne', 9313664), (9313660, 'b', 9313728), (9313664, 'b', 9313668), (9313724, 'b', 9313412), (9313736, 'bne', 9314056), (9313828, 'beq', 9314040), (9313976, 'beq', 9314020), (9314036, 'b', 9314052), (9314052, 'b', 9314056)],
        semantics=('[DynamicWorld -[snowChangedAtMacroPos:]] (imp 0x008e1bf0, 202w): the snow-change accumulator - appends the macro pos into DynamicWorld.snowChangedMacroPositions (the dup/empty gates).\n'),
    ),
    dict(
        name='sl_24',
        method='DynamicWorld -[loadSnowSurfaceBlockAtPos:loadSnow:]',
        types='v20@0:4{?=ii}8c16',
        start=9332232,
        end=9332436,
        disasm='disasm_worldtileloader_sl_24.txt',
        base_add=9332248,
        base_literal=9332432,
        boundary='ARM.exidx end 0x008e66d4 (listing bound); next ObjC IMP 0x008e66d4 DynamicWorld -[loadNPCAtPosition:type:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x8e66c0: (15216804, 'loadStandardDynamicObjectOfType:atPos:'),
                 0x8e66cc: (15216808, 'updateInTimeSinceSaved'),
        },
        imports={
                 0x8e66c8: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9332232, 'push {r4, sl, fp, lr}'), (9332432, 'ldrsbteq sb, [r7], -0x44')],
        calls=[(9332344, 'bl loc.imp.objc_msgSend'), (9332404, 'blx r2')],
        branches=[(9332360, 'beq', 9332408)],
        semantics=('[DynamicWorld -[loadSnowSurfaceBlockAtPos:loadSnow:]] (imp 0x008e6608, 51w): the loader hook - loadStandardDynamicObjectOfType:atPos: then updateInTimeSinceSaved.\n'),
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
        'batch': 'Snow surface + ice melt (E118): the SnowSurfaceBlock lifecycle, the Column/Stairs ice melt and the snow propagation hooks; 25 bodies',
        'claim': ('the snow-surface lifecycle + ice melt; four giants are census-grade and the ParticleEmitter/macroTiles contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'snowline.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale snowline.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
