#!/usr/bin/env python3
"""Hash-gated recovery of the WorldTileLoader world-constructor batch (E17).

The WorldTileLoader world constructor - the largest single body in the binary:
it stores its six arguments, resolves the block-storage location, normalises the
world size to 0x200, allocates the per-column arrays, builds the noise-function
set from the save seed, runs the per-column tree/plant candidate pass with the
spawn-distance bids, and finishes in a seed-retry loop with the best-start
search, a statistics NSLog and the world-registration dispatch:
1 body, 10857 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WTL_INITWITHWORLD.md for the prose and boundaries.
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
    'bl 0x8540cc': 0x008540cc,
    'bl 0x8540dc': 0x008540dc,
    'bl 0x8540fc': 0x008540fc,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_': 0x00a14f28,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_': 0x00854138,
    'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_': 0x004c0bd4,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.NSSearchPathForDirectoriesInDomains': 0x001c3f20,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memset': 0x001c3c8c,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.quickSort_float__unsigned_int__unsigned_int_': 0x008546e0,
}

SPECS = [
    dict(
        name='wtl_initwithworld_randomse',
        method='WorldTileLoader -[initWithWorld:randomSeed:isNewWorld:saveID:loadedVersion:blockDatabase:]',
        types='@32@0:4@8I12c16@20i24@28',
        start=8689448,
        end=8732876,
        disasm='disasm_worldtileloader_initwithworld_randomseed_isnewworld_save.txt',
        base_add=8689476,
        base_literal=8693172,
        boundary='ARM.exidx end 0x008540cc (listing bound); next ObjC IMP 0x0085475c WorldTileLoader -[compressBlocks]',
        selectors={
                 0x84a5bc: (15213476, 'init'),
                 0x84a5d0: (15213480, 'worldWidthMacro'),
                 0x84a600: (15213492, 'retain'),
                 0x84a608: (15213488, 'stringWithFormat:'),
                 0x84a60c: (15213484, 'objectAtIndex:'),
                 0x84a610: (15213496, 'server'),
                 0x84acb4: (15213508, 'initWithEnvironment:name:'),
                 0x84acbc: (15213500, 'alloc'),
                 0x84acc4: (15213504, 'initWithPath:maxDatabases:maxMapSizeInMB:'),
                 0x84acd0: (15213520, 'countByEnumeratingWithState:objects:count:'),
                 0x84acd4: (15213516, 'contentsOfDirectoryAtPath:error:'),
                 0x84acd8: (15213512, 'defaultManager'),
                 0x84ace0: (15213524, 'length'),
                 0x84ace4: (15213528, 'rangeOfString:'),
                 0x84acf8: (15213548, 'moveItemAtPath:toPath:error:'),
                 0x84acfc: (15213544, 'createDirectoryAtPath:withIntermediateDirectories:attributes:error:'),
                 0x84ad00: (15213540, 'stringByDeletingLastPathComponent'),
                 0x84ad04: (15213536, 'stringByAppendingPathComponent:'),
                 0x84ad10: (15213532, 'substringWithRange:'),
                 0x84ad14: (15213552, 'removeItemAtPath:error:'),
                 0x84ad1c: (15213556, 'customRules'),
                 0x84b674: (15213564, 'initWithFrequencyX:frequencyY:frequencyZ:amplitude:seed:tileableX:tileableY:loop:persistance:'),
                 0x84b704: (15213560, 'initWithFrequencyX:frequencyY:frequencyZ:amplitude:seed:tileable:loop:persistance:'),
                 0x84c4d0: (15213568, 'getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:'),
                 0x84cc8c: (15213480, 'worldWidthMacro'),
                 0x84cfa0: (15213556, 'customRules'),
                 0x84d080: (15213576, 'isCaveForX:y:faultOffset:'),
                 0x84d084: (15213572, 'faultOffsetForX:y:'),
                 0x84d088: (15213580, 'isDesertForPos:height:'),
                 0x84d9bc: (15213584, 'findBestStartPosition'),
                 0x84d9d0: (15213588, 'release'),
                 0x84e448: (15213560, 'initWithFrequencyX:frequencyY:frequencyZ:amplitude:seed:tileable:loop:persistance:'),
                 0x84e450: (15213500, 'alloc'),
                 0x84ead4: (15213480, 'worldWidthMacro'),
                 0x84eae4: (15213556, 'customRules'),
                 0x84eb10: (15213592, 'sandFractionForPos:height:highRes:'),
                 0x84eb20: (15213596, 'isBeachForPos:height:'),
                 0x84eb3c: (15213600, 'getX:Y:octaves:'),
                 0x850630: (15213600, 'getX:Y:octaves:'),
                 0x850638: (15213480, 'worldWidthMacro'),
                 0x85063c: (15213556, 'customRules'),
                 0x85166c: (15213600, 'getX:Y:octaves:'),
                 0x851678: (15213480, 'worldWidthMacro'),
                 0x853984: (15213600, 'getX:Y:octaves:'),
                 0x853990: (15213480, 'worldWidthMacro'),
                 0x853a1c: (15213480, 'worldWidthMacro'),
                 0x85403c: (15213480, 'worldWidthMacro'),
                 0x854050: (15213608, 'detachNewThreadSelector:toTarget:withObject:'),
                 0x854054: (15213604, 'compressBlocks'),
                 0x85405c: (15213556, 'customRules'),
                 0x854078: (15213588, 'release'),
                 0x8540b4: (15213576, 'isCaveForX:y:faultOffset:'),
                 0x8540b8: (15213572, 'faultOffsetForX:y:'),
                 0x8540c0: (15213600, 'getX:Y:octaves:'),
        },
        imports={
                 0x84a5b8: (17151900, 'objc_msgSendSuper2'),
                 0x84a5c4: (17151968, '__stack_chk_guard'),
                 0x84a5cc: (17151904, 'objc_msgSend'),
                 0x84a604: (16327512, '__CFConstantStringClassReference'),
                 0x84a614: (16327528, '__CFConstantStringClassReference'),
                 0x84acb0: (16327544, '__CFConstantStringClassReference'),
                 0x84accc: (16327560, '__CFConstantStringClassReference'),
                 0x84ace8: (16327576, '__CFConstantStringClassReference'),
                 0x84acf4: (16327592, '__CFConstantStringClassReference'),
                 0x84ad08: (16327608, '__CFConstantStringClassReference'),
                 0x84ad18: (16327624, '__CFConstantStringClassReference'),
                 0x84d07c: (17151904, 'objc_msgSend'),
                 0x84d9c4: (16327640, '__CFConstantStringClassReference'),
                 0x84eb38: (17151904, 'objc_msgSend'),
                 0x85062c: (17151904, 'objc_msgSend'),
                 0x851668: (17151904, 'objc_msgSend'),
                 0x8538f4: (17151904, 'objc_msgSend'),
                 0x853980: (17151904, 'objc_msgSend'),
                 0x854034: (17151968, '__stack_chk_guard'),
                 0x854038: (17151904, 'objc_msgSend'),
                 0x85409c: (16327656, '__CFConstantStringClassReference'),
                 0x8540a8: (16327672, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x84a5c8: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x84a5d4: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x84a5d8: (17161552, 'OBJC_IVAR_$_WorldTileLoader.xFrequencyMultiplier', 240),
                 0x84a5dc: (17161556, 'OBJC_IVAR_$_WorldTileLoader.blockDatabase', 256),
                 0x84a5e4: (17161560, 'OBJC_IVAR_$_WorldTileLoader.randomSeed', 8),
                 0x84a5ec: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x84a5f0: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x84a5f8: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
                 0x84a5fc: (17161576, 'OBJC_IVAR_$_WorldTileLoader.blockDirectory', 12),
                 0x84acac: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
                 0x84acb8: (17161584, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment', 248),
                 0x84b670: (17161588, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionB', 56),
                 0x84b6f8: (17161592, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionA', 52),
                 0x84b6fc: (17161596, 'OBJC_IVAR_$_WorldTileLoader.faultNoiseFunction', 24),
                 0x84b700: (17161600, 'OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction', 44),
                 0x84b708: (17161604, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB', 20),
                 0x84b70c: (17161608, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA', 16),
                 0x84b78c: (17161604, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB', 20),
                 0x84b790: (17161608, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA', 16),
                 0x84c578: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x84cd38: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x84cde8: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x84cf98: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
                 0x84d9c0: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x84d9c8: (17161560, 'OBJC_IVAR_$_WorldTileLoader.randomSeed', 8),
                 0x84d9cc: (17161588, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionB', 56),
                 0x84d9d4: (17161592, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionA', 52),
                 0x84d9d8: (17161600, 'OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction', 44),
                 0x84d9dc: (17161596, 'OBJC_IVAR_$_WorldTileLoader.faultNoiseFunction', 24),
                 0x84d9e0: (17161604, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB', 20),
                 0x84d9e4: (17161608, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA', 16),
                 0x84e400: (17161616, 'OBJC_IVAR_$_WorldTileLoader.gemNoiseFunction', 60),
                 0x84e44c: (17161552, 'OBJC_IVAR_$_WorldTileLoader.xFrequencyMultiplier', 240),
                 0x84e458: (17161620, 'OBJC_IVAR_$_WorldTileLoader.seasonOffsetNoiseFunction', 48),
                 0x84e45c: (17161624, 'OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction', 40),
                 0x84e460: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x84e464: (17161632, 'OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction', 32),
                 0x84e4bc: (17161632, 'OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction', 32),
                 0x84e4c0: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x84eac8: (17161640, 'OBJC_IVAR_$_WorldTileLoader.treePositions', 64),
                 0x84ead0: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x84ead8: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x84eadc: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
                 0x84eaf4: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x84eafc: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x84eb04: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
                 0x84eb50: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x8505fc: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x850614: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85061c: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x850620: (17161640, 'OBJC_IVAR_$_WorldTileLoader.treePositions', 64),
                 0x850698: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
                 0x851634: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85164c: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x851650: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
                 0x851670: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x852c90: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x852c98: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x852ca0: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x8536b0: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x853740: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x8537d4: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x853988: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x853ab8: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
                 0x854040: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x854044: (17161560, 'OBJC_IVAR_$_WorldTileLoader.randomSeed', 8),
                 0x854048: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x85404c: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x854060: (17161588, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionB', 56),
                 0x854064: (17161592, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionA', 52),
                 0x854068: (17161596, 'OBJC_IVAR_$_WorldTileLoader.faultNoiseFunction', 24),
                 0x85406c: (17161600, 'OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction', 44),
                 0x854070: (17161604, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB', 20),
                 0x854074: (17161608, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA', 16),
                 0x85407c: (17161616, 'OBJC_IVAR_$_WorldTileLoader.gemNoiseFunction', 60),
                 0x854080: (17161620, 'OBJC_IVAR_$_WorldTileLoader.seasonOffsetNoiseFunction', 48),
                 0x854084: (17161624, 'OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction', 40),
                 0x854088: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x85408c: (17161632, 'OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction', 32),
                 0x854090: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x854094: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x8540a0: (17161652, 'OBJC_IVAR_$_WorldTileLoader.distanceOrderedFoodTypes', 108),
                 0x8540b0: (17161656, 'OBJC_IVAR_$_WorldTileLoader.highestPoint', 84),
        },
        classes={
                 0x84a5c0: (15252880, 'OBJC_CLASS_$_WorldTileLoader'),
                 0x84a5f4: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x84acc0: (15247504, 'OBJC_CLASS_$_Database'),
                 0x84acc8: (15247500, 'OBJC_CLASS_$_DatabaseEnvironment'),
                 0x84acdc: (15247508, 'OBJC_CLASS_$_NSFileManager'),
                 0x84b6f4: (15247512, 'OBJC_CLASS_$_NoiseFunction'),
                 0x84e454: (15247512, 'OBJC_CLASS_$_NoiseFunction'),
                 0x854058: (15247516, 'OBJC_CLASS_$_NSThread'),
        },
        instructions=[(8689448, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8689628, 'blx sl'), (8689836, 'blx r3'), (8689968, 'ldr r1, [sp, 0xe90]'), (8690204, 'bl sym.imp.__wrap_calloc'), (8690416, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8691776, 'cmp r0, 0x20'), (8693056, 'sub lr, fp, 0xa00'), (8693088, 'movw r0, 0'), (8693780, 'blx r8'), (8696960, 'movw r0, 5'), (8697296, 'movw r0, 0'), (8700200, 'blx ip'), (8701444, 'movw r0, 0'), (8704000, 'ldr r1, [sp, 0xea4]'), (8704040, 'b 0x84d074'), (8704984, 'ldr r0, [0x0084d07c]'), (8706072, 'blx r7'), (8709392, 'movw r0, 5'), (8709576, 'bl sym.imp.__aeabi_idiv'), (8710104, 'bl sym.makeIntpair_int__int_'), (8711456, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8712860, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8716472, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8716636, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8718480, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8722140, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8722848, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8726308, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8729256, 'movw r0, 5'), (8729340, 'bge 0x8534d8'), (8729664, 'blx ip'), (8729816, 'sub lr, fp, 0xa00'), (8730064, 'bl sym.imp.NSLog'), (8731432, 'bl sym.imp.NSLog'), (8731692, 'blx ip'), (8732404, 'str ip, [r0]'), (8732456, 'bl sym.quickSort_float__unsigned_int__unsigned_int_'), (8732536, 'str r2, [r1]'), (8732568, 'movw r0, 0'), (8732660, 'ldr r0, [fp, -0xa88]'), (8732704, 'ldr r0, [sp, 0x2c]'), (8732872, 'umulleq ip, r0, r4, r8')],
        calls=[(8689628, 'blx sl'), (8689836, 'blx r3'), (8689956, 'bl sym.imp.__aeabi_idiv'), (8690188, 'bl loc.imp.objc_msgSend'), (8690204, 'bl sym.imp.__wrap_calloc'), (8690256, 'bl loc.imp.objc_msgSend'), (8690268, 'bl sym.imp.__wrap_calloc'), (8690320, 'bl loc.imp.objc_msgSend'), (8690344, 'bl sym.imp.__wrap_calloc'), (8690416, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8690572, 'blx r5'), (8690628, 'blx lr'), (8690644, 'blx r2'), (8690700, 'bl sym.imp.NSSearchPathForDirectoriesInDomains'), (8690820, 'blx sl'), (8690876, 'blx lr'), (8690916, 'blx r3'), (8691108, 'blx r6'), (8691140, 'blx lr'), (8691192, 'blx ip'), (8691232, 'blx ip'), (8691296, 'bl sym.imp.NSLog'), (8691484, 'blx r2'), (8691524, 'blx ip'), (8691548, 'bl sym.imp.memset'), (8691596, 'blx lr'), (8691700, 'bl sym.imp.objc_enumerationMutation'), (8691772, 'blx r2'), (8691852, 'bl loc.imp.objc_msgSend_stret'), (8691888, 'bl sym.imp.memset'), (8691944, 'bl sym.imp.NSLog'), (8692264, 'bl loc.imp.objc_msgSend'), (8692328, 'bl loc.imp.objc_msgSend'), (8692364, 'bl loc.imp.objc_msgSend'), (8692432, 'bl loc.imp.objc_msgSend'), (8692484, 'blx r4'), (8692528, 'blx ip'), (8692572, 'blx ip'), (8692608, 'blx r3'), (8692640, 'blx r3'), (8692692, 'blx lr'), (8692724, 'blx r2'), (8692756, 'blx lr'), (8692848, 'blx lr'), (8692872, 'blx ip'), (8692992, 'blx ip'), (8693048, 'bl sym.imp.NSLog'), (8693164, 'bl loc.imp.objc_msgSend_stret'), (8693324, 'bl sym.imp.memset'), (8693408, 'blx r2'), (8693780, 'blx r8'), (8693920, 'blx r7'), (8693972, 'blx ip'), (8694112, 'blx r7'), (8694164, 'blx ip'), (8694304, 'blx r7'), (8694356, 'blx ip'), (8694504, 'blx r7'), (8694556, 'blx ip'), (8694716, 'blx r8'), (8694768, 'blx ip'), (8694928, 'blx r8'), (8695408, 'blx lr'), (8695568, 'blx r8'), (8695620, 'blx ip'), (8695780, 'blx r8'), (8695832, 'blx ip'), (8695992, 'blx r8'), (8696044, 'blx ip'), (8696204, 'blx r8'), (8696256, 'blx ip'), (8696432, 'blx r8'), (8696484, 'blx ip'), (8696660, 'blx r8'), (8696772, 'bl loc.imp.objc_msgSend'), (8696788, 'bl sym.imp.__wrap_calloc'), (8696824, 'bl loc.imp.objc_msgSend'), (8696836, 'bl sym.imp.__wrap_calloc'), (8696896, 'bl loc.imp.objc_msgSend'), (8696928, 'bl sym.imp.memset'), (8697020, 'bl loc.imp.objc_msgSend'), (8697112, 'bl loc.imp.objc_msgSend'), (8697448, 'bl loc.imp.objc_msgSend_stret'), (8697492, 'bl sym.imp.memset'), (8697580, 'bl loc.imp.objc_msgSend_stret'), (8697644, 'bl sym.imp.memset'), (8697732, 'bl loc.imp.objc_msgSend_stret'), (8697776, 'bl sym.imp.memset'), (8697892, 'bl loc.imp.objc_msgSend_stret'), (8697928, 'bl sym.imp.memset'), (8698048, 'bl loc.imp.objc_msgSend_stret'), (8698084, 'bl sym.imp.memset'), (8698204, 'bl loc.imp.objc_msgSend_stret'), (8698240, 'bl sym.imp.memset'), (8698332, 'bl loc.imp.objc_msgSend_stret'), (8698376, 'bl sym.imp.memset'), (8698468, 'bl loc.imp.objc_msgSend_stret'), (8698504, 'bl sym.imp.memset'), (8698620, 'bl loc.imp.objc_msgSend_stret'), (8698656, 'bl sym.imp.memset'), (8698812, 'bl loc.imp.objc_msgSend_stret'), (8698848, 'bl sym.imp.memset'), (8698960, 'bl loc.imp.objc_msgSend_stret'), (8698996, 'bl sym.imp.memset'), (8699160, 'bl loc.imp.objc_msgSend'), (8699936, 'bl loc.imp.objc_msgSend_stret'), (8699972, 'bl sym.imp.memset'), (8700200, 'blx ip'), (8700244, 'blx lr'), (8700360, 'bl loc.imp.objc_msgSend_stret'), (8700400, 'bl sym.imp.memset'), (8700456, 'bl sym.makeIntpair_int__int_'), (8700500, 'bl loc.imp.objc_msgSend'), (8701028, 'bl 0x8540cc'), (8701128, 'bl loc.imp.objc_msgSend_stret'), (8701172, 'bl sym.imp.memset'), (8701296, 'bl loc.imp.objc_msgSend_stret'), (8701340, 'bl sym.imp.memset'), (8701384, 'bl sym.makeIntpair_int__int_'), (8701428, 'bl loc.imp.objc_msgSend'), (8701672, 'bl loc.imp.objc_msgSend_stret'), (8701712, 'bl sym.imp.memset'), (8701784, 'bl loc.imp.objc_msgSend'), (8702088, 'bl loc.imp.objc_msgSend_stret'), (8702132, 'bl sym.imp.memset'), (8702348, 'blx ip'), (8702392, 'blx lr'), (8702512, 'bl loc.imp.objc_msgSend_stret'), (8702552, 'bl sym.imp.memset'), (8702604, 'bl sym.makeIntpair_int__int_'), (8702648, 'bl loc.imp.objc_msgSend'), (8703176, 'bl 0x8540cc'), (8703280, 'bl loc.imp.objc_msgSend_stret'), (8703328, 'bl sym.imp.memset'), (8703452, 'bl loc.imp.objc_msgSend_stret'), (8703504, 'bl sym.imp.memset'), (8703552, 'bl sym.makeIntpair_int__int_'), (8703596, 'bl loc.imp.objc_msgSend'), (8703752, 'bl sym.imp.__aeabi_idiv'), (8703784, 'bl sym.imp.__wrap_free'), (8703792, 'bl sym.imp.__wrap_free'), (8703888, 'bl loc.imp.objc_msgSend_stret'), (8703936, 'bl sym.imp.memset'), (8704056, 'bl sym.imp.NSLog'), (8704112, 'bl 0x8540dc'), (8704312, 'blx r3'), (8704372, 'blx lr'), (8704432, 'blx lr'), (8704492, 'blx lr'), (8704552, 'blx lr'), (8704612, 'blx lr'), (8704724, 'bl loc.imp.objc_msgSend_stret'), (8704764, 'bl sym.imp.memset'), (8704876, 'bl loc.imp.objc_msgSend_stret'), (8704952, 'bl sym.imp.memset'), (8705044, 'blx r2'), (8705336, 'blx lr'), (8705476, 'blx r7'), (8705528, 'blx ip'), (8705668, 'blx r7'), (8705720, 'blx ip'), (8705872, 'blx r8'), (8705924, 'blx ip'), (8706072, 'blx r7'), (8706124, 'blx ip'), (8706260, 'blx r6'), (8706312, 'blx ip'), (8706448, 'blx r6'), (8706788, 'blx ip'), (8706948, 'blx r8'), (8707000, 'blx ip'), (8707160, 'blx r8'), (8707212, 'blx ip'), (8707384, 'blx r8'), (8707436, 'blx ip'), (8707604, 'blx r7'), (8707656, 'blx ip'), (8707812, 'blx r7'), (8707864, 'blx ip'), (8708020, 'blx r7'), (8708176, 'bl loc.imp.objc_msgSend'), (8708204, 'bl sym.imp.__aeabi_memset'), (8708260, 'bl loc.imp.objc_msgSend'), (8708276, 'bl sym.imp.__aeabi_memset'), (8708332, 'bl loc.imp.objc_msgSend'), (8708364, 'bl sym.imp.memset'), (8708444, 'bl loc.imp.objc_msgSend'), (8708460, 'bl sym.imp.__wrap_calloc'), (8708512, 'bl loc.imp.objc_msgSend'), (8708524, 'bl sym.imp.__wrap_calloc'), (8708576, 'bl loc.imp.objc_msgSend'), (8708600, 'bl sym.imp.__wrap_calloc'), (8708796, 'bl loc.imp.objc_msgSend_stret'), (8708836, 'bl sym.imp.memset'), (8708948, 'bl loc.imp.objc_msgSend_stret'), (8708988, 'bl sym.imp.memset'), (8709112, 'bl loc.imp.objc_msgSend_stret'), (8709156, 'bl sym.imp.memset'), (8709300, 'bl loc.imp.objc_msgSend_stret'), (8709348, 'bl sym.imp.memset'), (8709452, 'bl loc.imp.objc_msgSend'), (8709552, 'bl loc.imp.objc_msgSend'), (8709576, 'bl sym.imp.__aeabi_idiv'), (8709668, 'bl loc.imp.objc_msgSend'), (8709692, 'bl sym.imp.__aeabi_idiv'), (8710104, 'bl sym.makeIntpair_int__int_'), (8710168, 'bl loc.imp.objc_msgSend'), (8710244, 'bl sym.makeIntpair_int__int_'), (8710284, 'bl loc.imp.objc_msgSend'), (8710576, 'bl loc.imp.objc_msgSend_stret'), (8710616, 'bl sym.imp.memset'), (8710712, 'bl loc.imp.objc_msgSend_stret'), (8710752, 'bl sym.imp.memset'), (8710848, 'bl loc.imp.objc_msgSend_stret'), (8711040, 'bl sym.imp.memset'), (8711220, 'bl loc.imp.objc_msgSend'), (8711308, 'blx lr'), (8711412, 'bl sym.makeIntpair_int__int_'), (8711456, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8711508, 'bl 0x8540cc'), (8711668, 'bl 0x8540fc'), (8711952, 'bl loc.imp.objc_msgSend'), (8712040, 'blx lr'), (8712140, 'bl sym.makeIntpair_int__int_'), (8712184, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8712272, 'bl 0x8540cc'), (8712628, 'bl loc.imp.objc_msgSend'), (8712716, 'blx lr'), (8712816, 'bl sym.makeIntpair_int__int_'), (8712860, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8712912, 'bl 0x8540cc'), (8713064, 'bl 0x8540fc'), (8713344, 'bl loc.imp.objc_msgSend'), (8713432, 'blx lr'), (8713536, 'bl sym.makeIntpair_int__int_'), (8713580, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8713664, 'bl 0x8540cc'), (8713824, 'bl 0x8540fc'), (8714108, 'bl loc.imp.objc_msgSend'), (8714196, 'blx lr'), (8714296, 'bl sym.makeIntpair_int__int_'), (8714340, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8714392, 'bl 0x8540cc'), (8714552, 'bl 0x8540fc'), (8714832, 'bl loc.imp.objc_msgSend'), (8714920, 'blx lr'), (8715052, 'bl sym.makeIntpair_int__int_'), (8715096, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8715148, 'bl 0x8540cc'), (8715308, 'bl 0x8540fc'), (8715344, 'bl sym.imp.__aeabi_idiv'), (8715600, 'bl loc.imp.objc_msgSend'), (8715688, 'blx lr'), (8715844, 'bl loc.imp.objc_msgSend_stret'), (8715892, 'bl sym.imp.memset'), (8716020, 'blx r2'), (8716060, 'bl sym.imp.__wrap_fmodf'), (8716128, 'bl sym.makeIntpair_int__int_'), (8716208, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_'), (8716308, 'bl sym.clamp_float__float__float_'), (8716428, 'bl sym.makeIntpair_int__int_'), (8716472, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8716592, 'bl sym.makeIntpair_int__int_'), (8716636, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8716720, 'bl 0x8540cc'), (8716876, 'bl 0x8540fc'), (8717276, 'bl loc.imp.objc_msgSend'), (8717364, 'blx lr'), (8717412, 'bl 0x8540cc'), (8717572, 'bl 0x8540fc'), (8717608, 'bl sym.imp.__aeabi_idiv'), (8717804, 'bl loc.imp.objc_msgSend_stret'), (8718048, 'bl sym.imp.memset'), (8718244, 'bl loc.imp.objc_msgSend'), (8718332, 'blx lr'), (8718436, 'bl sym.makeIntpair_int__int_'), (8718480, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8718540, 'bl 0x8540cc'), (8718900, 'bl loc.imp.objc_msgSend'), (8718988, 'blx lr'), (8719092, 'bl sym.makeIntpair_int__int_'), (8719136, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8719288, 'bl 0x8540cc'), (8719644, 'bl loc.imp.objc_msgSend'), (8719732, 'blx lr'), (8719836, 'bl sym.makeIntpair_int__int_'), (8719880, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8719940, 'bl 0x8540cc'), (8720304, 'bl loc.imp.objc_msgSend'), (8720392, 'blx lr'), (8720492, 'bl sym.makeIntpair_int__int_'), (8720536, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8720656, 'bl 0x8540cc'), (8720816, 'bl 0x8540fc'), (8721092, 'bl loc.imp.objc_msgSend'), (8721172, 'blx lr'), (8721264, 'bl sym.makeIntpair_int__int_'), (8721308, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8721364, 'bl 0x8540cc'), (8721524, 'bl 0x8540fc'), (8721560, 'bl sym.imp.__aeabi_idiv'), (8721808, 'bl loc.imp.objc_msgSend'), (8721888, 'blx lr'), (8722096, 'bl sym.makeIntpair_int__int_'), (8722140, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8722196, 'bl 0x8540cc'), (8722356, 'bl 0x8540fc'), (8722632, 'bl loc.imp.objc_msgSend'), (8722712, 'blx lr'), (8722804, 'bl sym.makeIntpair_int__int_'), (8722848, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8722904, 'bl 0x8540cc'), (8723256, 'bl loc.imp.objc_msgSend'), (8723336, 'blx lr'), (8723476, 'bl sym.makeIntpair_int__int_'), (8723520, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8723568, 'bl 0x8540cc'), (8723728, 'bl 0x8540fc'), (8724096, 'bl 0x8540fc'), (8724172, 'bl 0x8540fc'), (8724316, 'bl loc.imp.objc_msgSend'), (8724396, 'blx lr'), (8724480, 'bl sym.makeIntpair_int__int_'), (8724524, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8724592, 'bl 0x8540cc'), (8724752, 'bl 0x8540fc'), (8724808, 'bl sym.imp.__aeabi_idiv'), (8724840, 'bl sym.imp.__aeabi_idiv'), (8725292, 'bl loc.imp.objc_msgSend'), (8725372, 'blx lr'), (8725408, 'bl 0x8540cc'), (8725836, 'bl 0x8540fc'), (8725912, 'bl 0x8540fc'), (8726068, 'bl loc.imp.objc_msgSend'), (8726148, 'blx lr'), (8726264, 'bl sym.makeIntpair_int__int_'), (8726308, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8726356, 'bl 0x8540cc'), (8726800, 'bl 0x8540fc'), (8726876, 'bl 0x8540fc'), (8727032, 'bl loc.imp.objc_msgSend'), (8727112, 'blx lr'), (8727196, 'bl sym.makeIntpair_int__int_'), (8727240, 'bl sym.growthVigorForPlantTypeAtPos_PlantType__intpair__World_'), (8727288, 'bl 0x8540cc'), (8727980, 'bl loc.imp.objc_msgSend'), (8728060, 'blx lr'), (8728104, 'bl 0x8540cc'), (8728436, 'bl loc.imp.objc_msgSend'), (8728516, 'blx lr'), (8728560, 'bl 0x8540cc'), (8728956, 'bl loc.imp.objc_msgSend'), (8729036, 'blx lr'), (8729072, 'bl 0x8540cc'), (8729316, 'bl loc.imp.objc_msgSend'), (8729664, 'blx ip'), (8729708, 'blx lr'), (8730064, 'bl sym.imp.NSLog'), (8730144, 'bl loc.imp.objc_msgSend_stret'), (8730184, 'bl sym.imp.memset'), (8730280, 'bl loc.imp.objc_msgSend_stret'), (8730328, 'bl sym.imp.memset'), (8730424, 'bl loc.imp.objc_msgSend_stret'), (8730472, 'bl sym.imp.memset'), (8730568, 'bl loc.imp.objc_msgSend_stret'), (8730616, 'bl sym.imp.memset'), (8730712, 'bl loc.imp.objc_msgSend_stret'), (8730760, 'bl sym.imp.memset'), (8730856, 'bl loc.imp.objc_msgSend_stret'), (8730904, 'bl sym.imp.memset'), (8731000, 'bl loc.imp.objc_msgSend_stret'), (8731060, 'bl sym.imp.memset'), (8731156, 'bl loc.imp.objc_msgSend_stret'), (8731200, 'bl sym.imp.memset'), (8731296, 'bl loc.imp.objc_msgSend_stret'), (8731372, 'bl sym.imp.memset'), (8731432, 'bl sym.imp.NSLog'), (8731692, 'blx ip'), (8731752, 'blx lr'), (8731812, 'blx lr'), (8731872, 'blx lr'), (8731932, 'blx lr'), (8731992, 'blx lr'), (8732052, 'blx lr'), (8732112, 'blx lr'), (8732172, 'blx lr'), (8732232, 'blx lr'), (8732292, 'blx lr'), (8732352, 'blx lr'), (8732424, 'bl 0x8540dc'), (8732456, 'bl sym.quickSort_float__unsigned_int__unsigned_int_'), (8732656, 'blx lr'), (8732716, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8689656, 'bne', 8689672), (8689668, 'b', 8732668), (8689880, 'ble', 8690004), (8690000, 'b', 8689872), (8690004, 'b', 8690008), (8690016, 'bge', 8690084), (8690076, 'b', 8690008), (8690928, 'beq', 8691304), (8691280, 'bne', 8691300), (8691300, 'b', 8691304), (8691608, 'beq', 8693016), (8691692, 'beq', 8691704), (8691780, 'bne', 8692884), (8691820, 'beq', 8691860), (8691856, 'b', 8691892), (8691904, 'bne', 8692884), (8691920, 'bne', 8691948), (8692768, 'bne', 8692880), (8692880, 'b', 8692884), (8692884, 'b', 8692888), (8692912, 'blo', 8691656), (8693012, 'bne', 8691656), (8693016, 'b', 8693020), (8693032, 'beq', 8693052), (8693052, 'b', 8693056), (8693084, 'beq', 8732568), (8693148, 'beq', 8693296), (8693168, 'b', 8693328), (8693336, 'bne', 8693348), (8693416, 'bge', 8695096), (8694952, 'b', 8696684), (8697044, 'bge', 8697296), (8697152, 'ble', 8697192), (8697236, 'bpl', 8697276), (8697276, 'b', 8697280), (8697292, 'b', 8696960), (8697432, 'beq', 8697464), (8697452, 'b', 8697496), (8697504, 'beq', 8697796), (8697564, 'beq', 8697616), (8697584, 'b', 8697648), (8697656, 'beq', 8697796), (8697716, 'beq', 8697748), (8697736, 'b', 8697780), (8697792, 'bne', 8697820), (8697816, 'b', 8698132), (8697876, 'beq', 8697900), (8697896, 'b', 8697932), (8697944, 'bne', 8697976), (8697972, 'b', 8698128), (8698032, 'beq', 8698056), (8698052, 'b', 8698088), (8698100, 'bne', 8698124), (8698124, 'b', 8698128), (8698128, 'b', 8698132), (8698188, 'beq', 8698212), (8698208, 'b', 8698244), (8698256, 'beq', 8698524), (8698316, 'beq', 8698348), (8698336, 'b', 8698380), (8698392, 'beq', 8698524), (8698452, 'beq', 8698476), (8698472, 'b', 8698508), (8698520, 'bne', 8698548), (8698544, 'b', 8698704), (8698604, 'beq', 8698628), (8698624, 'b', 8698660), (8698672, 'bne', 8698700), (8698700, 'b', 8698704), (8698796, 'beq', 8698820), (8698816, 'b', 8698852), (8698944, 'beq', 8698968), (8698964, 'b', 8699000), (8699056, 'bge', 8703780), (8699184, 'bge', 8701564), (8699196, 'bne', 8699676), (8699244, 'ble', 8699344), (8699340, 'b', 8699436), (8699480, 'ble', 8699580), (8699576, 'b', 8699672), (8699672, 'b', 8699676), (8699772, 'bge', 8699788), (8699784, 'b', 8699796), (8699860, 'bne', 8701516), (8699920, 'beq', 8699944), (8699940, 'b', 8699976), (8699988, 'beq', 8701516), (8700000, 'ble', 8701516), (8700012, 'ble', 8701516), (8700088, 'bgt', 8700260), (8700256, 'bne', 8701516), (8700268, 'bgt', 8700288), (8700284, 'beq', 8700836), (8700344, 'beq', 8700372), (8700364, 'b', 8700404), (8700424, 'beq', 8700524), (8700548, 'bge', 8700644), (8700576, 'bgt', 8700612), (8700592, 'bne', 8700612), (8700608, 'beq', 8700640), (8700640, 'b', 8700832), (8700656, 'bne', 8700680), (8700676, 'b', 8700828), (8700696, 'ble', 8700824), (8700720, 'bge', 8700796), (8700788, 'b', 8700708), (8700824, 'b', 8700828), (8700828, 'b', 8700832), (8700832, 'b', 8701512), (8700952, 'bge', 8700972), (8700964, 'b', 8700980), (8701000, 'bge', 8701492), (8701024, 'ble', 8701488), (8701112, 'beq', 8701144), (8701132, 'b', 8701176), (8701216, 'ble', 8701488), (8701276, 'beq', 8701308), (8701300, 'b', 8701344), (8701356, 'beq', 8701444), (8701440, 'bne', 8701488), (8701488, 'b', 8701508), (8701508, 'b', 8701512), (8701512, 'b', 8701544), (8701544, 'b', 8701548), (8701560, 'b', 8699100), (8701652, 'beq', 8701680), (8701676, 'b', 8701716), (8701728, 'beq', 8703744), (8701816, 'ble', 8703740), (8701916, 'bge', 8701936), (8701928, 'b', 8701944), (8702008, 'bne', 8703684), (8702068, 'beq', 8702100), (8702092, 'b', 8702136), (8702148, 'beq', 8703684), (8702160, 'ble', 8703684), (8702236, 'bgt', 8702408), (8702404, 'bne', 8703684), (8702416, 'bgt', 8702436), (8702432, 'beq', 8702984), (8702492, 'beq', 8702520), (8702516, 'b', 8702556), (8702576, 'beq', 8702672), (8702696, 'bge', 8702792), (8702724, 'bgt', 8702760), (8702740, 'bne', 8702760), (8702756, 'beq', 8702788), (8702788, 'b', 8702980), (8702804, 'bne', 8702828), (8702824, 'b', 8702976), (8702844, 'ble', 8702972), (8702872, 'bgt', 8702944), (8702940, 'b', 8702860), (8702972, 'b', 8702976), (8702976, 'b', 8702980), (8702980, 'b', 8703680), (8703096, 'bge', 8703120), (8703108, 'b', 8703128), (8703148, 'bge', 8703660), (8703172, 'ble', 8703656), (8703260, 'beq', 8703296), (8703284, 'b', 8703332), (8703372, 'ble', 8703656), (8703432, 'beq', 8703472), (8703456, 'b', 8703508), (8703520, 'beq', 8703612), (8703608, 'bne', 8703656), (8703656, 'b', 8703676), (8703676, 'b', 8703680), (8703680, 'b', 8703712), (8703712, 'b', 8703716), (8703732, 'b', 8701808), (8703740, 'b', 8703744), (8703772, 'b', 8699044), (8703808, 'beq', 8704152), (8703872, 'beq', 8703908), (8703892, 'b', 8703940), (8703992, 'beq', 8704044), (8704028, 'beq', 8704044), (8704040, 'b', 8704116), (8704116, 'b', 8704160), (8704172, 'bne', 8704644), (8704640, 'b', 8693056), (8704704, 'beq', 8704732), (8704728, 'b', 8704768), (8704780, 'bne', 8704800), (8704792, 'b', 8704984), (8704856, 'beq', 8704920), (8704880, 'b', 8704956), (8704968, 'bne', 8704980), (8704980, 'b', 8704984), (8705052, 'bge', 8706544), (8706472, 'b', 8708044), (8708080, 'beq', 8708372), (8708368, 'b', 8708632), (8708652, 'bge', 8708708), (8708704, 'b', 8708644), (8708776, 'beq', 8708804), (8708800, 'b', 8708840), (8708852, 'bne', 8708872), (8708868, 'b', 8709024), (8708928, 'beq', 8708956), (8708952, 'b', 8708992), (8709004, 'bne', 8709020), (8709020, 'b', 8709024), (8709092, 'beq', 8709124), (8709116, 'b', 8709160), (8709172, 'bne', 8709224), (8709188, 'b', 8709384), (8709280, 'beq', 8709316), (8709304, 'b', 8709352), (8709364, 'bne', 8709380), (8709380, 'b', 8709384), (8709480, 'bge', 8729248), (8709588, 'beq', 8709716), (8709712, 'bne', 8709728), (8709716, 'b', 8729228), (8709800, 'bge', 8727432), (8709856, 'blt', 8727432), (8709912, 'bne', 8727432), (8710012, 'bge', 8710032), (8710024, 'b', 8710040), (8710312, 'bne', 8710340), (8710408, 'bne', 8717640), (8710452, 'blt', 8710500), (8710496, 'ble', 8717640), (8710556, 'beq', 8710584), (8710580, 'b', 8710620), (8710632, 'beq', 8717640), (8710692, 'beq', 8710720), (8710716, 'b', 8710756), (8710768, 'beq', 8717640), (8710828, 'beq', 8711008), (8710852, 'b', 8711044), (8711056, 'beq', 8717640), (8711072, 'bne', 8711728), (8711364, 'ble', 8711724), (8711504, 'ble', 8711720), (8711576, 'bpl', 8711716), (8711684, 'bge', 8711712), (8711712, 'b', 8711716), (8711716, 'b', 8711720), (8711720, 'b', 8711724), (8711724, 'b', 8711728), (8711740, 'bne', 8712408), (8711796, 'bne', 8712408), (8712096, 'ble', 8712404), (8712232, 'ble', 8712400), (8712236, 'b', 8712272), (8712340, 'bpl', 8712396), (8712396, 'b', 8712400), (8712400, 'b', 8712404), (8712404, 'b', 8712408), (8712420, 'bne', 8713124), (8712476, 'bne', 8713124), (8712772, 'ble', 8713120), (8712908, 'ble', 8713116), (8712980, 'bpl', 8713112), (8713080, 'bge', 8713108), (8713108, 'b', 8713112), (8713112, 'b', 8713116), (8713116, 'b', 8713120), (8713120, 'b', 8713124), (8713136, 'bne', 8713884), (8713192, 'bne', 8713884), (8713488, 'ble', 8713880), (8713628, 'ble', 8713876), (8713632, 'b', 8713664), (8713732, 'bpl', 8713872), (8713840, 'bge', 8713868), (8713868, 'b', 8713872), (8713872, 'b', 8713876), (8713876, 'b', 8713880), (8713880, 'b', 8713884), (8713896, 'bne', 8714612), (8713952, 'bne', 8714612), (8714252, 'ble', 8714608), (8714388, 'ble', 8714604), (8714460, 'bpl', 8714600), (8714568, 'bge', 8714596), (8714596, 'b', 8714600), (8714600, 'b', 8714604), (8714604, 'b', 8714608), (8714608, 'b', 8714612), (8714624, 'bne', 8715376), (8714680, 'bne', 8715376), (8714976, 'ble', 8715372), (8714980, 'b', 8715008), (8715144, 'ble', 8715368), (8715216, 'bpl', 8715364), (8715324, 'bge', 8715360), (8715360, 'b', 8715364), (8715364, 'b', 8715368), (8715368, 'b', 8715372), (8715372, 'b', 8715376), (8715388, 'bne', 8716940), (8715444, 'bne', 8716940), (8715744, 'ble', 8716936), (8715824, 'beq', 8715860), (8715848, 'b', 8715896), (8715908, 'bne', 8716112), (8716092, 'b', 8716340), (8716348, 'bge', 8716548), (8716376, 'bpl', 8716548), (8716508, 'b', 8716672), (8716688, 'ble', 8716932), (8716700, 'beq', 8716720), (8716716, 'bne', 8716932), (8716772, 'bpl', 8716928), (8716836, 'bne', 8716924), (8716892, 'bge', 8716920), (8716920, 'b', 8716924), (8716924, 'b', 8716928), (8716928, 'b', 8716932), (8716932, 'b', 8716936), (8716936, 'b', 8716940), (8716952, 'beq', 8717636), (8716964, 'ble', 8717636), (8717020, 'bne', 8717636), (8717080, 'bne', 8717636), (8717140, 'bne', 8717636), (8717408, 'ble', 8717632), (8717480, 'bpl', 8717628), (8717588, 'bge', 8717624), (8717624, 'b', 8717628), (8717628, 'b', 8717632), (8717632, 'b', 8717636), (8717636, 'b', 8717640), (8717680, 'blt', 8717728), (8717724, 'ble', 8723792), (8717784, 'beq', 8718016), (8717808, 'b', 8718052), (8718064, 'beq', 8723792), (8718088, 'bpl', 8718676), (8718388, 'ble', 8718672), (8718536, 'ble', 8718668), (8718608, 'bpl', 8718664), (8718664, 'b', 8718668), (8718668, 'b', 8718672), (8718672, 'b', 8718676), (8718688, 'bne', 8719416), (8718744, 'bne', 8719416), (8719044, 'ble', 8719412), (8719192, 'ble', 8719408), (8719196, 'b', 8719288), (8719356, 'bpl', 8719404), (8719404, 'b', 8719408), (8719408, 'b', 8719412), (8719412, 'b', 8719416), (8719428, 'bne', 8720076), (8719484, 'bne', 8720076), (8719788, 'ble', 8720072), (8719936, 'ble', 8720068), (8720008, 'bpl', 8720064), (8720064, 'b', 8720068), (8720068, 'b', 8720072), (8720072, 'b', 8720076), (8720088, 'bne', 8720876), (8720144, 'bne', 8720876), (8720448, 'ble', 8720872), (8720588, 'ble', 8720868), (8720592, 'b', 8720656), (8720724, 'bpl', 8720864), (8720832, 'bge', 8720860), (8720860, 'b', 8720864), (8720864, 'b', 8720868), (8720868, 'b', 8720872), (8720872, 'b', 8720876), (8720888, 'bne', 8721592), (8720944, 'bne', 8721592), (8721224, 'ble', 8721588), (8721360, 'ble', 8721584), (8721432, 'bpl', 8721580), (8721540, 'bge', 8721576), (8721576, 'b', 8721580), (8721580, 'b', 8721584), (8721584, 'b', 8721588), (8721588, 'b', 8721592), (8721604, 'bne', 8722416), (8721660, 'bne', 8722416), (8721940, 'ble', 8722412), (8721944, 'b', 8722056), (8722192, 'ble', 8722408), (8722264, 'bpl', 8722404), (8722372, 'bge', 8722400), (8722400, 'b', 8722404), (8722404, 'b', 8722408), (8722408, 'b', 8722412), (8722412, 'b', 8722416), (8722428, 'bne', 8723040), (8722484, 'bne', 8723040), (8722764, 'ble', 8723036), (8722900, 'ble', 8723032), (8722972, 'bpl', 8723028), (8723028, 'b', 8723032), (8723032, 'b', 8723036), (8723036, 'b', 8723040), (8723052, 'bne', 8723788), (8723108, 'bne', 8723788), (8723388, 'ble', 8723784), (8723392, 'b', 8723440), (8723564, 'ble', 8723780), (8723636, 'bpl', 8723776), (8723744, 'bge', 8723772), (8723772, 'b', 8723776), (8723776, 'b', 8723780), (8723780, 'b', 8723784), (8723784, 'b', 8723788), (8723788, 'b', 8723792), (8723804, 'bne', 8724876), (8723864, 'bne', 8724876), (8723908, 'blt', 8723956), (8723952, 'ble', 8724876), (8724028, 'ble', 8724872), (8724104, 'bge', 8724872), (8724180, 'bge', 8724872), (8724436, 'ble', 8724868), (8724568, 'ble', 8724864), (8724572, 'b', 8724592), (8724660, 'bpl', 8724860), (8724768, 'bge', 8724856), (8724856, 'b', 8724860), (8724860, 'b', 8724864), (8724864, 'b', 8724868), (8724868, 'b', 8724872), (8724872, 'b', 8724876), (8724888, 'beq', 8725532), (8724900, 'ble', 8725532), (8724956, 'bne', 8725532), (8725016, 'bne', 8725532), (8725076, 'bne', 8725532), (8725120, 'blt', 8725168), (8725164, 'ble', 8725532), (8725404, 'ble', 8725528), (8725468, 'bpl', 8725524), (8725524, 'b', 8725528), (8725528, 'b', 8725532), (8725544, 'bne', 8726496), (8725604, 'bne', 8726496), (8725648, 'blt', 8725696), (8725692, 'ble', 8726496), (8725768, 'ble', 8726492), (8725844, 'bge', 8726492), (8725920, 'bge', 8726492), (8726188, 'ble', 8726488), (8726192, 'b', 8726224), (8726352, 'ble', 8726484), (8726424, 'bpl', 8726480), (8726480, 'b', 8726484), (8726484, 'b', 8726488), (8726488, 'b', 8726492), (8726492, 'b', 8726496), (8726508, 'bne', 8727428), (8726568, 'bne', 8727428), (8726612, 'blt', 8726660), (8726656, 'ble', 8727428), (8726732, 'ble', 8727424), (8726808, 'bge', 8727424), (8726884, 'bge', 8727424), (8727152, 'ble', 8727420), (8727284, 'ble', 8727416), (8727356, 'bpl', 8727412), (8727412, 'b', 8727416), (8727416, 'b', 8727420), (8727420, 'b', 8727424), (8727424, 'b', 8727428), (8727428, 'b', 8729224), (8727528, 'bge', 8727548), (8727540, 'b', 8727556), (8727576, 'bge', 8729220), (8727676, 'bge', 8727752), (8727688, 'b', 8727760), (8727776, 'ble', 8728764), (8727836, 'bne', 8728236), (8728100, 'ble', 8728232), (8728172, 'bpl', 8728228), (8728228, 'b', 8728232), (8728232, 'b', 8728236), (8728292, 'bne', 8728692), (8728556, 'ble', 8728688), (8728628, 'bpl', 8728684), (8728684, 'b', 8728688), (8728688, 'b', 8728692), (8728692, 'b', 8729216), (8728820, 'bne', 8729212), (8729068, 'ble', 8729208), (8729148, 'bpl', 8729204), (8729204, 'b', 8729208), (8729208, 'b', 8729212), (8729212, 'b', 8729216), (8729216, 'b', 8729220), (8729220, 'b', 8729224), (8729224, 'b', 8729228), (8729240, 'b', 8709392), (8729340, 'bge', 8729816), (8729440, 'bge', 8729464), (8729452, 'b', 8729472), (8729512, 'ble', 8729784), (8729552, 'bge', 8729780), (8729720, 'bne', 8729776), (8729776, 'b', 8729780), (8729780, 'b', 8729784), (8729784, 'b', 8729788), (8729800, 'b', 8729256), (8729828, 'beq', 8732564), (8729856, 'bge', 8730044), (8729936, 'ble', 8729952), (8730032, 'b', 8729848), (8730124, 'beq', 8730152), (8730148, 'b', 8730188), (8730200, 'bne', 8732436), (8730260, 'beq', 8730296), (8730284, 'b', 8730332), (8730344, 'bne', 8732436), (8730404, 'beq', 8730440), (8730428, 'b', 8730476), (8730488, 'bne', 8732436), (8730548, 'beq', 8730584), (8730572, 'b', 8730620), (8730632, 'beq', 8732436), (8730692, 'beq', 8730728), (8730716, 'b', 8730764), (8730776, 'beq', 8732436), (8730836, 'beq', 8730872), (8730860, 'b', 8730908), (8730920, 'beq', 8732436), (8730980, 'beq', 8731028), (8731004, 'b', 8731064), (8731076, 'beq', 8732436), (8731136, 'beq', 8731168), (8731160, 'b', 8731204), (8731216, 'beq', 8732436), (8731276, 'beq', 8731340), (8731300, 'b', 8731376), (8731388, 'beq', 8732436), (8731400, 'blt', 8731420), (8731416, 'bge', 8732436), (8732428, 'b', 8693056), (8732476, 'bge', 8732560), (8732556, 'b', 8732468), (8732560, 'b', 8732564), (8732564, 'b', 8693056), (8732700, 'bne', 8732716)],
        semantics=("initWithWorld:randomSeed:isNewWorld:saveID:loadedVersion:blockDatabase: is the WorldTileLoader world constructor: the largest body in the binary (10857 words, 0x00849728-0x008540cc). It stores the six arguments, resolves the save/block database location, normalises the world size to 0x200, allocates the per-column arrays, builds the noise-function set from the save seed, runs the per-column candidate pass that stamps tree and plant types and records spawn-distance bids, and finishes in a seed-retry loop with the best-start search, a statistics NSLog and a final world-registration dispatch. Prologue 0x00849728 (push {r4-r8,sl,fp,lr}; sub sp,0xe10 then a second frame stage; PIC base cell 0x0084a5b4). Argument spills: self [fp,-0xa88], r7 byte [fp,-0xa95], r6 [fp,-0xa9c], r5 [fp,-0xaa0], r4 [fp,-0xaa4], plus world/save args staged into the local parameter block: [sp,0xea8] holds fp-0x5ec (a LOCAL STRUCT - read as the world-parameter scratch block; see uncertainties), which the body fills with fields at +0x50/+0x88..+0x1cc/+0x200/+0x204/+0x324/+0x328.\n\nOPENING (0x008497b4-0x00849800). self is copied to fp-0xab0 and a first dispatch runs through the GOT stub at 0x105b79c (cell 0x0084a5b8) with two other slot values; the result (0x008497f4) is stored to [fp,-0xa88]; if it is zero the method returns 0 immediately (branch 0x008497fc to the shared return at 0x00853ffc). The r7 argument byte is stored into an ivar slot and an argument is written through a second slot; then a slot-addressed ivar is cleared (0x00849840-0x0084988c).\n\nSIZE NORMALISATION (0x008498ac-0x008499a0). A slot call returns a float (pool 0x008499a0) into [fp,-0xab4]; `while ([-0xab4] > 0x200) { [-0xab4] /= 2; counter ivar += 1; a float field *= 2.0; }` (0x008498d0-0x0084999c) and `while ([-0xab4] < 0x200) { [-0xab4] *= 2; counter ivar -= 1; }` - the world size is normalised to 0x200, with a residual scale count kept in an ivar (both directions present; the body enters at whichever comparison fails).\n\nARRAYS + DATABASE LOCATION (0x008499a4-0x00849b90). `[self slot] << 5` is passed as the element count to three `__wrap_calloc(n<<5, 4)` calls (0x00849a1c/0x00849a5c/0x00849aa8) - three int arrays of (columns<<5) entries stored into three ivar slots: the ivar cells resolve to rockHeights, dirtHeights and lakeHeights. Then NSSearchPathForDirectoriesInDomains(0xe, 1, 1) (import call 0x00849af0) fetches the search paths and a slot dispatch on the result (0x00849b8c) extracts the element used to build the block-storage location.\n\nPHASE LOOP HEAD (0x0084a540). The remaining body is a seed-retry loop. The head reads the byte flag at [fp,-0xab5] (cleared during the opening); `flag == 1` jumps to the FINAL path (0x00853f98). Otherwise the loop runs the phases below and, at their ends (0x0084d280, 0x00853f94, 0x00853f0c), branches back to this head.\n\nSAVED-STATE PASS (0x00849fc8-0x0084a518, enters the first loop pass). Iterates a collection held in [sp,0xd78]/[sp,0xd7c] (head 0x00849fc8, tail 0x0084a494): per item, a slot call result is compared `cmp r0, 0x20` (== 32 required, else skip at 0x0084a040); a two-int result is fetched via objc_msgSend_stret into fp-0xb30 (with an 8-byte memset fallback) and compared against the literal 0x7fffffff (cell 0x0084acf0) - on equality the body logs (NSLog string cell 0x0084acf4) and runs a multi-argument slot send (0x0084a228). After the loop a do/while with stacked argument 0x10 re-enters the same head (0x0084a500-0x0084a518); an NSLog follows when the flag path is taken (0x0084a53c).\n\nWORLD OPTION PROBES (loop body 0x0084a560-0x0084a6a4, repeated variants). [world customRules] is fetched as a 0x40-byte struct (cell 0x0084ad1c = the customRules selector family; unclassified-pool fallback memset 0x40); the byte at +0xc is tested: `== 2` writes 2 to [fp,-0xb5c]. Then [world worldWidthMacro] (cell family 0x0084ead0) is compared against 0x200; width >= 0x200 takes the large-world path (0x0084ad38 etc.), the small-world path goes to 0x0084d9f0.\n\nNOISE CONSTRUCTION SETS. The body builds its noise functions in three visible groups, each a run of shape: read a stored ivar (the seed), add a fixed sub-seed offset, stage a large argument set (doubles, sxtb flags, pointers) and dispatch through a slot; the result is stored back to an ivar slot. Group 1: 0x0084a6ac-0x0084a814 (first construction; doubles 1/1/3, pools 0x0084a618/0x0084a620/0x0084a628, imm 8/4/3/2). Group 2 (0x0084b000-0x0084b368): repeated passes with sub-seed offsets +9 (0x0084b060), +8 (0x0084b104), +0x49 (0x0084b134), +6 and +3 plus [-0xb5c] (0x0084b1d8-0x0084b1fc), +8 (0x0084b218), +0xc plus [-0xb5c] (0x0084b2bc), writing results into slots staged at [sp,0xbec..0xbfc]. Group 3 (0x0084d420-0x0084d818): offsets +7/+4, +8/+9, +0xa/+5 written to slots including [sp,0x8f0]/[sp,0x8f4]/[sp,0x8fc]; the small-world variant at 0x0084d9f0 builds with f64 1.0 and pool 0x0084d9e8. Each construction is a leaf dispatch (blx through a slot register); their parameter meanings (octaves-like ints, noise keyword doubles) are observed shapes, not mapped to a named API.\n\nSKY/HEIGHT ARRAYS (0x0084b36c-0x0084b5cc). Two further `calloc([self slot] << 5, 4)` arrays (0x0084b464/0x0084b474 region; staged [fp,-0xb60]/[fp,-0xb64]) are zeroed with `memset(a, 0, (n<<5)<<1)`; a scan loop (head 0x0084b480) over idx in [0, [self slot]<<5) tracks the running max [fp,-0xb68] and min [fp,-0xb6c] of the float view of that array. The pair is turned into the vertical scale: [sp,0xea8+0x328] = (max - c2)/c1 and [sp,0xea8+0x324] = -(min - c2)/c1 (constants staged 0x100/0x200, pools 0x0084b9e4/0x0084b9e8). customRules overrides: byte +2 (== 4) and byte +0xb (== 0) force +0x328 to 1.0 (0x0084b7c4); a further byte +0xb (== 1) chain follows at 0x0084b8xx.\n\nPARAM FLOATS (0x0084e264-0x0084e508). The parameter block gets two floats: +0x204 defaults from pool 0x0084e658 with customRules byte +0xa == 3 (0x0084e2b0) selecting pool 0x0084e65c, and == 5 selecting pool 0x0084e78c; +0x200 defaults 0x0084e658 with byte +0xa == 1 and == 3 overrides. The block is zeroed for a 32-entry int scratch at fp-0xc90 (0x0084e218-0x0084e264) used by the candidate pass as its bid table.\n\nARRAY BRANCH (0x0084e000-0x0084e218). Either path allocates the height-array companions: one path memsets arrays sized (count<<7) and (count<<5) (0x0084e000-0x0084e110), the other calloc([self slot]<<5, 4) three times (0x0084e114-0x0084e214); both fall to the shared 0x0084e218.\n\nSPAWN STREAK SEARCH (0x0084bcdc-0x0084cf00 after the world-width gate). A column scan over [fp,-0xba0] compares the two height arrays; a slot call decides skips (0x0084c128/0x0084c154); a streak machine ([fp,-0xb7c] streak, [-0xb80] best-end, [-0xba0] scan best) accepts columns through `bl 0x008540cc` (the lrand48 wrapper) divided by 2^31 against a customRules byte +0xd threshold (== 2 selects 5.0 else pool 0x0084c890; compare at 0x0084c518); on a new best the state updates at 0x0084c604 (best = [-0xba0]+1, streak=1) and clears at 0x0084c2d4. Second scan head 0x0084c770 (entry 0x0084c678 gated by customRules byte +0xd == 0 -> 0x0084cf00) walks from `([self slot]<<5)-2`.\n\nSENTINEL + RETRY SEED (0x0084d000-0x0084d280). A stored value is read and compared with -1 (cmn r0, 1; 0x0084d000): when it is -1 the body logs (cell 0x0084d9c4), increments the stored value, calls 0x008540dc (the helper immediately after the lrand48 wrapper; read as the srand48-style seeder - usage-only) and sets the retry flag [fp,-0xab5] = 1. When the flag is still 0, the six position/food collections resolve through ivar cells (treePositions, plantPositions, npcPositions and the food/npc families); each is read, dispatched and stored back (0x0084d0a0-0x0084d280) and the body branches to the loop head 0x0084a540. Two customRules byte +0x10 probes follow in the large-world path (struct@fp-0x5a8 == 2 -> [-0xc14] = -1; struct@fp-0x5e8 != 0 -> [-0xc14] = 1; 0x0084d284-0x0084d3d0). [world worldWidthMacro] >= 0x200 gate at 0x0084d3d8 (small worlds jump to 0x0084d9f0).\n\nTHE COLUMN CANDIDATE LOOP (head 0x0084e510, one exit 0x0084e564, tail site 0x0084e510->0x008532a8). Iterates [fp,-0xb70] from 2 to ([self slot]<<5)-1 (bound check 0x0084e564 vs 0x008532a0). Special indices: `count<<5 / 4` (idiv 0x0084e5c8) and `(count<<5/4)*3` (0x0084e63c) jump to the quarter-column handling at 0x0085328c. Per column a pre-gate compares the two height arrays and a third zero-tested array (0x0084e660-0x0084e718); failing columns skip to 0x00852b88. Passing columns compute max(a,b) into [-0xcac]/[-0xca0], build makeIntpair(int, int) arguments and start the candidate chain.\n\nCANDIDATE BLOCKS - TREES (9 blocks, `bl sym.growthVigorForTreeTypeAtPos`). Sites and TreeType: 0x0084ed20 type 1; 0x0084eff8 type 3; 0x0084f29c type 2; 0x0084f56c type 7; 0x0084f864 type 8; 0x0084fb58 type 9; 0x008500b8 type 6; 0x0085015c type 4; 0x0085202c type 1. Per block: p = noiseSample(index with the block's offset) / (count<<5) + d1 + params[0x204]; skip if p <= 0; p = p * (growthVigorForTreeTypeAtPos(TreeType, (idx, maxAB), world) - C); skip if p <= 0; r = lrand48()/2^31 * 2.0; skip unless r < p*p; on success the type is stored into the type array at column idx (`str r2, [array+idx*4]`) and a distance bid is accumulated: dist = 0x008540fc(idx, storedBase) and for dist < 0x3e8 the block's accumulator slot ([fp,-0xc90] family) gains 0x3e8 - dist (with one variant dividing by 4 via __aeabi_idiv, 0x00850524).\n\nCANDIDATE BLOCKS - PLANTS (10 blocks, `bl sym.growthVigorForPlantTypeAtPos`). Sites: 0x00850890 type 1; 0x00850b20 type 2; 0x00850e08 type 9; 0x00851098 (type from a register; parameterised variant with cmp [fp,-0xd58], 6 side gate); 0x0085139c type 4; 0x008516dc type 3; 0x008519a0 type 8; 0x00851c40 type 5; 0x00852724 type 4; 0x00852ac8 type 9. Same shape as the tree blocks with plant vigor, plant-scale multipliers (x8.0 at 0x008519e0, x4.0 at 0x0085275c, x2.0 variants elsewhere), index transforms (idx*2 + 0xbb8 / 0x4ba / 0x1d4c / 0xc23 / 0x164 / 0x98d / 0x3e8 / 0x7d0) and the same array write + bid accumulator. The second family (0x0085241c onward, blocks at 0x0085242c-0x00852b80) adds flatness gates: the two height arrays are indexed at idx-1 and idx+1, their differences are passed through 0x008540fc and accepted only when the result is < 2 before the noise/vigor/rng chain runs, and this family's markers are written through the third array cell (0x00852c90 family).\n\nLOOP EXIT - BEST POSITION (0x008532b0-0x008534c8). When idx reaches the bound a pair (max(a[idx], b[idx]) and the source values) is compared; a callback dispatch (blx ip 0x00853440 / blx lr 0x0085346c) checks against `[-0xeac] > d0` (pool 0x008530b0) and a stored record level; on acceptance the position record is written (`[+4] = [-0xea0]` and `[*] = idx`, 0x0085348c-0x008534ac) - this is the bestStartPosition selection (ivar cell resolves to bestStartPosition) - and idx increments and loops (0x008534bc).\n\nNEW-WORLD TAIL (0x008534d8 onward, only when the [fp,-0xa95] byte != 0; else 0x00853f94). The 32 bid counters ([fp,-0xc90]+i) are converted to float into a scratch array at [sp,0xc00+0x2c4] (0x008534f8-0x008535b0) while counting positive entries ([sp,0xec0]) and summing them ([sp,0xebc]); an NSLog reports the pair (string cell 0xfff328f4, 0x008535d0). Then a cascade of world-option gates, each a [world customRules] fetch with a byte test, any of which ends the pass at 0x00853f14: byte +2 == 2 (0x00853650), byte +2 == 2 (0x008536e0), byte +2 == 2 (0x00853770), byte +0xa == 0 (0x00853800), byte +0xa == 1 (0x00853890), byte +0xa == 2 (0x00853920), byte +0xa == 3 (0x008539bc), byte +0xa == 0 (0x00853a48), byte +0xa == 1 (0x00853af4); then the statistics gate: `[sp,0xec0] >= 6 && [sp,0xebc] >= 0x2710` also ends the pass at 0x00853f14 (0x00853b00-0x00853b18). Otherwise an NSLog (cell 0xfff32904, 0x00853b28) then the finishing sweep: about a dozen ivar slots are loaded and one broad dispatch runs (blx ip, 10 stacked + 8 register arguments, 0x00853c2c) - read as the world-registration call; then a 12-step pattern (0x00853c30-0x00853ed8) sends each of twelve slots a message with a shared value and stores that value back to the slot; the retry flag is cleared again (0x00853bd8 writes [fp,-0xab5] = 0 before the sweep); one slot's counter increments (0x00853ef4) and 0x008540dc re-seeds from it (0x00853f08) before branching back to the loop head (0x00853f0c -> 0x0084a540). If instead the -1 sentinel set the flag during this pass, the loop head takes the FINAL path on the next entry.\n\nQUICKSORT/SORTED TABLE (0x00853f14). The bid scratch is sorted with `quickSort(float*, 0x1f, unsigned int*)` (0x00853f28) and the sorted values are written back in reverse order (rsb r2, r1, 0x1e) into an ivar array (0x00853f40-0x00853f8c) - the sorted spawn-distance table (ivar cell resolves to distanceOrderedFoodTypes); then the loop head is re-entered (0x00853f94).\n\nFINAL PATH (0x00853f98-0x00854028). A dispatch through a slot (cells 0xffe22934/0xffe22930, classref cell 0xffe2ada8) with arguments (self, and the staged values) runs once; self is moved to [fp,-0xa84] and returned; the stack-protector check compares [sp,0xeb8] and branches to __stack_chk_fail (0x0085402c) on mismatch, and the epilogue is `sub sp, fp, 0x18; pop {r4, r5, r6, r7, r8, sl, fp, pc}` (0x00854020-0x00854028). The shared return-0 path from the opening lands at 0x00853ffc with the same epilogue. The body ends at 0x008540cc; the words from 0x00854034 to 0x008540cc are the embedded literal pool (values referenced above as cells).\n\nFUNCTIONS REACHED 393 call rows: objc_msgSend-family dispatches through GOT slots and slot registers, plus named routes: makeIntpair, growthVigorForTreeTypeAtPos, growthVigorForPlantTypeAtPos, NSObject runtime/dyld imports (NSSearchPathForDirectoriesInDomains, NSLog, memset, __stack_chk_fail, __wrap_calloc, __aeabi_idiv, __aeabi_memset, lrand48 at 0x008540cc), quickSort and the local helpers 0x008540dc (reseed), 0x008540fc (distance/bid helper). 25 lrand48-wrapper calls and 2 reseed calls are counted in the body. The tree/plant type numbers (1-9) are raw ids in this pass; their game taxonomy is not named here.\n"),
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
        'batch': 'WorldTileLoader world-constructor batch (E17): initWithWorld:randomSeed:isNewWorld:saveID:loadedVersion:blockDatabase: - the 10857-word constructor that normalises the world size, allocates the per-column arrays, builds the noise set, runs the tree/plant candidate pass with spawn-distance bids and closes in a seed-retry loop; 1 body',
        'claim': ('a static bounded-body map with per-instruction anchors; the concrete noise API behind '
                  'the construction groups, the -1 sentinel slot identity, the selectors of the finishing '
                  'dispatch at 0x00853c2c and the helper names 0x008540dc/0x008540fc are outside this body'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'wtl_initwithworld.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale wtl_initwithworld.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
