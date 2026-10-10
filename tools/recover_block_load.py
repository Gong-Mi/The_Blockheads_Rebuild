#!/usr/bin/env python3
"""Hash-gated recovery of the Physical-block load-path batch (E16).

The WorldTileLoader block-load orchestrator - the fourth body of the block-storage
line (write/sync E14, migrate E15, here the loader that reads or generates one
PhysicalBlock):
1 body, 5736 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/BLOCK_LOAD.md for the prose and boundaries.
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
    'bl 0x864050': 0x00864050,
    'bl 0xfe9a7918': 0xfe9a7918,
    'bl 0xfe9a7ff8': 0xfe9a7ff8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.clampi_int__int__int_': 0x004c0b70,
    'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_': 0x004c0bd4,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__aeabi_memcpy': 0x001c3c08,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.cosf': 0x001c2b58,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wtl_loadphysicalblock_atxp',
        method='WorldTileLoader -[loadPhysicalBlock:atXPos:yPos:createIfNotCreated:]',
        types='v24@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8i12i16c20',
        start=8775344,
        end=8798288,
        disasm='disasm_worldtileloader_loadphysicalblock_atxpos_ypos_createifno.txt',
        base_add=8775372,
        base_literal=8779420,
        boundary='ARM.exidx end 0x00864050 (listing bound); next ObjC IMP 0x00864188 WorldTileLoader -[findBestStartPosition]',
        selectors={
                 0x85f6a8: (15213480, 'worldWidthMacro'),
                 0x85f6b0: (15213732, 'macroTiles'),
                 0x85f8dc: (15213740, 'gzipInflate'),
                 0x85f8e0: (15213736, 'dataForKey:'),
                 0x85f8ec: (15213488, 'stringWithFormat:'),
                 0x85f93c: (15213740, 'gzipInflate'),
                 0x85f940: (15213488, 'stringWithFormat:'),
                 0x85f998: (15213744, 'fileExistsAtPath:'),
                 0x85f99c: (15213512, 'defaultManager'),
                 0x85f9a4: (15213536, 'stringByAppendingPathComponent:'),
                 0x85f9b0: (15213748, 'dataWithContentsOfFile:'),
                 0x85f9bc: (15213524, 'length'),
                 0x85f9c0: (15213752, 'bytes'),
                 0x85f9ec: (15213756, 'getBytes:range:'),
                 0x85fca0: (15213756, 'getBytes:range:'),
                 0x85ff2c: (15213760, 'timeIntervalSinceReferenceDate'),
                 0x86005c: (15213716, 'expertMode'),
                 0x860184: (15213556, 'customRules'),
                 0x860218: (15213556, 'customRules'),
                 0x8602b0: (15213624, 'getRockAndDirtHeightforX:rockHeight:dirtHeight:'),
                 0x860348: (15213624, 'getRockAndDirtHeightforX:rockHeight:dirtHeight:'),
                 0x860494: (15213600, 'getX:Y:octaves:'),
                 0x861c28: (15213768, 'sandstoneFractionForX:y:faultOffset:limestoneFraction:'),
                 0x861c2c: (15213764, 'limestoneFractionForX:y:faultOffset:'),
                 0x861c30: (15213572, 'faultOffsetForX:y:'),
                 0x861d28: (15213764, 'limestoneFractionForX:y:faultOffset:'),
                 0x861d2c: (15213572, 'faultOffsetForX:y:'),
                 0x861ef0: (15213576, 'isCaveForX:y:faultOffset:'),
                 0x861ef4: (15213772, 'placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:'),
                 0x862104: (15213776, 'sandFractionForPos:highRes:'),
                 0x8623cc: (15213556, 'customRules'),
                 0x8624d4: (15213556, 'customRules'),
                 0x8625b4: (15213480, 'worldWidthMacro'),
                 0x862660: (15213480, 'worldWidthMacro'),
                 0x86270c: (15213600, 'getX:Y:octaves:'),
                 0x8627cc: (15213600, 'getX:Y:octaves:'),
                 0x863428: (15213720, 'fillDirtTile:worldPos:worldDirtHeight:parentType:'),
                 0x86364c: (15213716, 'expertMode'),
                 0x864028: (15213480, 'worldWidthMacro'),
                 0x864030: (15213556, 'customRules'),
                 0x864034: (15213600, 'getX:Y:octaves:'),
                 0x864048: (15213728, 'isFloatingIslandCaveForX:y:'),
                 0x86404c: (15213772, 'placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:'),
        },
        imports={
                 0x85f6a0: (17151968, '__stack_chk_guard'),
                 0x85f6a4: (17151904, 'objc_msgSend'),
                 0x85f8e8: (16327880, '__CFConstantStringClassReference'),
                 0x85f9ac: (16327896, '__CFConstantStringClassReference'),
                 0x85fcb4: (16327912, '__CFConstantStringClassReference'),
                 0x8616c8: (17151904, 'objc_msgSend'),
                 0x863648: (17151904, 'objc_msgSend'),
                 0x864020: (17151968, '__stack_chk_guard'),
                 0x864024: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x85f6ac: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85f8e4: (17161556, 'OBJC_IVAR_$_WorldTileLoader.blockDatabase', 256),
                 0x85f9a8: (17161576, 'OBJC_IVAR_$_WorldTileLoader.blockDirectory', 12),
                 0x860498: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x86049c: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x860530: (17161616, 'OBJC_IVAR_$_WorldTileLoader.gemNoiseFunction', 60),
                 0x861b4c: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
                 0x8623d0: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x8624d8: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x862710: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x8627d0: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x862830: (17161624, 'OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction', 40),
                 0x862834: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x863424: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x863994: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x86402c: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x864038: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x86403c: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
        },
        classes={
                 0x85f8f0: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x85f944: (15247496, 'OBJC_CLASS_$_NSString'),
                 0x85f9a0: (15247508, 'OBJC_CLASS_$_NSFileManager'),
                 0x85f9b4: (15247528, 'OBJC_CLASS_$_NSData'),
                 0x85ff30: (15247544, 'OBJC_CLASS_$_NSDate'),
        },
        instructions=[(8775344, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8776692, 'bl loc.imp.objc_msgSend'), (8776728, 'bl sym.imp.__aeabi_memcpy'), (8776800, 'bl loc.imp.objc_msgSend'), (8776812, 'strb r0, [r1, 0xd]'), (8777688, 'blx r2'), (8778188, 'bl loc.imp.objc_msgSend_stret'), (8778604, 'bl loc.imp.objc_msgSend'), (8778768, 'strb ip, [r3, r2, lsl 6]'), (8780924, 'movw r0, 5'), (8781288, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8781316, 'movw r0, 0xd'), (8783376, 'blx ip'), (8784532, 'strb ip, [r2, 2]'), (8784832, 'bl loc.imp.objc_msgSend'), (8786640, 'strb r0, [r2, 3]'), (8789276, 'strb r0, [r2, 3]'), (8791200, 'strb ip, [r3, r2, lsl 6]'), (8791444, 'strb r3, [r2, 1]'), (8793216, 'strb r3, [r2, 2]'), (8793548, 'strb ip, [r3, r2, lsl 6]'), (8795624, 'bl 0x864050'), (8795916, 'strb r2, [r1, 3]'), (8796796, 'strb r0, [r2, 0xb]'), (8797300, 'bl sym.imp.cosf'), (8797884, 'strb ip, [lr, 1]'), (8798128, 'blx ip'), (8798232, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}'), (8798284, 'invalid')],
        calls=[(8775504, 'blx r2'), (8775592, 'blx r2'), (8775668, 'blx r2'), (8775792, 'blx r4'), (8775864, 'blx ip'), (8776084, 'blx r7'), (8776128, 'blx ip'), (8776144, 'blx r2'), (8776352, 'blx r8'), (8776396, 'blx ip'), (8776432, 'blx r3'), (8776452, 'blx r3'), (8776524, 'blx r3'), (8776604, 'blx r3'), (8776692, 'bl loc.imp.objc_msgSend'), (8776728, 'bl sym.imp.__aeabi_memcpy'), (8776800, 'bl loc.imp.objc_msgSend'), (8777052, 'blx r8'), (8777084, 'blx r3'), (8777120, 'blx r3'), (8777140, 'blx r3'), (8777240, 'blx lr'), (8777264, 'blx r2'), (8777340, 'blx r3'), (8777420, 'bl loc.imp.objc_msgSend'), (8777456, 'bl sym.imp.__aeabi_memcpy'), (8777528, 'bl loc.imp.objc_msgSend'), (8777688, 'blx r2'), (8777852, 'bl sym.imp.__wrap_free'), (8778040, 'blx r2'), (8778188, 'bl loc.imp.objc_msgSend_stret'), (8778224, 'bl sym.imp.memset'), (8778604, 'bl loc.imp.objc_msgSend'), (8779412, 'bl loc.imp.objc_msgSend_stret'), (8779480, 'bl sym.imp.memset'), (8779868, 'blx lr'), (8779984, 'bl loc.imp.objc_msgSend_stret'), (8780048, 'bl sym.imp.memset'), (8780176, 'bl loc.imp.objc_msgSend_stret'), (8780300, 'bl sym.imp.memset'), (8780476, 'blx lr'), (8780580, 'bl loc.imp.objc_msgSend'), (8780800, 'blx lr'), (8781148, 'blx lr'), (8781244, 'bl sym.makeIntpair_int__int_'), (8781288, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8781360, 'bl 0xfe9a7918'), (8781528, 'bl sym.makeIntpair_int__int_'), (8781572, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8781680, 'bl sym.makeIntpair_int__int_'), (8781724, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8781828, 'bl sym.makeIntpair_int__int_'), (8781872, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8781980, 'bl sym.makeIntpair_int__int_'), (8782024, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8782128, 'bl sym.makeIntpair_int__int_'), (8782172, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8782276, 'bl sym.makeIntpair_int__int_'), (8782320, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8782428, 'bl sym.makeIntpair_int__int_'), (8782472, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8782580, 'bl sym.makeIntpair_int__int_'), (8782624, 'bl sym.growthVigorForTreeTypeAtPos_TreeType__intpair__World_'), (8782900, 'blx r4'), (8783120, 'bl 0xfe9a7ff8'), (8783376, 'blx ip'), (8783460, 'bl sym.clampi_int__int__int_'), (8783672, 'blx ip'), (8783776, 'bl sym.clampi_int__int__int_'), (8783900, 'bl sym.imp.__aeabi_idiv'), (8784020, 'blx lr'), (8784832, 'bl loc.imp.objc_msgSend'), (8785188, 'blx r5'), (8785240, 'blx r4'), (8785308, 'blx ip'), (8785892, 'blx ip'), (8785996, 'blx lr'), (8786392, 'bl sym.makeIntpair_int__int_'), (8786436, 'bl loc.imp.objc_msgSend'), (8786592, 'blx ip'), (8786956, 'blx ip'), (8787160, 'bl loc.imp.objc_msgSend_stret'), (8787204, 'bl sym.imp.memset'), (8787516, 'blx r6'), (8787632, 'blx ip'), (8787724, 'blx r2'), (8787896, 'blx lr'), (8788216, 'blx lr'), (8788528, 'blx r4'), (8788960, 'blx lr'), (8789436, 'blx lr'), (8789900, 'blx r4'), (8790176, 'blx r4'), (8790424, 'blx r4'), (8790700, 'blx r4'), (8791340, 'bl sym.makeIntpair_int__int_'), (8791400, 'bl loc.imp.objc_msgSend'), (8791548, 'bl loc.imp.objc_msgSend'), (8791572, 'bl sym.imp.__aeabi_idiv'), (8791720, 'bl loc.imp.objc_msgSend'), (8791744, 'bl sym.imp.__aeabi_idiv'), (8791904, 'bl loc.imp.objc_msgSend'), (8791928, 'bl sym.imp.__aeabi_idiv'), (8792104, 'bl loc.imp.objc_msgSend_stret'), (8792152, 'bl sym.imp.memset'), (8792232, 'blx r2'), (8792464, 'blx ip'), (8792508, 'blx lr'), (8792820, 'blx lr'), (8792916, 'bl loc.imp.objc_msgSend_stret'), (8792952, 'bl sym.imp.memset'), (8793060, 'bl loc.imp.objc_msgSend_stret'), (8793096, 'bl sym.imp.memset'), (8794152, 'bl loc.imp.objc_msgSend'), (8794176, 'bl sym.imp.__aeabi_idiv'), (8794540, 'bl loc.imp.objc_msgSend'), (8794932, 'bl loc.imp.objc_msgSend'), (8794956, 'bl sym.imp.__aeabi_idiv'), (8795560, 'bl loc.imp.objc_msgSend_stret'), (8795600, 'bl sym.imp.memset'), (8795624, 'bl 0x864050'), (8795704, 'bl loc.imp.objc_msgSend_stret'), (8795756, 'bl sym.imp.memset'), (8796188, 'blx r6'), (8796556, 'bl loc.imp.objc_msgSend_stret'), (8796596, 'bl sym.imp.memset'), (8796632, 'bl 0x8540cc'), (8796896, 'bl 0x8540cc'), (8797300, 'bl sym.imp.cosf'), (8797492, 'blx r4'), (8797928, 'blx ip'), (8798128, 'blx ip'), (8798236, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8775440, 'bge', 8775524), (8775520, 'b', 8775688), (8775604, 'blt', 8775684), (8775684, 'b', 8775688), (8775900, 'bne', 8775924), (8775916, 'beq', 8775924), (8775920, 'b', 8798196), (8776164, 'bne', 8776536), (8776464, 'beq', 8776532), (8776532, 'b', 8776536), (8776548, 'beq', 8776844), (8776616, 'blo', 8776844), (8776856, 'bne', 8777560), (8777152, 'beq', 8777556), (8777284, 'beq', 8777552), (8777352, 'blo', 8777552), (8777552, 'b', 8777556), (8777556, 'b', 8777560), (8777572, 'bne', 8777592), (8777588, 'beq', 8777904), (8777772, 'bge', 8777900), (8777812, 'beq', 8777880), (8777880, 'b', 8777884), (8777896, 'b', 8777764), (8777900, 'b', 8777904), (8777916, 'bne', 8777948), (8777932, 'bne', 8777948), (8778052, 'beq', 8778116), (8778172, 'beq', 8778196), (8778192, 'b', 8778228), (8778240, 'beq', 8778412), (8778244, 'b', 8778248), (8778256, 'beq', 8778332), (8778260, 'b', 8778264), (8778272, 'bne', 8778476), (8778276, 'b', 8778280), (8778328, 'b', 8778480), (8778408, 'b', 8778480), (8778472, 'b', 8778480), (8778476, 'b', 8778480), (8778492, 'beq', 8779272), (8778516, 'bge', 8779268), (8778668, 'bge', 8779228), (8778740, 'beq', 8778884), (8778864, 'b', 8779208), (8778900, 'bge', 8779108), (8779104, 'b', 8779204), (8779204, 'b', 8779208), (8779208, 'b', 8779212), (8779224, 'b', 8778660), (8779228, 'b', 8779232), (8779244, 'b', 8778508), (8779268, 'b', 8779272), (8779284, 'bne', 8798196), (8779300, 'beq', 8798196), (8779396, 'beq', 8779452), (8779416, 'b', 8779484), (8779492, 'beq', 8784144), (8779520, 'bge', 8784144), (8779548, 'ble', 8784144), (8779968, 'beq', 8780020), (8779988, 'b', 8780052), (8780060, 'bne', 8780104), (8780088, 'b', 8780340), (8780160, 'beq', 8780272), (8780180, 'b', 8780304), (8780316, 'bne', 8780336), (8780336, 'b', 8780340), (8780356, 'ble', 8784140), (8780504, 'ble', 8784136), (8780608, 'ble', 8784132), (8780628, 'ble', 8780988), (8780860, 'bpl', 8780976), (8780880, 'bpl', 8780964), (8780900, 'bpl', 8780948), (8780920, 'bpl', 8780936), (8780932, 'b', 8780944), (8780944, 'b', 8780956), (8780956, 'b', 8780972), (8780972, 'b', 8780976), (8780976, 'b', 8782712), (8781204, 'bpl', 8781468), (8781312, 'ble', 8781468), (8781324, 'b', 8782708), (8781488, 'bpl', 8781620), (8781596, 'ble', 8781620), (8781608, 'b', 8782704), (8781640, 'bpl', 8781764), (8781748, 'ble', 8781764), (8781760, 'b', 8782700), (8781784, 'bpl', 8781920), (8781896, 'ble', 8781920), (8781908, 'b', 8782696), (8781940, 'bpl', 8782064), (8782048, 'ble', 8782064), (8782060, 'b', 8782692), (8782084, 'bpl', 8782216), (8782196, 'ble', 8782216), (8782208, 'b', 8782688), (8782236, 'bpl', 8782364), (8782344, 'ble', 8782364), (8782356, 'b', 8782684), (8782384, 'bpl', 8782520), (8782496, 'ble', 8782520), (8782508, 'b', 8782680), (8782540, 'bpl', 8782668), (8782648, 'ble', 8782668), (8782660, 'b', 8782676), (8782676, 'b', 8782680), (8782680, 'b', 8782684), (8782684, 'b', 8782688), (8782688, 'b', 8782692), (8782692, 'b', 8782696), (8782696, 'b', 8782700), (8782700, 'b', 8782704), (8782704, 'b', 8782708), (8782708, 'b', 8782712), (8782720, 'beq', 8784128), (8782980, 'bge', 8783160), (8782992, 'b', 8783168), (8783792, 'ble', 8784124), (8784088, 'bgt', 8784112), (8784108, 'bge', 8784120), (8784120, 'b', 8784124), (8784124, 'b', 8784128), (8784128, 'b', 8784132), (8784132, 'b', 8784136), (8784136, 'b', 8784140), (8784140, 'b', 8784144), (8784164, 'bge', 8798192), (8784220, 'bge', 8784748), (8784740, 'b', 8784212), (8784992, 'bge', 8785016), (8785024, 'beq', 8790920), (8785376, 'bne', 8785412), (8785464, 'beq', 8785604), (8785588, 'b', 8790848), (8785620, 'bge', 8785828), (8785904, 'beq', 8786012), (8786000, 'b', 8790844), (8786024, 'beq', 8786680), (8786116, 'beq', 8786160), (8786152, 'b', 8786660), (8786252, 'beq', 8786300), (8786288, 'b', 8786656), (8786352, 'bpl', 8786652), (8786468, 'bgt', 8786516), (8786488, 'ble', 8786648), (8786512, 'bpl', 8786648), (8786612, 'bpl', 8786648), (8786648, 'b', 8786652), (8786652, 'b', 8786656), (8786656, 'b', 8786660), (8786660, 'b', 8790840), (8786692, 'beq', 8787056), (8786784, 'beq', 8786824), (8786820, 'b', 8787040), (8786876, 'bpl', 8787036), (8786976, 'bpl', 8787032), (8787032, 'b', 8787036), (8787036, 'b', 8787040), (8787040, 'b', 8790836), (8787144, 'beq', 8787176), (8787164, 'b', 8787208), (8787220, 'beq', 8790832), (8787248, 'ble', 8787316), (8787272, 'bpl', 8787316), (8787304, 'ble', 8787316), (8787328, 'beq', 8787372), (8787364, 'b', 8790828), (8787640, 'bge', 8787664), (8787652, 'b', 8787732), (8787928, 'ble', 8790824), (8787960, 'bge', 8787980), (8787972, 'b', 8787988), (8788268, 'ble', 8788296), (8788292, 'bmi', 8788360), (8788332, 'bpl', 8788404), (8788356, 'ble', 8788404), (8788392, 'b', 8790820), (8788580, 'ble', 8788608), (8788604, 'bmi', 8788672), (8788644, 'bpl', 8788820), (8788668, 'ble', 8788820), (8788704, 'b', 8790816), (8789008, 'bge', 8789044), (8789020, 'b', 8789052), (8789160, 'ble', 8789188), (8789184, 'bmi', 8789252), (8789224, 'bpl', 8789296), (8789248, 'ble', 8789296), (8789284, 'b', 8790812), (8789484, 'bge', 8789500), (8789496, 'b', 8789508), (8789616, 'ble', 8789644), (8789640, 'bmi', 8789708), (8789680, 'bpl', 8789760), (8789704, 'ble', 8789760), (8789740, 'b', 8790808), (8789952, 'ble', 8789980), (8789976, 'bmi', 8790044), (8790016, 'bpl', 8790284), (8790040, 'ble', 8790284), (8790212, 'ble', 8790272), (8790236, 'bpl', 8790272), (8790272, 'b', 8790804), (8790476, 'ble', 8790504), (8790500, 'bmi', 8790568), (8790540, 'bpl', 8790800), (8790564, 'ble', 8790800), (8790736, 'ble', 8790796), (8790760, 'bpl', 8790796), (8790796, 'b', 8790800), (8790800, 'b', 8790804), (8790804, 'b', 8790808), (8790808, 'b', 8790812), (8790812, 'b', 8790816), (8790816, 'b', 8790820), (8790820, 'b', 8790824), (8790824, 'b', 8790828), (8790828, 'b', 8790832), (8790832, 'b', 8790836), (8790836, 'b', 8790840), (8790840, 'b', 8790844), (8790844, 'b', 8790848), (8790916, 'b', 8784972), (8790948, 'bge', 8790996), (8790960, 'b', 8791004), (8791040, 'bge', 8791064), (8791072, 'beq', 8793340), (8791172, 'bne', 8791304), (8791248, 'b', 8791404), (8791412, 'bne', 8791480), (8791472, 'b', 8793320), (8791584, 'bne', 8791652), (8791644, 'b', 8793316), (8791756, 'bne', 8791828), (8791816, 'b', 8793312), (8791948, 'bne', 8792020), (8792008, 'b', 8793308), (8792028, 'ble', 8793304), (8792088, 'beq', 8792124), (8792108, 'b', 8792156), (8792168, 'beq', 8793300), (8792244, 'bne', 8793300), (8792280, 'beq', 8792320), (8792316, 'bne', 8793296), (8792332, 'bne', 8793292), (8792352, 'ble', 8793292), (8792520, 'bne', 8793288), (8792900, 'beq', 8792924), (8792920, 'b', 8792956), (8792968, 'bne', 8792988), (8792984, 'b', 8793132), (8793044, 'beq', 8793068), (8793064, 'b', 8793100), (8793112, 'bne', 8793128), (8793128, 'b', 8793132), (8793160, 'ble', 8793284), (8793184, 'bpl', 8793284), (8793284, 'b', 8793288), (8793288, 'b', 8793292), (8793292, 'b', 8793296), (8793296, 'b', 8793300), (8793300, 'b', 8793304), (8793304, 'b', 8793308), (8793308, 'b', 8793312), (8793312, 'b', 8793316), (8793316, 'b', 8793320), (8793320, 'b', 8793324), (8793336, 'b', 8791020), (8793368, 'bge', 8793384), (8793380, 'b', 8793392), (8793428, 'bge', 8793476), (8793440, 'b', 8793484), (8793508, 'bge', 8798168), (8793604, 'blt', 8793624), (8793620, 'bge', 8793748), (8793744, 'b', 8793780), (8793788, 'bne', 8794084), (8793864, 'bge', 8793880), (8793876, 'b', 8793888), (8793916, 'bge', 8793932), (8793928, 'b', 8793940), (8793968, 'bge', 8793988), (8793980, 'b', 8793996), (8794020, 'bge', 8794080), (8794080, 'b', 8795292), (8794188, 'bne', 8794480), (8794264, 'bge', 8794280), (8794276, 'b', 8794288), (8794316, 'bge', 8794332), (8794328, 'b', 8794340), (8794368, 'bge', 8794384), (8794380, 'b', 8794392), (8794416, 'bge', 8794476), (8794476, 'b', 8795288), (8794564, 'bne', 8794856), (8794640, 'bge', 8794656), (8794652, 'b', 8794664), (8794692, 'bge', 8794708), (8794704, 'b', 8794716), (8794744, 'bge', 8794760), (8794756, 'b', 8794768), (8794792, 'bge', 8794852), (8794852, 'b', 8795284), (8794976, 'bne', 8795280), (8795052, 'bge', 8795068), (8795064, 'b', 8795076), (8795104, 'bge', 8795120), (8795116, 'b', 8795128), (8795156, 'bge', 8795184), (8795168, 'b', 8795192), (8795216, 'bge', 8795276), (8795276, 'b', 8795280), (8795280, 'b', 8795284), (8795284, 'b', 8795288), (8795288, 'b', 8795292), (8795300, 'ble', 8798148), (8795316, 'blt', 8798148), (8795340, 'bge', 8798148), (8795364, 'bne', 8795432), (8795392, 'ble', 8795432), (8795464, 'beq', 8795936), (8795480, 'bne', 8795932), (8795544, 'beq', 8795572), (8795564, 'b', 8795604), (8795616, 'beq', 8795632), (8795688, 'beq', 8795728), (8795708, 'b', 8795760), (8795772, 'bne', 8795848), (8795784, 'beq', 8795844), (8795796, 'beq', 8795844), (8795808, 'beq', 8795844), (8795820, 'beq', 8795844), (8795832, 'beq', 8795844), (8795844, 'b', 8795848), (8795856, 'beq', 8795928), (8795872, 'bge', 8795924), (8795924, 'b', 8795928), (8795928, 'b', 8795932), (8795932, 'b', 8795936), (8795952, 'bne', 8796312), (8795968, 'ble', 8796312), (8795996, 'bge', 8796312), (8796220, 'ble', 8796308), (8796256, 'blt', 8796296), (8796308, 'b', 8796312), (8796324, 'beq', 8796996), (8796372, 'beq', 8796388), (8796384, 'bne', 8796396), (8796480, 'bne', 8796972), (8796540, 'beq', 8796568), (8796560, 'b', 8796600), (8796612, 'beq', 8796972), (8796628, 'bge', 8796896), (8796664, 'ble', 8796896), (8796708, 'beq', 8796760), (8796720, 'beq', 8796760), (8796732, 'beq', 8796760), (8796744, 'beq', 8796760), (8796756, 'bne', 8796844), (8796768, 'bne', 8796808), (8796804, 'b', 8796840), (8796840, 'b', 8796892), (8796852, 'bne', 8796888), (8796888, 'b', 8796892), (8796892, 'b', 8796968), (8796928, 'ble', 8796964), (8796964, 'b', 8796968), (8796968, 'b', 8796972), (8796972, 'b', 8798144), (8797008, 'bge', 8798140), (8797032, 'blt', 8798140), (8797640, 'bge', 8797664), (8797652, 'b', 8797672), (8797708, 'ble', 8798136), (8797728, 'beq', 8797780), (8797740, 'beq', 8797780), (8797752, 'beq', 8797780), (8797764, 'beq', 8797780), (8797776, 'bne', 8797796), (8797788, 'b', 8797820), (8797804, 'bne', 8797816), (8797816, 'b', 8797820), (8797940, 'bne', 8798048), (8797996, 'b', 8798132), (8798132, 'b', 8798136), (8798136, 'b', 8798140), (8798140, 'b', 8798144), (8798144, 'b', 8798148), (8798148, 'b', 8798152), (8798164, 'b', 8793500), (8798168, 'b', 8798172), (8798184, 'b', 8784156), (8798192, 'b', 8798196), (8798220, 'bne', 8798236)],
        semantics=('loadPhysicalBlock:atXPos:yPos:createIfNotCreated: is the WorldTileLoader block-load orchestrator: it reads a serialized PhysicalBlock from the block database (or its per-block file), unpacks the 64 KB tile image and the header fields into the passed record, and - when nothing is stored and createIfNotCreated is set - generates and populates the block from scratch, finishing with per-tile material, ore, spawn-marker and tree passes. Prologue 0x0085e6b0 (push; sub sp,0xc80); PIC base from cell 0x0085f69c (add lr,pc,lr 0x0085e6cc). Arguments spill self [fp,-0x31c], _cmd [fp,-0x320] (never re-read), the PhysicalBlock [fp,-0x324], atXPos [fp,-0x328], yPos [fp,-0x32c] and the createIfNotCreated byte [fp,-0x32d] (0x0085e6e8-0x0085e6fc). atXPos is wrapped into [0, W) against [self->world worldWidthMacro] (cell 0x0085f6a8; the <0 and >=W arms at 0x0085e710-0x0085e75c and 0x0085e764-0x0085e800), then linear = yPos*W + atXPos (0x0085e874-0x0085e87c) indexes a macroTiles-based lookup (cell 0x0085f6b0, call 0x0085e8b8) whose result selects \\"which column of this block matters\\" for the fetch. When createIfNotCreated == 0 and that lookup is negative (ldrsb pair 0x0085e8d0-0x0085e8ec) the body jumps straight to the finish at 0x00863ff4. The fetch: key = [NSString stringWithFormat:(CFString cell 0x0085f8e8)] (class cell 0x0085f8f0, call 0x0085e994), then [self->blockDatabase dataForKey:] (ivar cell 0x0085f8e4 @256, selector 0x0085f8e0, call 0x0085e9d0) into [fp,-0x33c]; on nil the file fallback runs (0x0085e9e8-0x0085eb54): second stringWithFormat (cell 0x0085f9ac; blockDirectory ivar cell 0x0085f9a8 @12), [NSFileManager defaultManager] + [fm fileExistsAtPath:] (cells 0x0085f99c/0x0085f998, call 0x0085eaf0, tested sxtb 0x0085eb08) and [NSData dataWithContentsOfFile:] (class cell 0x0085f9b4, selector 0x0085f9b0, call 0x0085eb4c). Unpack (0x0085eb58-0x0085ec88): require the data non-nil and [data length] >= 0x10001 (literal cell 0x0085f9b8 = 0x10001; [data length] via cell 0x0085f9bc, blo 0x0085eb64/0x0085eba8 to 0x0085ec8c); memcpy(dst = *(PhysicalBlock+8) = the tile image, src = [data bytes] (cell 0x0085f9c0, call 0x0085ebf4), 0x10000) at 0x0085ec18; then [data getBytes:&stackByte range:{0x10000,1}] (cell 0x0085f9ec, call 0x0085ec60) reads the payload byte at 0x10000 and 0x0085ec6c stores it to PhysicalBlock+0xd (the version field); 0x0085ec80/0x0085ec88 store the literal 0 (movw r0,0 0x0085ebac) to PhysicalBlock+0x18 and +0x1c on this database branch. The second half of the fetch (0x0085ec8c-0x0085ef54) repeats the same shape for the stored-as-file variant (getBytes:range: cell 0x0085fca0, memcpy 0x0085eef0, version store 0x0085ef44) and sets the loaded flag [fp,-0x33d] = 1 (0x0085ef4c) - this path does not zero +0x18/+0x1c. Create path (0x0085ef58-0x0085f0a8), taken when no data was found and the create flag is set: [NSDate timeIntervalSinceReferenceDate] (class cell 0x0085ff30, call 0x0085efd8) is vstr double into PhysicalBlock+0x10 (0x0085efe4); PhysicalBlock+0 = atXPos and +4 = yPos (0x0085efa8/0x0085efb4); +0xc = 1 (0x0085efbc); the 32 tile-pointer slots at PhysicalBlock+0x20 are freed via __wrap_free and zeroed (loop head 0x0085f024, call 0x0085f07c, store 0x0085f094); the record at [fp,-0x338] gets the block pointer at +4 (0x0085eff0) and zero bytes 0/2 (0x0085effc/0x0085f004); PhysicalBlock+0x18/+0x1c = 0 (0x0085f010/0x0085f018). If neither load nor create happened a 1 is written to the [fp,-0x338] record\'s byte0 (0x0085f0d0). Common post step (0x0085f0dc-0x0085f2f0): four floats from the pool at 0x0085f474-0x0085f480 are loaded, [world expertMode] (cell 0x0086005c, call 0x0085f138) scales them x5 (0x0085f14c-0x0085f17c), and a [world customRules] 64-byte stret (cell 0x00860184, call 0x0085f1cc, memset 0x40 at 0x0085f1f0 when world nil) selects on byte +15 (ldrsb [fp,-0x79]): ==3 identity (0x0085f2ac), ==1 scale by the doubles at 0x0085f5f0-0x0085f600 (0x0085f25c), ==0 negates all four (vneg 0x0085f228-0x0085f258). Loaded-repair double loop (0x0085f2f0-0x0085f604, runs only when the loaded flag [fp,-0x33d] is set; 0x0085f2f0 beq 0x0085f608 otherwise): per column i 0..0x1F (head 0x0085f30c) it computes colX = PhysicalBlock->x*32 + i (0x0085f320-0x0085f32c), calls [self getRockAndDirtHeightforX:colX rockHeight:&(fp-0x390) dirtHeight:stack] (cell 0x008602b0, call 0x0085f36c), localRock = rock/16 - y*32 + 0x10 (asr-4 idiom 0x0085f370-0x0085f390), then per row j 0..0x1F (head 0x0085f3a4) tiles at *(PhysicalBlock+8) + (j*32+i)*64: j < localRock writes byte0 = 0x1f and strh 0xff/0x7f/0x1f/0x7f to +0xe/+0x10/+0x12/+0x14 (0x0085f410-0x0085f468), j < localRock+0x20 writes the fading band s0 = (j-localRock)/C1 + 1.0 scaled by C2/C2/3.0/C2 (0x0085f484-0x0085f558), else zeroes the band (0x0085f564-0x0085f5bc). After the loop: loaded -> 0x00863ff4 (finish), create==0 -> 0x00863ff4; only (not loaded and create) falls into generation: version byte cleared to 0 (0x0085f650), five -1 locals [fp,-0x3b0..-0x3bc] and a 0 (0x0085f654-0x0085f660). Generation gates (0x0085f6dc): customRules[14] (second fetch struct base fp-0xc8; ldrsb [fp,-0xba] 0x0085f6dc) must be non-zero and 0x240 < yPos*32 < 0x384 (0x0085f6f8/0x0085f714) - else straight to the tile-init loops at 0x00860910. Noise scalars: x\'/y\' = ((coord*32)*s10 + K)/s10 / yHeightDivider@244 (cell 0x0086049c; 0x0085f7a4-0x0085f7f0) into [fp,-0x3c0]/[-0x3c4]; flint@36 (cell 0x00860498) getX:Y:octaves:2 (cell 0x00860494, call 0x0085f85c) -> |res|*2.0 -> S1 [fp,-0x3c8]; thresholds default (0x0085f9c8, 7.0) with customRules[14]==3 -> (0x0085fcb8,1.0) (0x0085f920-0x0085f938) and ==1 -> (0x0085f9c8,0x0085fe10) (0x0085fa10-0x0085fa2c); require S1 > threshold (0x0085fa44). Gem gate: gemNoiseFunction@60 (cell 0x00860530) sampled (0x0085fa5c-0x0085fab8) must be > 0 (0x0085fad8) else 0x00860908. Centre column check: getRockAndDirtHeightforX:(x*32+16) (0x0085faf4-0x0085fb24; the 16|(x<<5) form 0x0085faf0) requires yPos*32 <= rock+0x40 (0x0085fb3c) else 0x00860904. Second scalar S2 [fp,-0x3e4] = flint sample (0x0085fcec/0x0085fd5c) *5 + 5 (0x0085fcc0-0x0085fd70). Marker ladders both write [fp,-0x3ac] (init 0): ladder A on S1 maps to 5/4/3/2 (0x0085fc40-0x0085fca8; constants 0x0085fcb8 and 0x00860058 areas) and jumps to 0x00860378; ladder B on S2 walks nine rungs - each `if S2 < thr next-rung; makeIntpair(&pair, yPos*32, yPos*32); growthVigorForTreeTypeAtPos(TreeType=N, pair, self->world) > 0.2` (threshold cell 0x0085fe40, calls 0x0085fde8, 0x0085ff04, 0x0085ff9c, 0x00860030, 0x008600c8, 0x0086015c, 0x008601f0, 0x00860288, 0x00860320) - TreeType->marker: 9->0xd (0x0085fe04), 2->7 (0x0085ff20), 7->8 (0x0085ffb8), 0xa->0xa (0x0086004c), 8->0xc (0x008600e4), 3->0xe (0x00860178), 2->0xf (0x0086020c), 1->6 (0x008602a4), 4->9 (0x0086033c), fallback 0xb (0x0086034c). The pair as read is (yPos*32, yPos*32) - recorded as observed (the two words read back at the call sites, e.g. 0x008600bc/0x008600c0). Placement intent (0x00860378, only when the marker != 0): flint sample (call 0x00860434, octaves 2, staged constants 0,1,2,5 around 0x00860384-0x00860414) -> int depth [fp,-0x3b4]; two further noise samples (pools 0x008604d0-0x00860508, call 0x00860610 and 0x00860738) give [fp,-0x3b8] = clampi(noise, 0, 0x20 - depth) and [fp,-0x3b0] = clampi(noise, depth, 0x1f) (clampi call 0x00860664/0x008607a0); if depth <= 0xc skip to 0x008608fc. Tile-init double loop (0x00860910-0x00860b68): i 0..0x1F (head 0x0086091c, exit 0x00863ff0), colX = x*32+i ([fp,-0x44c]); j 0..0x1F (head 0x00860954) tiles (i + j*32): every field cleared with byte2 = 2 (0x00860a94), byte0xa = 0x7f (0x00860ac0), byte4 = 0xff (0x00860ad8) (full list 0x00860988-0x00860b50: bytes 3/5/6/7/8/9/0xb/0xc, strh 0xe/0x10/0x12/0x14/0x1c/0x1e/0x20/0x22/0x24, str 0x18/0x28/0x2c). After each column: getRockAndDirtHeightforX:colX (call 0x00860bc0) -> localRock [-0x460], localDirt [-0x464], lakeHeights@100[colX]-yPos*32 [-0x468] (cell 0x00861b4c), rock/16-y*32+0x10 [-0x46c]. Column loop head 0x00860c4c: rows above localRock (sky) run the material chain: sandstoneFractionForX:y:faultOffset:limestoneFraction: / limestoneFractionForX:y:faultOffset: / faultOffsetForX:y: (cells 0x00861c28/0x00861c2c/0x00861c30; calls from 0x00860d24 onward) with sandFractionForPos:highRes: (cell 0x00862104, call 0x00861204) and the IDs byte0 = 0x13 (0x0086137c), 0x11 (0x008613a4), 0xc (0x0086143c), byte3 = 0x40 (0x008612d0), 0x41 (0x0086159c; gated customRules[15]!=0, j > localRock-0x40, fraction in (0.7-[-0x378], 0.7)); default byte0 = 1 (0x008614a0). ORE BANDS (0x00861c60-0x00862314): band tests on cached scalars (tin@40 cell 0x00862830 and flint@36 cell 0x008627d0; getX:Y:octaves: cell 0x008627cc) write byte3 = 0x3f (0x00861d1c), 0x4d (0x00861ee4), 0x6a (0x008620f8), 0x6b (0x00862304), using the four customRules floats [-0x378..-0x384] as band offsets; the same region clamps a width against max(result,0x200) (0x008616bc) and yPos against max(...,0x190) (0x008617dc-0x00861814). Spawn/marker loop (0x008623d4-0x00862cfc, head 0x008623ec): per row j < localDirt: when colX == self->bestStartPosition@76 (cell 0x00863424, ldr 0x00862468; bne 0x00862508) the tile gets byte0/1/2 = 1 (0x008624a0-0x008624c8) and a [self sel-from-slot-pair] call with an intpair and stacked 2 (objc_msgSend 0x00862568; the selector slot pair 0x00863428/0x0086342c is not among the classified cells - reported as not determined); quarter columns: colX==0 -> byte1 = 0x26 (0x00862594) and colX == (W*32)/4 -> 0x29 (0x00862640), /4*2 -> 0x27 (0x008626ec), /4*3 -> 0x28 (0x008627ac) (each byte2 = 1; the divisions via [world worldWidthMacro] cell 0x00862660 and __aeabi_idiv 0x00862614/0x008626c0/0x00862778); DEEP branch (0x008627d4, yPos > 0x1f0): [world customRules] byte +0x12 gate and not [world expertMode] (cell 0x0086364c), tile byte0 must be 8 or 0x3a, localRock == j and localDirt-localRock > 2, faultOffsetForX:y: (cell 0x00861d2c, call 0x00862990) + isCaveForX:y:faultOffset: (cell 0x00861ef0, call 0x008629bc) must report no cave, then a deep-ore band (flint/tin noise at the 1247/1453 offsets 0x00862a34-0x00862ae4, cached [local,0xe0/0xe4/0xe8]; customRules byte +0x0a and +0x12 select blend constants, 0x00862b7c-0x00862c24) writes byte0 = 2, byte1 = 1, byte2 = 1, byte3 = 0x5e (0x00862c64-0x00862cbc). Final double loop (0x00862cfc-0x00863fd8; start row = max(min(localRock,localDirt), 0) clamped, 0x00862cfc-0x00862d98; head 0x00862d9c, exit i-loop 0x00863ff0): per tile sets byte0 = 2, byte1 = 2 (0x00862dcc/0x00862de0), byte7 = 0xff (0x00862df4); rows below the lake line and yPos >= 0x10 get byte0 = 3, byte1 = 2, byte2 = 3, byte7 = 0, byte4 = 0xff (0x00862e18-0x00862e88) else byte4 = 0 (0x00862e94); the quarter columns repeat their byte1 markers 0x26/0x29/0x27/0x28 under a 0x200 - yPos*32 depth window (0x00862fc4, 0x0086314c, 0x008632c4, 0x0086346c); tree stamping (0x0086349c): when the marker\'s depth [-0x3b4] > 0 and i lies in [treeTop, treeTop+depth) with the inner-column flag [fp,-0x5c1] (0x00863528-0x00863538): if i == [fp,-0x3bc] and [world customRules] byte +0x0a != 0 the unnamed local function at 0x00864050 is called with the marker (bl 0x00864050, 0x008635e8) and its result - when customRules byte +0x0a == 1 - is whitelisted to {0x6c,0x80,0x81,0x82,0x83} else 0 (0x00863680-0x008636c0), then written to byte3 of the tile one row up (i + (j+1)*32, 0x0086370c); trunk writes set byte0 = byte1 = id (0x1b, or 6 when [fp,-0x5c2] == 0; markers 7/0xb -> 7) and byte7 = 0 (0x008638ec-0x00863930); fruit markers on the trunk use the lrand48 wrapper (bl 0x008540cc): rng/2^31 > 0.55 -> byte0xb = 0x8f or 0x8e for markers 1..5 (0x00863a64-0x00863aa0), id==0x1b -> 0x7e (0x00863ad0), rng > 0.6 -> byte0xb = 0x7f (0x00863b1c); canopy (0x00863b44-0x00863f2c): cosf at 0x00863c74 phases the leaf row (doubles 0x00863f30-0x00863f58), a flint@36 sample (cells 0x00864034/0x00864038) sets the radius = max(result, depth) (0x00863cf8-0x00863db0), rows below treeBottom - radius are skipped, and leaf ids [fp,-0x600] = 0xc (default), 0xe (markers 1..5), 0x11 (marker 0xb) are written as byte1 (0x00863ebc); when [self isFloatingIslandCaveForX:y:] (cell 0x00864048, call 0x00863ee8) returns nonzero the tile instead runs [self placeGemsInCaveForPhysicalBlock:block tileIndex:[fp,-0x530] worldX:colX worldY:[fp,-0x604] floatingIslandType:marker] (cell 0x0086404c, call 0x00863fb0) - the marker doubles as the floating-island type; when it returns 0 the tile gets byte0 = leafId and byte7 = 0 (0x00863f10/0x00863f24). Loop exits re-enter at 0x00862d9c then 0x0086091c (0x00863fd4/0x00863fe8); the finish at 0x00863ff4 re-reads the __stack_chk_guard (cell 0x00864020) against the saved [fp,-0x608] and branches to __stack_chk_fail (0x0086401c), then the epilogue 0x00864010 (sub sp, fp, 0x38; vpop {d8-d11}; pop {r4-r8, sl, fp, pc}). Measured artifacts: _cmd never re-read; the database branch zeroes PhysicalBlock+0x18/+0x1c while the file branch leaves them; the marker ladders\' growthVigor calls read back the pair words as (yPos*32, yPos*32); the quarter-column grid (W*32)/4 recurs in both the marker loops and matches the E15 migration\'s pass-A guards; nine of the pool words are per-site PIC-base re-materialisations. State consulted: self->world (cells 0x00860184/0x008623d0/0x008624d8/0x0086402c - worldWidthMacro and customRules), blockDatabase@256, blockDirectory@12, bestStartPosition@76, yHeightDivider@244, flintDensityNoiseFunction@36, tinDensityNoiseFunction@40, gemNoiseFunction@60, lakeHeights@100, rockHeights@96; the only memory this body writes is the PhysicalBlock header (+0/4/0xc/0xd/0x10/0x18/0x1c), its 32 pointer slots (+0x20) and the 64-byte-stride tile image at *(PhysicalBlock+8).'),
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
        'batch': 'Physical-block load-path batch (E16): the WorldTileLoader block-load orchestrator - loadPhysicalBlock:atXPos:yPos:createIfNotCreated: reads a serialized PhysicalBlock from the database (or file), unpacks the 64 KB tile image + header, and on a miss with createIfNotCreated generates and populates the block (material, ore, spawn-marker and tree passes); 1 body',
        'claim': ('a static bounded-body map with per-instruction anchors; the concrete storage '
                  'layer behind dataForKey:/dataWithContentsOfFile:, the selector of the spawn-column '
                  'call at 0x00862568 (slot pair 0x00863428/0x0086342c), the unnamed local function at '
                  '0x00864050 and the tile-type names behind the raw tile bytes are outside this body'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'block_load.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale block_load.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
