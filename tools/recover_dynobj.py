#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicObject base class (E116).

The DynamicObject base class: the ctor triad (plain/save/net), the
position updater, the removal-permission check, the dirty-flag pairs
and the base-class hook stubs the concrete objects override:
66 bodies, 2523 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DYNAMICOBJECT.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.imp.NSLog': 0x001c2a5c,
    'bl sym.imp.cosf': 0x001c2b58,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.macroPosForWorldPos_intpair__World_': 0x00a16594,
    'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_': 0x00a16ccc,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='dob_00',
        method='DynamicObject -[initDerivedStuff:loadPhysicalBlockIfNeeded:]',
        types='c16@0:4c8c12',
        start=8623368,
        end=8624336,
        disasm='disasm_worldtileloader_dob_00.txt',
        base_add=8623384,
        base_literal=8624332,
        boundary='ARM.exidx end 0x008398d0 (listing bound); next ObjC IMP 0x008398d0 DynamicObject -[removeFromMacroBlock]',
        selectors={
                 0x8398a0: (15212892, 'macroTiles'),
                 0x8398ac: (15212896, 'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:'),
                 0x8398b0: (15212900, 'shouldAddToMacroBlock'),
                 0x8398b4: (15212908, 'addObject:'),
                 0x8398b8: (15212904, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'),
                 0x8398c4: (15212912, 'objectType'),
                 0x8398c8: (15212916, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x8398a8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x839894: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x839898: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x8398a4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x8398bc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(8623368, 'push {r4, r5, r6, r7, fp, lr}'), (8624332, 'ldrdeq r6, r7, [r2], r4')],
        calls=[(8623456, 'bl loc.imp.objc_msgSend'), (8623528, 'bl sym.macroPosForWorldPos_intpair__World_'), (8623588, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (8623860, 'blx r4'), (8623924, 'blx r2'), (8624076, 'blx lr'), (8624120, 'blx ip'), (8624216, 'bl loc.imp.objc_msgSend'), (8624252, 'bl loc.imp.objc_msgSend')],
        branches=[(8623644, 'bne', 8623660), (8623656, 'b', 8624264), (8623700, 'bne', 8623884), (8623712, 'beq', 8623868), (8623864, 'b', 8623880), (8623876, 'b', 8624264), (8623880, 'b', 8623884), (8623936, 'bne', 8623952), (8623948, 'b', 8624264), (8624132, 'bne', 8624256)],
        semantics=('[DynamicObject -[initDerivedStuff:loadPhysicalBlockIfNeeded:]] (imp 0x00839508, 242w): the macro-tile attach - shouldAddToMacroBlock gate + macroPosForWorldPos + macroTileAtMacroPostion + loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated: (the E113 loader) for the backing block.\n'),
    ),
    dict(
        name='dob_01',
        method='DynamicObject -[removeFromMacroBlock]',
        types='v8@0:4',
        start=8624336,
        end=8624636,
        disasm='disasm_worldtileloader_dob_01.txt',
        base_add=8624352,
        base_literal=8624632,
        boundary='ARM.exidx end 0x008399fc (listing bound); next ObjC IMP 0x008399fc DynamicObject -[objectType]',
        selectors={
                 0x8399d8: (15212900, 'shouldAddToMacroBlock'),
                 0x8399e4: (15212920, 'removeObject:'),
                 0x8399f0: (15212912, 'objectType'),
                 0x8399f4: (15212916, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x8399d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8399dc: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x8399e8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x8399ec: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(8624336, 'push {fp, lr}'), (8624632, 'addeq r6, r2, ip, lsl 4')],
        calls=[(8624388, 'blx r3'), (8624472, 'bl loc.imp.objc_msgSend'), (8624548, 'bl loc.imp.objc_msgSend'), (8624584, 'bl loc.imp.objc_msgSend')],
        branches=[(8624400, 'bne', 8624408), (8624404, 'b', 8624588)],
        semantics=('[DynamicObject -[removeFromMacroBlock]] (imp 0x008398d0, 75w): detaches from the macro block - removeObject: with the dynamicWorldChangedAtPos:objectType: notification behind shouldAddToMacroBlock.\n'),
    ),
    dict(
        name='dob_02',
        method='DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]',
        types='@40@0:4@8@12{?=ii}16@24i28@32@36',
        start=8624664,
        end=8624888,
        disasm='disasm_worldtileloader_dob_02.txt',
        base_add=8624784,
        base_literal=8624884,
        boundary='ARM.exidx end 0x00839af8 (listing bound); next ObjC IMP 0x00839af8 DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:]',
        selectors={
                 0x839af0: (15212924, 'initWithWorld:dynamicWorld:atPosition:cache:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(8624664, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8624884, 'addeq r6, r2, ip, asr r0')],
        calls=[(8624824, 'bl loc.imp.objc_msgSend')],
        branches=[(8624844, 'bne', 8624860), (8624856, 'b', 8624868)],
        semantics=('[DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:type:saveDict:placedByClient:]] (imp 0x00839a18, 56w): save-ctor forwarder - delegates to initWithWorld:dynamicWorld:atPosition:cache: with the type/saveDict carried.\n'),
    ),
    dict(
        name='dob_03',
        method='DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:]',
        types='@28@0:4@8@12{?=ii}16@24',
        start=8624888,
        end=8626044,
        disasm='disasm_worldtileloader_dob_03.txt',
        base_add=8624904,
        base_literal=8626040,
        boundary='ARM.exidx end 0x00839f7c (listing bound); next ObjC IMP 0x00839f7c DynamicObject -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x839f3c: (15212928, 'init'),
                 0x839f54: (15212932, 'getNextDynamicObjectID'),
                 0x839f60: (15212936, 'worldWidthMacro'),
                 0x839f70: (15212940, 'initDerivedStuff:loadPhysicalBlockIfNeeded:'),
        },
        imports={
                 0x839f38: (17151900, 'objc_msgSendSuper2'),
                 0x839f6c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x839f44: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x839f4c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x839f50: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x839f58: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x839f5c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x839f74: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x839f40: (15252868, 'OBJC_CLASS_$_DynamicObject'),
        },
        instructions=[(8624888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8626040, 'addeq r5, r2, r4, ror 31')],
        calls=[(8625004, 'blx r7'), (8625172, 'bl loc.imp.objc_msgSend'), (8625280, 'bl loc.imp.objc_msgSend'), (8625372, 'bl loc.imp.objc_msgSend'), (8625520, 'bl loc.imp.objc_msgSend'), (8625784, 'bl method.Vector2.operator_float__'), (8625856, 'bl method.Vector2.operator_float__'), (8625948, 'blx r5')],
        branches=[(8625032, 'bne', 8625048), (8625044, 'b', 8625964), (8625304, 'ble', 8625420), (8625416, 'b', 8625568), (8625452, 'bge', 8625564), (8625564, 'b', 8625568), (8625604, 'blt', 8625644), (8625640, 'b', 8625716), (8625676, 'bge', 8625712), (8625712, 'b', 8625716)],
        semantics=('[DynamicObject -[initWithWorld:dynamicWorld:atPosition:cache:]] (imp 0x00839af8, 289w): the plain ctor - uniqueID from getNextDynamicObjectID, floatPos/pos seeding, worldWidthMacro wrap, then initDerivedStuff:loadPhysicalBlockIfNeeded:.\n'),
    ),
    dict(
        name='dob_04',
        method='DynamicObject -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=8627136,
        end=8628032,
        disasm='disasm_worldtileloader_dob_04.txt',
        base_add=8627152,
        base_literal=8628028,
        boundary='ARM.exidx end 0x0083a740 (listing bound); next ObjC IMP 0x0083a740 DynamicObject -[dealloc]',
        selectors={
                 0x83a6f8: (15212928, 'init'),
                 0x83a714: (15212964, 'getBytes:length:'),
                 0x83a720: (15212932, 'getNextDynamicObjectID'),
                 0x83a728: (15212940, 'initDerivedStuff:loadPhysicalBlockIfNeeded:'),
                 0x83a734: (15212972, 'release'),
                 0x83a738: (15212968, 'removeFromMacroBlock'),
        },
        imports={
                 0x83a6f4: (17151900, 'objc_msgSendSuper2'),
                 0x83a724: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x83a700: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x83a708: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x83a70c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x83a710: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x83a718: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
                 0x83a72c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x83a730: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={
                 0x83a6fc: (15252868, 'OBJC_CLASS_$_DynamicObject'),
        },
        instructions=[(8627136, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8628028, 'addeq r5, r2, ip, lsl r7')],
        calls=[(8627244, 'blx r6'), (8627420, 'bl loc.imp.objc_msgSend'), (8627532, 'bl loc.imp.objc_msgSend'), (8627672, 'bl method.Vector2.operator_float__'), (8627744, 'bl method.Vector2.operator_float__'), (8627820, 'blx lr'), (8627900, 'blx ip'), (8627920, 'blx r2')],
        branches=[(8627272, 'bne', 8627288), (8627284, 'b', 8627944), (8627484, 'bne', 8627564), (8627488, 'b', 8627492), (8627832, 'bne', 8627936), (8627932, 'b', 8627944)],
        semantics=('[DynamicObject -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x0083a3c0, 224w): the net ctor - isNet flag, getBytes:length: decode of the net record, uniqueID/floatPos/pos restore (Vector2 operator float*), then initDerivedStuff:loadPhysicalBlockIfNeeded:.\n'),
    ),
    dict(
        name='dob_05',
        method='DynamicObject -[dealloc]',
        types='v8@0:4',
        start=8628032,
        end=8628140,
        disasm='disasm_worldtileloader_dob_05.txt',
        base_add=8628048,
        base_literal=8628136,
        boundary='ARM.exidx end 0x0083a7ac (listing bound); next ObjC IMP 0x0083a7ac DynamicObject -[getSaveDict]',
        selectors={
                 0x83a7a0: (15212976, 'dealloc'),
        },
        imports={
                 0x83a79c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x83a7a4: (15252868, 'OBJC_CLASS_$_DynamicObject'),
        },
        instructions=[(8628032, 'push {r4, sl, fp, lr}'), (8628136, 'umulleq r5, r2, ip, r3')],
        calls=[(8628112, 'blx ip')],
        branches=[],
        semantics=('[DynamicObject -[dealloc]] (imp 0x0083a740, 27w): dealloc - one super dispatch.\n'),
    ),
    dict(
        name='dob_06',
        method='DynamicObject -[dynamicObjectNetData]',
        types='{DynamicObjectNetData=QIIC[7C]}8@0:4',
        start=8628924,
        end=8629280,
        disasm='disasm_worldtileloader_dob_06.txt',
        base_add=8628940,
        base_literal=8629276,
        boundary='ARM.exidx end 0x0083ac20 (listing bound); next ObjC IMP 0x0083ac20 DynamicObject -[update:accurateDT:isSimulation:]',
        selectors={
                 0x83ac0c: (15212936, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x83ac00: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x83ac08: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x83ac10: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x83ac18: (17155060, 'OBJC_IVAR_$_DynamicObject.uniqueID', 40),
        },
        classes={},
        instructions=[(8628924, 'push {fp, lr}'), (8629276, 'addeq r5, r2, r0, lsr 32')],
        calls=[(8629064, 'bl loc.imp.objc_msgSend')],
        branches=[(8628988, 'bge', 8629096), (8629092, 'b', 8629128)],
        semantics=('[DynamicObject -[dynamicObjectNetData]] (imp 0x0083aabc, 89w): the net payload builder - worldWidthMacro-wrapped pos + uniqueID + needsRemoved into the dynamic-object record.\n'),
    ),
    dict(
        name='dob_07',
        method='DynamicObject -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=8629280,
        end=8629328,
        disasm='disasm_worldtileloader_dob_07.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ac50 (listing bound); next ObjC IMP 0x0083ac50 DynamicObject -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8629280, 'sub sp, sp, 0x14'), (8629324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[update:accurateDT:isSimulation:]] (imp 0x0083ac20, 12w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_08',
        method='DynamicObject -[updatePosition:]',
        types='v16@0:4{?=ii}8',
        start=8629880,
        end=8631636,
        disasm='disasm_worldtileloader_dob_08.txt',
        base_add=8629896,
        base_literal=8631632,
        boundary='ARM.exidx end 0x0083b554 (listing bound); next ObjC IMP 0x0083b554 DynamicObject -[requiresPhysicalBlock]',
        selectors={
                 0x83b4f4: (15212936, 'worldWidthMacro'),
                 0x83b504: (15212900, 'shouldAddToMacroBlock'),
                 0x83b510: (15212892, 'macroTiles'),
                 0x83b514: (15213004, 'setNeedsRemoved:'),
                 0x83b51c: (15213008, 'shouldSaveEveryChangeInPosition'),
                 0x83b528: (15212912, 'objectType'),
                 0x83b52c: (15212916, 'dynamicWorldChangedAtPos:objectType:'),
                 0x83b540: (15212920, 'removeObject:'),
                 0x83b544: (15212896, 'loadPhysicalBlockForMacroTile:atX:y:loadSurroundingBlocks:createIfNotCreated:'),
                 0x83b548: (15212904, 'loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:'),
                 0x83b54c: (15212908, 'addObject:'),
        },
        imports={
                 0x83b500: (17151904, 'objc_msgSend'),
                 0x83b538: (16326936, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x83b4ec: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x83b508: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x83b518: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
                 0x83b520: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x83b530: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x83b534: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(8629880, 'push {r4, r5, r6, r7, fp, lr}'), (8631632, 'addeq r4, r2, r4, ror 24')],
        calls=[(8629980, 'bl loc.imp.objc_msgSend'), (8630060, 'bl loc.imp.objc_msgSend'), (8630156, 'bl loc.imp.objc_msgSend'), (8630344, 'blx r2'), (8630408, 'bl loc.imp.objc_msgSend'), (8630460, 'bl sym.macroPosForWorldPos_intpair__World_'), (8630520, 'bl sym.macroTileAtMacroPostion_int__int__MacroTile__World_'), (8630604, 'blx ip'), (8630776, 'bl sym.imp.NSLog'), (8630848, 'bl loc.imp.objc_msgSend'), (8630924, 'bl loc.imp.objc_msgSend'), (8630972, 'bl loc.imp.objc_msgSend'), (8631088, 'bl loc.imp.objc_msgSend'), (8631148, 'bl loc.imp.objc_msgSend'), (8631196, 'bl loc.imp.objc_msgSend'), (8631264, 'bl loc.imp.objc_msgSend'), (8631300, 'bl loc.imp.objc_msgSend'), (8631348, 'blx r2'), (8631476, 'bl loc.imp.objc_msgSend'), (8631512, 'bl loc.imp.objc_msgSend')],
        branches=[(8630004, 'ble', 8630092), (8630088, 'b', 8630188), (8630100, 'bge', 8630184), (8630184, 'b', 8630188), (8630200, 'blt', 8630216), (8630212, 'b', 8630240), (8630224, 'bge', 8630236), (8630236, 'b', 8630240), (8630356, 'bne', 8630364), (8630360, 'b', 8631524), (8630540, 'bne', 8630612), (8630608, 'b', 8631524), (8630648, 'beq', 8631308), (8630684, 'bne', 8630720), (8630760, 'bne', 8630780), (8631304, 'b', 8631520), (8631360, 'beq', 8631516), (8631376, 'bne', 8631396), (8631392, 'beq', 8631516), (8631516, 'b', 8631520), (8631520, 'b', 8631524)],
        semantics=('[DynamicObject -[updatePosition:]] (imp 0x0083ae78, 439w): the position updater - macro-tile migration: worldWidthMacro wrap, macroTiles add/remove behind shouldAddToMacroBlock, setNeedsRemoved: when leaving the macro block, shouldSaveEveryChangeInPosition -> dirty flags.\n'),
    ),
    dict(
        name='dob_09',
        method='DynamicObject -[requiresPhysicalBlock]',
        types='c8@0:4',
        start=8631636,
        end=8631664,
        disasm='disasm_worldtileloader_dob_09.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b570 (listing bound); next ObjC IMP 0x0083b570 DynamicObject -[worldChanged:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8631636, 'sub sp, sp, 8'), (8631660, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[requiresPhysicalBlock]] (imp 0x0083b554, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_10',
        method='DynamicObject -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=8631664,
        end=8631688,
        disasm='disasm_worldtileloader_dob_10.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b588 (listing bound); next ObjC IMP 0x0083b588 DynamicObject -[shouldSaveEveryChangeInPosition]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8631664, 'sub sp, sp, 0xc'), (8631684, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[worldChanged:]] (imp 0x0083b570, 6w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_11',
        method='DynamicObject -[shouldSaveEveryChangeInPosition]',
        types='c8@0:4',
        start=8631688,
        end=8631716,
        disasm='disasm_worldtileloader_dob_11.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b5a4 (listing bound); next ObjC IMP 0x0083b5a4 DynamicObject -[worldContentsChanged:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8631688, 'sub sp, sp, 8'), (8631712, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[shouldSaveEveryChangeInPosition]] (imp 0x0083b588, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_12',
        method='DynamicObject -[worldContentsChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=8631716,
        end=8631800,
        disasm='disasm_worldtileloader_dob_12.txt',
        base_add=8631732,
        base_literal=8631796,
        boundary='ARM.exidx end 0x0083b64c; body trimmed at the next IMP 0x0083b5f8 DynamicObject -[waterContentChanged:]',
        selectors={
                 0x83b5f0: (15213012, 'worldChanged:'),
        },
        imports={
                 0x83b5ec: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(8631716, 'push {fp, lr}'), (8631796, 'addeq r4, r2, r8, lsr r5')],
        calls=[(8631776, 'blx ip')],
        branches=[],
        semantics=('[DynamicObject -[worldContentsChanged:]] (imp 0x0083b5a4, 21w): forwards worldContentsChanged: to worldChanged:.\n'),
    ),
    dict(
        name='dob_13',
        method='DynamicObject -[waterContentChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=8631800,
        end=8631884,
        disasm='disasm_worldtileloader_dob_13.txt',
        base_add=8631816,
        base_literal=8631880,
        boundary='ARM.exidx end 0x0083b64c (listing bound); next ObjC IMP 0x0083b64c DynamicObject -[creationNetDataForClient:]',
        selectors={
                 0x83b644: (15213012, 'worldChanged:'),
        },
        imports={
                 0x83b640: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(8631800, 'push {fp, lr}'), (8631880, 'addeq r4, r2, r4, ror 9')],
        calls=[(8631860, 'blx ip')],
        branches=[],
        semantics=('[DynamicObject -[waterContentChanged:]] (imp 0x0083b5f8, 21w): forwards waterContentChanged: to worldChanged:.\n'),
    ),
    dict(
        name='dob_14',
        method='DynamicObject -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=8631884,
        end=8631916,
        disasm='disasm_worldtileloader_dob_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b68c; body trimmed at the next IMP 0x0083b66c DynamicObject -[updateNetDataForClient:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8631884, 'sub sp, sp, 0xc'), (8631912, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[creationNetDataForClient:]] (imp 0x0083b64c, 8w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_15',
        method='DynamicObject -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=8631916,
        end=8631948,
        disasm='disasm_worldtileloader_dob_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b68c (listing bound); next ObjC IMP 0x0083b68c DynamicObject -[remoteUpdate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8631916, 'sub sp, sp, 0xc'), (8631944, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[updateNetDataForClient:]] (imp 0x0083b66c, 8w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_16',
        method='DynamicObject -[remoteUpdate:]',
        types='v12@0:4@8',
        start=8631948,
        end=8632240,
        disasm='disasm_worldtileloader_dob_16.txt',
        base_add=8631964,
        base_literal=8632236,
        boundary='ARM.exidx end 0x0083b7b0 (listing bound); next ObjC IMP 0x0083b7b0 DynamicObject -[remoteCreationDataUpdate:]',
        selectors={
                 0x83b790: (15213016, 'isServer'),
                 0x83b7a4: (15212912, 'objectType'),
                 0x83b7a8: (15212916, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x83b78c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x83b794: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x83b798: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x83b7a0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(8631948, 'push {r4, sl, fp, lr}'), (8632236, 'addeq r4, r2, r0, asr r4')],
        calls=[(8632028, 'blx ip'), (8632156, 'bl loc.imp.objc_msgSend'), (8632192, 'bl loc.imp.objc_msgSend')],
        branches=[(8632040, 'beq', 8632076)],
        semantics=('[DynamicObject -[remoteUpdate:]] (imp 0x0083b68c, 73w): the server-side update broadcast - isServer gate + dynamicWorldChangedAtPos:objectType: behind updateNeedsToBeSent.\n'),
    ),
    dict(
        name='dob_17',
        method='DynamicObject -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=8632240,
        end=8632532,
        disasm='disasm_worldtileloader_dob_17.txt',
        base_add=8632256,
        base_literal=8632528,
        boundary='ARM.exidx end 0x0083b8d4 (listing bound); next ObjC IMP 0x0083b8d4 DynamicObject -[shouldAddToMacroBlock]',
        selectors={
                 0x83b8b4: (15213016, 'isServer'),
                 0x83b8c8: (15212912, 'objectType'),
                 0x83b8cc: (15212916, 'dynamicWorldChangedAtPos:objectType:'),
        },
        imports={
                 0x83b8b0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x83b8b8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x83b8bc: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x83b8c4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
        },
        classes={},
        instructions=[(8632240, 'push {r4, sl, fp, lr}'), (8632528, 'addeq r4, r2, ip, lsr 6')],
        calls=[(8632320, 'blx ip'), (8632448, 'bl loc.imp.objc_msgSend'), (8632484, 'bl loc.imp.objc_msgSend')],
        branches=[(8632332, 'beq', 8632368)],
        semantics=('[DynamicObject -[remoteCreationDataUpdate:]] (imp 0x0083b7b0, 73w): the server-side creation-data broadcast - isServer gate + dynamicWorldChangedAtPos:objectType: behind creationDataNeedsToBeSent.\n'),
    ),
    dict(
        name='dob_18',
        method='DynamicObject -[shouldAddToMacroBlock]',
        types='c8@0:4',
        start=8632532,
        end=8632560,
        disasm='disasm_worldtileloader_dob_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b8f0 (listing bound); next ObjC IMP 0x0083b8f0 DynamicObject -[setFloatPosAndUpdatePosition:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632532, 'sub sp, sp, 8'), (8632556, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[shouldAddToMacroBlock]] (imp 0x0083b8d4, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_19',
        method='DynamicObject -[setFloatPosAndUpdatePosition:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=8632560,
        end=8632772,
        disasm='disasm_worldtileloader_dob_19.txt',
        base_add=8632600,
        base_literal=8632764,
        boundary='ARM.exidx end 0x0083b9c4 (listing bound); next ObjC IMP 0x0083b9c4 DynamicObject -[staticGeometryDrawCubeCount]',
        selectors={
                 0x83b9c0: (15213020, 'updatePosition:'),
        },
        imports={},
        ivars={
                 0x83b9b8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(8632560, 'push {r4, sl, fp, lr}'), (8632768, 'invalid')],
        calls=[(8632660, 'bl method.Vector2.operator_float__'), (8632696, 'bl method.Vector2.operator_float__'), (8632720, 'bl sym.makeIntpair_int__int_'), (8632748, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[DynamicObject -[setFloatPosAndUpdatePosition:]] (imp 0x0083b8f0, 53w): sets floatPos then runs updatePosition: (Vector2 operator float* x2 + makeIntpair).\n'),
    ),
    dict(
        name='dob_20',
        method='DynamicObject -[staticGeometryDrawCubeCount]',
        types='i8@0:4',
        start=8632772,
        end=8632800,
        disasm='disasm_worldtileloader_dob_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b9fc; body trimmed at the next IMP 0x0083b9e0 DynamicObject -[staticGeometryDrawCubeCountTrans]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632772, 'sub sp, sp, 8'), (8632796, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryDrawCubeCount]] (imp 0x0083b9c4, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_21',
        method='DynamicObject -[staticGeometryDrawCubeCountTrans]',
        types='i8@0:4',
        start=8632800,
        end=8632828,
        disasm='disasm_worldtileloader_dob_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083b9fc (listing bound); next ObjC IMP 0x0083b9fc DynamicObject -[addDrawCubeData:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632800, 'sub sp, sp, 8'), (8632824, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryDrawCubeCountTrans]] (imp 0x0083b9e0, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_22',
        method='DynamicObject -[addDrawCubeData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=8632828,
        end=8632864,
        disasm='disasm_worldtileloader_dob_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ba8c; body trimmed at the next IMP 0x0083ba20 DynamicObject -[addDrawCubeDataTrans:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632828, 'sub sp, sp, 0x10'), (8632860, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addDrawCubeData:fromIndex:]] (imp 0x0083b9fc, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_23',
        method='DynamicObject -[addDrawCubeDataTrans:fromIndex:]',
        types='i16@0:4^f8i12',
        start=8632864,
        end=8632900,
        disasm='disasm_worldtileloader_dob_23.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ba8c; body trimmed at the next IMP 0x0083ba44 DynamicObject -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632864, 'sub sp, sp, 0x10'), (8632896, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addDrawCubeDataTrans:fromIndex:]] (imp 0x0083ba20, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_24',
        method='DynamicObject -[staticGeometryDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=8632900,
        end=8632936,
        disasm='disasm_worldtileloader_dob_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ba8c; body trimmed at the next IMP 0x0083ba68 DynamicObject -[staticGeometryForegroundDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632900, 'sub sp, sp, 0x10'), (8632932, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryDrawQuadCountForMacroPos:]] (imp 0x0083ba44, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_25',
        method='DynamicObject -[staticGeometryForegroundDrawQuadCountForMacroPos:]',
        types='i16@0:4{?=ii}8',
        start=8632936,
        end=8632972,
        disasm='disasm_worldtileloader_dob_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ba8c (listing bound); next ObjC IMP 0x0083ba8c DynamicObject -[addDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632936, 'sub sp, sp, 0x10'), (8632968, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryForegroundDrawQuadCountForMacroPos:]] (imp 0x0083ba68, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_26',
        method='DynamicObject -[addDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=8632972,
        end=8633028,
        disasm='disasm_worldtileloader_dob_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bafc; body trimmed at the next IMP 0x0083bac4 DynamicObject -[addForegroundDrawQuadData:fromIndex:forMacroPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8632972, 'push {r4, lr}'), (8633024, 'pop {r4, pc}')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addDrawQuadData:fromIndex:forMacroPos:]] (imp 0x0083ba8c, 14w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_27',
        method='DynamicObject -[addForegroundDrawQuadData:fromIndex:forMacroPos:]',
        types='i24@0:4^f8i12{?=ii}16',
        start=8633028,
        end=8633084,
        disasm='disasm_worldtileloader_dob_27.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bafc (listing bound); next ObjC IMP 0x0083bafc DynamicObject -[staticGeometryDrawItemQuadCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633028, 'push {r4, lr}'), (8633080, 'pop {r4, pc}')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addForegroundDrawQuadData:fromIndex:forMacroPos:]] (imp 0x0083bac4, 14w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_28',
        method='DynamicObject -[staticGeometryDrawItemQuadCount]',
        types='i8@0:4',
        start=8633084,
        end=8633112,
        disasm='disasm_worldtileloader_dob_28.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bb18 (listing bound); next ObjC IMP 0x0083bb18 DynamicObject -[addDrawItemQuadData:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633084, 'sub sp, sp, 8'), (8633108, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryDrawItemQuadCount]] (imp 0x0083bafc, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_29',
        method='DynamicObject -[addDrawItemQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=8633112,
        end=8633148,
        disasm='disasm_worldtileloader_dob_29.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bb3c (listing bound); next ObjC IMP 0x0083bb3c DynamicObject -[lightGlowQuadCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633112, 'sub sp, sp, 0x10'), (8633144, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addDrawItemQuadData:fromIndex:]] (imp 0x0083bb18, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_30',
        method='DynamicObject -[lightGlowQuadCount]',
        types='i8@0:4',
        start=8633148,
        end=8633176,
        disasm='disasm_worldtileloader_dob_30.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bb74; body trimmed at the next IMP 0x0083bb58 DynamicObject -[staticGeometryCylinderCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633148, 'sub sp, sp, 8'), (8633172, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[lightGlowQuadCount]] (imp 0x0083bb3c, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_31',
        method='DynamicObject -[staticGeometryCylinderCount]',
        types='i8@0:4',
        start=8633176,
        end=8633204,
        disasm='disasm_worldtileloader_dob_31.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bb74 (listing bound); next ObjC IMP 0x0083bb74 DynamicObject -[addCylinderData:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633176, 'sub sp, sp, 8'), (8633200, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryCylinderCount]] (imp 0x0083bb58, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_32',
        method='DynamicObject -[addCylinderData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=8633204,
        end=8633240,
        disasm='disasm_worldtileloader_dob_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bb98 (listing bound); next ObjC IMP 0x0083bb98 DynamicObject -[staticGeometryCylinderCountTrans]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633204, 'sub sp, sp, 0x10'), (8633236, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addCylinderData:fromIndex:]] (imp 0x0083bb74, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_33',
        method='DynamicObject -[staticGeometryCylinderCountTrans]',
        types='i8@0:4',
        start=8633240,
        end=8633268,
        disasm='disasm_worldtileloader_dob_33.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bbb4 (listing bound); next ObjC IMP 0x0083bbb4 DynamicObject -[addCylinderDataTrans:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633240, 'sub sp, sp, 8'), (8633264, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryCylinderCountTrans]] (imp 0x0083bb98, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_34',
        method='DynamicObject -[addCylinderDataTrans:fromIndex:]',
        types='i16@0:4^f8i12',
        start=8633268,
        end=8633304,
        disasm='disasm_worldtileloader_dob_34.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bbd8 (listing bound); next ObjC IMP 0x0083bbd8 DynamicObject -[staticGeometryDodoEggCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633268, 'sub sp, sp, 0x10'), (8633300, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addCylinderDataTrans:fromIndex:]] (imp 0x0083bbb4, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_35',
        method='DynamicObject -[staticGeometryDodoEggCount]',
        types='i8@0:4',
        start=8633304,
        end=8633332,
        disasm='disasm_worldtileloader_dob_35.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bbf4 (listing bound); next ObjC IMP 0x0083bbf4 DynamicObject -[addDodoEggDrawQuadData:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633304, 'sub sp, sp, 8'), (8633328, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[staticGeometryDodoEggCount]] (imp 0x0083bbd8, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_36',
        method='DynamicObject -[addDodoEggDrawQuadData:fromIndex:]',
        types='i16@0:4^f8i12',
        start=8633332,
        end=8633368,
        disasm='disasm_worldtileloader_dob_36.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083bc18 (listing bound); next ObjC IMP 0x0083bc18 DynamicObject -[addLightGlowQuadData:fromIndex:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8633332, 'sub sp, sp, 0x10'), (8633364, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addDodoEggDrawQuadData:fromIndex:]] (imp 0x0083bbf4, 9w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_37',
        method='DynamicObject -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=8636560,
        end=8636584,
        disasm='disasm_worldtileloader_dob_37.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083c8a8 (listing bound); next ObjC IMP 0x0083c8a8 DynamicObject -[blockheadsLoaded]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8636560, 'sub sp, sp, 0xc'), (8636580, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[blockheadUnloaded:]] (imp 0x0083c890, 6w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_38',
        method='DynamicObject -[blockheadsLoaded]',
        types='v8@0:4',
        start=8636584,
        end=8636604,
        disasm='disasm_worldtileloader_dob_38.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083c8bc (listing bound); next ObjC IMP 0x0083c8bc DynamicObject -[lightPos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8636584, 'sub sp, sp, 8'), (8636600, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[blockheadsLoaded]] (imp 0x0083c8a8, 5w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_39',
        method='DynamicObject -[isDownlight]',
        types='c8@0:4',
        start=8636768,
        end=8636796,
        disasm='disasm_worldtileloader_dob_39.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083c998; body trimmed at the next IMP 0x0083c97c DynamicObject -[isUplight]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8636768, 'sub sp, sp, 8'), (8636792, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[isDownlight]] (imp 0x0083c960, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_40',
        method='DynamicObject -[isUplight]',
        types='c8@0:4',
        start=8636796,
        end=8636824,
        disasm='disasm_worldtileloader_dob_40.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083c998 (listing bound); next ObjC IMP 0x0083c998 DynamicObject -[getLightRGB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8636796, 'sub sp, sp, 8'), (8636820, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[isUplight]] (imp 0x0083c97c, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_41',
        method='DynamicObject -[needsNetDataToBeSent]',
        types='c8@0:4',
        start=8636892,
        end=8637080,
        disasm='disasm_worldtileloader_dob_41.txt',
        base_add=8636900,
        base_literal=8637076,
        boundary='ARM.exidx end 0x0083ca98 (listing bound); next ObjC IMP 0x0083ca98 DynamicObject -[occupiesForegroundContents]',
        selectors={},
        imports={},
        ivars={
                 0x83ca88: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x83ca8c: (17157420, 'OBJC_IVAR_$_DynamicObject.unreliableUpdateNeedsToBeSent', 51),
                 0x83ca90: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(8636892, 'sub sp, sp, 0x10'), (8637076, 'addeq r3, r2, r8, lsl 2')],
        calls=[],
        branches=[(8636952, 'bne', 8637044), (8636996, 'bne', 8637044)],
        semantics=('[DynamicObject -[needsNetDataToBeSent]] (imp 0x0083c9dc, 47w): the dirty-net-data fold - ors updateNeedsToBeSent/unreliableUpdateNeedsToBeSent/needsRemoved.\n'),
    ),
    dict(
        name='dob_42',
        method='DynamicObject -[occupiesForegroundContents]',
        types='c8@0:4',
        start=8637080,
        end=8637108,
        disasm='disasm_worldtileloader_dob_42.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cb7c; body trimmed at the next IMP 0x0083cab4 DynamicObject -[occupiesNormalContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8637080, 'sub sp, sp, 8'), (8637104, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[occupiesForegroundContents]] (imp 0x0083ca98, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_43',
        method='DynamicObject -[occupiesNormalContents]',
        types='c8@0:4',
        start=8637108,
        end=8637136,
        disasm='disasm_worldtileloader_dob_43.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cb7c; body trimmed at the next IMP 0x0083cad0 DynamicObject -[occupiesBackgroundContents]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8637108, 'sub sp, sp, 8'), (8637132, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[occupiesNormalContents]] (imp 0x0083cab4, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_44',
        method='DynamicObject -[occupiesBackgroundContents]',
        types='c8@0:4',
        start=8637136,
        end=8637164,
        disasm='disasm_worldtileloader_dob_44.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cb7c; body trimmed at the next IMP 0x0083caec DynamicObject -[ownerID]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8637136, 'sub sp, sp, 8'), (8637160, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[occupiesBackgroundContents]] (imp 0x0083cad0, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_45',
        method='DynamicObject -[ownerID]',
        types='@8@0:4',
        start=8637164,
        end=8637224,
        disasm='disasm_worldtileloader_dob_45.txt',
        base_add=8637172,
        base_literal=8637220,
        boundary='ARM.exidx end 0x0083cb7c; body trimmed at the next IMP 0x0083cb28 DynamicObject -[mayOnlyBeRemovedByOwner]',
        selectors={},
        imports={},
        ivars={
                 0x83cb20: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={},
        instructions=[(8637164, 'sub sp, sp, 8'), (8637220, 'strdeq r2, r3, [r2], r8')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[ownerID]] (imp 0x0083caec, 15w): bare ivar getter (ownerID).\n'),
    ),
    dict(
        name='dob_46',
        method='DynamicObject -[mayOnlyBeRemovedByOwner]',
        types='c8@0:4',
        start=8637224,
        end=8637308,
        disasm='disasm_worldtileloader_dob_46.txt',
        base_add=8637232,
        base_literal=8637304,
        boundary='ARM.exidx end 0x0083cb7c (listing bound); next ObjC IMP 0x0083cb7c DynamicObject -[canBeRemovedByBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x83cb74: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={},
        instructions=[(8637224, 'sub sp, sp, 8'), (8637304, 'strheq r2, [r2], ip')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[mayOnlyBeRemovedByOwner]] (imp 0x0083cb28, 21w): the ownership flag - ownerID-based (may only be removed by its owner).\n'),
    ),
    dict(
        name='dob_47',
        method='DynamicObject -[canBeRemovedByBlockhead:]',
        types='c12@0:4@8',
        start=8637308,
        end=8638108,
        disasm='disasm_worldtileloader_dob_47.txt',
        base_add=8637324,
        base_literal=8638104,
        boundary='ARM.exidx end 0x0083ce9c (listing bound); next ObjC IMP 0x0083ce9c DynamicObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={
                 0x83ce60: (15213044, 'isAdmin'),
                 0x83ce68: (15213048, 'isClientBlockheadBeingControlledByServer'),
                 0x83ce6c: (15213052, 'isNet'),
                 0x83ce70: (15213064, 'playerIsAdminWithID:'),
                 0x83ce74: (15213060, 'clientID'),
                 0x83ce78: (15213056, 'server'),
                 0x83ce7c: (15213068, 'mayOnlyBeRemovedByOwner'),
                 0x83ce88: (15213072, 'tileIsProtectedAtPos:againstBlockhead:'),
                 0x83ce8c: (15213080, 'isEqualToString:'),
                 0x83ce94: (15213076, 'localNetID'),
        },
        imports={
                 0x83ce5c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x83ce64: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x83ce84: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x83ce90: (17154976, 'OBJC_IVAR_$_DynamicObject.ownerID', 36),
        },
        classes={},
        instructions=[(8637308, 'push {r4, r5, r6, sl, fp, lr}'), (8638104, 'addeq r2, r2, r0, ror 30')],
        calls=[(8637388, 'blx ip'), (8637444, 'blx r2'), (8637500, 'blx r2'), (8637628, 'blx r4'), (8637660, 'blx r3'), (8637692, 'blx r3'), (8637760, 'blx r2'), (8637876, 'bl loc.imp.objc_msgSend'), (8637988, 'blx lr'), (8638024, 'blx r3')],
        branches=[(8637400, 'beq', 8637528), (8637456, 'bne', 8637528), (8637512, 'bne', 8637528), (8637524, 'b', 8638032), (8637704, 'beq', 8637720), (8637716, 'b', 8638032), (8637772, 'bne', 8637916), (8637888, 'beq', 8637904), (8637900, 'b', 8638032), (8637912, 'b', 8638032)],
        semantics=('[DynamicObject -[canBeRemovedByBlockhead:]] (imp 0x0083cb7c, 200w): the removal permission check - isNet / isAdmin / isClientBlockheadBeingControlledByServer + playerIsAdminWithID:/clientID/server + the mayOnlyBeRemovedByOwner gate.\n'),
    ),
    dict(
        name='dob_48',
        method='DynamicObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=8638108,
        end=8638136,
        disasm='disasm_worldtileloader_dob_48.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ceb8 (listing bound); next ObjC IMP 0x0083ceb8 DynamicObject -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8638108, 'sub sp, sp, 0x10'), (8638132, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]] (imp 0x0083ce9c, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_49',
        method='DynamicObject -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]',
        types='@8@0:4',
        start=8638136,
        end=8638164,
        disasm='disasm_worldtileloader_dob_49.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083ced4 (listing bound); next ObjC IMP 0x0083ced4 DynamicObject -[renderPos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8638136, 'sub sp, sp, 8'), (8638160, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]] (imp 0x0083ceb8, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_50',
        method='DynamicObject -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=8638164,
        end=8638300,
        disasm='disasm_worldtileloader_dob_50.txt',
        base_add=8638180,
        base_literal=8638296,
        boundary='ARM.exidx end 0x0083cf5c (listing bound); next ObjC IMP 0x0083cf5c DynamicObject -[freeblockCreationItemType]',
        selectors={
                 0x83cf54: (15213084, 'floatPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(8638164, 'push {fp, lr}'), (8638296, 'addeq r2, r2, r8, lsl 24')],
        calls=[(8638244, 'bl loc.imp.objc_msgSend_stret'), (8638280, 'bl sym.imp.memset')],
        branches=[(8638228, 'beq', 8638252), (8638248, 'b', 8638284)],
        semantics=('[DynamicObject -[renderPos]] (imp 0x0083ced4, 34w): renderPos - floatPos read via stret.\n'),
    ),
    dict(
        name='dob_51',
        method='DynamicObject -[freeblockCreationItemType]',
        types='i8@0:4',
        start=8638300,
        end=8638328,
        disasm='disasm_worldtileloader_dob_51.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cfcc; body trimmed at the next IMP 0x0083cf78 DynamicObject -[freeBlockCreationSaveDict]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8638300, 'sub sp, sp, 8'), (8638324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[freeblockCreationItemType]] (imp 0x0083cf5c, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_52',
        method='DynamicObject -[freeBlockCreationSaveDict]',
        types='@8@0:4',
        start=8638328,
        end=8638356,
        disasm='disasm_worldtileloader_dob_52.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cfcc; body trimmed at the next IMP 0x0083cf94 DynamicObject -[freeBlockCreationDataA]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8638328, 'sub sp, sp, 8'), (8638352, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[freeBlockCreationSaveDict]] (imp 0x0083cf78, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_53',
        method='DynamicObject -[freeBlockCreationDataA]',
        types='S8@0:4',
        start=8638356,
        end=8638384,
        disasm='disasm_worldtileloader_dob_53.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cfcc; body trimmed at the next IMP 0x0083cfb0 DynamicObject -[freeBlockCreationDataB]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8638356, 'sub sp, sp, 8'), (8638380, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[freeBlockCreationDataA]] (imp 0x0083cf94, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_54',
        method='DynamicObject -[freeBlockCreationDataB]',
        types='S8@0:4',
        start=8638384,
        end=8638412,
        disasm='disasm_worldtileloader_dob_54.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0083cfcc (listing bound); next ObjC IMP 0x0083cfcc DynamicObject -[pos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8638384, 'sub sp, sp, 8'), (8638408, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[freeBlockCreationDataB]] (imp 0x0083cfb0, 7w): base-class hook stub (override point; default return).\n'),
    ),
    dict(
        name='dob_55',
        method='DynamicObject -[needsRemoved]',
        types='c8@0:4',
        start=8638704,
        end=8638764,
        disasm='disasm_worldtileloader_dob_55.txt',
        base_add=8638712,
        base_literal=8638760,
        boundary='ARM.exidx end 0x0083d12c (listing bound); next ObjC IMP 0x0083d12c DynamicObject -[setNeedsRemoved:]',
        selectors={},
        imports={},
        ivars={
                 0x83d124: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(8638704, 'sub sp, sp, 8'), (8638760, 'strdeq r2, r3, [r2], r4')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[needsRemoved]] (imp 0x0083d0f0, 15w): bare ivar getter (needsRemoved).\n'),
    ),
    dict(
        name='dob_56',
        method='DynamicObject -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=8638764,
        end=8638832,
        disasm='disasm_worldtileloader_dob_56.txt',
        base_add=8638792,
        base_literal=8638828,
        boundary='ARM.exidx end 0x0083d170 (listing bound); next ObjC IMP 0x0083d170 DynamicObject -[updateNeedsToBeSent]',
        selectors={},
        imports={},
        ivars={
                 0x83d168: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(8638764, 'sub sp, sp, 0xc'), (8638828, 'addeq r2, r2, r4, lsr 19')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[setNeedsRemoved:]] (imp 0x0083d12c, 17w): bare ivar setter (needsRemoved).\n'),
    ),
    dict(
        name='dob_57',
        method='DynamicObject -[updateNeedsToBeSent]',
        types='c8@0:4',
        start=8638832,
        end=8638892,
        disasm='disasm_worldtileloader_dob_57.txt',
        base_add=8638840,
        base_literal=8638888,
        boundary='ARM.exidx end 0x0083d1ac (listing bound); next ObjC IMP 0x0083d1ac DynamicObject -[setUpdateNeedsToBeSent:]',
        selectors={},
        imports={},
        ivars={
                 0x83d1a4: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(8638832, 'sub sp, sp, 8'), (8638888, 'addeq r2, r2, r4, ror sb')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[updateNeedsToBeSent]] (imp 0x0083d170, 15w): bare ivar getter (updateNeedsToBeSent).\n'),
    ),
    dict(
        name='dob_58',
        method='DynamicObject -[setUpdateNeedsToBeSent:]',
        types='v12@0:4c8',
        start=8638892,
        end=8638960,
        disasm='disasm_worldtileloader_dob_58.txt',
        base_add=8638920,
        base_literal=8638956,
        boundary='ARM.exidx end 0x0083d1f0 (listing bound); next ObjC IMP 0x0083d1f0 DynamicObject -[creationDataNeedsToBeSent]',
        selectors={},
        imports={},
        ivars={
                 0x83d1e8: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
        },
        classes={},
        instructions=[(8638892, 'sub sp, sp, 0xc'), (8638956, 'addeq r2, r2, r4, lsr 18')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[setUpdateNeedsToBeSent:]] (imp 0x0083d1ac, 17w): bare ivar setter (updateNeedsToBeSent).\n'),
    ),
    dict(
        name='dob_59',
        method='DynamicObject -[creationDataNeedsToBeSent]',
        types='c8@0:4',
        start=8638960,
        end=8639020,
        disasm='disasm_worldtileloader_dob_59.txt',
        base_add=8638968,
        base_literal=8639016,
        boundary='ARM.exidx end 0x0083d22c (listing bound); next ObjC IMP 0x0083d22c DynamicObject -[setCreationDataNeedsToBeSent:]',
        selectors={},
        imports={},
        ivars={
                 0x83d224: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
        },
        classes={},
        instructions=[(8638960, 'sub sp, sp, 8'), (8639016, 'strdeq r2, r3, [r2], r4')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[creationDataNeedsToBeSent]] (imp 0x0083d1f0, 15w): bare ivar getter (creationDataNeedsToBeSent).\n'),
    ),
    dict(
        name='dob_60',
        method='DynamicObject -[setCreationDataNeedsToBeSent:]',
        types='v12@0:4c8',
        start=8639020,
        end=8639088,
        disasm='disasm_worldtileloader_dob_60.txt',
        base_add=8639048,
        base_literal=8639084,
        boundary='ARM.exidx end 0x0083d270 (listing bound); next ObjC IMP 0x0083d270 DynamicObject -[unreliableUpdateNeedsToBeSent]',
        selectors={},
        imports={},
        ivars={
                 0x83d268: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
        },
        classes={},
        instructions=[(8639020, 'sub sp, sp, 0xc'), (8639084, 'addeq r2, r2, r4, lsr 17')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[setCreationDataNeedsToBeSent:]] (imp 0x0083d22c, 17w): bare ivar setter (creationDataNeedsToBeSent).\n'),
    ),
    dict(
        name='dob_61',
        method='DynamicObject -[unreliableUpdateNeedsToBeSent]',
        types='c8@0:4',
        start=8639088,
        end=8639148,
        disasm='disasm_worldtileloader_dob_61.txt',
        base_add=8639096,
        base_literal=8639144,
        boundary='ARM.exidx end 0x0083d2ac (listing bound); next ObjC IMP 0x0083d2ac DynamicObject -[setUnreliableUpdateNeedsToBeSent:]',
        selectors={},
        imports={},
        ivars={
                 0x83d2a4: (17157420, 'OBJC_IVAR_$_DynamicObject.unreliableUpdateNeedsToBeSent', 51),
        },
        classes={},
        instructions=[(8639088, 'sub sp, sp, 8'), (8639144, 'addeq r2, r2, r4, ror r8')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[unreliableUpdateNeedsToBeSent]] (imp 0x0083d270, 15w): bare ivar getter (unreliableUpdateNeedsToBeSent).\n'),
    ),
    dict(
        name='dob_62',
        method='DynamicObject -[setUnreliableUpdateNeedsToBeSent:]',
        types='v12@0:4c8',
        start=8639148,
        end=8639216,
        disasm='disasm_worldtileloader_dob_62.txt',
        base_add=8639176,
        base_literal=8639212,
        boundary='ARM.exidx end 0x0083d2f0 (listing bound); next ObjC IMP 0x0083d2f0 DynamicObject -[isNet]',
        selectors={},
        imports={},
        ivars={
                 0x83d2e8: (17157420, 'OBJC_IVAR_$_DynamicObject.unreliableUpdateNeedsToBeSent', 51),
        },
        classes={},
        instructions=[(8639148, 'sub sp, sp, 0xc'), (8639212, 'addeq r2, r2, r4, lsr 16')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[setUnreliableUpdateNeedsToBeSent:]] (imp 0x0083d2ac, 17w): bare ivar setter (unreliableUpdateNeedsToBeSent).\n'),
    ),
    dict(
        name='dob_63',
        method='DynamicObject -[isNet]',
        types='c8@0:4',
        start=8639216,
        end=8639276,
        disasm='disasm_worldtileloader_dob_63.txt',
        base_add=8639224,
        base_literal=8639272,
        boundary='ARM.exidx end 0x0083d32c (listing bound); next ObjC IMP 0x0083d32c DynamicObject -[macroTileOwner]',
        selectors={},
        imports={},
        ivars={
                 0x83d324: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
        },
        classes={},
        instructions=[(8639216, 'sub sp, sp, 8'), (8639272, 'strdeq r2, r3, [r2], r4')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[isNet]] (imp 0x0083d2f0, 15w): bare ivar getter (isNet).\n'),
    ),
    dict(
        name='dob_64',
        method='DynamicObject -[macroTileOwner]',
        types='^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8@0:4',
        start=8639276,
        end=8639344,
        disasm='disasm_worldtileloader_dob_64.txt',
        base_add=8639300,
        base_literal=8639340,
        boundary='ARM.exidx end 0x0083d370 (listing bound); next ObjC IMP 0x0083d370 DynamicObject -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x83d368: (17155000, 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 12),
        },
        classes={},
        instructions=[(8639276, 'sub sp, sp, 0xc'), (8639340, 'addeq r2, r2, r8, lsr 15')],
        calls=[],
        branches=[],
        semantics=('[DynamicObject -[macroTileOwner]] (imp 0x0083d32c, 17w): bare ivar getter (macroTileOwner).\n'),
    ),
    dict(
        name='dob_65',
        method='DynamicObject -[.cxx_construct]',
        types='@8@0:4',
        start=8639344,
        end=8639632,
        disasm='disasm_worldtileloader_dob_65.txt',
        base_add=8639360,
        base_literal=8639420,
        boundary='ARM.exidx end 0x0083d490 (listing bound); next ObjC IMP 0x0083dbb0 FishingRod -[initWithWorld:blockhead:cache:]',
        selectors={},
        imports={},
        ivars={
                 0x83d3b8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(8639344, 'push {fp, lr}'), (8639628, 'andeq r0, r0, r0')],
        calls=[(8639392, 'bl method.Vector2.Vector2__'), (8639492, 'bl sym.imp.cosf'), (8639512, 'bl sym.imp.sinf')],
        branches=[],
        semantics=('[DynamicObject -[.cxx_construct]] (imp 0x0083d370, 72w): the C++ member constructor - Vector2 ctor + cosf + sinf: the rotation basis (the DonkeyLike .cxx_construct pattern).\n'),
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
        'batch': 'DynamicObject base class closure (E116): ctor triad, position updater, permission check and hook stubs; 66 bodies',
        'claim': ('the DynamicObject base class closures; the concrete subclass overrides are covered by their own batches (Workbench/Torch/plants etc.)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dynobj.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale dynobj.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
