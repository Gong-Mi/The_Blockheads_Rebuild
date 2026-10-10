#!/usr/bin/env python3
"""Hash-gated recovery of the WorldTileLoader closure batch (E18).

The WorldTileLoader closure set - the class's teardown and accessor surface that
closes the class after the write/send (E14), migrate (E15), load (E16) and
construct (E17) batches: dealloc (releases + six C-buffer frees + super),
.cxx_construct (no-op) and fourteen accessors:
1 body, 736 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WTL_CLOSURE.md for the prose and boundaries.
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
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.objc_copyStruct': 0x001c2888,
}

SPECS = [
    dict(
        name='wtl_dealloc',
        method='WorldTileLoader -[dealloc]',
        types='v8@0:4',
        start=8734576,
        end=8735768,
        disasm='disasm_worldtileloader_dealloc.txt',
        base_add=8734592,
        base_literal=8735764,
        boundary='ARM.exidx end 0x00854c18 (listing bound); next ObjC IMP 0x00854c18 WorldTileLoader -[refineTerrainCount]',
        selectors={
                 0x854bb0: (15213612, 'dealloc'),
                 0x854bbc: (15213588, 'release'),
        },
        imports={
                 0x854bac: (17151900, 'objc_msgSendSuper2'),
                 0x854bb8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x854bc0: (17161584, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment', 248),
                 0x854bc4: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
                 0x854bc8: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
                 0x854bcc: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x854bd0: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x854bd4: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
                 0x854bd8: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x854bdc: (17161640, 'OBJC_IVAR_$_WorldTileLoader.treePositions', 64),
                 0x854be0: (17161616, 'OBJC_IVAR_$_WorldTileLoader.gemNoiseFunction', 60),
                 0x854be4: (17161588, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionB', 56),
                 0x854be8: (17161592, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionA', 52),
                 0x854bec: (17161620, 'OBJC_IVAR_$_WorldTileLoader.seasonOffsetNoiseFunction', 48),
                 0x854bf0: (17161600, 'OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction', 44),
                 0x854bf4: (17161624, 'OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction', 40),
                 0x854bf8: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x854bfc: (17161632, 'OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction', 32),
                 0x854c00: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x854c04: (17161596, 'OBJC_IVAR_$_WorldTileLoader.faultNoiseFunction', 24),
                 0x854c08: (17161604, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB', 20),
                 0x854c0c: (17161608, 'OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionA', 16),
                 0x854c10: (17161576, 'OBJC_IVAR_$_WorldTileLoader.blockDirectory', 12),
        },
        classes={
                 0x854bb4: (15252880, 'OBJC_CLASS_$_WorldTileLoader'),
        },
        instructions=[(8734576, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8734832, 'blx ip'), (8735288, 'bl sym.imp.__wrap_free'), (8735648, 'blx r2'), (8735764, 'addeq fp, r0, ip, ror 6')],
        calls=[(8734832, 'blx ip'), (8734868, 'blx r3'), (8734904, 'blx r3'), (8734940, 'blx r3'), (8734976, 'blx r3'), (8735012, 'blx r3'), (8735048, 'blx r3'), (8735084, 'blx r3'), (8735120, 'blx r3'), (8735156, 'blx r3'), (8735192, 'blx r3'), (8735228, 'blx r3'), (8735264, 'blx r3'), (8735288, 'bl sym.imp.__wrap_free'), (8735320, 'bl sym.imp.__wrap_free'), (8735352, 'bl sym.imp.__wrap_free'), (8735384, 'bl sym.imp.__wrap_free'), (8735416, 'bl sym.imp.__wrap_free'), (8735448, 'bl sym.imp.__wrap_free'), (8735572, 'blx lr'), (8735608, 'blx r3'), (8735648, 'blx r2')],
        branches=[],
        semantics=('dealloc is the WorldTileLoader teardown: it releases the object ivars, frees the six C\nbuffers and calls [super dealloc]. Prologue 0x00854770 (push {r4-r8,sl,fp,lr}; frame\n0x78; PIC base cell 0x00854c14). The body first stages 21 ivar cells into the frame\n(0x008547f4-0x00854820, cells 0x00854bc0-0x00854c10) plus the two selector cells\n(0x00854bb0 dealloc, 0x00854bbc release) and the import cells (0x00854bac\nobjc_msgSendSuper2, 0x00854bb8 objc_msgSend) and the classref cell (0x00854bb4\nOBJC_CLASS_$_WorldTileLoader).\nRelease chain (0x00854824-0x00854a20): thirteen objc_msgSend(release) dispatches through\nthe selector cell 0x00854bbc with self staged at [fp,-0x1c]: blockDirectory (cell\n0x00854c10) first at 0x00854870, then the twelve noise functions - heightNoiseFunctionA\n(0x00854c0c), heightNoiseFunctionB (0x00854c08), faultNoiseFunction (0x00854c04),\ntreeDensityNoiseFunction (0x00854c00), rockTypeNoiseFunction (0x00854bfc),\nflintDensityNoiseFunction (0x00854bf8), tinDensityNoiseFunction (0x00854bf4),\nsandNoiseFunction (0x00854bf0), seasonOffsetNoiseFunction (0x00854bec),\ncaveNoiseFunctionA (0x00854be8), caveNoiseFunctionB (0x00854be4), gemNoiseFunction\n(0x00854be0).\nC-buffer frees (0x00854a24-0x00854ad8): six __wrap_free calls on the ivar values of\ntreePositions (0x00854bdc), npcPositions (0x00854bd8), plantPositions (0x00854bd4),\ndirtHeights (0x00854bd0), rockHeights (0x00854bcc) and lakeHeights (0x00854bc8) - the\nthree height arrays and the three position arrays are raw C buffers, not collections.\nTail (0x00854adc-0x00854ba8): [self.lightBlockDatabase release] (cells 0x00854bc4 +\n0x00854bbc, dispatch 0x00854b54), [self.lightBlockDatabaseEnvironment release] (cell\n0x00854bc0, dispatch 0x00854b78), then the super-call struct {self, class} is built at\nfp-0x28 and dispatched through objc_msgSendSuper2 (cell 0x00854bac) with\n@selector(dealloc) (cell 0x00854bb0) at 0x00854ba0; epilogue pop {r4-r8,sl,fp,pc}\n(0x00854ba4-0x00854ba8). One unclassified pool cell (0x00854c14) is the PIC base\nanchor itself.\n'),
    ),
    dict(
        name='wtl_cxx_construct',
        method='WorldTileLoader -[.cxx_construct]',
        types='@8@0:4',
        start=8818648,
        end=8818672,
        disasm='disasm_worldtileloader_cxx_construct.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00868ff0 (listing bound); next ObjC IMP 0x00869584 GatherBlock -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8818648, 'sub sp, sp, 8'), (8818660, 'ldr r0, [sp, 4]'), (8818668, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('.cxx_construct is a no-op stub: sub sp,8; spill (self, _cmd); reload self; restore\nsp; bx lr - it returns self unchanged. The class declares no C++ subobjects that need\nconstruction. Six words, the shortest body of the batch.\n'),
    ),
    dict(
        name='wtl_distanceorderedfoodtyp',
        method='WorldTileLoader -[distanceOrderedFoodTypes]',
        types='^i8@0:4',
        start=8802420,
        end=8802480,
        disasm='disasm_worldtileloader_distanceorderedfoodtypes.txt',
        base_add=8802428,
        base_literal=8802472,
        boundary='ARM.exidx end 0x008650b0 (listing bound); next ObjC IMP 0x008650b0 WorldTileLoader -[updatePhysicalBlockToLatestVersion:]',
        selectors={},
        imports={},
        ivars={
                 0x8650a4: (17161652, 'OBJC_IVAR_$_WorldTileLoader.distanceOrderedFoodTypes', 108),
        },
        classes={},
        instructions=[(8802420, 'sub sp, sp, 8'), (8802476, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('distanceOrderedFoodTypes is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x008650a4 (distanceOrderedFoodTypes). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for an int* return.\n'),
    ),
    dict(
        name='wtl_randomseed',
        method='WorldTileLoader -[randomSeed]',
        types='I8@0:4',
        start=8817728,
        end=8817788,
        disasm='disasm_worldtileloader_randomseed.txt',
        base_add=8817752,
        base_literal=8817784,
        boundary='ARM.exidx end 0x00868c7c (listing bound); next ObjC IMP 0x00868c7c WorldTileLoader -[bestStartPosition]',
        selectors={},
        imports={},
        ivars={
                 0x868c74: (17161560, 'OBJC_IVAR_$_WorldTileLoader.randomSeed', 8),
        },
        classes={},
        instructions=[(8817728, 'sub sp, sp, 8'), (8817784, 'invalid')],
        calls=[],
        branches=[],
        semantics=('randomSeed is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868c74 (randomSeed). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for an unsigned-int return.\n'),
    ),
    dict(
        name='wtl_beststartposition',
        method='WorldTileLoader -[bestStartPosition]',
        types='{?=ii}8@0:4',
        start=8817788,
        end=8817884,
        disasm='disasm_worldtileloader_beststartposition.txt',
        base_add=8817804,
        base_literal=8817880,
        boundary='ARM.exidx end 0x00868cdc (listing bound); next ObjC IMP 0x00868cdc WorldTileLoader -[treeDensityNoiseFunction]',
        selectors={},
        imports={},
        ivars={
                 0x868cd4: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
        },
        classes={},
        instructions=[(8817788, 'push {r4, r5, fp, lr}'), (8817880, 'rsbseq r6, pc, r0, ror 28')],
        calls=[(8817864, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('bestStartPosition is a struct getter: objc_copyStruct(dst = the ABI return pointer, src = self + OFF\n(cell 0x00868cd4, bestStartPosition), size 8, atomic 1, hasStrong 0) - an atomic 8-byte copy of the\n{int,int} pair, with the atomic flag argument materialised as movw lr,1 / movw r4,0.\n'),
    ),
    dict(
        name='wtl_treedensitynoisefuncti',
        method='WorldTileLoader -[treeDensityNoiseFunction]',
        types='@8@0:4',
        start=8817884,
        end=8818224,
        disasm='disasm_worldtileloader_treedensitynoisefunction.txt',
        base_add=8817908,
        base_literal=8817948,
        boundary='ARM.exidx end 0x00868e30 (listing bound); next ObjC IMP 0x00868d20 WorldTileLoader -[seasonOffsetNoiseFunction]',
        selectors={},
        imports={},
        ivars={
                 0x868d18: (17161636, 'OBJC_IVAR_$_WorldTileLoader.treeDensityNoiseFunction', 28),
                 0x868d5c: (17161620, 'OBJC_IVAR_$_WorldTileLoader.seasonOffsetNoiseFunction', 48),
                 0x868da0: (17161640, 'OBJC_IVAR_$_WorldTileLoader.treePositions', 64),
                 0x868de4: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x868e28: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
        },
        classes={},
        instructions=[(8817884, 'sub sp, sp, 0xc'), (8818220, 'rsbseq r6, pc, r8, ror 25')],
        calls=[],
        branches=[],
        semantics=('treeDensityNoiseFunction is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868d18 (treeDensityNoiseFunction). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for an object-typed ivar read.\n'),
    ),
    dict(
        name='wtl_seasonoffsetnoisefunct',
        method='WorldTileLoader -[seasonOffsetNoiseFunction]',
        types='@8@0:4',
        start=8817952,
        end=8818224,
        disasm='disasm_worldtileloader_seasonoffsetnoisefunction.txt',
        base_add=8817976,
        base_literal=8818016,
        boundary='ARM.exidx end 0x00868e30 (listing bound); next ObjC IMP 0x00868d64 WorldTileLoader -[treePositions]',
        selectors={},
        imports={},
        ivars={
                 0x868d5c: (17161620, 'OBJC_IVAR_$_WorldTileLoader.seasonOffsetNoiseFunction', 48),
                 0x868da0: (17161640, 'OBJC_IVAR_$_WorldTileLoader.treePositions', 64),
                 0x868de4: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x868e28: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
        },
        classes={},
        instructions=[(8817952, 'sub sp, sp, 0xc'), (8818220, 'rsbseq r6, pc, r8, ror 25')],
        calls=[],
        branches=[],
        semantics=('seasonOffsetNoiseFunction is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868d5c (seasonOffsetNoiseFunction). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for an object-typed ivar read.\n'),
    ),
    dict(
        name='wtl_treepositions',
        method='WorldTileLoader -[treePositions]',
        types='^i8@0:4',
        start=8818020,
        end=8818224,
        disasm='disasm_worldtileloader_treepositions.txt',
        base_add=8818044,
        base_literal=8818084,
        boundary='ARM.exidx end 0x00868e30 (listing bound); next ObjC IMP 0x00868da8 WorldTileLoader -[npcPositions]',
        selectors={},
        imports={},
        ivars={
                 0x868da0: (17161640, 'OBJC_IVAR_$_WorldTileLoader.treePositions', 64),
                 0x868de4: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x868e28: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
        },
        classes={},
        instructions=[(8818020, 'sub sp, sp, 0xc'), (8818220, 'rsbseq r6, pc, r8, ror 25')],
        calls=[],
        branches=[],
        semantics=('treePositions is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868da0 (treePositions). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for a raw pointer ivar read.\n'),
    ),
    dict(
        name='wtl_npcpositions',
        method='WorldTileLoader -[npcPositions]',
        types='^i8@0:4',
        start=8818088,
        end=8818224,
        disasm='disasm_worldtileloader_npcpositions.txt',
        base_add=8818112,
        base_literal=8818152,
        boundary='ARM.exidx end 0x00868e30 (listing bound); next ObjC IMP 0x00868dec WorldTileLoader -[plantPositions]',
        selectors={},
        imports={},
        ivars={
                 0x868de4: (17161644, 'OBJC_IVAR_$_WorldTileLoader.npcPositions', 68),
                 0x868e28: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
        },
        classes={},
        instructions=[(8818088, 'sub sp, sp, 0xc'), (8818220, 'rsbseq r6, pc, r8, ror 25')],
        calls=[],
        branches=[],
        semantics=('npcPositions is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868de4 (npcPositions). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for a raw pointer ivar read.\n'),
    ),
    dict(
        name='wtl_plantpositions',
        method='WorldTileLoader -[plantPositions]',
        types='^i8@0:4',
        start=8818156,
        end=8818224,
        disasm='disasm_worldtileloader_plantpositions.txt',
        base_add=8818180,
        base_literal=8818220,
        boundary='ARM.exidx end 0x00868e30 (listing bound); next ObjC IMP 0x00868e30 WorldTileLoader -[highestPoint]',
        selectors={},
        imports={},
        ivars={
                 0x868e28: (17161648, 'OBJC_IVAR_$_WorldTileLoader.plantPositions', 72),
        },
        classes={},
        instructions=[(8818156, 'sub sp, sp, 0xc'), (8818220, 'rsbseq r6, pc, r8, ror 25')],
        calls=[],
        branches=[],
        semantics=('plantPositions is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868e28 (plantPositions). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for a raw pointer ivar read.\n'),
    ),
    dict(
        name='wtl_highestpoint',
        method='WorldTileLoader -[highestPoint]',
        types='{?=ii}8@0:4',
        start=8818224,
        end=8818320,
        disasm='disasm_worldtileloader_highestpoint.txt',
        base_add=8818240,
        base_literal=8818316,
        boundary='ARM.exidx end 0x00868e90 (listing bound); next ObjC IMP 0x00868e90 WorldTileLoader -[needsToExit]',
        selectors={},
        imports={},
        ivars={
                 0x868e88: (17161656, 'OBJC_IVAR_$_WorldTileLoader.highestPoint', 84),
        },
        classes={},
        instructions=[(8818224, 'push {r4, r5, fp, lr}'), (8818316, 'rsbseq r6, pc, ip, lsr 25')],
        calls=[(8818300, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('highestPoint is a struct getter: objc_copyStruct(dst = the ABI return pointer, src = self + OFF\n(cell 0x00868e88, highestPoint), size 8, atomic 1, hasStrong 0) - an atomic 8-byte copy of the\n{int,int} pair, with the atomic flag argument materialised as movw lr,1 / movw r4,0.\n'),
    ),
    dict(
        name='wtl_needstoexit',
        method='WorldTileLoader -[needsToExit]',
        types='c8@0:4',
        start=8818320,
        end=8818380,
        disasm='disasm_worldtileloader_needstoexit.txt',
        base_add=8818328,
        base_literal=8818376,
        boundary='ARM.exidx end 0x00868ecc (listing bound); next ObjC IMP 0x00868ecc WorldTileLoader -[setNeedsToExit:]',
        selectors={},
        imports={},
        ivars={
                 0x868ec4: (17161668, 'OBJC_IVAR_$_WorldTileLoader.needsToExit', 236),
        },
        classes={},
        instructions=[(8818320, 'sub sp, sp, 8'), (8818376, 'rsbseq r6, pc, r4, asr ip')],
        calls=[],
        branches=[],
        semantics=('needsToExit is a plain getter: `r0 = ldrsb *(self + OFF)` where OFF is the ivar cell\n0x00868ec4 (needsToExit); a signed-byte load with no memory barrier on the read path.\n'),
    ),
    dict(
        name='wtl_setneedstoexit_',
        method='WorldTileLoader -[setNeedsToExit:]',
        types='v12@0:4c8',
        start=8818380,
        end=8818448,
        disasm='disasm_worldtileloader_setneedstoexit_.txt',
        base_add=8818408,
        base_literal=8818444,
        boundary='ARM.exidx end 0x00868f10 (listing bound); next ObjC IMP 0x00868f10 WorldTileLoader -[xFrequencyMultiplier]',
        selectors={},
        imports={},
        ivars={
                 0x868f08: (17161668, 'OBJC_IVAR_$_WorldTileLoader.needsToExit', 236),
        },
        classes={},
        instructions=[(8818380, 'sub sp, sp, 0xc'), (8818444, 'rsbseq r6, pc, r4, lsl 24')],
        calls=[],
        branches=[],
        semantics=('setNeedsToExit: is the char setter: `dmb ish; *(self + OFF) = (signed char)value; dmb ish`\nwhere OFF is the ivar cell 0x00868f08 (needsToExit); barrier-before-store and\nbarrier-after-store, no retain (primitive ivar).\n'),
    ),
    dict(
        name='wtl_xfrequencymultiplier',
        method='WorldTileLoader -[xFrequencyMultiplier]',
        types='i8@0:4',
        start=8818448,
        end=8818508,
        disasm='disasm_worldtileloader_xfrequencymultiplier.txt',
        base_add=8818472,
        base_literal=8818504,
        boundary='ARM.exidx end 0x00868f4c (listing bound); next ObjC IMP 0x00868f4c WorldTileLoader -[yHeightDivider]',
        selectors={},
        imports={},
        ivars={
                 0x868f44: (17161552, 'OBJC_IVAR_$_WorldTileLoader.xFrequencyMultiplier', 240),
        },
        classes={},
        instructions=[(8818448, 'sub sp, sp, 8'), (8818504, 'rsbseq r6, pc, r4, asr 23')],
        calls=[],
        branches=[],
        semantics=('xFrequencyMultiplier is a float getter: `dmb ish` then `r0 = *(self + OFF)` (cell 0x00868f44, xFrequencyMultiplier)\nreloaded through the stack and moved to r0 via vmov r0, s0 - the value is returned in\nthe integer register pair per the ObjC float-return convention.\n'),
    ),
    dict(
        name='wtl_yheightdivider',
        method='WorldTileLoader -[yHeightDivider]',
        types='f8@0:4',
        start=8818508,
        end=8818648,
        disasm='disasm_worldtileloader_yheightdivider.txt',
        base_add=8818532,
        base_literal=8818576,
        boundary='ARM.exidx end 0x00868fd8 (listing bound); next ObjC IMP 0x00868f94 WorldTileLoader -[lightBlockDatabase]',
        selectors={},
        imports={},
        ivars={
                 0x868f8c: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x868fd0: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
        },
        classes={},
        instructions=[(8818508, 'sub sp, sp, 0xc'), (8818644, 'rsbseq r6, pc, r0, asr 22')],
        calls=[],
        branches=[],
        semantics=('yHeightDivider is a float getter: `dmb ish` then `r0 = *(self + OFF)` (cell 0x00868f8c, yHeightDivider)\nreloaded through the stack and moved to r0 via vmov r0, s0 - the value is returned in\nthe integer register pair per the ObjC float-return convention.\n'),
    ),
    dict(
        name='wtl_lightblockdatabase',
        method='WorldTileLoader -[lightBlockDatabase]',
        types='@8@0:4',
        start=8818580,
        end=8818648,
        disasm='disasm_worldtileloader_lightblockdatabase.txt',
        base_add=8818604,
        base_literal=8818644,
        boundary='ARM.exidx end 0x00868fd8 (listing bound); next ObjC IMP 0x00868fd8 WorldTileLoader -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x868fd0: (17161580, 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase', 252),
        },
        classes={},
        instructions=[(8818580, 'sub sp, sp, 0xc'), (8818644, 'rsbseq r6, pc, r0, asr 22')],
        calls=[],
        branches=[],
        semantics=('lightBlockDatabase is an atomic getter: `dmb ish` then `r0 = *(self + OFF)` where OFF is the\nivar cell 0x00868fd0 (lightBlockDatabase). No autorelease, no retain, no nil-check - the released-read\n(barrier-before-load) convention the compiler emits for an object-typed ivar read.\n'),
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
        'batch': 'WorldTileLoader closure batch (E18): dealloc (15 objc_msgSend(release) dispatches, six __wrap_free C-buffer frees, objc_msgSendSuper2(super, dealloc)), .cxx_construct (no-op stub) and fourteen atomic/plain accessors (getters + one char setter + two objc_copyStruct struct getters); 16 bodies',
        'claim': ('a static bounded-body map with per-instruction anchors; the field meanings of the '
                  'copied structs, the reference-counting semantics behind the objc_msgSend(release) '
                  'dispatches and any reader/writer of the six freed buffers outside this class are '
                  'outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'wtl_closure.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale wtl_closure.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
