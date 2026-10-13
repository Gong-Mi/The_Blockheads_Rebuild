#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld draw & reload cluster (E25).

The DynamicWorld draw and reload cluster: the packed in-front object draw, the
names/labels pass, and the three macro-tile keeper reload contracts (quads,
static cylinders, static geometry) with their free/count/malloc/fill phases:
1 body, 5368 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DRAW_RELOAD.md for the prose and boundaries.
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
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl sym.imp.__wrap_exit': 0x001c2fd8,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wtl_drawinfrontofblocksobj',
        method='DynamicWorld -[drawInFrontOfBlocksObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        types='v160@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152i156',
        start=9252280,
        end=9258848,
        disasm='disasm_worldtileloader_drawinfrontofblocksobjects_projectionmat.txt',
        base_add=9253500,
        base_literal=9256440,
        boundary='ARM.exidx end 0x008d4760 (listing bound); next ObjC IMP 0x008d4760 DynamicWorld -[drawFreeBlocks:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:]',
        selectors={
                 0x8d3df4: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8d4750: (15216684, 'draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={},
        ivars={
                 0x8d3dec: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8d4740: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9252280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9252880, 'ldr r1, [0x008d3dec]'), (9253744, 'mov r0, sp'), (9254060, 'add r0, sp, 0x920'), (9255256, 'ldr r2, [0x008d4740]'), (9256480, 'add r2, r1, 0x168'), (9257668, 'add r2, r1, 0xc0'), (9258844, 'rsbseq fp, r8, r0, lsr pc')],
        calls=[(9254004, 'bl loc.imp.objc_msgSend'), (9254044, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9255188, 'bl loc.imp.objc_msgSend'), (9255228, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9256372, 'bl loc.imp.objc_msgSend'), (9256412, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9257572, 'bl loc.imp.objc_msgSend'), (9257612, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9258756, 'bl loc.imp.objc_msgSend'), (9258792, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9253172, 'beq', 9254060), (9254056, 'b', 9253084), (9254356, 'beq', 9255244), (9255240, 'b', 9254268), (9255540, 'beq', 9256444), (9256424, 'b', 9255452), (9256740, 'beq', 9257636), (9257624, 'b', 9256652), (9257928, 'beq', 9258808), (9258804, 'b', 9257844)],
        semantics=("drawInFrontOfBlocksObjects:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType: draws the in-front object families with the packed camera arguments. Prologue 0x008d2db8 (frame 0xa10, 16-aligned; base 0x105faf4; a local arena at sp+0x400 holds the iterator states). Arguments: the two matrices as floats plus the camera rectangle and hideUIType.\nStructure: a fixed sequence of member slices of the ffffe54c map is drawn one family at a time. Per slice: the iterator pair is set up (e.g. +0x240 @0x8d3010-0x8d30ac, +0x234 @0x8d34ac, +0x2d0 @0x8d3958, +0x168 @0x8d3e20, +0xc0 @0x8d42c4); the per-node loop gathers the camera/projection/modelView/hide args into the packed send frame (r0+0x0..0x8c; @0x8d3370-0x8d346c and siblings) with the dispatch slot resolved through the literal-pool pair 0xffe23538 + 0x78c870 / 0x78c3d0 / 0x78bf30 / 0x78ba80 (cells 0x8d3df4-0x8d3df8, 0x8d4750/0x8d4758); `objc_msgSend` runs per node (0x8d3474, 0x8d3914, 0x8d3db4, 0x8d4264) and the loop advances with `std::__1::__tree_next` (0x8d349c, 0x8d393c, 0x8d3ddc, 0x8d428c). Epilogue after the last slice's packed call.\nBoundary: the specific slice offsets (+0x2d0/+0x240/+0x234/+0x168/+0xc0) and the per-slice dispatch slots are read from the immediates; the drawn families' classes are outside this body.\n"),
    ),
    dict(
        name='wtl_drawnames_projectionma',
        method='DynamicWorld -[drawNames:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:drawLocalNames:]',
        types='v164@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76f140i144i148i152i156c160',
        start=9291444,
        end=9297016,
        disasm='disasm_worldtileloader_drawnames_projectionmatrix_modelviewmatr.txt',
        base_add=9291468,
        base_literal=9293296,
        boundary='ARM.exidx end 0x008ddc78 (listing bound); next ObjC IMP 0x008ddc78 DynamicWorld -[createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:]',
        selectors={
                 0x8dce00: (15216696, 'drawName:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
                 0x8ddc58: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ddc60: (15216696, 'drawName:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={
                 0x8ddc54: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8dcdfc: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
                 0x8ddc5c: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
                 0x8ddc68: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
                 0x8ddc70: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
        },
        classes={},
        instructions=[(9291444, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9292060, 'bl sym.imp.__wrap_glEnable'), (9292076, 'cmp r0, 8'), (9292108, 'ldr r1, [r2, r1, lsl 2]'), (9293260, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9293324, 'ldrsb r0, [lr, 0xff]'), (9294588, 'ldr r4, [0x008ddc68]'), (9297012, 'rsbseq r2, r8, r0, lsr 2')],
        calls=[(9292060, 'bl sym.imp.__wrap_glEnable'), (9293224, 'bl loc.imp.objc_msgSend'), (9293260, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9293436, 'bl sym.imp.memset'), (9293500, 'blx lr'), (9293604, 'bl sym.imp.objc_enumerationMutation'), (9294408, 'bl loc.imp.objc_msgSend'), (9294516, 'blx ip'), (9294648, 'bl sym.imp.memset'), (9294712, 'blx lr'), (9294816, 'bl sym.imp.objc_enumerationMutation'), (9295620, 'bl loc.imp.objc_msgSend'), (9295728, 'blx ip'), (9295856, 'bl sym.imp.memset'), (9295920, 'blx lr'), (9296024, 'bl sym.imp.objc_enumerationMutation'), (9296828, 'bl loc.imp.objc_msgSend'), (9296936, 'blx ip'), (9296968, 'bl sym.imp.__wrap_glDisable')],
        branches=[(9292080, 'bge', 9293320), (9292400, 'beq', 9293276), (9293272, 'b', 9292312), (9293276, 'b', 9293280), (9293292, 'b', 9292072), (9293332, 'beq', 9294548), (9293512, 'beq', 9294540), (9293596, 'beq', 9293608), (9294436, 'blo', 9293560), (9294536, 'bne', 9293560), (9294540, 'b', 9294544), (9294544, 'b', 9294548), (9294724, 'beq', 9295752), (9294808, 'beq', 9294820), (9295648, 'blo', 9294772), (9295748, 'bne', 9294772), (9295752, 'b', 9295756), (9295932, 'beq', 9296960), (9296016, 'beq', 9296028), (9296856, 'blo', 9295980), (9296956, 'bne', 9295980), (9296960, 'b', 9296964)],
        semantics=('drawNames:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:drawLocalNames: draws the floating names/labels. Prologue 0x008dc6b4 (frame 0x840, 16-aligned; base 0x105faf4). pinchScale on s0 ([fp,0x88] also carries a value used as s2).\nGL prep: `__wrap_glEnable(0xbe2)` (@0x8dc91c; 0xbe2 = GL_BLEND) plus a state byte written to [sp,0x6ff] (@0x8dc90c).\nFamily pass: `for i in 0..8` (cmp 8 @0x8dc92c) with the SWITCH jump table (cells 0x8dcdf4 0xffdeaf28 + 0x8dcdf8 0x7831a8 -> table @ 0x00E4AA1C, dispatch @0x8dc94c): per arm the ffffe54c map segment (12-byte stride) is iterated; per node the packed name-draw send (camera args + pinchScale float at r0+0x78 + hideUIType; dispatch slot ffe23544 via cells 0x8dce00/0x8dce04) runs and the loop advances with `std::__1::tree_next` (@0x8dcdcc).\nLocal names: the byte at [lr+0xff] (@0x8dce0c) gates the blockhead pass; when set, blockheads ffffe4f8 (cell 0x8ddc5c) are enumerated (@0x8dce3c) and per bh the packed local-name send runs (dispatch slot ffe23544 re-resolved via cells 0x8ddc60/0x8ddc64, @0x8dcf40-0x8dd248), then the ffffe4f4 pass (@0x8dd2fc-0x8dd4f8) and the ffffe4f0 pass mirror the same shape. Epilogue after the loops.\n'),
    ),
    dict(
        name='wtl_reloaddynamicobjectqua',
        method='DynamicWorld -[reloadDynamicObjectQuadsForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9435324,
        end=9439168,
        disasm='disasm_worldtileloader_reloaddynamicobjectquadsformacrotile_.txt',
        base_add=9435344,
        base_literal=9439164,
        boundary='ARM.exidx end 0x009007c0 (listing bound); next ObjC IMP 0x009007c0 DynamicWorld -[reloadDynamicObjectItemQuadsForMacroTile:]',
        selectors={
                 0x900774: (15215864, 'count'),
                 0x900778: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x90077c: (15217236, 'staticGeometryDrawQuadCountForMacroPos:'),
                 0x900784: (15217240, 'staticGeometryForegroundDrawQuadCountForMacroPos:'),
                 0x900788: (15217248, 'addDrawQuadData:fromIndex:forMacroPos:'),
                 0x900790: (15217252, 'addForegroundDrawQuadData:fromIndex:forMacroPos:'),
                 0x9007a4: (15217244, 'macroTileOwner'),
        },
        imports={
                 0x900770: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9007a0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9435324, 'push {r4, r5, r6, sl, fp, lr}'), (9435420, 'ldr r0, [r0, 0x1a4]'), (9435580, 'blx r2'), (9436132, 'cmp r0, 2'), (9436164, 'ldr r1, [r2, r1, lsl 2]'), (9436792, 'bl sym.imp.__wrap_malloc'), (9437136, 'ldr lr, [0x0090078c]'), (9439164, 'rsbseq r0, r6, ip, lsl r2')],
        calls=[(9435424, 'bl sym.imp.__wrap_free'), (9435492, 'bl sym.imp.__wrap_free'), (9435580, 'blx r2'), (9435620, 'bl sym.makeIntpair_int__int_'), (9435704, 'bl sym.imp.memset'), (9435756, 'blx lr'), (9435856, 'bl sym.imp.objc_enumerationMutation'), (9435924, 'bl loc.imp.objc_msgSend'), (9435980, 'bl loc.imp.objc_msgSend'), (9436092, 'blx ip'), (9436532, 'blx r2'), (9436608, 'bl loc.imp.objc_msgSend'), (9436668, 'bl loc.imp.objc_msgSend'), (9436720, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9436792, 'bl sym.imp.__wrap_malloc'), (9436836, 'bl sym.imp.__wrap_exit'), (9436928, 'bl sym.imp.memset'), (9436980, 'blx lr'), (9437080, 'bl sym.imp.objc_enumerationMutation'), (9437168, 'bl loc.imp.objc_msgSend'), (9437280, 'blx ip'), (9437720, 'blx r2'), (9437812, 'bl loc.imp.objc_msgSend'), (9437864, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9437952, 'bl sym.imp.__wrap_malloc'), (9437996, 'bl sym.imp.__wrap_exit'), (9438088, 'bl sym.imp.memset'), (9438140, 'blx lr'), (9438240, 'bl sym.imp.objc_enumerationMutation'), (9438328, 'bl loc.imp.objc_msgSend'), (9438440, 'blx ip'), (9438880, 'blx r2'), (9438972, 'bl loc.imp.objc_msgSend'), (9439024, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9435380, 'bne', 9435388), (9435384, 'b', 9439080), (9435408, 'beq', 9435456), (9435476, 'beq', 9435524), (9435588, 'bls', 9439080), (9435768, 'beq', 9436116), (9435848, 'beq', 9435860), (9436020, 'blo', 9435812), (9436112, 'bne', 9435812), (9436116, 'b', 9436120), (9436136, 'bge', 9436756), (9436444, 'beq', 9436736), (9436544, 'beq', 9436684), (9436684, 'b', 9436688), (9436732, 'b', 9436360), (9436736, 'b', 9436740), (9436752, 'b', 9436128), (9436764, 'ble', 9437916), (9436828, 'bne', 9436840), (9436992, 'beq', 9437304), (9437072, 'beq', 9437084), (9437208, 'blo', 9437036), (9437300, 'bne', 9437036), (9437304, 'b', 9437308), (9437324, 'bge', 9437900), (9437632, 'beq', 9437880), (9437732, 'beq', 9437828), (9437828, 'b', 9437832), (9437876, 'b', 9437548), (9437880, 'b', 9437884), (9437896, 'b', 9437316), (9437924, 'ble', 9439076), (9437988, 'bne', 9438000), (9438152, 'beq', 9438464), (9438232, 'beq', 9438244), (9438368, 'blo', 9438196), (9438460, 'bne', 9438196), (9438464, 'b', 9438468), (9438484, 'bge', 9439060), (9438792, 'beq', 9439040), (9438892, 'beq', 9438988), (9438988, 'b', 9438992), (9439036, 'b', 9438708), (9439040, 'b', 9439044), (9439056, 'b', 9438476), (9439076, 'b', 9439080)],
        semantics=("reloadDynamicObjectQuadsForMacroTile: rebuilds one macro tile keeper's quad buffers. Prologue 0x008ff8bc (frame 0xb8+0x400; base 0x105faf4). Arguments: the keeper object (r0) and its macro tile object (r1); [r0+8] == 0 exits (0x8ff8f8).\nFree phase: `__wrap_free([tile+0x1a4])` + clear +0x1a4/+0x1a8 (@0x8ff918-0x8ff93c); `__wrap_free([tile+0x1b8])` + clear +0x1b8/+0x1bc (@0x8ff964-0x8ff980) - the keeper's two quad-cache pointer pairs.\nCount phase: the object collection at [r3+0xc] must be non-empty (cell 0x900774 ffe23204, @0x8ff9bc); the entity at [r0+8] is enumerated (@0x8ff9e8-0x8ffbc0): per item the quad counts are computed through the ffe23760 / ffe23764 calls (cells 0x90077c/0x900784) reading [item+8]. Then `for i in 0..2` (cmp 2 @0x8ffbe4) with the SWITCH jump table (cells 0x900798 0xffdb8640 + 0x90079c 0x75f5c4 -> table @ 0x00E18134, dispatch @0x8ffc04): the ffffe54c segments (cell 0x9007a0) are iterated adding the per-family counts (ffe23760/ffe23764 again, @0x8ffd8c-0x8ffe04); `std::__1::tree_next` advances (@0x8ffe30).\nAlloc phase: when the total > 0 (cmp @0x8ffe58) `__wrap_malloc(count * 2 * 4 * 0x60)` (@0x8ffe60-0x8ffe78: movw r0, 0x60; mul) is stored at [tile+0x1a4]; a NULL result calls `__wrap_exit(0)` (@0x8ffea4); then a second enumeration (@0x8ffea8-0x900040) fills the buffer through the ffe2376c call (cell 0x900788) per object. Epilogue 0x900768.\n"),
    ),
    dict(
        name='dyn_reload_cylin',
        method='DynamicWorld -[reloadDynamicObjectStaticCylindersForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9432128,
        end=9434076,
        disasm='disasm_worldtileloader_reloaddynamicobjectstaticcylindersformacrotile_.txt',
        base_add=9432144,
        base_literal=9434072,
        boundary='ARM.exidx end 0x008ff3dc (listing bound); next ObjC IMP 0x008ff3dc DynamicWorld -[reloadDodoEggQuadsForMacroTile:]',
        selectors={
                 0x8ff3c0: (15215864, 'count'),
                 0x8ff3c4: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8ff3c8: (15217216, 'staticGeometryCylinderCountTrans'),
                 0x8ff3cc: (15217212, 'staticGeometryCylinderCount'),
                 0x8ff3d0: (15217220, 'addCylinderData:fromIndex:'),
                 0x8ff3d4: (15217224, 'addCylinderDataTrans:fromIndex:'),
        },
        imports={
                 0x8ff3bc: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9432128, 'push {r4, r5, r6, sl, fp, lr}'), (9432224, 'bl sym.imp.__wrap_free'), (9432380, 'blx r2'), (9432708, 'blx r3'), (9432916, 'bl sym.imp.__wrap_malloc'), (9432960, 'bl sym.imp.__wrap_exit'), (9434072, 'invalid')],
        calls=[(9432224, 'bl sym.imp.__wrap_free'), (9432292, 'bl sym.imp.__wrap_free'), (9432380, 'blx r2'), (9432472, 'bl sym.imp.memset'), (9432524, 'blx lr'), (9432624, 'bl sym.imp.objc_enumerationMutation'), (9432708, 'blx r3'), (9432740, 'blx r2'), (9432852, 'blx ip'), (9432916, 'bl sym.imp.__wrap_malloc'), (9432960, 'bl sym.imp.__wrap_exit'), (9433052, 'bl sym.imp.memset'), (9433104, 'blx lr'), (9433204, 'bl sym.imp.objc_enumerationMutation'), (9433300, 'blx ip'), (9433412, 'blx ip'), (9433492, 'bl sym.imp.__wrap_malloc'), (9433536, 'bl sym.imp.__wrap_exit'), (9433628, 'bl sym.imp.memset'), (9433680, 'blx lr'), (9433780, 'bl sym.imp.objc_enumerationMutation'), (9433876, 'blx ip'), (9433988, 'blx ip')],
        branches=[(9432180, 'bne', 9432188), (9432184, 'b', 9434036), (9432208, 'beq', 9432256), (9432276, 'beq', 9432324), (9432388, 'bls', 9434036), (9432536, 'beq', 9432876), (9432616, 'beq', 9432628), (9432780, 'blo', 9432580), (9432872, 'bne', 9432580), (9432876, 'b', 9432880), (9432888, 'ble', 9433456), (9432952, 'bne', 9432964), (9433116, 'beq', 9433436), (9433196, 'beq', 9433208), (9433340, 'blo', 9433160), (9433432, 'bne', 9433160), (9433436, 'b', 9433440), (9433464, 'ble', 9434032), (9433528, 'bne', 9433540), (9433692, 'beq', 9434012), (9433772, 'beq', 9433784), (9433916, 'blo', 9433736), (9434008, 'bne', 9433736), (9434012, 'b', 9434016), (9434032, 'b', 9434036)],
        semantics=("reloadDynamicObjectStaticCylindersForMacroTile: rebuilds the static cylinder buffers. Prologue 0x008fec40 (frame 0x230; base 0x105faf4). Same contract shape as the quads reload with the cylinder slots: `__wrap_free([tile+0x1dc])` + clear +0x1dc/+0x1e0 (@0x8feca0-0x8fecbc); `__wrap_free([tile+0x1e4])` + clear +0x1e4/+0x1e8 (@0x8fece4-0x8fed00); the count gate at [r3+0xc] (cell 0x8ff3c0, @0x8fed3c); the entity enumeration computes counts via ffe2374c / ffe23748 (cells 0x8ff3c8/0x8ff3cc, @0x8fee84-0x8feea4); when total > 0 (cmp @0x8fef34): `__wrap_malloc(count * 2 * 4 * 0x240)` (@0x8fef3c-0x8fef54: movw r0, 0x240; mul) stored at [tile+0x1dc]; NULL -> `__wrap_exit(0)` (@0x8fef80); fill pass follows. The 0x240 stride vs the quads' 0x60 is the size difference between the cylinder and quad records.\n"),
    ),
    dict(
        name='dyn_reload_gem',
        method='DynamicWorld -[reloadDynamicObjectStaticGemometryForMacroTile:]',
        types='v12@0:4^{MacroTile=CCC^{PhysicalBlock}^{DrawBlock}@f}8',
        start=9430180,
        end=9432128,
        disasm='disasm_worldtileloader_reloaddynamicobjectstaticgemometryformacrotile_.txt',
        base_add=9430196,
        base_literal=9432124,
        boundary='ARM.exidx end 0x008fec40 (listing bound); next ObjC IMP 0x008fec40 DynamicWorld -[reloadDynamicObjectStaticCylindersForMacroTile:]',
        selectors={
                 0x8fec24: (15215864, 'count'),
                 0x8fec28: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8fec2c: (15217200, 'staticGeometryDrawCubeCountTrans'),
                 0x8fec30: (15217196, 'staticGeometryDrawCubeCount'),
                 0x8fec34: (15217204, 'addDrawCubeData:fromIndex:'),
                 0x8fec38: (15217208, 'addDrawCubeDataTrans:fromIndex:'),
        },
        imports={
                 0x8fec20: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9430180, 'push {r4, r5, r6, sl, fp, lr}'), (9430276, 'bl sym.imp.__wrap_free'), (9430432, 'blx r2'), (9430760, 'blx r3'), (9430968, 'bl sym.imp.__wrap_malloc'), (9431012, 'bl sym.imp.__wrap_exit'), (9432124, 'rsbseq r1, r6, r8, lsr r6')],
        calls=[(9430276, 'bl sym.imp.__wrap_free'), (9430344, 'bl sym.imp.__wrap_free'), (9430432, 'blx r2'), (9430524, 'bl sym.imp.memset'), (9430576, 'blx lr'), (9430676, 'bl sym.imp.objc_enumerationMutation'), (9430760, 'blx r3'), (9430792, 'blx r2'), (9430904, 'blx ip'), (9430968, 'bl sym.imp.__wrap_malloc'), (9431012, 'bl sym.imp.__wrap_exit'), (9431104, 'bl sym.imp.memset'), (9431156, 'blx lr'), (9431256, 'bl sym.imp.objc_enumerationMutation'), (9431352, 'blx ip'), (9431464, 'blx ip'), (9431544, 'bl sym.imp.__wrap_malloc'), (9431588, 'bl sym.imp.__wrap_exit'), (9431680, 'bl sym.imp.memset'), (9431732, 'blx lr'), (9431832, 'bl sym.imp.objc_enumerationMutation'), (9431928, 'blx ip'), (9432040, 'blx ip')],
        branches=[(9430232, 'bne', 9430240), (9430236, 'b', 9432088), (9430260, 'beq', 9430308), (9430328, 'beq', 9430376), (9430440, 'bls', 9432088), (9430588, 'beq', 9430928), (9430668, 'beq', 9430680), (9430832, 'blo', 9430632), (9430924, 'bne', 9430632), (9430928, 'b', 9430932), (9430940, 'ble', 9431508), (9431004, 'bne', 9431016), (9431168, 'beq', 9431488), (9431248, 'beq', 9431260), (9431392, 'blo', 9431212), (9431484, 'bne', 9431212), (9431488, 'b', 9431492), (9431516, 'ble', 9432084), (9431580, 'bne', 9431592), (9431744, 'beq', 9432064), (9431824, 'beq', 9431836), (9431968, 'blo', 9431788), (9432060, 'bne', 9431788), (9432064, 'b', 9432068), (9432084, 'b', 9432088)],
        semantics=("reloadDynamicObjectStaticGemometryForMacroTile: rebuilds the static geometry buffers. Prologue 0x008fe4a4 (frame 0x230; base 0x105faf4). Same contract shape with the geometry slots: `__wrap_free([tile+0x190])` + clear +0x190/+0x194 (@0x8fe504-0x8fe520); `__wrap_free([tile+0x198])` + clear +0x198/+0x19c (@0x8fe548-0x8fe564); the count gate at [r3+0xc] (cell 0x8fec24, @0x8fe5a0); counts via ffe2373c / ffe23738 (cells 0x8fec2c/0x8fec30, @0x8fe6e8-0x8fe708); total > 0 -> `__wrap_malloc(count * 2 * 4 * 0x240)` (@0x8fe7a0-0x8fe7b8) at [tile+0x190]; NULL -> `__wrap_exit(0)` (@0x8fe7e4); fill pass follows. The 'Gemometry' spelling is the original selector's.\n"),
    ),
    dict(
        name='wtl_drawblockheadboxes_pro',
        method='DynamicWorld -[drawBlockheadBoxes:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v160@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76f140i144i148i152i156',
        start=9289852,
        end=9291444,
        disasm='disasm_worldtileloader_drawblockheadboxes_projectionmatrix_mode.txt',
        base_add=9289872,
        base_literal=9291440,
        boundary='ARM.exidx end 0x008dc6b4 (listing bound); next ObjC IMP 0x008dc6b4 DynamicWorld -[drawNames:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:drawLocalNames:]',
        selectors={
                 0x8dc69c: (15215864, 'count'),
                 0x8dc6a8: (15215808, 'objectAtIndex:'),
                 0x8dc6ac: (15216692, 'drawBoxes:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:'),
        },
        imports={
                 0x8dc698: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8dc694: (17162320, 'OBJC_IVAR_$_DynamicWorld.activeBlockheadIndex', 7360),
                 0x8dc6a0: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9289852, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9290468, 'ldr r0, [r0]'), (9290580, 'mov r0, r1'), (9290892, 'ldr lr, [lr, r4]'), (9291132, 'mov r0, sp'), (9291380, 'str r6, [r0, 0x7c]'), (9291440, 'rsbseq r3, r8, ip, asr sl')],
        calls=[(9290492, 'blx r2'), (9290600, 'bl loc.imp.objc_msgSend'), (9291400, 'bl loc.imp.objc_msgSend')],
        branches=[(9290520, 'bls', 9291404)],
        semantics=('drawBlockheadBoxes:projectionMatrix:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld: draws the blockhead selection boxes. Prologue 0x008dc07c (frame 0x2b0, 16-aligned; base 0x105faf4). pinchScale on s0 with [fp,0x88] on s2.\nPass: the count/lookup chain (cells ffffe55c 0x8dc694, ffffe4f8 0x8dc6a0, ffe23204 0x8dc69c) checks the blockheads collection; the first blockhead is taken when the count > 0 (@0x8dc2e4-0x8dc318) and the specialized box-draw call runs with the two blockhead fields (ffffe55c + ffe231cc cells 0x8dc694/0x8dc6a8, @0x8dc354-0x8dc368 objc_msgSend with the packed (r0,r1,r2) shape) followed by the full packed send frame (camera args + pinchScale s2 at r0+0x80 + s0 fields, dispatch slot ffe23540 cell 0x8dc6ac, @0x8dc57c-0x8dc674). Non-positive counts exit at 0x8dc68c.\n'),
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
        'batch': 'DynamicWorld draw & reload cluster (E25): drawInFrontOfBlocksObjects:..., drawNames:..., reloadDynamicObjectQuadsForMacroTile:, reloadDynamicObjectStaticCylindersForMacroTile:, reloadDynamicObjectStaticGemometryForMacroTile: and drawBlockheadBoxes:...; 6 bodies',
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
                        default=NATIVE / 'draw_reload.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale draw_reload.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
