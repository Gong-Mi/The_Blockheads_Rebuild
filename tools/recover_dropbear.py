#!/usr/bin/env python3
"""Hash-gated recovery of the DropBear (E145).

DropBear lands: the batch sweeps dropbear surface:
33 bodies, 14274 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DROPBEAR.md for the prose and boundaries.
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
    'bl 0x79d29c': 0x0079d29c,
    'bl 0x7aa2f0': 0x007aa2f0,
    'bl 0x7aa364': 0x007aa364,
    'bl 0x7aa54c': 0x007aa54c,
    'bl 0x7aa8e4': 0x007aa8e4,
    'bl 0x7aac7c': 0x007aac7c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2__': 0x004d5170,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator_float_': 0x004d0368,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.cosf': 0x001c2b58,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsClimable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_': 0x00a1311c,
}

SPECS = [
    dict(
        name='db_00',
        method='DropBear -[.cxx_construct]',
        types='@8@0:4',
        start=8070328,
        end=8071076,
        disasm='disasm_worldtileloader_db_00.txt',
        base_add=8070344,
        base_literal=8070404,
        boundary='ARM.exidx end 0x007b27a4 (listing bound); next ObjC IMP 0x007b27d4 WHThreadSafeQueue -[init]',
        selectors={},
        imports={},
        ivars={
                 0x7b2500: (17160296, 'OBJC_IVAR_$_DropBear.attackOffset', 328),
        },
        classes={},
        instructions=[(8070328, 'push {fp, lr}'), (8071072, 'cmnmi pc, 0')],
        calls=[(8070376, 'bl method.Vector2.Vector2__'), (8070476, 'bl sym.imp.cosf'), (8070496, 'bl sym.imp.sinf'), (8070684, 'bl sym.imp.cosf'), (8070704, 'bl sym.imp.sinf'), (8070908, 'bl sym.clamp_float__float__float_'), (8070952, 'bl sym.clamp_float__float__float_'), (8070996, 'bl sym.clamp_float__float__float_'), (8071040, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=('[DropBear -[.cxx_construct]] (imp 0x007b24b8, 187w): -[.cxx_construct] (0x7b24b8, 187w): real method = 18w: calls C++ `Vector2::Vector2()` on self.attackOffset@328 (offset cell 0x7b2500 -> slot 0x0105d868) then returns self - attackOffset is the only non-POD member. The rest of the listing span (to the exidx bound 0x7b27a4) holds 3 DropBear TU-local static helpers placed right after the ctor: rotX mat4 builder @0x7b2508 (cosf+sinf -> {1,0,0,0, 0,cos,sin,0, 0,-sin,cos,0, 0,0,0,1}), rotY mat4 builder @0x7b25d8 ({cos,0,-sin,0, 0,1,0,0, sin,0,cos,0, 0,0,0,1}, 0.0f filler), RGBA packer @0x7b26a8 (4 float args -> clamp(c*255,0,255) via clamp_float x4 + pool 0x437f0000, vcvt.s32.f32, strb x4, returns packed u32)..\n'),
    ),
    dict(
        name='db_01',
        method='DropBear -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=8068844,
        end=8069036,
        disasm='disasm_worldtileloader_db_01.txt',
        base_add=8068860,
        base_literal=8069032,
        boundary='ARM.exidx end 0x007b1fac (listing bound); next ObjC IMP 0x007b1fac DropBear -[reactToBeingFed]',
        selectors={
                 0x7b1fa4: (15209544, 'release'),
        },
        imports={
                 0x7b1fa0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7b1f9c: (17160276, 'OBJC_IVAR_$_DropBear.attackBlockhead', 324),
        },
        classes={},
        instructions=[(8068844, 'push {r4, sl, fp, lr}'), (8069032, 'strdeq sp, lr, [sl], r0')],
        calls=[(8068984, 'blx r3')],
        branches=[(8068912, 'bne', 8069012)],
        semantics=('[DropBear -[blockheadUnloaded:]] (imp 0x007b1eec, 48w): -[blockheadUnloaded:] (0x7b1eec, 48w): `if (arg == self.attackBlockhead@324) { [self.attackBlockhead release]; self.attackBlockhead = nil; }` - no [super blockheadUnloaded:] call (same shape as ClownFish). attackBlockhead@324 is the blockhead being dropped on / attacked (pair with db_09 drop-start and db_15)..\n'),
    ),
    dict(
        name='db_02',
        method='DropBear -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=8069636,
        end=8069804,
        disasm='disasm_worldtileloader_db_02.txt',
        base_add=8069652,
        base_literal=8069800,
        boundary='ARM.exidx end 0x007b22ac (listing bound); next ObjC IMP 0x007b22ac DropBear -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={
                 0x7b22a4: (15209692, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x7b22a0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(8069636, 'push {fp, lr}'), (8069800, 'ldrdeq sp, lr, [sl], r8')],
        calls=[(8069740, 'blx r3')],
        branches=[(8069688, 'bne', 8069772), (8069752, 'beq', 8069768), (8069764, 'b', 8069780), (8069768, 'b', 8069772)],
        semantics=('[DropBear -[canBeCapturedByBlockhead:withItemType:]] (imp 0x007b2204, 42w): -[canBeCapturedByBlockhead:withItemType:] (0x7b2204, 42w): `return itemType == 0x12e(302) ? (BOOL)[self belongsToPlayerWithBlockhead:bh] : NO` - single gate; no inline tamed check (the belongsToPlayerWithBlockhead: call is the whole ownership test)..\n'),
    ),
    dict(
        name='db_03',
        method='DropBear -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=8069804,
        end=8070300,
        disasm='disasm_worldtileloader_db_03.txt',
        base_add=8069820,
        base_literal=8070296,
        boundary='ARM.exidx end 0x007b249c (listing bound); next ObjC IMP 0x007b249c DropBear -[ridableWhenTamed]',
        selectors={
                 0x7b247c: (15209776, 'tamed'),
                 0x7b2484: (15209716, 'stringWithFormat:'),
                 0x7b2488: (15209780, 'speciesName'),
                 0x7b2490: (15209692, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x7b2478: (17151904, 'objc_msgSend'),
                 0x7b2480: (16320984, '__CFConstantStringClassReference'),
                 0x7b2494: (16320968, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0x7b248c: (15247048, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(8069804, 'push {r4, r5, fp, lr}'), (8070296, 'addeq sp, sl, r0, lsr r8')],
        calls=[(8069900, 'blx r2'), (8069964, 'blx r3'), (8070060, 'blx r2'), (8070096, 'blx ip'), (8070192, 'blx r2'), (8070228, 'blx ip')],
        branches=[(8069856, 'bne', 8070244), (8069912, 'beq', 8070112), (8069976, 'bne', 8070108), (8070104, 'b', 8070252), (8070108, 'b', 8070240), (8070236, 'b', 8070252), (8070240, 'b', 8070244)],
        semantics=('[DropBear -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x007b22ac, 124w): -[cantBeCapturedTipStringForBlockhead:withItemType:] (0x7b22ac, 124w): itemType != 0x12e -> nil; if (![self tamed]) -> [NSString stringWithFormat:@`%@S MUST BE TAMED\\nBEFORE YOU CAN CAPTURE THEM` (CFString @0xF909D8), [self speciesName]]; if tamed and owned by bh -> nil; else -> @`THAT %@ BELONGS TO\\nSOMEONE ELSE` (@0xF909C8) + speciesName. Same tamed / belongsToPlayer pair as ClownFish..\n'),
    ),
    dict(
        name='db_04',
        method='DropBear -[captureRequiredItemType]',
        types='i8@0:4',
        start=7981108,
        end=7981136,
        disasm='disasm_worldtileloader_db_04.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c89c; body trimmed at the next IMP 0x0079c850 DropBear -[getNamesArray]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7981108, 'sub sp, sp, 8'), (7981132, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[captureRequiredItemType]] (imp 0x0079c834, 7w): -[captureRequiredItemType] (0x79c834, 7w): returns 0x12e (302) - items required to capture a DropBear..\n'),
    ),
    dict(
        name='db_05',
        method='DropBear -[capturedItemType]',
        types='i8@0:4',
        start=7981080,
        end=7981108,
        disasm='disasm_worldtileloader_db_05.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c89c; body trimmed at the next IMP 0x0079c834 DropBear -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7981080, 'sub sp, sp, 8'), (7981104, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[capturedItemType]] (imp 0x0079c818, 7w): -[capturedItemType] (0x79c818, 7w): returns 0x146 (326) - the item produced when captured..\n'),
    ),
    dict(
        name='db_06',
        method='DropBear -[creationDataStructSize]',
        types='L8@0:4',
        start=7991216,
        end=7991244,
        disasm='disasm_worldtileloader_db_06.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079efcc (listing bound); next ObjC IMP 0x0079efcc DropBear -[remoteUpdate:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7991216, 'sub sp, sp, 8'), (7991240, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[creationDataStructSize]] (imp 0x0079efb0, 7w): -[creationDataStructSize] (0x79efb0, 7w): returns 0x78 (120) - matches the 0x78 creation blob of db_07..\n'),
    ),
    dict(
        name='db_07',
        method='DropBear -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=7988284,
        end=7988808,
        disasm='disasm_worldtileloader_db_07.txt',
        base_add=7988300,
        base_literal=7988804,
        boundary='ARM.exidx end 0x0079e648 (listing bound); next ObjC IMP 0x0079e648 DropBear -[updateNetDataForClient:]',
        selectors={
                 0x79e62c: (15209576, 'npcCreationNetDataForClient:'),
                 0x79e630: (15209580, 'dropBearUpdateNetDataForClient:'),
                 0x79e638: (15209588, 'appendNPCCreationDataToData:'),
                 0x79e63c: (15209584, 'dataWithBytes:length:'),
        },
        imports={
                 0x79e634: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x79e640: (15247040, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(7988284, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7988804, 'addeq r1, ip, r0, lsr 13')],
        calls=[(7988388, 'bl loc.imp.objc_msgSend_stret'), (7988424, 'bl sym.imp.memset'), (7988480, 'bl sym.imp.memcpy'), (7988552, 'bl loc.imp.objc_msgSend_stret'), (7988588, 'bl sym.imp.memset'), (7988692, 'bl sym.imp.memcpy'), (7988732, 'blx ip'), (7988760, 'blx r3')],
        branches=[(7988368, 'beq', 7988396), (7988392, 'b', 7988428), (7988532, 'beq', 7988560), (7988556, 'b', 7988592)],
        semantics=('[DropBear -[creationNetDataForClient:]] (imp 0x0079e43c, 131w): -[creationNetDataForClient:] (0x79e43c, 131w): builds the 0x78-byte creation blob = npcCreationNetDataForClient (0x48B sret, O0 nil-guard memset 0x48) at +0x00 plus dropBearUpdateNetDataForClient (0x28B sret, nil-guard memset 0x28) at +0x48 (memcpy of both scratches); returns [self appendNPCCreationDataToData:[NSData dataWithBytes:blob length:0x78]]. 0x48+0x28=0x78 pinned twice..\n'),
    ),
    dict(
        name='db_08',
        method='DropBear -[dealloc]',
        types='v8@0:4',
        start=7989044,
        end=7989620,
        disasm='disasm_worldtileloader_db_08.txt',
        base_add=7989060,
        base_literal=7989616,
        boundary='ARM.exidx end 0x0079e974 (listing bound); next ObjC IMP 0x0079e974 DropBear -[doRemoteUpdate:]',
        selectors={
                 0x79e940: (15209592, 'dealloc'),
                 0x79e94c: (15209544, 'release'),
        },
        imports={
                 0x79e93c: (17151900, 'objc_msgSendSuper2'),
                 0x79e948: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x79e950: (17160276, 'OBJC_IVAR_$_DropBear.attackBlockhead', 324),
                 0x79e954: (17160184, 'OBJC_IVAR_$_DropBear.armCube', 260),
                 0x79e958: (17160180, 'OBJC_IVAR_$_DropBear.legCube', 256),
                 0x79e95c: (17160188, 'OBJC_IVAR_$_DropBear.eyeCube', 252),
                 0x79e960: (17160192, 'OBJC_IVAR_$_DropBear.snoutCube', 248),
                 0x79e964: (17160196, 'OBJC_IVAR_$_DropBear.headCube', 244),
                 0x79e968: (17160200, 'OBJC_IVAR_$_DropBear.backBodyCube', 240),
                 0x79e96c: (17160204, 'OBJC_IVAR_$_DropBear.frontBodyCube', 236),
        },
        classes={
                 0x79e944: (15252796, 'OBJC_CLASS_$_DropBear'),
        },
        instructions=[(7989044, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7989616, 'addeq r1, ip, r8, lsr 7')],
        calls=[(7989260, 'blx r5'), (7989296, 'blx r3'), (7989332, 'blx r3'), (7989368, 'blx r3'), (7989404, 'blx r3'), (7989440, 'blx r3'), (7989476, 'blx r3'), (7989512, 'blx r3'), (7989552, 'blx r2')],
        branches=[],
        semantics=('[DropBear -[dealloc]] (imp 0x0079e734, 144w): -[dealloc] (0x79e734, 144w): releases the 7 DrawCubes in order frontBodyCube@236, backBodyCube@240, headCube@244, snoutCube@248, eyeCube@252, legCube@256, armCube@260; then releases attackBlockhead@324 (nil-safe release); then [super dealloc] via objc_msgSendSuper2. shader@208 and the 6 textures are NOT released (cache-owned) - same policy as the other NPC animals..\n'),
    ),
    dict(
        name='db_09',
        method='DropBear -[doRemoteUpdate:]',
        types='v48@0:4{DropBearUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIsCC[4C]}8',
        start=7989620,
        end=7990812,
        disasm='disasm_worldtileloader_db_09.txt',
        base_add=7989636,
        base_literal=7990808,
        boundary='ARM.exidx end 0x0079ee1c (listing bound); next ObjC IMP 0x0079ee1c DropBear -[remoteCreationDataUpdate:]',
        selectors={
                 0x79edc0: (15209596, 'isClient'),
                 0x79ee08: (15209600, 'instance'),
                 0x79ee0c: (15209604, 'multiSoundNamed:'),
                 0x79ee14: (15209608, 'playAtPosition:'),
        },
        imports={
                 0x79edbc: (17151904, 'objc_msgSend'),
                 0x79ee10: (16320872, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x79edc4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x79edc8: (17160280, 'OBJC_IVAR_$_DropBear.currentNetQueueSize', 368),
                 0x79edcc: (17160264, 'OBJC_IVAR_$_DropBear.nextOnGround', 420),
                 0x79edd0: (17160268, 'OBJC_IVAR_$_DropBear.nextToSquare', 372),
                 0x79eddc: (17160272, 'OBJC_IVAR_$_DropBear.nextWalkSpeed', 404),
                 0x79ede0: (17160240, 'OBJC_IVAR_$_DropBear.dropping', 308),
                 0x79ede4: (17160252, 'OBJC_IVAR_$_DropBear.onGround', 344),
                 0x79ede8: (17160164, 'OBJC_IVAR_$_DropBear.fromSquare', 284),
                 0x79edf0: (17160176, 'OBJC_IVAR_$_DropBear.walkSpeed', 276),
                 0x79edf4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x79edf8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x79edfc: (17160256, 'OBJC_IVAR_$_DropBear.dropSpeed', 312),
                 0x79ee00: (17160248, 'OBJC_IVAR_$_DropBear.dropPos', 348),
        },
        classes={
                 0x79ee04: (15247044, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(7989620, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7990808, 'addeq r1, ip, r8, ror 2')],
        calls=[(7989808, 'blx lr'), (7990016, 'bl sym.makeIntpair_int__int_'), (7990324, 'bl sym.makeIntpair_int__int_'), (7990492, 'bl method.Vector2.operator_float__'), (7990624, 'bl loc.imp.objc_msgSend'), (7990648, 'bl loc.imp.objc_msgSend'), (7990700, 'bl loc.imp.objc_msgSend')],
        branches=[(7989820, 'beq', 7990708), (7989876, 'blt', 7989916), (7990168, 'beq', 7990704), (7990204, 'bne', 7990704), (7990240, 'bne', 7990704), (7990252, 'bne', 7990704), (7990704, 'b', 7990708)],
        semantics=('[DropBear -[doRemoteUpdate:]] (imp 0x0079e974, 298w): -[doRemoteUpdate:] (0x79e974, 298w): struct passed by value - w0/w1 arrive in r2/r3 and w2..w9 on the stack ([fp+8..fp+0x24]); same AAPCS split as ClownFish. `if (![self.dynamicWorld isClient]) return;` - server side is a no-op. CLIENT: size = self.currentNetQueueSize@368; `if (size >= 4) self.currentNetQueueSize = size = 3;` then push into the 4-slot ring: nextToSquare@372[size] = makeIntpair(w6, w7) (toSquare), nextWalkSpeed@404[size] = (float)(s16)w8 / 255.0f (pool 0x79edd8 = 0x437f0000), nextOnGround@420[size] = w8.byte3 (onGround byte), currentNetQueueSize = size + 1. DROP-START special block, entered iff (w8.dropping != 0 && !self.dropping@308 && !self.onGround@344 && !w8.onGround): self.toSquare = makeIntpair(w6, w7); self.walkSpeed@276 = (s16)w8 / 255.0f; self.currentNetQueueSize = 0 (flush queue); self.floatPos.x = self.pos.x + 5.0f; self.dropping = 1; self.dropSpeed@312 = 10.0f (0x41200000); self.dropPos@348 = self.pos (intpair copy); then [[MJSoundManager instance] multiSoundNamed:@`dropbearddrop.wav` (@0xF90968)] playAtPosition:self.floatPos. Same 4-slot ring design as ClownFish doRemoteUpdate but the third parallel array is nextOnGround (char[4]) instead of movementDirection, and the tree-drop start is handled locally on the receiving client..\n'),
    ),
    dict(
        name='db_10',
        method='DropBear -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=7991648,
        end=8037104,
        disasm='disasm_worldtileloader_db_10.txt',
        base_add=7991696,
        base_literal=7995424,
        boundary='ARM.exidx end 0x007aa2f0 (listing bound); next ObjC IMP 0x007ab240 DropBear -[update:accurateDT:isSimulation:]',
        selectors={
                 0x7a0400: (15209624, 'worldWidthMacro'),
                 0x7a0438: (15209628, 'macroTiles'),
                 0x7a4e14: (15209632, 'program'),
                 0x7a4e1c: (15209528, 'intValue'),
                 0x7a4e20: (15209640, 'objectAtIndex:'),
                 0x7a4e24: (15209636, 'uniformLocations'),
                 0x7a4e28: (15209644, 'dayColor'),
                 0x7a4e44: (15209648, 'name'),
                 0x7a4e4c: (15209652, 'draw'),
                 0x7aa2d0: (15209528, 'intValue'),
                 0x7aa2d4: (15209640, 'objectAtIndex:'),
                 0x7aa2d8: (15209636, 'uniformLocations'),
                 0x7aa2e0: (15209652, 'draw'),
                 0x7aa2e8: (15209648, 'name'),
        },
        imports={
                 0x7a0434: (17151904, 'objc_msgSend'),
                 0x7a4e10: (17151904, 'objc_msgSend'),
                 0x7aa2cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7a0384: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x7a03fc: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7a0420: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7a043c: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
                 0x7a0440: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x7a0444: (17160176, 'OBJC_IVAR_$_DropBear.walkSpeed', 276),
                 0x7a0448: (17160280, 'OBJC_IVAR_$_DropBear.currentNetQueueSize', 368),
                 0x7a044c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7a0450: (17160284, 'OBJC_IVAR_$_DropBear.walkTimer', 272),
                 0x7a0454: (17160288, 'OBJC_IVAR_$_DropBear.attacking', 316),
                 0x7a0458: (17160292, 'OBJC_IVAR_$_DropBear.attackFraction', 320),
                 0x7a045c: (17160296, 'OBJC_IVAR_$_DropBear.attackOffset', 328),
                 0x7a0464: (17160164, 'OBJC_IVAR_$_DropBear.fromSquare', 284),
                 0x7a0468: (17160160, 'OBJC_IVAR_$_DropBear.toSquare', 292),
                 0x7a046c: (17160172, 'OBJC_IVAR_$_DropBear.goalRotationType', 268),
                 0x7a0480: (17160168, 'OBJC_IVAR_$_DropBear.bodyRotation', 264),
                 0x7a1214: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7a1218: (17160168, 'OBJC_IVAR_$_DropBear.bodyRotation', 264),
                 0x7a1220: (17160156, 'OBJC_IVAR_$_DropBear.travelFraction', 280),
                 0x7a2618: (17160252, 'OBJC_IVAR_$_DropBear.onGround', 344),
                 0x7a261c: (17160240, 'OBJC_IVAR_$_DropBear.dropping', 308),
                 0x7a4a04: (17160164, 'OBJC_IVAR_$_DropBear.fromSquare', 284),
                 0x7a4a08: (17160160, 'OBJC_IVAR_$_DropBear.toSquare', 292),
                 0x7a4a0c: (17160284, 'OBJC_IVAR_$_DropBear.walkTimer', 272),
                 0x7a4e18: (17160232, 'OBJC_IVAR_$_DropBear.shader', 208),
                 0x7a4e2c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x7a4e40: (17160228, 'OBJC_IVAR_$_DropBear.bodyFrontTexture', 212),
                 0x7a4e48: (17160204, 'OBJC_IVAR_$_DropBear.frontBodyCube', 236),
                 0x7a6ec8: (17160224, 'OBJC_IVAR_$_DropBear.bodyBackTexture', 216),
                 0x7a6ecc: (17160200, 'OBJC_IVAR_$_DropBear.backBodyCube', 240),
                 0x7a6ed0: (17160220, 'OBJC_IVAR_$_DropBear.headTexture', 220),
                 0x7a6ed4: (17160196, 'OBJC_IVAR_$_DropBear.headCube', 244),
                 0x7a6ed8: (17160208, 'OBJC_IVAR_$_DropBear.snoutTexture', 232),
                 0x7a6edc: (17160192, 'OBJC_IVAR_$_DropBear.snoutCube', 248),
                 0x7a6ee0: (17160216, 'OBJC_IVAR_$_DropBear.legTexture', 224),
                 0x7a6ee4: (17160184, 'OBJC_IVAR_$_DropBear.armCube', 260),
                 0x7a987c: (17160180, 'OBJC_IVAR_$_DropBear.legCube', 256),
                 0x7aa2dc: (17160232, 'OBJC_IVAR_$_DropBear.shader', 208),
                 0x7aa2e4: (17160188, 'OBJC_IVAR_$_DropBear.eyeCube', 252),
                 0x7aa2ec: (17160212, 'OBJC_IVAR_$_DropBear.eyeTexture', 228),
        },
        classes={},
        instructions=[(7991648, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8037100, 'invalid')],
        calls=[(7992368, 'bl loc.imp.objc_msgSend'), (7992392, 'bl sym.imp.__aeabi_idiv'), (7992460, 'bl loc.imp.objc_msgSend'), (7992588, 'bl loc.imp.objc_msgSend'), (7992604, 'bl sym.imp.__aeabi_idiv'), (7992672, 'bl loc.imp.objc_msgSend'), (7992804, 'bl loc.imp.objc_msgSend'), (7992828, 'bl sym.imp.__aeabi_idiv'), (7992896, 'bl loc.imp.objc_msgSend'), (7993024, 'bl loc.imp.objc_msgSend'), (7993040, 'bl sym.imp.__aeabi_idiv'), (7993108, 'bl loc.imp.objc_msgSend'), (7993400, 'bl method.Vector2.operator_float__'), (7993464, 'bl loc.imp.objc_msgSend'), (7993488, 'bl sym.imp.__aeabi_idiv'), (7993588, 'bl loc.imp.objc_msgSend'), (7993624, 'bl method.Vector2.operator_float__'), (7993680, 'bl method.Vector2.operator_float__'), (7993748, 'bl loc.imp.objc_msgSend'), (7993764, 'bl sym.imp.__aeabi_idiv'), (7993864, 'bl loc.imp.objc_msgSend'), (7993900, 'bl method.Vector2.operator_float__'), (7994040, 'blx r2'), (7994088, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (7994776, 'bl method.Vector2.operator__Vector2_'), (7994864, 'bl method.Vector2.operator_float_'), (7994884, 'bl method.Vector2.operator_float_'), (7994916, 'bl method.Vector2.operator_Vector2_'), (7994948, 'bl method.Vector2.operator_float__'), (7994976, 'bl method.Vector2.operator_float__'), (7995032, 'bl 0x7aa2f0'), (7995044, 'bl method.Vector2.operator_float__'), (7995072, 'bl method.Vector2.operator_float__'), (7995128, 'bl 0x7aa2f0'), (7995308, 'bl method.Vector2.operator_float__'), (7995356, 'bl method.Vector2.operator_float__'), (7995560, 'bl method.Vector2.operator_float__'), (7995608, 'bl method.Vector2.operator_float__'), (7996948, 'bl sym.imp.sinf'), (7997088, 'bl sym.imp.sinf'), (7997476, 'bl 0x7aa364'), (7997968, 'bl 0x7aa364'), (7998488, 'bl 0x7aa54c'), (7998980, 'bl 0x7aa54c'), (7999468, 'bl 0x7aa8e4'), (7999960, 'bl 0x7aa8e4'), (7999996, 'bl sym.imp.memcpy'), (8000432, 'bl 0x7aa54c'), (8000932, 'bl 0x7aa54c'), (8001420, 'bl 0x7aa8e4'), (8001456, 'bl sym.imp.memcpy'), (8001920, 'bl 0x7aa54c'), (8002420, 'bl 0x7aa54c'), (8002908, 'bl 0x7aa8e4'), (8003476, 'bl 0x7aa364'), (8004004, 'bl 0x7aa364'), (8004548, 'bl 0x7aa8e4'), (8005088, 'bl 0x7aa8e4'), (8005124, 'bl sym.imp.memcpy'), (8005584, 'bl 0x7aa8e4'), (8006072, 'bl 0x7aa8e4'), (8006108, 'bl sym.imp.memcpy'), (8006492, 'bl 0x7aa364'), (8006844, 'bl 0x7aa8e4'), (8007360, 'bl 0x7aa364'), (8007752, 'bl 0x7aa364'), (8008120, 'bl 0x7aa364'), (8008492, 'bl 0x7aa364'), (8008864, 'bl 0x7aa364'), (8009248, 'bl 0x7aa364'), (8009620, 'bl 0x7aa364'), (8009972, 'bl 0x7aa8e4'), (8010452, 'bl 0x7aa8e4'), (8010516, 'bl sym.imp.memcpy'), (8010852, 'bl sym.imp.sinf'), (8011112, 'bl 0x7aa8e4'), (8011416, 'bl sym.imp.sinf'), (8011668, 'bl 0x7aa8e4'), (8012016, 'bl sym.imp.sinf'), (8012260, 'bl 0x7aa8e4'), (8012564, 'bl sym.imp.sinf'), (8012804, 'bl 0x7aa8e4'), (8012840, 'bl sym.imp.memcpy'), (8013204, 'bl 0x7aa8e4'), (8013684, 'bl 0x7aa8e4'), (8013720, 'bl sym.imp.memcpy'), (8013788, 'blx r2'), (8013792, 'bl sym.imp.__wrap_glUseProgram'), (8013924, 'blx r6'), (8013944, 'blx r3'), (8013960, 'blx r2'), (8013968, 'bl sym.imp.__wrap_glUniform1i'), (8013976, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (8014060, 'bl loc.imp.objc_msgSend_stret'), (8014100, 'bl sym.imp.memset'), (8014588, 'bl method.Vector.Vector_float__float__float_'), (8014608, 'bl method.Vector.operator_float__'), (8014680, 'bl method.Vector.operator_float__'), (8014732, 'bl method.Vector.operator_float__'), (8014804, 'bl method.Vector.operator_float__'), (8014856, 'bl method.Vector.operator_float__'), (8014928, 'bl method.Vector.operator_float__'), (8015000, 'bl method.Vector.Vector_float__float__float_'), (8015020, 'bl method.Vector.operator_float__'), (8015140, 'bl method.Vector.operator_float__'), (8015168, 'bl method.Vector.operator_float__'), (8015284, 'bl method.Vector.operator_float__'), (8015312, 'bl method.Vector.operator_float__'), (8015496, 'bl method.Vector.operator_float__'), (8015568, 'bl loc.imp.objc_msgSend'), (8015604, 'bl loc.imp.objc_msgSend'), (8015628, 'bl loc.imp.objc_msgSend'), (8015644, 'bl method.Vector.operator_float__'), (8015660, 'bl method.Vector.operator_float__'), (8015676, 'bl method.Vector.operator_float__'), (8015716, 'bl sym.imp.__wrap_glUniform4f'), (8016512, 'bl 0x7aac7c'), (8017308, 'bl 0x7aac7c'), (8017344, 'bl loc.imp.objc_msgSend'), (8017372, 'bl loc.imp.objc_msgSend'), (8017388, 'bl loc.imp.objc_msgSend'), (8017408, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8017444, 'bl loc.imp.objc_msgSend'), (8017472, 'bl loc.imp.objc_msgSend'), (8017488, 'bl loc.imp.objc_msgSend'), (8017504, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8017552, 'bl loc.imp.objc_msgSend'), (8017580, 'bl sym.imp.__wrap_glBindTexture'), (8017628, 'bl loc.imp.objc_msgSend'), (8018420, 'bl 0x7aac7c'), (8019344, 'bl 0x7aac7c'), (8019512, 'bl loc.imp.objc_msgSend'), (8019532, 'bl loc.imp.objc_msgSend'), (8019548, 'bl loc.imp.objc_msgSend'), (8019564, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8019600, 'bl loc.imp.objc_msgSend'), (8019620, 'bl loc.imp.objc_msgSend'), (8019636, 'bl loc.imp.objc_msgSend'), (8019652, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8019692, 'bl loc.imp.objc_msgSend'), (8019712, 'bl sym.imp.__wrap_glBindTexture'), (8019752, 'bl loc.imp.objc_msgSend'), (8020548, 'bl 0x7aac7c'), (8021472, 'bl 0x7aac7c'), (8021640, 'bl loc.imp.objc_msgSend'), (8021660, 'bl loc.imp.objc_msgSend'), (8021676, 'bl loc.imp.objc_msgSend'), (8021692, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8021728, 'bl loc.imp.objc_msgSend'), (8021748, 'bl loc.imp.objc_msgSend'), (8021764, 'bl loc.imp.objc_msgSend'), (8021780, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8021820, 'bl loc.imp.objc_msgSend'), (8021840, 'bl sym.imp.__wrap_glBindTexture'), (8021880, 'bl loc.imp.objc_msgSend'), (8022676, 'bl 0x7aac7c'), (8023600, 'bl 0x7aac7c'), (8023804, 'bl loc.imp.objc_msgSend'), (8023824, 'bl loc.imp.objc_msgSend'), (8023840, 'bl loc.imp.objc_msgSend'), (8023856, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8023892, 'bl loc.imp.objc_msgSend'), (8023912, 'bl loc.imp.objc_msgSend'), (8023928, 'bl loc.imp.objc_msgSend'), (8023944, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8023984, 'bl loc.imp.objc_msgSend'), (8024004, 'bl sym.imp.__wrap_glBindTexture'), (8024044, 'bl loc.imp.objc_msgSend'), (8024840, 'bl 0x7aac7c'), (8025764, 'bl 0x7aac7c'), (8025932, 'bl loc.imp.objc_msgSend'), (8025952, 'bl loc.imp.objc_msgSend'), (8025968, 'bl loc.imp.objc_msgSend'), (8025984, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8026020, 'bl loc.imp.objc_msgSend'), (8026040, 'bl loc.imp.objc_msgSend'), (8026056, 'bl loc.imp.objc_msgSend'), (8026072, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8026116, 'bl loc.imp.objc_msgSend'), (8026136, 'bl sym.imp.__wrap_glBindTexture'), (8026180, 'bl loc.imp.objc_msgSend'), (8026976, 'bl 0x7aac7c'), (8027900, 'bl 0x7aac7c'), (8028068, 'bl loc.imp.objc_msgSend'), (8028088, 'bl loc.imp.objc_msgSend'), (8028104, 'bl loc.imp.objc_msgSend'), (8028120, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8028156, 'bl loc.imp.objc_msgSend'), (8028176, 'bl loc.imp.objc_msgSend'), (8028192, 'bl loc.imp.objc_msgSend'), (8028208, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8028244, 'bl loc.imp.objc_msgSend'), (8029040, 'bl 0x7aac7c'), (8029964, 'bl 0x7aac7c'), (8030132, 'bl loc.imp.objc_msgSend'), (8030152, 'bl loc.imp.objc_msgSend'), (8030168, 'bl loc.imp.objc_msgSend'), (8030184, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8030220, 'bl loc.imp.objc_msgSend'), (8030240, 'bl loc.imp.objc_msgSend'), (8030256, 'bl loc.imp.objc_msgSend'), (8030272, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8030308, 'bl loc.imp.objc_msgSend'), (8030328, 'bl sym.imp.__wrap_glBindTexture'), (8030372, 'bl loc.imp.objc_msgSend'), (8031168, 'bl 0x7aac7c'), (8032092, 'bl 0x7aac7c'), (8032260, 'bl loc.imp.objc_msgSend'), (8032280, 'bl loc.imp.objc_msgSend'), (8032296, 'bl loc.imp.objc_msgSend'), (8032312, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8032348, 'bl loc.imp.objc_msgSend'), (8032368, 'bl loc.imp.objc_msgSend'), (8032384, 'bl loc.imp.objc_msgSend'), (8032400, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8032436, 'bl loc.imp.objc_msgSend'), (8032472, 'bl loc.imp.objc_msgSend'), (8032492, 'bl loc.imp.objc_msgSend'), (8032508, 'bl loc.imp.objc_msgSend'), (8032532, 'bl sym.imp.__wrap_glUniform4f'), (8033328, 'bl 0x7aac7c'), (8034252, 'bl 0x7aac7c'), (8034420, 'bl loc.imp.objc_msgSend'), (8034448, 'bl loc.imp.objc_msgSend'), (8034464, 'bl loc.imp.objc_msgSend'), (8034480, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8034516, 'bl loc.imp.objc_msgSend'), (8034536, 'bl loc.imp.objc_msgSend'), (8034552, 'bl loc.imp.objc_msgSend'), (8034568, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8034608, 'bl loc.imp.objc_msgSend'), (8034628, 'bl sym.imp.__wrap_glBindTexture'), (8034668, 'bl loc.imp.objc_msgSend'), (8035464, 'bl 0x7aac7c'), (8036384, 'bl 0x7aac7c'), (8036544, 'bl sym.imp.memcpy'), (8036592, 'blx ip'), (8036612, 'blx r3'), (8036628, 'blx r2'), (8036660, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8036800, 'blx r3'), (8036820, 'blx r3'), (8036836, 'blx r2'), (8036868, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8036948, 'blx r3'), (8036968, 'bl sym.imp.__wrap_glBindTexture'), (8037048, 'blx r3'), (8037056, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(7992404, 'blt', 7992496), (7992492, 'b', 7992708), (7992616, 'bge', 7992704), (7992704, 'b', 7992708), (7992840, 'blt', 7992932), (7992928, 'b', 7993144), (7993052, 'bge', 7993140), (7993140, 'b', 7993144), (7993184, 'blt', 7993320), (7993228, 'bgt', 7993320), (7993272, 'blt', 7993320), (7993316, 'ble', 7993324), (7993320, 'b', 8037060), (7993516, 'ble', 7993652), (7993648, 'b', 7993928), (7993792, 'bpl', 7993924), (7993924, 'b', 7993928), (7994112, 'beq', 7994136), (7994132, 'bne', 7994176), (7994172, 'b', 8037060), (7994268, 'beq', 7994496), (7994368, 'ble', 7994492), (7994420, 'bpl', 7994444), (7994440, 'b', 7994464), (7994492, 'b', 7994496), (7994532, 'bne', 7994608), (7994644, 'beq', 7994940), (7994692, 'bpl', 7994940), (7995236, 'bgt', 7995384), (7995276, 'beq', 7995428), (7995380, 'ble', 7995428), (7995420, 'b', 7995676), (7995488, 'blt', 7995636), (7995528, 'beq', 7995672), (7995632, 'bpl', 7995672), (7995672, 'b', 7995676), (7995712, 'bne', 7995840), (7995776, 'bpl', 7995836), (7995832, 'b', 7995728), (7995836, 'b', 7996628), (7995876, 'bne', 7996004), (7995940, 'ble', 7996000), (7995996, 'b', 7995892), (7996000, 'b', 7996624), (7996040, 'bne', 7996164), (7996096, 'bpl', 7996156), (7996152, 'b', 7996056), (7996156, 'b', 7996620), (7996232, 'ble', 7996300), (7996288, 'b', 7996184), (7996300, 'b', 7996304), (7996352, 'bpl', 7996616), (7996408, 'b', 7996304), (7996616, 'b', 7996620), (7996620, 'b', 7996624), (7996624, 'b', 7996628), (7996724, 'bne', 8001464), (7996788, 'bne', 7996856), (7996852, 'beq', 8000036), (7997012, 'bpl', 7997036), (8000000, 'b', 8001460), (8001460, 'b', 8001464), (8001500, 'beq', 8005152), (8005128, 'b', 8005152), (8005188, 'bne', 8005232), (8005228, 'beq', 8006112), (8010568, 'bne', 8010636), (8010632, 'beq', 8012856), (8011824, 'b', 8011848), (8012844, 'b', 8013724), (8014040, 'beq', 8014068), (8014064, 'b', 8014104), (8014228, 'bpl', 8014252), (8014248, 'b', 8014268), (8014316, 'bpl', 8014356), (8014336, 'b', 8014372), (8014420, 'ble', 8014492), (8015060, 'bpl', 8015088), (8015080, 'b', 8015104), (8015208, 'bpl', 8015232), (8015228, 'b', 8015248), (8015352, 'bpl', 8015440), (8015372, 'b', 8015456), (8023748, 'b', 8023784), (8034424, 'b', 8034432)],
        semantics=('[DropBear -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x0079f160, 11364w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0x79f160, 11364w) CENSUS grade: enormous O0 frame (sub sp #0x1d0 + #0x3000 + bic #0xf, ~12.7KB) with 3 scratch arenas (sp+0xc00+0x32c / sp+0x1c00+0x22c / sp+0x2c00+0x22c) and a draw-state struct ([sp+0xe90]: self @+0x320, cached tile @+0x2f0, walkSpeed snapshot @+0x2ec, pose slots +0x214/0x218/0x21c, x-offset @+0x304). Head: copies the 8 args (dt + two by-value 64B _GLKMatrix4) into the frame then runs 6x worldWidthMacro<<5 /2 toroidal-wrap sections for position components. Visibility gate @0x79fafc: tileAtWorldPosition(int,int,MacroTile*,World*) -> if (tile == 0 || tile->byte6 == 0) { visible byte (offset 0x84, cell 0xffffd224) = 0; return; } else { visible = 1; state+0x2ec = walkSpeed; }. Pose: 6x sinf walk cycle (phase = walkTimer@272 * 6.0f + pools @0x7a04b8/0x7a04bc, negative-branch scale pool 0x7a04c0) + DropBear-local matrix helpers 0x7aac7c x20 / 0x7aa8e4 x17 / 0x7aa364 x12 / 0x7aa54c x6 / 0x7aa2f0 x2 + Vector/Vector2 operator float* x15/x12 + f64 fixed-point section (7.0/2.0/1.0 immediates @0x79fbac..). GL: glUseProgram @0x7a47e0 (after [shader program]), glUniform1i + glEnableVertexAttribArray @0x7a4890, glUniform4f x2 (@0x7a4f64 dayColor / @0x7a9114), glBindTexture x8 (0xde1=GL_TEXTURE_2D), glUniformMatrix4fv x20 = per-cube pairs uniformLocations[0]=mvp_matrix + [3]=normal_matrix, glDisableVertexAttribArray @0x7aa2c0. Per-cube block (first @0x7a55c0): 2x [[shader uniformLocations] objectAtIndex:i] intValue uploads then texture intValue -> glBindTexture(0xde1, id) with the cube texture from bodyFrontTexture@212. 88 objc_msgSend total; 8 memcpy + 1 memset; 6 idiv. Defined by full call histogram + constant scan + window samples (head, fixed-point @0x79faa8, GL prologue, cube block, sinf block); NOT instruction-by-instruction..\n'),
    ),
    dict(
        name='db_11',
        method='DropBear -[dropBearUpdateNetDataForClient:]',
        types='{DropBearUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIsCC[4C]}12@0:4@8',
        start=7987896,
        end=7988284,
        disasm='disasm_worldtileloader_db_11.txt',
        base_add=7987912,
        base_literal=7988280,
        boundary='ARM.exidx end 0x0079e43c (listing bound); next ObjC IMP 0x0079e43c DropBear -[creationNetDataForClient:]',
        selectors={
                 0x79e41c: (15209572, 'npcUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0x79e420: (17160240, 'OBJC_IVAR_$_DropBear.dropping', 308),
                 0x79e424: (17160252, 'OBJC_IVAR_$_DropBear.onGround', 344),
                 0x79e428: (17160160, 'OBJC_IVAR_$_DropBear.toSquare', 292),
                 0x79e430: (17160176, 'OBJC_IVAR_$_DropBear.walkSpeed', 276),
        },
        classes={},
        instructions=[(7987896, 'push {r4, r5, r6, r7, fp, lr}'), (7988280, 'addeq r1, ip, r4, lsr 16')],
        calls=[(7987996, 'bl loc.imp.objc_msgSend_stret'), (7988032, 'bl sym.imp.memset')],
        branches=[(7987976, 'beq', 7988004), (7988000, 'b', 7988036)],
        semantics=('[DropBear -[dropBearUpdateNetDataForClient:]] (imp 0x0079e2b8, 97w): -[dropBearUpdateNetDataForClient:] (0x79e2b8, 97w): sret writer for the 0x28-byte DropBearUpdateNetData: [self npcUpdateNetDataForClient:client] (0x18B sret, O0 nil-guard memset 0x18) at +0x00; +0x18 = self.toSquare@292 (intpair); +0x20 = (s16)(self.walkSpeed@276 * 255.0f) (strh, pool 0x79e434 = 0x437f0000); +0x22 = (char)self.dropping@308; +0x23 = (char)self.onGround@344; +0x24 char[4] never written..\n'),
    ),
    dict(
        name='db_12',
        method='DropBear -[foodItemType]',
        types='i8@0:4',
        start=7981052,
        end=7981080,
        disasm='disasm_worldtileloader_db_12.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c89c; body trimmed at the next IMP 0x0079c818 DropBear -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7981052, 'sub sp, sp, 8'), (7981076, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[foodItemType]] (imp 0x0079c7fc, 7w): -[foodItemType] (0x79c7fc, 7w): returns 0x1b (27) - the food item that tames/feeds a DropBear..\n'),
    ),
    dict(
        name='db_13',
        method='DropBear -[getNamesArray]',
        types='^@8@0:4',
        start=7981136,
        end=7981184,
        disasm='disasm_worldtileloader_db_13.txt',
        base_add=7981144,
        base_literal=7981180,
        boundary='ARM.exidx end 0x0079c89c; body trimmed at the next IMP 0x0079c880 DropBear -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7981136, 'sub sp, sp, 8'), (7981180, 'umulleq r3, ip, r4, r2')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[getNamesArray]] (imp 0x0079c850, 12w): -[getNamesArray] (0x79c850, 12w): returns the global 38-name CFString table @0x01051DF0 (no allocation): Ted, Yogi, Mr. Bear, Fluffy, Cuddles, Winnie, Wuzzy, Grizzlee, Franklin, Claws, Theodore, Barney, Bobo, Bongo, Disco, Flippy, Humphrey, Snuggles, Bubbles, Lulu, Max, Panda, Koala, Papa, Paws, Sonya, Sebastian, Paddington, Jasper, Bungle, Fozzie, Kevin, Rupert, Freddy, Droppy, Vegemite, Bruno, Jazz (bear-name pool; Droppy and Vegemite are drop-bear puns)..\n'),
    ),
    dict(
        name='db_14',
        method='DropBear -[getNamesArrayCount]',
        types='i8@0:4',
        start=7981184,
        end=7981212,
        disasm='disasm_worldtileloader_db_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c89c (listing bound); next ObjC IMP 0x0079c89c DropBear -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7981184, 'sub sp, sp, 8'), (7981208, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[getNamesArrayCount]] (imp 0x0079c880, 7w): -[getNamesArrayCount] (0x79c880, 7w): returns 0x26 (38) = number of names in db_13..\n'),
    ),
    dict(
        name='db_15',
        method='DropBear -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=8068576,
        end=8068748,
        disasm='disasm_worldtileloader_db_15.txt',
        base_add=8068592,
        base_literal=8068744,
        boundary='ARM.exidx end 0x007b1e8c (listing bound); next ObjC IMP 0x007b1e8c DropBear -[renderPos]',
        selectors={
                 0x7b1e7c: (15209768, 'hitWithForce:blockhead:'),
        },
        imports={
                 0x7b1e78: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x7b1e84: (17160260, 'OBJC_IVAR_$_DropBear.provokeMeter', 300),
        },
        classes={
                 0x7b1e80: (15252796, 'OBJC_CLASS_$_DropBear'),
        },
        instructions=[(8068576, 'push {r4, r5, r6, sl, fp, lr}'), (8068744, 'strdeq sp, lr, [sl], ip')],
        calls=[(8068676, 'blx r4')],
        branches=[],
        semantics=('[DropBear -[hitWithForce:blockhead:]] (imp 0x007b1de0, 43w): -[hitWithForce:blockhead:] (0x7b1de0, 43w): [super hitWithForce:blockhead:] (objc_msgSendSuper2) then self.provokeMeter@300 = 1.0f (vmov.f32 #1; ivar cell 0x7b1e84 -> slot 0x0105d844). The hit -> provoked trigger that feeds the tree-drop attack (paired with courageMeter@304 seeded in db_16)..\n'),
    ),
    dict(
        name='db_16',
        method='DropBear -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=7983788,
        end=7984440,
        disasm='disasm_worldtileloader_db_16.txt',
        base_add=7983804,
        base_literal=7984436,
        boundary='ARM.exidx end 0x0079d538 (listing bound); next ObjC IMP 0x0079d538 DropBear -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x79d514: (15209504, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x79d530: (15209508, 'loadDerivedStuff'),
        },
        imports={
                 0x79d52c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x79d518: (17160236, 'OBJC_IVAR_$_DropBear.courageMeter', 304),
                 0x79d51c: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x79d524: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x79d528: (17160240, 'OBJC_IVAR_$_DropBear.dropping', 308),
        },
        classes={
                 0x79d50c: (15252796, 'OBJC_CLASS_$_DropBear'),
        },
        instructions=[(7983788, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7984436, 'addeq r2, ip, r0, lsr r8')],
        calls=[(7984032, 'bl loc.imp.objc_msgSendSuper2'), (7984208, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (7984280, 'bl sym.tileIsClimable_Tile__intpair__World__DynamicObject_objcproto21PathUserDynamicObject_'), (7984372, 'blx r2')],
        branches=[(7984060, 'bne', 7984076), (7984072, 'b', 7984384), (7984124, 'beq', 7984332), (7984292, 'bne', 7984328), (7984328, 'b', 7984332)],
        semantics=('[DropBear -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]] (imp 0x0079d2ac, 163w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] (0x79d2ac, 163w): [super initWithWorld:... same 8 args] (super2, position/cache/saveDict/isAdult/wasPlaced/placedByClient on the stack + world/dynamicWorld in r2/r3); nil -> return nil; then self.courageMeter@304 = 1.0f; if (wasPlaced) { tile = tileAtWorldPositionLoaded(self.pos.x, self.pos.y, self.world); if (!tileIsClimable(tile, self.pos, self.world, nil)) self.dropping@308 = 1; } - a bear placed on a non-climbable square (e.g. in a tree canopy) starts out dropping; finally [self loadDerivedStuff] and return self..\n'),
    ),
    dict(
        name='db_17',
        method='DropBear -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=7986056,
        end=7986624,
        disasm='disasm_worldtileloader_db_17.txt',
        base_add=7986072,
        base_literal=7986620,
        boundary='ARM.exidx end 0x0079ddc0 (listing bound); next ObjC IMP 0x0079ddc0 DropBear -[getSaveDict]',
        selectors={
                 0x79dd90: (15209548, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0x79dd9c: (15209508, 'loadDerivedStuff'),
                 0x79dda0: (15209552, 'remoteCreationDataUpdate:'),
        },
        imports={
                 0x79dd8c: (17151900, 'objc_msgSendSuper2'),
                 0x79dd98: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x79dda4: (17160264, 'OBJC_IVAR_$_DropBear.nextOnGround', 420),
                 0x79ddac: (17160268, 'OBJC_IVAR_$_DropBear.nextToSquare', 372),
                 0x79ddb4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x79ddb8: (17160272, 'OBJC_IVAR_$_DropBear.nextWalkSpeed', 404),
        },
        classes={
                 0x79dd94: (15252796, 'OBJC_CLASS_$_DropBear'),
        },
        instructions=[(7986056, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7986620, 'addeq r1, ip, r4, asr pc')],
        calls=[(7986208, 'blx r6'), (7986304, 'blx r3'), (7986548, 'blx r3')],
        branches=[(7986236, 'bne', 7986252), (7986248, 'b', 7986560), (7986328, 'bge', 7986500), (7986496, 'b', 7986320)],
        semantics=('[DropBear -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x0079db88, 142w): -[initWithWorld:dynamicWorld:cache:netData:] (0x79db88, 142w): [super initWithWorld:dynamicWorld:cache:netData:] (super2, cache/netData on stack); nil -> nil; [self loadDerivedStuff]; then for i = 0..3: nextToSquare@372[i] = self.pos; nextWalkSpeed@404[i] = 0.0f (pool 0x79dda8 = 0x00000000); nextOnGround@420[i] = 0; then [self remoteCreationDataUpdate:netData]; return self. Seeds the 4-slot remote queue with the spawn pos (currentNetQueueSize@368 is not touched here)..\n'),
    ),
    dict(
        name='db_18',
        method='DropBear -[loadDerivedStuff]',
        types='v8@0:4',
        start=7981212,
        end=7983772,
        disasm='disasm_worldtileloader_db_18.txt',
        base_add=7981228,
        base_literal=7983768,
        boundary='ARM.exidx end 0x0079d29c (listing bound); next ObjC IMP 0x0079d2ac DropBear -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x79d20c: (15209496, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
                 0x79d210: (15209492, 'alloc'),
                 0x79d220: (15209500, 'initWithWidth:height:depth:calculateNormals:'),
                 0x79d23c: (15209488, 'textureNamed:'),
                 0x79d270: (15209484, 'shaderNamed:attributes:uniforms:'),
                 0x79d284: (15209480, 'arrayWithObjects:'),
        },
        imports={
                 0x79d208: (17151904, 'objc_msgSend'),
                 0x79d238: (16320712, '__CFConstantStringClassReference'),
                 0x79d248: (16320696, '__CFConstantStringClassReference'),
                 0x79d250: (16320680, '__CFConstantStringClassReference'),
                 0x79d258: (16320664, '__CFConstantStringClassReference'),
                 0x79d260: (16320648, '__CFConstantStringClassReference'),
                 0x79d26c: (16320520, '__CFConstantStringClassReference'),
                 0x79d274: (16320584, '__CFConstantStringClassReference'),
                 0x79d278: (16320600, '__CFConstantStringClassReference'),
                 0x79d27c: (16320616, '__CFConstantStringClassReference'),
                 0x79d280: (16320632, '__CFConstantStringClassReference'),
                 0x79d28c: (16320536, '__CFConstantStringClassReference'),
                 0x79d290: (16320552, '__CFConstantStringClassReference'),
                 0x79d294: (16320568, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x79d1e0: (17160156, 'OBJC_IVAR_$_DropBear.travelFraction', 280),
                 0x79d1e4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x79d1e8: (17160160, 'OBJC_IVAR_$_DropBear.toSquare', 292),
                 0x79d1ec: (17160164, 'OBJC_IVAR_$_DropBear.fromSquare', 284),
                 0x79d1f4: (17160168, 'OBJC_IVAR_$_DropBear.bodyRotation', 264),
                 0x79d1f8: (17160172, 'OBJC_IVAR_$_DropBear.goalRotationType', 268),
                 0x79d1fc: (17160176, 'OBJC_IVAR_$_DropBear.walkSpeed', 276),
                 0x79d204: (17160180, 'OBJC_IVAR_$_DropBear.legCube', 256),
                 0x79d218: (17160184, 'OBJC_IVAR_$_DropBear.armCube', 260),
                 0x79d21c: (17160188, 'OBJC_IVAR_$_DropBear.eyeCube', 252),
                 0x79d224: (17160192, 'OBJC_IVAR_$_DropBear.snoutCube', 248),
                 0x79d228: (17160196, 'OBJC_IVAR_$_DropBear.headCube', 244),
                 0x79d22c: (17160200, 'OBJC_IVAR_$_DropBear.backBodyCube', 240),
                 0x79d230: (17160204, 'OBJC_IVAR_$_DropBear.frontBodyCube', 236),
                 0x79d234: (17160208, 'OBJC_IVAR_$_DropBear.snoutTexture', 232),
                 0x79d240: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x79d244: (17160212, 'OBJC_IVAR_$_DropBear.eyeTexture', 228),
                 0x79d24c: (17160216, 'OBJC_IVAR_$_DropBear.legTexture', 224),
                 0x79d254: (17160220, 'OBJC_IVAR_$_DropBear.headTexture', 220),
                 0x79d25c: (17160224, 'OBJC_IVAR_$_DropBear.bodyBackTexture', 216),
                 0x79d264: (17160228, 'OBJC_IVAR_$_DropBear.bodyFrontTexture', 212),
                 0x79d268: (17160232, 'OBJC_IVAR_$_DropBear.shader', 208),
        },
        classes={
                 0x79d214: (15247032, 'OBJC_CLASS_$_DrawCube'),
                 0x79d288: (15247028, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(7981212, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7983768, 'addeq r3, ip, r0, asr 4')],
        calls=[(7981908, 'blx r4'), (7981972, 'blx r5'), (7982016, 'blx lr'), (7982076, 'blx ip'), (7982136, 'blx ip'), (7982196, 'blx ip'), (7982292, 'blx ip'), (7982352, 'blx ip'), (7982412, 'blx ip'), (7982464, 'blx ip'), (7982552, 'blx lr'), (7982604, 'blx ip'), (7982688, 'blx lr'), (7982740, 'blx ip'), (7982820, 'blx lr'), (7982872, 'blx ip'), (7982924, 'blx lr'), (7982976, 'blx ip'), (7983024, 'blx lr'), (7983076, 'blx ip'), (7983160, 'blx lr'), (7983212, 'blx ip'), (7983296, 'blx lr'), (7983320, 'bl 0x79d29c')],
        branches=[(7982248, 'b', 7982284)],
        semantics=('[DropBear -[loadDerivedStuff]] (imp 0x0079c89c, 640w): -[loadDerivedStuff] (0x79c89c, 640w, fully read): shader@208 = [cache shaderNamed:@`ShadedWorldObject` attributes:[NSArray arrayWithObjects:@`position`,@`texCoord`,@`normal`] uniforms:[NSArray arrayWithObjects:@`mvp_matrix`,@`texture`,@`light`,@`normal_matrix`]] (CFStrings @0xF90808/818/828/838/848/858/868/878). Textures: bodyFrontTexture@212 = bodyBackTexture@216 = [cache textureNamed:@`grizratBodyFront.png`] (the same CFString @0xF90888 is passed twice); headTexture@220 = grizratHead.png; legTexture@224 = grizratLeg.png; eyeTexture@228 = grizratEye.png; snoutTexture@232 = grizratSnout.png. Cubes (8-arg initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals: unless noted): frontBodyCube@236 = (0.6, 0.4, 0.3, c 0.3, 0.0, 0.15); backBodyCube@240 = (0.6, 2.0, 0.3, c 0.3, 2.0, 0.15); headCube@244 = (0.4, 0.4, 0.4, c 0.2, 0.0, 0.2); snoutCube@248 = 4-arg (0.15, 0.2, 0.2); eyeCube@252 = 4-arg (0.05, 0.05, 0.05); armCube@260 = (0.2, 0.2, 5.0, c 0.1, 0.1, 0.0); legCube@256 = (0.2, 0.2, 0.4, c 0.1, 0.1, 0.0); all calculateNormals:YES. Float pools 0x79ccac..0x79ccc8 = 0.2/0.4/0.1/0.0/0.05/0.15/0.6/0.3. Movement seed: u = lrand48()/2^31 (bl 0x79d29c, the local RNG wrapper right after the body; pool 0x79d200 = 0x4f000000); walkSpeed@276 = 4.0 + 5.0*u; goalRotationType@268 = 0; bodyRotation@264 = pi (pool 0x79d1f0 = 0x40490fdb); toSquare@292 = self.pos; fromSquare@284 = toSquare; travelFraction@280 = 1.0f..\n'),
    ),
    dict(
        name='db_19',
        method='DropBear -[maxAge]',
        types='f8@0:4',
        start=7980956,
        end=7981004,
        disasm='disasm_worldtileloader_db_19.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c7cc (listing bound); next ObjC IMP 0x0079c7cc DropBear -[speciesName]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7980956, 'sub sp, sp, 0x10'), (7981000, 'strbmi r0, [r1, 0]!')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[maxAge]] (imp 0x0079c79c, 12w): -[maxAge] (0x79c79c, 12w): returns 7200.0f (movw/movt 0x45e10000; pool word 0x79c7c8) - 2 game-hours, same as ClownFish..\n'),
    ),
    dict(
        name='db_20',
        method='DropBear -[maxHealth]',
        types='S8@0:4',
        start=8067252,
        end=8067280,
        disasm='disasm_worldtileloader_db_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007b18d0 (listing bound); next ObjC IMP 0x007b18d0 DropBear -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8067252, 'sub sp, sp, 8'), (8067276, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[maxHealth]] (imp 0x007b18b4, 7w): -[maxHealth] (0x7b18b4, 7w): returns (unsigned short) 0x10 = 16..\n'),
    ),
    dict(
        name='db_21',
        method='DropBear -[npcType]',
        types='i8@0:4',
        start=7980928,
        end=7980956,
        disasm='disasm_worldtileloader_db_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0079c79c (listing bound); next ObjC IMP 0x0079c79c DropBear -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7980928, 'sub sp, sp, 8'), (7980952, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[npcType]] (imp 0x0079c780, 7w): -[npcType] (0x79c780, 7w): returns 2 (NPCType 2)..\n'),
    ),
    dict(
        name='db_22',
        method='DropBear -[reactToBeingFed]',
        types='v8@0:4',
        start=8069036,
        end=8069360,
        disasm='disasm_worldtileloader_db_22.txt',
        base_add=8069052,
        base_literal=8069356,
        boundary='ARM.exidx end 0x007b20f0 (listing bound); next ObjC IMP 0x007b20f0 DropBear -[successfulTame]',
        selectors={
                 0x7b20d8: (15209600, 'instance'),
                 0x7b20dc: (15209604, 'multiSoundNamed:'),
                 0x7b20e8: (15209764, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x7b20e0: (16320952, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7b20c8: (17160284, 'OBJC_IVAR_$_DropBear.walkTimer', 272),
                 0x7b20cc: (17160176, 'OBJC_IVAR_$_DropBear.walkSpeed', 276),
                 0x7b20e4: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x7b20d0: (15247044, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(8069036, 'push {r4, sl, fp, lr}'), (8069356, 'addeq sp, sl, r0, lsr fp')],
        calls=[(8069152, 'bl loc.imp.objc_msgSend'), (8069176, 'bl loc.imp.objc_msgSend'), (8069256, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[DropBear -[reactToBeingFed]] (imp 0x007b1fac, 81w): -[reactToBeingFed] (0x7b1fac, 81w): [[MJSoundManager instance] multiSoundNamed:@`crunch.wav` (@0xF909B8)] playAtPosition:self.floatPos afterDelay:0.1 (double 0x3fb99999a0000000); then self.walkSpeed@276 = 1.0f; self.walkTimer@272 = 0.0f (pool 0x7b20c4 = 0x00000000). No super call..\n'),
    ),
    dict(
        name='db_23',
        method='DropBear -[reactToBeingHit]',
        types='v8@0:4',
        start=8068380,
        end=8068576,
        disasm='disasm_worldtileloader_db_23.txt',
        base_add=8068408,
        base_literal=8068552,
        boundary='ARM.exidx end 0x007b1de0 (listing bound); next ObjC IMP 0x007b1de0 DropBear -[hitWithForce:blockhead:]',
        selectors={
                 0x7b1dcc: (15209600, 'instance'),
                 0x7b1dd0: (15209604, 'multiSoundNamed:'),
                 0x7b1ddc: (15209764, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x7b1dd4: (16320936, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7b1dd8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x7b1dc4: (15247044, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(8068380, 'push {fp, lr}'), (8068572, 'invalid')],
        calls=[(8068432, 'bl loc.imp.objc_msgSend'), (8068456, 'bl loc.imp.objc_msgSend'), (8068536, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[DropBear -[reactToBeingHit]] (imp 0x007b1d1c, 49w): -[reactToBeingHit] (0x7b1d1c, 49w): [[MJSoundManager instance] multiSoundNamed:@`dropbear.wav` (@0xF909A8)] playAtPosition:self.floatPos afterDelay:0.1 (double 0x3fb99999a0000000). No super call..\n'),
    ),
    dict(
        name='db_24',
        method='DropBear -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=7990812,
        end=7991216,
        disasm='disasm_worldtileloader_db_24.txt',
        base_add=7990828,
        base_literal=7991212,
        boundary='ARM.exidx end 0x0079efb0 (listing bound); next ObjC IMP 0x0079efb0 DropBear -[creationDataStructSize]',
        selectors={
                 0x79ef94: (15209552, 'remoteCreationDataUpdate:'),
                 0x79efa0: (15209612, 'getBytes:length:'),
                 0x79efa8: (15209616, 'doRemoteUpdate:'),
        },
        imports={
                 0x79ef90: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x79ef9c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0x79ef98: (15252796, 'OBJC_CLASS_$_DropBear'),
        },
        instructions=[(7990812, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7991212, 'addeq r0, ip, r0, asr 25')],
        calls=[(7990904, 'blx lr'), (7990984, 'bl loc.imp.objc_msgSend'), (7991172, 'bl loc.imp.objc_msgSend')],
        branches=[(7990940, 'bne', 7991176)],
        semantics=('[DropBear -[remoteCreationDataUpdate:]] (imp 0x0079ee1c, 101w): -[remoteCreationDataUpdate:] (0x79ee1c, 101w): [super remoteCreationDataUpdate:data] (super2); if (self.dead@56) return; [data getBytes:buf length:0x78]; then hands the 0x28-byte update struct at buf+0x48 to [self doRemoteUpdate:] using the AAPCS split (w0/w1 in r2/r3, w2..w9 staged on the stack) - the exact call-site form ClownFish documented..\n'),
    ),
    dict(
        name='db_25',
        method='DropBear -[remoteUpdate:]',
        types='v12@0:4@8',
        start=7991244,
        end=7991648,
        disasm='disasm_worldtileloader_db_25.txt',
        base_add=7991260,
        base_literal=7991644,
        boundary='ARM.exidx end 0x0079f160 (listing bound); next ObjC IMP 0x0079f160 DropBear -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={
                 0x79f144: (15209620, 'remoteUpdate:'),
                 0x79f150: (15209612, 'getBytes:length:'),
                 0x79f158: (15209616, 'doRemoteUpdate:'),
        },
        imports={
                 0x79f140: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x79f14c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0x79f148: (15252796, 'OBJC_CLASS_$_DropBear'),
        },
        instructions=[(7991244, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7991644, 'addeq r0, ip, r0, lsl fp')],
        calls=[(7991336, 'blx lr'), (7991416, 'bl loc.imp.objc_msgSend'), (7991604, 'bl loc.imp.objc_msgSend')],
        branches=[(7991372, 'bne', 7991608)],
        semantics=('[DropBear -[remoteUpdate:]] (imp 0x0079efcc, 101w): -[remoteUpdate:] (0x79efcc, 101w): [super remoteUpdate:data] (super2); if (self.dead@56) return; [data getBytes:buf length:0x28]; then [self doRemoteUpdate:] with the same w0/w1-in-registers split. Identical body to db_24 except length 0x28 and offset 0..\n'),
    ),
    dict(
        name='db_26',
        method='DropBear -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=8068748,
        end=8068820,
        disasm='disasm_worldtileloader_db_26.txt',
        base_add=8068756,
        base_literal=8068816,
        boundary='ARM.exidx end 0x007b1ed4 (listing bound); next ObjC IMP 0x007b1ed4 DropBear -[worldChanged:]',
        selectors={},
        imports={},
        ivars={
                 0x7b1ecc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(8068748, 'sub sp, sp, 8'), (8068816, 'addeq sp, sl, r8, asr ip')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[renderPos]] (imp 0x007b1e8c, 18w): -[renderPos] (0x7b1e8c, 18w): sret copy of floatPos@24 (Vector2) to the out pointer (proc: r0=dest, r1=self, r2=_cmd; offset via ivar cell 0x7b1ecc -> 0x0105c3d0)..\n'),
    ),
    dict(
        name='db_27',
        method='DropBear -[ridableWhenTamed]',
        types='c8@0:4',
        start=8070300,
        end=8070328,
        disasm='disasm_worldtileloader_db_27.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007b24b8 (listing bound); next ObjC IMP 0x007b24b8 DropBear -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8070300, 'sub sp, sp, 8'), (8070324, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[ridableWhenTamed]] (imp 0x007b249c, 7w): -[ridableWhenTamed] (0x7b249c, 7w): returns 0 (sxtb) - not ridable..\n'),
    ),
    dict(
        name='db_28',
        method='DropBear -[speciesName]',
        types='@8@0:4',
        start=7981004,
        end=7981052,
        disasm='disasm_worldtileloader_db_28.txt',
        base_add=7981012,
        base_literal=7981048,
        boundary='ARM.exidx end 0x0079c89c; body trimmed at the next IMP 0x0079c7fc DropBear -[foodItemType]',
        selectors={},
        imports={
                 0x79c7f4: (16320504, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(7981004, 'sub sp, sp, 8'), (7981048, 'addeq r3, ip, r8, lsl r3')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[speciesName]] (imp 0x0079c7cc, 12w): -[speciesName] (0x79c7cc, 12w): returns CFString @`DROPBEAR` (object @0x00f907f8, cstr @0xf55f90 len 8; uncl pair 0xfff30d04 / 0x8c3318)..\n'),
    ),
    dict(
        name='db_29',
        method='DropBear -[successfulTame]',
        types='v8@0:4',
        start=8069360,
        end=8069636,
        disasm='disasm_worldtileloader_db_29.txt',
        base_add=8069376,
        base_literal=8069632,
        boundary='ARM.exidx end 0x007b2204 (listing bound); next ObjC IMP 0x007b2204 DropBear -[canBeCapturedByBlockhead:withItemType:]',
        selectors={
                 0x7b21dc: (15209772, 'successfulTame'),
                 0x7b21ec: (15209600, 'instance'),
                 0x7b21f0: (15209604, 'multiSoundNamed:'),
                 0x7b21fc: (15209764, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0x7b21d8: (17151900, 'objc_msgSendSuper2'),
                 0x7b21f4: (16320936, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7b21f8: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0x7b21e0: (15252796, 'OBJC_CLASS_$_DropBear'),
                 0x7b21e4: (15247044, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(8069360, 'push {r4, sl, fp, lr}'), (8069632, 'addeq sp, sl, ip, ror 19')],
        calls=[(8069440, 'blx ip'), (8069476, 'bl loc.imp.objc_msgSend'), (8069500, 'bl loc.imp.objc_msgSend'), (8069580, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[DropBear -[successfulTame]] (imp 0x007b20f0, 69w): -[successfulTame] (0x7b20f0, 69w): [super successfulTame] (super2); then [[MJSoundManager instance] multiSoundNamed:@`dropbear.wav`] playAtPosition:self.floatPos afterDelay:0.6 (double 0x3fe3333340000000)..\n'),
    ),
    dict(
        name='db_30',
        method='DropBear -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=8067280,
        end=8068380,
        disasm='disasm_worldtileloader_db_30.txt',
        base_add=8067296,
        base_literal=8068376,
        boundary='ARM.exidx end 0x007b1de0; body trimmed at the next IMP 0x007b1d1c DropBear -[reactToBeingHit]',
        selectors={
                 0x7b1d08: (15209624, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x7b1cf8: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x7b1cfc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0x7b1d04: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(8067280, 'push {fp, lr}'), (8068376, 'addeq lr, sl, ip, lsl 4')],
        calls=[(8067388, 'bl method.Vector2.operator_float__'), (8067432, 'bl method.Vector2.operator_float__'), (8067484, 'bl loc.imp.objc_msgSend'), (8067508, 'bl sym.imp.__aeabi_idiv'), (8067552, 'bl method.Vector2.operator_float__'), (8067596, 'bl method.Vector2.operator_float__'), (8067648, 'bl loc.imp.objc_msgSend'), (8067712, 'bl method.Vector2.operator_float__'), (8067756, 'bl method.Vector2.operator_float__'), (8067808, 'bl loc.imp.objc_msgSend'), (8067824, 'bl sym.imp.__aeabi_idiv'), (8067868, 'bl method.Vector2.operator_float__'), (8067912, 'bl method.Vector2.operator_float__'), (8067964, 'bl loc.imp.objc_msgSend'), (8068008, 'bl method.Vector2.operator_float__'), (8068044, 'bl method.Vector2.operator_float__'), (8068132, 'bl method.Vector2.operator_float__'), (8068172, 'bl method.Vector2.operator_float__'), (8068216, 'bl method.Vector2.operator_float__'), (8068256, 'bl method.Vector2.operator_float__')],
        branches=[(8067348, 'beq', 8067364), (8067360, 'b', 8068320), (8067532, 'blt', 8067688), (8067684, 'b', 8068072), (8067848, 'bpl', 8068004), (8068000, 'b', 8068064), (8068100, 'bpl', 8068312), (8068124, 'ble', 8068312), (8068208, 'ble', 8068312), (8068296, 'bpl', 8068312), (8068308, 'b', 8068320)],
        semantics=('[DropBear -[tapIsWithinBodyRadius:]] (imp 0x007b18d0, 275w): -[tapIsWithinBodyRadius:] (0x7b18d0, 275w, fully read): if (self.dead@56) return NO. dx = tap.x - floatPos.x; width32 = worldWidthMacro << 5; half = width32 / 2; toroidal wrap of dx: dx >= half -> dx -= width32; dx < -half -> dx += width32 (three-branch warp, cells 0xffffc8dc floatPos / 0xffffc8a0 world / worldWidthMacro). Pass requires |dx| < 5.0 (f64 compares with vmov.f64 #5, both >=5 and <=-5 fail). Y checks (all f64): require (double)tap.y > (double)floatPos.y - 5.0 + 5.0 (literal -5.0 then +5.0 roundtrip, collapses to > floatPos.y) and (double)tap.y < (double)floatPos.y + 5.0 + 0.6 (pool double @0x7b1cf0 = 0x3fe6666666666666 = 0.6). Uses Vector2::operator float* x6..\n'),
    ),
    dict(
        name='db_31',
        method='DropBear -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=7988808,
        end=7989044,
        disasm='disasm_worldtileloader_db_31.txt',
        base_add=7988824,
        base_literal=7989040,
        boundary='ARM.exidx end 0x0079e734 (listing bound); next ObjC IMP 0x0079e734 DropBear -[dealloc]',
        selectors={
                 0x79e720: (15209580, 'dropBearUpdateNetDataForClient:'),
                 0x79e728: (15209584, 'dataWithBytes:length:'),
        },
        imports={
                 0x79e724: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x79e72c: (15247040, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(7988808, 'push {fp, lr}'), (7989040, 'umulleq r1, ip, r4, r4')],
        calls=[(7988904, 'bl loc.imp.objc_msgSend_stret'), (7988940, 'bl sym.imp.memset'), (7989004, 'blx ip')],
        branches=[(7988884, 'beq', 7988912), (7988908, 'b', 7988944)],
        semantics=('[DropBear -[updateNetDataForClient:]] (imp 0x0079e648, 59w): -[updateNetDataForClient:] (0x79e648, 59w): returns [NSData dataWithBytes:stret(self dropBearUpdateNetDataForClient:client) length:0x28] - the 0x28B writer wrapped as NSData (O0 nil-guard memset 0x28 when self == nil)..\n'),
    ),
    dict(
        name='db_32',
        method='DropBear -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=8068820,
        end=8068844,
        disasm='disasm_worldtileloader_db_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007b1eec (listing bound); next ObjC IMP 0x007b1eec DropBear -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8068820, 'sub sp, sp, 0xc'), (8068840, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[DropBear -[worldChanged:]] (imp 0x007b1ed4, 6w): -[worldChanged:] (0x7b1ed4, 6w): empty override (prologue/epilogue only) - vector<intpair> change notifications are ignored (no super call, no work)..\n'),
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
        'batch': 'DropBear (E145): the dropbear animal; 33 bodies',
        'claim': ('the dropbear animal (provoke/courage drop attack, remote update queue)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dropbear.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale dropbear.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
