#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld remote-receive/painting/chest smalls (E32).

The DynamicWorld remote-receive/painting/chest smalls: the remote creation-
data and update appliers, the snow-change recorder, the NPC-existence probe,
the free-block move, the painting request/receive pair and the chest-inventory
receiver:
1 body, 1197 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/REMOTE_RECEIVE.md for the prose and boundaries.
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
    'bl method.std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject_const_': 0x0090dc2c,
    'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__': 0x005dc5d8,
    'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_': 0x008bd2e4,
    'bl method.unsigned_long_std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__erase_unique_DynamicObject__DynamicObject_const_': 0x0090ba74,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const': 0x0090c648,
    'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__erase_unique_unsigned_long_long__unsigned_long_long_const_': 0x00913998,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_remotecreationdataupda',
        method='DynamicWorld -[remoteCreationDataUpdate:forObjectsOfType:fromClient:]',
        types='v20@0:4@8i12@16',
        start=9191012,
        end=9191328,
        disasm='disasm_worldtileloader_remotecreationdataupdate_forobjectsoftyp.txt',
        base_add=9191028,
        base_literal=9191324,
        boundary='ARM.exidx end 0x008c3fa0 (listing bound); next ObjC IMP 0x008c3fa0 DynamicWorld -[remoteUpdate:forObjectsOfType:fromClient:]',
        selectors={
                 0x8c3f8c: (15215804, 'alloc'),
                 0x8c3f90: (15215800, 'init'),
                 0x8c3f98: (15216424, 'addObjectsFromArray:'),
        },
        imports={
                 0x8c3f94: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8c3f7c: (17162296, 'OBJC_IVAR_$_DynamicWorld.netUpdateCreationDataDynamicObjects', 7892),
        },
        classes={
                 0x8c3f84: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9191012, 'push {r4, r5, fp, lr}'), (9191060, 'str lr, [sp, 0x1c]'), (9191112, 'cmp r0, r4'), (9191164, 'mov r1, r3'), (9191224, 'str r0, [r1]'), (9191324, 'rsbseq fp, sb, r8, ror ip')],
        calls=[(9191172, 'bl loc.imp.objc_msgSend'), (9191188, 'bl loc.imp.objc_msgSend'), (9191280, 'blx r3')],
        branches=[(9191124, 'bne', 9191232)],
        semantics=('remoteCreationDataUpdate:forObjectsOfType:fromClient: applies a remote creation-data update. Prologue 0x008c3e64 (frame 0x38; base 0x105faf4). Args: intpair pos, objectType, client.\nLazy bucket: the **ffffe544 slot array** (`add r0, r1, r0, lsl 2` 4-byte pointer array, @0x8c3eb4-0x8c3ebc) is indexed by objectType; a NULL cell (@0x8c3ec8) creates `[[class ffe2aeb0 alloc] init]` (cells ffe231c8/ffe231c4 @0x8c3ed8-0x8c3f14) and stores it (@0x8c3f38). The update call follows through the slot.\n'),
    ),
    dict(
        name='wtl_remoteupdate_forobject',
        method='DynamicWorld -[remoteUpdate:forObjectsOfType:fromClient:]',
        types='v20@0:4@8i12@16',
        start=9191328,
        end=9191948,
        disasm='disasm_worldtileloader_remoteupdate_forobjectsoftype_fromclient.txt',
        base_add=9191344,
        base_literal=9191944,
        boundary='ARM.exidx end 0x008c420c (listing bound); next ObjC IMP 0x008c420c DynamicWorld -[remoteRemove:forObjectsOfType:fromClient:]',
        selectors={
                 0x8c41d8: (15216420, 'isServer'),
                 0x8c41dc: (15216428, 'playerIsAdminWithID:'),
                 0x8c41e4: (15216280, 'isEqualToString:'),
                 0x8c41e8: (15216432, 'playerUpdate'),
                 0x8c41fc: (15215804, 'alloc'),
                 0x8c4200: (15215800, 'init'),
                 0x8c4204: (15216424, 'addObjectsFromArray:'),
        },
        imports={
                 0x8c41d4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8c41e0: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x8c41ec: (17162292, 'OBJC_IVAR_$_DynamicWorld.netUpdateDynamicObjects', 7632),
        },
        classes={
                 0x8c41f4: (15247780, 'OBJC_CLASS_$_NSMutableArray'),
        },
        instructions=[(9191328, 'push {r4, sl, fp, lr}'), (9191376, 'cmp r0, 0x3c'), (9191428, 'blx r2'), (9191512, 'blx r3'), (9191636, 'sxtb r0, r0'), (9191944, 'rsbseq fp, sb, ip, lsr fp')],
        calls=[(9191428, 'blx r2'), (9191512, 'blx r3'), (9191612, 'blx ip'), (9191632, 'blx r3'), (9191772, 'bl loc.imp.objc_msgSend'), (9191788, 'bl loc.imp.objc_msgSend'), (9191880, 'blx r3')],
        branches=[(9191384, 'bne', 9191660), (9191440, 'beq', 9191660), (9191524, 'bne', 9191532), (9191528, 'b', 9191884), (9191644, 'beq', 9191652), (9191648, 'b', 9191884), (9191652, 'b', 9191656), (9191656, 'b', 9191660), (9191724, 'bne', 9191832)],
        semantics=("remoteUpdate:forObjectsOfType:fromClient: applies a remote update. Prologue 0x008c3fa0 (frame 0x48; base 0x105faf4).\nType gate: `if (objectType != 0x3c) return` (@0x8c3fd0-0x8c3fd8).\nPath: the ffe23430 check (@0x8c3ffc) -> the **ffffe51c slot** (4-byte pointer array, @0x8c4038) -> the ffe23438/ffe2343c selector calls + the ffe233a4 + the ffffe51c walk (@0x8c408c-0x8c40f8): the objectType-0x3c (60) special remote-update path (matching E24's interaction type code 60).\n"),
    ),
    dict(
        name='wtl_snowchangedatmacropos_',
        method='DynamicWorld -[snowChangedAtMacroPos:]',
        types='v16@0:4{?=ii}8',
        start=9313264,
        end=9314072,
        disasm='disasm_worldtileloader_snowchangedatmacropos_.txt',
        base_add=9313280,
        base_literal=9314068,
        boundary='ARM.exidx end 0x008e1f18 (listing bound); next ObjC IMP 0x008e1f18 DynamicWorld -[lightChangedAtMacroPos:sendReliably:sendAtAll:]',
        selectors={},
        imports={},
        ivars={
                 0x8e1f10: (17162356, 'OBJC_IVAR_$_DynamicWorld.snowChangedMacroPositions', 6096),
        },
        classes={},
        instructions=[(9313264, 'push {r4, r5, r6, sl, fp, lr}'), (9313288, 'ldr r4, [0x008e1f10]'), (9313560, 'ldr r1, [r1]'), (9313656, 'strb r0, [sp, 0x2f]'), (9313728, 'ldrsb r0, [sp, 0x2f]'), (9314068, 'rsbseq sp, r7, ip, ror 29')],
        calls=[(9314048, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9313584, 'beq', 9313728), (9313632, 'bne', 9313664), (9313648, 'bne', 9313664), (9313660, 'b', 9313728), (9313664, 'b', 9313668), (9313724, 'b', 9313412), (9313736, 'bne', 9314056), (9313828, 'beq', 9314040), (9313976, 'beq', 9314020), (9314036, 'b', 9314052), (9314052, 'b', 9314056)],
        semantics=("snowChangedAtMacroPos: records a changed snow macro position. Prologue 0x008e1bf0 (frame 0x138; base 0x105faf4). Argument: macro pair.\nRecord: the **ffffe580 member** (cell 0x8e1f10, @0x8e1c08-0x8e1c38) pair-dedup walk: the eor/tst found-flag pattern (@0x8e1d18-0x8e1d30, like E22's worldChanged), the exact-pair probe with the strb-1 on hit (@0x8e1d74-0x8e1d78); a not-found pair exits the loop (@0x8e1d84+) and proceeds to the second structure pass (@0x8e1dc0+) — the E21-family snow queue (the ffffe580 member E22's save sweep scans).\n"),
    ),
    dict(
        name='wtl_npcexistsatpos_ignoren',
        method='DynamicWorld -[npcExistsAtPos:ignoreNPC:]',
        types='c20@0:4{?=ii}8@16',
        start=9382052,
        end=9382836,
        disasm='disasm_worldtileloader_npcexistsatpos_ignorenpc_.txt',
        base_add=9382068,
        base_literal=9382832,
        boundary='ARM.exidx end 0x008f2bb4 (listing bound); next ObjC IMP 0x008f2bb4 DynamicWorld -[tooManyNPCsToSpawnMoreNearPos:]',
        selectors={
                 0x8f2bac: (15216012, 'pos'),
        },
        imports={},
        ivars={
                 0x8f2ba8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9382052, 'push {r4, sl, fp, lr}'), (9382112, 'cmp r0, 8'), (9382144, 'ldr r1, [r2, r1, lsl 2]'), (9382168, 'add r1, r1, r1, lsl 1'), (9382472, 'ldr r0, [r0, 8]'), (9382548, 'bl loc.imp.objc_msgSend_stret'), (9382832, 'rsbseq sp, r6, r8, lsr r2')],
        calls=[(9382548, 'bl loc.imp.objc_msgSend_stret'), (9382584, 'bl sym.imp.memset'), (9382656, 'bl loc.imp.objc_msgSend_stret'), (9382692, 'bl sym.imp.memset'), (9382760, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9382116, 'bge', 9382796), (9382424, 'beq', 9382776), (9382492, 'beq', 9382724), (9382532, 'beq', 9382556), (9382552, 'b', 9382588), (9382600, 'bne', 9382724), (9382640, 'beq', 9382664), (9382660, 'b', 9382696), (9382708, 'bne', 9382724), (9382720, 'b', 9382804), (9382724, 'b', 9382728), (9382772, 'b', 9382340), (9382776, 'b', 9382780), (9382792, 'b', 9382108)],
        semantics=("npcExistsAtPos:ignoreNPC: answers whether an NPC family exists at a position. Prologue 0x008f28a4 (frame 0x110; base 0x105faf4). Args: argument index, intpair pos, ignoreNPC.\nFamily dispatch: `if (arg >= 8) return false` (@0x8f28e0-0x8f28e4); the **jump table 0x00E4AA1C** (`ldr r1, [r2, r1, lsl 2]` @0x8f2900, the 8-arm NPC family table) selects the family slice of the **ffffe54c member** (`add r1, r1, r1, lsl 1` <<2 = 12-byte striding @0x8f2918).\nScan: the slice's tree is iterated (the __tree walk @0x8f2954+); per node the pos member ([node+0x10]+8 @0x8f2a3c-0x8f2a48) is compared against the argument pair via `[obj xPos]`/`[obj yPos]` (ffe23298 stret reads @0x8f2a94/0x8f2b00); equality + the ignoreNPC gate decides (@0x8f2b44+).\n"),
    ),
    dict(
        name='wtl_freeblockpositionchang',
        method='DynamicWorld -[freeblockPositionChanged:oldPos:]',
        types='v20@0:4@8{?=ii}12',
        start=9464216,
        end=9465036,
        disasm='disasm_worldtileloader_freeblockpositionchanged_oldpos_.txt',
        base_add=9464232,
        base_literal=9465032,
        boundary='ARM.exidx end 0x00906ccc (listing bound); next ObjC IMP 0x00906ccc DynamicWorld -[.cxx_destruct]',
        selectors={
                 0x906cc0: (15216012, 'pos'),
        },
        imports={},
        ivars={
                 0x906cac: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x906cb4: (17162364, 'OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition', 2400),
        },
        classes={},
        instructions=[(9464216, 'push {r4, sl, fp, lr}'), (9464348, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9464472, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9464504, 'bl method.unsigned_long_std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__erase_unique_DynamicObject__DynamicObject_const_'), (9464628, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9464792, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9465032, 'rsbseq sb, r5, r4, asr 2')],
        calls=[(9464348, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9464412, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__count_unique_unsigned_long_long__unsigned_long_long_const__const'), (9464472, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9464504, 'bl method.unsigned_long_std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__erase_unique_DynamicObject__DynamicObject_const_'), (9464628, 'bl method.unsigned_long_std::__1::__tree_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_______std::__1::__map_value_compare_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___true___std::__1::allocator_std::__1::pair_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.__erase_unique_unsigned_long_long__unsigned_long_long_const_'), (9464692, 'bl loc.imp.objc_msgSend_stret'), (9464728, 'bl sym.imp.memset'), (9464792, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9464852, 'bl method.std::__1::map_unsigned_long_long__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_____std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__std::__1::set_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject_________.operator___unsigned_long_long_'), (9464896, 'bl method.std::__1::__tree_DynamicObject__std::__1::less_DynamicObject___std::__1::allocator_DynamicObject___.__insert_unique_DynamicObject_const_')],
        branches=[(9464420, 'bls', 9464640), (9464560, 'bne', 9464636), (9464636, 'b', 9464640), (9464676, 'beq', 9464700), (9464696, 'b', 9464732)],
        semantics=("freeblockPositionChanged:oldPos: moves a free block's registry entry. Prologue 0x00906998 (frame 0x100; base 0x105faf4). Args: the block, oldPos.\nUnregister old: `worldIndexAtWorldPos(oldPos, world)` (@0x906a1c) -> the **ffffe588 registry** `__count_unique` (@0x906a5c) -> `operator[](u64&&)` (@0x906a98) -> the per-pos set; the object is removed via the **set's `__erase_unique`** (@0x906ab8); when the set empties (`[r1+8]` NULL check @0x906ae4-0x906af4) the **map's `__erase_unique(u64)`** drops the position (@0x906b34).\nRe-register new: the second `worldIndexAtWorldPos` (newPos @0x906bd8) repeats the registry walk (the continuation from 0x906bf0) to insert the object at the new position. Full writer+reader of E24's ffffe588 registration.\n"),
    ),
    dict(
        name='wtl_requestpaintingdatafor',
        method='DynamicWorld -[requestPaintingDataForPainting:]',
        types='v12@0:4@8',
        start=9442656,
        end=9443008,
        disasm='disasm_worldtileloader_requestpaintingdataforpainting_.txt',
        base_add=9442672,
        base_literal=9443004,
        boundary='ARM.exidx end 0x009016c0 (listing bound); next ObjC IMP 0x009016c0 DynamicWorld -[sendPaintingDataForPaintingWithID:toClient:]',
        selectors={
                 0x9016a0: (15216192, 'sendDataToServer:reliable:'),
                 0x9016a8: (15216220, 'appendBytes:length:'),
                 0x9016b4: (15216180, 'dataWithBytes:length:'),
                 0x9016b8: (15216160, 'uniqueID'),
        },
        imports={
                 0x90169c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9016a4: (17162252, 'OBJC_IVAR_$_DynamicWorld.client', 20),
        },
        classes={
                 0x9016ac: (15247844, 'OBJC_CLASS_$_NSMutableData'),
        },
        instructions=[(9442656, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9442700, 'ldr r6, [0x009016a4]'), (9442736, 'mov r0, 0x30'), (9442840, 'bl loc.imp.objc_msgSend'), (9442852, 'ldr r1, [0x009016b8]'), (9443004, 'rsbseq lr, r5, ip, ror r5')],
        calls=[(9442840, 'bl loc.imp.objc_msgSend'), (9442864, 'bl loc.imp.objc_msgSend'), (9442912, 'blx ip'), (9442960, 'blx lr')],
        branches=[],
        semantics=("requestPaintingDataForPainting: requests a painting's pixel data from the server. Prologue 0x00901560 (frame 0x68; base 0x105faf4). Argument: the painting.\nGate: self.client (ffffe518, cell 0x9016a4) != 0 -> the request path.\nBuild: the ffe2aef0 class + ffe23340 (last client blockhead uniqueID) + the byte 0x30 at fp-0x25 and `mov r0, 1`/r7 = 8 message frame (@0x9015b0-0x901618); the painting's `[uniqueID]` (ffe2332c @0x901624) completes the request; the socket send helper follows.\n"),
    ),
    dict(
        name='wtl_paintingdatarecievedfr',
        method='DynamicWorld -[paintingDataRecievedFromServer:]',
        types='v12@0:4@8',
        start=9443752,
        end=9444184,
        disasm='disasm_worldtileloader_paintingdatarecievedfromserver_.txt',
        base_add=9443768,
        base_literal=9444180,
        boundary='ARM.exidx end 0x00901b58 (listing bound); next ObjC IMP 0x00901b58 DynamicWorld -[sendChestInventoryForChest:toClientOwningBlockheadWithID:]',
        selectors={
                 0x901b34: (15217276, 'paintingWithID:'),
                 0x901b38: (15216436, 'getBytes:length:'),
                 0x901b40: (15216188, 'length'),
                 0x901b48: (15217284, 'subdataWithRange:'),
                 0x901b50: (15217288, 'imageDataRecieved:'),
        },
        imports={
                 0x901b4c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9443752, 'push {r4, sl, fp, lr}'), (9443816, 'mov r4, 8'), (9443944, 'sub r0, r0, 8'), (9443976, 'ldr r1, [0x00901b48]'), (9444024, 'cmp r0, r1'), (9444180, 'rsbseq lr, r5, r4, lsr r1')],
        calls=[(9443848, 'bl loc.imp.objc_msgSend'), (9443872, 'bl loc.imp.objc_msgSend'), (9443940, 'bl loc.imp.objc_msgSend'), (9444008, 'bl loc.imp.objc_msgSend'), (9444072, 'blx r2'), (9444132, 'blx r3')],
        branches=[(9443892, 'beq', 9444140), (9444028, 'beq', 9444136), (9444080, 'bls', 9444136), (9444136, 'b', 9444140)],
        semantics=("paintingDataRecievedFromServer: applies received painting data. Prologue 0x009019a8 (frame 0x60; base 0x105faf4). Argument: the data.\nParse: the payload is read with `mov r4, 8` (@0x9019e8); the second chunk's 8-byte tail is sliced (`sub r0, r0, 8; mov r1, 8` @0x901a68-0x901a6c) and read via the ffe23348 accessor (@0x901a88); the ffe23790 class + ffe23348 compare walk (@0x901ab8 `cmp r0, r1; beq 0x901b28`) resolves the target painting and applies the data (the tail from 0x901ac0).\n"),
    ),
    dict(
        name='wtl_chestinventorydatareci',
        method='DynamicWorld -[chestInventoryDataRecievedFromServer:]',
        types='v12@0:4@8',
        start=9445732,
        end=9446388,
        disasm='disasm_worldtileloader_chestinventorydatarecievedfromserver_.txt',
        base_add=9445748,
        base_literal=9446384,
        boundary='ARM.exidx end 0x009023f4 (listing bound); next ObjC IMP 0x009023f4 DynamicWorld -[userMuteChanged:]',
        selectors={
                 0x9023b8: (15217296, 'interactionObjectWithID:'),
                 0x9023bc: (15216436, 'getBytes:length:'),
                 0x9023c8: (15216140, 'isKindOfClass:'),
                 0x9023cc: (15216136, 'class'),
                 0x9023d4: (15216188, 'length'),
                 0x9023dc: (15217284, 'subdataWithRange:'),
                 0x9023e0: (15217304, 'updateChestUI'),
                 0x9023e4: (15216636, 'uiManager'),
                 0x9023ec: (15217300, 'remoteInventoryDataRecieved:'),
        },
        imports={
                 0x9023c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9023e8: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
        },
        classes={
                 0x9023d0: (15247984, 'OBJC_CLASS_$_Chest'),
        },
        instructions=[(9445732, 'push {r4, r5, r6, r7, fp, lr}'), (9445804, 'mov r0, r2'), (9446056, 'bls 0x902314'), (9446096, 'mov r1, 8'), (9446124, 'ldr r1, [0x009023dc]'), (9445972, 'mov r0, r2'), (9446384, 'rsbseq sp, r5, r8, ror sb')],
        calls=[(9445828, 'bl loc.imp.objc_msgSend'), (9445852, 'bl loc.imp.objc_msgSend'), (9445952, 'blx ip'), (9445984, 'blx r3'), (9446048, 'blx r2'), (9446088, 'bl loc.imp.objc_msgSend'), (9446156, 'bl loc.imp.objc_msgSend'), (9446264, 'blx r5'), (9446300, 'blx r3'), (9446316, 'blx r2')],
        branches=[(9445872, 'beq', 9446320), (9445996, 'beq', 9446320), (9446056, 'bls', 9446164)],
        semantics=("chestInventoryDataRecievedFromServer: applies received chest-inventory data. Prologue 0x00902164 (frame 0x90; base 0x105faf4). Argument: the data.\nGate+parse: the ffe23440 check (@0x9021ac) + `cmp r0, 8; bls 0x902314` (@0x9022a4-0x9022a8): payloads longer than the 8-byte header proceed; the ffe23348 8-byte tail read (`sub r0, r0, 8; mov r1, 8` @0x9022cc-0x9022d0) + the ffe23790 alloc/parse (@0x9022ec) + the ffe2af7c class check (@0x902214-0x902260) resolve the chest and apply the inventory — the client side of E28's sendChestInventoryForChest:.\n"),
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
        'batch': 'DynamicWorld remote-receive/painting/chest smalls (E32): remoteCreationDataUpdate:forObjectsOfType:fromClient:, remoteUpdate:forObjectsOfType:fromClient:, snowChangedAtMacroPos:, npcExistsAtPos:ignoreNPC:, freeblockPositionChanged:oldPos:, requestPaintingDataForPainting:, paintingDataRecievedFromServer: and chestInventoryDataRecievedFromServer:; 8 bodies',
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
                        default=NATIVE / 'remote_receive.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale remote_receive.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
