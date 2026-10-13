#!/usr/bin/env python3
"""Hash-gated recovery of the Action (E154).

The action-queue entry object lands: the batch sweeps the addressed action parameters surface:
35 bodies, {total} instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/ACTION.md for the prose and boundaries.
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
    'bl sym.imp.objc_copyStruct': 0x001c2888,
    'bl sym.imp.objc_setProperty_atomic': 0x001c2f3c,
}

SPECS = [
    dict(
        name='ac_00',
        method='Action -[.cxx_construct]',
        types='@8@0:4',
        start=7565580,
        end=7565604,
        disasm='disasm_worldtileloader_ac_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00737124 (listing bound); next ObjC IMP 0x00737284 TradingPostSellUI -[loadResources]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7565580, 'sub sp, sp, 8'), (7565600, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('Action -[.cxx_construct] @0x73710c (6 words, @8@0:4): empty synthesized ObjC++ constructor stub - sub sp,#8 / spill self+_cmd / ldr r0,[sp,4] / add sp,#8 / bx lr. Returns self untouched; zero ivar init, no PIC cell, no calls. Bound: exidx 0x737124; next IMP is TradingPostSellUI -[loadResources] @0x737284.'),
    ),
    dict(
        name='ac_01',
        method='Action -[animationTimer]',
        types='f8@0:4',
        start=7564820,
        end=7564892,
        disasm='disasm_worldtileloader_ac_01.txt',
        base_add=7564844,
        base_literal=7564888,
        boundary='ARM.exidx end 0x00736ea8; body trimmed at the next IMP 0x00736e5c Action -[setAnimationTimer:]',
        selectors={},
        imports={},
        ivars={
                 0x736e54: (17159304, 'OBJC_IVAR_$_Action.animationTimer', 68),
        },
        classes={},
        instructions=[(7564820, 'sub sp, sp, 0xc'), (7564888, 'addseq r8, r2, r0, asr 25')],
        calls=[],
        branches=[],
        semantics=('Action -[animationTimer] @0x736e14 (18 words, f8@0:4): float getter of animationTimer@68 via the Apportable offset cell .got 0x0105d488 (= s32(pool 0xffffd994) + PIC base 0x0105faf4) whose content 0x00f33644 is the OBJC_IVAR_$_Action.animationTimer word, first word = 68. `ldr r0,[r0,r1]` reads the 32-bit field, `dmb ish`, spill, `vldr s0,[sp,8]; vmov r0,s0` returns the float in r0 (soft-float style int move). No calls/branches; body trimmed at next IMP 0x736e5c (setAnimationTimer:), pool words 0x736e54/58.'),
    ),
    dict(
        name='ac_02',
        method='Action -[blockCube]',
        types='@8@0:4',
        start=7565232,
        end=7565288,
        disasm='disasm_worldtileloader_ac_02.txt',
        base_add=7565256,
        base_literal=7565284,
        boundary='ARM.exidx end 0x00736fe8 (listing bound); next ObjC IMP 0x00736fe8 Action -[setBlockCube:]',
        selectors={},
        imports={},
        ivars={
                 0x736fe0: (17159316, 'OBJC_IVAR_$_Action.blockCube', 48),
        },
        classes={},
        instructions=[(7565232, 'sub sp, sp, 8'), (7565284, 'addseq r8, r2, r4, lsr 22')],
        calls=[],
        branches=[],
        semantics=('Action -[blockCube] @0x736fb0 (14 words, @8@0:4): object getter of blockCube@48 (@DrawCube). Cell .got 0x0105d494 (pool 0xffffd9a0) -> ivar word 0x00f3364c = 48; tail-branch `b sym.imp.objc_getProperty` with r0=self, r1=_cmd, r2=48, r3=1 (atomic) after `mov r3,1; add sp,#8`.'),
    ),
    dict(
        name='ac_03',
        method='Action -[complete]',
        types='c8@0:4',
        start=7563360,
        end=7563420,
        disasm='disasm_worldtileloader_ac_03.txt',
        base_add=7563368,
        base_literal=7563416,
        boundary='ARM.exidx end 0x0073689c (listing bound); next ObjC IMP 0x0073689c Action -[setComplete:]',
        selectors={},
        imports={},
        ivars={
                 0x736894: (17159320, 'OBJC_IVAR_$_Action.complete', 5),
        },
        classes={},
        instructions=[(7563360, 'sub sp, sp, 8'), (7563416, 'addseq sb, r2, r4, lsl 5')],
        calls=[],
        branches=[],
        semantics=('Action -[complete] @0x736860 (15 words, c8@0:4): signed-char getter of complete@5. Merged single-stage cell idiom: `ldr r2,[0x736898]=0x929284; add r2,pc,r2` = PIC base 0x0105faf4, then `ldr r3,[0x736894]=0xffffd9a4; ldr r2,[r3,r2]` = cell .got 0x0105d498 -> ivar word 0x00f33650 = 5; `ldrsb r0,[self+5]` returns. No dmb (unlike the int/float getters), no calls/branches.'),
    ),
    dict(
        name='ac_04',
        method='Action -[craftCountOrExtraData]',
        types='s8@0:4',
        start=7565100,
        end=7565160,
        disasm='disasm_worldtileloader_ac_04.txt',
        base_add=7565108,
        base_literal=7565156,
        boundary='ARM.exidx end 0x00736f68 (listing bound); next ObjC IMP 0x00736f68 Action -[setCraftCountOrExtraData:]',
        selectors={},
        imports={},
        ivars={
                 0x736f60: (17159268, 'OBJC_IVAR_$_Action.craftCountOrExtraData', 44),
        },
        classes={},
        instructions=[(7565100, 'sub sp, sp, 8'), (7565156, 'ldrheq r8, [r2], r8')],
        calls=[],
        branches=[],
        semantics=('Action -[craftCountOrExtraData] @0x736f2c (15 words, s8@0:4): signed-short getter of craftCountOrExtraData@44. Cell .got 0x0105d464 (pool 0xffffd970) -> ivar word 0x00f33634 = 44; `ldrsh r0,[self+44]` sign-extends the 16-bit field; no dmb, no calls.'),
    ),
    dict(
        name='ac_05',
        method='Action -[craftableItemObject]',
        types='@8@0:4',
        start=7564968,
        end=7565024,
        disasm='disasm_worldtileloader_ac_05.txt',
        base_add=7564992,
        base_literal=7565020,
        boundary='ARM.exidx end 0x00736ee0 (listing bound); next ObjC IMP 0x00736ee0 Action -[setCraftableItemObject:]',
        selectors={},
        imports={},
        ivars={
                 0x736ed8: (17159272, 'OBJC_IVAR_$_Action.craftableItemObject', 40),
        },
        classes={},
        instructions=[(7564968, 'sub sp, sp, 8'), (7565020, 'addseq r8, r2, ip, lsr 24')],
        calls=[],
        branches=[],
        semantics=('Action -[craftableItemObject] @0x736ea8 (14 words, @8@0:4): object getter of craftableItemObject@40 (@CraftableItemObject). Cell .got 0x0105d468 (pool 0xffffd974) -> ivar word 0x00f33630 = 40; tail-branch `b sym.imp.objc_getProperty` (self, _cmd, 40, atomic=1).'),
    ),
    dict(
        name='ac_06',
        method='Action -[dealloc]',
        types='v8@0:4',
        start=7562828,
        end=7563232,
        disasm='disasm_worldtileloader_ac_06.txt',
        base_add=7562844,
        base_literal=7563228,
        boundary='ARM.exidx end 0x007367e0 (listing bound); next ObjC IMP 0x007367e0 Action -[inProgress]',
        selectors={
                 0x7367b8: (15206724, 'dealloc'),
                 0x7367c4: (15206720, 'release'),
                 0x7367d4: (15206716, 'autorelease'),
        },
        imports={
                 0x7367b4: (17151900, 'objc_msgSendSuper2'),
                 0x7367c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7367c8: (17159260, 'OBJC_IVAR_$_Action.inventoryChange', 64),
                 0x7367cc: (17159316, 'OBJC_IVAR_$_Action.blockCube', 48),
                 0x7367d0: (17159272, 'OBJC_IVAR_$_Action.craftableItemObject', 40),
                 0x7367d8: (17159288, 'OBJC_IVAR_$_Action.interactionItem', 16),
        },
        classes={
                 0x7367bc: (15252740, 'OBJC_CLASS_$_Action'),
        },
        instructions=[(7562828, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7563228, 'umullseq sb, r2, r0, r4')],
        calls=[(7563016, 'blx r5'), (7563064, 'blx ip'), (7563100, 'blx r3'), (7563136, 'blx r3'), (7563176, 'blx r2')],
        branches=[],
        semantics=('Action -[dealloc] @0x73664c (101 words, v8@0:4): one straight-line teardown block, 0 conditional branches, 5 indirect calls. Pre-resolves from PIC-relative pools: objc_msgSendSuper2 (.got 0x0105b79c), objc_msgSend (.got 0x0105b7a0), selrefs \'autorelease\' (0x00e8093c), \'release\' (0x00e80940), \'dealloc\' (0x00e80944), and superref 0x00e8bd04 (content = Action class 0x00e90da0). Calls: (1) objc_msgSend(self->interactionItem@16, @selector(autorelease)) - autorelease, NOT release; (2) objc_msgSend(self->craftableItemObject@40, release); (3) objc_msgSend(self->blockCube@48, release); (4) objc_msgSend(self->inventoryChange@64, release); (5) objc_msgSendSuper2(&(struct objc_super){self, Action-class}, @selector(dealloc)) = [super dealloc]. All five go through blx on spilled GOT fn pointers (r5/ip/r3/r2); epilogue sub sp,fp,#0x18; pop {r4-r8,sl,fp,pc}. Covers all four object ivars (interactionItem, craftableItemObject, blockCube, inventoryChange).'),
    ),
    dict(
        name='ac_07',
        method='Action -[goalInteraction]',
        types='i8@0:4',
        start=7564436,
        end=7564496,
        disasm='disasm_worldtileloader_ac_07.txt',
        base_add=7564460,
        base_literal=7564492,
        boundary='ARM.exidx end 0x00736cd0 (listing bound); next ObjC IMP 0x00736cd0 Action -[setGoalInteraction:]',
        selectors={},
        imports={},
        ivars={
                 0x736cc8: (17159280, 'OBJC_IVAR_$_Action.goalInteraction', 24),
        },
        classes={},
        instructions=[(7564436, 'sub sp, sp, 8'), (7564492, 'addseq r8, r2, r0, asr 28')],
        calls=[],
        branches=[],
        semantics=('Action -[goalInteraction] @0x736c94 (15 words, i8@0:4): int getter of goalInteraction@24. Cell .got 0x0105d470 (pool 0xffffd97c) -> ivar word 0x00f33618 = 24; `ldr r0,[r0,r1]; dmb ish` then return r0.'),
    ),
    dict(
        name='ac_08',
        method='Action -[goalTilePos]',
        types='{?=ii}8@0:4',
        start=7563488,
        end=7563584,
        disasm='disasm_worldtileloader_ac_08.txt',
        base_add=7563504,
        base_literal=7563580,
        boundary='ARM.exidx end 0x00736940 (listing bound); next ObjC IMP 0x00736940 Action -[setGoalTilePos:]',
        selectors={},
        imports={},
        ivars={
                 0x736938: (17159276, 'OBJC_IVAR_$_Action.goalTilePos', 8),
        },
        classes={},
        instructions=[(7563488, 'push {r4, r5, fp, lr}'), (7563580, 'ldrsheq sb, [r2], ip')],
        calls=[(7563564, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('Action -[goalTilePos] @0x7368e0 (24 words, {?=ii}8@0:4): 8-byte {x,y} struct getter of goalTilePos@8. Cell .got 0x0105d46c (pool 0xffffd978) -> ivar word 0x00f33614 = 8. Composite >4 bytes so AAPCS passes the return buffer in r0: the spills are self=[sp,0xc], _cmd=[sp,8]; r1 = self+8 is the SOURCE and `bl sym.imp.objc_copyStruct` @0x73692c copies (dest=r0, src=self+8, size=8, atomic=1, hasStrong=0) - movw ip,#8 / lr=1 / r4=0 feed the flags.'),
    ),
    dict(
        name='ac_09',
        method='Action -[inProgress]',
        types='c8@0:4',
        start=7563232,
        end=7563292,
        disasm='disasm_worldtileloader_ac_09.txt',
        base_add=7563240,
        base_literal=7563288,
        boundary='ARM.exidx end 0x0073681c (listing bound); next ObjC IMP 0x0073681c Action -[setInProgress:]',
        selectors={},
        imports={},
        ivars={
                 0x736814: (17159308, 'OBJC_IVAR_$_Action.inProgress', 4),
        },
        classes={},
        instructions=[(7563232, 'sub sp, sp, 8'), (7563288, 'addseq sb, r2, r4, lsl 6')],
        calls=[],
        branches=[],
        semantics=('Action -[inProgress] @0x7367e0 (15 words, c8@0:4): signed-char getter of inProgress@4. Cell .got 0x0105d48c (pool 0xffffd998) -> ivar word 0x00f33640 = 4; `ldrsb r0,[self+4]`; no dmb, no calls.'),
    ),
    dict(
        name='ac_10',
        method='Action -[initWithGoalPos:goalInteraction:pathType:interactionItem:itemIndex:itemSubIndex:interactionObjectID:craftableItemObject:craftCountOrExtraData:isAI:inventoryChange:]',
        types='@60@0:4{?=ii}8i16i20@24s28s32Q36@44s48c52@56',
        start=7556708,
        end=7557528,
        disasm='disasm_worldtileloader_ac_10.txt',
        base_add=7556724,
        base_literal=7557524,
        boundary='ARM.exidx end 0x00735198 (listing bound); next ObjC IMP 0x00735198 Action -[initWithSaveDict:inventoryItems:]',
        selectors={
                 0x735154: (15206632, 'init'),
                 0x735164: (15206636, 'retain'),
        },
        imports={
                 0x735150: (17151900, 'objc_msgSendSuper2'),
                 0x735160: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x73515c: (17159260, 'OBJC_IVAR_$_Action.inventoryChange', 64),
                 0x735168: (17159264, 'OBJC_IVAR_$_Action.isAI', 6),
                 0x73516c: (17159268, 'OBJC_IVAR_$_Action.craftCountOrExtraData', 44),
                 0x735170: (17159272, 'OBJC_IVAR_$_Action.craftableItemObject', 40),
                 0x735174: (17159276, 'OBJC_IVAR_$_Action.goalTilePos', 8),
                 0x73517c: (17159280, 'OBJC_IVAR_$_Action.goalInteraction', 24),
                 0x735180: (17159284, 'OBJC_IVAR_$_Action.pathType', 28),
                 0x735184: (17159288, 'OBJC_IVAR_$_Action.interactionItem', 16),
                 0x735188: (17159292, 'OBJC_IVAR_$_Action.interactionItemIndex', 20),
                 0x73518c: (17159296, 'OBJC_IVAR_$_Action.interactionItemSubIndex', 22),
                 0x735190: (17159300, 'OBJC_IVAR_$_Action.interactionObjectID', 32),
        },
        classes={
                 0x735158: (15252740, 'OBJC_CLASS_$_Action'),
        },
        instructions=[(7556708, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7557524, 'addseq sl, r2, r8, ror ip')],
        calls=[(7556956, 'blx lr'), (7557192, 'bl loc.imp.objc_msgSend'), (7557324, 'blx r2'), (7557412, 'blx lr')],
        branches=[(7556984, 'bne', 7557000), (7556996, 'b', 7557444)],
        semantics=('Action -[initWithGoalPos:goalInteraction:pathType:interactionItem:itemIndex:itemSubIndex:interactionObjectID:craftableItemObject:craftCountOrExtraData:isAI:inventoryChange:] @0x734e64 (205 words - batch heavyweight; 4 calls, 2 branches). Prologue fp=sp+0x18 grabs all stack params; builds objc_super on stack ([sp+0x48]=self, [sp+0x4c]=*(superref 0xe8bd04)=Action class 0x00e90da0) and calls objc_msgSendSuper2(&super, @selector(init)) via .got 0x0105b79c + selref \'init\' 0x00e808e8 (blx lr @0x734f5c); `cmp r1,r0; bne 0x734f88` skips to an early `return nil` (b 0x735144) when [super init] returned nil. Else stores, in order: goalTilePos@8 <- {r2,r3} goalPos pair (`str sl,[r5,r6]; str r1,[r8,4]`), goalInteraction@24, pathType@28, interactionItem@16 <- objc_msgSend(param, @selector(retain)) [bl loc.imp.objc_msgSend @0x735048; selref \'retain\' 0x00e808ec], interactionItemIndex@20 (strh), interactionItemSubIndex@22 (strh), interactionObjectID@32 (8-byte pair via `str r0,[r2,ip]!; str r1,[r2,4]`), craftableItemObject@40 <- retain(param) (blx r2 @0x7350cc), craftCountOrExtraData@44 (strh), isAI@6 (strb), inventoryChange@64 <- retain(param) (blx lr @0x735124); returns self. Frame detail: the declared encoding \'@60@0:4{?=ii}8i16i20@24s28s32Q36@44s48c52@56\' has the 8-byte Q at frame 36, but the callee actually loads it from [fp+0x20]/[fp+0x24] (frames 40/44 - 4-byte alignment pad at frame 36) and reads the tail params from frames 48/52/56/60 (encoder labels 44/48/52/56); all 16 cell references resolve to the expected OBJC_IVAR_$_Action words.'),
    ),
    dict(
        name='ac_11',
        method='Action -[interactionItem]',
        types='@8@0:4',
        start=7563828,
        end=7563884,
        disasm='disasm_worldtileloader_ac_11.txt',
        base_add=7563852,
        base_literal=7563880,
        boundary='ARM.exidx end 0x00736a6c (listing bound); next ObjC IMP 0x00736a6c Action -[setInteractionItem:]',
        selectors={},
        imports={},
        ivars={
                 0x736a64: (17159288, 'OBJC_IVAR_$_Action.interactionItem', 16),
        },
        classes={},
        instructions=[(7563828, 'sub sp, sp, 8'), (7563880, 'addseq sb, r2, r0, lsr 1')],
        calls=[],
        branches=[],
        semantics=('Action -[interactionItem] @0x736a34 (14 words, @8@0:4): object getter of interactionItem@16 (@InventoryItem). Cell .got 0x0105d478 (pool 0xffffd984) -> ivar word 0x00f33620 = 16; tail-branch `b sym.imp.objc_getProperty` (self, _cmd, 16, atomic=1).'),
    ),
    dict(
        name='ac_12',
        method='Action -[interactionItemIndex]',
        types='s8@0:4',
        start=7563960,
        end=7564020,
        disasm='disasm_worldtileloader_ac_12.txt',
        base_add=7563968,
        base_literal=7564016,
        boundary='ARM.exidx end 0x00736af4 (listing bound); next ObjC IMP 0x00736af4 Action -[setInteractionItemIndex:]',
        selectors={},
        imports={},
        ivars={
                 0x736aec: (17159292, 'OBJC_IVAR_$_Action.interactionItemIndex', 20),
        },
        classes={},
        instructions=[(7563960, 'sub sp, sp, 8'), (7564016, 'addseq sb, r2, ip, lsr 32')],
        calls=[],
        branches=[],
        semantics=('Action -[interactionItemIndex] @0x736ab8 (15 words, s8@0:4): signed-short getter of interactionItemIndex@20. Cell .got 0x0105d47c (pool 0xffffd988) -> ivar word 0x00f33624 = 20; `ldrsh r0,[self+20]`; no dmb, no calls.'),
    ),
    dict(
        name='ac_13',
        method='Action -[interactionItemSubIndex]',
        types='s8@0:4',
        start=7564092,
        end=7564152,
        disasm='disasm_worldtileloader_ac_13.txt',
        base_add=7564100,
        base_literal=7564148,
        boundary='ARM.exidx end 0x00736b78 (listing bound); next ObjC IMP 0x00736b78 Action -[setInteractionItemSubIndex:]',
        selectors={},
        imports={},
        ivars={
                 0x736b70: (17159296, 'OBJC_IVAR_$_Action.interactionItemSubIndex', 22),
        },
        classes={},
        instructions=[(7564092, 'sub sp, sp, 8'), (7564148, 'addseq r8, r2, r8, lsr 31')],
        calls=[],
        branches=[],
        semantics=('Action -[interactionItemSubIndex] @0x736b3c (15 words, s8@0:4): signed-short getter of interactionItemSubIndex@22. Cell .got 0x0105d480 (pool 0xffffd98c) -> ivar word 0x00f33628 = 22; `ldrsh r0,[self+22]`; no dmb, no calls.'),
    ),
    dict(
        name='ac_14',
        method='Action -[interactionObjectID]',
        types='Q8@0:4',
        start=7564224,
        end=7564324,
        disasm='disasm_worldtileloader_ac_14.txt',
        base_add=7564256,
        base_literal=7564320,
        boundary='ARM.exidx end 0x00736c24 (listing bound); next ObjC IMP 0x00736c24 Action -[setInteractionObjectID:]',
        selectors={},
        imports={},
        ivars={
                 0x736c1c: (17159300, 'OBJC_IVAR_$_Action.interactionObjectID', 32),
        },
        classes={},
        instructions=[(7564224, 'push {fp, lr}'), (7564320, 'addseq r8, r2, ip, lsl 30')],
        calls=[(7564296, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('Action -[interactionObjectID] @0x736bc0 (25 words, Q8@0:4): 64-bit getter of interactionObjectID@32. Cell .got 0x0105d484 (pool 0xffffd990) -> ivar word 0x00f3362c = 32. Returns the scalar in r0/r1 but routes through a stack temp: zeroes the hasStrong arg slot (`mov r0,sp; mov r2,0; str r2,[r0]`), dst=fp-8, then `bl sym.imp.objc_copyStruct` @0x736c08 (dest=fp-8, src=self+32, size=8, atomic=1, hasStrong=0); returns `ldr r0,[fp,-8]; ldr r1,[fp,-4]`.'),
    ),
    dict(
        name='ac_15',
        method='Action -[interactionTestResult]',
        types='{InteractionTestResult=iiSS}8@0:4',
        start=7565364,
        end=7565460,
        disasm='disasm_worldtileloader_ac_15.txt',
        base_add=7565380,
        base_literal=7565456,
        boundary='ARM.exidx end 0x00737094 (listing bound); next ObjC IMP 0x00737094 Action -[setInteractionTestResult:]',
        selectors={},
        imports={},
        ivars={
                 0x73708c: (17159312, 'OBJC_IVAR_$_Action.interactionTestResult', 52),
        },
        classes={},
        instructions=[(7565364, 'push {r4, r5, fp, lr}'), (7565456, 'addseq r8, r2, r8, lsr 21')],
        calls=[(7565440, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('Action -[interactionTestResult] @0x737034 (24 words, {InteractionTestResult=iiSS}8@0:4): 12-byte struct getter of interactionTestResult@52 (struct = {goodOrBad i, renderItemType i, renderItemDataA S, renderItemDataB S}, see methtype string @0x1029c6a). Cell .got 0x0105d490 (pool 0xffffd99c) -> ivar word 0x00f33648 = 52. Composite >4 bytes => hidden return buffer in r0 is the dest; src=self+52; `bl sym.imp.objc_copyStruct` @0x737080 (size=0xc via movw ip,#0xc, atomic=1, hasStrong=0).'),
    ),
    dict(
        name='ac_16',
        method='Action -[inventoryChange]',
        types='@8@0:4',
        start=7563696,
        end=7563752,
        disasm='disasm_worldtileloader_ac_16.txt',
        base_add=7563720,
        base_literal=7563748,
        boundary='ARM.exidx end 0x007369e8 (listing bound); next ObjC IMP 0x007369e8 Action -[setInventoryChange:]',
        selectors={},
        imports={},
        ivars={
                 0x7369e0: (17159260, 'OBJC_IVAR_$_Action.inventoryChange', 64),
        },
        classes={},
        instructions=[(7563696, 'sub sp, sp, 8'), (7563748, 'addseq sb, r2, r4, lsr 2')],
        calls=[],
        branches=[],
        semantics=('Action -[inventoryChange] @0x7369b0 (14 words, @8@0:4): object getter of inventoryChange@64 (@NSDictionary). Cell .got 0x0105d45c (pool 0xffffd968) -> ivar word 0x00f3363c = 64; tail-branch `b sym.imp.objc_getProperty` (self, _cmd, 64, atomic=1).'),
    ),
    dict(
        name='ac_17',
        method='Action -[isAI]',
        types='c8@0:4',
        start=7564692,
        end=7564752,
        disasm='disasm_worldtileloader_ac_17.txt',
        base_add=7564700,
        base_literal=7564748,
        boundary='ARM.exidx end 0x00736dd0 (listing bound); next ObjC IMP 0x00736dd0 Action -[setIsAI:]',
        selectors={},
        imports={},
        ivars={
                 0x736dc8: (17159264, 'OBJC_IVAR_$_Action.isAI', 6),
        },
        classes={},
        instructions=[(7564692, 'sub sp, sp, 8'), (7564748, 'addseq r8, r2, r0, asr sp')],
        calls=[],
        branches=[],
        semantics=('Action -[isAI] @0x736d94 (15 words, c8@0:4): signed-char getter of isAI@6. Cell .got 0x0105d460 (pool 0xffffd96c) -> ivar word 0x00f33638 = 6; `ldrsb r0,[self+6]`; no dmb, no calls.'),
    ),
    dict(
        name='ac_18',
        method='Action -[pathType]',
        types='i8@0:4',
        start=7564564,
        end=7564624,
        disasm='disasm_worldtileloader_ac_18.txt',
        base_add=7564588,
        base_literal=7564620,
        boundary='ARM.exidx end 0x00736d50 (listing bound); next ObjC IMP 0x00736d50 Action -[setPathType:]',
        selectors={},
        imports={},
        ivars={
                 0x736d48: (17159284, 'OBJC_IVAR_$_Action.pathType', 28),
        },
        classes={},
        instructions=[(7564564, 'sub sp, sp, 8'), (7564620, 'addseq r8, r2, r0, asr 27')],
        calls=[],
        branches=[],
        semantics=('Action -[pathType] @0x736d14 (15 words, i8@0:4): int getter of pathType@28. Cell .got 0x0105d474 (pool 0xffffd980) -> ivar word 0x00f3361c = 28; `ldr r0,[r0,r1]; dmb ish` then return r0.'),
    ),
    dict(
        name='ac_19',
        method='Action -[setAnimationTimer:]',
        types='v12@0:4f8',
        start=7564892,
        end=7564968,
        disasm='disasm_worldtileloader_ac_19.txt',
        base_add=7564924,
        base_literal=7564964,
        boundary='ARM.exidx end 0x00736ea8 (listing bound); next ObjC IMP 0x00736ea8 Action -[craftableItemObject]',
        selectors={},
        imports={},
        ivars={
                 0x736ea0: (17159304, 'OBJC_IVAR_$_Action.animationTimer', 68),
        },
        classes={},
        instructions=[(7564892, 'sub sp, sp, 0xc'), (7564964, 'addseq r8, r2, r0, ror ip')],
        calls=[],
        branches=[],
        semantics=('Action -[setAnimationTimer:] @0x736e5c (19 words, v12@0:4f8): float setter of animationTimer@68. Incoming float in r2: `vmov s0,r2; vstr s0,[sp]` spill, reload `ldr r2,[sp]`, then nonatomic 32-bit store `dmb ish; str r2,[self+68]; dmb ish`. Cell .got 0x0105d488 (pool 0xffffd994) -> 0x00f33644 = 68; no calls.'),
    ),
    dict(
        name='ac_20',
        method='Action -[setBlockCube:]',
        types='v12@0:4@8',
        start=7565288,
        end=7565364,
        disasm='disasm_worldtileloader_ac_20.txt',
        base_add=7565304,
        base_literal=7565360,
        boundary='ARM.exidx end 0x00737034 (listing bound); next ObjC IMP 0x00737034 Action -[interactionTestResult]',
        selectors={},
        imports={},
        ivars={
                 0x73702c: (17159316, 'OBJC_IVAR_$_Action.blockCube', 48),
        },
        classes={},
        instructions=[(7565288, 'push {fp, lr}'), (7565360, 'ldrsheq r8, [r2], r4')],
        calls=[(7565344, 'bl sym.imp.objc_setProperty_atomic')],
        branches=[],
        semantics=('Action -[setBlockCube:] @0x736fe8 (19 words, v12@0:4@8): object setter of blockCube@48. Cell .got 0x0105d494 (pool 0xffffd9a0) -> ivar word 0x00f3364c = 48; `bl sym.imp.objc_setProperty_atomic(self, _cmd, value, 48)` @0x737020; epilogue mov sp,fp; pop {fp,pc}.'),
    ),
    dict(
        name='ac_21',
        method='Action -[setComplete:]',
        types='v12@0:4c8',
        start=7563420,
        end=7563488,
        disasm='disasm_worldtileloader_ac_21.txt',
        base_add=7563448,
        base_literal=7563484,
        boundary='ARM.exidx end 0x007368e0 (listing bound); next ObjC IMP 0x007368e0 Action -[goalTilePos]',
        selectors={},
        imports={},
        ivars={
                 0x7368d8: (17159320, 'OBJC_IVAR_$_Action.complete', 5),
        },
        classes={},
        instructions=[(7563420, 'sub sp, sp, 0xc'), (7563484, 'addseq sb, r2, r4, lsr r2')],
        calls=[],
        branches=[],
        semantics=('Action -[setComplete:] @0x73689c (17 words, v12@0:4c8): char setter of complete@5. Cell .got 0x0105d498 (pool 0xffffd9a4) -> 0x00f33650 = 5; `dmb ish; strb r2,[self+5]; dmb ish` (byte store). No calls.'),
    ),
    dict(
        name='ac_22',
        method='Action -[setCraftCountOrExtraData:]',
        types='v12@0:4s8',
        start=7565160,
        end=7565232,
        disasm='disasm_worldtileloader_ac_22.txt',
        base_add=7565188,
        base_literal=7565228,
        boundary='ARM.exidx end 0x00736fb0 (listing bound); next ObjC IMP 0x00736fb0 Action -[blockCube]',
        selectors={},
        imports={},
        ivars={
                 0x736fa8: (17159268, 'OBJC_IVAR_$_Action.craftCountOrExtraData', 44),
        },
        classes={},
        instructions=[(7565160, 'sub sp, sp, 0xc'), (7565228, 'addseq r8, r2, r8, ror 22')],
        calls=[],
        branches=[],
        semantics=('Action -[setCraftCountOrExtraData:] @0x736f68 (18 words, v12@0:4s8): short setter of craftCountOrExtraData@44. Cell .got 0x0105d464 (pool 0xffffd970) -> 0x00f33634 = 44; `strh r2,[self+44]` inside a `dmb ish` pair.'),
    ),
    dict(
        name='ac_23',
        method='Action -[setCraftableItemObject:]',
        types='v12@0:4@8',
        start=7565024,
        end=7565100,
        disasm='disasm_worldtileloader_ac_23.txt',
        base_add=7565040,
        base_literal=7565096,
        boundary='ARM.exidx end 0x00736f2c (listing bound); next ObjC IMP 0x00736f2c Action -[craftCountOrExtraData]',
        selectors={},
        imports={},
        ivars={
                 0x736f24: (17159272, 'OBJC_IVAR_$_Action.craftableItemObject', 40),
        },
        classes={},
        instructions=[(7565024, 'push {fp, lr}'), (7565096, 'ldrsheq r8, [r2], ip')],
        calls=[(7565080, 'bl sym.imp.objc_setProperty_atomic')],
        branches=[],
        semantics=('Action -[setCraftableItemObject:] @0x736ee0 (19 words, v12@0:4@8): object setter of craftableItemObject@40. Cell .got 0x0105d468 (pool 0xffffd974) -> 0x00f33630 = 40; `bl sym.imp.objc_setProperty_atomic(self, _cmd, value, 40)` @0x736f18.'),
    ),
    dict(
        name='ac_24',
        method='Action -[setGoalInteraction:]',
        types='v12@0:4i8',
        start=7564496,
        end=7564564,
        disasm='disasm_worldtileloader_ac_24.txt',
        base_add=7564524,
        base_literal=7564560,
        boundary='ARM.exidx end 0x00736d14 (listing bound); next ObjC IMP 0x00736d14 Action -[pathType]',
        selectors={},
        imports={},
        ivars={
                 0x736d0c: (17159280, 'OBJC_IVAR_$_Action.goalInteraction', 24),
        },
        classes={},
        instructions=[(7564496, 'sub sp, sp, 0xc'), (7564560, 'addseq r8, r2, r0, lsl 28')],
        calls=[],
        branches=[],
        semantics=('Action -[setGoalInteraction:] @0x736cd0 (17 words, v12@0:4i8): int setter of goalInteraction@24. Cell .got 0x0105d470 (pool 0xffffd97c) -> 0x00f33618 = 24; `dmb ish; str r2,[self+24]; dmb ish`.'),
    ),
    dict(
        name='ac_25',
        method='Action -[setGoalTilePos:]',
        types='v16@0:4{?=ii}8',
        start=7563584,
        end=7563696,
        disasm='disasm_worldtileloader_ac_25.txt',
        base_add=7563600,
        base_literal=7563692,
        boundary='ARM.exidx end 0x007369b0 (listing bound); next ObjC IMP 0x007369b0 Action -[inventoryChange]',
        selectors={},
        imports={},
        ivars={
                 0x7369a8: (17159276, 'OBJC_IVAR_$_Action.goalTilePos', 8),
        },
        classes={},
        instructions=[(7563584, 'push {r4, r5, r6, r7, fp, lr}'), (7563692, 'umullseq sb, r2, ip, r1')],
        calls=[(7563676, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('Action -[setGoalTilePos:] @0x736940 (28 words, v16@0:4{?=ii}8): 8-byte {x,y} struct setter of goalTilePos@8. Cell .got 0x0105d46c (pool 0xffffd978) -> 0x00f33614 = 8; the incoming pair {r2,r3} is spilled to sp+0x10 (src) and `bl sym.imp.objc_copyStruct` @0x73699c copies (dest=self+8, src=sp+0x10, size=8 via movw lr,#8, atomic=1, hasStrong=0 via movw r5,#0).'),
    ),
    dict(
        name='ac_26',
        method='Action -[setInProgress:]',
        types='v12@0:4c8',
        start=7563292,
        end=7563360,
        disasm='disasm_worldtileloader_ac_26.txt',
        base_add=7563320,
        base_literal=7563356,
        boundary='ARM.exidx end 0x00736860 (listing bound); next ObjC IMP 0x00736860 Action -[complete]',
        selectors={},
        imports={},
        ivars={
                 0x736858: (17159308, 'OBJC_IVAR_$_Action.inProgress', 4),
        },
        classes={},
        instructions=[(7563292, 'sub sp, sp, 0xc'), (7563356, 'ldrheq sb, [r2], r4')],
        calls=[],
        branches=[],
        semantics=('Action -[setInProgress:] @0x73681c (17 words, v12@0:4c8): char setter of inProgress@4. Cell .got 0x0105d48c (pool 0xffffd998) -> 0x00f33640 = 4; `dmb ish; strb r2,[self+4]; dmb ish`.'),
    ),
    dict(
        name='ac_27',
        method='Action -[setInteractionItem:]',
        types='v12@0:4@8',
        start=7563884,
        end=7563960,
        disasm='disasm_worldtileloader_ac_27.txt',
        base_add=7563900,
        base_literal=7563956,
        boundary='ARM.exidx end 0x00736ab8 (listing bound); next ObjC IMP 0x00736ab8 Action -[interactionItemIndex]',
        selectors={},
        imports={},
        ivars={
                 0x736ab0: (17159288, 'OBJC_IVAR_$_Action.interactionItem', 16),
        },
        classes={},
        instructions=[(7563884, 'push {fp, lr}'), (7563956, 'addseq sb, r2, r0, ror r0')],
        calls=[(7563940, 'bl sym.imp.objc_setProperty_atomic')],
        branches=[],
        semantics=('Action -[setInteractionItem:] @0x736a6c (19 words, v12@0:4@8): object setter of interactionItem@16. Cell .got 0x0105d478 (pool 0xffffd984) -> 0x00f33620 = 16; `bl sym.imp.objc_setProperty_atomic(self, _cmd, value, 16)` @0x736aa4.'),
    ),
    dict(
        name='ac_28',
        method='Action -[setInteractionItemIndex:]',
        types='v12@0:4s8',
        start=7564020,
        end=7564092,
        disasm='disasm_worldtileloader_ac_28.txt',
        base_add=7564048,
        base_literal=7564088,
        boundary='ARM.exidx end 0x00736b3c (listing bound); next ObjC IMP 0x00736b3c Action -[interactionItemSubIndex]',
        selectors={},
        imports={},
        ivars={
                 0x736b34: (17159292, 'OBJC_IVAR_$_Action.interactionItemIndex', 20),
        },
        classes={},
        instructions=[(7564020, 'sub sp, sp, 0xc'), (7564088, 'ldrsbeq r8, [r2], ip')],
        calls=[],
        branches=[],
        semantics=('Action -[setInteractionItemIndex:] @0x736af4 (18 words, v12@0:4s8): short setter of interactionItemIndex@20. Cell .got 0x0105d47c (pool 0xffffd988) -> 0x00f33624 = 20; `strh r2,[self+20]` in a `dmb ish` pair.'),
    ),
    dict(
        name='ac_29',
        method='Action -[setInteractionItemSubIndex:]',
        types='v12@0:4s8',
        start=7564152,
        end=7564224,
        disasm='disasm_worldtileloader_ac_29.txt',
        base_add=7564180,
        base_literal=7564220,
        boundary='ARM.exidx end 0x00736bc0 (listing bound); next ObjC IMP 0x00736bc0 Action -[interactionObjectID]',
        selectors={},
        imports={},
        ivars={
                 0x736bb8: (17159296, 'OBJC_IVAR_$_Action.interactionItemSubIndex', 22),
        },
        classes={},
        instructions=[(7564152, 'sub sp, sp, 0xc'), (7564220, 'addseq r8, r2, r8, asr pc')],
        calls=[],
        branches=[],
        semantics=('Action -[setInteractionItemSubIndex:] @0x736b78 (18 words, v12@0:4s8): short setter of interactionItemSubIndex@22. Cell .got 0x0105d480 (pool 0xffffd98c) -> 0x00f33628 = 22; `strh r2,[self+22]` in a `dmb ish` pair.'),
    ),
    dict(
        name='ac_30',
        method='Action -[setInteractionObjectID:]',
        types='v16@0:4Q8',
        start=7564324,
        end=7564436,
        disasm='disasm_worldtileloader_ac_30.txt',
        base_add=7564340,
        base_literal=7564432,
        boundary='ARM.exidx end 0x00736c94 (listing bound); next ObjC IMP 0x00736c94 Action -[goalInteraction]',
        selectors={},
        imports={},
        ivars={
                 0x736c8c: (17159300, 'OBJC_IVAR_$_Action.interactionObjectID', 32),
        },
        classes={},
        instructions=[(7564324, 'push {r4, r5, r6, r7, fp, lr}'), (7564432, 'ldrheq r8, [r2], r8')],
        calls=[(7564416, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('Action -[setInteractionObjectID:] @0x736c24 (28 words, v16@0:4Q8): 64-bit setter of interactionObjectID@32. Cell .got 0x0105d484 (pool 0xffffd990) -> 0x00f3362c = 32; the incoming Q pair {r3,r2} is spilled to sp+8/sp+0xc (src) and `bl sym.imp.objc_copyStruct` @0x736c80 copies (dest=self+32, src=sp+8, size=8, atomic=1, hasStrong=0).'),
    ),
    dict(
        name='ac_31',
        method='Action -[setInteractionTestResult:]',
        types='v20@0:4{InteractionTestResult=iiSS}8',
        start=7565460,
        end=7565580,
        disasm='disasm_worldtileloader_ac_31.txt',
        base_add=7565476,
        base_literal=7565576,
        boundary='ARM.exidx end 0x0073710c (listing bound); next ObjC IMP 0x0073710c Action -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x737104: (17159312, 'OBJC_IVAR_$_Action.interactionTestResult', 52),
        },
        classes={},
        instructions=[(7565460, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7565576, 'addseq r8, r2, r8, asr 20')],
        calls=[(7565560, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('Action -[setInteractionTestResult:] @0x737094 (30 words, v20@0:4{InteractionTestResult=iiSS}8): 12-byte struct setter of interactionTestResult@52. The composite arrives in r2,r3 + one stack word [fp,8]; the code spills the 12-byte copy to sp+0x10..[sp+0x18] (src) and `bl sym.imp.objc_copyStruct` @0x7370f8 copies (dest=self+52, src=sp+0x10, size=0xc via movw r4,#0xc, atomic=1, hasStrong=0).'),
    ),
    dict(
        name='ac_32',
        method='Action -[setInventoryChange:]',
        types='v12@0:4@8',
        start=7563752,
        end=7563828,
        disasm='disasm_worldtileloader_ac_32.txt',
        base_add=7563768,
        base_literal=7563824,
        boundary='ARM.exidx end 0x00736a34 (listing bound); next ObjC IMP 0x00736a34 Action -[interactionItem]',
        selectors={},
        imports={},
        ivars={
                 0x736a2c: (17159260, 'OBJC_IVAR_$_Action.inventoryChange', 64),
        },
        classes={},
        instructions=[(7563752, 'push {fp, lr}'), (7563824, 'ldrsheq sb, [r2], r4')],
        calls=[(7563808, 'bl sym.imp.objc_setProperty_atomic')],
        branches=[],
        semantics=('Action -[setInventoryChange:] @0x7369e8 (19 words, v12@0:4@8): object setter of inventoryChange@64. Cell .got 0x0105d45c (pool 0xffffd968) -> 0x00f3363c = 64; `bl sym.imp.objc_setProperty_atomic(self, _cmd, value, 64)` @0x736a20.'),
    ),
    dict(
        name='ac_33',
        method='Action -[setIsAI:]',
        types='v12@0:4c8',
        start=7564752,
        end=7564820,
        disasm='disasm_worldtileloader_ac_33.txt',
        base_add=7564780,
        base_literal=7564816,
        boundary='ARM.exidx end 0x00736ea8; body trimmed at the next IMP 0x00736e14 Action -[animationTimer]',
        selectors={},
        imports={},
        ivars={
                 0x736e0c: (17159264, 'OBJC_IVAR_$_Action.isAI', 6),
        },
        classes={},
        instructions=[(7564752, 'sub sp, sp, 0xc'), (7564816, 'addseq r8, r2, r0, lsl 26')],
        calls=[],
        branches=[],
        semantics=('Action -[setIsAI:] @0x736dd0 (17 words recorded, v12@0:4c8): char setter of isAI@6. Cell .got 0x0105d460 (pool 0xffffd96c) -> 0x00f33638 = 6; `dmb ish; strb r2,[self+6]; dmb ish`. Roster marks the body TRIMMED: the listing stops at the next IMP 0x736e14 (animationTimer) while this IMP\'s ARM.exidx entry runs to 0x736ea8; the captured stream is the complete standard byte-setter (epilogue `add sp,#0xc; bx lr` + 2 pool words at 0x736e0c/0x736e10).'),
    ),
    dict(
        name='ac_34',
        method='Action -[setPathType:]',
        types='v12@0:4i8',
        start=7564624,
        end=7564692,
        disasm='disasm_worldtileloader_ac_34.txt',
        base_add=7564652,
        base_literal=7564688,
        boundary='ARM.exidx end 0x00736d94 (listing bound); next ObjC IMP 0x00736d94 Action -[isAI]',
        selectors={},
        imports={},
        ivars={
                 0x736d8c: (17159284, 'OBJC_IVAR_$_Action.pathType', 28),
        },
        classes={},
        instructions=[(7564624, 'sub sp, sp, 0xc'), (7564688, 'addseq r8, r2, r0, lsl 27')],
        calls=[],
        branches=[],
        semantics=('Action -[setPathType:] @0x736d50 (17 words, v12@0:4i8): int setter of pathType@28. Cell .got 0x0105d474 (pool 0xffffd980) -> 0x00f3361c = 28; `dmb ish; str r2,[self+28]; dmb ish`.'),
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
        'batch': 'Action (E154): the blockhead action-queue entry; 35 bodies',
        'claim': ('\'the action-queue entry surface (goal position, interaction parameters, path type, AI/inventory flags); the Blockhead consumers that drive and retire these actions are outside these bodies\''),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'action.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale action.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
