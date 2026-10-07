#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld users/bans/session smalls (E33).

The DynamicWorld users/bans/session smalls: the mute/ban propagators, the
ban query, the player-list broadcast, the owner-name resolver, the client-
control check, the pickup reply, the blockhead lookup and the debug chest
loader:
1 body, 1013 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/USERS_BANS.md for the prose and boundaries.
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
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_enumerationMutation': 0x001c2e28,
    'bl sym.worldIndexAtWorldPos_intpair__World_': 0x00a15838,
}

SPECS = [
    dict(
        name='wtl_usermutechanged_',
        method='DynamicWorld -[userMuteChanged:]',
        types='v12@0:4@8',
        start=9446388,
        end=9446884,
        disasm='disasm_worldtileloader_usermutechanged_.txt',
        base_add=9446404,
        base_literal=9446880,
        boundary='ARM.exidx end 0x009025e4 (listing bound); next ObjC IMP 0x009025e4 DynamicWorld -[userBanChanged:isBanned:]',
        selectors={
                 0x9025dc: (15217308, 'userMuteChanged:'),
        },
        imports={
                 0x9025d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9025d0: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9446388, 'push {fp, lr}'), (9446428, 'ldr r1, [0x009025d0]'), (9446472, 'ldr r0, [r0, 0x270]'), (9446712, 'ldr r0, [0x009025d8]'), (9446840, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__'), (9446880, 'rsbseq sp, r5, r8, ror 13')],
        calls=[(9446804, 'blx r3'), (9446840, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9446708, 'beq', 9446856), (9446852, 'b', 9446624)],
        semantics=("userMuteChanged: propagates a mute change to the world's clients. Prologue 0x009023f4 (frame 0xd0; base 0x105faf4).\nWalk: the **ffffe54c member's +0x270 client slice** (cell 0x9025d0, `ldr r0, [r0, 0x270]` @0x902448) is tree-walked (the eor/tst iteration guard @0x902520-0x902534): per node the **ffe237a8 call** (cell 0x9025dc, @0x902544) runs with the node's payload ([node+0x10]+8 @0x90256c-0x902578); `__tree_next` advances (@0x9025b8).\n"),
    ),
    dict(
        name='wtl_userbanchanged_isbanne',
        method='DynamicWorld -[userBanChanged:isBanned:]',
        types='v16@0:4@8c12',
        start=9446884,
        end=9447436,
        disasm='disasm_worldtileloader_userbanchanged_isbanned_.txt',
        base_add=9446900,
        base_literal=9447432,
        boundary='ARM.exidx end 0x0090280c (listing bound); next ObjC IMP 0x0090280c DynamicWorld -[playerIsBannedWithID:]',
        selectors={
                 0x902804: (15217312, 'userBanChanged:isBanned:'),
        },
        imports={
                 0x902800: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9027f4: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
                 0x9027f8: (17162304, 'OBJC_IVAR_$_DynamicWorld.dynamicObjects', 60),
        },
        classes={},
        instructions=[(9446884, 'push {r4, sl, fp, lr}'), (9446908, 'ldr r4, [0x009027f4]'), (9446960, 'sub r0, fp, 0x60'), (9447260, 'ldr r2, [0x00902804]'), (9447340, 'sxtb r3, lr'), (9447432, 'ldrshteq sp, [r5], -0x48')],
        calls=[(9447348, 'blx ip'), (9447384, 'bl method.std::__1::__tree_node_base_void__std::__1::__tree_next_std::__1.__tree_node_base_void___std::__1::__tree_node_base_void__')],
        branches=[(9446956, 'beq', 9447404), (9447244, 'beq', 9447400), (9447396, 'b', 9447160), (9447400, 'b', 9447404)],
        semantics=("userBanChanged:isBanned: propagates a ban-state change. Prologue 0x009025e4 (frame 0xd0; base 0x105faf4). Args: user ID, banned byte.\nGate: the **ffffe51c lookup** (cell 0x9027f4, @0x9025fc) must be non-NULL (@0x902624-0x90262c).\nWalk: the ffffe54c +0x270 client slice (cell 0x9027f8) tree-walk (guards @0x902738-0x90274c); per node the **ffe237ac call** (cell 0x902804, @0x90275c) with the sxtb'd isBanned byte (@0x902798-0x9027ac).\n"),
    ),
    dict(
        name='wtl_playerisbannedwithid_',
        method='DynamicWorld -[playerIsBannedWithID:]',
        types='c12@0:4@8',
        start=9447436,
        end=9447624,
        disasm='disasm_worldtileloader_playerisbannedwithid_.txt',
        base_add=9447452,
        base_literal=9447620,
        boundary='ARM.exidx end 0x009028c8 (listing bound); next ObjC IMP 0x009028c8 DynamicWorld -[playersChanged]',
        selectors={
                 0x9028c0: (15217316, 'playerIsBannedWithID:'),
        },
        imports={
                 0x9028bc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x9028b8: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9447436, 'push {fp, lr}'), (9447460, 'ldr lr, [0x009028b8]'), (9447496, 'cmp r0, ip'), (9447520, 'ldr r2, [0x009028c0]'), (9447620, 'ldrsbteq sp, [r5], -0x20')],
        calls=[(9447576, 'blx r3')],
        branches=[(9447504, 'beq', 9447588), (9447584, 'b', 9447596)],
        semantics=("playerIsBannedWithID: queries a player's ban state. Prologue 0x0090280c (frame 0x20; base 0x105faf4).\nQuery: the ffffe51c registry lookup (cell 0x9028b8) must be non-NULL (@0x902844-0x902850); the **ffe237b0 call** (cell 0x9028c0, @0x902860) resolves the ban state for the ID.\n"),
    ),
    dict(
        name='wtl_playerschanged',
        method='DynamicWorld -[playersChanged]',
        types='v8@0:4',
        start=9447624,
        end=9448128,
        disasm='disasm_worldtileloader_playerschanged.txt',
        base_add=9447640,
        base_literal=9448124,
        boundary='ARM.exidx end 0x00902ac0 (listing bound); next ObjC IMP 0x00902ac0 DynamicWorld -[getOwnerNameForObjectOwnerID:]',
        selectors={
                 0x902ab0: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x902ab8: (15217320, 'updateNameTextView'),
        },
        imports={
                 0x902aac: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x902ab4: (17162216, 'OBJC_IVAR_$_DynamicWorld.netBlockheads', 48),
        },
        classes={},
        instructions=[(9447624, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9447672, 'ldr r6, [0x00902ab4]'), (9447900, 'bl sym.imp.objc_enumerationMutation'), (9447916, 'ldr r2, [0x00902ab8]'), (9448124, 'rsbseq sp, r5, r4, lsl r2')],
        calls=[(9447736, 'bl sym.imp.memset'), (9447800, 'blx lr'), (9447900, 'bl sym.imp.objc_enumerationMutation'), (9447972, 'blx r2'), (9448072, 'blx ip')],
        branches=[(9447812, 'beq', 9448096), (9447892, 'beq', 9447904), (9448000, 'blo', 9447856), (9448092, 'bne', 9447856), (9448096, 'b', 9448100)],
        semantics=('playersChanged broadcasts the player list. Prologue 0x009028c8 (frame 0xd8; base 0x105faf4).\nEnumerate: the **ffffe4f4 netBlockheads** collection (cell 0x902ab4, @0x9028f8) is enumerated (fast-enumeration walk with the mutation guard @0x9029dc); per blockhead the **ffe237b4 call** (cell 0x902ab8, @0x9029ec) runs (the per-player change notice).\n'),
    ),
    dict(
        name='wtl_getownernameforobjecto',
        method='DynamicWorld -[getOwnerNameForObjectOwnerID:]',
        types='@12@0:4@8',
        start=9448128,
        end=9448236,
        disasm='disasm_worldtileloader_getownernameforobjectownerid_.txt',
        base_add=9448144,
        base_literal=9448232,
        boundary='ARM.exidx end 0x00902b2c (listing bound); next ObjC IMP 0x00902b2c DynamicWorld -[appendDebugLog:]',
        selectors={
                 0x902b20: (15217324, 'playerNameForPlayerWithIDIncludingOldPlayers:'),
        },
        imports={
                 0x902b1c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x902b24: (17162256, 'OBJC_IVAR_$_DynamicWorld.server', 16),
        },
        classes={},
        instructions=[(9448128, 'push {r4, sl, fp, lr}'), (9448164, 'ldr r4, [0x00902b24]'), (9448204, 'ldr r1, [lr]'), (9448232, 'rsbseq sp, r5, ip, lsl r0')],
        calls=[(9448208, 'blx ip')],
        branches=[],
        semantics=('getOwnerNameForObjectOwnerID: resolves an object-owner name. Prologue 0x00902ac0 (frame 0x18; base 0x105faf4).\nChain: the **ffffe51c registry** (cell 0x902b24 @0x902ae4-0x902b04) + the **ffe237b8 selector** (cell 0x902b20 @0x902b0c): the owner-ID slot is read and the name accessor called (tail call).\n'),
    ),
    dict(
        name='wtl_iscontrollingblockhead',
        method='DynamicWorld -[isControllingBlockheadsForClientPlayer:]',
        types='c12@0:4@8',
        start=9427952,
        end=9428652,
        disasm='disasm_worldtileloader_iscontrollingblockheadsforclientplayer_.txt',
        base_add=9427968,
        base_literal=9428648,
        boundary='ARM.exidx end 0x008fdeac (listing bound); next ObjC IMP 0x008fdeac DynamicWorld -[portalPositions]',
        selectors={
                 0x8fde90: (15216328, 'containsObject:'),
                 0x8fde98: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8fdea0: (15216280, 'isEqualToString:'),
                 0x8fdea4: (15216440, 'clientID'),
        },
        imports={
                 0x8fde8c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8fde94: (17162400, 'OBJC_IVAR_$_DynamicWorld.disconnectedClientsSaveDirNames', 9468),
                 0x8fde9c: (17162212, 'OBJC_IVAR_$_DynamicWorld.netBlockheadsWithDisconnectedClients', 52),
        },
        classes={},
        instructions=[(9427952, 'push {r4, r5, r6, r7, fp, lr}'), (9427988, 'ldr r4, [0x008fde94]'), (9428064, 'movw r0, 1'), (9428108, 'ldr r4, [0x008fde9c]'), (9428380, 'add r4, r4, r5, lsl 2'), (9428648, 'rsbseq r1, r6, ip, ror 29')],
        calls=[(9428048, 'blx ip'), (9428168, 'bl sym.imp.memset'), (9428232, 'blx lr'), (9428332, 'bl sym.imp.objc_enumerationMutation'), (9428424, 'blx ip'), (9428444, 'blx r3'), (9428572, 'blx ip')],
        branches=[(9428060, 'beq', 9428076), (9428072, 'b', 9428608), (9428244, 'beq', 9428596), (9428324, 'beq', 9428336), (9428456, 'beq', 9428472), (9428468, 'b', 9428608), (9428472, 'b', 9428476), (9428500, 'blo', 9428288), (9428592, 'bne', 9428288), (9428596, 'b', 9428600)],
        semantics=("isControllingBlockheadsForClientPlayer: answers whether the local client controls a player's blockheads. Prologue 0x008fdbf0 (frame 0xe0; base 0x105faf4).\nFast path: the **ffffe5ac dict** (cell 0x8fde94, @0x8fdc14) checked via the ffe233d4 call (@0x8fdc50): a hit sets the true flag (@0x8fdc60-0x8fdc68).\nScan: otherwise the **ffffe4f0 collection** (cell 0x8fde9c, the local-and-disconnected-client family) is enumerated (@0x8fdc8c-0x8fdd08); per blockhead the ffe233a4/ffe23444 (clientID) and the <<2 indexed reads (@0x8fdd9c) run the match.\n"),
    ),
    dict(
        name='wtl_remotepickuprequestrep',
        method='DynamicWorld -[remotePickupRequestReply:]',
        types='v12@0:4@8',
        start=9400876,
        end=9401384,
        disasm='disasm_worldtileloader_remotepickuprequestreply_.txt',
        base_add=9400892,
        base_literal=9401380,
        boundary='ARM.exidx end 0x008f7428 (listing bound); next ObjC IMP 0x008f7428 DynamicWorld -[clientConnected:]',
        selectors={
                 0x8f7404: (15217108, 'blockheadWithUniqueID:'),
                 0x8f7410: (15216436, 'getBytes:length:'),
                 0x8f7414: (15216188, 'length'),
                 0x8f7418: (15217104, 'getBytes:range:'),
                 0x8f7420: (15217112, 'remotePickupRequestResponse:uniqueIDs:count:'),
        },
        imports={
                 0x8f7408: (17151968, '__stack_chk_guard'),
                 0x8f741c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(9400876, 'push {r4, r5, r6, r7, fp, lr}'), (9400956, 'mov r4, 0x10'), (9401068, 'mov sp, r0'), (9401220, 'cmp r0, r1'), (9401252, 'ldrb ip, [fp, -0x39]'), (9401380, 'ldrhteq r8, [r6], -0x80')],
        calls=[(9400996, 'bl loc.imp.objc_msgSend'), (9401032, 'bl loc.imp.objc_msgSend'), (9401104, 'bl loc.imp.objc_msgSend'), (9401176, 'bl loc.imp.objc_msgSend'), (9401204, 'bl loc.imp.objc_msgSend'), (9401292, 'blx ip'), (9401344, 'bl sym.imp.__stack_chk_fail')],
        branches=[(9401224, 'beq', 9401300), (9401332, 'bne', 9401344)],
        semantics=("remotePickupRequestReply: applies a remote pickup reply. Prologue 0x008f722c (frame 0x80; base 0x105faf4). Argument: the reply data.\nParse: the payload is read with `mov r4, 0x10` (16-byte unit, @0x8f727c); the **VLA alloc** (`lsr r1, r0, 3; bfc r0, 0, 3; sub r0, r1, r0; mov sp, r0` @0x8f72d0-0x8f72ec) reserves the stack buffer for the payload; the chunk is sliced (`sub r0, r0, 0x10` @0x8f72cc and @0x8f7314).\nApply: the ffe236dc lookup (cell 0x8f7418) + the compare walk (@0x8f7384 `cmp r0, r1; beq 0x8f73d4`) + the **ffe236e4 apply** (cell 0x8f7420, @0x8f7398) with the stored pickup byte (ldrb [fp,-0x39] @0x8f73a4).\nBoundary: the 16-byte IDs match E28's clientPickupRequest:count:clientID:blockheadRequesterUniqueID:.\n"),
    ),
    dict(
        name='wtl_blockheadwithuniqueid_',
        method='DynamicWorld -[blockheadWithUniqueID:]',
        types='@16@0:4Q8',
        start=9400320,
        end=9400876,
        disasm='disasm_worldtileloader_blockheadwithuniqueid_.txt',
        base_add=9400336,
        base_literal=9400872,
        boundary='ARM.exidx end 0x008f722c (listing bound); next ObjC IMP 0x008f722c DynamicWorld -[remotePickupRequestReply:]',
        selectors={
                 0x8f7218: (15215840, 'countByEnumeratingWithState:objects:count:'),
                 0x8f7220: (15216160, 'uniqueID'),
        },
        imports={
                 0x8f7214: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8f721c: (17162220, 'OBJC_IVAR_$_DynamicWorld.blockheads', 44),
        },
        classes={},
        instructions=[(9400320, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9400368, 'ldr r8, [0x008f721c]'), (9400640, 'ldr r2, [0x008f7220]'), (9400680, 'cmp r0, 0'), (9400720, 'cmp r1, r2'), (9400872, 'ldrsbteq r8, [r6], -0xac')],
        calls=[(9400456, 'bl sym.imp.memset'), (9400520, 'blx lr'), (9400620, 'bl sym.imp.objc_enumerationMutation'), (9400656, 'bl loc.imp.objc_msgSend'), (9400804, 'blx ip')],
        branches=[(9400532, 'beq', 9400828), (9400612, 'beq', 9400624), (9400684, 'bne', 9400704), (9400688, 'b', 9400692), (9400700, 'b', 9400840), (9400704, 'b', 9400708), (9400732, 'blo', 9400576), (9400824, 'bne', 9400576), (9400828, 'b', 9400832)],
        semantics=('blockheadWithUniqueID: resolves a blockhead by uniqueID. Prologue 0x008f7000 (frame 0xe0; base 0x105faf4).\nEnumerate: the **ffffe4f8 blockheads collection** (@0x8f7030) is enumerated (@0x8f7088-0x8f70c8 walk); per blockhead `[bh uniqueID]` (ffe2332c @0x8f7140) is compared with the argument via the **eor/orr 64-bit equality** (@0x8f715c-0x8f7168: `eor r1, r1, r3; eor r0, r0, r2; orr r0, r0, r1`); a match returns the blockhead (@0x8f716c+); the loop continues through the enumeration (@0x8f7190).\n'),
    ),
    dict(
        name='wtl_loaddebugchestatpos_ch',
        method='DynamicWorld -[loadDebugChestAtPos:chest:]',
        types='v20@0:4{?=ii}8@16',
        start=9463776,
        end=9464216,
        disasm='disasm_worldtileloader_loaddebugchestatpos_chest_.txt',
        base_add=9463792,
        base_literal=9464212,
        boundary='ARM.exidx end 0x00906998 (listing bound); next ObjC IMP 0x00906998 DynamicWorld -[freeblockPositionChanged:oldPos:]',
        selectors={
                 0x906978: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x90697c: (15216168, 'objectType'),
                 0x906988: (15216160, 'uniqueID'),
        },
        imports={
                 0x906974: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x906984: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
                 0x90698c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x906990: (17162312, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex', 1620),
        },
        classes={},
        instructions=[(9463776, 'push {r4, sl, fp, lr}'), (9463824, 'ldr r0, [0x0090697c]'), (9463896, 'add r0, r0, r0, lsl 1'), (9464008, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9464092, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9464112, 'ldr ip, [0x00906978]'), (9464212, 'ldrshteq sb, [r5], -0x2c')],
        calls=[(9463868, 'bl loc.imp.objc_msgSend'), (9463928, 'bl loc.imp.objc_msgSend'), (9463948, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9464008, 'bl sym.worldIndexAtWorldPos_intpair__World_'), (9464036, 'bl loc.imp.objc_msgSend'), (9464092, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9464168, 'blx r4')],
        branches=[],
        semantics=("loadDebugChestAtPos:chest: registers a debug chest into the world registries. Prologue 0x009067e0 (frame 0x70; base 0x105faf4).\nRegister: `[chest objectType]` (ffe23334 @0x906810) -> the **ffffe550 map's 12-byte segment** (`add r0, r0, r0, lsl 1` <<2 @0x906858) `operator[](u64&&)` (@0x90688c) stores the chest; `worldIndexAtWorldPos` (world via ffffe4e4 @0x9068ac-0x9068c8) -> the **ffffe554 map** `operator[](u64&&)` (@0x90691c) stores it; the **ffe232a0 flag-1 call** (cell 0x906978, `movw r1, 1` @0x906920) closes — the same writer shape as E26's interaction placer and E30's adders.\n"),
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
        'batch': 'DynamicWorld users/bans/session smalls (E33): userMuteChanged:, userBanChanged:isBanned:, playerIsBannedWithID:, playersChanged, getOwnerNameForObjectOwnerID:, isControllingBlockheadsForClientPlayer:, remotePickupRequestReply:, blockheadWithUniqueID: and loadDebugChestAtPos:chest:; 9 bodies',
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
                        default=NATIVE / 'users_bans.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale users_bans.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
