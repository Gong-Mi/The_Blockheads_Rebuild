#!/usr/bin/env python3
"""Hash-gated recovery of the Dodo (E141).

Dodo lands: the batch sweeps dodo surface:
46 bodies, 13936 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DODO.md for the prose and boundaries.
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
    'bl 0xa6b40c': 0x00a6b40c,
    'bl 0xa6b608': 0x00a6b608,
    'bl 0xa6b654': 0x00a6b654,
    'bl 0xa75b2c': 0x00a75b2c,
    'bl 0xa75ba0': 0x00a75ba0,
    'bl 0xa75d88': 0x00a75d88,
    'bl 0xa76120': 0x00a76120,
    'bl 0xa764b8': 0x00a764b8,
    'bl 0xa76670': 0x00a76670,
    'bl 0xa76a08': 0x00a76a08,
    'bl 0xa77a5c': 0x00a77a5c,
    'bl 0xa78158': 0x00a78158,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSendSuper2_stret': 0x001c335c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_glActiveTexture': 0x001c2dc8,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.nameForDodoBreed_DodoBreed_': 0x00a7ffd0,
    'bl sym.prefixNameForDodoBreed_DodoBreed_': 0x006a4b18,
    'bl sym.texCoordsForImageIndex_int_': 0x004d6820,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
}

SPECS = [
    dict(
        name='dd_00',
        method='Dodo -[.cxx_construct]',
        types='@8@0:4',
        start=11012768,
        end=11013376,
        disasm='disasm_worldtileloader_dd_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a80d00 (listing bound); next ObjC IMP 0x00a810d0 TradePortalUI -[loadResources]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11012768, 'sub sp, sp, 8'), (11013372, 'bx lr')],
        calls=[],
        branches=[(11012816, 'bhi', 11013352), (11012976, 'b', 11013364), (11012988, 'b', 11013364), (11013000, 'b', 11013364), (11013012, 'b', 11013364), (11013024, 'b', 11013364), (11013036, 'b', 11013364), (11013048, 'b', 11013364), (11013060, 'b', 11013364), (11013072, 'b', 11013364), (11013084, 'b', 11013364), (11013096, 'b', 11013364), (11013108, 'b', 11013364), (11013120, 'b', 11013364), (11013132, 'b', 11013364), (11013144, 'b', 11013364), (11013156, 'b', 11013364), (11013168, 'b', 11013364), (11013180, 'b', 11013364), (11013192, 'b', 11013364), (11013204, 'b', 11013364), (11013216, 'b', 11013364), (11013228, 'b', 11013364), (11013240, 'b', 11013364), (11013252, 'b', 11013364), (11013264, 'b', 11013364), (11013276, 'b', 11013364), (11013288, 'b', 11013364), (11013300, 'b', 11013364), (11013312, 'b', 11013364), (11013324, 'b', 11013364), (11013336, 'b', 11013364), (11013348, 'b', 11013364), (11013352, 'b', 11013356)],
        semantics=('[Dodo -[.cxx_construct]] (imp 0x00a80aa0, 152w): -[.cxx_construct] (0xa80aa0, 152w): the real .cxx_construct is the first 6 words - an O0 `return self` stub (sub sp,#8; save r0/r1; reload r0; bx lr), i.e. an empty C++ member constructor (no non-POD members need init). The remaining 146 words of the exidx span (0xa80ab8..0xa80d00) are an adjacent C helper (u16 -> u16 breed re-indexer, not method-shaped): `sub r0,#1; cmp r0,#0x1f; bhi default`; 32-arm jump table @0xa80ae8 (arm target = 0xa80ae8 + word), each arm `movw r0,K; strh r0,[sp,#6]; b 0xa80cf4`; default returns the input unchanged. Decoded table (input 1..32 -> out): 1->0, 2->1, 3->11, 4->2, 5->4, 6->5, 7->0, 8->7, 9->0, 10->1, 11->10, 12->11, 13->3, 14->12, 15->7, 16->15, 17->7, 18->17, 19->18, 20->19, 21->1, 22->21, 23->22, 24->23, 25->24, 26->25, 27->1, 28->27, 29->28, 30->29, 31->30, 32->31. ELF BL-scan: the helper\'s only caller is Dodo -[update:accurateDT:isSimulation:] @0xa7ea40 (`ldrh r0,[fp,-4](breed); bl 0xa80ab8; strh r0,[fp,-2]`) under an lrand48()-gated (<0.5, wrapper 0xa6b654 + vdiv /2^31) branch - the egg-lay breed-variation path (the same update: also plays eggLay.wav). No callers of the tiny stub itself (empty ctor)..\n'),
    ),
    dict(
        name='dd_01',
        method='Dodo -[addRider:]',
        types='v12@0:4@8',
        start=11011528,
        end=11011896,
        disasm='disasm_worldtileloader_dd_01.txt',
        base_add=11011544,
        base_literal=11011892,
        boundary='ARM.exidx end 0x00a80738 (listing bound); next ObjC IMP 0x00a80738 Dodo -[removeRider:]',
        selectors={
                 0xa8070c: (15225676, 'addRider:'),
        },
        imports={
                 0xa80708: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa80714: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0xa8071c: (17164712, 'OBJC_IVAR_$_Dodo.riderTargetVelocity', 320),
                 0xa80720: (17164664, 'OBJC_IVAR_$_Dodo.remoteMovementDirection', 364),
                 0xa80724: (17164668, 'OBJC_IVAR_$_Dodo.remoteWalkSpeed', 360),
                 0xa80728: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa8072c: (17164672, 'OBJC_IVAR_$_Dodo.remoteGoalSquare', 352),
                 0xa80730: (17164612, 'OBJC_IVAR_$_Dodo.randomXOffsetGoal', 296),
        },
        classes={
                 0xa80710: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(11011528, 'push {r4, r5, fp, lr}'), (11011892, 'subseq pc, sp, r4, lsl r5')],
        calls=[(11011620, 'blx lr')],
        branches=[(11011656, 'bne', 11011700)],
        semantics=('[Dodo -[addRider:]] (imp 0x00a805c8, 92w): -[addRider:] (0xa805c8, 92w): [super addRider:rider] via objc_msgSendSuper2 (superstruct {self, Dodo}; class cell 0xa80710, sel 0xa8070c). Then `if (!self.beingControlled@128) riderTargetVelocity@320 = (0,0)` (pool 0xa80718 = 0x0), and unconditionally resets the net-sync cache: remoteWalkSpeed@360 = 0.0f; remoteGoalSquare@352 = self.pos@16 (2-word copy); randomXOffsetGoal@296 = 0.0f; remoteMovementDirection@364 = 0. Mounting clears direction/velocity/goal/random-offset and their remote mirrors..\n'),
    ),
    dict(
        name='dd_02',
        method='Dodo -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=11012116,
        end=11012492,
        disasm='disasm_worldtileloader_dd_02.txt',
        base_add=11012132,
        base_literal=11012488,
        boundary='ARM.exidx end 0x00a8098c (listing bound); next ObjC IMP 0x00a8098c Dodo -[jumpsOnSwipe]',
        selectors={
                 0xa80978: (15225572, 'tamed'),
                 0xa8097c: (15225552, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0xa80974: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa80970: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa80980: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xa80984: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(11012116, 'push {r4, r5, fp, lr}'), (11012488, 'subseq pc, sp, r8, asr 5')],
        calls=[(11012252, 'blx r2'), (11012324, 'blx r3')],
        branches=[(11012208, 'ble', 11012440), (11012264, 'beq', 11012348), (11012344, 'beq', 11012440), (11012388, 'bne', 11012440)],
        semantics=('[Dodo -[blockheadCanRide:usingItem:]] (imp 0x00a80814, 94w): -[blockheadCanRide:usingItem:] (0xa80814, 94w): returns age@88 > 900.0f (0x44610000 @0xa8096c) && (![self tamed] || [self belongsToPlayerWithBlockhead:blockhead]) && !dead@56 && !needsRemoved@48 (final result = !needsRemoved, bool-inverted by movne/eor). The usingItem arg (r3) is never read; the constant 0x384(900) is loaded to r4 and spilled to [sp,#0x10] with no reader..\n'),
    ),
    dict(
        name='dd_03',
        method='Dodo -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=11012520,
        end=11012740,
        disasm='disasm_worldtileloader_dd_03.txt',
        base_add=11012536,
        base_literal=11012736,
        boundary='ARM.exidx end 0x00a80a84 (listing bound); next ObjC IMP 0x00a80a84 Dodo -[riderRidesWithArmsDown]',
        selectors={
                 0xa80a78: (15225684, 'blockheadUnloaded:'),
        },
        imports={
                 0xa80a74: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa80a68: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xa80a70: (17164712, 'OBJC_IVAR_$_Dodo.riderTargetVelocity', 320),
        },
        classes={
                 0xa80a7c: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(11012520, 'push {fp, lr}'), (11012736, 'subseq pc, sp, r4, lsr r1')],
        calls=[(11012700, 'blx r3')],
        branches=[(11012588, 'bne', 11012632)],
        semantics=('[Dodo -[blockheadUnloaded:]] (imp 0x00a809a8, 55w): -[blockheadUnloaded:] (0xa809a8, 55w): `if (self.rider@132 == arg) riderTargetVelocity@320 = (0,0)` (0.0f pool 0xa80a6c), then [super blockheadUnloaded:] via objc_msgSendSuper2 (class cell 0xa80a7c). No further state (Dodo has no attack-blockhead field)..\n'),
    ),
    dict(
        name='dd_04',
        method='Dodo -[breedString]',
        types='@8@0:4',
        start=11009928,
        end=11010196,
        disasm='disasm_worldtileloader_dd_04.txt',
        base_add=11009944,
        base_literal=11009996,
        boundary='ARM.exidx end 0x00a80178; body trimmed at the next IMP 0x00a80094 Dodo -[canBeCapturedByBlockhead:withItemType:]',
        selectors={
                 0xa80088: (15225668, 'stringWithFormat:'),
        },
        imports={
                 0xa8007c: (16348216, '__CFConstantStringClassReference'),
                 0xa80080: (16348824, '__CFConstantStringClassReference'),
                 0xa80084: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa7ffc8: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={
                 0xa8008c: (15249160, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11009928, 'push {fp, lr}'), (11010192, 'subseq pc, sp, ip, lsl 22')],
        calls=[(11009980, 'bl sym.nameForDodoBreed_DodoBreed_'), (11010032, 'bl sym.prefixNameForDodoBreed_DodoBreed_'), (11010132, 'blx ip')],
        branches=[(11010052, 'beq', 11010144), (11010140, 'b', 11010160)],
        semantics=('[Dodo -[breedString]] (imp 0x00a7ff88, 67w): -[breedString] (0xa7ff88, 67w; listing trimmed at the next IMP 0xa80094): returns nameForDodoBreed((u16)self.breed@96) - the listing also carries that C helper @0xa7ffd0 (single caller @0xa7ffbc): it calls prefixNameForDodoBreed(breed) @0x6a4b18 and returns [NSString stringWithFormat:@"%@ DODO", prefix] (fmt obj 0x01057698, cstr @0xf5c385) when the prefix is non-null, else the static CFString @"DODO" (obj 0xf97438, cstr @0xf5c2f6). Pools: 0xa7ffc8 = breed ivar cell; 0xa7ffcc/0xa80090 = PIC-base anchors..\n'),
    ),
    dict(
        name='dd_05',
        method='Dodo -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=11011028,
        end=11011128,
        disasm='disasm_worldtileloader_dd_05.txt',
        base_add=11011044,
        base_literal=11011124,
        boundary='ARM.exidx end 0x00a80438 (listing bound); next ObjC IMP 0x00a80438 Dodo -[riderBodyYRotationForBlockhead:]',
        selectors={
                 0xa8042c: (15225672, 'cameraPosForBlockhead:'),
        },
        imports={},
        ivars={},
        classes={
                 0xa80430: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(11011028, 'push {r4, sl, fp, lr}'), (11011124, 'subseq pc, sp, r8, lsl 14')],
        calls=[(11011104, 'bl loc.imp.objc_msgSendSuper2_stret')],
        branches=[],
        semantics=('[Dodo -[cameraPosForBlockhead:]] (imp 0x00a803d4, 25w): -[cameraPosForBlockhead:] (0xa803d4, 25w): byte-identical twin of Shark sh_04 - a pure forward `[super cameraPosForBlockhead:blockhead]` via objc_msgSendSuper2_stret with superstruct {self, Dodo class cell 0xa80430} and selector cell 0xa8042c; the Vector2 is returned through the stret buffer received in r0..\n'),
    ),
    dict(
        name='dd_06',
        method='Dodo -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=11010196,
        end=11010424,
        disasm='disasm_worldtileloader_dd_06.txt',
        base_add=11010212,
        base_literal=11010420,
        boundary='ARM.exidx end 0x00a80178 (listing bound); next ObjC IMP 0x00a80178 Dodo -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={
                 0xa8016c: (15225572, 'tamed'),
                 0xa80170: (15225552, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0xa80168: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11010196, 'push {fp, lr}'), (11010420, 'subseq pc, sp, r8, asr 20')],
        calls=[(11010292, 'blx r2'), (11010356, 'blx r3')],
        branches=[(11010248, 'bne', 11010388), (11010304, 'beq', 11010372), (11010368, 'beq', 11010384), (11010380, 'b', 11010396), (11010384, 'b', 11010388)],
        semantics=('[Dodo -[canBeCapturedByBlockhead:withItemType:]] (imp 0x00a80094, 57w): -[canBeCapturedByBlockhead:withItemType:] (0xa80094, 57w): returns itemType == 0x12e (302; item table = CAGE) && (![self tamed] || [self belongsToPlayerWithBlockhead:blockhead]). No age or dead checks (unlike Shark)..\n'),
    ),
    dict(
        name='dd_07',
        method='Dodo -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=11010424,
        end=11010784,
        disasm='disasm_worldtileloader_dd_07.txt',
        base_add=11010440,
        base_literal=11010780,
        boundary='ARM.exidx end 0x00a802e0 (listing bound); next ObjC IMP 0x00a802e0 Dodo -[riderPosForBlockhead:]',
        selectors={
                 0xa802c4: (15225572, 'tamed'),
                 0xa802c8: (15225552, 'belongsToPlayerWithBlockhead:'),
                 0xa802d0: (15225668, 'stringWithFormat:'),
                 0xa802d4: (15225664, 'speciesName'),
        },
        imports={
                 0xa802c0: (17151904, 'objc_msgSend'),
                 0xa802cc: (16348808, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={
                 0xa802d8: (15249160, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11010424, 'push {r4, r5, fp, lr}'), (11010780, 'subseq pc, sp, r4, ror 18')],
        calls=[(11010520, 'blx r2'), (11010584, 'blx r3'), (11010680, 'blx r2'), (11010716, 'blx ip')],
        branches=[(11010476, 'bne', 11010732), (11010532, 'beq', 11010728), (11010596, 'bne', 11010728), (11010724, 'b', 11010740), (11010728, 'b', 11010732)],
        semantics=('[Dodo -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x00a80178, 90w): -[cantBeCapturedTipStringForBlockhead:withItemType:] (0xa80178, 90w): returns nil unless (itemType == 0x12e && [self tamed] && ![self belongsToPlayerWithBlockhead:blockhead]); in that case returns [NSString stringWithFormat:@"THAT %@ BELONGS TO\nSOMEONE ELSE" (fmt obj 0xf97688), [self speciesName]]..\n'),
    ),
    dict(
        name='dd_08',
        method='Dodo -[captureRequiredItemType]',
        types='i8@0:4',
        start=10921116,
        end=10921144,
        disasm='disasm_worldtileloader_dd_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6a508; body trimmed at the next IMP 0x00a6a4b8 Dodo -[getNamesArray]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10921116, 'sub sp, sp, 8'), (10921140, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[captureRequiredItemType]] (imp 0x00a6a49c, 7w): -[captureRequiredItemType] (0xa6a49c, 7w): returns 0x12e (302; item table = CAGE)..\n'),
    ),
    dict(
        name='dd_09',
        method='Dodo -[capturedItemType]',
        types='i8@0:4',
        start=10921088,
        end=10921116,
        disasm='disasm_worldtileloader_dd_09.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6a508; body trimmed at the next IMP 0x00a6a49c Dodo -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10921088, 'sub sp, sp, 8'), (10921112, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[capturedItemType]] (imp 0x00a6a480, 7w): -[capturedItemType] (0xa6a480, 7w): returns 0x12f (303; item table = CAGED DODO)..\n'),
    ),
    dict(
        name='dd_10',
        method='Dodo -[createItemDropsForDeath]',
        types='v8@0:4',
        start=10974956,
        end=10975836,
        disasm='disasm_worldtileloader_dd_10.txt',
        base_add=10974972,
        base_literal=10975832,
        boundary='ARM.exidx end 0x00a77a5c (listing bound); next ObjC IMP 0x00a781c8 Dodo -[update:accurateDT:isSimulation:]',
        selectors={
                 0xa77a48: (15225520, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={},
        ivars={
                 0xa77a2c: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa77a30: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa77a34: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0xa77a3c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa77a40: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa77a44: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
        },
        classes={},
        instructions=[(10974956, 'push {r4, r5, r6, sl, fp, lr}'), (10975832, 'ldrsheq r8, [lr], -0x30')],
        calls=[(10975304, 'bl loc.imp.objc_msgSend'), (10975308, 'bl 0xa6b654'), (10975520, 'bl loc.imp.objc_msgSend'), (10975580, 'bl 0xa77a5c'), (10975604, 'bl 0xa78158'), (10975772, 'bl loc.imp.objc_msgSend')],
        branches=[(10975032, 'bmi', 10975072), (10975068, 'beq', 10975076), (10975072, 'b', 10975776), (10975108, 'beq', 10975148), (10975144, 'blt', 10975544), (10975360, 'bge', 10975540), (10975536, 'b', 10975348), (10975540, 'b', 10975776)],
        semantics=('[Dodo -[createItemDropsForDeath]] (imp 0x00a776ec, 220w): -[createItemDropsForDeath] (0xa776ec, 220w): guards - age@88 < 900.0f (0x44610000 @0xa77a28, vcmpe+bmi) -> return (no drops for a dodo younger than 900); isNet@52 -> return. breed@96 == 0 or >= 33 (wild): createFreeBlockAtPosition:pos ofType:0x1d (29 = RAW DODO MEAT) dataA/B = 0 playSound = 1 priorityBlockhead = killBlockhead@60; then flag = (lrand48() > 0x3fffffff) (25%) and a loop i<flag drops one extra 0x1e (30 = DODO FEATHER). breed 1..32 (bred): itemType = itemTypeForDodoBreed(breed) - helper @0xa77a5c, a lazy-init static std::map<DodoBreed,ItemType> (`__tree<pair<DodoBreed,ItemType>>` ctor/`__count_unique` guard, whole 32-insert sequence read inline at 0xa77b2c..0xa7813c, `count()==0 -> 0`); dataA/dataB = the pair from helper @0xa78158(&pair, itemType) = (0x7f,0x7f) if itemTypeIsSowable(itemType) else (0,0) (helper: itemTypeIsSowable @0x56871c, makeIntpair @0x4b49fc); createFreeBlock drop of that itemType with playSound = 1 and priorityBlockhead = killBlockhead. Decoded map (breed -> item, 0x400-series item names from the item-name table): 1->STONE(1024), 2->LIMESTONE(1028), 3->SANDSTONE(1036), 4->MARBLE(1030), 5->RED MARBLE(1038), 6->LAPIS LAZULI(1054), 7->DIRT(1048), 8->COMPOST(1062), 9->WOOD(1049), 10->GRAVEL(1094), 11->SAND(1051), 12->BLACK SAND(1075), 13->GLASS(1042), 14->BLACK GLASS(1076), 15->CLAY(28), 16->RED BRICKS(1026), 17->FLINT(3), 18->COAL(51), 19->OIL(48), 20->FUEL(269), 21->COPPER ORE(31), 22->TIN ORE(36), 23->IRON ORE(32), 24->GOLD NUGGET(73), 25->TITANIUM ORE(279), 26->PLATINUM NUGGET(261), 27->AMETHYST SHARD(305), 28->SAPPHIRE SHARD(306), 29->EMERALD SHARD(307), 30->RUBY SHARD(308), 31->DIAMOND SHARD(309), 32->RAINBOW ESSENCE(329). So a bred dodo drops its breed-mineral item on death; none of the 32 values are in the sowable-seed set, so the data pair is always (0,0)..\n'),
    ),
    dict(
        name='dd_11',
        method='Dodo -[creationDataStructSize]',
        types='L8@0:4',
        start=10930316,
        end=10930344,
        disasm='disasm_worldtileloader_dd_11.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6c8a8 (listing bound); next ObjC IMP 0x00a6c8a8 Dodo -[getRandomDirection]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10930316, 'sub sp, sp, 8'), (10930340, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[creationDataStructSize]] (imp 0x00a6c88c, 7w): -[creationDataStructSize] (0xa6c88c, 7w): returns 0x70 (112)..\n'),
    ),
    dict(
        name='dd_12',
        method='Dodo -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=10927420,
        end=10927944,
        disasm='disasm_worldtileloader_dd_12.txt',
        base_add=10927436,
        base_literal=10927940,
        boundary='ARM.exidx end 0x00a6bf48 (listing bound); next ObjC IMP 0x00a6bf48 Dodo -[updateNetDataForClient:]',
        selectors={
                 0xa6bf2c: (15225396, 'npcCreationNetDataForClient:'),
                 0xa6bf30: (15225400, 'dodoUpdateNetDataForClient:'),
                 0xa6bf38: (15225408, 'appendNPCCreationDataToData:'),
                 0xa6bf3c: (15225404, 'dataWithBytes:length:'),
        },
        imports={
                 0xa6bf34: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa6bf40: (15249136, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(10927420, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10927940, 'subseq r3, pc, r0, lsr 27')],
        calls=[(10927524, 'bl loc.imp.objc_msgSend_stret'), (10927560, 'bl sym.imp.memset'), (10927616, 'bl sym.imp.memcpy'), (10927688, 'bl loc.imp.objc_msgSend_stret'), (10927724, 'bl sym.imp.memset'), (10927828, 'bl sym.imp.memcpy'), (10927868, 'blx ip'), (10927896, 'blx r3')],
        branches=[(10927504, 'beq', 10927532), (10927528, 'b', 10927564), (10927668, 'beq', 10927696), (10927692, 'b', 10927728)],
        semantics=('[Dodo -[creationNetDataForClient:]] (imp 0x00a6bd3c, 131w): -[creationNetDataForClient:] (0xa6bd3c, 131w): builds the 0x70-byte creation blob. B[0..0x48) = [self npcCreationNetDataForClient:client] (0x48-byte stret into [sp+0x80]; memset-0 on the O0 nil-self guard path); C = [self dodoUpdateNetDataForClient:client] (0x28 stret into [sp+0x58]); memcpy(B+0x48, C, 0x28); returns [self appendNPCCreationDataToData:[NSData dataWithBytes:B length:0x70]] (sel cells 0xa6bf2c/0xa6bf30/0xa6bf38/0xa6bf3c, NSData class 0xa6bf40). 0x70 = creationDataStructSize (dd_11)..\n'),
    ),
    dict(
        name='dd_13',
        method='Dodo -[dealloc]',
        types='v8@0:4',
        start=10928180,
        end=10928600,
        disasm='disasm_worldtileloader_dd_13.txt',
        base_add=10928196,
        base_literal=10928596,
        boundary='ARM.exidx end 0x00a6c1d8 (listing bound); next ObjC IMP 0x00a6c1d8 Dodo -[doRemoteUpdate:]',
        selectors={
                 0xa6c1b0: (15225416, 'dealloc'),
                 0xa6c1bc: (15225412, 'release'),
        },
        imports={
                 0xa6c1ac: (17151900, 'objc_msgSendSuper2'),
                 0xa6c1b8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6c1c0: (17164648, 'OBJC_IVAR_$_Dodo.footCube', 256),
                 0xa6c1c4: (17164652, 'OBJC_IVAR_$_Dodo.legCube', 252),
                 0xa6c1c8: (17164656, 'OBJC_IVAR_$_Dodo.headCube', 248),
                 0xa6c1cc: (17164660, 'OBJC_IVAR_$_Dodo.neckCube', 244),
                 0xa6c1d0: (17164596, 'OBJC_IVAR_$_Dodo.bodyCube', 240),
        },
        classes={
                 0xa6c1b4: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(10928180, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10928596, 'subseq r3, pc, r8, lsr 21')],
        calls=[(10928360, 'blx r5'), (10928396, 'blx r3'), (10928432, 'blx r3'), (10928468, 'blx r3'), (10928504, 'blx r3'), (10928544, 'blx r2')],
        branches=[],
        semantics=('[Dodo -[dealloc]] (imp 0x00a6c034, 105w): -[dealloc] (0xa6c034, 105w): releases the five cubes in order bodyCube@240, neckCube@244, headCube@248, legCube@252, footCube@256 (release sel cell 0xa6c1bc; each release built via self+offset cell loads), then [super dealloc] via objc_msgSendSuper2 (class cell 0xa6c1b4). Textures and both shaders are NOT released here (matches Shark)..\n'),
    ),
    dict(
        name='dd_14',
        method='Dodo -[die:]',
        types='v12@0:4@8',
        start=10973128,
        end=10973824,
        disasm='disasm_worldtileloader_dd_14.txt',
        base_add=10973144,
        base_literal=10973820,
        boundary='ARM.exidx end 0x00a77280 (listing bound); next ObjC IMP 0x00a77280 Dodo -[jumpAndCluck]',
        selectors={
                 0xa7724c: (15225480, 'multiSoundNamed:'),
                 0xa77250: (15225472, 'instance'),
                 0xa77258: (15225504, 'setPitch:'),
                 0xa77260: (15225512, 'die:'),
                 0xa77278: (15225508, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xa77244: (16348616, '__CFConstantStringClassReference'),
                 0xa77248: (17151904, 'objc_msgSend'),
                 0xa7725c: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa77238: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xa77240: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa7726c: (17164632, 'OBJC_IVAR_$_Dodo.travelFraction', 284),
                 0xa77270: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0xa77254: (15249144, 'OBJC_CLASS_$_MJSoundManager'),
                 0xa77264: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(10973128, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10973820, 'subseq r8, lr, r4, lsl fp')],
        calls=[(10973300, 'blx ip'), (10973320, 'blx r3'), (10973424, 'blx r3'), (10973492, 'blx r3'), (10973668, 'bl loc.imp.objc_msgSend'), (10973736, 'blx ip')],
        branches=[(10973192, 'bne', 10973744), (10973360, 'ble', 10973432), (10973428, 'b', 10973496), (10973740, 'b', 10973744)],
        semantics=('[Dodo -[die:]] (imp 0x00a76fc8, 174w): -[die:] (0xa76fc8, 174w): if (!dead@56): snd = [[MJSoundManager instance] multiSoundNamed:@"dodoDie.wav"] (class 0xa77254, name obj 0xf975c8); [snd setPitch:(age@88 > 900.0f (pool 0xa7723c) ? 1.0f : 3.0f)] (vmov.f32 #112 = 1.0 / #8 = 3.0 - r2 immediate labels were corrected against GNU objdump truth where VFP vmov immediates are involved); [snd playAtPosition:floatPos@24 afterDelay:(double)0.1] (0.1 double materialized from movw/movt 0x3fb99999/0xa0000000); travelFraction@284 = 0.0f (pool 0xa77268 = 0); [super die:arg] via msgSendSuper2 (sel cell 0xa77260, class 0xa77264)..\n'),
    ),
    dict(
        name='dd_15',
        method='Dodo -[doRemoteUpdate:]',
        types='v48@0:4{DodoUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIscc[3c]}8',
        start=10928600,
        end=10929552,
        disasm='disasm_worldtileloader_dd_15.txt',
        base_add=10928616,
        base_literal=10929548,
        boundary='ARM.exidx end 0x00a6c590 (listing bound); next ObjC IMP 0x00a6c590 Dodo -[remoteUpdate:]',
        selectors={
                 0xa6c560: (15225420, 'isNet'),
                 0xa6c564: (15225424, 'isClient'),
                 0xa6c588: (15225428, 'jumpAndCluck'),
        },
        imports={
                 0xa6c55c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6c558: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xa6c568: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa6c56c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa6c570: (17164644, 'OBJC_IVAR_$_Dodo.movementDirection', 260),
                 0xa6c574: (17164664, 'OBJC_IVAR_$_Dodo.remoteMovementDirection', 364),
                 0xa6c578: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa6c57c: (17164668, 'OBJC_IVAR_$_Dodo.remoteWalkSpeed', 360),
                 0xa6c584: (17164672, 'OBJC_IVAR_$_Dodo.remoteGoalSquare', 352),
        },
        classes={},
        instructions=[(10928600, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10929548, 'subseq r3, pc, r4, lsl 18')],
        calls=[(10928832, 'blx r2'), (10928912, 'blx r2'), (10929028, 'blx r2'), (10929088, 'bl sym.makeIntpair_int__int_'), (10929320, 'bl sym.makeIntpair_int__int_'), (10929480, 'blx r2')],
        branches=[(10928768, 'beq', 10928852), (10928844, 'bne', 10928852), (10928848, 'b', 10929488), (10928924, 'bne', 10929276), (10928964, 'beq', 10929272), (10929040, 'beq', 10929272), (10929272, 'b', 10929488), (10929436, 'beq', 10929484), (10929484, 'b', 10929488)],
        semantics=('[Dodo -[doRemoteUpdate:]] (imp 0x00a6c1d8, 238w): -[doRemoteUpdate:] (0xa6c1d8, 238w; 0x28-byte struct passed by value): `if (self.rider@132 && ![rider isNet]) return`. Server path (`![dynamicWorld@8 isClient]`): `if (rider && [rider isNet])`: remoteGoalSquare@352 = makeIntpair(w@0x18, w@0x1c); walkSpeed@316 = remoteWalkSpeed@360 = (float)(s16)w@0x20 / 255.0f (pool 0xa6c580); movementDirection@260 = remoteMovementDirection@364 = (s8)w@0x22; updateNeedsToBeSent@49 = 1. Client path: remoteGoalSquare@352 = makeIntpair(w18,w1c); remoteWalkSpeed@360 = (s16)w20/255.0f; remoteMovementDirection@364 = (s8)w22; if (byte w@0x23 != 0) [self jumpAndCluck]. No age sync (unlike Shark)..\n'),
    ),
    dict(
        name='dd_16',
        method='Dodo -[dodoUpdateNetDataForClient:]',
        types='{DodoUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIscc[3c]}12@0:4@8',
        start=10926976,
        end=10927420,
        disasm='disasm_worldtileloader_dd_16.txt',
        base_add=10926992,
        base_literal=10927416,
        boundary='ARM.exidx end 0x00a6bd3c (listing bound); next ObjC IMP 0x00a6bd3c Dodo -[creationNetDataForClient:]',
        selectors={
                 0xa6bd1c: (15225392, 'npcUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0xa6bd20: (17164676, 'OBJC_IVAR_$_Dodo.jumpAndCluckState', 264),
                 0xa6bd24: (17164644, 'OBJC_IVAR_$_Dodo.movementDirection', 260),
                 0xa6bd28: (17164636, 'OBJC_IVAR_$_Dodo.toSquare', 276),
                 0xa6bd30: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
        },
        classes={},
        instructions=[(10926976, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10927416, 'subseq r3, pc, ip, asr pc')],
        calls=[(10927076, 'bl loc.imp.objc_msgSend_stret'), (10927112, 'bl sym.imp.memset')],
        branches=[(10927056, 'beq', 10927084), (10927080, 'b', 10927116), (10927332, 'beq', 10927380)],
        semantics=('[Dodo -[dodoUpdateNetDataForClient:]] (imp 0x00a6bb80, 111w): -[dodoUpdateNetDataForClient:] (0xa6bb80, 111w; stret - r0 = out buffer): fills DodoUpdateNetData (0x28; tsv types `{DodoUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}IIscc[3c]}`): [0..0x18) = [self npcUpdateNetDataForClient:client] (0x18 stret, memset-0 on the nil-self guard); +0x18/+0x1c = toSquare@276 (2 ints); +0x20 = (s16)(walkSpeed@316 * 255.0f) (pool 0xa6bd34); +0x22 = (s8)movementDirection@260; +0x23 = 0, and if jumpAndCluckState@264 != 0 then out[0x23] = 1 and jumpAndCluckState@264 := 2 (the jump flag rides the update blob to be re-triggered by doRemoteUpdate\'s client path)..\n'),
    ),
    dict(
        name='dd_17',
        method='Dodo -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        types='v156@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76i140i144i148i152',
        start=10930496,
        end=10967852,
        disasm='disasm_worldtileloader_dd_17.txt',
        base_add=10930540,
        base_literal=10934608,
        boundary='ARM.exidx end 0x00a75b2c (listing bound); next ObjC IMP 0x00a76fc8 Dodo -[die:]',
        selectors={
                 0xa6d9e4: (15225444, 'worldWidthMacro'),
                 0xa6da1c: (15225448, 'macroTiles'),
                 0xa709ec: (15225452, 'program'),
                 0xa709f4: (15225464, 'intValue'),
                 0xa709f8: (15225460, 'objectAtIndex:'),
                 0xa709fc: (15225456, 'uniformLocations'),
                 0xa70a00: (15225468, 'dayColorForPosition:'),
                 0xa70a1c: (15225472, 'instance'),
                 0xa70a24: (15225476, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
                 0xa70a30: (15225480, 'multiSoundNamed:'),
                 0xa70a38: (15225484, 'playAtPosition:'),
                 0xa70a40: (15225488, 'name'),
                 0xa70a48: (15225492, 'draw'),
                 0xa72cf0: (15225456, 'uniformLocations'),
                 0xa72cf4: (15225460, 'objectAtIndex:'),
                 0xa72cf8: (15225464, 'intValue'),
                 0xa72d00: (15225488, 'name'),
                 0xa72d08: (15225492, 'draw'),
                 0xa753d4: (15225464, 'intValue'),
                 0xa753d8: (15225460, 'objectAtIndex:'),
                 0xa753dc: (15225456, 'uniformLocations'),
                 0xa753e8: (15225492, 'draw'),
                 0xa753f4: (15225344, 'textureNamed:'),
                 0xa753fc: (15225496, 'textureNamed:withAlpha:'),
                 0xa75b04: (15225464, 'intValue'),
                 0xa75b08: (15225460, 'objectAtIndex:'),
                 0xa75b0c: (15225456, 'uniformLocations'),
                 0xa75b10: (15225452, 'program'),
                 0xa75b14: (15225492, 'draw'),
                 0xa75b1c: (15225488, 'name'),
                 0xa75b20: (15225500, 'roundedTranslation'),
        },
        imports={
                 0xa6da18: (17151904, 'objc_msgSend'),
                 0xa709e8: (17151904, 'objc_msgSend'),
                 0xa70a34: (16348552, '__CFConstantStringClassReference'),
                 0xa753d0: (17151904, 'objc_msgSend'),
                 0xa753f8: (16348568, '__CFConstantStringClassReference'),
                 0xa75400: (16348584, '__CFConstantStringClassReference'),
                 0xa75404: (16348600, '__CFConstantStringClassReference'),
                 0xa75afc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6d9d8: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa6d9e0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa6da04: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa6da20: (17164640, 'OBJC_IVAR_$_Dodo.fromSquare', 268),
                 0xa6da24: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
                 0xa6da28: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xa6e048: (17164680, 'OBJC_IVAR_$_Dodo.walkTimer', 312),
                 0xa6e04c: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa6e054: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa6e3ec: (17164680, 'OBJC_IVAR_$_Dodo.walkTimer', 312),
                 0xa6e3f0: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa6e3f4: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa6e3f8: (17164644, 'OBJC_IVAR_$_Dodo.movementDirection', 260),
                 0xa6e3fc: (17164684, 'OBJC_IVAR_$_Dodo.bodyRotation', 304),
                 0xa6e400: (17164688, 'OBJC_IVAR_$_Dodo.randomGoalRotation', 308),
                 0xa6e404: (17164692, 'OBJC_IVAR_$_Dodo.yOffset', 332),
                 0xa6e408: (17164696, 'OBJC_IVAR_$_Dodo.xOffset', 336),
                 0xa6e40c: (17164608, 'OBJC_IVAR_$_Dodo.randomXOffset', 292),
                 0xa6e410: (17164700, 'OBJC_IVAR_$_Dodo.jumping', 348),
                 0xa6e414: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa6e420: (17164632, 'OBJC_IVAR_$_Dodo.travelFraction', 284),
                 0xa70460: (17164616, 'OBJC_IVAR_$_Dodo.peckTimer', 324),
                 0xa709e4: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa709f0: (17164588, 'OBJC_IVAR_$_Dodo.shader', 208),
                 0xa70a04: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa70a08: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa70a0c: (17164704, 'OBJC_IVAR_$_Dodo.createSplashNextFrame', 368),
                 0xa70a10: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa70a3c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0xa70a44: (17164584, 'OBJC_IVAR_$_Dodo.bodyTexture', 216),
                 0xa70a4c: (17164596, 'OBJC_IVAR_$_Dodo.bodyCube', 240),
                 0xa72ce8: (17164588, 'OBJC_IVAR_$_Dodo.shader', 208),
                 0xa72cfc: (17164580, 'OBJC_IVAR_$_Dodo.neckTexture', 220),
                 0xa72d04: (17164660, 'OBJC_IVAR_$_Dodo.neckCube', 244),
                 0xa72d0c: (17164576, 'OBJC_IVAR_$_Dodo.headTexture', 224),
                 0xa72d10: (17164656, 'OBJC_IVAR_$_Dodo.headCube', 248),
                 0xa72d14: (17164572, 'OBJC_IVAR_$_Dodo.legTexture', 228),
                 0xa72d18: (17164652, 'OBJC_IVAR_$_Dodo.legCube', 252),
                 0xa748c4: (17164568, 'OBJC_IVAR_$_Dodo.footTexture', 232),
                 0xa748c8: (17164648, 'OBJC_IVAR_$_Dodo.footCube', 256),
                 0xa753e0: (17164588, 'OBJC_IVAR_$_Dodo.shader', 208),
                 0xa753e4: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0xa753ec: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa75af8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa75b18: (17164596, 'OBJC_IVAR_$_Dodo.bodyCube', 240),
                 0xa75b24: (17164600, 'OBJC_IVAR_$_Dodo.nonStandardBodyShader', 212),
                 0xa75b28: (17164592, 'OBJC_IVAR_$_Dodo.breedWingTexture', 236),
        },
        classes={
                 0xa70a14: (15249140, 'OBJC_CLASS_$_ParticleEmitter'),
                 0xa70a28: (15249144, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(10930496, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10967848, 'invalid')],
        calls=[(10931212, 'bl loc.imp.objc_msgSend'), (10931236, 'bl sym.imp.__aeabi_idiv'), (10931304, 'bl loc.imp.objc_msgSend'), (10931432, 'bl loc.imp.objc_msgSend'), (10931448, 'bl sym.imp.__aeabi_idiv'), (10931516, 'bl loc.imp.objc_msgSend'), (10931648, 'bl loc.imp.objc_msgSend'), (10931672, 'bl sym.imp.__aeabi_idiv'), (10931740, 'bl loc.imp.objc_msgSend'), (10931868, 'bl loc.imp.objc_msgSend'), (10931884, 'bl sym.imp.__aeabi_idiv'), (10931952, 'bl loc.imp.objc_msgSend'), (10932244, 'bl method.Vector2.operator_float__'), (10932308, 'bl loc.imp.objc_msgSend'), (10932332, 'bl sym.imp.__aeabi_idiv'), (10932432, 'bl loc.imp.objc_msgSend'), (10932468, 'bl method.Vector2.operator_float__'), (10932524, 'bl method.Vector2.operator_float__'), (10932592, 'bl loc.imp.objc_msgSend'), (10932608, 'bl sym.imp.__aeabi_idiv'), (10932708, 'bl loc.imp.objc_msgSend'), (10932744, 'bl method.Vector2.operator_float__'), (10932884, 'blx r2'), (10932932, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (10933236, 'bl method.Vector2.operator_float__'), (10933264, 'bl method.Vector2.operator_float__'), (10933320, 'bl 0xa75b2c'), (10934324, 'bl 0xa6b654'), (10934556, 'bl sym.imp.sinf'), (10935040, 'bl sym.imp.sinf'), (10935264, 'bl sym.imp.sinf'), (10935764, 'bl 0xa75ba0'), (10936288, 'bl 0xa75d88'), (10936332, 'bl sym.imp.memcpy'), (10936804, 'bl 0xa75ba0'), (10936848, 'bl sym.imp.memcpy'), (10937284, 'bl 0xa76120'), (10937316, 'bl sym.imp.memcpy'), (10937804, 'bl 0xa76120'), (10937836, 'bl sym.imp.memcpy'), (10938276, 'bl 0xa75ba0'), (10938764, 'bl 0xa764b8'), (10938796, 'bl sym.imp.memcpy'), (10939176, 'bl 0xa75ba0'), (10939544, 'bl 0xa75ba0'), (10939916, 'bl 0xa75ba0'), (10940168, 'bl sym.imp.sinf'), (10940408, 'bl 0xa76670'), (10940712, 'bl sym.imp.sinf'), (10940948, 'bl 0xa76670'), (10941320, 'bl sym.imp.sinf'), (10941552, 'bl 0xa76670'), (10941580, 'bl sym.imp.memcpy'), (10941704, 'bl sym.imp.sinf'), (10942088, 'bl 0xa76670'), (10942588, 'bl 0xa75ba0'), (10942620, 'bl sym.imp.memcpy'), (10943012, 'bl 0xa75ba0'), (10943044, 'bl sym.imp.memcpy'), (10943456, 'bl 0xa764b8'), (10943488, 'bl sym.imp.memcpy'), (10943860, 'bl 0xa75ba0'), (10944232, 'bl 0xa75ba0'), (10944300, 'blx r2'), (10944304, 'bl sym.imp.__wrap_glUseProgram'), (10944436, 'blx r6'), (10944456, 'blx r3'), (10944472, 'blx r2'), (10944480, 'bl sym.imp.__wrap_glUniform1i'), (10944624, 'bl loc.imp.objc_msgSend_stret'), (10944664, 'bl sym.imp.memset'), (10945136, 'bl method.Vector.Vector_float__float__float_'), (10945156, 'bl method.Vector.operator_float__'), (10945228, 'bl method.Vector.operator_float__'), (10945280, 'bl method.Vector.operator_float__'), (10945352, 'bl method.Vector.operator_float__'), (10945404, 'bl method.Vector.operator_float__'), (10945476, 'bl method.Vector.operator_float__'), (10945548, 'bl method.Vector.Vector_float__float__float_'), (10945568, 'bl method.Vector.operator_float__'), (10945696, 'bl method.Vector.operator_float__'), (10945724, 'bl method.Vector.operator_float__'), (10945840, 'bl method.Vector.operator_float__'), (10945868, 'bl method.Vector.operator_float__'), (10945996, 'bl method.Vector.operator_float__'), (10946112, 'bl method.Vector.Vector_float__float__float__float_'), (10946128, 'bl method.Vector.operator_float__'), (10946144, 'bl method.Vector.operator_float__'), (10946160, 'bl method.Vector.operator_float__'), (10946196, 'bl method.Vector.Vector_float__float__float__float_'), (10946244, 'bl sym.Vector::operator_Vector_'), (10946360, 'bl method.Vector2.operator_float__'), (10946424, 'bl method.Vector.Vector_float__float__float_'), (10946496, 'bl loc.imp.objc_msgSend'), (10946504, 'bl 0xa6b654'), (10946556, 'bl 0xa6b654'), (10946624, 'bl method.Vector.Vector_float__float__float_'), (10946676, 'bl method.Vector.operator_Vector_'), (10946680, 'bl 0xa6b654'), (10946728, 'bl 0xa6b654'), (10946788, 'bl method.Vector.Vector_float__float__float_'), (10947020, 'bl loc.imp.objc_msgSend'), (10947212, 'bl loc.imp.objc_msgSend'), (10947236, 'bl loc.imp.objc_msgSend'), (10947300, 'bl loc.imp.objc_msgSend'), (10947464, 'blx r6'), (10947484, 'blx r3'), (10947500, 'blx r2'), (10947516, 'bl method.Vector.operator_float__'), (10947544, 'bl method.Vector.operator_float__'), (10947572, 'bl method.Vector.operator_float__'), (10947636, 'bl sym.imp.__wrap_glUniform4f'), (10947644, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (10948476, 'bl 0xa76a08'), (10949400, 'bl 0xa76a08'), (10949572, 'bl sym.imp.memcpy'), (10949620, 'blx ip'), (10949640, 'blx r3'), (10949656, 'blx r2'), (10949688, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10949828, 'blx r3'), (10949848, 'blx r3'), (10949864, 'blx r2'), (10949896, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10949976, 'blx r3'), (10949996, 'bl sym.imp.__wrap_glBindTexture'), (10950064, 'blx r2'), (10950860, 'bl 0xa76a08'), (10951784, 'bl 0xa76a08'), (10951972, 'bl loc.imp.objc_msgSend'), (10952008, 'bl loc.imp.objc_msgSend'), (10952032, 'bl loc.imp.objc_msgSend'), (10952068, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10952104, 'bl loc.imp.objc_msgSend'), (10952132, 'bl loc.imp.objc_msgSend'), (10952148, 'bl loc.imp.objc_msgSend'), (10952180, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10952228, 'bl loc.imp.objc_msgSend'), (10952256, 'bl sym.imp.__wrap_glBindTexture'), (10952304, 'bl loc.imp.objc_msgSend'), (10953100, 'bl 0xa76a08'), (10954024, 'bl 0xa76a08'), (10954192, 'bl loc.imp.objc_msgSend'), (10954212, 'bl loc.imp.objc_msgSend'), (10954228, 'bl loc.imp.objc_msgSend'), (10954244, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10954280, 'bl loc.imp.objc_msgSend'), (10954300, 'bl loc.imp.objc_msgSend'), (10954316, 'bl loc.imp.objc_msgSend'), (10954332, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10954372, 'bl loc.imp.objc_msgSend'), (10954392, 'bl sym.imp.__wrap_glBindTexture'), (10954432, 'bl loc.imp.objc_msgSend'), (10955228, 'bl 0xa76a08'), (10956208, 'bl 0xa76a08'), (10956376, 'bl loc.imp.objc_msgSend'), (10956396, 'bl loc.imp.objc_msgSend'), (10956412, 'bl loc.imp.objc_msgSend'), (10956428, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10956464, 'bl loc.imp.objc_msgSend'), (10956484, 'bl loc.imp.objc_msgSend'), (10956500, 'bl loc.imp.objc_msgSend'), (10956516, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10956556, 'bl loc.imp.objc_msgSend'), (10956576, 'bl sym.imp.__wrap_glBindTexture'), (10956620, 'bl loc.imp.objc_msgSend'), (10957416, 'bl 0xa76a08'), (10958340, 'bl 0xa76a08'), (10958508, 'bl loc.imp.objc_msgSend'), (10958528, 'bl loc.imp.objc_msgSend'), (10958544, 'bl loc.imp.objc_msgSend'), (10958560, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10958596, 'bl loc.imp.objc_msgSend'), (10958616, 'bl loc.imp.objc_msgSend'), (10958632, 'bl loc.imp.objc_msgSend'), (10958648, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10958684, 'bl loc.imp.objc_msgSend'), (10959480, 'bl 0xa76a08'), (10960404, 'bl 0xa76a08'), (10960572, 'bl loc.imp.objc_msgSend'), (10960592, 'bl loc.imp.objc_msgSend'), (10960608, 'bl loc.imp.objc_msgSend'), (10960624, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10960660, 'bl loc.imp.objc_msgSend'), (10960680, 'bl loc.imp.objc_msgSend'), (10960696, 'bl loc.imp.objc_msgSend'), (10960712, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10960752, 'bl loc.imp.objc_msgSend'), (10960772, 'bl sym.imp.__wrap_glBindTexture'), (10960812, 'bl loc.imp.objc_msgSend'), (10961608, 'bl 0xa76a08'), (10962532, 'bl 0xa76a08'), (10962704, 'bl sym.imp.memcpy'), (10962752, 'blx ip'), (10962772, 'blx r3'), (10962788, 'blx r2'), (10962820, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10962960, 'blx r3'), (10962980, 'blx r3'), (10962996, 'blx r2'), (10963028, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10963100, 'blx r2'), (10963208, 'bl loc.imp.objc_msgSend'), (10963268, 'bl loc.imp.objc_msgSend'), (10964060, 'bl 0xa76a08'), (10964980, 'bl 0xa76a08'), (10965052, 'bl sym.imp.memcpy'), (10965100, 'blx ip'), (10965104, 'bl sym.imp.__wrap_glUseProgram'), (10965236, 'blx r6'), (10965256, 'blx r3'), (10965272, 'blx r2'), (10965280, 'bl sym.imp.__wrap_glUniform1i'), (10965412, 'blx r6'), (10965432, 'blx r3'), (10965448, 'blx r2'), (10965456, 'bl sym.imp.__wrap_glUniform1i'), (10965588, 'blx r6'), (10965608, 'blx r3'), (10965624, 'blx r2'), (10965632, 'bl sym.imp.__wrap_glUniform1i'), (10965684, 'bl method.Vector.operator_float__'), (10965756, 'bl method.Vector.operator_float__'), (10965828, 'bl method.Vector.operator_float__'), (10965872, 'bl method.Vector.Vector_float__float__float_'), (10965960, 'bl loc.imp.objc_msgSend_stret'), (10966060, 'bl sym.imp.memset'), (10966192, 'blx r6'), (10966212, 'blx r3'), (10966228, 'blx r2'), (10966244, 'bl method.Vector.operator_float__'), (10966264, 'bl method.Vector.operator_float__'), (10966284, 'bl method.Vector.operator_float__'), (10966340, 'bl sym.imp.__wrap_glUniform4f'), (10966476, 'blx r6'), (10966496, 'blx r3'), (10966512, 'blx r2'), (10966528, 'bl method.Vector.operator_float__'), (10966552, 'bl method.Vector.operator_float__'), (10966576, 'bl method.Vector.operator_float__'), (10966632, 'bl sym.imp.__wrap_glUniform4f'), (10966768, 'blx r6'), (10966788, 'blx r3'), (10966804, 'blx r2'), (10966820, 'bl method.Vector2.operator_float__'), (10966844, 'bl method.Vector2.operator_float__'), (10966876, 'bl method.Vector2.operator_float__'), (10966900, 'bl method.Vector2.operator_float__'), (10966960, 'bl sym.imp.__wrap_glUniform4f'), (10966968, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (10967108, 'blx r3'), (10967128, 'blx r3'), (10967144, 'blx r2'), (10967176, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10967316, 'blx r3'), (10967336, 'blx r3'), (10967352, 'blx r2'), (10967384, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (10967444, 'blx r3'), (10967464, 'bl sym.imp.__wrap_glBindTexture'), (10967472, 'bl sym.imp.__wrap_glActiveTexture'), (10967532, 'blx r3'), (10967552, 'bl sym.imp.__wrap_glBindTexture'), (10967560, 'bl sym.imp.__wrap_glActiveTexture'), (10967640, 'blx r3'), (10967660, 'bl sym.imp.__wrap_glBindTexture'), (10967740, 'blx r2'), (10967752, 'bl sym.imp.__wrap_glBindTexture'), (10967760, 'bl sym.imp.__wrap_glActiveTexture'), (10967772, 'bl sym.imp.__wrap_glBindTexture'), (10967780, 'bl sym.imp.__wrap_glActiveTexture'), (10967788, 'bl sym.imp.__wrap_glDisableVertexAttribArray')],
        branches=[(10931248, 'blt', 10931340), (10931336, 'b', 10931552), (10931460, 'bge', 10931548), (10931548, 'b', 10931552), (10931684, 'blt', 10931776), (10931772, 'b', 10931988), (10931896, 'bge', 10931984), (10931984, 'b', 10931988), (10932028, 'blt', 10932164), (10932072, 'bgt', 10932164), (10932116, 'blt', 10932164), (10932160, 'ble', 10932168), (10932164, 'b', 10967792), (10932360, 'ble', 10932496), (10932492, 'b', 10932772), (10932636, 'bpl', 10932768), (10932768, 'b', 10932772), (10932956, 'beq', 10932980), (10932976, 'bne', 10933020), (10933016, 'b', 10967792), (10933084, 'bne', 10933228), (10933384, 'bne', 10933512), (10933448, 'bpl', 10933508), (10933504, 'b', 10933400), (10933508, 'b', 10933980), (10933524, 'bne', 10933652), (10933588, 'ble', 10933648), (10933644, 'b', 10933540), (10933648, 'b', 10933976), (10933736, 'ble', 10933796), (10933792, 'b', 10933688), (10933796, 'b', 10933800), (10933848, 'bpl', 10933972), (10933904, 'b', 10933800), (10933972, 'b', 10933976), (10933976, 'b', 10933980), (10934160, 'bne', 10935340), (10934200, 'beq', 10934612), (10934252, 'ble', 10934408), (10934320, 'bne', 10934392), (10934392, 'b', 10934604), (10934456, 'ble', 10934600), (10934600, 'b', 10934604), (10934604, 'b', 10935336), (10934648, 'beq', 10935332), (10934720, 'bpl', 10934852), (10934740, 'b', 10934868), (10935124, 'bpl', 10935172), (10935332, 'b', 10935336), (10935336, 'b', 10935340), (10936364, 'beq', 10937844), (10936368, 'b', 10936408), (10936880, 'ble', 10937404), (10937320, 'b', 10937840), (10937840, 'b', 10937844), (10937896, 'bpl', 10938800), (10939956, 'beq', 10941584), (10941148, 'b', 10941196), (10941628, 'bpl', 10942644), (10942624, 'b', 10943048), (10943100, 'bpl', 10943492), (10944584, 'beq', 10944632), (10944628, 'b', 10944668), (10944792, 'bpl', 10944816), (10944812, 'b', 10944832), (10944880, 'bpl', 10944904), (10944900, 'b', 10944920), (10944968, 'ble', 10945040), (10945608, 'bpl', 10945644), (10945628, 'b', 10945660), (10945764, 'bpl', 10945788), (10945784, 'b', 10945804), (10945908, 'bpl', 10945944), (10945928, 'b', 10945960), (10946048, 'beq', 10947332), (10946460, 'bge', 10947152), (10947040, 'b', 10946448), (10947684, 'bne', 10950068), (10956004, 'b', 10956060), (10963132, 'beq', 10967784), (10963136, 'b', 10963148), (10965940, 'beq', 10966028), (10965964, 'b', 10966064)],
        semantics=('[Dodo -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]] (imp 0x00a6c940, 9339w): -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] (0xa6c940, 9339w) [census]: the render giant (float dt + two _GLKMatrix4 by value + 5 camera ints; ~11.7KB locals with stacked scratch arenas). 272 calls: 58 objc_msgSend, 16 glUniformMatrix4fv, 10 glBindTexture, 7 sinf, 4 glUniform1i, 4 glUniform4f, 4 glActiveTexture (units 0x84c0/0x84c1/0x84c2 = GL_TEXTURE0-2), 2 glUseProgram, 2 glEnableVertexAttribArray + 1 glDisable, 12 memcpy (64-byte matrices), 38 Vector/Vector2 math calls, 6 __aeabi_idiv, 5 lrand48 (wrapper 0xa6b654), local helper family 0xa75b2c / 0xa75ba0 x12 / 0xa75d88 / 0xa76120 x2 / 0xa764b8 x2 / 0xa76670 x4 / 0xa76a08 x16 (matrix compose + quad emitters). Flow: (1) prologue: walk state (fromSquare/toSquare/travelFraction), pos vs worldWidthMacro cell 0xa6d9e4 with `lsl 5` + idiv /32 macro-tile math, tileAtWorldPosition (ground/seam checks); (2) animation 0xa6d91c-0xa6f688: 7 sinf + 12 helper 0xa75ba0 calls + memcpy(64B) chain = leg/head bob matrices (float pool 0.5/2.0/10.0/1.0/4.0/-0.5 via GL-truth); (3) glUseProgram([self.shader@208 program], call #64 @0xa6ff30); glUniform1i(tex unit 0) @0xa6ffe0; [world dayColorForPosition:]-style stret + ParticleEmitter bubbles (addParticleAtPos:velocity:color:gravityType:life:scale: @0xa70a24) + [[MJSoundManager instance] multiSoundNamed:@"splash.wav" (obj 0xf97588, cell 0xa70a34)] playAtPosition + createSplashNextFrame@368 flag; glUniform4f(light/color @0xa70c34); glEnableVertexAttribArray(2); (4) EIGHT textured draw blocks 0xa70f7c..0xa74ff4 (body 0xa70a44/4c, neck 0xa72cfc/d04, head 0xa72d0c/d10, leg 0xa72d14/d18, foot 0xa748c4/c8 ivar cells): each block = 2x helper 0xa76a08 + glUniformMatrix4fv(mvp) + glUniformMatrix4fv(normal) + glBindTexture(GL_TEXTURE_2D 0xde1) + cube \'draw\'; (5) tail 0xa7506c+: second glUseProgram (nonStandardBodyShader@212) + glUniform1i x3 + glUniform4f x3 + 2x glUniformMatrix4fv + 5x glBindTexture + 4x glActiveTexture(GL_TEXTURE0/1/2) + bodyCube@240/breedWingTexture@236 cells (0xa75b18/0xa75b24/0xa75b28) + glDisableVertexAttribArray = the BREED body pass (multi-texture body cube path). Census grade: call histogram + constant pools + sampled windows; per-block matrix contents not individually decoded..\n'),
    ),
    dict(
        name='dd_18',
        method='Dodo -[foodItemType]',
        types='i8@0:4',
        start=10921060,
        end=10921088,
        disasm='disasm_worldtileloader_dd_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6a508; body trimmed at the next IMP 0x00a6a480 Dodo -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10921060, 'sub sp, sp, 8'), (10921084, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[foodItemType]] (imp 0x00a6a464, 7w): -[foodItemType] (0xa6a464, 7w): returns 0x15 (21; item table = APPLE)..\n'),
    ),
    dict(
        name='dd_19',
        method='Dodo -[getNamesArray]',
        types='^@8@0:4',
        start=10921144,
        end=10921192,
        disasm='disasm_worldtileloader_dd_19.txt',
        base_add=10921152,
        base_literal=10921188,
        boundary='ARM.exidx end 0x00a6a508; body trimmed at the next IMP 0x00a6a4e8 Dodo -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10921144, 'sub sp, sp, 8'), (10921188, 'subseq r5, pc, ip, lsr 12')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[getNamesArray]] (imp 0x00a6a4b8, 12w): -[getNamesArray] (0xa6a4b8, 12w): returns the CFString* name table at 0x10524D8 (r2 = pc + 0x5f562c + 0xffff29e4). 244 entries read: [0]=\'Charlie\', [1]=\'Angel\', [2]=\'Skittles\', [3]=\'Coco\', [4]=\'Max\', [5]=\'Sunny\', ..., [243]=\'Sky\'..\n'),
    ),
    dict(
        name='dd_20',
        method='Dodo -[getNamesArrayCount]',
        types='i8@0:4',
        start=10921192,
        end=10921224,
        disasm='disasm_worldtileloader_dd_20.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6a508 (listing bound); next ObjC IMP 0x00a6a508 Dodo -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10921192, 'sub sp, sp, 8'), (10921220, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[getNamesArrayCount]] (imp 0x00a6a4e8, 8w): -[getNamesArrayCount] (0xa6a4e8, 8w): returns 0xf4 (244)..\n'),
    ),
    dict(
        name='dd_21',
        method='Dodo -[getRandomDirection]',
        types='i8@0:4',
        start=10930344,
        end=10930496,
        disasm='disasm_worldtileloader_dd_21.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6c940 (listing bound); next ObjC IMP 0x00a6c940 Dodo -[draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10930344, 'push {fp, lr}'), (10930492, 'andeq r0, r0, r0')],
        calls=[(10930364, 'bl 0xa6b654')],
        branches=[(10930408, 'ble', 10930424), (10930420, 'b', 10930468)],
        semantics=('[Dodo -[getRandomDirection]] (imp 0x00a6c8a8, 38w): -[getRandomDirection] (0xa6c8a8, 38w): u = lrand48()/2147483648.0f (pool 0xa6c938); u > 0.75 -> +1; u < 0.25 -> -1; else 0. (GL-truth immediates 0.75/0.25 - r2 immediate labels were corrected against GNU objdump truth where VFP vmov immediates are involved.).\n'),
    ),
    dict(
        name='dd_22',
        method='Dodo -[hitWithForce:blockhead:]',
        types='v16@0:4i8@12',
        start=11007852,
        end=11008248,
        disasm='disasm_worldtileloader_dd_22.txt',
        base_add=11007868,
        base_literal=11008244,
        boundary='ARM.exidx end 0x00a7f8f8 (listing bound); next ObjC IMP 0x00a7f8f8 Dodo -[renderPos]',
        selectors={
                 0xa7f8d4: (15225608, 'hitWithForce:blockhead:'),
        },
        imports={
                 0xa7f8d0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa7f8dc: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xa7f8e0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa7f8e4: (17164628, 'OBJC_IVAR_$_Dodo.randomTimeBetweenDirectionChanges', 288),
                 0xa7f8e8: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa7f8ec: (17164644, 'OBJC_IVAR_$_Dodo.movementDirection', 260),
        },
        classes={
                 0xa7f8d8: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(11007852, 'push {r4, r5, r6, sl, fp, lr}'), (11008244, 'subseq r0, lr, r0, ror r3')],
        calls=[(11007952, 'blx r4'), (11008028, 'bl 0xa6b654')],
        branches=[(11007988, 'bne', 11008200), (11008024, 'bne', 11008200)],
        semantics=('[Dodo -[hitWithForce:blockhead:]] (imp 0x00a7f76c, 99w): -[hitWithForce:blockhead:] (0xa7f76c, 99w): [super hitWithForce:force blockhead:bh] via msgSendSuper2 (class cell 0xa7f8d8). Then if (!dead@56 && !isNet@52): u = lrand48()/2^31 (pool 0xa7f8f0); movementDirection@260 = (u > 0.5 ? +1 : -1) (GL-truth 0.5 - r2 immediate labels were corrected against GNU objdump truth where VFP vmov immediates are involved); walkSpeed@316 = 3.0f; randomTimeBetweenDirectionChanges@288 = 5.0f..\n'),
    ),
    dict(
        name='dd_23',
        method='Dodo -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=10925668,
        end=10926044,
        disasm='disasm_worldtileloader_dd_23.txt',
        base_add=10925684,
        base_literal=10926040,
        boundary='ARM.exidx end 0x00a6b7dc (listing bound); next ObjC IMP 0x00a6b7dc Dodo -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xa6b7cc: (15225368, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0xa6b7d4: (15225372, 'loadDerivedStuff'),
        },
        imports={
                 0xa6b7d0: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa6b7c4: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(10925668, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10926040, 'subseq r4, pc, r8, ror r4')],
        calls=[(10925912, 'bl loc.imp.objc_msgSendSuper2'), (10925996, 'blx r2')],
        branches=[(10925940, 'bne', 10925956), (10925952, 'b', 10926008)],
        semantics=('[Dodo -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]] (imp 0x00a6b664, 94w): -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] (0xa6b664, 94w): [super <same 8-arg selector>] via objc_msgSendSuper2 (superstruct {self, Dodo class cell 0xa6b7c4}; sel cell 0xa6b7cc; the six tail args staged on the stack at sp..sp+0x18); if result == nil -> return nil; else [self loadDerivedStuff] (sel cell 0xa6b7d4) and return self. Unlike Shark, no tile/water/temperature placement gate here..\n'),
    ),
    dict(
        name='dd_24',
        method='Dodo -[initWithWorld:dynamicWorld:cache:netData:]',
        types='@24@0:4@8@12@16@20',
        start=10926340,
        end=10926852,
        disasm='disasm_worldtileloader_dd_24.txt',
        base_add=10926356,
        base_literal=10926848,
        boundary='ARM.exidx end 0x00a6bb04 (listing bound); next ObjC IMP 0x00a6bb04 Dodo -[getSaveDict]',
        selectors={
                 0xa6bad8: (15225380, 'initWithWorld:dynamicWorld:cache:netData:'),
                 0xa6bae4: (15225384, 'remoteCreationDataUpdate:'),
                 0xa6bafc: (15225372, 'loadDerivedStuff'),
        },
        imports={
                 0xa6bad4: (17151900, 'objc_msgSendSuper2'),
                 0xa6bae0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa6bae8: (17164664, 'OBJC_IVAR_$_Dodo.remoteMovementDirection', 364),
                 0xa6baf0: (17164668, 'OBJC_IVAR_$_Dodo.remoteWalkSpeed', 360),
                 0xa6baf4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa6baf8: (17164672, 'OBJC_IVAR_$_Dodo.remoteGoalSquare', 352),
        },
        classes={
                 0xa6badc: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(10926340, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10926848, 'ldrsbeq r4, [pc], -0x18')],
        calls=[(10926492, 'blx r6'), (10926660, 'blx r7'), (10926780, 'blx r5')],
        branches=[(10926520, 'bne', 10926536), (10926532, 'b', 10926792)],
        semantics=('[Dodo -[initWithWorld:dynamicWorld:cache:netData:]] (imp 0x00a6b904, 128w): -[initWithWorld:dynamicWorld:cache:netData:] (0xa6b904, 128w): [super <netData selector>] via objc_msgSendSuper2 (class cell 0xa6badc); nil -> nil; [self loadDerivedStuff]; remoteGoalSquare@352 = self.pos@16 (2-word copy); remoteWalkSpeed@360 = 0.0f (pool 0xa6baec); remoteMovementDirection@364 = 0; [self remoteCreationDataUpdate:netData] (sel cell 0xa6bae4); return self..\n'),
    ),
    dict(
        name='dd_25',
        method='Dodo -[jumpAndCluck]',
        types='v8@0:4',
        start=10973824,
        end=10974956,
        disasm='disasm_worldtileloader_dd_25.txt',
        base_add=10973840,
        base_literal=10974952,
        boundary='ARM.exidx end 0x00a776ec (listing bound); next ObjC IMP 0x00a776ec Dodo -[createItemDropsForDeath]',
        selectors={
                 0xa77674: (15225516, 'isServer'),
                 0xa776cc: (15225480, 'multiSoundNamed:'),
                 0xa776d0: (15225472, 'instance'),
                 0xa776d8: (15225504, 'setPitch:'),
                 0xa776e4: (15225508, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xa77670: (17151904, 'objc_msgSend'),
                 0xa776bc: (16348680, '__CFConstantStringClassReference'),
                 0xa776c0: (16348664, '__CFConstantStringClassReference'),
                 0xa776c4: (16348648, '__CFConstantStringClassReference'),
                 0xa776c8: (16348632, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa77678: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa7767c: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0xa77680: (17164676, 'OBJC_IVAR_$_Dodo.jumpAndCluckState', 264),
                 0xa77684: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0xa7768c: (17164688, 'OBJC_IVAR_$_Dodo.randomGoalRotation', 308),
                 0xa77690: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa77694: (17164680, 'OBJC_IVAR_$_Dodo.walkTimer', 312),
                 0xa77698: (17164604, 'OBJC_IVAR_$_Dodo.randomCluckNoiseTimer', 300),
                 0xa776a8: (17164700, 'OBJC_IVAR_$_Dodo.jumping', 348),
                 0xa776b0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa776dc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0xa776d4: (15249144, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(10973824, 'push {r4, r5, fp, lr}'), (10974952, 'subseq r8, lr, ip, asr r8')],
        calls=[(10973900, 'blx r3'), (10974108, 'bl 0xa6b654'), (10974188, 'bl 0xa6b654'), (10974540, 'blx r3'), (10974560, 'blx r3'), (10974664, 'blx r3'), (10974732, 'blx r3'), (10974820, 'bl loc.imp.objc_msgSend')],
        branches=[(10973912, 'beq', 10973976), (10974104, 'bne', 10974188), (10974268, 'bpl', 10974344), (10974320, 'ble', 10974344), (10974340, 'b', 10974448), (10974360, 'bpl', 10974384), (10974380, 'b', 10974444), (10974400, 'bpl', 10974424), (10974420, 'b', 10974440), (10974440, 'b', 10974444), (10974444, 'b', 10974448), (10974600, 'ble', 10974672), (10974668, 'b', 10974736)],
        semantics=('[Dodo -[jumpAndCluck]] (imp 0x00a77280, 283w): -[jumpAndCluck] (0xa77280, 283w): if ([dynamicWorld@8 isServer]): jumpAndCluckState@264 = 1 and updateNeedsToBeSent@49 = 1. Then randomGoalRotation@308 = 0.0f; walkSpeed@316 = 1.0f; walkTimer@312 = 0.0f. If (!isNet@52): randomCluckNoiseTimer@300 = (lrand48()/2^31)*100.0f + 20.0f (pools 0xa7769c/0x42c80000=100.0, GL-truth 20.0); u = lrand48()/2^31; jumping@348 = 1; sound pick: u < 0.05 && age@88 > 900.0f -> @"dodoCluck4.wav" (0xf975d8); else u < 0.4 -> @"dodoCluck1.wav" (0xf975e8); else u < 0.7 -> @"dodoCluck2.wav" (0xf975f8); else @"dodoCluck3.wav" (0xf97608); [[MJSoundManager instance] multiSoundNamed:sound]; setPitch(age > 900 ? 1.0f : 3.0f); [snd playAtPosition:floatPos@24 afterDelay:(double)0.6] (0x3fe3333340000000)..\n'),
    ),
    dict(
        name='dd_26',
        method='Dodo -[jumpsOnSwipe]',
        types='c8@0:4',
        start=11012492,
        end=11012520,
        disasm='disasm_worldtileloader_dd_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a809a8 (listing bound); next ObjC IMP 0x00a809a8 Dodo -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11012492, 'sub sp, sp, 8'), (11012516, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[jumpsOnSwipe]] (imp 0x00a8098c, 7w): -[jumpsOnSwipe] (0xa8098c, 7w): returns NO (movw r2,#0 + sxtb)..\n'),
    ),
    dict(
        name='dd_27',
        method='Dodo -[loadDerivedStuff]',
        types='v8@0:4',
        start=10921224,
        end=10925068,
        disasm='disasm_worldtileloader_dd_27.txt',
        base_add=10921244,
        base_literal=10925064,
        boundary='ARM.exidx end 0x00a6b40c (listing bound); next ObjC IMP 0x00a6b664 Dodo -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0xa6b320: (15225344, 'textureNamed:'),
                 0xa6b350: (15225340, 'shaderNamed:attributes:uniforms:'),
                 0xa6b364: (15225336, 'arrayWithObjects:'),
                 0xa6b3a8: (15225348, 'alloc'),
                 0xa6b3ac: (15225356, 'initMultiTextureWithWidth:height:depth:centerX:centerY:centerZ:topTexCoords:sideTexCoords:topTexCoordsB:sideTexCoordsB:calculateNormals:useBoxTexCoordsForB:'),
                 0xa6b3b0: (15225352, 'initWithWidth:height:depth:calculateNormals:'),
                 0xa6b3f0: (15225364, 'getRandomDirection'),
                 0xa6b3fc: (15225360, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
        },
        imports={
                 0xa6b318: (16348424, '__CFConstantStringClassReference'),
                 0xa6b31c: (17151904, 'objc_msgSend'),
                 0xa6b32c: (16348408, '__CFConstantStringClassReference'),
                 0xa6b334: (16348392, '__CFConstantStringClassReference'),
                 0xa6b33c: (16348376, '__CFConstantStringClassReference'),
                 0xa6b344: (16348360, '__CFConstantStringClassReference'),
                 0xa6b34c: (16348232, '__CFConstantStringClassReference'),
                 0xa6b354: (16348296, '__CFConstantStringClassReference'),
                 0xa6b358: (16348312, '__CFConstantStringClassReference'),
                 0xa6b35c: (16348328, '__CFConstantStringClassReference'),
                 0xa6b360: (16348344, '__CFConstantStringClassReference'),
                 0xa6b36c: (16348248, '__CFConstantStringClassReference'),
                 0xa6b370: (16348264, '__CFConstantStringClassReference'),
                 0xa6b374: (16348280, '__CFConstantStringClassReference'),
                 0xa6b37c: (16348536, '__CFConstantStringClassReference'),
                 0xa6b388: (16348520, '__CFConstantStringClassReference'),
                 0xa6b38c: (16348504, '__CFConstantStringClassReference'),
                 0xa6b390: (16348488, '__CFConstantStringClassReference'),
                 0xa6b394: (16348472, '__CFConstantStringClassReference'),
                 0xa6b398: (16348456, '__CFConstantStringClassReference'),
                 0xa6b39c: (16348440, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa6b310: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0xa6b314: (17164568, 'OBJC_IVAR_$_Dodo.footTexture', 232),
                 0xa6b324: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xa6b328: (17164572, 'OBJC_IVAR_$_Dodo.legTexture', 228),
                 0xa6b330: (17164576, 'OBJC_IVAR_$_Dodo.headTexture', 224),
                 0xa6b338: (17164580, 'OBJC_IVAR_$_Dodo.neckTexture', 220),
                 0xa6b340: (17164584, 'OBJC_IVAR_$_Dodo.bodyTexture', 216),
                 0xa6b348: (17164588, 'OBJC_IVAR_$_Dodo.shader', 208),
                 0xa6b378: (17164592, 'OBJC_IVAR_$_Dodo.breedWingTexture', 236),
                 0xa6b380: (17164596, 'OBJC_IVAR_$_Dodo.bodyCube', 240),
                 0xa6b3a0: (17164600, 'OBJC_IVAR_$_Dodo.nonStandardBodyShader', 212),
                 0xa6b3b4: (17164604, 'OBJC_IVAR_$_Dodo.randomCluckNoiseTimer', 300),
                 0xa6b3c0: (17164608, 'OBJC_IVAR_$_Dodo.randomXOffset', 292),
                 0xa6b3c4: (17164612, 'OBJC_IVAR_$_Dodo.randomXOffsetGoal', 296),
                 0xa6b3c8: (17164616, 'OBJC_IVAR_$_Dodo.peckTimer', 324),
                 0xa6b3cc: (17164620, 'OBJC_IVAR_$_Dodo.nextPeckTimer', 328),
                 0xa6b3d4: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa6b3d8: (17164628, 'OBJC_IVAR_$_Dodo.randomTimeBetweenDirectionChanges', 288),
                 0xa6b3dc: (17164632, 'OBJC_IVAR_$_Dodo.travelFraction', 284),
                 0xa6b3e0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa6b3e4: (17164636, 'OBJC_IVAR_$_Dodo.toSquare', 276),
                 0xa6b3e8: (17164640, 'OBJC_IVAR_$_Dodo.fromSquare', 268),
                 0xa6b3ec: (17164644, 'OBJC_IVAR_$_Dodo.movementDirection', 260),
                 0xa6b3f4: (17164648, 'OBJC_IVAR_$_Dodo.footCube', 256),
                 0xa6b3f8: (17164652, 'OBJC_IVAR_$_Dodo.legCube', 252),
                 0xa6b400: (17164656, 'OBJC_IVAR_$_Dodo.headCube', 248),
                 0xa6b404: (17164660, 'OBJC_IVAR_$_Dodo.neckCube', 244),
        },
        classes={
                 0xa6b368: (15249128, 'OBJC_CLASS_$_NSArray'),
                 0xa6b3a4: (15249132, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(10921224, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10925064, 'ldrsbeq r5, [pc], -0x50')],
        calls=[(10921676, 'blx r4'), (10921740, 'blx r5'), (10921784, 'blx lr'), (10921844, 'blx ip'), (10921904, 'blx ip'), (10921964, 'blx ip'), (10922024, 'blx ip'), (10922084, 'blx ip'), (10922224, 'blx r3'), (10922272, 'blx lr'), (10922536, 'bl loc.imp.objc_msgSend'), (10922676, 'bl loc.imp.objc_msgSend'), (10922716, 'bl loc.imp.objc_msgSend'), (10922768, 'bl 0xa6b40c'), (10922792, 'bl sym.texCoordsForImageIndex_int_'), (10922828, 'bl 0xa6b608'), (10922864, 'bl loc.imp.objc_msgSend'), (10923284, 'bl loc.imp.objc_msgSend'), (10923344, 'blx ip'), (10923752, 'blx r2'), (10923836, 'blx lr'), (10923888, 'blx ip'), (10923968, 'blx lr'), (10924020, 'blx ip'), (10924104, 'blx lr'), (10924156, 'blx ip'), (10924212, 'blx lr'), (10924252, 'blx r3'), (10924432, 'bl 0xa6b654'), (10924504, 'bl 0xa6b654'), (10924612, 'bl 0xa6b654'), (10924708, 'bl 0xa6b654')],
        branches=[(10922132, 'bne', 10922304), (10922296, 'b', 10923368), (10924380, 'b', 10924408)],
        semantics=('[Dodo -[loadDerivedStuff]] (imp 0x00a6a508, 961w): -[loadDerivedStuff] (0xa6a508, 961w) [census-lite]: builds all render resources from [self cache]@32. Shader 1: [cache shaderNamed:@"ShadedWorldObject" (obj 0xf97448) attributes:arrayWithObjects(@"position",@"texCoord",@"normal") uniforms:arrayWithObjects(@"mvp_matrix",@"texture",@"light",@"normal_matrix")] -> shader@208. Textures via [cache textureNamed:]: @"dodoBody.png"(0xf974c8) -> bodyTexture@216, @"dodoNeck.png"(0xf974d8) -> neckTexture@220, @"dodoHead.png"(0xf974e8) -> headTexture@224, @"dodoLeg.png"(0xf974f8) -> legTexture@228, @"dodoFoot.png"(0xf97508) -> footTexture@232. breed@96 == 0 (wild): bodyCube@240 = [[DrawCube alloc] initWithWidth:0.4f height:0.4f depth:0.4f calculateNormals:YES] (4-arg variant, pool 0xa6a93c = 0x3ecccccd). breed != 0 (bred): shader 2 = [cache shaderNamed:@"DodoBreedBody"(0xf97518) attributes:... uniforms:...] -> nonStandardBodyShader@212 (extended name sets incl. @"wing_texture"(0xf97568)/@"lightPosition"(0xf97558)/@"artificalLight"(0xf97548)/@"destruct_texture"(0xf97538)/@"daylight"(0xf97528) plus reused mvp_matrix/texture/normal_matrix); breedWingTexture@236 = [cache textureNamed:@"dodoWings.png"(0xf97578)]; texCoordsForImageIndex(imageTypeForDodoBreed(breed)) -> 4-float top-tex-coords block (helper 0xa6b40c = imageTypeForDodoBreed: 33-arm jump table @0xa6b458, breed 0/>=33 -> 0x2e5(741), special arms 15->667, 17->666, 18->670, 19->668, 20->669, 21->112, 22->113, 23->115, 24->85, 25->190, 26->672, 27..32->697..702; other breeds -> imageTypeForItemType(itemTypeForDodoBreed(breed))); bodyCube@240 = [[DrawCube alloc] initMultiTextureWithWidth:0.4 height:0.4 depth:0.4 centerX:0.2 centerY:0.2 centerZ:0.2 topTexCoords:sideTexCoords:topTexCoordsB:sideTexCoordsB:calculateNormals:1 useBoxTexCoordsForB:1] (0.2 = 0.4 * 0.5 GL-truth; the 12-arg multi-texture variant, 4-float arg blocks written by helper 0xa6b608). Both paths then: neckCube@244 = initWithWidth:1.0 height:0.4 depth:1.0 center(0.0625,0,0.0625) (8-arg variant); headCube@248 = (0.25,0.125,0.125) center(0.25,0.0625,0.0625); legCube@252 = (0.0625,0.275,0.0625) center(0.03125,0.15,0.03125) (pools 0xa6b160=0.0, 0xa6b164=0.0625, 0xa6b168=0.275, 0xa6b16c=0.03125, 0xa6b170=0.15, 0xa6b174=0.4); footCube@256 = initWithWidth:0.25 height:0.0625 depth:0.125 calculateNormals:YES (4-arg variant). Locomotion init: movementDirection@260 = [self getRandomDirection]; fromSquare@268 = toSquare@276 = pos@16 (2-word copies); travelFraction@284 = 1.0f; randomTimeBetweenDirectionChanges@288 = 0.0f; randomXOffset@292 = randomXOffsetGoal@296 = (lrand48()/2^31)*0.8 - 0.4 (double pools 0xa6b300/0xa6b308); randomCluckNoiseTimer@300 = (lrand48()/2^31)*100.0f + 20.0f; peckTimer@324 = 1.0f; nextPeckTimer@328 = (lrand48()/2^31)*2.0f + 0.1f; walkSpeed@316 = (lrand48()/2^31 + 0.25) * 2.0f (GL-truth 0.25/2.0; r2 misprints as 2/2). All VFP immediates verified against GNU objdump..\n'),
    ),
    dict(
        name='dd_28',
        method='Dodo -[maxAge]',
        types='f8@0:4',
        start=10920964,
        end=10921012,
        disasm='disasm_worldtileloader_dd_28.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6a434 (listing bound); next ObjC IMP 0x00a6a434 Dodo -[speciesName]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10920964, 'sub sp, sp, 0x10'), (10921008, 'strbmi r0, [r1, 0]!')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[maxAge]] (imp 0x00a6a404, 12w): -[maxAge] (0xa6a404, 12w): returns 7200.0f (0x45e10000; int echo movw 0x1c20; pool 0xa6a430 = 0x45e10000)..\n'),
    ),
    dict(
        name='dd_29',
        method='Dodo -[maxHealth]',
        types='S8@0:4',
        start=11006236,
        end=11006264,
        disasm='disasm_worldtileloader_dd_29.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a7f138 (listing bound); next ObjC IMP 0x00a7f138 Dodo -[tapIsWithinBodyRadius:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11006236, 'sub sp, sp, 8'), (11006260, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[maxHealth]] (imp 0x00a7f11c, 7w): -[maxHealth] (0xa7f11c, 7w): returns 0x10 (16; uxth)..\n'),
    ),
    dict(
        name='dd_30',
        method='Dodo -[npcType]',
        types='i8@0:4',
        start=10920936,
        end=10920964,
        disasm='disasm_worldtileloader_dd_30.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a6a404 (listing bound); next ObjC IMP 0x00a6a404 Dodo -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10920936, 'sub sp, sp, 8'), (10920960, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[npcType]] (imp 0x00a6a3e8, 7w): -[npcType] (0xa6a3e8, 7w): returns 1..\n'),
    ),
    dict(
        name='dd_31',
        method='Dodo -[reactToBeingFed]',
        types='v8@0:4',
        start=11008396,
        end=11009384,
        disasm='disasm_worldtileloader_dd_31.txt',
        base_add=11008412,
        base_literal=11009380,
        boundary='ARM.exidx end 0x00a7fd68 (listing bound); next ObjC IMP 0x00a7fd68 Dodo -[successfulTame]',
        selectors={
                 0xa7fd10: (15225656, 'reactToBeingFed'),
                 0xa7fd28: (15225480, 'multiSoundNamed:'),
                 0xa7fd2c: (15225472, 'instance'),
                 0xa7fd40: (15225508, 'playAtPosition:afterDelay:'),
                 0xa7fd44: (15225504, 'setPitch:'),
        },
        imports={
                 0xa7fd0c: (17151900, 'objc_msgSendSuper2'),
                 0xa7fd20: (16348776, '__CFConstantStringClassReference'),
                 0xa7fd24: (17151904, 'objc_msgSend'),
                 0xa7fd38: (16348760, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa7fd1c: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa7fd3c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa7fd4c: (17164680, 'OBJC_IVAR_$_Dodo.walkTimer', 312),
                 0xa7fd50: (17164700, 'OBJC_IVAR_$_Dodo.jumping', 348),
                 0xa7fd54: (17164624, 'OBJC_IVAR_$_Dodo.walkSpeed', 316),
                 0xa7fd58: (17164688, 'OBJC_IVAR_$_Dodo.randomGoalRotation', 308),
                 0xa7fd5c: (17164644, 'OBJC_IVAR_$_Dodo.movementDirection', 260),
        },
        classes={
                 0xa7fd14: (15253052, 'OBJC_CLASS_$_Dodo'),
                 0xa7fd30: (15249144, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11008396, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11009380, 'subseq r0, lr, r0, asr r1')],
        calls=[(11008480, 'blx ip'), (11008620, 'bl loc.imp.objc_msgSend'), (11008644, 'bl loc.imp.objc_msgSend'), (11008724, 'bl loc.imp.objc_msgSend'), (11008756, 'blx r3'), (11008776, 'blx r3'), (11008880, 'blx r3'), (11008948, 'blx r3'), (11009164, 'bl loc.imp.objc_msgSend')],
        branches=[(11008816, 'ble', 11008888), (11008884, 'b', 11008952)],
        semantics=('[Dodo -[reactToBeingFed]] (imp 0x00a7f98c, 247w): -[reactToBeingFed] (0xa7f98c, 247w): [super reactToBeingFed] via msgSendSuper2 (class cell 0xa7fd14); snd1 = [[MJSoundManager instance] multiSoundNamed:@"crunch.wav" (obj 0xf97658)]; [snd1 playAtPosition:floatPos@24 afterDelay:(double)0.1]; snd2 = [instance multiSoundNamed:@"dodo2.wav" (obj 0xf97668)]; [snd2 setPitch:(age@88 > 900.0f (pool 0xa7fd18) ? 1.0f : 3.0f)]; [snd2 playAtPosition:floatPos afterDelay:(double)0.6] (0x3fe3333340000000). Then state reset: movementDirection@260 = 0; walkSpeed@316 = 0.0f (pool 0xa7fd48); randomGoalRotation@308 = 1.0f; jumping@348 = 1; walkTimer@312 = 0.0f..\n'),
    ),
    dict(
        name='dd_32',
        method='Dodo -[reactToBeingHit]',
        types='v8@0:4',
        start=11007340,
        end=11007852,
        disasm='disasm_worldtileloader_dd_32.txt',
        base_add=11007356,
        base_literal=11007848,
        boundary='ARM.exidx end 0x00a7f76c (listing bound); next ObjC IMP 0x00a7f76c Dodo -[hitWithForce:blockhead:]',
        selectors={
                 0xa7f74c: (15225480, 'multiSoundNamed:'),
                 0xa7f750: (15225472, 'instance'),
                 0xa7f758: (15225504, 'setPitch:'),
                 0xa7f764: (15225508, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xa7f744: (16348744, '__CFConstantStringClassReference'),
                 0xa7f748: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa7f738: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xa7f740: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa7f75c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0xa7f754: (15249144, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11007340, 'push {r4, r5, r6, sl, fp, lr}'), (11007848, 'subseq r0, lr, r0, ror r5')],
        calls=[(11007508, 'blx ip'), (11007528, 'blx r3'), (11007632, 'blx r3'), (11007700, 'blx r3'), (11007788, 'bl loc.imp.objc_msgSend')],
        branches=[(11007400, 'bne', 11007792), (11007568, 'ble', 11007640), (11007636, 'b', 11007704)],
        semantics=('[Dodo -[reactToBeingHit]] (imp 0x00a7f56c, 128w): -[reactToBeingHit] (0xa7f56c, 128w): if (!dead@56): [[MJSoundManager instance] multiSoundNamed:@"cluck.wav" (obj 0xf97648)]; [snd setPitch:(age@88 > 900.0f (pool 0xa7f73c) ? 1.0f : 3.0f)]; [snd playAtPosition:floatPos@24 afterDelay:(double)0.1]. No state changes..\n'),
    ),
    dict(
        name='dd_33',
        method='Dodo -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=10929956,
        end=10930316,
        disasm='disasm_worldtileloader_dd_33.txt',
        base_add=10929972,
        base_literal=10930312,
        boundary='ARM.exidx end 0x00a6c88c (listing bound); next ObjC IMP 0x00a6c88c Dodo -[creationDataStructSize]',
        selectors={
                 0xa6c874: (15225384, 'remoteCreationDataUpdate:'),
                 0xa6c87c: (15225436, 'getBytes:length:'),
                 0xa6c884: (15225440, 'doRemoteUpdate:'),
        },
        imports={
                 0xa6c870: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0xa6c878: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(10929956, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10930312, 'ldrheq r3, [pc], -0x38')],
        calls=[(10930044, 'blx lr'), (10930088, 'bl loc.imp.objc_msgSend'), (10930276, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[Dodo -[remoteCreationDataUpdate:]] (imp 0x00a6c724, 90w): -[remoteCreationDataUpdate:] (0xa6c724, 90w): [super remoteCreationDataUpdate:arg] via msgSendSuper2 (class cell 0xa6c878); [arg getBytes:&buf length:0x70] (sel cell 0xa6c87c) fills the full creation blob; the 0x28-byte dodo sub-blob at buf+0x48 is copied to a struct at sp and applied via [self doRemoteUpdate:&blob[0x48]] (sel cell 0xa6c884)..\n'),
    ),
    dict(
        name='dd_34',
        method='Dodo -[remoteUpdate:]',
        types='v12@0:4@8',
        start=10929552,
        end=10929956,
        disasm='disasm_worldtileloader_dd_34.txt',
        base_add=10929568,
        base_literal=10929952,
        boundary='ARM.exidx end 0x00a6c724 (listing bound); next ObjC IMP 0x00a6c724 Dodo -[remoteCreationDataUpdate:]',
        selectors={
                 0xa6c708: (15225432, 'remoteUpdate:'),
                 0xa6c714: (15225436, 'getBytes:length:'),
                 0xa6c71c: (15225440, 'doRemoteUpdate:'),
        },
        imports={
                 0xa6c704: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa6c710: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0xa6c70c: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(10929552, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (10929952, 'subseq r3, pc, ip, asr 10')],
        calls=[(10929644, 'blx lr'), (10929724, 'bl loc.imp.objc_msgSend'), (10929912, 'bl loc.imp.objc_msgSend')],
        branches=[(10929680, 'bne', 10929916)],
        semantics=('[Dodo -[remoteUpdate:]] (imp 0x00a6c590, 101w): -[remoteUpdate:] (0xa6c590, 101w): [super remoteUpdate:arg] via msgSendSuper2 (class cell 0xa6c70c); if (!dead@56): [arg getBytes:&buf length:0x28] (sel cell 0xa6c714) then [self doRemoteUpdate:&buf] (sel cell 0xa6c71c). Dead dodos ignore the update (no needsRemoved reset here)..\n'),
    ),
    dict(
        name='dd_35',
        method='Dodo -[removeRider:]',
        types='v12@0:4@8',
        start=11011896,
        end=11012116,
        disasm='disasm_worldtileloader_dd_35.txt',
        base_add=11011912,
        base_literal=11012112,
        boundary='ARM.exidx end 0x00a80814 (listing bound); next ObjC IMP 0x00a80814 Dodo -[blockheadCanRide:usingItem:]',
        selectors={
                 0xa80800: (15225680, 'removeRider:'),
        },
        imports={
                 0xa807fc: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xa807f8: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xa8080c: (17164712, 'OBJC_IVAR_$_Dodo.riderTargetVelocity', 320),
        },
        classes={
                 0xa80804: (15253052, 'OBJC_CLASS_$_Dodo'),
        },
        instructions=[(11011896, 'push {fp, lr}'), (11012112, 'subseq pc, sp, r4, lsr 7')],
        calls=[(11012036, 'blx r3')],
        branches=[(11011964, 'bne', 11012080)],
        semantics=('[Dodo -[removeRider:]] (imp 0x00a80738, 55w): -[removeRider:] (0xa80738, 55w): if (arg == self.rider@132): [super removeRider:arg] via msgSendSuper2 (class cell 0xa80804); riderTargetVelocity@320 = 0.0f (pool 0xa80808 = 0x0)..\n'),
    ),
    dict(
        name='dd_36',
        method='Dodo -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=11008248,
        end=11008396,
        disasm='disasm_worldtileloader_dd_36.txt',
        base_add=11008280,
        base_literal=11008384,
        boundary='ARM.exidx end 0x00a7f98c (listing bound); next ObjC IMP 0x00a7f98c Dodo -[reactToBeingFed]',
        selectors={},
        imports={},
        ivars={
                 0xa7f97c: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
                 0xa7f984: (17164696, 'OBJC_IVAR_$_Dodo.xOffset', 336),
                 0xa7f988: (17164692, 'OBJC_IVAR_$_Dodo.yOffset', 332),
        },
        classes={},
        instructions=[(11008248, 'push {fp, lr}'), (11008392, 'invalid')],
        calls=[(11008348, 'bl method.Vector2.Vector2_float__float_'), (11008368, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=('[Dodo -[renderPos]] (imp 0x00a7f8f8, 37w): -[renderPos] (0xa7f8f8, 37w; stret - r0 = Vector2 buffer): returns Vector2(floatPos@24.x + xOffset@336, floatPos@24.y + yOffset@332) (Vector2 ctor then Vector2::operator+; yOffset is the dodo\'s vertical bob offset)..\n'),
    ),
    dict(
        name='dd_37',
        method='Dodo -[rideDirection]',
        types='i8@0:4',
        start=11011296,
        end=11011528,
        disasm='disasm_worldtileloader_dd_37.txt',
        base_add=11011304,
        base_literal=11011524,
        boundary='ARM.exidx end 0x00a805c8 (listing bound); next ObjC IMP 0x00a805c8 Dodo -[addRider:]',
        selectors={},
        imports={},
        ivars={
                 0xa805b4: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
                 0xa805bc: (17164712, 'OBJC_IVAR_$_Dodo.riderTargetVelocity', 320),
        },
        classes={},
        instructions=[(11011296, 'sub sp, sp, 0x14'), (11011524, 'subseq pc, sp, r4, lsl 12')],
        calls=[],
        branches=[(11011352, 'beq', 11011488), (11011396, 'ble', 11011412), (11011408, 'b', 11011476), (11011484, 'b', 11011496)],
        semantics=('[Dodo -[rideDirection]] (imp 0x00a804e0, 58w): -[rideDirection] (0xa804e0, 58w): 0 if rider@132 == nil; else the sign of riderTargetVelocity@320.x with a +/-0.1 dead zone (> 0.1f -> 1; < -0.1f -> -1; else 0; pools 0xa805b8/0xa805c0 = 0x3dcccccd/0xbdcccccd)..\n'),
    ),
    dict(
        name='dd_38',
        method='Dodo -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=11011128,
        end=11011196,
        disasm='disasm_worldtileloader_dd_38.txt',
        base_add=11011156,
        base_literal=11011192,
        boundary='ARM.exidx end 0x00a8047c (listing bound); next ObjC IMP 0x00a8047c Dodo -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={
                 0xa80474: (17164684, 'OBJC_IVAR_$_Dodo.bodyRotation', 304),
        },
        classes={},
        instructions=[(11011128, 'sub sp, sp, 0xc'), (11011192, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[riderBodyYRotationForBlockhead:]] (imp 0x00a80438, 17w): -[riderBodyYRotationForBlockhead:] (0xa80438, 17w): returns self.bodyRotation@304 (float)..\n'),
    ),
    dict(
        name='dd_39',
        method='Dodo -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=11010784,
        end=11011028,
        disasm='disasm_worldtileloader_dd_39.txt',
        base_add=11010800,
        base_literal=11011024,
        boundary='ARM.exidx end 0x00a803d4 (listing bound); next ObjC IMP 0x00a803d4 Dodo -[cameraPosForBlockhead:]',
        selectors={
                 0xa803cc: (15225652, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(11010784, 'push {r4, sl, fp, lr}'), (11011024, 'ldrsheq pc, [sp], -0x7c')],
        calls=[(11010868, 'bl loc.imp.objc_msgSend_stret'), (11010904, 'bl sym.imp.memset'), (11010924, 'bl method.Vector2.Vector2_float__float_'), (11010944, 'bl method.Vector2.operator_Vector2_'), (11010952, 'bl method.Vector2.operator_float__'), (11010972, 'bl method.Vector2.operator_float__'), (11011004, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(11010852, 'beq', 11010876), (11010872, 'b', 11010908)],
        semantics=('[Dodo -[riderPosForBlockhead:]] (imp 0x00a802e0, 61w): -[riderPosForBlockhead:] (0xa802e0, 61w; stret): reads the dodo\'s own render pos via [self renderPos] @0xa80334 (objc_msgSend_stret; the blockhead arg is unused; the nil-guard is on self, an O0 artifact), adds Vector2(0, 0.4f) (0x3ecccccd) via ctor+operator+, then returns Vector3(p.x, p.y, -0.75f) (GL-truth -0.75; r2 misprints imm as -7). So the rider anchor = renderPos + (0, +0.4, -0.75)..\n'),
    ),
    dict(
        name='dd_40',
        method='Dodo -[riderRidesWithArmsDown]',
        types='c8@0:4',
        start=11012740,
        end=11012768,
        disasm='disasm_worldtileloader_dd_40.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a80d00; body trimmed at the next IMP 0x00a80aa0 Dodo -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11012740, 'sub sp, sp, 8'), (11012764, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[riderRidesWithArmsDown]] (imp 0x00a80a84, 7w): -[riderRidesWithArmsDown] (0xa80a84, 7w): returns YES (movw r2,#1 + sxtb)..\n'),
    ),
    dict(
        name='dd_41',
        method='Dodo -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=11011196,
        end=11011296,
        disasm='disasm_worldtileloader_dd_41.txt',
        base_add=11011212,
        base_literal=11011292,
        boundary='ARM.exidx end 0x00a804e0 (listing bound); next ObjC IMP 0x00a804e0 Dodo -[rideDirection]',
        selectors={},
        imports={},
        ivars={
                 0xa804d8: (17164712, 'OBJC_IVAR_$_Dodo.riderTargetVelocity', 320),
        },
        classes={},
        instructions=[(11011196, 'push {fp, lr}'), (11011292, 'subseq pc, sp, r0, ror 12')],
        calls=[(11011244, 'bl method.Vector2.operator_float__')],
        branches=[],
        semantics=('[Dodo -[setTargetVelocity:]] (imp 0x00a8047c, 25w): -[setTargetVelocity:] (0xa8047c, 25w): writes the x component (first float) of the by-value Vector2 arg into riderTargetVelocity@320 (via Vector2::operator float*(); only [r0] is vstr\'d - y is left untouched)..\n'),
    ),
    dict(
        name='dd_42',
        method='Dodo -[speciesName]',
        types='@8@0:4',
        start=10921012,
        end=10921060,
        disasm='disasm_worldtileloader_dd_42.txt',
        base_add=10921020,
        base_literal=10921056,
        boundary='ARM.exidx end 0x00a6a508; body trimmed at the next IMP 0x00a6a464 Dodo -[foodItemType]',
        selectors={},
        imports={
                 0xa6a45c: (16348216, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(10921012, 'sub sp, sp, 8'), (10921056, 'ldrheq r5, [pc], -0x60')],
        calls=[],
        branches=[],
        semantics=('[Dodo -[speciesName]] (imp 0x00a6a434, 12w): -[speciesName] (0xa6a434, 12w): returns the static CFString @"DODO" (obj 0xf97438, cstr @0xf5c2f6; r2 = pc + 0x5f56b0 + 0xfff37944) - the same object nameForDodoBreed falls back to..\n'),
    ),
    dict(
        name='dd_43',
        method='Dodo -[successfulTame]',
        types='v8@0:4',
        start=11009384,
        end=11009928,
        disasm='disasm_worldtileloader_dd_43.txt',
        base_add=11009400,
        base_literal=11009924,
        boundary='ARM.exidx end 0x00a7ff88 (listing bound); next ObjC IMP 0x00a7ff88 Dodo -[breedString]',
        selectors={
                 0xa7ff50: (15225660, 'successfulTame'),
                 0xa7ff68: (15225480, 'multiSoundNamed:'),
                 0xa7ff6c: (15225472, 'instance'),
                 0xa7ff74: (15225504, 'setPitch:'),
                 0xa7ff80: (15225508, 'playAtPosition:afterDelay:'),
        },
        imports={
                 0xa7ff4c: (17151900, 'objc_msgSendSuper2'),
                 0xa7ff60: (16348792, '__CFConstantStringClassReference'),
                 0xa7ff64: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa7ff5c: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0xa7ff78: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={
                 0xa7ff54: (15253052, 'OBJC_CLASS_$_Dodo'),
                 0xa7ff70: (15249144, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(11009384, 'push {r4, r5, r6, sl, fp, lr}'), (11009924, 'subseq pc, sp, r4, ror sp')],
        calls=[(11009468, 'blx ip'), (11009576, 'blx ip'), (11009596, 'blx r3'), (11009700, 'blx r3'), (11009768, 'blx r3'), (11009856, 'bl loc.imp.objc_msgSend')],
        branches=[(11009636, 'ble', 11009708), (11009704, 'b', 11009772)],
        semantics=('[Dodo -[successfulTame]] (imp 0x00a7fd68, 136w): -[successfulTame] (0xa7fd68, 136w): [super successfulTame] via msgSendSuper2 (class cell 0xa7ff54); [[MJSoundManager instance] multiSoundNamed:@"dodoTame.wav" (obj 0xf97678)]; setPitch(age@88 > 900.0f (pool 0xa7ff58) ? 1.0f : 3.0f); [snd playAtPosition:floatPos@24 afterDelay:(double)0.6] (0x3fe3333340000000)..\n'),
    ),
    dict(
        name='dd_44',
        method='Dodo -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=11006264,
        end=11007340,
        disasm='disasm_worldtileloader_dd_44.txt',
        base_add=11006280,
        base_literal=11007336,
        boundary='ARM.exidx end 0x00a7f56c (listing bound); next ObjC IMP 0x00a7f56c Dodo -[reactToBeingHit]',
        selectors={
                 0xa7f54c: (15225652, 'renderPos'),
                 0xa7f558: (15225444, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0xa7f548: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0xa7f550: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(11006264, 'push {fp, lr}'), (11007336, 'subseq r0, lr, r4, lsr 19')],
        calls=[(11006400, 'bl loc.imp.objc_msgSend_stret'), (11006436, 'bl sym.imp.memset'), (11006484, 'bl method.Vector2.Vector2_float__float_'), (11006508, 'bl method.Vector2.operator_Vector2_'), (11006516, 'bl method.Vector2.operator_float__'), (11006532, 'bl method.Vector2.operator_float__'), (11006588, 'bl loc.imp.objc_msgSend'), (11006612, 'bl sym.imp.__aeabi_idiv'), (11006656, 'bl method.Vector2.operator_float__'), (11006672, 'bl method.Vector2.operator_float__'), (11006728, 'bl loc.imp.objc_msgSend'), (11006792, 'bl method.Vector2.operator_float__'), (11006808, 'bl method.Vector2.operator_float__'), (11006864, 'bl loc.imp.objc_msgSend'), (11006880, 'bl sym.imp.__aeabi_idiv'), (11006924, 'bl method.Vector2.operator_float__'), (11006940, 'bl method.Vector2.operator_float__'), (11006996, 'bl loc.imp.objc_msgSend'), (11007040, 'bl method.Vector2.operator_float__'), (11007060, 'bl method.Vector2.operator_float__'), (11007148, 'bl method.Vector2.operator_float__'), (11007172, 'bl method.Vector2.operator_float__'), (11007212, 'bl method.Vector2.operator_float__'), (11007236, 'bl method.Vector2.operator_float__')],
        branches=[(11006332, 'beq', 11006348), (11006344, 'b', 11007292), (11006384, 'beq', 11006408), (11006404, 'b', 11006440), (11006636, 'blt', 11006768), (11006764, 'b', 11007088), (11006904, 'bpl', 11007036), (11007032, 'b', 11007080), (11007116, 'bpl', 11007284), (11007140, 'ble', 11007284), (11007204, 'ble', 11007284), (11007268, 'bpl', 11007284), (11007280, 'b', 11007292)],
        semantics=('[Dodo -[tapIsWithinBodyRadius:]] (imp 0x00a7f138, 269w): -[tapIsWithinBodyRadius:] (0xa7f138, 269w; arg = Vector2 in r2:r3): false if dead@56. C = [self renderPos] + (0, 0.4f) (stret read + Vector2 ctor/operator+). dx = tap.x - C.x; seam-wrap: halfWidth = worldWidthMacro*32/2 (worldWidthMacro msgSend on self.world@4, `lsl 5`, idiv by 2); if dx >= halfWidth -> dx -= worldWidthMacro*32; if dx < -halfWidth -> dx += worldWidthMacro*32. Then the hit test: |dx| < 0.5 AND |tap.y - C.y| < 0.5 (four double comparisons vs GL-truth +/-0.5 immediates; r2 misprints as 5/-5). So the tap box is a 1x1 square centered at renderPos + (0, 0.4)..\n'),
    ),
    dict(
        name='dd_45',
        method='Dodo -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=10927944,
        end=10928180,
        disasm='disasm_worldtileloader_dd_45.txt',
        base_add=10927960,
        base_literal=10928176,
        boundary='ARM.exidx end 0x00a6c034 (listing bound); next ObjC IMP 0x00a6c034 Dodo -[dealloc]',
        selectors={
                 0xa6c020: (15225400, 'dodoUpdateNetDataForClient:'),
                 0xa6c028: (15225404, 'dataWithBytes:length:'),
        },
        imports={
                 0xa6c024: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa6c02c: (15249136, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(10927944, 'push {fp, lr}'), (10928176, 'invalid')],
        calls=[(10928040, 'bl loc.imp.objc_msgSend_stret'), (10928076, 'bl sym.imp.memset'), (10928140, 'blx ip')],
        branches=[(10928020, 'beq', 10928048), (10928044, 'b', 10928080)],
        semantics=('[Dodo -[updateNetDataForClient:]] (imp 0x00a6bf48, 59w): -[updateNetDataForClient:] (0xa6bf48, 59w): builds the 0x28 DodoUpdateNetData via [self dodoUpdateNetDataForClient:client] (msgSend_stret into a 0x28 stack buffer; memset-0 on the nil-self guard path) and returns [NSData dataWithBytes:&blob length:0x28] (sel cell 0xa6bf28, NSData class cell 0xa6bf2c)..\n'),
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
        'batch': 'Dodo (E141): the dodo animal; 46 bodies',
        'claim': ('the dodo animal (AI tick, motion/render, egg sequence)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'dodo.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale dodo.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
