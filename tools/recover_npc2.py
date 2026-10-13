#!/usr/bin/env python3
"""Hash-gated recovery of the NPC tail sweep (E128).

The NPC class tail closes: the riding contract, the menu gates and the remaining accessors:
73 bodies, 1440 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/NPC2.md for the prose and boundaries.
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
    'bl 0x6445d8': 0x006445d8,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.dynamicObjectTypeForNPCType_NPCType_': 0x006495a0,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
}

SPECS = [
    dict(
        name='nq_00',
        method='NPC -[actionTitle]',
        types='@8@0:4',
        start=6596492,
        end=6596552,
        disasm='disasm_worldtileloader_nq_00.txt',
        base_add=6596500,
        base_literal=6596548,
        boundary='ARM.exidx end 0x0064a7e4; body trimmed at the next IMP 0x0064a7c8 NPC -[isDoubleHeight]',
        selectors={},
        imports={},
        ivars={
                 0x64a7c0: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
        },
        classes={},
        instructions=[(6596492, 'sub sp, sp, 8'), (6596548, 'adceq r5, r1, r8, asr r3')],
        calls=[],
        branches=[],
        semantics=('[NPC -[actionTitle]] (imp 0x0064a78c, 15w): [NPC -[actionTitle]] (imp 0x0064a78c, 15w): returns the name ivar (self+0x5c, OBJC_IVAR_$_NPC.name) as the action title - the NPC\'s name doubles as its menu title..\n'),
    ),
    dict(
        name='nq_01',
        method='NPC -[actsAsInteractionObject]',
        types='@8@0:4',
        start=6618436,
        end=6618464,
        disasm='disasm_worldtileloader_nq_01.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fd60 (listing bound); next ObjC IMP 0x0064fd60 NPC -[blockheadsLoaded]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618436, 'sub sp, sp, 8'), (6618460, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[actsAsInteractionObject]] (imp 0x0064fd44, 7w): [NPC -[actsAsInteractionObject]] (imp 0x0064fd44, 7w): returns nil (movw r2, 0, @ return) - no interaction object in the base class..\n'),
    ),
    dict(
        name='nq_02',
        method='NPC -[age]',
        types='f8@0:4',
        start=6624020,
        end=6624092,
        disasm='disasm_worldtileloader_nq_02.txt',
        base_add=6624044,
        base_literal=6624088,
        boundary='ARM.exidx end 0x006513a8; body trimmed at the next IMP 0x0065135c NPC -[setAge:]',
        selectors={},
        imports={},
        ivars={
                 0x651354: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(6624020, 'sub sp, sp, 0xc'), (6624088, 'adceq lr, r0, r0, asr 15')],
        calls=[],
        branches=[],
        semantics=('[NPC -[age]] (imp 0x00651314, 18w): [NPC -[age]] (imp 0x00651314, 18w): float getter for the age ivar (self+0x58) with a dmb ish barrier right after the load (bit-atomic read)..\n'),
    ),
    dict(
        name='nq_03',
        method='NPC -[beginBlockheadInspection:]',
        types='v12@0:4@8',
        start=6614428,
        end=6614532,
        disasm='disasm_worldtileloader_nq_03.txt',
        base_add=6614440,
        base_literal=6614528,
        boundary='ARM.exidx end 0x0064ee04 (listing bound); next ObjC IMP 0x0064ee04 NPC -[blockheadIsComingToInspect:]',
        selectors={},
        imports={},
        ivars={
                 0x64edf8: (17157404, 'OBJC_IVAR_$_NPC.inspectingBlockhead', 116),
                 0x64edfc: (17157408, 'OBJC_IVAR_$_NPC.comingToInspectBlockhead', 112),
        },
        classes={},
        instructions=[(6614428, 'push {r4, lr}'), (6614528, 'adceq r0, r1, r4, asr 26')],
        calls=[],
        branches=[],
        semantics=('[NPC -[beginBlockheadInspection:]] (imp 0x0064ed9c, 26w): [NPC -[beginBlockheadInspection:]] (imp 0x0064ed9c, 26w): stores the blockhead into inspectingBlockhead (self+0x74) and clears comingToInspectBlockhead (self+0x70)..\n'),
    ),
    dict(
        name='nq_04',
        method='NPC -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=6594504,
        end=6594540,
        disasm='disasm_worldtileloader_nq_04.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00649fec (listing bound); next ObjC IMP 0x00649fec NPC -[blockheadUnloaded:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6594504, 'sub sp, sp, 0x10'), (6594536, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[blockheadCanRide:usingItem:]] (imp 0x00649fc8, 9w): [NPC -[blockheadCanRide:usingItem:]] (imp 0x00649fc8, 9w): constant NO (sxtb 0) - the base NPC is not ridable; the species subclasses override..\n'),
    ),
    dict(
        name='nq_05',
        method='NPC -[blockheadIsComingToInspect:]',
        types='v12@0:4@8',
        start=6614532,
        end=6614600,
        disasm='disasm_worldtileloader_nq_05.txt',
        base_add=6614540,
        base_literal=6614596,
        boundary='ARM.exidx end 0x0064ee48 (listing bound); next ObjC IMP 0x0064ee48 NPC -[canMate]',
        selectors={},
        imports={},
        ivars={
                 0x64ee40: (17157408, 'OBJC_IVAR_$_NPC.comingToInspectBlockhead', 112),
        },
        classes={},
        instructions=[(6614532, 'sub sp, sp, 0xc'), (6614596, 'adceq r0, r1, r0, ror 25')],
        calls=[],
        branches=[],
        semantics=('[NPC -[blockheadIsComingToInspect:]] (imp 0x0064ee04, 17w): [NPC -[blockheadIsComingToInspect:]] (imp 0x0064ee04, 17w): stores the blockhead into comingToInspectBlockhead (self+0x70)..\n'),
    ),
    dict(
        name='nq_06',
        method='NPC -[breed]',
        types='S8@0:4',
        start=6624168,
        end=6624228,
        disasm='disasm_worldtileloader_nq_06.txt',
        base_add=6624176,
        base_literal=6624224,
        boundary='ARM.exidx end 0x006513e4 (listing bound); next ObjC IMP 0x006513e4 NPC -[setBreed:]',
        selectors={},
        imports={},
        ivars={
                 0x6513dc: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(6624168, 'sub sp, sp, 8'), (6624224, 'adceq lr, r0, ip, lsr r7')],
        calls=[],
        branches=[],
        semantics=('[NPC -[breed]] (imp 0x006513a8, 15w): [NPC -[breed]] (imp 0x006513a8, 15w): u16 getter (ldrh) for the breed ivar (self+0x60)..\n'),
    ),
    dict(
        name='nq_07',
        method='NPC -[breedString]',
        types='@8@0:4',
        start=6597936,
        end=6598016,
        disasm='disasm_worldtileloader_nq_07.txt',
        base_add=6597952,
        base_literal=6598008,
        boundary='ARM.exidx end 0x0064ad80 (listing bound); next ObjC IMP 0x0064ad80 NPC -[successfulTame]',
        selectors={
                 0x64ad74: (15200808, 'speciesName'),
        },
        imports={
                 0x64ad70: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6597936, 'push {fp, lr}'), (6598012, 'andeq r0, r0, r0')],
        calls=[(6597988, 'blx r3')],
        branches=[],
        semantics=('[NPC -[breedString]] (imp 0x0064ad30, 20w): [NPC -[breedString]] (imp 0x0064ad30, 20w): forwards to [self speciesName] (one objc_msgSend) - the breed\'s display string is the species name..\n'),
    ),
    dict(
        name='nq_08',
        method='NPC -[cameraPosForBlockhead:]',
        types='{Vector2=[2f]}12@0:4@8',
        start=6618212,
        end=6618352,
        disasm='disasm_worldtileloader_nq_08.txt',
        base_add=6618228,
        base_literal=6618348,
        boundary='ARM.exidx end 0x0064fcf0 (listing bound); next ObjC IMP 0x0064fcf0 NPC -[jumpsOnSwipe]',
        selectors={
                 0x64fce8: (15200804, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6618212, 'push {r4, sl, fp, lr}'), (6618348, 'adceq pc, r0, r8, ror lr')],
        calls=[(6618296, 'bl loc.imp.objc_msgSend_stret'), (6618332, 'bl sym.imp.memset')],
        branches=[(6618280, 'beq', 6618304), (6618300, 'b', 6618336)],
        semantics=('[NPC -[cameraPosForBlockhead:]] (imp 0x0064fc64, 35w): [NPC -[cameraPosForBlockhead:]] (imp 0x0064fc64, 35w): returns [self renderPos] as Vector2 (objc_msgSend_stret; nil-self -> zeroed 8 bytes); the blockhead argument is spilled but never read..\n'),
    ),
    dict(
        name='nq_09',
        method='NPC -[canBeCapturedByBlockhead:withItemType:]',
        types='c16@0:4@8i12',
        start=6596420,
        end=6596456,
        disasm='disasm_worldtileloader_nq_09.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a78c; body trimmed at the next IMP 0x0064a768 NPC -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596420, 'sub sp, sp, 0x10'), (6596452, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[canBeCapturedByBlockhead:withItemType:]] (imp 0x0064a744, 9w): [NPC -[canBeCapturedByBlockhead:withItemType:]] (imp 0x0064a744, 9w): constant NO (sxtb 0); capture is a species feature..\n'),
    ),
    dict(
        name='nq_10',
        method='NPC -[canBeMilkedByBlockhead:]',
        types='c12@0:4@8',
        start=6595924,
        end=6595956,
        disasm='disasm_worldtileloader_nq_10.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a574 (listing bound); next ObjC IMP 0x0064a574 NPC -[cantBeMilkedTipStringForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6595924, 'sub sp, sp, 0xc'), (6595952, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[canBeMilkedByBlockhead:]] (imp 0x0064a554, 8w): [NPC -[canBeMilkedByBlockhead:]] (imp 0x0064a554, 8w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_11',
        method='NPC -[canBeRemovedByBlockhead:]',
        types='c12@0:4@8',
        start=6596580,
        end=6596668,
        disasm='disasm_worldtileloader_nq_11.txt',
        base_add=6596596,
        base_literal=6596664,
        boundary='ARM.exidx end 0x0064a83c (listing bound); next ObjC IMP 0x0064a83c NPC -[minRidableAge]',
        selectors={
                 0x64a834: (15200816, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x64a830: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6596580, 'push {fp, lr}'), (6596664, 'invalid')],
        calls=[(6596640, 'blx ip')],
        branches=[],
        semantics=('[NPC -[canBeRemovedByBlockhead:]] (imp 0x0064a7e4, 22w): [NPC -[canBeRemovedByBlockhead:]] (imp 0x0064a7e4, 22w): returns [self belongsToPlayerWithBlockhead:] (single objc_msgSend + sxtb) - removal allowed only for the owning player..\n'),
    ),
    dict(
        name='nq_12',
        method='NPC -[canBeShavedByBlockhead:]',
        types='c12@0:4@8',
        start=6596172,
        end=6596204,
        disasm='disasm_worldtileloader_nq_12.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a66c (listing bound); next ObjC IMP 0x0064a66c NPC -[cantBeShavedTipStringForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596172, 'sub sp, sp, 0xc'), (6596200, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[canBeShavedByBlockhead:]] (imp 0x0064a64c, 8w): [NPC -[canBeShavedByBlockhead:]] (imp 0x0064a64c, 8w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_13',
        method='NPC -[canMate]',
        types='c8@0:4',
        start=6614600,
        end=6614816,
        disasm='disasm_worldtileloader_nq_13.txt',
        base_add=6614608,
        base_literal=6614808,
        boundary='ARM.exidx end 0x0064ef20 (listing bound); next ObjC IMP 0x0064ef20 NPC -[mateWithNPC:]',
        selectors={},
        imports={},
        ivars={
                 0x64ef08: (17157284, 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76),
                 0x64ef0c: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x64ef14: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(6614600, 'sub sp, sp, 0x14'), (6614812, 'andeq r0, r0, r0')],
        calls=[],
        branches=[(6614664, 'bhi', 6614772), (6614708, 'bne', 6614772)],
        semantics=('[NPC -[canMate]] (imp 0x0064ee48, 54w): [NPC -[canMate]] (imp 0x0064ee48, 54w): the breeding gate = mateCooldownTimer (self+0x4c) <= 0.0f && !dead (self+0x38) && age (self+0x58) > 900.0f (0x384 pool constant); result bool-masked + sxtb..\n'),
    ),
    dict(
        name='nq_14',
        method='NPC -[cantBeCapturedTipStringForBlockhead:withItemType:]',
        types='@16@0:4@8i12',
        start=6596456,
        end=6596492,
        disasm='disasm_worldtileloader_nq_14.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a78c (listing bound); next ObjC IMP 0x0064a78c NPC -[actionTitle]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596456, 'sub sp, sp, 0x10'), (6596488, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x0064a768, 9w): [NPC -[cantBeCapturedTipStringForBlockhead:withItemType:]] (imp 0x0064a768, 9w): returns nil (mov r0, ip=0) - no tip for base NPCs..\n'),
    ),
    dict(
        name='nq_15',
        method='NPC -[cantBeFedTipStringForBlockhead:]',
        types='@12@0:4@8',
        start=6595740,
        end=6595924,
        disasm='disasm_worldtileloader_nq_15.txt',
        base_add=6595756,
        base_literal=6595920,
        boundary='ARM.exidx end 0x0064a554 (listing bound); next ObjC IMP 0x0064a554 NPC -[canBeMilkedByBlockhead:]',
        selectors={
                 0x64a544: (15200812, 'stringWithFormat:'),
                 0x64a548: (15200808, 'speciesName'),
        },
        imports={
                 0x64a53c: (16254600, '__CFConstantStringClassReference'),
                 0x64a540: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x64a54c: (15245900, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6595740, 'push {r4, r5, r6, r7, fp, lr}'), (6595920, 'adceq r5, r1, r0, asr 12')],
        calls=[(6595852, 'blx lr'), (6595888, 'blx ip')],
        branches=[],
        semantics=('[NPC -[cantBeFedTipStringForBlockhead:]] (imp 0x0064a49c, 46w): [NPC -[cantBeFedTipStringForBlockhead:]] (imp 0x0064a49c, 46w): [NSString stringWithFormat:@"THAT %@ ISN\'T HUNGRY\\nTRY AGAIN LATER", [self speciesName]] - format CFString @0xf80688; same-shaped 46w sibling of nq_16/nq_17 (cells differ only)..\n'),
    ),
    dict(
        name='nq_16',
        method='NPC -[cantBeMilkedTipStringForBlockhead:]',
        types='@12@0:4@8',
        start=6595956,
        end=6596140,
        disasm='disasm_worldtileloader_nq_16.txt',
        base_add=6595972,
        base_literal=6596136,
        boundary='ARM.exidx end 0x0064a62c (listing bound); next ObjC IMP 0x0064a62c NPC -[milkByBlockhead:]',
        selectors={
                 0x64a61c: (15200812, 'stringWithFormat:'),
                 0x64a620: (15200808, 'speciesName'),
        },
        imports={
                 0x64a614: (16254616, '__CFConstantStringClassReference'),
                 0x64a618: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x64a624: (15245900, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6595956, 'push {r4, r5, r6, r7, fp, lr}'), (6596136, 'adceq r5, r1, r8, ror 10')],
        calls=[(6596068, 'blx lr'), (6596104, 'blx ip')],
        branches=[],
        semantics=('[NPC -[cantBeMilkedTipStringForBlockhead:]] (imp 0x0064a574, 46w): [NPC -[cantBeMilkedTipStringForBlockhead:]] (imp 0x0064a574, 46w): [NSString stringWithFormat:@"THAT %@ HAS NO MILK\\nTRY AGAIN LATER", [self speciesName]] - format CFString @0xf80698..\n'),
    ),
    dict(
        name='nq_17',
        method='NPC -[cantBeShavedTipStringForBlockhead:]',
        types='@12@0:4@8',
        start=6596204,
        end=6596388,
        disasm='disasm_worldtileloader_nq_17.txt',
        base_add=6596220,
        base_literal=6596384,
        boundary='ARM.exidx end 0x0064a724 (listing bound); next ObjC IMP 0x0064a724 NPC -[shaveByBlockhead:]',
        selectors={
                 0x64a714: (15200812, 'stringWithFormat:'),
                 0x64a718: (15200808, 'speciesName'),
        },
        imports={
                 0x64a70c: (16254632, '__CFConstantStringClassReference'),
                 0x64a710: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x64a71c: (15245900, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(6596204, 'push {r4, r5, r6, r7, fp, lr}'), (6596384, 'adceq r5, r1, r0, ror r4')],
        calls=[(6596316, 'blx lr'), (6596352, 'blx ip')],
        branches=[],
        semantics=('[NPC -[cantBeShavedTipStringForBlockhead:]] (imp 0x0064a66c, 46w): [NPC -[cantBeShavedTipStringForBlockhead:]] (imp 0x0064a66c, 46w): [NSString stringWithFormat:@"THAT %@ IS ALREADY SHAVED\\nTRY AGAIN LATER", [self speciesName]] - format CFString @0xf806a8..\n'),
    ),
    dict(
        name='nq_18',
        method='NPC -[captureRequiredItemType]',
        types='i8@0:4',
        start=6595280,
        end=6595312,
        disasm='disasm_worldtileloader_nq_18.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a2f0 (listing bound); next ObjC IMP 0x0064a2f0 NPC -[canBeFedByBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6595280, 'sub sp, sp, 8'), (6595308, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[captureRequiredItemType]] (imp 0x0064a2d0, 8w): [NPC -[captureRequiredItemType]] (imp 0x0064a2d0, 8w): constant 0 (no capture item in the base class)..\n'),
    ),
    dict(
        name='nq_19',
        method='NPC -[capturedItemType]',
        types='i8@0:4',
        start=6595252,
        end=6595280,
        disasm='disasm_worldtileloader_nq_19.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a2f0; body trimmed at the next IMP 0x0064a2d0 NPC -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6595252, 'sub sp, sp, 8'), (6595276, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[capturedItemType]] (imp 0x0064a2b4, 7w): [NPC -[capturedItemType]] (imp 0x0064a2b4, 7w): constant 0..\n'),
    ),
    dict(
        name='nq_20',
        method='NPC -[center]',
        types='{Vector2=[2f]}8@0:4',
        start=6594308,
        end=6594444,
        disasm='disasm_worldtileloader_nq_20.txt',
        base_add=6594324,
        base_literal=6594440,
        boundary='ARM.exidx end 0x00649f8c (listing bound); next ObjC IMP 0x00649f8c NPC -[isVisible]',
        selectors={
                 0x649f84: (15200804, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6594308, 'push {fp, lr}'), (6594440, 'invalid')],
        calls=[(6594388, 'bl loc.imp.objc_msgSend_stret'), (6594424, 'bl sym.imp.memset')],
        branches=[(6594372, 'beq', 6594396), (6594392, 'b', 6594428)],
        semantics=('[NPC -[center]] (imp 0x00649f04, 34w): [NPC -[center]] (imp 0x00649f04, 34w): returns [self renderPos] as Vector2 (objc_msgSend_stret; nil-self -> zeroed 8 bytes) - the same contract as cameraPosForBlockhead: (that one spills an extra r3)..\n'),
    ),
    dict(
        name='nq_21',
        method='NPC -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]',
        types='@8@0:4',
        start=6621824,
        end=6621884,
        disasm='disasm_worldtileloader_nq_21.txt',
        base_add=6621832,
        base_literal=6621880,
        boundary='ARM.exidx end 0x00650b10; body trimmed at the next IMP 0x00650abc NPC -[shouldSaveEveryChangeInPosition]',
        selectors={},
        imports={},
        ivars={
                 0x650ab4: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
        },
        classes={},
        instructions=[(6621824, 'sub sp, sp, 8'), (6621880, 'adceq pc, r0, r4, rrx')],
        calls=[],
        branches=[],
        semantics=('[NPC -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]] (imp 0x00650a80, 15w): [NPC -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]] (imp 0x00650a80, 15w): returns the tamedClientID pointer (self+0x6c) - the tamed client\'s ID keys the save shard that only loads while that player is online..\n'),
    ),
    dict(
        name='nq_22',
        method='NPC -[createItemDropsForDeath]',
        types='v8@0:4',
        start=6571780,
        end=6571800,
        disasm='disasm_worldtileloader_nq_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00644718 (listing bound); next ObjC IMP 0x00644718 NPC -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6571780, 'sub sp, sp, 8'), (6571796, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[createItemDropsForDeath]] (imp 0x00644704, 5w): [NPC -[createItemDropsForDeath]] (imp 0x00644704, 5w): empty override (frame only) - the base NPC drops nothing on death..\n'),
    ),
    dict(
        name='nq_23',
        method='NPC -[creationDataStructSize]',
        types='L8@0:4',
        start=6591320,
        end=6591348,
        disasm='disasm_worldtileloader_nq_23.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00649390; body trimmed at the next IMP 0x00649374 NPC -[maxHealth]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6591320, 'sub sp, sp, 8'), (6591344, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[creationDataStructSize]] (imp 0x00649358, 7w): [NPC -[creationDataStructSize]] (imp 0x00649358, 7w): constant 0x48 (72) - the NPC creation record size (matches the 0x48 creation wire record, E117)..\n'),
    ),
    dict(
        name='nq_24',
        method='NPC -[diesOfLowFullness]',
        types='c8@0:4',
        start=6568708,
        end=6568736,
        disasm='disasm_worldtileloader_nq_24.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00643b20 (listing bound); next ObjC IMP 0x00643b20 NPC -[loadValuesFromSaveDict:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6568708, 'sub sp, sp, 8'), (6568732, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[diesOfLowFullness]] (imp 0x00643b04, 7w): [NPC -[diesOfLowFullness]] (imp 0x00643b04, 7w): constant YES (1)..\n'),
    ),
    dict(
        name='nq_25',
        method='NPC -[diesOfOldAge]',
        types='c8@0:4',
        start=6568628,
        end=6568656,
        disasm='disasm_worldtileloader_nq_25.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00643ad0 (listing bound); next ObjC IMP 0x00643ad0 NPC -[minFullness]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6568628, 'sub sp, sp, 8'), (6568652, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[diesOfOldAge]] (imp 0x00643ab4, 7w): [NPC -[diesOfOldAge]] (imp 0x00643ab4, 7w): constant YES (1) - instruction-identical to diesOfLowFullness..\n'),
    ),
    dict(
        name='nq_26',
        method='NPC -[foodItemType]',
        types='i8@0:4',
        start=6595224,
        end=6595252,
        disasm='disasm_worldtileloader_nq_26.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a2f0; body trimmed at the next IMP 0x0064a2b4 NPC -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6595224, 'sub sp, sp, 8'), (6595248, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[foodItemType]] (imp 0x0064a298, 7w): [NPC -[foodItemType]] (imp 0x0064a298, 7w): constant 0..\n'),
    ),
    dict(
        name='nq_27',
        method='NPC -[fullnessFraction]',
        types='f8@0:4',
        start=6591528,
        end=6591788,
        disasm='disasm_worldtileloader_nq_27.txt',
        base_add=6591544,
        base_literal=6591784,
        boundary='ARM.exidx end 0x0064952c (listing bound); next ObjC IMP 0x0064952c NPC -[tapIsWithinBodyRadius:]',
        selectors={
                 0x64951c: (15200656, 'diesOfLowFullness'),
        },
        imports={
                 0x649518: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x649524: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
        },
        classes={},
        instructions=[(6591528, 'push {fp, lr}'), (6591784, 'invalid')],
        calls=[(6591584, 'blx r3'), (6591728, 'bl sym.clamp_float__float__float_')],
        branches=[(6591596, 'bne', 6591620), (6591616, 'b', 6591740)],
        semantics=('[NPC -[fullnessFraction]] (imp 0x00649428, 65w): [NPC -[fullnessFraction]] (imp 0x00649428, 65w): if [self diesOfLowFullness] == 0 returns 1.0f, else clamp01(fullness (f32 self+0x44) / 5400.0) - f64 divide by the 5400.0 pool (0x1518 twin), clamp_float(_, 0.0f, 1.0f)..\n'),
    ),
    dict(
        name='nq_28',
        method='NPC -[getNamesArray]',
        types='^@8@0:4',
        start=6597880,
        end=6597908,
        disasm='disasm_worldtileloader_nq_28.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064ad30; body trimmed at the next IMP 0x0064ad14 NPC -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6597880, 'sub sp, sp, 8'), (6597904, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[getNamesArray]] (imp 0x0064acf8, 7w): [NPC -[getNamesArray]] (imp 0x0064acf8, 7w): returns nil (movw 0, ^@ return) - species subclasses supply the name pool..\n'),
    ),
    dict(
        name='nq_29',
        method='NPC -[getNamesArrayCount]',
        types='i8@0:4',
        start=6597908,
        end=6597936,
        disasm='disasm_worldtileloader_nq_29.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064ad30 (listing bound); next ObjC IMP 0x0064ad30 NPC -[breedString]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6597908, 'sub sp, sp, 8'), (6597932, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[getNamesArrayCount]] (imp 0x0064ad14, 7w): [NPC -[getNamesArrayCount]] (imp 0x0064ad14, 7w): constant 0..\n'),
    ),
    dict(
        name='nq_30',
        method='NPC -[healthFraction]',
        types='f8@0:4',
        start=6591376,
        end=6591528,
        disasm='disasm_worldtileloader_nq_30.txt',
        base_add=6591408,
        base_literal=6591516,
        boundary='ARM.exidx end 0x0064952c; body trimmed at the next IMP 0x00649428 NPC -[fullnessFraction]',
        selectors={
                 0x649420: (15200660, 'maxHealth'),
        },
        imports={},
        ivars={
                 0x649418: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
        },
        classes={},
        instructions=[(6591376, 'push {fp, lr}'), (6591524, 'andeq r0, r0, r0')],
        calls=[(6591448, 'bl loc.imp.objc_msgSend'), (6591492, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=('[NPC -[healthFraction]] (imp 0x00649390, 38w): [NPC -[healthFraction]] (imp 0x00649390, 38w): clamp01(1 - damage (u16 ldrh self+0x36) / [self maxHealth]) - vcvt.f32.u32 + vdiv + vsub, clamped to [0, 1.0f] by clamp_float..\n'),
    ),
    dict(
        name='nq_31',
        method='NPC -[inspectionStopped]',
        types='v8@0:4',
        start=6595080,
        end=6595176,
        disasm='disasm_worldtileloader_nq_31.txt',
        base_add=6595092,
        base_literal=6595172,
        boundary='ARM.exidx end 0x0064a268 (listing bound); next ObjC IMP 0x0064a268 NPC -[speciesName]',
        selectors={},
        imports={},
        ivars={
                 0x64a25c: (17157408, 'OBJC_IVAR_$_NPC.comingToInspectBlockhead', 112),
                 0x64a260: (17157404, 'OBJC_IVAR_$_NPC.inspectingBlockhead', 116),
        },
        classes={},
        instructions=[(6595080, 'push {fp, lr}'), (6595172, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[NPC -[inspectionStopped]] (imp 0x0064a208, 24w): [NPC -[inspectionStopped]] (imp 0x0064a208, 24w): clears both inspectingBlockhead (self+0x74) and comingToInspectBlockhead (self+0x70)..\n'),
    ),
    dict(
        name='nq_32',
        method='NPC -[isDoubleHeight]',
        types='c8@0:4',
        start=6596552,
        end=6596580,
        disasm='disasm_worldtileloader_nq_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a7e4 (listing bound); next ObjC IMP 0x0064a7e4 NPC -[canBeRemovedByBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596552, 'sub sp, sp, 8'), (6596576, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[isDoubleHeight]] (imp 0x0064a7c8, 7w): [NPC -[isDoubleHeight]] (imp 0x0064a7c8, 7w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_33',
        method='NPC -[isVisible]',
        types='c8@0:4',
        start=6594444,
        end=6594504,
        disasm='disasm_worldtileloader_nq_33.txt',
        base_add=6594452,
        base_literal=6594500,
        boundary='ARM.exidx end 0x00649fc8 (listing bound); next ObjC IMP 0x00649fc8 NPC -[blockheadCanRide:usingItem:]',
        selectors={},
        imports={},
        ivars={
                 0x649fc0: (17157400, 'OBJC_IVAR_$_NPC.visible', 57),
        },
        classes={},
        instructions=[(6594444, 'sub sp, sp, 8'), (6594500, 'adceq r5, r1, r8, asr fp')],
        calls=[],
        branches=[],
        semantics=('[NPC -[isVisible]] (imp 0x00649f8c, 15w): [NPC -[isVisible]] (imp 0x00649f8c, 15w): returns the visible byte (ldrsb self+0x39)..\n'),
    ),
    dict(
        name='nq_34',
        method='NPC -[jumpsOnSwipe]',
        types='c8@0:4',
        start=6618352,
        end=6618380,
        disasm='disasm_worldtileloader_nq_34.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fd60; body trimmed at the next IMP 0x0064fd0c NPC -[rideDirection]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618352, 'sub sp, sp, 8'), (6618376, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[jumpsOnSwipe]] (imp 0x0064fcf0, 7w): [NPC -[jumpsOnSwipe]] (imp 0x0064fcf0, 7w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_35',
        method='NPC -[maxAge]',
        types='f8@0:4',
        start=6568580,
        end=6568628,
        disasm='disasm_worldtileloader_nq_35.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00643ab4 (listing bound); next ObjC IMP 0x00643ab4 NPC -[diesOfOldAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6568580, 'sub sp, sp, 0x10'), (6568624, 'strmi sl, [ip], -r0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[maxAge]] (imp 0x00643a84, 12w): [NPC -[maxAge]] (imp 0x00643a84, 12w): constant 9000.0f (pool 0x460ca000; the r2 = 0x2328 int twin is a dead store)..\n'),
    ),
    dict(
        name='nq_36',
        method='NPC -[maxHealth]',
        types='S8@0:4',
        start=6591348,
        end=6591376,
        disasm='disasm_worldtileloader_nq_36.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00649390 (listing bound); next ObjC IMP 0x00649390 NPC -[healthFraction]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6591348, 'sub sp, sp, 8'), (6591372, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[maxHealth]] (imp 0x00649374, 7w): [NPC -[maxHealth]] (imp 0x00649374, 7w): constant 16 (0x10, uxth) - the u16 health ceiling behind healthFraction..\n'),
    ),
    dict(
        name='nq_37',
        method='NPC -[milkByBlockhead:]',
        types='c12@0:4@8',
        start=6596140,
        end=6596172,
        disasm='disasm_worldtileloader_nq_37.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a66c; body trimmed at the next IMP 0x0064a64c NPC -[canBeShavedByBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596140, 'sub sp, sp, 0xc'), (6596168, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[milkByBlockhead:]] (imp 0x0064a62c, 8w): [NPC -[milkByBlockhead:]] (imp 0x0064a62c, 8w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_38',
        method='NPC -[minFullness]',
        types='f8@0:4',
        start=6568656,
        end=6568708,
        disasm='disasm_worldtileloader_nq_38.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00643b04 (listing bound); next ObjC IMP 0x00643b04 NPC -[diesOfLowFullness]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6568656, 'sub sp, sp, 0x10'), (6568704, 'strbtgt r0, [r1], 0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[minFullness]] (imp 0x00643ad0, 13w): [NPC -[minFullness]] (imp 0x00643ad0, 13w): constant -1800.0f (pool 0xc4e10000)..\n'),
    ),
    dict(
        name='nq_39',
        method='NPC -[minRidableAge]',
        types='f8@0:4',
        start=6596668,
        end=6596716,
        disasm='disasm_worldtileloader_nq_39.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a86c (listing bound); next ObjC IMP 0x0064a86c NPC -[secondOptionTitle]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596668, 'sub sp, sp, 0x10'), (6596712, 'strbtmi r0, [r1], -0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[minRidableAge]] (imp 0x0064a83c, 12w): [NPC -[minRidableAge]] (imp 0x0064a83c, 12w): constant 900.0f (pool 0x44610000; 0x384 - the same age gate canMate uses)..\n'),
    ),
    dict(
        name='nq_40',
        method='NPC -[name]',
        types='@8@0:4',
        start=6612424,
        end=6612484,
        disasm='disasm_worldtileloader_nq_40.txt',
        base_add=6612432,
        base_literal=6612480,
        boundary='ARM.exidx end 0x0064e604 (listing bound); next ObjC IMP 0x0064e604 NPC -[changeName:]',
        selectors={},
        imports={},
        ivars={
                 0x64e5fc: (17157304, 'OBJC_IVAR_$_NPC.name', 92),
        },
        classes={},
        instructions=[(6612424, 'sub sp, sp, 8'), (6612480, 'adceq r1, r1, ip, lsl r5')],
        calls=[],
        branches=[],
        semantics=('[NPC -[name]] (imp 0x0064e5c8, 15w): [NPC -[name]] (imp 0x0064e5c8, 15w): getter for the name ivar (self+0x5c; same cell content 0xffffd1c4 as actionTitle)..\n'),
    ),
    dict(
        name='nq_41',
        method='NPC -[namePos]',
        types='{Vector2=[2f]}8@0:4',
        start=6621568,
        end=6621740,
        disasm='disasm_worldtileloader_nq_41.txt',
        base_add=6621584,
        base_literal=6621736,
        boundary='ARM.exidx end 0x00650a2c (listing bound); next ObjC IMP 0x00650a2c NPC -[riderDPadShouldAllowUpDown]',
        selectors={
                 0x650a24: (15200804, 'renderPos'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6621568, 'push {fp, lr}'), (6621736, 'adceq pc, r0, ip, asr r1')],
        calls=[(6621648, 'bl loc.imp.objc_msgSend_stret'), (6621684, 'bl sym.imp.memset'), (6621700, 'bl method.Vector2.Vector2_float__float_'), (6621720, 'bl method.Vector2.operator_Vector2_')],
        branches=[(6621632, 'beq', 6621656), (6621652, 'b', 6621688)],
        semantics=('[NPC -[namePos]] (imp 0x00650980, 43w): [NPC -[namePos]] (imp 0x00650980, 43w): [self renderPos] + Vector2(0, 1.0f) (objc_msgSend_stret + Vector2 ctor + Vector2::operator+) - the name label anchor one unit above the render position..\n'),
    ),
    dict(
        name='nq_42',
        method='NPC -[npcType]',
        types='i8@0:4',
        start=6568552,
        end=6568580,
        disasm='disasm_worldtileloader_nq_42.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00643a84 (listing bound); next ObjC IMP 0x00643a84 NPC -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6568552, 'sub sp, sp, 8'), (6568576, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[npcType]] (imp 0x00643a68, 7w): [NPC -[npcType]] (imp 0x00643a68, 7w): constant 0 (base; the 8 species override - the E121 NPCType table)..\n'),
    ),
    dict(
        name='nq_43',
        method='NPC -[npcUpdateNetDataForClient:]',
        types='{NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}12@0:4@8',
        start=6575572,
        end=6575740,
        disasm='disasm_worldtileloader_nq_43.txt',
        base_add=6575588,
        base_literal=6575736,
        boundary='ARM.exidx end 0x0064567c (listing bound); next ObjC IMP 0x0064567c NPC -[appendNPCCreationDataToData:]',
        selectors={
                 0x645674: (15200544, 'dynamicObjectNetData'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(6575572, 'push {r4, sl, fp, lr}'), (6575736, 'adceq sl, r1, r8, lsl 10')],
        calls=[(6575656, 'bl loc.imp.objc_msgSend_stret'), (6575692, 'bl sym.imp.memset'), (6575720, 'bl sym.imp.memcpy')],
        branches=[(6575640, 'beq', 6575664), (6575660, 'b', 6575696)],
        semantics=('[NPC -[npcUpdateNetDataForClient:]] (imp 0x006455d4, 42w): [NPC -[npcUpdateNetDataForClient:]] (imp 0x006455d4, 42w): copies [self dynamicObjectNetData] (24-byte stret record) into the NPCUpdateNetData return struct; nil-self -> zeroed 24 bytes; the client argument is spilled and never read..\n'),
    ),
    dict(
        name='nq_44',
        method='NPC -[objectType]',
        types='i8@0:4',
        start=6591824,
        end=6591904,
        disasm='disasm_worldtileloader_nq_44.txt',
        base_add=6591840,
        base_literal=6591900,
        boundary='ARM.exidx end 0x006495a0 (listing bound); next ObjC IMP 0x00649670 NPC -[die:]',
        selectors={
                 0x649598: (15200772, 'npcType'),
        },
        imports={
                 0x649594: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(6591824, 'push {fp, lr}'), (6591900, 'adceq r6, r1, ip, lsl 11')],
        calls=[(6591876, 'blx r3'), (6591880, 'bl sym.dynamicObjectTypeForNPCType_NPCType_')],
        branches=[],
        semantics=('[NPC -[objectType]] (imp 0x00649550, 20w): [NPC -[objectType]] (imp 0x00649550, 20w): dynamicObjectTypeForNPCType([self npcType]) - one objc_msgSend + the C table lookup (E121 NPCType -> dynamic object type)..\n'),
    ),
    dict(
        name='nq_45',
        method='NPC -[reactToBeingFed]',
        types='v8@0:4',
        start=6621548,
        end=6621568,
        disasm='disasm_worldtileloader_nq_45.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00650980 (listing bound); next ObjC IMP 0x00650980 NPC -[namePos]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6621548, 'sub sp, sp, 8'), (6621564, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[reactToBeingFed]] (imp 0x0065096c, 5w): [NPC -[reactToBeingFed]] (imp 0x0065096c, 5w): empty override (frame only, no-op)..\n'),
    ),
    dict(
        name='nq_46',
        method='NPC -[reactToBeingHit]',
        types='v8@0:4',
        start=6592640,
        end=6592660,
        disasm='disasm_worldtileloader_nq_46.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00649894 (listing bound); next ObjC IMP 0x00649894 NPC -[hitWithForce:blockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6592640, 'sub sp, sp, 8'), (6592656, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[reactToBeingHit]] (imp 0x00649880, 5w): [NPC -[reactToBeingHit]] (imp 0x00649880, 5w): empty override (frame only, no-op)..\n'),
    ),
    dict(
        name='nq_47',
        method='NPC -[remoteUpdate:]',
        types='v12@0:4@8',
        start=6585476,
        end=6585592,
        disasm='disasm_worldtileloader_nq_47.txt',
        base_add=6585492,
        base_literal=6585588,
        boundary='ARM.exidx end 0x00647cf8 (listing bound); next ObjC IMP 0x00647cf8 NPC -[remoteCreationDataUpdate:]',
        selectors={
                 0x647cec: (15200684, 'remoteUpdate:'),
        },
        imports={
                 0x647ce8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x647cf0: (15252612, 'OBJC_CLASS_$_NPC'),
        },
        instructions=[(6585476, 'push {r4, r5, fp, lr}'), (6585588, 'adceq r7, r1, r8, asr lr')],
        calls=[(6585564, 'blx lr')],
        branches=[],
        semantics=('[NPC -[remoteUpdate:]] (imp 0x00647c84, 29w): [NPC -[remoteUpdate:]] (imp 0x00647c84, 29w): pure super forward - objc_msgSendSuper2 with {self, OBJC_CLASS_$_NPC} and the remoteUpdate: selector (trampoline)..\n'),
    ),
    dict(
        name='nq_48',
        method='NPC -[removeIsRed]',
        types='c8@0:4',
        start=6597052,
        end=6597080,
        disasm='disasm_worldtileloader_nq_48.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a9f8; body trimmed at the next IMP 0x0064a9d8 NPC -[secondChoiceIsBlue]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6597052, 'sub sp, sp, 8'), (6597076, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[removeIsRed]] (imp 0x0064a9bc, 7w): [NPC -[removeIsRed]] (imp 0x0064a9bc, 7w): constant YES (sxtb 1) - the remove button renders red..\n'),
    ),
    dict(
        name='nq_49',
        method='NPC -[removeTitle]',
        types='@8@0:4',
        start=6597004,
        end=6597052,
        disasm='disasm_worldtileloader_nq_49.txt',
        base_add=6597012,
        base_literal=6597048,
        boundary='ARM.exidx end 0x0064a9f8; body trimmed at the next IMP 0x0064a9bc NPC -[removeIsRed]',
        selectors={},
        imports={
                 0x64a9b4: (16254664, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6597004, 'sub sp, sp, 8'), (6597048, 'adceq r5, r1, r8, asr r1')],
        calls=[],
        branches=[],
        semantics=('[NPC -[removeTitle]] (imp 0x0064a98c, 12w): [NPC -[removeTitle]] (imp 0x0064a98c, 12w): returns the constant CFString "SET FREE" (object @0xf806c8)..\n'),
    ),
    dict(
        name='nq_50',
        method='NPC -[renderPos]',
        types='{Vector2=[2f]}8@0:4',
        start=6594236,
        end=6594308,
        disasm='disasm_worldtileloader_nq_50.txt',
        base_add=6594244,
        base_literal=6594304,
        boundary='ARM.exidx end 0x00649f04 (listing bound); next ObjC IMP 0x00649f04 NPC -[center]',
        selectors={},
        imports={},
        ivars={
                 0x649efc: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(6594236, 'sub sp, sp, 8'), (6594304, 'adceq r5, r1, r8, lsr 24')],
        calls=[],
        branches=[],
        semantics=('[NPC -[renderPos]] (imp 0x00649ebc, 18w): [NPC -[renderPos]] (imp 0x00649ebc, 18w): copies the DynamicObject floatPos ivar (self+0x18, 2 floats) into the Vector2 return buffer (r0 = hidden struct pointer)..\n'),
    ),
    dict(
        name='nq_51',
        method='NPC -[requiresFuel]',
        types='c8@0:4',
        start=6618408,
        end=6618436,
        disasm='disasm_worldtileloader_nq_51.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fd60; body trimmed at the next IMP 0x0064fd44 NPC -[actsAsInteractionObject]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618408, 'sub sp, sp, 8'), (6618432, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[requiresFuel]] (imp 0x0064fd28, 7w): [NPC -[requiresFuel]] (imp 0x0064fd28, 7w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_52',
        method='NPC -[requiresPhysicalBlock]',
        types='c8@0:4',
        start=6619576,
        end=6619672,
        disasm='disasm_worldtileloader_nq_52.txt',
        base_add=6619584,
        base_literal=6619664,
        boundary='ARM.exidx end 0x00650218 (listing bound); next ObjC IMP 0x00650218 NPC -[checkCurrentPositionForFood]',
        selectors={},
        imports={},
        ivars={
                 0x65020c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
        },
        classes={},
        instructions=[(6619576, 'sub sp, sp, 0xc'), (6619668, 'andeq r0, r0, r0')],
        calls=[],
        branches=[(6619624, 'beq', 6619640), (6619636, 'b', 6619648)],
        semantics=('[NPC -[requiresPhysicalBlock]] (imp 0x006501b8, 24w): [NPC -[requiresPhysicalBlock]] (imp 0x006501b8, 24w): constant NO - the DynamicObject.isNet byte (self+0x34) is probed but both arms store 0..\n'),
    ),
    dict(
        name='nq_53',
        method='NPC -[ridableWhenTamed]',
        types='c8@0:4',
        start=6621796,
        end=6621824,
        disasm='disasm_worldtileloader_nq_53.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00650b10; body trimmed at the next IMP 0x00650a80 NPC -[clientIDForSavingSeperatelyAndOnlyLoadingWhilePlayerOnline]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6621796, 'sub sp, sp, 8'), (6621820, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[ridableWhenTamed]] (imp 0x00650a64, 7w): [NPC -[ridableWhenTamed]] (imp 0x00650a64, 7w): constant YES (sxtb 1)..\n'),
    ),
    dict(
        name='nq_54',
        method='NPC -[rideDirection]',
        types='i8@0:4',
        start=6618380,
        end=6618408,
        disasm='disasm_worldtileloader_nq_54.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fd60; body trimmed at the next IMP 0x0064fd28 NPC -[requiresFuel]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618380, 'sub sp, sp, 8'), (6618404, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[rideDirection]] (imp 0x0064fd0c, 7w): [NPC -[rideDirection]] (imp 0x0064fd0c, 7w): constant 0..\n'),
    ),
    dict(
        name='nq_55',
        method='NPC -[riderBodyYRotationForBlockhead:]',
        types='f12@0:4@8',
        start=6618116,
        end=6618164,
        disasm='disasm_worldtileloader_nq_55.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fc64; body trimmed at the next IMP 0x0064fc34 NPC -[riderBodyZRotationForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618116, 'sub sp, sp, 0x14'), (6618160, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[riderBodyYRotationForBlockhead:]] (imp 0x0064fc04, 12w): [NPC -[riderBodyYRotationForBlockhead:]] (imp 0x0064fc04, 12w): constant 0.0f (pool 0x00000000; arg ignored)..\n'),
    ),
    dict(
        name='nq_56',
        method='NPC -[riderBodyZRotationForBlockhead:]',
        types='f12@0:4@8',
        start=6618164,
        end=6618212,
        disasm='disasm_worldtileloader_nq_56.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fc64 (listing bound); next ObjC IMP 0x0064fc64 NPC -[cameraPosForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618164, 'sub sp, sp, 0x14'), (6618208, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[riderBodyZRotationForBlockhead:]] (imp 0x0064fc34, 12w): [NPC -[riderBodyZRotationForBlockhead:]] (imp 0x0064fc34, 12w): constant 0.0f - instruction-identical to nq_55 except the pool address..\n'),
    ),
    dict(
        name='nq_57',
        method='NPC -[riderDPadShouldAllowUpDown]',
        types='c8@0:4',
        start=6621740,
        end=6621768,
        disasm='disasm_worldtileloader_nq_57.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00650b10; body trimmed at the next IMP 0x00650a48 NPC -[suffersDamageAtHighTemperatures]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6621740, 'sub sp, sp, 8'), (6621764, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[riderDPadShouldAllowUpDown]] (imp 0x00650a2c, 7w): [NPC -[riderDPadShouldAllowUpDown]] (imp 0x00650a2c, 7w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_58',
        method='NPC -[riderDPadShouldGiveDiscreteValues]',
        types='c8@0:4',
        start=6619548,
        end=6619576,
        disasm='disasm_worldtileloader_nq_58.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006501b8 (listing bound); next ObjC IMP 0x006501b8 NPC -[requiresPhysicalBlock]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6619548, 'sub sp, sp, 8'), (6619572, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[riderDPadShouldGiveDiscreteValues]] (imp 0x0065019c, 7w): [NPC -[riderDPadShouldGiveDiscreteValues]] (imp 0x0065019c, 7w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_59',
        method='NPC -[riderPosForBlockhead:]',
        types='{Vector=[4f]}12@0:4@8',
        start=6619328,
        end=6619520,
        disasm='disasm_worldtileloader_nq_59.txt',
        base_add=6619364,
        base_literal=6619516,
        boundary='ARM.exidx end 0x00650180 (listing bound); next ObjC IMP 0x00650180 NPC -[setTargetVelocity:]',
        selectors={},
        imports={},
        ivars={
                 0x650178: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(6619328, 'push {fp, lr}'), (6619516, 'adceq pc, r0, r8, lsl 20')],
        calls=[(6619416, 'bl method.Vector2.Vector2_float__float_'), (6619436, 'bl method.Vector2.operator_Vector2_'), (6619444, 'bl method.Vector2.operator_float__'), (6619464, 'bl method.Vector2.operator_float__'), (6619496, 'bl method.Vector.Vector_float__float__float_')],
        branches=[],
        semantics=('[NPC -[riderPosForBlockhead:]] (imp 0x006500c0, 48w): [NPC -[riderPosForBlockhead:]] (imp 0x006500c0, 48w): Vector(floatPos.x, floatPos.y + 1.6f, -7.0f) - Vector2(0, 1.6f) (0x3f4ccccd) added to floatPos (self+0x18), then Vector ctor with z = -7.0f; the blockhead parameter is unused..\n'),
    ),
    dict(
        name='nq_60',
        method='NPC -[secondChoiceIsBlue]',
        types='c8@0:4',
        start=6597080,
        end=6597112,
        disasm='disasm_worldtileloader_nq_60.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a9f8 (listing bound); next ObjC IMP 0x0064a9f8 NPC -[generateNewName]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6597080, 'sub sp, sp, 8'), (6597108, 'andeq r0, r0, r0')],
        calls=[],
        branches=[],
        semantics=('[NPC -[secondChoiceIsBlue]] (imp 0x0064a9d8, 8w): [NPC -[secondChoiceIsBlue]] (imp 0x0064a9d8, 8w): constant YES (sxtb 1) - the second option button is blue..\n'),
    ),
    dict(
        name='nq_61',
        method='NPC -[secondOptionTitle]',
        types='@8@0:4',
        start=6596716,
        end=6597004,
        disasm='disasm_worldtileloader_nq_61.txt',
        base_add=6596732,
        base_literal=6597000,
        boundary='ARM.exidx end 0x0064a98c (listing bound); next ObjC IMP 0x0064a98c NPC -[removeTitle]',
        selectors={
                 0x64a974: (15200820, 'ridableWhenTamed'),
                 0x64a978: (15200664, 'diesOfOldAge'),
                 0x64a97c: (15200824, 'minRidableAge'),
        },
        imports={
                 0x64a970: (17151904, 'objc_msgSend'),
                 0x64a984: (16254648, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x64a980: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(6596716, 'push {fp, lr}'), (6597000, 'adceq r5, r1, r0, ror r2')],
        calls=[(6596772, 'blx r3'), (6596828, 'blx r2'), (6596912, 'blx r2')],
        branches=[(6596784, 'beq', 6596936), (6596840, 'beq', 6596948), (6596932, 'bpl', 6596948), (6596944, 'b', 6596964)],
        semantics=('[NPC -[secondOptionTitle]] (imp 0x0064a86c, 72w): [NPC -[secondOptionTitle]] (imp 0x0064a86c, 72w): the gated RIDE label - returns the RIDE CFString (@0xf806b8) iff [self ridableWhenTamed] && !([self diesOfOldAge] && [self age] < [self minRidableAge]); nil otherwise (the batch\'s longest body)..\n'),
    ),
    dict(
        name='nq_62',
        method='NPC -[setAge:]',
        types='v12@0:4f8',
        start=6624092,
        end=6624168,
        disasm='disasm_worldtileloader_nq_62.txt',
        base_add=6624124,
        base_literal=6624164,
        boundary='ARM.exidx end 0x006513a8 (listing bound); next ObjC IMP 0x006513a8 NPC -[breed]',
        selectors={},
        imports={},
        ivars={
                 0x6513a0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(6624092, 'sub sp, sp, 0xc'), (6624164, 'adceq lr, r0, r0, ror r7')],
        calls=[],
        branches=[],
        semantics=('[NPC -[setAge:]] (imp 0x0065135c, 19w): [NPC -[setAge:]] (imp 0x0065135c, 19w): float setter for age (self+0x58) with dmb ish on both sides of the store (bit-atomic write)..\n'),
    ),
    dict(
        name='nq_63',
        method='NPC -[setBabyCreationStartValues]',
        types='v8@0:4',
        start=6571496,
        end=6571780,
        disasm='disasm_worldtileloader_nq_63.txt',
        base_add=6571512,
        base_literal=6571776,
        boundary='ARM.exidx end 0x00644704 (listing bound); next ObjC IMP 0x00644704 NPC -[createItemDropsForDeath]',
        selectors={},
        imports={},
        ivars={
                 0x6446e4: (17157284, 'OBJC_IVAR_$_NPC.mateCooldownTimer', 76),
                 0x6446e8: (17157292, 'OBJC_IVAR_$_NPC.layCooldownTimer', 84),
                 0x6446f4: (17157268, 'OBJC_IVAR_$_NPC.fullness', 68),
                 0x6446fc: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(6571496, 'push {fp, lr}'), (6571776, 'invalid')],
        calls=[(6571564, 'bl 0x6445d8'), (6571632, 'bl 0x6445d8')],
        branches=[],
        semantics=('[NPC -[setBabyCreationStartValues]] (imp 0x006445e8, 71w): [NPC -[setBabyCreationStartValues]] (imp 0x006445e8, 71w): newborn defaults - age = 0.0f; fullness = 900 + lrand48()/2^31 * 900; layCooldownTimer = the same 900 + u*900; mateCooldownTimer = 60.0f (0x3c). Helper 0x6445d8 = thin lrand48 wrapper, called x2..\n'),
    ),
    dict(
        name='nq_64',
        method='NPC -[setTargetVelocity:]',
        types='v16@0:4{Vector2=[2f]}8',
        start=6619520,
        end=6619548,
        disasm='disasm_worldtileloader_nq_64.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0065019c (listing bound); next ObjC IMP 0x0065019c NPC -[riderDPadShouldGiveDiscreteValues]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6619520, 'sub sp, sp, 0x10'), (6619544, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[setTargetVelocity:]] (imp 0x00650180, 7w): [NPC -[setTargetVelocity:]] (imp 0x00650180, 7w): empty override - the Vector2 argument words are only spilled; the base NPC ignores target velocity..\n'),
    ),
    dict(
        name='nq_65',
        method='NPC -[shaveByBlockhead:]',
        types='c12@0:4@8',
        start=6596388,
        end=6596420,
        disasm='disasm_worldtileloader_nq_65.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064a744 (listing bound); next ObjC IMP 0x0064a744 NPC -[canBeCapturedByBlockhead:withItemType:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6596388, 'sub sp, sp, 0xc'), (6596416, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[shaveByBlockhead:]] (imp 0x0064a724, 8w): [NPC -[shaveByBlockhead:]] (imp 0x0064a724, 8w): constant NO (sxtb 0)..\n'),
    ),
    dict(
        name='nq_66',
        method='NPC -[shouldSaveEveryChangeInPosition]',
        types='c8@0:4',
        start=6621884,
        end=6621968,
        disasm='disasm_worldtileloader_nq_66.txt',
        base_add=6621892,
        base_literal=6621964,
        boundary='ARM.exidx end 0x00650b10 (listing bound); next ObjC IMP 0x00650b10 NPC -[updatePosition:]',
        selectors={},
        imports={},
        ivars={
                 0x650b08: (17157364, 'OBJC_IVAR_$_NPC.rider', 132),
        },
        classes={},
        instructions=[(6621884, 'sub sp, sp, 8'), (6621964, 'adceq pc, r0, r8, lsr 32')],
        calls=[],
        branches=[],
        semantics=('[NPC -[shouldSaveEveryChangeInPosition]] (imp 0x00650abc, 21w): [NPC -[shouldSaveEveryChangeInPosition]] (imp 0x00650abc, 21w): rider (self+0x84) != nil (movne 1 + and 1 + sxtb)..\n'),
    ),
    dict(
        name='nq_67',
        method='NPC -[speciesName]',
        types='@8@0:4',
        start=6595176,
        end=6595224,
        disasm='disasm_worldtileloader_nq_67.txt',
        base_add=6595184,
        base_literal=6595220,
        boundary='ARM.exidx end 0x0064a2f0; body trimmed at the next IMP 0x0064a298 NPC -[foodItemType]',
        selectors={},
        imports={
                 0x64a290: (16254584, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(6595176, 'sub sp, sp, 8'), (6595220, 'adceq r5, r1, ip, ror r8')],
        calls=[],
        branches=[],
        semantics=('[NPC -[speciesName]] (imp 0x0064a268, 12w): [NPC -[speciesName]] (imp 0x0064a268, 12w): returns the constant CFString "CRITTER" (object @0xf80678) - the base species label the tip formats substitute..\n'),
    ),
    dict(
        name='nq_68',
        method='NPC -[swipeUpGesture]',
        types='v8@0:4',
        start=6618096,
        end=6618116,
        disasm='disasm_worldtileloader_nq_68.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0064fc04 (listing bound); next ObjC IMP 0x0064fc04 NPC -[riderBodyYRotationForBlockhead:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6618096, 'sub sp, sp, 8'), (6618112, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[swipeUpGesture]] (imp 0x0064fbf0, 5w): [NPC -[swipeUpGesture]] (imp 0x0064fbf0, 5w): empty override (frame only, no-op)..\n'),
    ),
    dict(
        name='nq_69',
        method='NPC -[tamed]',
        types='c8@0:4',
        start=6613020,
        end=6613208,
        disasm='disasm_worldtileloader_nq_69.txt',
        base_add=6613028,
        base_literal=6613204,
        boundary='ARM.exidx end 0x0064e8d8 (listing bound); next ObjC IMP 0x0064e8d8 NPC -[belongsToPlayerWithBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x64e8c8: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x64e8cc: (17157308, 'OBJC_IVAR_$_NPC.tamedClientID', 108),
                 0x64e8d0: (17157320, 'OBJC_IVAR_$_NPC.netTameType', 192),
        },
        classes={},
        instructions=[(6613020, 'sub sp, sp, 0x10'), (6613204, 'adceq r1, r1, r8, asr 5')],
        calls=[],
        branches=[(6613072, 'beq', 6613128), (6613124, 'b', 6613180)],
        semantics=('[NPC -[tamed]] (imp 0x0064e81c, 47w): [NPC -[tamed]] (imp 0x0064e81c, 47w): isNet (self+0x34) ? (netTameType byte (self+0xc0) != 0) : (tamedClientID pointer (self+0x6c) != nil); both arms bool-masked + sxtb..\n'),
    ),
    dict(
        name='nq_70',
        method='NPC -[tapIsWithinBodyRadius:]',
        types='c16@0:4{Vector2=[2f]}8',
        start=6591788,
        end=6591824,
        disasm='disasm_worldtileloader_nq_70.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00649550 (listing bound); next ObjC IMP 0x00649550 NPC -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6591788, 'sub sp, sp, 0x10'), (6591820, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[tapIsWithinBodyRadius:]] (imp 0x0064952c, 9w): [NPC -[tapIsWithinBodyRadius:]] (imp 0x0064952c, 9w): constant NO (sxtb 0) - the Vector2 tap argument is spilled only..\n'),
    ),
    dict(
        name='nq_71',
        method='NPC -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=6576576,
        end=6576812,
        disasm='disasm_worldtileloader_nq_71.txt',
        base_add=6576592,
        base_literal=6576808,
        boundary='ARM.exidx end 0x00645aac (listing bound); next ObjC IMP 0x00645aac NPC -[getSaveDict]',
        selectors={
                 0x645a98: (15200584, 'npcUpdateNetDataForClient:'),
                 0x645aa0: (15200576, 'dataWithBytes:length:'),
        },
        imports={
                 0x645a9c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x645aa4: (15245892, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(6576576, 'push {fp, lr}'), (6576808, 'adceq sl, r1, ip, lsl r1')],
        calls=[(6576672, 'bl loc.imp.objc_msgSend_stret'), (6576708, 'bl sym.imp.memset'), (6576772, 'blx ip')],
        branches=[(6576652, 'beq', 6576680), (6576676, 'b', 6576712)],
        semantics=('[NPC -[updateNetDataForClient:]] (imp 0x006459c0, 59w): [NPC -[updateNetDataForClient:]] (imp 0x006459c0, 59w): packs the 24-byte [self npcUpdateNetDataForClient:client] record into [NSData dataWithBytes:length:0x18] - the NPC update wire blob; nil-self -> zeroed record still packed..\n'),
    ),
    dict(
        name='nq_72',
        method='NPC -[willDieIfHitByForce:]',
        types='c12@0:4i8',
        start=6594080,
        end=6594236,
        disasm='disasm_worldtileloader_nq_72.txt',
        base_add=6594096,
        base_literal=6594232,
        boundary='ARM.exidx end 0x00649ebc (listing bound); next ObjC IMP 0x00649ebc NPC -[renderPos]',
        selectors={
                 0x649eb0: (15200660, 'maxHealth'),
        },
        imports={
                 0x649eac: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x649eb4: (17157260, 'OBJC_IVAR_$_NPC.damage', 54),
        },
        classes={},
        instructions=[(6594080, 'push {r4, sl, fp, lr}'), (6594232, 'invalid')],
        calls=[(6594180, 'blx ip')],
        branches=[],
        semantics=('[NPC -[willDieIfHitByForce:]] (imp 0x00649e20, 39w): [NPC -[willDieIfHitByForce:]] (imp 0x00649e20, 39w): (damage (u16 ldrh self+0x36) + force) >= [self maxHealth] (uxth on the result; movge 1) - the lethal-blow probe..\n'),
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
        'batch': 'NPC tail sweep (E128): 73 bodies',
        'claim': ('the riding contract and the RIDE/SET FREE gates; all 73 bodies read in full'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'npc2.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale npc2.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
