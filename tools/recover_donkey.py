#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The animals line opens: the Donkey class: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 15785 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/DONKEY.md for the prose and boundaries.
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
    'bl 0x6bc3ac': 0x006bc3ac,
    'bl 0x6c3d3c': 0x006c3d3c,
    'bl 0x6c3f24': 0x006c3f24,
    'bl 0x6c42bc': 0x006c42bc,
    'bl 0x6c4654': 0x006c4654,
    'bl 0x6c480c': 0x006c480c,
    'bl 0x6c9fe0': 0x006c9fe0,
    'bl 0x6ca5a0': 0x006ca5a0,
    'bl 0x6ca854': 0x006ca854,
    'bl 0x6ca890': 0x006ca890,
    'bl 0x6cadb8': 0x006cadb8,
    'bl 0x6cb3e0': 0x006cb3e0,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.pow': 0x001c3fec,
    'bl sym.imp.sinf': 0x001c2b34,
    'bl sym.nameForDonkeyBreed_DonkeyBreed_': 0x006caf24,
}

SPECS = [
    dict(
        name='d_npctype',
        method='Donkey -[npcType]',
        types='i8@0:4',
        start=7054488,
        end=7054516,
        disasm='disasm_worldtileloader_d_npctype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ba4b4 (listing bound); next ObjC IMP 0x006ba4b4 Donkey -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7054488, 'sub sp, sp, 8'), (7054512, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey npcType] (imp 0x006ba498, 7w): the NPC type constant.\n'),
    ),
    dict(
        name='d_maxage',
        method='Donkey -[maxAge]',
        types='f8@0:4',
        start=7054516,
        end=7054616,
        disasm='disasm_worldtileloader_d_maxage.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ba518 (listing bound); next ObjC IMP 0x006ba4e4 Donkey -[minFullness]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7054516, 'sub sp, sp, 0x10'), (7054612, 'strbtgt r0, [r1], 0')],
        calls=[],
        branches=[],
        semantics=('[Donkey maxAge] (imp 0x006ba4b4, 25w): the max-age accessor.\n'),
    ),
    dict(
        name='d_minfullness',
        method='Donkey -[minFullness]',
        types='f8@0:4',
        start=7054564,
        end=7054616,
        disasm='disasm_worldtileloader_d_minfullness.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ba518 (listing bound); next ObjC IMP 0x006ba518 Donkey -[foodPlantType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7054564, 'sub sp, sp, 0x10'), (7054612, 'strbtgt r0, [r1], 0')],
        calls=[],
        branches=[],
        semantics=('[Donkey minFullness] (imp 0x006ba4e4, 13w): the fullness floor.\n'),
    ),
    dict(
        name='d_foodplanttype',
        method='Donkey -[foodPlantType]',
        types='i8@0:4',
        start=7054616,
        end=7054704,
        disasm='disasm_worldtileloader_d_foodplanttype.txt',
        base_add=7054624,
        base_literal=7054700,
        boundary='ARM.exidx end 0x006ba570 (listing bound); next ObjC IMP 0x006ba570 Donkey -[speciesName]',
        selectors={},
        imports={},
        ivars={
                 0x6ba568: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7054616, 'sub sp, sp, 8'), (7054700, 'addseq r5, sl, ip, asr 11')],
        calls=[],
        branches=[],
        semantics=('[Donkey foodPlantType] (imp 0x006ba518, 22w): the food plant type.\n'),
    ),
    dict(
        name='d_speciesname',
        method='Donkey -[speciesName]',
        types='@8@0:4',
        start=7054704,
        end=7054816,
        disasm='disasm_worldtileloader_d_speciesname.txt',
        base_add=7054716,
        base_literal=7054812,
        boundary='ARM.exidx end 0x006ba5e0 (listing bound); next ObjC IMP 0x006ba5e0 Donkey -[foodItemType]',
        selectors={},
        imports={
                 0x6ba5d0: (16275832, '__CFConstantStringClassReference'),
                 0x6ba5d4: (16275848, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x6ba5d8: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7054704, 'push {fp, lr}'), (7054812, 'addseq r5, sl, r0, ror r5')],
        calls=[],
        branches=[],
        semantics=('[Donkey speciesName] (imp 0x006ba570, 28w): the species name (imp x2).\n'),
    ),
    dict(
        name='d_fooditemtype',
        method='Donkey -[foodItemType]',
        types='i8@0:4',
        start=7054816,
        end=7055020,
        disasm='disasm_worldtileloader_d_fooditemtype.txt',
        base_add=7054824,
        base_literal=7054900,
        boundary='ARM.exidx end 0x006ba6ac (listing bound); next ObjC IMP 0x006ba638 Donkey -[capturedItemType]',
        selectors={},
        imports={},
        ivars={
                 0x6ba630: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6ba688: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7054816, 'sub sp, sp, 8'), (7055016, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey foodItemType] (imp 0x006ba5e0, 51w): the food item.\n'),
    ),
    dict(
        name='d_captureditemtype',
        method='Donkey -[capturedItemType]',
        types='i8@0:4',
        start=7054904,
        end=7055020,
        disasm='disasm_worldtileloader_d_captureditemtype.txt',
        base_add=7054912,
        base_literal=7054988,
        boundary='ARM.exidx end 0x006ba6ac (listing bound); next ObjC IMP 0x006ba690 Donkey -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={
                 0x6ba688: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7054904, 'sub sp, sp, 8'), (7055016, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey capturedItemType] (imp 0x006ba638, 29w): the capture item.\n'),
    ),
    dict(
        name='d_capturerequireditemtype',
        method='Donkey -[captureRequiredItemType]',
        types='i8@0:4',
        start=7054992,
        end=7055020,
        disasm='disasm_worldtileloader_d_capturerequireditemtype.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ba6ac (listing bound); next ObjC IMP 0x006ba6ac Donkey -[getNamesArray]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7054992, 'sub sp, sp, 8'), (7055016, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey captureRequiredItemType] (imp 0x006ba690, 7w): the required capture item constant.\n'),
    ),
    dict(
        name='d_getnamesarray',
        method='Donkey -[getNamesArray]',
        types='^@8@0:4',
        start=7055020,
        end=7055132,
        disasm='disasm_worldtileloader_d_getnamesarray.txt',
        base_add=7055032,
        base_literal=7055128,
        boundary='ARM.exidx end 0x006ba71c (listing bound); next ObjC IMP 0x006ba71c Donkey -[getNamesArrayCount]',
        selectors={},
        imports={},
        ivars={
                 0x6ba714: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7055020, 'push {fp, lr}'), (7055128, 'addseq r5, sl, r4, lsr r4')],
        calls=[],
        branches=[],
        semantics=('[Donkey getNamesArray] (imp 0x006ba6ac, 28w): the names array (cfstring x2!).\n'),
    ),
    dict(
        name='d_getnamesarraycount',
        method='Donkey -[getNamesArrayCount]',
        types='i8@0:4',
        start=7055132,
        end=7055248,
        disasm='disasm_worldtileloader_d_getnamesarraycount.txt',
        base_add=7055140,
        base_literal=7055216,
        boundary='ARM.exidx end 0x006ba790 (listing bound); next ObjC IMP 0x006ba774 Donkey -[creationDataStructSize]',
        selectors={},
        imports={},
        ivars={
                 0x6ba76c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7055132, 'sub sp, sp, 8'), (7055244, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey getNamesArrayCount] (imp 0x006ba71c, 29w): the names count.\n'),
    ),
    dict(
        name='d_creationdatastructsize',
        method='Donkey -[creationDataStructSize]',
        types='L8@0:4',
        start=7055220,
        end=7055248,
        disasm='disasm_worldtileloader_d_creationdatastructsize.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ba790 (listing bound); next ObjC IMP 0x006ba790 Donkey -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7055220, 'sub sp, sp, 8'), (7055244, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey creationDataStructSize] (imp 0x006ba774, 7w): the creation struct size constant.\n'),
    ),
    dict(
        name='d_loadderivedstuff',
        method='Donkey -[loadDerivedStuff]',
        types='v8@0:4',
        start=7055248,
        end=7062444,
        disasm='disasm_worldtileloader_d_loadderivedstuff.txt',
        base_add=7055268,
        base_literal=7057508,
        boundary='ARM.exidx end 0x006bc3ac (listing bound); next ObjC IMP 0x006bc680 Donkey -[dealloc]',
        selectors={
                 0x6bb06c: (15203212, 'loadDerivedStuff'),
                 0x6bb084: (15203216, 'textureNamed:'),
                 0x6bc1b4: (15203224, 'shaderNamed:attributes:uniforms:'),
                 0x6bc338: (15203220, 'arrayWithObjects:'),
                 0x6bc350: (15203232, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
                 0x6bc354: (15203228, 'alloc'),
                 0x6bc384: (15203240, 'multiSoundNamed:'),
                 0x6bc388: (15203236, 'instance'),
        },
        imports={
                 0x6bb068: (17151900, 'objc_msgSendSuper2'),
                 0x6bb07c: (16275928, '__CFConstantStringClassReference'),
                 0x6bb080: (17151904, 'objc_msgSend'),
                 0x6bb090: (16275912, '__CFConstantStringClassReference'),
                 0x6bb098: (16275896, '__CFConstantStringClassReference'),
                 0x6bb0a0: (16275880, '__CFConstantStringClassReference'),
                 0x6bb0a8: (16275864, '__CFConstantStringClassReference'),
                 0x6bb0ac: (16276008, '__CFConstantStringClassReference'),
                 0x6bb0b0: (16275992, '__CFConstantStringClassReference'),
                 0x6bb0b4: (16275976, '__CFConstantStringClassReference'),
                 0x6bb0b8: (16275960, '__CFConstantStringClassReference'),
                 0x6bb0bc: (16275944, '__CFConstantStringClassReference'),
                 0x6bbb98: (16276104, '__CFConstantStringClassReference'),
                 0x6bbb9c: (16276088, '__CFConstantStringClassReference'),
                 0x6bbba0: (16276072, '__CFConstantStringClassReference'),
                 0x6bbba4: (16276056, '__CFConstantStringClassReference'),
                 0x6bbba8: (16276040, '__CFConstantStringClassReference'),
                 0x6bbbac: (16276024, '__CFConstantStringClassReference'),
                 0x6bbbb0: (16276200, '__CFConstantStringClassReference'),
                 0x6bbbb4: (16276184, '__CFConstantStringClassReference'),
                 0x6bbbb8: (16276168, '__CFConstantStringClassReference'),
                 0x6bbbbc: (16276152, '__CFConstantStringClassReference'),
                 0x6bbbc0: (16276136, '__CFConstantStringClassReference'),
                 0x6bbbc4: (16276120, '__CFConstantStringClassReference'),
                 0x6bc1b0: (16276216, '__CFConstantStringClassReference'),
                 0x6bc1b8: (16276280, '__CFConstantStringClassReference'),
                 0x6bc1bc: (16276296, '__CFConstantStringClassReference'),
                 0x6bc1c0: (16276312, '__CFConstantStringClassReference'),
                 0x6bc1c4: (16276328, '__CFConstantStringClassReference'),
                 0x6bc1c8: (16276344, '__CFConstantStringClassReference'),
                 0x6bc330: (17151904, 'objc_msgSend'),
                 0x6bc340: (16276232, '__CFConstantStringClassReference'),
                 0x6bc344: (16276248, '__CFConstantStringClassReference'),
                 0x6bc348: (16276264, '__CFConstantStringClassReference'),
                 0x6bc380: (16276440, '__CFConstantStringClassReference'),
                 0x6bc394: (16276424, '__CFConstantStringClassReference'),
                 0x6bc39c: (16276408, '__CFConstantStringClassReference'),
                 0x6bc3a0: (16276392, '__CFConstantStringClassReference'),
                 0x6bc3a4: (16276376, '__CFConstantStringClassReference'),
                 0x6bc3a8: (16276360, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x6bb074: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6bb078: (17158156, 'OBJC_IVAR_$_Donkey.earTexture', 840),
                 0x6bb088: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x6bb08c: (17158160, 'OBJC_IVAR_$_DonkeyLike.legTexture', 224),
                 0x6bb094: (17158164, 'OBJC_IVAR_$_DonkeyLike.headTexture', 220),
                 0x6bb09c: (17158168, 'OBJC_IVAR_$_DonkeyLike.neckTexture', 216),
                 0x6bb0a4: (17158172, 'OBJC_IVAR_$_DonkeyLike.bodyTexture', 212),
                 0x6bbb94: (17158176, 'OBJC_IVAR_$_Donkey.hornTexture', 976),
                 0x6bc1a4: (17158180, 'OBJC_IVAR_$_DonkeyLike.bodyColor', 808),
                 0x6bc1a8: (17158184, 'OBJC_IVAR_$_DonkeyLike.useColoredShader', 824),
                 0x6bc1ac: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x6bc32c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6bc334: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x6bc34c: (17158192, 'OBJC_IVAR_$_Donkey.tailCubeA', 1056),
                 0x6bc35c: (17158196, 'OBJC_IVAR_$_DonkeyLike.legCube', 240),
                 0x6bc360: (17158200, 'OBJC_IVAR_$_DonkeyLike.neckCube', 232),
                 0x6bc364: (17158204, 'OBJC_IVAR_$_DonkeyLike.headCube', 236),
                 0x6bc368: (17158208, 'OBJC_IVAR_$_Donkey.earCube', 844),
                 0x6bc36c: (17158212, 'OBJC_IVAR_$_DonkeyLike.bodyCube', 228),
                 0x6bc370: (17158216, 'OBJC_IVAR_$_Donkey.hornCube', 980),
                 0x6bc374: (17158220, 'OBJC_IVAR_$_Donkey.tailCubeC', 1064),
                 0x6bc378: (17158224, 'OBJC_IVAR_$_Donkey.tailCubeB', 1060),
                 0x6bc37c: (17158228, 'OBJC_IVAR_$_DonkeyLike.deathSound', 252),
                 0x6bc390: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0x6bc398: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
        },
        classes={
                 0x6bb070: (15252668, 'OBJC_CLASS_$_Donkey'),
                 0x6bc33c: (15246232, 'OBJC_CLASS_$_NSArray'),
                 0x6bc358: (15246236, 'OBJC_CLASS_$_DrawCube'),
                 0x6bc38c: (15246240, 'OBJC_CLASS_$_MJSoundManager'),
        },
        instructions=[(7055248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7062440, 'invalid')],
        calls=[(7055336, 'blx ip'), (7055568, 'blx r3'), (7055628, 'blx ip'), (7055688, 'blx ip'), (7055748, 'blx ip'), (7055808, 'blx ip'), (7056064, 'blx r3'), (7056124, 'blx ip'), (7056184, 'blx ip'), (7056244, 'blx ip'), (7056304, 'blx ip'), (7056592, 'blx r3'), (7056652, 'blx ip'), (7056712, 'blx ip'), (7056772, 'blx ip'), (7056832, 'blx ip'), (7056892, 'blx ip'), (7057180, 'blx r3'), (7057240, 'blx ip'), (7057300, 'blx ip'), (7057360, 'blx ip'), (7057420, 'blx ip'), (7057480, 'blx ip'), (7057792, 'blx r3'), (7057852, 'blx ip'), (7057912, 'blx ip'), (7057972, 'blx ip'), (7058032, 'blx ip'), (7058116, 'bl 0x6bc3ac'), (7058480, 'blx lr'), (7058552, 'blx r6'), (7058596, 'blx lr'), (7059092, 'blx ip'), (7059180, 'blx lr'), (7059232, 'blx ip'), (7059324, 'blx lr'), (7059376, 'blx ip'), (7059456, 'blx lr'), (7059508, 'blx ip'), (7059600, 'blx lr'), (7059652, 'blx ip'), (7059812, 'blx lr'), (7059864, 'blx ip'), (7059944, 'blx lr'), (7059996, 'blx ip'), (7060076, 'blx lr'), (7060128, 'blx ip'), (7060208, 'blx lr'), (7060260, 'blx ip'), (7060344, 'blx lr'), (7060744, 'blx r3'), (7060836, 'blx lr'), (7060888, 'blx ip'), (7060980, 'blx lr'), (7061032, 'blx ip'), (7061112, 'blx lr'), (7061164, 'blx ip'), (7061256, 'blx lr'), (7061308, 'blx ip'), (7061388, 'blx lr'), (7061440, 'blx ip'), (7061520, 'blx lr'), (7061732, 'blx r3'), (7061752, 'blx r3'), (7061804, 'blx ip'), (7061824, 'blx r3'), (7061876, 'blx ip'), (7061896, 'blx r3'), (7062116, 'blx r3'), (7062136, 'blx r3'), (7062188, 'blx ip'), (7062208, 'blx r3'), (7062260, 'blx ip'), (7062280, 'blx r3')],
        branches=[(7055372, 'bne', 7055836), (7055832, 'b', 7058652), (7055868, 'bne', 7056332), (7056328, 'b', 7058648), (7056364, 'bne', 7056920), (7056916, 'b', 7058644), (7056952, 'blt', 7057600), (7057504, 'b', 7058056), (7058644, 'b', 7058648), (7058648, 'b', 7058652), (7058684, 'blt', 7060436), (7059712, 'b', 7059792), (7060368, 'b', 7061544), (7061576, 'blt', 7061964), (7061920, 'b', 7062304)],
        semantics=('[Donkey loadDerivedStuff] (imp 0x006ba790, 1799w): the derived loader - 74 calls (sel x8/imp x40/ivar x25/cls x4) + the helper 0x6bc3ac: the donkey derives its stats/parts from the breed data.\n'),
    ),
    dict(
        name='d_dealloc',
        method='Donkey -[dealloc]',
        types='v8@0:4',
        start=7063168,
        end=7063796,
        disasm='disasm_worldtileloader_d_dealloc.txt',
        base_add=7063184,
        base_literal=7063792,
        boundary='ARM.exidx end 0x006bc8f4 (listing bound); next ObjC IMP 0x006bc8f4 Donkey -[maxHealth]',
        selectors={
                 0x6bc8bc: (15203248, 'dealloc'),
                 0x6bc8c8: (15203244, 'release'),
        },
        imports={
                 0x6bc8b8: (17151900, 'objc_msgSendSuper2'),
                 0x6bc8c4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6bc8cc: (17158220, 'OBJC_IVAR_$_Donkey.tailCubeC', 1064),
                 0x6bc8d0: (17158224, 'OBJC_IVAR_$_Donkey.tailCubeB', 1060),
                 0x6bc8d4: (17158192, 'OBJC_IVAR_$_Donkey.tailCubeA', 1056),
                 0x6bc8d8: (17158216, 'OBJC_IVAR_$_Donkey.hornCube', 980),
                 0x6bc8dc: (17158208, 'OBJC_IVAR_$_Donkey.earCube', 844),
                 0x6bc8e0: (17158196, 'OBJC_IVAR_$_DonkeyLike.legCube', 240),
                 0x6bc8e4: (17158204, 'OBJC_IVAR_$_DonkeyLike.headCube', 236),
                 0x6bc8e8: (17158200, 'OBJC_IVAR_$_DonkeyLike.neckCube', 232),
                 0x6bc8ec: (17158212, 'OBJC_IVAR_$_DonkeyLike.bodyCube', 228),
        },
        classes={
                 0x6bc8c0: (15252668, 'OBJC_CLASS_$_Donkey'),
        },
        instructions=[(7063168, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7063792, 'addseq r3, sl, ip, asr r4')],
        calls=[(7063396, 'blx r5'), (7063432, 'blx r3'), (7063468, 'blx r3'), (7063504, 'blx r3'), (7063540, 'blx r3'), (7063576, 'blx r3'), (7063612, 'blx r3'), (7063648, 'blx r3'), (7063684, 'blx r3'), (7063724, 'blx r2')],
        branches=[],
        semantics=('[Donkey dealloc] (imp 0x006bc680, 157w): the teardown - 10 calls + the ivar chain.\n'),
    ),
    dict(
        name='d_maxhealth',
        method='Donkey -[maxHealth]',
        types='S8@0:4',
        start=7063796,
        end=7063984,
        disasm='disasm_worldtileloader_d_maxhealth.txt',
        base_add=7063832,
        base_literal=7063900,
        boundary='ARM.exidx end 0x006bc9b0 (listing bound); next ObjC IMP 0x006bc910 Donkey -[flies]',
        selectors={},
        imports={},
        ivars={
                 0x6bc958: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6bc9a8: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7063796, 'sub sp, sp, 8'), (7063980, 'addseq r3, sl, r4, lsl 3')],
        calls=[],
        branches=[],
        semantics=('[Donkey maxHealth] (imp 0x006bc8f4, 47w): the health cap (const 0x20 in the pool + the ivar chain).\n'),
    ),
    dict(
        name='d_flies',
        method='Donkey -[flies]',
        types='c8@0:4',
        start=7063824,
        end=7063984,
        disasm='disasm_worldtileloader_d_flies.txt',
        base_add=7063832,
        base_literal=7063900,
        boundary='ARM.exidx end 0x006bc9b0 (listing bound); next ObjC IMP 0x006bc960 Donkey -[canJumpMultipleTilesWhileFlying]',
        selectors={},
        imports={},
        ivars={
                 0x6bc958: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6bc9a8: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7063824, 'sub sp, sp, 8'), (7063980, 'addseq r3, sl, r4, lsl 3')],
        calls=[],
        branches=[],
        semantics=('[Donkey flies] (imp 0x006bc910, 40w): the flight flag.\n'),
    ),
    dict(
        name='d_canjumpmultipletileswhilefly',
        method='Donkey -[canJumpMultipleTilesWhileFlying]',
        types='c8@0:4',
        start=7063904,
        end=7063984,
        disasm='disasm_worldtileloader_d_canjumpmultipletileswhilefly.txt',
        base_add=7063912,
        base_literal=7063980,
        boundary='ARM.exidx end 0x006bc9b0 (listing bound); next ObjC IMP 0x006bc9b0 Donkey -[galloping]',
        selectors={},
        imports={},
        ivars={
                 0x6bc9a8: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7063904, 'sub sp, sp, 8'), (7063980, 'addseq r3, sl, r4, lsl 3')],
        calls=[],
        branches=[],
        semantics=('[Donkey canJumpMultipleTilesWhileFlying] (imp 0x006bc960, 20w): the flight-jump predicate.\n'),
    ),
    dict(
        name='d_galloping',
        method='Donkey -[galloping]',
        types='c8@0:4',
        start=7063984,
        end=7064200,
        disasm='disasm_worldtileloader_d_galloping.txt',
        base_add=7063992,
        base_literal=7064196,
        boundary='ARM.exidx end 0x006bca88 (listing bound); next ObjC IMP 0x006bca88 Donkey -[maxVelocity]',
        selectors={},
        imports={},
        ivars={
                 0x6bca78: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6bca7c: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0x6bca80: (17158244, 'OBJC_IVAR_$_DonkeyLike.falling', 316),
        },
        classes={},
        instructions=[(7063984, 'sub sp, sp, 0x18'), (7064196, 'addseq r3, sl, r4, lsr r1')],
        calls=[],
        branches=[(7064044, 'blt', 7064164), (7064108, 'bgt', 7064156)],
        semantics=('[Donkey galloping] (imp 0x006bc9b0, 54w): the gallop state (2 branches).\n'),
    ),
    dict(
        name='d_maxvelocity',
        method='Donkey -[maxVelocity]',
        types='f8@0:4',
        start=7064200,
        end=7064280,
        disasm='disasm_worldtileloader_d_maxvelocity.txt',
        base_add=7064224,
        base_literal=7064276,
        boundary='ARM.exidx end 0x006bcad8 (listing bound); next ObjC IMP 0x006bcad8 Donkey -[setupMatrices:dt:]',
        selectors={},
        imports={},
        ivars={
                 0x6bcad0: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7064200, 'sub sp, sp, 8'), (7064276, 'addseq r3, sl, ip, asr 32')],
        calls=[],
        branches=[],
        semantics=('[Donkey maxVelocity] (imp 0x006bca88, 20w): the speed cap accessor.\n'),
    ),
    dict(
        name='d_setupmatrices_dt_',
        method='Donkey -[setupMatrices:dt:]',
        types='v20@0:4{Vector2=[2f]}8f16',
        start=7064280,
        end=7093564,
        disasm='disasm_worldtileloader_d_setupmatrices_dt_.txt',
        base_add=7064324,
        base_literal=7067316,
        boundary='ARM.exidx end 0x006c3d3c (listing bound); next ObjC IMP 0x006c4ba4 Donkey -[drawSubClassStuff:projectionMatrix:modelViewMatrix:]',
        selectors={
                 0x6bd6c0: (15203252, 'setupMatrices:dt:'),
                 0x6c00b4: (15203256, 'galloping'),
        },
        imports={
                 0x6c00b0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6bd6c4: (17158248, 'OBJC_IVAR_$_DonkeyLike.leftArmMatrix', 528),
                 0x6bd6cc: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
                 0x6bd6d0: (17158256, 'OBJC_IVAR_$_DonkeyLike.rightArmMatrix', 592),
                 0x6bd6d4: (17158260, 'OBJC_IVAR_$_DonkeyLike.leftLegMatrix', 656),
                 0x6bd6d8: (17158264, 'OBJC_IVAR_$_DonkeyLike.rightLegMatrix', 720),
                 0x6bd6dc: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6bd6e8: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0x6bd6ec: (17158268, 'OBJC_IVAR_$_Donkey.lastYPosForTailMovement', 1332),
                 0x6bd6f0: (17158272, 'OBJC_IVAR_$_Donkey.lastTailExtraRotation', 1336),
                 0x6bd6f8: (17158276, 'OBJC_IVAR_$_Donkey.lastTailExtraRotationB', 1340),
                 0x6bd6fc: (17158280, 'OBJC_IVAR_$_Donkey.lastTailExtraRotationC', 1344),
                 0x6bd704: (17158284, 'OBJC_IVAR_$_Donkey.tailMatrixA', 1072),
                 0x6bd708: (17158288, 'OBJC_IVAR_$_DonkeyLike.walkTimer', 264),
                 0x6bd718: (17158292, 'OBJC_IVAR_$_Donkey.tailMatrixB', 1136),
                 0x6befd4: (17158296, 'OBJC_IVAR_$_Donkey.tailMatrixC', 1200),
                 0x6befd8: (17158300, 'OBJC_IVAR_$_Donkey.tailMatrixD', 1264),
                 0x6beff0: (17158280, 'OBJC_IVAR_$_Donkey.lastTailExtraRotationC', 1344),
                 0x6beff4: (17158284, 'OBJC_IVAR_$_Donkey.tailMatrixA', 1072),
                 0x6beffc: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
                 0x6c00a4: (17158288, 'OBJC_IVAR_$_DonkeyLike.walkTimer', 264),
                 0x6c00a8: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0x6c00ac: (17158244, 'OBJC_IVAR_$_DonkeyLike.falling', 316),
                 0x6c00b8: (17158264, 'OBJC_IVAR_$_DonkeyLike.rightLegMatrix', 720),
                 0x6c00c0: (17158260, 'OBJC_IVAR_$_DonkeyLike.leftLegMatrix', 656),
                 0x6c00c4: (17158256, 'OBJC_IVAR_$_DonkeyLike.rightArmMatrix', 592),
                 0x6c00c8: (17158248, 'OBJC_IVAR_$_DonkeyLike.leftArmMatrix', 528),
                 0x6c1684: (17158304, 'OBJC_IVAR_$_DonkeyLike.munchMotionTimer', 796),
                 0x6c1688: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6c168c: (17158308, 'OBJC_IVAR_$_DonkeyLike.neckMatrix', 400),
                 0x6c1694: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
                 0x6c1698: (17158312, 'OBJC_IVAR_$_DonkeyLike.headDownFraction', 788),
                 0x6c169c: (17158316, 'OBJC_IVAR_$_DonkeyLike.headMatrix', 464),
                 0x6c2ea8: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x6c2eb0: (17158320, 'OBJC_IVAR_$_Donkey.leftEarMatrix', 848),
                 0x6c2eb8: (17158324, 'OBJC_IVAR_$_Donkey.rightEarMatrix', 912),
                 0x6c3d20: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6c3d24: (17158316, 'OBJC_IVAR_$_DonkeyLike.headMatrix', 464),
                 0x6c3d28: (17158320, 'OBJC_IVAR_$_Donkey.leftEarMatrix', 848),
                 0x6c3d2c: (17158324, 'OBJC_IVAR_$_Donkey.rightEarMatrix', 912),
                 0x6c3d34: (17158328, 'OBJC_IVAR_$_Donkey.hornMatrix', 992),
        },
        classes={
                 0x6bd6b8: (15252668, 'OBJC_CLASS_$_Donkey'),
        },
        instructions=[(7064280, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7093560, 'addseq ip, sb, r8, ror 7')],
        calls=[(7064460, 'bl loc.imp.objc_msgSendSuper2'), (7064984, 'bl 0x6c3d3c'), (7065580, 'bl 0x6c3d3c'), (7066176, 'bl 0x6c3d3c'), (7066760, 'bl 0x6c3d3c'), (7066832, 'bl sym.imp.memcpy'), (7066964, 'bl method.Vector2.operator_float__'), (7067500, 'bl method.Vector2.operator_float__'), (7068012, 'bl 0x6c3d3c'), (7068392, 'bl sym.imp.sinf'), (7068680, 'bl 0x6c3f24'), (7069304, 'bl 0x6c3d3c'), (7069704, 'bl sym.imp.sinf'), (7070008, 'bl 0x6c3f24'), (7070616, 'bl 0x6c3d3c'), (7071040, 'bl sym.imp.sinf'), (7071348, 'bl 0x6c3f24'), (7071872, 'bl 0x6c42bc'), (7072480, 'bl 0x6c3d3c'), (7072876, 'bl sym.imp.sinf'), (7073184, 'bl 0x6c3f24'), (7073712, 'bl 0x6c42bc'), (7073740, 'bl sym.imp.memcpy'), (7074288, 'bl 0x6c3d3c'), (7074648, 'bl sym.imp.sinf'), (7074904, 'bl 0x6c3f24'), (7074932, 'bl sym.imp.memcpy'), (7075080, 'blx r2'), (7075620, 'bl sym.imp.sinf'), (7075860, 'bl 0x6c3f24'), (7076220, 'bl sym.imp.sinf'), (7076456, 'bl 0x6c3f24'), (7077180, 'bl sym.imp.sinf'), (7077416, 'bl 0x6c3f24'), (7077780, 'bl sym.imp.sinf'), (7078016, 'bl 0x6c3f24'), (7078044, 'bl sym.imp.memcpy'), (7078652, 'bl sym.imp.sinf'), (7078892, 'bl 0x6c3f24'), (7079252, 'bl sym.imp.sinf'), (7079488, 'bl 0x6c3f24'), (7080168, 'bl sym.imp.sinf'), (7080404, 'bl 0x6c3f24'), (7080748, 'bl sym.imp.sinf'), (7080984, 'bl 0x6c3f24'), (7081012, 'bl sym.imp.memcpy'), (7081096, 'bl sym.imp.sinf'), (7081124, 'bl sym.imp.pow'), (7081724, 'bl 0x6c3d3c'), (7082364, 'bl 0x6c3f24'), (7082984, 'bl 0x6c3d3c'), (7083612, 'bl 0x6c3f24'), (7083644, 'bl sym.imp.memcpy'), (7084220, 'bl 0x6c3d3c'), (7084860, 'bl 0x6c3f24'), (7085476, 'bl 0x6c3d3c'), (7086104, 'bl 0x6c3f24'), (7086136, 'bl sym.imp.memcpy'), (7086608, 'bl 0x6c4654'), (7086640, 'bl sym.imp.memcpy'), (7087124, 'bl 0x6c3d3c'), (7087692, 'bl 0x6c3d3c'), (7087732, 'bl sym.imp.memcpy'), (7088188, 'bl 0x6c480c'), (7088712, 'bl 0x6c3f24'), (7089268, 'bl 0x6c480c'), (7089796, 'bl 0x6c3f24'), (7089824, 'bl sym.imp.memcpy'), (7090276, 'bl 0x6c480c'), (7090800, 'bl 0x6c3f24'), (7091356, 'bl 0x6c480c'), (7091884, 'bl 0x6c3f24'), (7091912, 'bl sym.imp.memcpy'), (7092428, 'bl 0x6c3d3c'), (7092968, 'bl 0x6c3f24'), (7093496, 'bl 0x6c42bc'), (7093524, 'bl sym.imp.memcpy')],
        branches=[(7066912, 'blt', 7073800), (7067016, 'bpl', 7067144), (7067292, 'bpl', 7067420), (7067312, 'b', 7067436), (7070724, 'b', 7070752), (7073744, 'b', 7074936), (7074992, 'bgt', 7075036), (7075032, 'beq', 7081020), (7075092, 'beq', 7078112), (7076584, 'b', 7076616), (7078048, 'b', 7081016), (7081016, 'b', 7081020), (7081188, 'blt', 7083720), (7081192, 'b', 7081224), (7083648, 'b', 7086164), (7086140, 'b', 7086164), (7086216, 'bpl', 7086644), (7087764, 'blt', 7089856), (7089828, 'b', 7091916), (7091952, 'blt', 7093528)],
        semantics=("[Donkey setupMatrices:dt:] (imp 0x006bcad8, 7321w): the animation engine - **`sinf` x14** (the gait/bob animation!) + **memcpy x12** (the matrix record copies) + the helpers 0x6c3f24 x22 / 0x6c3d3c x16 / 0x6c480c x4 / 0x6c42bc x3 + Vector float* x2 + super2 + the float pool 0xd70a/0xcccd/0x8f5c/0x851f/0x40/0x999a/0x6666/0x3333 (the phase/amplitude constants of the donkey's walk/run cycle); 40 ivars threaded.\n"),
    ),
    dict(
        name='d_drawsubclassstuff_projection',
        method='Donkey -[drawSubClassStuff:projectionMatrix:modelViewMatrix:]',
        types='v140@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76',
        start=7097252,
        end=7118816,
        disasm='disasm_worldtileloader_d_drawsubclassstuff_projection.txt',
        base_add=7097296,
        base_literal=7101384,
        boundary='ARM.exidx end 0x006c9fe0 (listing bound); next ObjC IMP 0x006ca8a0 Donkey -[createItemDropsForDeath]',
        selectors={
                 0x6c5bd8: (15203260, 'uniformLocations'),
                 0x6c5bdc: (15203264, 'objectAtIndex:'),
                 0x6c5be0: (15203268, 'intValue'),
                 0x6c5be8: (15203272, 'name'),
                 0x6c5bf0: (15203276, 'draw'),
                 0x6c6e88: (15203268, 'intValue'),
                 0x6c6e8c: (15203264, 'objectAtIndex:'),
                 0x6c6e90: (15203260, 'uniformLocations'),
                 0x6c6e9c: (15203272, 'name'),
                 0x6c6ea4: (15203276, 'draw'),
                 0x6c91d0: (15203260, 'uniformLocations'),
                 0x6c91d4: (15203264, 'objectAtIndex:'),
                 0x6c91d8: (15203268, 'intValue'),
                 0x6c91e0: (15203272, 'name'),
                 0x6c91e8: (15203276, 'draw'),
                 0x6c9f90: (15203276, 'draw'),
                 0x6c9f94: (15203268, 'intValue'),
                 0x6c9f98: (15203264, 'objectAtIndex:'),
                 0x6c9f9c: (15203260, 'uniformLocations'),
                 0x6c9fd0: (15203236, 'instance'),
                 0x6c9fdc: (15203280, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
        },
        imports={
                 0x6c5bf8: (17151904, 'objc_msgSend'),
                 0x6c5c08: (17151904, 'objc_msgSend'),
                 0x6c6e98: (17151904, 'objc_msgSend'),
                 0x6c9f8c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6c5bcc: (17158320, 'OBJC_IVAR_$_Donkey.leftEarMatrix', 848),
                 0x6c5bd4: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x6c5be4: (17158156, 'OBJC_IVAR_$_Donkey.earTexture', 840),
                 0x6c5bec: (17158208, 'OBJC_IVAR_$_Donkey.earCube', 844),
                 0x6c5bf4: (17158324, 'OBJC_IVAR_$_Donkey.rightEarMatrix', 912),
                 0x6c5bfc: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6c5c00: (17158328, 'OBJC_IVAR_$_Donkey.hornMatrix', 992),
                 0x6c6e94: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x6c6ea0: (17158176, 'OBJC_IVAR_$_Donkey.hornTexture', 976),
                 0x6c6ea8: (17158216, 'OBJC_IVAR_$_Donkey.hornCube', 980),
                 0x6c6eac: (17158284, 'OBJC_IVAR_$_Donkey.tailMatrixA', 1072),
                 0x6c6eb4: (17158168, 'OBJC_IVAR_$_DonkeyLike.neckTexture', 216),
                 0x6c6eb8: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6c6ebc: (17158192, 'OBJC_IVAR_$_Donkey.tailCubeA', 1056),
                 0x6c6ec0: (17158292, 'OBJC_IVAR_$_Donkey.tailMatrixB', 1136),
                 0x6c91cc: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x6c91dc: (17158168, 'OBJC_IVAR_$_DonkeyLike.neckTexture', 216),
                 0x6c91e4: (17158224, 'OBJC_IVAR_$_Donkey.tailCubeB', 1060),
                 0x6c91ec: (17158296, 'OBJC_IVAR_$_Donkey.tailMatrixC', 1200),
                 0x6c9c58: (17158220, 'OBJC_IVAR_$_Donkey.tailCubeC', 1064),
                 0x6c9c5c: (17158300, 'OBJC_IVAR_$_Donkey.tailMatrixD', 1264),
                 0x6c9f88: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6c9fa0: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x6c9fa4: (17158220, 'OBJC_IVAR_$_Donkey.tailCubeC', 1064),
                 0x6c9fa8: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0x6c9fac: (17158332, 'OBJC_IVAR_$_Donkey.emitTimer', 1328),
                 0x6c9fb4: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
        },
        classes={
                 0x6c9fc8: (15246244, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(7097252, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (7118812, 'invalid')],
        calls=[(7099072, 'bl 0x6c9fe0'), (7100188, 'bl 0x6c9fe0'), (7100240, 'bl loc.imp.objc_msgSend'), (7100276, 'bl loc.imp.objc_msgSend'), (7100300, 'bl loc.imp.objc_msgSend'), (7100320, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7100356, 'bl loc.imp.objc_msgSend'), (7100376, 'bl loc.imp.objc_msgSend'), (7100392, 'bl loc.imp.objc_msgSend'), (7100408, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7100448, 'bl loc.imp.objc_msgSend'), (7100468, 'bl sym.imp.__wrap_glBindTexture'), (7100508, 'bl loc.imp.objc_msgSend'), (7101652, 'bl 0x6c9fe0'), (7102824, 'bl 0x6c9fe0'), (7102996, 'bl sym.imp.memcpy'), (7103036, 'blx r3'), (7103056, 'blx r3'), (7103072, 'blx r2'), (7103104, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7103252, 'blx r3'), (7103272, 'blx r3'), (7103288, 'blx r2'), (7103320, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7103400, 'blx r3'), (7103420, 'bl sym.imp.__wrap_glBindTexture'), (7103492, 'blx r2'), (7104404, 'bl 0x6c9fe0'), (7105512, 'bl 0x6c9fe0'), (7105684, 'bl sym.imp.memcpy'), (7105724, 'blx r3'), (7105744, 'blx r3'), (7105760, 'blx r2'), (7105792, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7105940, 'blx r3'), (7105960, 'blx r3'), (7105976, 'blx r2'), (7106008, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7106088, 'blx r3'), (7106108, 'bl sym.imp.__wrap_glBindTexture'), (7106176, 'blx r2'), (7107120, 'bl 0x6c9fe0'), (7108224, 'bl 0x6c9fe0'), (7108384, 'bl sym.imp.memcpy'), (7108424, 'blx r3'), (7108444, 'blx r3'), (7108460, 'blx r2'), (7108492, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7108640, 'blx r3'), (7108660, 'blx r3'), (7108676, 'blx r2'), (7108708, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7108788, 'blx r3'), (7108808, 'bl sym.imp.__wrap_glBindTexture'), (7108880, 'blx r2'), (7109808, 'bl 0x6c9fe0'), (7110912, 'bl 0x6c9fe0'), (7111160, 'bl loc.imp.objc_msgSend'), (7111196, 'bl loc.imp.objc_msgSend'), (7111220, 'bl loc.imp.objc_msgSend'), (7111256, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7111292, 'bl loc.imp.objc_msgSend'), (7111320, 'bl loc.imp.objc_msgSend'), (7111336, 'bl loc.imp.objc_msgSend'), (7111368, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7111408, 'bl loc.imp.objc_msgSend'), (7111428, 'bl sym.imp.__wrap_glBindTexture'), (7111476, 'bl loc.imp.objc_msgSend'), (7112348, 'bl 0x6c9fe0'), (7113452, 'bl 0x6c9fe0'), (7113684, 'bl loc.imp.objc_msgSend'), (7113704, 'bl loc.imp.objc_msgSend'), (7113720, 'bl loc.imp.objc_msgSend'), (7113736, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7113772, 'bl loc.imp.objc_msgSend'), (7113792, 'bl loc.imp.objc_msgSend'), (7113808, 'bl loc.imp.objc_msgSend'), (7113824, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7113864, 'bl loc.imp.objc_msgSend'), (7114736, 'bl 0x6c9fe0'), (7115880, 'bl 0x6c9fe0'), (7116040, 'bl sym.imp.memcpy'), (7116080, 'blx r3'), (7116100, 'blx r3'), (7116116, 'blx r2'), (7116148, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7116296, 'blx r3'), (7116316, 'blx r3'), (7116332, 'blx r2'), (7116364, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (7116432, 'blx r2'), (7116956, 'bl 0x6ca854'), (7117224, 'bl 0x6ca5a0'), (7117260, 'bl method.Vector.Vector_float__float__float_'), (7117276, 'bl method.Vector.Vector__'), (7117332, 'bl 0x6ca890'), (7117456, 'bl sym.clamp_float__float__float_'), (7117572, 'bl sym.clamp_float__float__float_'), (7117688, 'bl sym.clamp_float__float__float_'), (7117816, 'bl sym.clamp_float__float__float_'), (7117864, 'bl method.Vector.Vector_float__float__float_'), (7117980, 'bl 0x6bc3ac'), (7118020, 'bl 0x6ca890'), (7118084, 'bl method.Vector.Vector_float__float__float_'), (7118128, 'bl method.Vector.operator_Vector_'), (7118200, 'bl loc.imp.objc_msgSend'), (7118208, 'bl 0x6ca890'), (7118248, 'bl 0x6ca890'), (7118300, 'bl method.Vector.Vector_float__float__float_'), (7118344, 'bl method.Vector.operator_Vector_'), (7118348, 'bl 0x6ca890'), (7118384, 'bl 0x6ca890'), (7118436, 'bl method.Vector.Vector_float__float__float_'), (7118476, 'bl 0x6ca890'), (7118704, 'bl loc.imp.objc_msgSend')],
        branches=[(7101380, 'b', 7101452), (7103524, 'blt', 7106248), (7106180, 'b', 7106248), (7108912, 'blt', 7116436), (7115208, 'b', 7115248), (7116472, 'blt', 7118716), (7116532, 'ble', 7118716), (7116684, 'ble', 7116712), (7116720, 'beq', 7118712), (7117320, 'bne', 7117936), (7117324, 'b', 7117332), (7117908, 'b', 7118168), (7118708, 'b', 7116632), (7118712, 'b', 7118716)],
        semantics=('[Donkey drawSubClassStuff:projectionMatrix:modelViewMatrix:] (imp 0x006c4ba4, 5391w): the render - objc x25 + **`glUniformMatrix4fv` x14** (the per-part matrices) + **`glBindTexture` x5** + the helpers 0x6c9fe0 x14 / 0x6ca890 x7 + Vector ctors (x5 three-float) + consts 0xde1 (the GL texture target GL_TEXTURE_2D!)/0xa; 27 ivars, 115 calls.\n'),
    ),
    dict(
        name='d_createitemdropsfordeath',
        method='Donkey -[createItemDropsForDeath]',
        types='v8@0:4',
        start=7121056,
        end=7122724,
        disasm='disasm_worldtileloader_d_createitemdropsfordeath.txt',
        base_add=7121072,
        base_literal=7122200,
        boundary='ARM.exidx end 0x006caf24 (listing bound); next ObjC IMP 0x006cad1c Donkey -[generateBreedForChild]',
        selectors={
                 0x6cace8: (15203284, 'expertMode'),
                 0x6cad0c: (15203288, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x6cace4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6cace0: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6cacec: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x6cacfc: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x6cad04: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x6cad08: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
                 0x6cada8: (17157280, 'OBJC_IVAR_$_NPC.hasBred', 100),
                 0x6cadac: (17157272, 'OBJC_IVAR_$_NPC.mateBreed', 98),
                 0x6cadb0: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6caf1c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7121056, 'push {fp, lr}'), (7122720, 'addseq r4, sb, r0, lsl 24')],
        calls=[(7121188, 'blx r2'), (7121204, 'bl 0x6ca890'), (7121244, 'bl 0x6ca890'), (7121480, 'bl loc.imp.objc_msgSend'), (7121576, 'blx r2'), (7121592, 'bl 0x6ca890'), (7121628, 'bl 0x6ca890'), (7121656, 'bl 0x6ca890'), (7121712, 'bl 0x6ca890'), (7121720, 'bl sym.imp.__modsi3'), (7121908, 'bl loc.imp.objc_msgSend'), (7122112, 'bl loc.imp.objc_msgSend'), (7122328, 'bl 0x6cadb8'), (7122412, 'bl 0x6ca890'), (7122532, 'bl 0x6ca890'), (7122576, 'bl 0x6cb3e0'), (7122704, 'bl sym.nameForDonkeyBreed_DonkeyBreed_')],
        branches=[(7121116, 'blt', 7121504), (7121200, 'beq', 7121244), (7121216, 'ble', 7121232), (7121228, 'b', 7121240), (7121240, 'b', 7121300), (7121320, 'bge', 7121500), (7121496, 'b', 7121308), (7121500, 'b', 7122136), (7121588, 'beq', 7121656), (7121604, 'ble', 7121620), (7121616, 'b', 7121628), (7121640, 'ble', 7121652), (7121652, 'b', 7121728), (7121748, 'bge', 7121928), (7121924, 'b', 7121736), (7121948, 'bge', 7122132), (7122128, 'b', 7121936), (7122132, 'b', 7122136), (7122396, 'bne', 7122412), (7122408, 'b', 7122636), (7122448, 'beq', 7122508), (7122472, 'ble', 7122488), (7122484, 'b', 7122496), (7122504, 'b', 7122636), (7122528, 'ble', 7122600), (7122568, 'bpl', 7122588), (7122584, 'b', 7122636), (7122596, 'b', 7122636), (7122608, 'bge', 7122628), (7122624, 'b', 7122636)],
        semantics=('[Donkey createItemDropsForDeath] (imp 0x006ca8a0, 417w): the death drops - the helper 0x6ca890 x8 + objc x3 + **`nameForDonkeyBreed(DonkeyBreed)`** (!) + `__modsi3` + consts 0x149 (329)/0x78 (120)/0x7f (127)/0x47 (71) (the drop item/quantity picks); 1 unclassified = the 0x3fffffff sentinel.\n'),
    ),
    dict(
        name='d_generatebreedforchild',
        method='Donkey -[generateBreedForChild]',
        types='i8@0:4',
        start=7122204,
        end=7122724,
        disasm='disasm_worldtileloader_d_generatebreedforchild.txt',
        base_add=7122220,
        base_literal=7122356,
        boundary='ARM.exidx end 0x006caf24 (listing bound); next ObjC IMP 0x006caedc Donkey -[breedString]',
        selectors={},
        imports={},
        ivars={
                 0x6cada8: (17157280, 'OBJC_IVAR_$_NPC.hasBred', 100),
                 0x6cadac: (17157272, 'OBJC_IVAR_$_NPC.mateBreed', 98),
                 0x6cadb0: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6caf1c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7122204, 'push {fp, lr}'), (7122720, 'addseq r4, sb, r0, lsl 24')],
        calls=[(7122328, 'bl 0x6cadb8'), (7122412, 'bl 0x6ca890'), (7122532, 'bl 0x6ca890'), (7122576, 'bl 0x6cb3e0'), (7122704, 'bl sym.nameForDonkeyBreed_DonkeyBreed_')],
        branches=[(7122396, 'bne', 7122412), (7122408, 'b', 7122636), (7122448, 'beq', 7122508), (7122472, 'ble', 7122488), (7122484, 'b', 7122496), (7122504, 'b', 7122636), (7122528, 'ble', 7122600), (7122568, 'bpl', 7122588), (7122584, 'b', 7122636), (7122596, 'b', 7122636), (7122608, 'bge', 7122628), (7122624, 'b', 7122636)],
        semantics=("[Donkey generateBreedForChild] (imp 0x006cad1c, 130w): the breeding - the same helper family (0x6ca890 x2/0x6cadb8/0x6cb3e0) + **`nameForDonkeyBreed`**: the child's breed is generated.\n"),
    ),
    dict(
        name='d_breedstring',
        method='Donkey -[breedString]',
        types='@8@0:4',
        start=7122652,
        end=7122724,
        disasm='disasm_worldtileloader_d_breedstring.txt',
        base_add=7122668,
        base_literal=7122720,
        boundary='ARM.exidx end 0x006caf24 (listing bound); next ObjC IMP 0x006cb018 Donkey -[blockheadCanRide:usingItem:]',
        selectors={},
        imports={},
        ivars={
                 0x6caf1c: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
        },
        classes={},
        instructions=[(7122652, 'push {fp, lr}'), (7122720, 'addseq r4, sb, r0, lsl 24')],
        calls=[(7122704, 'bl sym.nameForDonkeyBreed_DonkeyBreed_')],
        branches=[],
        semantics=('[Donkey breedString] (imp 0x006caedc, 18w): the breed string accessor.\n'),
    ),
    dict(
        name='d_blockheadcanride_usingitem_',
        method='Donkey -[blockheadCanRide:usingItem:]',
        types='c16@0:4@8i12',
        start=7122968,
        end=7123444,
        disasm='disasm_worldtileloader_d_blockheadcanride_usingitem_.txt',
        base_add=7122984,
        base_literal=7123440,
        boundary='ARM.exidx end 0x006cb1f4 (listing bound); next ObjC IMP 0x006cb1f4 Donkey -[.cxx_construct]',
        selectors={
                 0x6cb1dc: (15203292, 'tamed'),
                 0x6cb1e4: (15203296, 'belongsToPlayerWithBlockhead:'),
        },
        imports={
                 0x6cb1d8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x6cb1d0: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x6cb1d4: (17157392, 'OBJC_IVAR_$_NPC.beingControlled', 128),
                 0x6cb1e0: (17157296, 'OBJC_IVAR_$_NPC.breed', 96),
                 0x6cb1e8: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
                 0x6cb1ec: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
        },
        classes={},
        instructions=[(7122968, 'push {r4, r5, fp, lr}'), (7123440, 'addseq r4, sb, r4, asr 21')],
        calls=[(7123148, 'blx r2'), (7123268, 'blx r3')],
        branches=[(7123060, 'ble', 7123384), (7123104, 'bne', 7123384), (7123160, 'bne', 7123212), (7123172, 'bne', 7123212), (7123208, 'blt', 7123292), (7123288, 'beq', 7123384), (7123332, 'bne', 7123384)],
        semantics=('[Donkey blockheadCanRide:usingItem:] (imp 0x006cb018, 119w): the ride gate - const **0x384 (900)** (the same constant as the plant harvest family) with 7 branches (the ride conditions).\n'),
    ),
    dict(
        name='d_cxx_construct',
        method='Donkey -[.cxx_construct]',
        types='@8@0:4',
        start=7123444,
        end=7123468,
        disasm='disasm_worldtileloader_d_cxx_construct.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006cb20c (listing bound); next ObjC IMP 0x006cba34 Stairs -[isTransparent]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7123444, 'sub sp, sp, 8'), (7123464, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Donkey .cxx_construct] (imp 0x006cb1f4, 6w): empty C++ member ctor.\n'),
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
        'batch': 'Animals line opener (E96): the Donkey class - the animation engine, the render and the breed family; 25 bodies',
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
                        default=NATIVE / 'donkey.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale donkey.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
