#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The animals line: the Yak, the milkable shaveable animal: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 8563 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/YAK.md for the prose and boundaries.
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
    'bl 0x9621d8': 0x009621d8,
    'bl 0x9623c0': 0x009623c0,
    'bl 0x962758': 0x00962758,
    'bl 0x962910': 0x00962910,
    'bl 0x962ca8': 0x00962ca8,
    'bl 0x965290': 0x00965290,
    'bl 0x966378': 0x00966378,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.lrand48': 0x001c2804,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.pow': 0x001c3fec,
    'bl sym.imp.sinf': 0x001c2b34,
}

SPECS = [
    dict(
        name='y_00',
        method='Yak -[npcType]',
        types='i8@0:4',
        start=9816004,
        end=9816032,
        disasm='disasm_worldtileloader_y_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c7e0 (listing bound); next ObjC IMP 0x0095c7e0 Yak -[maxAge]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816004, 'sub sp, sp, 8'), (9816028, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak npcType] (imp 0x0095c7c4, 7w): the NPC type constant.\n'),
    ),
    dict(
        name='y_01',
        method='Yak -[maxAge]',
        types='f8@0:4',
        start=9816032,
        end=9816180,
        disasm='disasm_worldtileloader_y_01.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c874 (listing bound); next ObjC IMP 0x0095c810 Yak -[minFullness]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816032, 'sub sp, sp, 0x10'), (9816176, 'strbtmi r0, [r1], 0')],
        calls=[],
        branches=[],
        semantics=('[Yak maxAge] (imp 0x0095c7e0, 12w): the max age.\n'),
    ),
    dict(
        name='y_02',
        method='Yak -[minFullness]',
        types='f8@0:4',
        start=9816080,
        end=9816180,
        disasm='disasm_worldtileloader_y_02.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c874 (listing bound); next ObjC IMP 0x0095c844 Yak -[foodToRemoveWhenSpawningNPC]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816080, 'sub sp, sp, 0x10'), (9816176, 'strbtmi r0, [r1], 0')],
        calls=[],
        branches=[],
        semantics=('[Yak minFullness] (imp 0x0095c810, 13w): the fullness floor.\n'),
    ),
    dict(
        name='y_03',
        method='Yak -[foodToRemoveWhenSpawningNPC]',
        types='f8@0:4',
        start=9816132,
        end=9816180,
        disasm='disasm_worldtileloader_y_03.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c874 (listing bound); next ObjC IMP 0x0095c874 Yak -[foodPlantType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816132, 'sub sp, sp, 0x10'), (9816176, 'strbtmi r0, [r1], 0')],
        calls=[],
        branches=[],
        semantics=('[Yak foodToRemoveWhenSpawningNPC] (imp 0x0095c844, 12w): the spawn food cost.\n'),
    ),
    dict(
        name='y_04',
        method='Yak -[foodPlantType]',
        types='i8@0:4',
        start=9816180,
        end=9816340,
        disasm='disasm_worldtileloader_y_04.txt',
        base_add=9816216,
        base_literal=9816252,
        boundary='ARM.exidx end 0x0095c914 (listing bound); next ObjC IMP 0x0095c890 Yak -[speciesName]',
        selectors={},
        imports={
                 0x95c8b8: (16340584, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(9816180, 'sub sp, sp, 8'), (9816336, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak foodPlantType] (imp 0x0095c874, 7w): the food plant type.\n'),
    ),
    dict(
        name='y_05',
        method='Yak -[speciesName]',
        types='@8@0:4',
        start=9816208,
        end=9816340,
        disasm='disasm_worldtileloader_y_05.txt',
        base_add=9816216,
        base_literal=9816252,
        boundary='ARM.exidx end 0x0095c914 (listing bound); next ObjC IMP 0x0095c8c0 Yak -[foodItemType]',
        selectors={},
        imports={
                 0x95c8b8: (16340584, '__CFConstantStringClassReference'),
        },
        ivars={},
        classes={},
        instructions=[(9816208, 'sub sp, sp, 8'), (9816336, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak speciesName] (imp 0x0095c890, 12w): the species name.\n'),
    ),
    dict(
        name='y_06',
        method='Yak -[foodItemType]',
        types='i8@0:4',
        start=9816256,
        end=9816340,
        disasm='disasm_worldtileloader_y_06.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c914 (listing bound); next ObjC IMP 0x0095c8dc Yak -[capturedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816256, 'sub sp, sp, 8'), (9816336, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak foodItemType] (imp 0x0095c8c0, 7w): the food item.\n'),
    ),
    dict(
        name='y_07',
        method='Yak -[capturedItemType]',
        types='i8@0:4',
        start=9816284,
        end=9816340,
        disasm='disasm_worldtileloader_y_07.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c914 (listing bound); next ObjC IMP 0x0095c8f8 Yak -[captureRequiredItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816284, 'sub sp, sp, 8'), (9816336, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak capturedItemType] (imp 0x0095c8dc, 7w): the capture item.\n'),
    ),
    dict(
        name='y_08',
        method='Yak -[captureRequiredItemType]',
        types='i8@0:4',
        start=9816312,
        end=9816340,
        disasm='disasm_worldtileloader_y_08.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095c914 (listing bound); next ObjC IMP 0x0095c914 Yak -[setAdultCreationStartValues]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9816312, 'sub sp, sp, 8'), (9816336, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak captureRequiredItemType] (imp 0x0095c8f8, 7w): the required capture item.\n'),
    ),
    dict(
        name='y_09',
        method='Yak -[setAdultCreationStartValues]',
        types='v8@0:4',
        start=9816340,
        end=9816512,
        disasm='disasm_worldtileloader_y_09.txt',
        base_add=9816356,
        base_literal=9816508,
        boundary='ARM.exidx end 0x0095c9c0 (listing bound); next ObjC IMP 0x0095c9c0 Yak -[updateTextures]',
        selectors={
                 0x95c9ac: (15219688, 'setAdultCreationStartValues'),
        },
        imports={
                 0x95c9a8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x95c9b4: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
                 0x95c9b8: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={
                 0x95c9b0: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9816340, 'push {r4, sl, fp, lr}'), (9816508, 'rsbseq r3, r0, r8, asr 3')],
        calls=[(9816424, 'blx ip')],
        branches=[],
        semantics=('[Yak setAdultCreationStartValues] (imp 0x0095c914, 43w): the adult-start values.\n'),
    ),
    dict(
        name='y_10',
        method='Yak -[updateTextures]',
        types='v8@0:4',
        start=9816512,
        end=9817000,
        disasm='disasm_worldtileloader_y_10.txt',
        base_add=9816524,
        base_literal=9816996,
        boundary='ARM.exidx end 0x0095cba8 (listing bound); next ObjC IMP 0x0095cba8 Yak -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={
                 0x95cb78: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
                 0x95cb7c: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x95cb80: (17158160, 'OBJC_IVAR_$_DonkeyLike.legTexture', 224),
                 0x95cb84: (17163056, 'OBJC_IVAR_$_Yak.legsTextureShaved', 852),
                 0x95cb88: (17158172, 'OBJC_IVAR_$_DonkeyLike.bodyTexture', 212),
                 0x95cb8c: (17163060, 'OBJC_IVAR_$_Yak.bodyTextureShaved', 844),
                 0x95cb90: (17158212, 'OBJC_IVAR_$_DonkeyLike.bodyCube', 228),
                 0x95cb94: (17163064, 'OBJC_IVAR_$_Yak.bodyCubeShaved', 864),
                 0x95cb98: (17163068, 'OBJC_IVAR_$_Yak.legsTextureHairy', 856),
                 0x95cb9c: (17163072, 'OBJC_IVAR_$_Yak.bodyTextureHairy', 848),
                 0x95cba0: (17163076, 'OBJC_IVAR_$_Yak.bodyCubeHairy', 860),
        },
        classes={},
        instructions=[(9816512, 'push {r4, r5, fp, lr}'), (9816996, 'rsbseq r3, r0, r0, lsr 2')],
        calls=[],
        branches=[(9816584, 'bgt', 9816640), (9816636, 'bpl', 9816792), (9816788, 'b', 9816940)],
        semantics=('[Yak updateTextures] (imp 0x0095c9c0, 122w): the texture update (const 0x384).\n'),
    ),
    dict(
        name='y_11',
        method='Yak -[loadDerivedStuff]',
        types='v8@0:4',
        start=9817000,
        end=9819712,
        disasm='disasm_worldtileloader_y_11.txt',
        base_add=9817016,
        base_literal=9819708,
        boundary='ARM.exidx end 0x0095d640 (listing bound); next ObjC IMP 0x0095d640 Yak -[maxHealth]',
        selectors={
                 0x95d5a0: (15219692, 'loadDerivedStuff'),
                 0x95d5ac: (15219716, 'updateTextures'),
                 0x95d5b8: (15219712, 'multiSoundNamed:'),
                 0x95d5bc: (15219708, 'instance'),
                 0x95d5d8: (15219704, 'initWithWidth:height:depth:centerX:centerY:centerZ:calculateNormals:'),
                 0x95d5dc: (15219700, 'alloc'),
                 0x95d604: (15219696, 'textureNamed:'),
        },
        imports={
                 0x95d59c: (17151900, 'objc_msgSendSuper2'),
                 0x95d5a8: (17151904, 'objc_msgSend'),
                 0x95d5b4: (16340744, '__CFConstantStringClassReference'),
                 0x95d5c8: (16340728, '__CFConstantStringClassReference'),
                 0x95d5d0: (16340712, '__CFConstantStringClassReference'),
                 0x95d600: (16340696, '__CFConstantStringClassReference'),
                 0x95d610: (16340680, '__CFConstantStringClassReference'),
                 0x95d618: (16340664, '__CFConstantStringClassReference'),
                 0x95d620: (16340648, '__CFConstantStringClassReference'),
                 0x95d628: (16340632, '__CFConstantStringClassReference'),
                 0x95d630: (16340616, '__CFConstantStringClassReference'),
                 0x95d638: (16340600, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x95d5b0: (17158228, 'OBJC_IVAR_$_DonkeyLike.deathSound', 252),
                 0x95d5c4: (17158232, 'OBJC_IVAR_$_DonkeyLike.adultSound', 248),
                 0x95d5cc: (17158236, 'OBJC_IVAR_$_DonkeyLike.babySound', 244),
                 0x95d5d4: (17163080, 'OBJC_IVAR_$_Yak.hornCubeB', 872),
                 0x95d5e4: (17163084, 'OBJC_IVAR_$_Yak.hornCubeA', 868),
                 0x95d5e8: (17158196, 'OBJC_IVAR_$_DonkeyLike.legCube', 240),
                 0x95d5ec: (17158204, 'OBJC_IVAR_$_DonkeyLike.headCube', 236),
                 0x95d5f0: (17158200, 'OBJC_IVAR_$_DonkeyLike.neckCube', 232),
                 0x95d5f4: (17163064, 'OBJC_IVAR_$_Yak.bodyCubeShaved', 864),
                 0x95d5f8: (17163076, 'OBJC_IVAR_$_Yak.bodyCubeHairy', 860),
                 0x95d5fc: (17163088, 'OBJC_IVAR_$_Yak.hornTexture', 840),
                 0x95d608: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0x95d60c: (17158164, 'OBJC_IVAR_$_DonkeyLike.headTexture', 220),
                 0x95d614: (17158168, 'OBJC_IVAR_$_DonkeyLike.neckTexture', 216),
                 0x95d61c: (17163056, 'OBJC_IVAR_$_Yak.legsTextureShaved', 852),
                 0x95d624: (17163068, 'OBJC_IVAR_$_Yak.legsTextureHairy', 856),
                 0x95d62c: (17163060, 'OBJC_IVAR_$_Yak.bodyTextureShaved', 844),
                 0x95d634: (17163072, 'OBJC_IVAR_$_Yak.bodyTextureHairy', 848),
        },
        classes={
                 0x95d5a4: (15252940, 'OBJC_CLASS_$_Yak'),
                 0x95d5c0: (15248372, 'OBJC_CLASS_$_MJSoundManager'),
                 0x95d5e0: (15248368, 'OBJC_CLASS_$_DrawCube'),
        },
        instructions=[(9817000, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9819708, 'rsbseq r2, r0, r4, lsr pc')],
        calls=[(9817084, 'blx ip'), (9817904, 'blx r3'), (9817964, 'blx ip'), (9818024, 'blx ip'), (9818084, 'blx ip'), (9818144, 'blx ip'), (9818204, 'blx ip'), (9818320, 'blx ip'), (9818372, 'blx ip'), (9818464, 'blx lr'), (9818516, 'blx ip'), (9818604, 'blx lr'), (9818656, 'blx ip'), (9818740, 'blx lr'), (9818792, 'blx ip'), (9818876, 'blx lr'), (9818928, 'blx ip'), (9819008, 'blx lr'), (9819060, 'blx ip'), (9819144, 'blx lr'), (9819196, 'blx ip'), (9819280, 'blx lr'), (9819332, 'blx ip'), (9819352, 'blx r3'), (9819404, 'blx ip'), (9819424, 'blx r3'), (9819476, 'blx ip'), (9819496, 'blx r3'), (9819536, 'blx r3')],
        branches=[(9818240, 'b', 9818296)],
        semantics=("[Yak loadDerivedStuff] (imp 0x0095cba8, 678w): the derived loader (the yak's stats from the breed data).\n"),
    ),
    dict(
        name='y_12',
        method='Yak -[maxHealth]',
        types='S8@0:4',
        start=9819712,
        end=9819740,
        disasm='disasm_worldtileloader_y_12.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095d65c (listing bound); next ObjC IMP 0x0095d65c Yak -[dealloc]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9819712, 'sub sp, sp, 8'), (9819736, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak maxHealth] (imp 0x0095d640, 7w): the health cap.\n'),
    ),
    dict(
        name='y_13',
        method='Yak -[dealloc]',
        types='v8@0:4',
        start=9819740,
        end=9820264,
        disasm='disasm_worldtileloader_y_13.txt',
        base_add=9819756,
        base_literal=9820260,
        boundary='ARM.exidx end 0x0095d868 (listing bound); next ObjC IMP 0x0095d868 Yak -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        selectors={
                 0x95d838: (15219724, 'dealloc'),
                 0x95d844: (15219720, 'release'),
        },
        imports={
                 0x95d834: (17151900, 'objc_msgSendSuper2'),
                 0x95d840: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95d848: (17163080, 'OBJC_IVAR_$_Yak.hornCubeB', 872),
                 0x95d84c: (17163084, 'OBJC_IVAR_$_Yak.hornCubeA', 868),
                 0x95d850: (17158196, 'OBJC_IVAR_$_DonkeyLike.legCube', 240),
                 0x95d854: (17158204, 'OBJC_IVAR_$_DonkeyLike.headCube', 236),
                 0x95d858: (17158200, 'OBJC_IVAR_$_DonkeyLike.neckCube', 232),
                 0x95d85c: (17163064, 'OBJC_IVAR_$_Yak.bodyCubeShaved', 864),
                 0x95d860: (17163076, 'OBJC_IVAR_$_Yak.bodyCubeHairy', 860),
        },
        classes={
                 0x95d83c: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9819740, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9820260, 'rsbseq r2, r0, r0, lsl 9')],
        calls=[(9819944, 'blx r5'), (9819980, 'blx r3'), (9820016, 'blx r3'), (9820052, 'blx r3'), (9820088, 'blx r3'), (9820124, 'blx r3'), (9820160, 'blx r3'), (9820200, 'blx r2')],
        branches=[],
        semantics=('[Yak dealloc] (imp 0x0095d65c, 131w): the teardown.\n'),
    ),
    dict(
        name='y_14',
        method='Yak -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:]',
        types='@44@0:4@8@12{?=ii}16@24@28c32c36@40',
        start=9820264,
        end=9820900,
        disasm='disasm_worldtileloader_y_14.txt',
        base_add=9820280,
        base_literal=9820896,
        boundary='ARM.exidx end 0x0095dae4 (listing bound); next ObjC IMP 0x0095dae4 Yak -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0x95dabc: (15219728, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:'),
                 0x95dac8: (15219736, 'floatValue'),
                 0x95dad0: (15219732, 'objectForKey:'),
                 0x95dadc: (15219716, 'updateTextures'),
        },
        imports={
                 0x95dac4: (17151904, 'objc_msgSend'),
                 0x95dacc: (16340776, '__CFConstantStringClassReference'),
                 0x95dad8: (16340760, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x95dac0: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
                 0x95dad4: (17163092, 'OBJC_IVAR_$_Yak.milk', 1136),
        },
        classes={
                 0x95dab4: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9820264, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9820896, 'rsbseq r2, r0, r4, ror r2')],
        calls=[(9820508, 'bl loc.imp.objc_msgSendSuper2'), (9820680, 'blx r6'), (9820696, 'blx r2'), (9820744, 'blx r3'), (9820760, 'blx r2'), (9820828, 'blx r2')],
        branches=[(9820536, 'bne', 9820552), (9820548, 'b', 9820840), (9820564, 'beq', 9820788)],
        semantics=('[Yak initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:was...] (imp 0x0095d868, 159w): the placed ctor (super2).\n'),
    ),
    dict(
        name='y_15',
        method='Yak -[update:accurateDT:isSimulation:]',
        types='v20@0:4f8f12c16',
        start=9821436,
        end=9821924,
        disasm='disasm_worldtileloader_y_15.txt',
        base_add=9821452,
        base_literal=9821920,
        boundary='ARM.exidx end 0x0095dee4 (listing bound); next ObjC IMP 0x0095dee4 Yak -[getSaveDict]',
        selectors={
                 0x95dec0: (15219744, 'update:accurateDT:isSimulation:'),
                 0x95ded8: (15219716, 'updateTextures'),
        },
        imports={
                 0x95debc: (17151900, 'objc_msgSendSuper2'),
                 0x95ded4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95decc: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x95ded0: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
                 0x95dedc: (17163092, 'OBJC_IVAR_$_Yak.milk', 1136),
        },
        classes={
                 0x95dec4: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9821436, 'push {r4, r5, r6, r7, fp, lr}'), (9821920, 'rsbseq r1, r0, r0, ror 27')],
        calls=[(9821652, 'blx lr'), (9821872, 'blx r2')],
        branches=[(9821704, 'ble', 9821876), (9821716, 'beq', 9821760)],
        semantics=('[Yak update:accurateDT:isSimulation:] (imp 0x0095dcfc, 122w): the tick (const 0x384).\n'),
    ),
    dict(
        name='y_16',
        method='Yak -[yakUpdateNetDataForClient:]',
        types='{YakUpdateNetData={DonkeyLikeUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}sssCC}ss[4C]}12@0:4@8',
        start=9822376,
        end=9822832,
        disasm='disasm_worldtileloader_y_16.txt',
        base_add=9822392,
        base_literal=9822828,
        boundary='ARM.exidx end 0x0095e270 (listing bound); next ObjC IMP 0x0095e270 Yak -[creationNetDataForClient:]',
        selectors={
                 0x95e260: (15219760, 'donkeyLikeUpdateNetDataForClient:'),
        },
        imports={},
        ivars={
                 0x95e264: (17163092, 'OBJC_IVAR_$_Yak.milk', 1136),
                 0x95e268: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
        },
        classes={},
        instructions=[(9822376, 'push {r4, sl, fp, lr}'), (9822828, 'rsbseq r1, r0, r4, lsr sl')],
        calls=[(9822476, 'bl loc.imp.objc_msgSend_stret'), (9822512, 'bl sym.imp.memset'), (9822568, 'bl sym.imp.memcpy')],
        branches=[(9822456, 'beq', 9822484), (9822480, 'b', 9822516), (9822624, 'bpl', 9822644), (9822640, 'b', 9822652), (9822744, 'bpl', 9822764), (9822760, 'b', 9822772)],
        semantics=('[Yak yakUpdateNetDataForClient:] (imp 0x0095e0a8, 114w): the yak net update.\n'),
    ),
    dict(
        name='y_17',
        method='Yak -[creationNetDataForClient:]',
        types='@12@0:4@8',
        start=9822832,
        end=9823356,
        disasm='disasm_worldtileloader_y_17.txt',
        base_add=9822848,
        base_literal=9823352,
        boundary='ARM.exidx end 0x0095e47c (listing bound); next ObjC IMP 0x0095e47c Yak -[updateNetDataForClient:]',
        selectors={
                 0x95e460: (15219764, 'donkeyLikeCreationNetDataForClient:'),
                 0x95e464: (15219768, 'yakUpdateNetDataForClient:'),
                 0x95e46c: (15219776, 'appendNPCCreationDataToData:'),
                 0x95e470: (15219772, 'dataWithBytes:length:'),
        },
        imports={
                 0x95e468: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x95e474: (15248380, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(9822832, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9823352, 'rsbseq r1, r0, ip, ror 16')],
        calls=[(9822936, 'bl loc.imp.objc_msgSend_stret'), (9822972, 'bl sym.imp.memset'), (9823028, 'bl sym.imp.memcpy'), (9823100, 'bl loc.imp.objc_msgSend_stret'), (9823136, 'bl sym.imp.memset'), (9823240, 'bl sym.imp.memcpy'), (9823280, 'blx ip'), (9823308, 'blx r3')],
        branches=[(9822916, 'beq', 9822944), (9822940, 'b', 9822976), (9823080, 'beq', 9823108), (9823104, 'b', 9823140)],
        semantics=('[Yak creationNetDataForClient:] (imp 0x0095e270, 131w): the creation record.\n'),
    ),
    dict(
        name='y_18',
        method='Yak -[updateNetDataForClient:]',
        types='@12@0:4@8',
        start=9823356,
        end=9823592,
        disasm='disasm_worldtileloader_y_18.txt',
        base_add=9823372,
        base_literal=9823588,
        boundary='ARM.exidx end 0x0095e568 (listing bound); next ObjC IMP 0x0095e568 Yak -[doYakRemoteUpdate:]',
        selectors={
                 0x95e554: (15219768, 'yakUpdateNetDataForClient:'),
                 0x95e55c: (15219772, 'dataWithBytes:length:'),
        },
        imports={
                 0x95e558: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0x95e560: (15248380, 'OBJC_CLASS_$_NSData'),
        },
        instructions=[(9823356, 'push {fp, lr}'), (9823588, 'rsbseq r1, r0, r0, ror 12')],
        calls=[(9823452, 'bl loc.imp.objc_msgSend_stret'), (9823488, 'bl sym.imp.memset'), (9823552, 'blx ip')],
        branches=[(9823432, 'beq', 9823460), (9823456, 'b', 9823492)],
        semantics=('[Yak updateNetDataForClient:] (imp 0x0095e47c, 59w): the net update (stret + memset, const 0x28).\n'),
    ),
    dict(
        name='y_19',
        method='Yak -[doYakRemoteUpdate:]',
        types='v48@0:4{YakUpdateNetData={DonkeyLikeUpdateNetData={NPCUpdateNetData={DynamicObjectNetData=QIIC[7C]}}sssCC}ss[4C]}8',
        start=9823592,
        end=9823904,
        disasm='disasm_worldtileloader_y_19.txt',
        base_add=9823608,
        base_literal=9823900,
        boundary='ARM.exidx end 0x0095e6a0 (listing bound); next ObjC IMP 0x0095e6a0 Yak -[remoteUpdate:]',
        selectors={
                 0x95e698: (15219716, 'updateTextures'),
        },
        imports={
                 0x95e694: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x95e688: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x95e68c: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
                 0x95e690: (17163092, 'OBJC_IVAR_$_Yak.milk', 1136),
        },
        classes={},
        instructions=[(9823592, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9823900, 'rsbseq r1, r0, r4, ror r5')],
        calls=[(9823868, 'blx r2')],
        branches=[(9823748, 'beq', 9823828)],
        semantics=('[Yak doYakRemoteUpdate:] (imp 0x0095e568, 78w): the remote update.\n'),
    ),
    dict(
        name='y_20',
        method='Yak -[remoteUpdate:]',
        types='v12@0:4@8',
        start=9823904,
        end=9824308,
        disasm='disasm_worldtileloader_y_20.txt',
        base_add=9823920,
        base_literal=9824304,
        boundary='ARM.exidx end 0x0095e834 (listing bound); next ObjC IMP 0x0095e834 Yak -[remoteCreationDataUpdate:]',
        selectors={
                 0x95e818: (15219780, 'remoteUpdate:'),
                 0x95e824: (15219784, 'getBytes:length:'),
                 0x95e82c: (15219788, 'doYakRemoteUpdate:'),
        },
        imports={
                 0x95e814: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0x95e820: (17157324, 'OBJC_IVAR_$_NPC.dead', 56),
        },
        classes={
                 0x95e81c: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9823904, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9824304, 'rsbseq r1, r0, ip, lsr r4')],
        calls=[(9823996, 'blx lr'), (9824076, 'bl loc.imp.objc_msgSend'), (9824264, 'bl loc.imp.objc_msgSend')],
        branches=[(9824032, 'bne', 9824268)],
        semantics=('[Yak remoteUpdate:] (imp 0x0095e6a0, 101w): the net update forwarder.\n'),
    ),
    dict(
        name='y_21',
        method='Yak -[remoteCreationDataUpdate:]',
        types='v12@0:4@8',
        start=9824308,
        end=9824668,
        disasm='disasm_worldtileloader_y_21.txt',
        base_add=9824324,
        base_literal=9824664,
        boundary='ARM.exidx end 0x0095e99c (listing bound); next ObjC IMP 0x0095e99c Yak -[creationDataStructSize]',
        selectors={
                 0x95e984: (15219792, 'remoteCreationDataUpdate:'),
                 0x95e98c: (15219784, 'getBytes:length:'),
                 0x95e994: (15219788, 'doYakRemoteUpdate:'),
        },
        imports={
                 0x95e980: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0x95e988: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9824308, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9824664, 'rsbseq r1, r0, r8, lsr 5')],
        calls=[(9824396, 'blx lr'), (9824440, 'bl loc.imp.objc_msgSend'), (9824628, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[Yak remoteCreationDataUpdate] (imp 0x0095e834, 90w): the remote creation update.\n'),
    ),
    dict(
        name='y_22',
        method='Yak -[creationDataStructSize]',
        types='L8@0:4',
        start=9824668,
        end=9824696,
        disasm='disasm_worldtileloader_y_22.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x0095e9b8 (listing bound); next ObjC IMP 0x0095e9b8 Yak -[setupMatrices:dt:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9824668, 'sub sp, sp, 8'), (9824692, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak creationDataStructSize] (imp 0x0095e99c, 7w): the struct size constant.\n'),
    ),
    dict(
        name='y_23',
        method='Yak -[setupMatrices:dt:]',
        types='v20@0:4{Vector2=[2f]}8f16',
        start=9824696,
        end=9839064,
        disasm='disasm_worldtileloader_y_23.txt',
        base_add=9824744,
        base_literal=9824936,
        boundary='ARM.exidx end 0x009621d8 (listing bound); next ObjC IMP 0x00963040 Yak -[drawSubClassStuff:projectionMatrix:modelViewMatrix:]',
        selectors={
                 0x95eab4: (15219796, 'setupMatrices:dt:'),
        },
        imports={},
        ivars={
                 0x95eab8: (17158248, 'OBJC_IVAR_$_DonkeyLike.leftArmMatrix', 528),
                 0x95eac0: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
                 0x95eac4: (17158256, 'OBJC_IVAR_$_DonkeyLike.rightArmMatrix', 592),
                 0x95eac8: (17158260, 'OBJC_IVAR_$_DonkeyLike.leftLegMatrix', 656),
                 0x95eacc: (17158264, 'OBJC_IVAR_$_DonkeyLike.rightLegMatrix', 720),
                 0x95ead0: (17158240, 'OBJC_IVAR_$_DonkeyLike.actualXSpeed', 284),
                 0x95ead4: (17158244, 'OBJC_IVAR_$_DonkeyLike.falling', 316),
                 0x95eadc: (17158288, 'OBJC_IVAR_$_DonkeyLike.walkTimer', 264),
                 0x95fb58: (17158256, 'OBJC_IVAR_$_DonkeyLike.rightArmMatrix', 592),
                 0x95fb5c: (17158248, 'OBJC_IVAR_$_DonkeyLike.leftArmMatrix', 528),
                 0x95fb60: (17158304, 'OBJC_IVAR_$_DonkeyLike.munchMotionTimer', 796),
                 0x960518: (17158308, 'OBJC_IVAR_$_DonkeyLike.neckMatrix', 400),
                 0x96051c: (17158252, 'OBJC_IVAR_$_DonkeyLike.bodyMatrix', 336),
                 0x960528: (17158312, 'OBJC_IVAR_$_DonkeyLike.headDownFraction', 788),
                 0x960540: (17158316, 'OBJC_IVAR_$_DonkeyLike.headMatrix', 464),
                 0x960ae4: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x960aec: (17163096, 'OBJC_IVAR_$_Yak.leftHornMatrixA', 880),
                 0x9621cc: (17163100, 'OBJC_IVAR_$_Yak.rightHornMatrixA', 944),
                 0x9621d0: (17163104, 'OBJC_IVAR_$_Yak.leftHornMatrixB', 1008),
                 0x9621d4: (17163108, 'OBJC_IVAR_$_Yak.rightHornMatrixB', 1072),
        },
        classes={
                 0x95eaac: (15252940, 'OBJC_CLASS_$_Yak'),
        },
        instructions=[(9824696, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9839060, 'invalid')],
        calls=[(9824928, 'bl loc.imp.objc_msgSendSuper2'), (9825620, 'bl 0x9621d8'), (9826368, 'bl 0x9621d8'), (9826976, 'bl 0x9621d8'), (9827540, 'bl 0x9621d8'), (9827596, 'bl sym.imp.memcpy'), (9828228, 'bl sym.imp.sinf'), (9828464, 'bl 0x9623c0'), (9828816, 'bl sym.imp.sinf'), (9829048, 'bl 0x9623c0'), (9829764, 'bl sym.imp.sinf'), (9829996, 'bl 0x9623c0'), (9830332, 'bl sym.imp.sinf'), (9830564, 'bl 0x9623c0'), (9830592, 'bl sym.imp.memcpy'), (9830648, 'bl sym.imp.sinf'), (9830672, 'bl sym.imp.pow'), (9831176, 'bl 0x9621d8'), (9831852, 'bl 0x9623c0'), (9832448, 'bl 0x9621d8'), (9833056, 'bl 0x9623c0'), (9833112, 'bl sym.imp.memcpy'), (9833588, 'bl 0x962758'), (9833616, 'bl sym.imp.memcpy'), (9834112, 'bl 0x9621d8'), (9834632, 'bl 0x962910'), (9835140, 'bl 0x962ca8'), (9835744, 'bl 0x9621d8'), (9836264, 'bl 0x962910'), (9836772, 'bl 0x962ca8'), (9837368, 'bl 0x9621d8'), (9837888, 'bl 0x962910'), (9838484, 'bl 0x9621d8'), (9839012, 'bl 0x962910'), (9839040, 'bl sym.imp.memcpy')],
        branches=[(9824932, 'b', 9824992), (9827640, 'bgt', 9827684), (9827680, 'beq', 9830596), (9829184, 'b', 9829224), (9831688, 'b', 9831748), (9833152, 'bpl', 9833620), (9833156, 'b', 9833204)],
        semantics=("[Yak setupMatrices:dt:] (imp 0x0095e9b8, 4514w): the yak animation - **`sinf` x5 + `powf` x1** (!) + memcpy x5 + the helpers 0x9621d8 x10 / 0x9623c0 x6 / 0x962910 x4 / 0x962ca8 x2 + super2 + consts 0xcccd/0x8f5c/0x40/0x3f00/0x3f80 (1.0f)/0x384/0x3fc0/0x33: the yak's gait + the pow-curve part.\n"),
    ),
    dict(
        name='y_24',
        method='Yak -[drawSubClassStuff:projectionMatrix:modelViewMatrix:]',
        types='v140@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12(_GLKMatrix4={?=ffffffffffffffff}[16f])76',
        start=9842752,
        end=9851536,
        disasm='disasm_worldtileloader_y_24.txt',
        base_add=9842772,
        base_literal=9846860,
        boundary='ARM.exidx end 0x00965290 (listing bound); next ObjC IMP 0x00965850 Yak -[jumps]',
        selectors={
                 0x96405c: (15219800, 'uniformLocations'),
                 0x964060: (15219804, 'objectAtIndex:'),
                 0x964064: (15219808, 'intValue'),
                 0x96406c: (15219812, 'name'),
                 0x964074: (15219816, 'draw'),
                 0x965264: (15219816, 'draw'),
                 0x965268: (15219812, 'name'),
                 0x965270: (15219808, 'intValue'),
                 0x965274: (15219804, 'objectAtIndex:'),
                 0x965278: (15219800, 'uniformLocations'),
        },
        imports={
                 0x96407c: (17151904, 'objc_msgSend'),
                 0x965260: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x964050: (17163096, 'OBJC_IVAR_$_Yak.leftHornMatrixA', 880),
                 0x964058: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x964068: (17163088, 'OBJC_IVAR_$_Yak.hornTexture', 840),
                 0x964070: (17163084, 'OBJC_IVAR_$_Yak.hornCubeA', 868),
                 0x964078: (17163100, 'OBJC_IVAR_$_Yak.rightHornMatrixA', 944),
                 0x964084: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x96526c: (17163088, 'OBJC_IVAR_$_Yak.hornTexture', 840),
                 0x96527c: (17158188, 'OBJC_IVAR_$_DonkeyLike.shader', 208),
                 0x965280: (17163080, 'OBJC_IVAR_$_Yak.hornCubeB', 872),
                 0x965284: (17163104, 'OBJC_IVAR_$_Yak.leftHornMatrixB', 1008),
                 0x96528c: (17163108, 'OBJC_IVAR_$_Yak.rightHornMatrixB', 1072),
        },
        classes={},
        instructions=[(9842752, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9851532, 'invalid')],
        calls=[(9844008, 'bl 0x965290'), (9844712, 'bl 0x965290'), (9844760, 'bl loc.imp.objc_msgSend'), (9844796, 'bl loc.imp.objc_msgSend'), (9844820, 'bl loc.imp.objc_msgSend'), (9844840, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9844872, 'bl loc.imp.objc_msgSend'), (9844892, 'bl loc.imp.objc_msgSend'), (9844908, 'bl loc.imp.objc_msgSend'), (9844924, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9844960, 'bl loc.imp.objc_msgSend'), (9844980, 'bl sym.imp.__wrap_glBindTexture'), (9845016, 'bl loc.imp.objc_msgSend'), (9845736, 'bl 0x965290'), (9846564, 'bl 0x965290'), (9846720, 'bl sym.imp.memcpy'), (9846756, 'blx r3'), (9846776, 'blx r3'), (9846792, 'blx r2'), (9846824, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9847020, 'blx r3'), (9847040, 'blx r3'), (9847056, 'blx r2'), (9847088, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9847164, 'blx r3'), (9847184, 'bl sym.imp.__wrap_glBindTexture'), (9847272, 'blx r3'), (9848048, 'bl 0x965290'), (9848876, 'bl 0x965290'), (9849052, 'bl loc.imp.objc_msgSend'), (9849088, 'bl loc.imp.objc_msgSend'), (9849112, 'bl loc.imp.objc_msgSend'), (9849132, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9849164, 'bl loc.imp.objc_msgSend'), (9849184, 'bl loc.imp.objc_msgSend'), (9849200, 'bl loc.imp.objc_msgSend'), (9849216, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9849252, 'bl loc.imp.objc_msgSend'), (9849272, 'bl sym.imp.__wrap_glBindTexture'), (9849308, 'bl loc.imp.objc_msgSend'), (9850028, 'bl 0x965290'), (9850856, 'bl 0x965290'), (9851012, 'bl sym.imp.memcpy'), (9851048, 'blx r3'), (9851068, 'blx r3'), (9851084, 'blx r2'), (9851116, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9851248, 'blx r3'), (9851268, 'blx r3'), (9851284, 'blx r2'), (9851316, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (9851392, 'blx r3'), (9851412, 'bl sym.imp.__wrap_glBindTexture'), (9851476, 'blx r2')],
        branches=[(9846856, 'b', 9846920), (9847308, 'ble', 9851480)],
        semantics=('[Yak drawSubClassStuff:projectionMatrix:modelViewMatrix:] (imp 0x00963040, 2564w): the render - objc x16 + **`glUniformMatrix4fv` x8** + **`glBindTexture` x4** + memcpy x2 + the helper 0x965290 x8 + consts 0xde1 (GL_TEXTURE_2D)/0x384.\n'),
    ),
    dict(
        name='y_25',
        method='Yak -[jumps]',
        types='c8@0:4',
        start=9853008,
        end=9853108,
        disasm='disasm_worldtileloader_y_25.txt',
        base_add=9853016,
        base_literal=9853104,
        boundary='ARM.exidx end 0x009658b4 (listing bound); next ObjC IMP 0x009658b4 Yak -[canBeMilkedByBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x9658ac: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
        },
        classes={},
        instructions=[(9853008, 'sub sp, sp, 0xc'), (9853104, 'mlseq pc, r4, r2, sl')],
        calls=[],
        branches=[],
        semantics=('[Yak jumps] (imp 0x00965850, 25w): the jump flag.\n'),
    ),
    dict(
        name='y_26',
        method='Yak -[canBeMilkedByBlockhead:]',
        types='c12@0:4@8',
        start=9853108,
        end=9853292,
        disasm='disasm_worldtileloader_y_26.txt',
        base_add=9853120,
        base_literal=9853288,
        boundary='ARM.exidx end 0x0096596c (listing bound); next ObjC IMP 0x0096596c Yak -[milkByBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x965960: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x965964: (17163092, 'OBJC_IVAR_$_Yak.milk', 1136),
        },
        classes={},
        instructions=[(9853108, 'push {r4, lr}'), (9853288, 'rsbeq sl, pc, ip, lsr 4')],
        calls=[],
        branches=[(9853192, 'ble', 9853256)],
        semantics=('[Yak canBeMilkedByBlockhead:] (imp 0x009658b4, 46w): the milking gate (the 0x13f family).\n'),
    ),
    dict(
        name='y_27',
        method='Yak -[milkByBlockhead:]',
        types='c12@0:4@8',
        start=9853292,
        end=9853980,
        disasm='disasm_worldtileloader_y_27.txt',
        base_add=9853308,
        base_literal=9853976,
        boundary='ARM.exidx end 0x00965c1c (listing bound); next ObjC IMP 0x00965c1c Yak -[canBeShavedByBlockhead:]',
        selectors={
                 0x965bdc: (15219820, 'canBeMilkedByBlockhead:'),
                 0x965bf8: (15219828, 'objectType'),
                 0x965bfc: (15219832, 'dynamicWorldChangedAtPos:objectType:'),
                 0x965c00: (15219836, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x965c0c: (15219824, 'uniqueID'),
        },
        imports={
                 0x965bd8: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x965be0: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x965be4: (17163092, 'OBJC_IVAR_$_Yak.milk', 1136),
                 0x965bec: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x965bf0: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x965bf4: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x965c04: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x965c08: (17157356, 'OBJC_IVAR_$_NPC.harvestTypeToSend', 193),
                 0x965c14: (17157352, 'OBJC_IVAR_$_NPC.harvestBlockheadUniqueIDToSend', 184),
        },
        classes={},
        instructions=[(9853292, 'push {r4, r5, fp, lr}'), (9853976, 'rsbeq sl, pc, r0, ror r1')],
        calls=[(9853356, 'blx ip'), (9853484, 'bl loc.imp.objc_msgSend'), (9853720, 'bl loc.imp.objc_msgSend'), (9853756, 'bl loc.imp.objc_msgSend'), (9853876, 'bl loc.imp.objc_msgSend')],
        branches=[(9853368, 'beq', 9853892), (9853404, 'beq', 9853572), (9853568, 'b', 9853900), (9853888, 'b', 9853900)],
        semantics=('[Yak milkByBlockhead:] (imp 0x0096596c, 172w): the MILKING - const **0x13f (319) = the milk item code!** + objc x4 (the milk production interaction).\n'),
    ),
    dict(
        name='y_28',
        method='Yak -[canBeShavedByBlockhead:]',
        types='c12@0:4@8',
        start=9853980,
        end=9854164,
        disasm='disasm_worldtileloader_y_28.txt',
        base_add=9853992,
        base_literal=9854160,
        boundary='ARM.exidx end 0x00965cd4 (listing bound); next ObjC IMP 0x00965cd4 Yak -[shaveByBlockhead:]',
        selectors={},
        imports={},
        ivars={
                 0x965cc8: (17157256, 'OBJC_IVAR_$_NPC.age', 88),
                 0x965ccc: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
        },
        classes={},
        instructions=[(9853980, 'push {r4, lr}'), (9854160, 'rsbeq sb, pc, r4, asr 29')],
        calls=[],
        branches=[(9854064, 'ble', 9854128)],
        semantics=('[Yak canBeShavedByBlockhead:] (imp 0x00965c1c, 46w): the shaving gate.\n'),
    ),
    dict(
        name='y_29',
        method='Yak -[shaveByBlockhead:]',
        types='c12@0:4@8',
        start=9854164,
        end=9854896,
        disasm='disasm_worldtileloader_y_29.txt',
        base_add=9854180,
        base_literal=9854892,
        boundary='ARM.exidx end 0x00965fb0 (listing bound); next ObjC IMP 0x00965fb0 Yak -[createItemDropsForDeath]',
        selectors={
                 0x965f68: (15219840, 'canBeShavedByBlockhead:'),
                 0x965f8c: (15219828, 'objectType'),
                 0x965f90: (15219832, 'dynamicWorldChangedAtPos:objectType:'),
                 0x965f94: (15219836, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
                 0x965fa0: (15219824, 'uniqueID'),
        },
        imports={
                 0x965f64: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x965f6c: (17155520, 'OBJC_IVAR_$_DynamicObject.isNet', 52),
                 0x965f70: (17163052, 'OBJC_IVAR_$_Yak.hair', 1140),
                 0x965f78: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49),
                 0x965f7c: (17163064, 'OBJC_IVAR_$_Yak.bodyCubeShaved', 864),
                 0x965f80: (17158212, 'OBJC_IVAR_$_DonkeyLike.bodyCube', 228),
                 0x965f84: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x965f88: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x965f98: (17157388, 'OBJC_IVAR_$_DynamicObject.creationDataNeedsToBeSent', 50),
                 0x965f9c: (17157356, 'OBJC_IVAR_$_NPC.harvestTypeToSend', 193),
                 0x965fa8: (17157352, 'OBJC_IVAR_$_NPC.harvestBlockheadUniqueIDToSend', 184),
        },
        classes={},
        instructions=[(9854164, 'push {r4, r5, fp, lr}'), (9854892, 'rsbeq sb, pc, r8, lsl 28')],
        calls=[(9854228, 'blx ip'), (9854356, 'bl loc.imp.objc_msgSend'), (9854628, 'bl loc.imp.objc_msgSend'), (9854664, 'bl loc.imp.objc_msgSend'), (9854784, 'bl loc.imp.objc_msgSend')],
        branches=[(9854240, 'beq', 9854800), (9854276, 'beq', 9854444), (9854440, 'b', 9854808), (9854796, 'b', 9854808)],
        semantics=('[Yak shaveByBlockhead:] (imp 0x00965cd4, 183w): the SHAVING - const **0x143 (323) = the fur item code!** + objc x4 (the wool harvest interaction).\n'),
    ),
    dict(
        name='y_30',
        method='Yak -[createItemDropsForDeath]',
        types='v8@0:4',
        start=9854896,
        end=9855880,
        disasm='disasm_worldtileloader_y_30.txt',
        base_add=9854912,
        base_literal=9855860,
        boundary='ARM.exidx end 0x00966388 (listing bound); next ObjC IMP 0x00966388 Yak -[jumpsOnSwipe]',
        selectors={
                 0x966344: (15219844, 'expertMode'),
                 0x966368: (15219836, 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'),
        },
        imports={
                 0x966340: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x966348: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x966358: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x966360: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x966364: (17157336, 'OBJC_IVAR_$_NPC.killBlockhead', 60),
        },
        classes={},
        instructions=[(9854896, 'push {fp, lr}'), (9855876, 'pop {fp, pc}')],
        calls=[(9854984, 'blx r3'), (9855000, 'bl 0x966378'), (9855036, 'bl 0x966378'), (9855064, 'bl 0x966378'), (9855120, 'bl 0x966378'), (9855128, 'bl sym.imp.__modsi3'), (9855136, 'bl 0x966378'), (9855364, 'bl loc.imp.objc_msgSend'), (9855564, 'bl loc.imp.objc_msgSend'), (9855768, 'bl loc.imp.objc_msgSend'), (9855872, 'bl sym.imp.lrand48')],
        branches=[(9854996, 'beq', 9855064), (9855012, 'ble', 9855028), (9855024, 'b', 9855036), (9855048, 'ble', 9855060), (9855060, 'b', 9855136), (9855172, 'bpl', 9855184), (9855204, 'bge', 9855384), (9855380, 'b', 9855192), (9855404, 'bge', 9855584), (9855580, 'b', 9855392), (9855604, 'bge', 9855788), (9855784, 'b', 9855592)],
        semantics=('[Yak createItemDropsForDeath] (imp 0x00965fb0, 246w): the death drops - the helper 0x966378 x5 + objc x3 + `__modsi3` + **`lrand48`** (randomized quantity!) + consts 0x78 (120)/**0x141 (321 = the beef item!)**/0x7f (127)/0x136 (310); 1 unclassified = the 0x3fffffff sentinel.\n'),
    ),
    dict(
        name='y_31',
        method='Yak -[jumpsOnSwipe]',
        types='c8@0:4',
        start=9855880,
        end=9855932,
        disasm='disasm_worldtileloader_y_31.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009663bc (listing bound); next ObjC IMP 0x009663a4 Yak -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9855880, 'sub sp, sp, 8'), (9855928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak jumpsOnSwipe] (imp 0x00966388, 13w): the swipe-jump flag.\n'),
    ),
    dict(
        name='y_32',
        method='Yak -[.cxx_construct]',
        types='@8@0:4',
        start=9855908,
        end=9855932,
        disasm='disasm_worldtileloader_y_32.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009663bc (listing bound); next ObjC IMP 0x0096678c ScrollingButtonsPaint -[initWithFrame:cache:windowInfo:paintMixUI:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(9855908, 'sub sp, sp, 8'), (9855928, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Yak .cxx_construct] (imp 0x009663a4, 6w): empty C++ member ctor.\n'),
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
        'batch': 'Yak (E98): the milkable shaveable animal - the milk/fur codes, the powf animation, the drops; 33 bodies',
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
                        default=NATIVE / 'yak.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale yak.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
