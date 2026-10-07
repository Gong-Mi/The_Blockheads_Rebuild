#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the electric-lighting cluster (ArtificialLight/GlowBlock/WirePathCreator/ElevatorShaft): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 2390 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/ELECTRIC_LIGHTING.md for the prose and boundaries.
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
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.__tree_std::__1::__map_value_compare_int__int__std::__1::less_int___true__const_': 0x0072fb18,
    'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__': 0x0072fa7c,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_': 0x00a197b4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='al_ctor_color',
        method='ArtificialLight -[initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:]',
        types='@56@0:4@8@12{?=ii}16@24@28i32i36i40i44i48i52',
        start=11089732,
        end=11090876,
        disasm='disasm_worldtileloader_al_ctor_color.txt',
        base_add=11089748,
        base_literal=11090872,
        boundary='ARM.exidx end 0x00a93bbc (listing bound); next ObjC IMP 0x00a93bbc ArtificialLight -[lightColor]',
        selectors={
                 0xa93b68: (15226092, 'isClient'),
                 0xa93b78: (15226100, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xa93b7c: (15226104, 'addToTiles'),
                 0xa93bb4: (15226096, 'release'),
        },
        imports={
                 0xa93b64: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa93b6c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xa93b80: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa93b84: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa93b88: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa93b8c: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa93b90: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa93b94: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
                 0xa93b98: (17164860, 'OBJC_IVAR_$_ArtificialLight.parentObject', 100),
                 0xa93b9c: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa93ba4: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
                 0xa93ba8: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa93bac: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa93bb0: (17164856, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
        },
        classes={
                 0xa93b70: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11089732, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11089960, 'cmp r0, 0'), (11090140, 'bl loc.imp.objc_msgSendSuper2'), (11090364, 'str r4, [r5, r7]'), (11090872, 'invalid')],
        calls=[(11089952, 'blx r5'), (11090020, 'blx r3'), (11090140, 'bl loc.imp.objc_msgSendSuper2'), (11090464, 'bl sym.imp.__wrap_calloc'), (11090544, 'bl sym.imp.__wrap_calloc'), (11090700, 'bl sym.makeIntpair_int__int_'), (11090764, 'blx r2')],
        branches=[(11089964, 'beq', 11090036), (11090032, 'b', 11090776), (11090168, 'bne', 11090184), (11090180, 'b', 11090776)],
        semantics=("[ArtificialLight initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:] (imp 0x00a93744, 286w): the colored constructor - super2 chains into the dynamic-object init (@0xa938dc); the ivar-cell sweep writes the light's slots through the ffffef20..ffffef48 offset cells (@0xa93918-0xa939bc, the objc ivar idiom: `ldr r6,[ffffefXX cell]; str r4,[r5,r6]`); the early nil-arm (@0xa93828-0xa93870) returns nil after a ffe259fc check. COLOR-CHANNEL constants: 0x7f/0x5e/0x4c immediates appear in the sibling ctor; the radius/heat/lightDirection args ride the packed frame.\n"),
    ),
    dict(
        name='al_ctor_save',
        method='ArtificialLight -[initWithWorld:dynamicWorld:saveDict:cache:parentObject:]',
        types='@28@0:4@8@12@16@20@24',
        start=11091044,
        end=11092692,
        disasm='disasm_worldtileloader_al_ctor_save.txt',
        base_add=11091060,
        base_literal=11092688,
        boundary='ARM.exidx end 0x00a942d4 (listing bound); next ObjC IMP 0x00a942d4 ArtificialLight -[getSaveDict]',
        selectors={
                 0xa94258: (15226092, 'isClient'),
                 0xa94260: (15226108, 'initWithWorld:dynamicWorld:saveDict:cache:'),
                 0xa94268: (15226120, 'boolValue'),
                 0xa94270: (15226112, 'objectForKey:'),
                 0xa94278: (15226116, 'intValue'),
                 0xa942b8: (15226104, 'addToTiles'),
                 0xa942cc: (15226096, 'release'),
        },
        imports={
                 0xa94254: (17151904, 'objc_msgSend'),
                 0xa9425c: (17151900, 'objc_msgSendSuper2'),
                 0xa9426c: (16364216, '__CFConstantStringClassReference'),
                 0xa9427c: (16364200, '__CFConstantStringClassReference'),
                 0xa94284: (16364184, '__CFConstantStringClassReference'),
                 0xa94288: (16364168, '__CFConstantStringClassReference'),
                 0xa94290: (16364152, '__CFConstantStringClassReference'),
                 0xa94298: (16364136, '__CFConstantStringClassReference'),
                 0xa942a0: (16364120, '__CFConstantStringClassReference'),
                 0xa942a8: (16364104, '__CFConstantStringClassReference'),
                 0xa942b0: (16364088, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xa94274: (17164836, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
                 0xa94280: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa9428c: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa94294: (17164856, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
                 0xa9429c: (17164852, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
                 0xa942a4: (17164848, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
                 0xa942ac: (17164844, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
                 0xa942b4: (17164860, 'OBJC_IVAR_$_ArtificialLight.parentObject', 100),
                 0xa942bc: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa942c0: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa942c4: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={
                 0xa94264: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11091044, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11091308, 'blx ip'), (11091352, 'ldr r0, [0x00a94254]'), (11091668, 'add r0, r0, r1'), (11092688, 'subseq fp, ip, r8, ror lr')],
        calls=[(11091132, 'blx r6'), (11091200, 'blx r3'), (11091308, 'blx ip'), (11091732, 'blx lr'), (11091748, 'blx r2'), (11091792, 'blx r3'), (11091808, 'blx r2'), (11091852, 'blx r3'), (11091868, 'blx r2'), (11091912, 'blx r3'), (11091928, 'blx r2'), (11091972, 'blx r3'), (11091988, 'blx r2'), (11092032, 'blx r3'), (11092048, 'blx r2'), (11092092, 'blx r3'), (11092108, 'blx r2'), (11092152, 'blx r3'), (11092168, 'blx r2'), (11092212, 'blx r3'), (11092228, 'blx r2'), (11092392, 'bl sym.imp.__wrap_calloc'), (11092472, 'bl sym.imp.__wrap_calloc'), (11092540, 'blx r3')],
        branches=[(11091144, 'beq', 11091216), (11091212, 'b', 11092552), (11091336, 'bne', 11091352), (11091348, 'b', 11092552), (11092240, 'beq', 11092276)],
        semantics=("[ArtificialLight initWithWorld:dynamicWorld:saveDict:cache:parentObject:] (imp 0x00a93c64, 412w): the save-dict constructor - super2 chain (@0xa93d6c) then the **saveDict decode ladder** (@0xa93d98-0xa93ed4): a chain of `ldr rN,[ffffefXX cell]` + dataForKey-family calls (24 calls) walking the fff3b7XX string pool (ffffff74..fff3b7c4 = the save keys) to restore the light's color/heat/radius/position state; nil-arm on the ffe259fc check.\n"),
    ),
    dict(
        name='al_dealloc',
        method='ArtificialLight -[dealloc]',
        types='v8@0:4',
        start=11093932,
        end=11094168,
        disasm='disasm_worldtileloader_al_dealloc.txt',
        base_add=11093948,
        base_literal=11094164,
        boundary='ARM.exidx end 0x00a94898 (listing bound); next ObjC IMP 0x00a94898 ArtificialLight -[worldChanged:]',
        selectors={
                 0xa9487c: (15226140, 'dealloc'),
                 0xa94890: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa94878: (17151900, 'objc_msgSendSuper2'),
                 0xa9488c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa94884: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa94888: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={
                 0xa94880: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11093932, 'push {fp, lr}'), (11094024, 'bl sym.imp.__wrap_free'), (11094056, 'bl sym.imp.__wrap_free'), (11094124, 'blx r3'), (11094164, 'subseq fp, ip, r0, lsr r3')],
        calls=[(11094000, 'blx ip'), (11094024, 'bl sym.imp.__wrap_free'), (11094056, 'bl sym.imp.__wrap_free'), (11094124, 'blx r3')],
        branches=[],
        semantics=('[ArtificialLight dealloc] (imp 0x00a947ac, 59w): frees the two owned buffers via __wrap_free on the ffffef28 and ffffef34 ivar chains (@0xa94808/0xa94828) then the super2 dealloc.\n'),
    ),
    dict(
        name='al_worldchanged',
        method='ArtificialLight -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=11094168,
        end=11096476,
        disasm='disasm_worldtileloader_al_worldchanged.txt',
        base_add=11094184,
        base_literal=11096472,
        boundary='ARM.exidx end 0x00a9519c (listing bound); next ObjC IMP 0x00a9519c ArtificialLight -[removeFromMacroBlock]',
        selectors={
                 0xa95150: (15226064, 'worldWidthMacro'),
                 0xa9518c: (15226104, 'addToTiles'),
                 0xa95190: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa95188: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xa95144: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xa9514c: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xa95160: (17164832, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
                 0xa95174: (17164820, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
                 0xa95178: (17164824, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
                 0xa9517c: (17164840, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
                 0xa95180: (17164828, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
        },
        classes={},
        instructions=[(11094168, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11094592, 'bl sym.imp.__aeabi_idiv'), (11094604, 'blt 0xa94ac0'), (11096160, 'ldrsb r0, [fp, -0xa1]'), (11096472, 'subseq fp, ip, r4, asr 4')],
        calls=[(11094568, 'bl loc.imp.objc_msgSend'), (11094592, 'bl sym.imp.__aeabi_idiv'), (11094688, 'bl loc.imp.objc_msgSend'), (11094808, 'bl loc.imp.objc_msgSend'), (11094824, 'bl sym.imp.__aeabi_idiv'), (11094920, 'bl loc.imp.objc_msgSend'), (11095136, 'bl loc.imp.objc_msgSend'), (11095160, 'bl sym.imp.__aeabi_idiv'), (11095256, 'bl loc.imp.objc_msgSend'), (11095376, 'bl loc.imp.objc_msgSend'), (11095392, 'bl sym.imp.__aeabi_idiv'), (11095488, 'bl loc.imp.objc_msgSend'), (11095816, 'bl sym.makeIntpair_int__int_'), (11096264, 'bl loc.imp.objc_msgSend'), (11096356, 'bl sym.imp.memset'), (11096376, 'blx r2')],
        branches=[(11094448, 'beq', 11096160), (11094604, 'blt', 11094720), (11094716, 'b', 11095000), (11094836, 'bge', 11094952), (11094948, 'b', 11094992), (11095044, 'blt', 11096096), (11095172, 'blt', 11095288), (11095284, 'b', 11095568), (11095404, 'bge', 11095520), (11095516, 'b', 11095560), (11095604, 'bge', 11096096), (11095680, 'blt', 11096096), (11095748, 'bge', 11096096), (11095828, 'ble', 11096092), (11095868, 'bge', 11096092), (11095880, 'ble', 11096092), (11095920, 'bge', 11096092), (11096012, 'bne', 11096088), (11096072, 'ble', 11096088), (11096084, 'b', 11096160), (11096088, 'b', 11096092), (11096092, 'b', 11096096), (11096096, 'b', 11096100), (11096156, 'b', 11094296), (11096168, 'beq', 11096380)],
        semantics=('[ArtificialLight worldChanged:] (imp 0x00a94898, 577w): the macro-region change handler - the pos is macro-mapped with the `lsl r0, r0, 5` (<<5 == *32) + __aeabi_idiv idiom (@0xa94a30-0xa94a40) against the world dims (ffe259dc family), the two-sided range compare (blt @0xa94a4c) and the per-macro re-registration walk; the light contributes/reloads through the ffffffXX ivar cells.\n'),
    ),
    dict(
        name='al_rmmacro',
        method='ArtificialLight -[removeFromMacroBlock]',
        types='v8@0:4',
        start=11096476,
        end=11096648,
        disasm='disasm_worldtileloader_al_rmmacro.txt',
        base_add=11096492,
        base_literal=11096644,
        boundary='ARM.exidx end 0x00a95248 (listing bound); next ObjC IMP 0x00a95248 ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={
                 0xa95234: (15226144, 'removeFromMacroBlock'),
                 0xa95240: (15226136, 'removeFromTiles'),
        },
        imports={
                 0xa95230: (17151900, 'objc_msgSendSuper2'),
                 0xa9523c: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xa95238: (15253064, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(11096476, 'push {r4, r5, r6, sl, fp, lr}'), (11096552, 'ldr r1, [r2]'), (11096612, 'blx r2'), (11096644, 'subseq sl, ip, r0, asr 18')],
        calls=[(11096572, 'blx r5'), (11096612, 'blx r2')],
        branches=[],
        semantics=('[ArtificialLight removeFromMacroBlock] (imp 0x00a9519c, 43w): the idempotent unlink - the ffe25a2c/ffe2c354/ffe25a24 chain call (@0xa951e8-0xa95224) removes the light from its macro block.\n'),
    ),
    dict(
        name='al_cxx_construct',
        method='ArtificialLight -[.cxx_construct]',
        types='@8@0:4',
        start=11098300,
        end=11098324,
        disasm='disasm_worldtileloader_al_cxx_construct.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a958d4 (listing bound); next ObjC IMP 0x00a95bd8 OrangeTree -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11098300, 'sub sp, sp, 8'), (11098320, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ArtificialLight .cxx_construct] (imp 0x00a958bc, 6w): empty body (the light has no C++ container members).\n'),
    ),
    dict(
        name='gb_initsubderived',
        method='GlowBlock -[initSubDerivedItems]',
        types='v8@0:4',
        start=13271812,
        end=13271860,
        disasm='disasm_worldtileloader_gb_initsubderived.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00ca8334 (listing bound); next ObjC IMP 0x00ca8318 GlowBlock -[objectType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13271812, 'sub sp, sp, 8'), (13271856, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[GlowBlock initSubDerivedItems] (imp 0x00ca8304, 12w): empty body; the listing tail belongs to the adjacent 0x12-returning getter (next function).\n'),
    ),
    dict(
        name='gb_ctor',
        method='GlowBlock -[initWithWorld:dynamicWorld:atPosition:cache:tile:]',
        types='@32@0:4@8@12{?=ii}16@24^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}28',
        start=13272020,
        end=13273376,
        disasm='disasm_worldtileloader_gb_ctor.txt',
        base_add=13272036,
        base_literal=13273372,
        boundary='ARM.exidx end 0x00ca8920 (listing bound); next ObjC IMP 0x00ca8920 GlowBlock -[initWithWorld:dynamicWorld:saveDict:cache:]',
        selectors={
                 0xca88e4: (15235864, 'initWithWorld:dynamicWorld:atPosition:cache:'),
                 0xca88f0: (15235880, 'initSubDerivedItems'),
                 0xca88fc: (15235868, 'alloc'),
                 0xca8910: (15235872, 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'),
                 0xca8918: (15235876, 'macroTiles'),
        },
        imports={
                 0xca88ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca88e8: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
                 0xca8900: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0xca8904: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0xca8908: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca890c: (17154988, 'OBJC_IVAR_$_DynamicObject.cache', 32),
                 0xca8914: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={
                 0xca88dc: (15253216, 'OBJC_CLASS_$_GlowBlock'),
                 0xca88f4: (15250844, 'OBJC_CLASS_$_ArtificialLight'),
        },
        instructions=[(13272020, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13272204, 'bl loc.imp.objc_msgSendSuper2'), (13272336, 'beq 0xca8710'), (13272424, 'bne 0xca8588'), (13272452, 'b 0xca870c'), (13273372, 'eorseq r7, fp, r8, lsl 14')],
        calls=[(13272204, 'bl loc.imp.objc_msgSendSuper2'), (13272880, 'bl loc.imp.objc_msgSend'), (13273116, 'bl loc.imp.objc_msgSend'), (13273196, 'bl loc.imp.objc_msgSend'), (13273240, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13273284, 'blx r2')],
        branches=[(13272232, 'bne', 13272248), (13272244, 'b', 13273296), (13272336, 'beq', 13272848), (13272372, 'beq', 13272848), (13272408, 'beq', 13272428), (13272424, 'bne', 13272456), (13272452, 'b', 13272844), (13272488, 'bne', 13272520), (13272516, 'b', 13272840), (13272552, 'bne', 13272580), (13272576, 'b', 13272836), (13272612, 'bne', 13272640), (13272636, 'b', 13272832), (13272672, 'bne', 13272700), (13272696, 'b', 13272828), (13272732, 'bne', 13272760), (13272756, 'b', 13272824), (13272792, 'bne', 13272820), (13272820, 'b', 13272824), (13272824, 'b', 13272828), (13272828, 'b', 13272832), (13272832, 'b', 13272836), (13272836, 'b', 13272840), (13272840, 'b', 13272844), (13272844, 'b', 13272848)],
        semantics=("[GlowBlock initWithWorld:dynamicWorld:atPosition:cache:tile:] (imp 0x00ca83d4, 339w): the tile-driven glow-block constructor - super2 (@0xca848c) then the TILE-STATE MACHINE: the tile byte compared against 0x10 and 0x19 (@0xca8508-0xca8534, the two glow-carrying tile kinds) and 0x1a with the byte[+3]==0x4d ('M') marker (@0xca8554-0xca8568); arm constants (8, 0x39, 0x3f) select the glow color/tier; the fffff968/ffe28024 cells carry the block refs.\n"),
    ),
    dict(
        name='gb_dealloc',
        method='GlowBlock -[dealloc]',
        types='v8@0:4',
        start=13274724,
        end=13274956,
        disasm='disasm_worldtileloader_gb_dealloc.txt',
        base_add=13274740,
        base_literal=13274952,
        boundary='ARM.exidx end 0x00ca8f4c (listing bound); next ObjC IMP 0x00ca8f4c GlowBlock -[removeFromMacroBlock]',
        selectors={
                 0xca8f34: (15235916, 'dealloc'),
                 0xca8f44: (15235912, 'release'),
        },
        imports={
                 0xca8f30: (17151900, 'objc_msgSendSuper2'),
                 0xca8f40: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca8f3c: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={
                 0xca8f38: (15253216, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(13274724, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13274852, 'blx r7'), (13274916, 'blx ip'), (13274952, 'eorseq r6, fp, r8, ror ip')],
        calls=[(13274852, 'blx r7'), (13274916, 'blx ip')],
        branches=[],
        semantics=('[GlowBlock dealloc] (imp 0x00ca8e64, 58w): the fffff968 ivar-chain unlink via the ffe28058/ffe28054 calls (@0xca8ee4-0xca8f24) then the super2 dealloc.\n'),
    ),
    dict(
        name='gb_rmmacro',
        method='GlowBlock -[removeFromMacroBlock]',
        types='v8@0:4',
        start=13274956,
        end=13275324,
        disasm='disasm_worldtileloader_gb_rmmacro.txt',
        base_add=13274972,
        base_literal=13275320,
        boundary='ARM.exidx end 0x00ca90bc (listing bound); next ObjC IMP 0x00ca90bc GlowBlock -[worldChanged:]',
        selectors={
                 0xca9098: (15235920, 'removeFromMacroBlock'),
                 0xca90a8: (15235912, 'release'),
                 0xca90b4: (15235876, 'macroTiles'),
        },
        imports={
                 0xca9094: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xca90a0: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca90ac: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca90b0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xca909c: (15253216, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(13274956, 'push {fp, lr}'), (13275204, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13275232, 'ldr ip, [0x00ca909c]'), (13275320, 'mlaseq fp, r0, fp, r6')],
        calls=[(13275036, 'bl loc.imp.objc_msgSend'), (13275068, 'bl loc.imp.objc_msgSend'), (13275160, 'bl loc.imp.objc_msgSend'), (13275204, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13275272, 'blx r3')],
        branches=[],
        semantics=("[GlowBlock removeFromMacroBlock] (imp 0x00ca8f4c, 92w): unlink then **reloadDrawBlockLightGlowQuadsForTile(intpair, MacroTile*, World*)** (@0xca9044, C symbol) - the glow-block removal invalidates the tile's light-glow quads; the ffe2805c/ffe28054/ffe28030 chain runs first.\n"),
    ),
    dict(
        name='gb_worldchanged',
        method='GlowBlock -[worldChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=13275324,
        end=13276076,
        disasm='disasm_worldtileloader_gb_worldchanged.txt',
        base_add=13275340,
        base_literal=13276072,
        boundary='ARM.exidx end 0x00ca93ac (listing bound); next ObjC IMP 0x00ca93ac GlowBlock -[setNeedsRemoved:]',
        selectors={
                 0xca9390: (15235924, 'worldChanged:'),
                 0xca93a4: (15235928, 'setNeedsRemoved:'),
        },
        imports={
                 0xca938c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca9394: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca9398: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca939c: (17167456, 'OBJC_IVAR_$_GlowBlock.tileType', 60),
                 0xca93a0: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={},
        instructions=[(13275324, 'push {r4, r5, r6, sl, fp, lr}'), (13275424, 'blx r4'), (13275732, 'cmp r2, r0'), (13276036, 'sub sp, fp, 0x10'), (13276072, 'eorseq r6, fp, r0, lsr 20')],
        calls=[(13275424, 'blx r4'), (13275852, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (13275964, 'blx ip')],
        branches=[(13275664, 'beq', 13276036), (13275736, 'bne', 13275972), (13275776, 'bne', 13275972), (13275900, 'beq', 13275968), (13275968, 'b', 13276036), (13275972, 'b', 13275976), (13276032, 'b', 13275512)],
        semantics=('[GlowBlock worldChanged:] (imp 0x00ca90bc, 188w): the packed-tile change walk - the fffe28060/fffff968 chain reads the tile pair (@0xca9120) and the containment guards (@0xca9254-0xca9280: begin/end checks against the ffffc89c/ffffc8a0 world slots) drive the per-tile update.\n'),
    ),
    dict(
        name='gb_setneedsremoved',
        method='GlowBlock -[setNeedsRemoved:]',
        types='v12@0:4c8',
        start=13276076,
        end=13276416,
        disasm='disasm_worldtileloader_gb_setneedsremoved.txt',
        base_add=13276092,
        base_literal=13276412,
        boundary='ARM.exidx end 0x00ca9500 (listing bound); next ObjC IMP 0x00ca9500 GlowBlock -[lightGlowQuadCount]',
        selectors={
                 0xca94dc: (15235928, 'setNeedsRemoved:'),
                 0xca94ec: (15235932, 'removeFromTiles'),
                 0xca94f8: (15235876, 'macroTiles'),
        },
        imports={
                 0xca94d8: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={
                 0xca94e4: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
                 0xca94f0: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0xca94f4: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
        },
        classes={
                 0xca94e0: (15253216, 'OBJC_CLASS_$_GlowBlock'),
        },
        instructions=[(13276076, 'push {r4, r5, fp, lr}'), (13276200, 'beq 0xca94d0'), (13276364, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_'), (13276412, 'eorseq r6, fp, r0, lsr r7')],
        calls=[(13276188, 'blx lr'), (13276244, 'bl loc.imp.objc_msgSend'), (13276320, 'bl loc.imp.objc_msgSend'), (13276364, 'bl sym.reloadDrawBlockLightGlowQuadsForTile_intpair__MacroTile__World_')],
        branches=[(13276200, 'beq', 13276368)],
        semantics=('[GlowBlock setNeedsRemoved:] (imp 0x00ca93ac, 85w): the sxtb-gated removal - on the non-zero flag (@0xca9424-0xca9428) the fffff968/ffe28068/ffe28030 chain runs and **reloadDrawBlockLightGlowQuadsForTile** (@0xca94cc) invalidates the quads.\n'),
    ),
    dict(
        name='gb_addlightcont',
        method='GlowBlock -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        types='v16@0:4i8i12',
        start=13276684,
        end=13276800,
        disasm='disasm_worldtileloader_gb_addlightcont.txt',
        base_add=13276700,
        base_literal=13276796,
        boundary='ARM.exidx end 0x00ca9680 (listing bound); next ObjC IMP 0x00ca97ac BHMatch -[localPlayerID]',
        selectors={
                 0xca9674: (15235936, 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'),
        },
        imports={
                 0xca9670: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xca9678: (17167452, 'OBJC_IVAR_$_GlowBlock.light', 56),
        },
        classes={},
        instructions=[(13276684, 'push {r4, r5, fp, lr}'), (13276772, 'blx lr'), (13276796, 'ldrsbteq r6, [fp], -r0')],
        calls=[(13276772, 'blx lr')],
        branches=[],
        semantics=('[GlowBlock addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:] (imp 0x00ca960c, 29w): thin forwarder - the fffff968/ffe2806c chain call (@0xca9664 blx) hands the light contribution to the block; the glow block is an artificial-light contributor (the electricity lighting contract).\n'),
    ),
    dict(
        name='wpc_cxx_destruct',
        method='WirePathCreator -[.cxx_destruct]',
        types='v8@0:4',
        start=14373972,
        end=14374404,
        disasm='disasm_worldtileloader_wpc_cxx_destruct.txt',
        base_add=14373988,
        base_literal=14374040,
        boundary='ARM.exidx end 0x00db5604 (listing bound); next ObjC IMP 0x00db549c WirePathCreator -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0xdb5494: (17169132, 'OBJC_IVAR_$_WirePathCreator.derivedTileIndices', 28),
                 0xdb5500: (17169132, 'OBJC_IVAR_$_WirePathCreator.derivedTileIndices', 28),
        },
        classes={},
        instructions=[(14373972, 'push {fp, lr}'), (14374020, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__'), (14374400, 'cmnmi pc, 0')],
        calls=[(14374020, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____._map__'), (14374120, 'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.__tree_std::__1::__map_value_compare_int__int__std::__1::less_int___true__const_'), (14374236, 'bl sym.clamp_float__float__float_'), (14374280, 'bl sym.clamp_float__float__float_'), (14374324, 'bl sym.clamp_float__float__float_'), (14374368, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=('[WirePathCreator .cxx_destruct] (imp 0x00db5454, 108w): the member destructor - `~std::__1::map<int, int>()` on the fffffff8 member (@0xdb5484) - the wire path creator owns an int->int map (the wire routing table).\n'),
    ),
    dict(
        name='wpc_cxx_construct',
        method='WirePathCreator -[.cxx_construct]',
        types='@8@0:4',
        start=14374044,
        end=14374404,
        disasm='disasm_worldtileloader_wpc_cxx_construct.txt',
        base_add=14374060,
        base_literal=14374148,
        boundary='ARM.exidx end 0x00db5604 (listing bound); next ObjC IMP 0x00db5668 MapleTree -[objectType]',
        selectors={},
        imports={},
        ivars={
                 0xdb5500: (17169132, 'OBJC_IVAR_$_WirePathCreator.derivedTileIndices', 28),
        },
        classes={},
        instructions=[(14374044, 'push {fp, lr}'), (14374120, 'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.__tree_std::__1::__map_value_compare_int__int__std::__1::less_int___true__const_'), (14374400, 'cmnmi pc, 0')],
        calls=[(14374120, 'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.__tree_std::__1::__map_value_compare_int__int__std::__1::less_int___true__const_'), (14374236, 'bl sym.clamp_float__float__float_'), (14374280, 'bl sym.clamp_float__float__float_'), (14374324, 'bl sym.clamp_float__float__float_'), (14374368, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=("[WirePathCreator .cxx_construct] (imp 0x00db549c, 90w): the member constructor - the `std::__1::__tree` map ctor on the fffffff8 member (@0xdb54e8) - the routing map's ctor.\n"),
    ),
    dict(
        name='es_cxx_construct',
        method='ElevatorShaft -[.cxx_construct]',
        types='@8@0:4',
        start=13309348,
        end=13309372,
        disasm='disasm_worldtileloader_es_cxx_construct.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00cb15bc (listing bound); next ObjC IMP 0x00cb1d64 SFHFKeychainUtils -[getPasswordForUsername:andServiceName:error:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13309348, 'sub sp, sp, 8'), (13309368, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ElevatorShaft .cxx_construct] (imp 0x00cb15a4, 6w): empty body (no C++ container members).\n'),
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
        'batch': 'Electric lighting cluster (E68): ArtificialLight (6), GlowBlock (7), WirePathCreator (2) and ElevatorShaft (.cxx_construct); 16 bodies',
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
                        default=NATIVE / 'electric_lighting.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale electric_lighting.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
