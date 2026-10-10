#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the Workbench tail closure: the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 2324 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WORKBENCH_TAIL.md for the prose and boundaries.
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
    'bl 0xae3538': 0x00ae3538,
    'bl 0xae3574': 0x00ae3574,
    'bl 0xafd54c': 0x00afd54c,
    'bl 0xb01800': 0x00b01800,
    'bl 0xb018f8': 0x00b018f8,
    'bl 0xb0b8fc': 0x00b0b8fc,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.operator_Vector2_': 0x004d0418,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
}

SPECS = [
    dict(
        name='wt_destroyitem',
        method='Workbench -[destroyItemType]',
        types='i8@0:4',
        start=11542864,
        end=11543084,
        disasm='disasm_worldtileloader_wt_destroyitem.txt',
        base_add=11542880,
        base_literal=11542960,
        boundary='ARM.exidx end 0x00b0222c (listing bound); next ObjC IMP 0x00b021b4 Workbench -[fuelUIPos]',
        selectors={},
        imports={},
        ivars={
                 0xb021a8: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb021ac: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb02224: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(11542864, 'push {fp, lr}'), (11542940, 'bl 0xafd54c'), (11543080, 'subseq sp, r5, r8, lsl sb')],
        calls=[(11542940, 'bl 0xafd54c'), (11543044, 'bl method.Vector2.Vector2_float__float_'), (11543064, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=('[Workbench destroyItemType] (imp 0x00b02150, 55w): type-keyed (fffff130 + fffff120) -> **the helper 0xafd54c** (@0xb0219c) - the SAME helper as freeblockCreationItemType (E79): destroy and create share the item-type derivation.\n'),
    ),
    dict(
        name='wt_fueluipos',
        method='Workbench -[fuelUIPos]',
        types='{Vector2=[2f]}8@0:4',
        start=11542964,
        end=11543084,
        disasm='disasm_worldtileloader_wt_fueluipos.txt',
        base_add=11542996,
        base_literal=11543080,
        boundary='ARM.exidx end 0x00b0222c (listing bound); next ObjC IMP 0x00b0222c Workbench -[staticGeometryDrawQuadCountForMacroPos:]',
        selectors={},
        imports={},
        ivars={
                 0xb02224: (17155024, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
        },
        classes={},
        instructions=[(11542964, 'push {fp, lr}'), (11543020, 'mov ip, 0x40000000'), (11543064, 'bl method.Vector2.operator_Vector2_'), (11543080, 'subseq sp, r5, r8, lsl sb')],
        calls=[(11543044, 'bl method.Vector2.Vector2_float__float_'), (11543064, 'bl method.Vector2.operator_Vector2_')],
        branches=[],
        semantics=("[Workbench fuelUIPos] (imp 0x00b021b4, 30w): `Vector2::operator+(Vector2::Vector2(0, 2.0f))` over the macro position (`mov ip, 0x40000000` = 2.0f @0xb021ec) - the workbench fuel UI floats **2** units up (vs the SteamTrain's 4.0f).\n"),
    ),
    dict(
        name='wt_renderquad',
        method='Workbench -[rendersDynamicObjectQuad]',
        types='c8@0:4',
        start=11578188,
        end=11579072,
        disasm='disasm_worldtileloader_wt_renderquad.txt',
        base_add=11578196,
        base_literal=11578900,
        boundary='ARM.exidx end 0x00b0aec0 (listing bound); next ObjC IMP 0x00b0ae18 Workbench -[rendersDynamicObjectCubes]',
        selectors={},
        imports={},
        ivars={
                 0xb0ae10: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0aeb8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11578188, 'sub sp, sp, 0x10'), (11578244, 'movw r0, 1'), (11578328, 'movw r0, 1'), (11579068, 'subseq r4, r5, ip, asr 25')],
        calls=[],
        branches=[(11578240, 'bne', 11578256), (11578252, 'b', 11578884), (11578288, 'beq', 11578328), (11578324, 'bne', 11578340), (11578336, 'b', 11578884), (11578372, 'beq', 11578520), (11578408, 'beq', 11578520), (11578444, 'beq', 11578520), (11578480, 'beq', 11578520), (11578516, 'bne', 11578532), (11578528, 'b', 11578884), (11578564, 'beq', 11578748), (11578600, 'beq', 11578748), (11578636, 'beq', 11578748), (11578672, 'beq', 11578748), (11578708, 'beq', 11578748), (11578744, 'bne', 11578760), (11578756, 'b', 11578884), (11578792, 'bne', 11578808), (11578804, 'b', 11578884), (11578840, 'bne', 11578856), (11578852, 'b', 11578884), (11578856, 'b', 11578860), (11578860, 'b', 11578864), (11578864, 'b', 11578868), (11578868, 'b', 11578872), (11578872, 'b', 11578876), (11578956, 'beq', 11579032), (11578992, 'beq', 11579032), (11579028, 'bne', 11579044), (11579040, 'b', 11579052)],
        semantics=('[Workbench rendersDynamicObjectQuad] (imp 0x00b0ab4c, 221w): the type->render table - the fffff120 cascade answers true for **type == 3** (@0xb0ab84), **1 or 0xd (13)** (@0xb0abd8), then the 8/0x1f arms (@0xb0ac04-0xb0ac28) continue the set; each arm stores the byte 1 into the result slot (strb r0, [sp, 0xf]).\n'),
    ),
    dict(
        name='wt_rendercubes',
        method='Workbench -[rendersDynamicObjectCubes]',
        types='c8@0:4',
        start=11578904,
        end=11579072,
        disasm='disasm_worldtileloader_wt_rendercubes.txt',
        base_add=11578912,
        base_literal=11579068,
        boundary='ARM.exidx end 0x00b0aec0 (listing bound); next ObjC IMP 0x00b0aec0 Workbench -[removeFromMacroBlock]',
        selectors={},
        imports={},
        ivars={
                 0xb0aeb8: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
        },
        classes={},
        instructions=[(11578904, 'sub sp, sp, 0x10'), (11578948, 'cmp r0, 0x18'), (11579068, 'subseq r4, r5, ip, asr 25')],
        calls=[],
        branches=[(11578956, 'beq', 11579032), (11578992, 'beq', 11579032), (11579028, 'bne', 11579044), (11579040, 'b', 11579052)],
        semantics=('[Workbench rendersDynamicObjectCubes] (imp 0x00b0ae18, 42w): true for **type 0x18 (24), 0x1a (26) or 0x1d (29)** (`cmp` x3 @0xb0ae44-0xb0ae94), else 0.\n'),
    ),
    dict(
        name='wt_bhunloaded',
        method='Workbench -[blockheadUnloaded:]',
        types='v12@0:4@8',
        start=11579996,
        end=11580312,
        disasm='disasm_worldtileloader_wt_bhunloaded.txt',
        base_add=11580012,
        base_literal=11580308,
        boundary='ARM.exidx end 0x00b0b398 (listing bound); next ObjC IMP 0x00b0b398 Workbench -[lightGlowQuadCount]',
        selectors={
                 0xb0b37c: (15229308, 'blockheadUnloaded:'),
                 0xb0b390: (15228704, 'release'),
        },
        imports={
                 0xb0b378: (17151900, 'objc_msgSendSuper2'),
                 0xb0b38c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xb0b384: (17165444, 'OBJC_IVAR_$_Workbench.currentFuelBlockhead', 108),
                 0xb0b388: (17165396, 'OBJC_IVAR_$_Workbench.isInUseFuel', 112),
        },
        classes={
                 0xb0b380: (15253120, 'OBJC_CLASS_$_Workbench'),
        },
        instructions=[(11579996, 'push {r4, r5, r6, sl, fp, lr}'), (11580128, 'bne 0xb0b370'), (11580220, 'blx lr'), (11580308, 'subseq r4, r5, r0, lsl 17')],
        calls=[(11580088, 'blx lr'), (11580220, 'blx lr')],
        branches=[(11580128, 'bne', 11580272)],
        semantics=("[Workbench blockheadUnloaded:] (imp 0x00b0b25c, 79w): super call (@0xb0b2b8) then the **fffff190 owner compare** (`cmp r2, r0; bne` @0xb0b2e0: only the current manager clears) + the fffff160 + ffe2642c chain (@0xb0b33c) - the fuel manager releases on its blockhead's unload.\n"),
    ),
    dict(
        name='wt_glowquadcount',
        method='Workbench -[lightGlowQuadCount]',
        types='i8@0:4',
        start=11580312,
        end=11580700,
        disasm='disasm_worldtileloader_wt_glowquadcount.txt',
        base_add=11580320,
        base_literal=11580696,
        boundary='ARM.exidx end 0x00b0b51c (listing bound); next ObjC IMP 0x00b0b51c Workbench -[lightPos]',
        selectors={},
        imports={},
        ivars={
                 0xb0b510: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0b514: (17165368, 'OBJC_IVAR_$_Workbench.hasFuel', 220),
        },
        classes={},
        instructions=[(11580312, 'sub sp, sp, 0x10'), (11580364, 'beq 0xb0b4f0'), (11580472, 'beq 0xb0b4fc'), (11580696, 'subseq r4, r5, ip, asr 14')],
        calls=[],
        branches=[(11580364, 'beq', 11580656), (11580400, 'beq', 11580656), (11580436, 'beq', 11580656), (11580472, 'beq', 11580668), (11580508, 'beq', 11580656), (11580544, 'beq', 11580656), (11580580, 'beq', 11580656), (11580616, 'beq', 11580656), (11580652, 'bne', 11580668), (11580664, 'b', 11580676)],
        semantics=("[Workbench lightGlowQuadCount] (imp 0x00b0b398, 97w): the glow-count table - **type 1 / 0xd (13) / 3** jump (@0xb0b3cc-0xb0b414), the fffff144 flag gates (@0xb0b438), and the **8/0x1f** arms (@0xb0b45c-0xb0b480) continue (the workbench light-contributor types; mirror of the torch's 0x9d exception).\n"),
    ),
    dict(
        name='wt_occupiesnormal',
        method='Workbench -[occupiesNormalContents]',
        types='c8@0:4',
        start=11581000,
        end=11581028,
        disasm='disasm_worldtileloader_wt_occupiesnormal.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b0b664 (listing bound); next ObjC IMP 0x00b0b664 Workbench -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11581000, 'sub sp, sp, 8'), (11581024, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Workbench occupiesNormalContents] (imp 0x00b0b648, 7w): returns **1**.\n'),
    ),
    dict(
        name='wt_expertuse',
        method='Workbench -[canBeUsedInExpertModeWhenNotOwned]',
        types='c8@0:4',
        start=11581144,
        end=11582628,
        disasm='disasm_worldtileloader_wt_expertuse.txt',
        base_add=11581160,
        base_literal=11581236,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0b738 Workbench -[requiresFuel]',
        selectors={
                 0xb0b730: (15229316, 'type'),
                 0xb0b7c4: (15229320, 'level'),
                 0xb0b7c8: (15229316, 'type'),
                 0xb0b85c: (15229320, 'level'),
                 0xb0b860: (15229316, 'type'),
                 0xb0b8f0: (15229320, 'level'),
                 0xb0b8f4: (15229316, 'type'),
                 0xb0ba58: (15228784, 'stringWithFormat:'),
                 0xb0baec: (15229320, 'level'),
                 0xb0baf0: (15229316, 'type'),
                 0xb0bb80: (15229320, 'level'),
                 0xb0bb84: (15229316, 'type'),
                 0xb0bbd0: (15229292, 'title'),
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0b72c: (17151904, 'objc_msgSend'),
                 0xb0b7c0: (17151904, 'objc_msgSend'),
                 0xb0b858: (17151904, 'objc_msgSend'),
                 0xb0b8ec: (17151904, 'objc_msgSend'),
                 0xb0ba3c: (16367160, '__CFConstantStringClassReference'),
                 0xb0ba40: (16367144, '__CFConstantStringClassReference'),
                 0xb0ba44: (16367128, '__CFConstantStringClassReference'),
                 0xb0ba48: (16367112, '__CFConstantStringClassReference'),
                 0xb0ba4c: (16367096, '__CFConstantStringClassReference'),
                 0xb0ba50: (16367176, '__CFConstantStringClassReference'),
                 0xb0ba54: (17151904, 'objc_msgSend'),
                 0xb0bae8: (17151904, 'objc_msgSend'),
                 0xb0bb7c: (17151904, 'objc_msgSend'),
                 0xb0bbcc: (17151904, 'objc_msgSend'),
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xb0ba5c: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11581144, 'push {fp, lr}'), (11581200, 'cmp r0, 1'), (11582624, 'pop {fp, pc}')],
        calls=[(11581196, 'blx r3'), (11581308, 'blx r3'), (11581340, 'blx r3'), (11581360, 'bl 0xae3538'), (11581460, 'blx r3'), (11581492, 'blx r3'), (11581512, 'bl 0xae3574'), (11581612, 'blx r3'), (11581644, 'blx r3'), (11581664, 'bl 0xb0b8fc'), (11581992, 'blx ip'), (11582120, 'blx r3'), (11582152, 'blx r3'), (11582172, 'bl 0xb01800'), (11582268, 'blx r3'), (11582300, 'blx r3'), (11582320, 'bl 0xb018f8'), (11582400, 'blx r3'), (11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11581732, 'beq', 11581748), (11581744, 'bne', 11581912), (11581760, 'bhi', 11581904), (11581820, 'b', 11582000), (11581840, 'b', 11582000), (11581860, 'b', 11582000), (11581880, 'b', 11582000), (11581900, 'b', 11582000), (11581904, 'b', 11581908), (11581908, 'b', 11581912), (11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench canBeUsedInExpertModeWhenNotOwned] (imp 0x00b0b6d8, 371w): the delegate chain (ffffbcac + ffe26690) then `cmp r0, 1; moveq 1` (@0xb0b710): the expert-mode use is a single equality against 1.\n'),
    ),
    dict(
        name='wt_requiresfuel',
        method='Workbench -[requiresFuel]',
        types='c8@0:4',
        start=11581240,
        end=11582628,
        disasm='disasm_worldtileloader_wt_requiresfuel.txt',
        base_add=11581256,
        base_literal=11581388,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0b7d0 Workbench -[requiresElectricty]',
        selectors={
                 0xb0b7c4: (15229320, 'level'),
                 0xb0b7c8: (15229316, 'type'),
                 0xb0b85c: (15229320, 'level'),
                 0xb0b860: (15229316, 'type'),
                 0xb0b8f0: (15229320, 'level'),
                 0xb0b8f4: (15229316, 'type'),
                 0xb0ba58: (15228784, 'stringWithFormat:'),
                 0xb0baec: (15229320, 'level'),
                 0xb0baf0: (15229316, 'type'),
                 0xb0bb80: (15229320, 'level'),
                 0xb0bb84: (15229316, 'type'),
                 0xb0bbd0: (15229292, 'title'),
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0b7c0: (17151904, 'objc_msgSend'),
                 0xb0b858: (17151904, 'objc_msgSend'),
                 0xb0b8ec: (17151904, 'objc_msgSend'),
                 0xb0ba3c: (16367160, '__CFConstantStringClassReference'),
                 0xb0ba40: (16367144, '__CFConstantStringClassReference'),
                 0xb0ba44: (16367128, '__CFConstantStringClassReference'),
                 0xb0ba48: (16367112, '__CFConstantStringClassReference'),
                 0xb0ba4c: (16367096, '__CFConstantStringClassReference'),
                 0xb0ba50: (16367176, '__CFConstantStringClassReference'),
                 0xb0ba54: (17151904, 'objc_msgSend'),
                 0xb0bae8: (17151904, 'objc_msgSend'),
                 0xb0bb7c: (17151904, 'objc_msgSend'),
                 0xb0bbcc: (17151904, 'objc_msgSend'),
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xb0ba5c: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11581240, 'push {fp, lr}'), (11581360, 'bl 0xae3538'), (11582624, 'pop {fp, pc}')],
        calls=[(11581308, 'blx r3'), (11581340, 'blx r3'), (11581360, 'bl 0xae3538'), (11581460, 'blx r3'), (11581492, 'blx r3'), (11581512, 'bl 0xae3574'), (11581612, 'blx r3'), (11581644, 'blx r3'), (11581664, 'bl 0xb0b8fc'), (11581992, 'blx ip'), (11582120, 'blx r3'), (11582152, 'blx r3'), (11582172, 'bl 0xb01800'), (11582268, 'blx r3'), (11582300, 'blx r3'), (11582320, 'bl 0xb018f8'), (11582400, 'blx r3'), (11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11581732, 'beq', 11581748), (11581744, 'bne', 11581912), (11581760, 'bhi', 11581904), (11581820, 'b', 11582000), (11581840, 'b', 11582000), (11581860, 'b', 11582000), (11581880, 'b', 11582000), (11581900, 'b', 11582000), (11581904, 'b', 11581908), (11581908, 'b', 11581912), (11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench requiresFuel] (imp 0x00b0b738, 347w): the ffe26694/ffe26690 delegate pair then **the helper 0xae3538** (@0xb0b7b0 - the same helper family as wb_getlightrgb in E75) -> sxtb; the delegate supplies the fuel requirement.\n'),
    ),
    dict(
        name='wt_upgradename',
        method='Workbench -[upgradeName]',
        types='@8@0:4',
        start=11581544,
        end=11582628,
        disasm='disasm_worldtileloader_wt_upgradename.txt',
        base_add=11581560,
        base_literal=11581688,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0ba64 Workbench -[fuelTypesCount]',
        selectors={
                 0xb0b8f0: (15229320, 'level'),
                 0xb0b8f4: (15229316, 'type'),
                 0xb0ba58: (15228784, 'stringWithFormat:'),
                 0xb0baec: (15229320, 'level'),
                 0xb0baf0: (15229316, 'type'),
                 0xb0bb80: (15229320, 'level'),
                 0xb0bb84: (15229316, 'type'),
                 0xb0bbd0: (15229292, 'title'),
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0b8ec: (17151904, 'objc_msgSend'),
                 0xb0ba3c: (16367160, '__CFConstantStringClassReference'),
                 0xb0ba40: (16367144, '__CFConstantStringClassReference'),
                 0xb0ba44: (16367128, '__CFConstantStringClassReference'),
                 0xb0ba48: (16367112, '__CFConstantStringClassReference'),
                 0xb0ba4c: (16367096, '__CFConstantStringClassReference'),
                 0xb0ba50: (16367176, '__CFConstantStringClassReference'),
                 0xb0ba54: (17151904, 'objc_msgSend'),
                 0xb0bae8: (17151904, 'objc_msgSend'),
                 0xb0bb7c: (17151904, 'objc_msgSend'),
                 0xb0bbcc: (17151904, 'objc_msgSend'),
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xb0ba5c: (15249636, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(11581544, 'push {fp, lr}'), (11581664, 'bl 0xb0b8fc'), (11582624, 'pop {fp, pc}')],
        calls=[(11581612, 'blx r3'), (11581644, 'blx r3'), (11581664, 'bl 0xb0b8fc'), (11581992, 'blx ip'), (11582120, 'blx r3'), (11582152, 'blx r3'), (11582172, 'bl 0xb01800'), (11582268, 'blx r3'), (11582300, 'blx r3'), (11582320, 'bl 0xb018f8'), (11582400, 'blx r3'), (11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11581732, 'beq', 11581748), (11581744, 'bne', 11581912), (11581760, 'bhi', 11581904), (11581820, 'b', 11582000), (11581840, 'b', 11582000), (11581860, 'b', 11582000), (11581880, 'b', 11582000), (11581900, 'b', 11582000), (11581904, 'b', 11581908), (11581908, 'b', 11581912), (11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench upgradeName] (imp 0x00b0b868, 271w): the delegate chain then the local helper **0xb0b8fc** (@0xb0b8e0) which is a **5-arm jump table over the type**: `cmp r0, 1 / cmp r0, 0xd (13)` special arms (@0xb0b91c-0xb0b930) + `cmp r0, 4; bhi` + `lsl r1, r0, 2` table at **0xb0b958** (@0xb0b948-0xb0b954) - the upgrade name per workbench type.\n'),
    ),
    dict(
        name='wt_fueltypescount',
        method='Workbench -[fuelTypesCount]',
        types='i8@0:4',
        start=11582052,
        end=11582628,
        disasm='disasm_worldtileloader_wt_fueltypescount.txt',
        base_add=11582068,
        base_literal=11582196,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0baf8 Workbench -[fuelTypes]',
        selectors={
                 0xb0baec: (15229320, 'level'),
                 0xb0baf0: (15229316, 'type'),
                 0xb0bb80: (15229320, 'level'),
                 0xb0bb84: (15229316, 'type'),
                 0xb0bbd0: (15229292, 'title'),
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0bae8: (17151904, 'objc_msgSend'),
                 0xb0bb7c: (17151904, 'objc_msgSend'),
                 0xb0bbcc: (17151904, 'objc_msgSend'),
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11582052, 'push {fp, lr}'), (11582172, 'bl 0xb01800'), (11582624, 'pop {fp, pc}')],
        calls=[(11582120, 'blx r3'), (11582152, 'blx r3'), (11582172, 'bl 0xb01800'), (11582268, 'blx r3'), (11582300, 'blx r3'), (11582320, 'bl 0xb018f8'), (11582400, 'blx r3'), (11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench fuelTypesCount] (imp 0x00b0ba64, 144w): the ffe26694/ffe26690 chain -> **helper 0xb01800** (@0xb0badc) - the fuel Items/Count helper region of E76 (0xb0179c+): the count per type.\n'),
    ),
    dict(
        name='wt_fueltypes',
        method='Workbench -[fuelTypes]',
        types='^i8@0:4',
        start=11582200,
        end=11582628,
        disasm='disasm_worldtileloader_wt_fueltypes.txt',
        base_add=11582216,
        base_literal=11582344,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0bb8c Workbench -[titleForCraftProgressUI]',
        selectors={
                 0xb0bb80: (15229320, 'level'),
                 0xb0bb84: (15229316, 'type'),
                 0xb0bbd0: (15229292, 'title'),
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0bb7c: (17151904, 'objc_msgSend'),
                 0xb0bbcc: (17151904, 'objc_msgSend'),
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11582200, 'push {fp, lr}'), (11582320, 'bl 0xb018f8'), (11582624, 'pop {fp, pc}')],
        calls=[(11582268, 'blx r3'), (11582300, 'blx r3'), (11582320, 'bl 0xb018f8'), (11582400, 'blx r3'), (11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench fuelTypes] (imp 0x00b0baf8, 107w): same chain -> **helper 0xb018f8** (@0xb0bb70) - the fuel-items table accessor of the E76 family.\n'),
    ),
    dict(
        name='wt_upgradenamecraft',
        method='Workbench -[upgradeNameForCraftProgressUI]',
        types='@8@0:4',
        start=11582424,
        end=11582628,
        disasm='disasm_worldtileloader_wt_upgradenamecraft.txt',
        base_add=11582440,
        base_literal=11582496,
        boundary='ARM.exidx end 0x00b0bca4 (listing bound); next ObjC IMP 0x00b0bc24 Workbench -[hurryCostForCraftTimeRemaining:totalCraftTime:]',
        selectors={
                 0xb0bc1c: (15229324, 'upgradeName'),
        },
        imports={
                 0xb0bc18: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(11582424, 'push {fp, lr}'), (11582624, 'pop {fp, pc}')],
        calls=[(11582476, 'blx r3'), (11582552, 'bl sym.imp.__aeabi_idiv')],
        branches=[(11582584, 'bge', 11582600), (11582596, 'b', 11582608)],
        semantics=('[Workbench upgradeNameForCraftProgressUI] (imp 0x00b0bbd8, 51w): forwarder via ffffbcac + ffe26698 (the crafting-progress UI variant of the upgrade name).\n'),
    ),
    dict(
        name='wt_numcraftable',
        method='Workbench -[numberOfCraftableItems]',
        types='i8@0:4',
        start=11582628,
        end=11582928,
        disasm='disasm_worldtileloader_wt_numcraftable.txt',
        base_add=11582652,
        base_literal=11582684,
        boundary='ARM.exidx end 0x00b0bdd0 (listing bound); next ObjC IMP 0x00b0bce0 Workbench -[numberOfCraftableItemsUpToCurrentLevel]',
        selectors={},
        imports={},
        ivars={
                 0xb0bcd8: (17165340, 'OBJC_IVAR_$_Workbench.numberOfCraftableItems', 124),
                 0xb0bd14: (17165336, 'OBJC_IVAR_$_Workbench.numberOfCraftableItemsUpToCurrentLevel', 128),
                 0xb0bd50: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0bd8c: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb0bdc8: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
        },
        classes={},
        instructions=[(11582628, 'sub sp, sp, 8'), (11582668, 'dmb ish'), (11582924, 'subseq r3, r5, r0, asr 26')],
        calls=[],
        branches=[],
        semantics=('[Workbench numberOfCraftableItems] (imp 0x00b0bca4, 75w): the **dmb ish-fenced read** through the **fffff128** cell (@0xb0bccc) - the craftable count is SMP-mirrored.\n'),
    ),
    dict(
        name='wt_numcraftablelevel',
        method='Workbench -[numberOfCraftableItemsUpToCurrentLevel]',
        types='i8@0:4',
        start=11582688,
        end=11582928,
        disasm='disasm_worldtileloader_wt_numcraftablelevel.txt',
        base_add=11582712,
        base_literal=11582744,
        boundary='ARM.exidx end 0x00b0bdd0 (listing bound); next ObjC IMP 0x00b0bd1c Workbench -[type]',
        selectors={},
        imports={},
        ivars={
                 0xb0bd14: (17165336, 'OBJC_IVAR_$_Workbench.numberOfCraftableItemsUpToCurrentLevel', 128),
                 0xb0bd50: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0bd8c: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb0bdc8: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
        },
        classes={},
        instructions=[(11582688, 'sub sp, sp, 8'), (11582728, 'dmb ish'), (11582924, 'subseq r3, r5, r0, asr 26')],
        calls=[],
        branches=[],
        semantics=('[Workbench numberOfCraftableItemsUpToCurrentLevel] (imp 0x00b0bce0, 60w): the dmb ish-fenced read through the **fffff124** cell (@0xb0bd08).\n'),
    ),
    dict(
        name='wt_type',
        method='Workbench -[type]',
        types='i8@0:4',
        start=11582748,
        end=11582928,
        disasm='disasm_worldtileloader_wt_type.txt',
        base_add=11582772,
        base_literal=11582804,
        boundary='ARM.exidx end 0x00b0bdd0 (listing bound); next ObjC IMP 0x00b0bd58 Workbench -[level]',
        selectors={},
        imports={},
        ivars={
                 0xb0bd50: (17165332, 'OBJC_IVAR_$_Workbench.type', 120),
                 0xb0bd8c: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb0bdc8: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
        },
        classes={},
        instructions=[(11582748, 'sub sp, sp, 8'), (11582924, 'subseq r3, r5, r0, asr 26')],
        calls=[],
        branches=[],
        semantics=('[Workbench type] (imp 0x00b0bd1c, 45w): the type read through **fffff120** (+ the fffff130 and fffff17c neighbors in the chain).\n'),
    ),
    dict(
        name='wt_level',
        method='Workbench -[level]',
        types='i8@0:4',
        start=11582808,
        end=11582928,
        disasm='disasm_worldtileloader_wt_level.txt',
        base_add=11582832,
        base_literal=11582864,
        boundary='ARM.exidx end 0x00b0bdd0 (listing bound); next ObjC IMP 0x00b0bd94 Workbench -[selectedIndex]',
        selectors={},
        imports={},
        ivars={
                 0xb0bd8c: (17165348, 'OBJC_IVAR_$_Workbench.level', 176),
                 0xb0bdc8: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
        },
        classes={},
        instructions=[(11582808, 'sub sp, sp, 8'), (11582924, 'subseq r3, r5, r0, asr 26')],
        calls=[],
        branches=[],
        semantics=('[Workbench level] (imp 0x00b0bd58, 30w): the level read through **fffff130** (+ fffff17c neighbor).\n'),
    ),
    dict(
        name='wt_selindex',
        method='Workbench -[selectedIndex]',
        types='i8@0:4',
        start=11582868,
        end=11582928,
        disasm='disasm_worldtileloader_wt_selindex.txt',
        base_add=11582892,
        base_literal=11582924,
        boundary='ARM.exidx end 0x00b0bdd0 (listing bound); next ObjC IMP 0x00b0bdd0 Workbench -[setSelectedIndex:]',
        selectors={},
        imports={},
        ivars={
                 0xb0bdc8: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
        },
        classes={},
        instructions=[(11582868, 'sub sp, sp, 8'), (11582924, 'subseq r3, r5, r0, asr 26')],
        calls=[],
        branches=[],
        semantics=('[Workbench selectedIndex] (imp 0x00b0bd94, 15w): read through **fffff17c**.\n'),
    ),
    dict(
        name='wt_setselindex',
        method='Workbench -[setSelectedIndex:]',
        types='v12@0:4i8',
        start=11582928,
        end=11583064,
        disasm='disasm_worldtileloader_wt_setselindex.txt',
        base_add=11582956,
        base_literal=11582992,
        boundary='ARM.exidx end 0x00b0be58 (listing bound); next ObjC IMP 0x00b0be14 Workbench -[craftingItemObject]',
        selectors={},
        imports={},
        ivars={
                 0xb0be0c: (17165424, 'OBJC_IVAR_$_Workbench.selectedIndex', 136),
                 0xb0be50: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
        },
        classes={},
        instructions=[(11582928, 'sub sp, sp, 0xc'), (11583060, 'subseq r3, r5, r0, asr 25')],
        calls=[],
        branches=[],
        semantics=('[Workbench setSelectedIndex:] (imp 0x00b0bdd0, 34w): write through **fffff17c** (also touches fffff180).\n'),
    ),
    dict(
        name='wt_craftobj',
        method='Workbench -[craftingItemObject]',
        types='@8@0:4',
        start=11582996,
        end=11583064,
        disasm='disasm_worldtileloader_wt_craftobj.txt',
        base_add=11583020,
        base_literal=11583060,
        boundary='ARM.exidx end 0x00b0be58 (listing bound); next ObjC IMP 0x00b0be58 Workbench -[count]',
        selectors={},
        imports={},
        ivars={
                 0xb0be50: (17165428, 'OBJC_IVAR_$_Workbench.craftingItemObject', 180),
        },
        classes={},
        instructions=[(11582996, 'sub sp, sp, 0xc'), (11583060, 'subseq r3, r5, r0, asr 25')],
        calls=[],
        branches=[],
        semantics=('[Workbench craftingItemObject] (imp 0x00b0be14, 17w): read through **fffff180** - the active crafting object.\n'),
    ),
    dict(
        name='wt_count',
        method='Workbench -[count]',
        types='i8@0:4',
        start=11583064,
        end=11583184,
        disasm='disasm_worldtileloader_wt_count.txt',
        base_add=11583088,
        base_literal=11583120,
        boundary='ARM.exidx end 0x00b0bed0 (listing bound); next ObjC IMP 0x00b0be94 Workbench -[countLeft]',
        selectors={},
        imports={},
        ivars={
                 0xb0be8c: (17165440, 'OBJC_IVAR_$_Workbench.count', 228),
                 0xb0bec8: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
        },
        classes={},
        instructions=[(11583064, 'sub sp, sp, 8'), (11583180, 'subseq r3, r5, r0, asr 24')],
        calls=[],
        branches=[],
        semantics=('[Workbench count] (imp 0x00b0be58, 30w): read through **fffff18c** (+ fffff188 neighbor).\n'),
    ),
    dict(
        name='wt_countleft',
        method='Workbench -[countLeft]',
        types='i8@0:4',
        start=11583124,
        end=11583184,
        disasm='disasm_worldtileloader_wt_countleft.txt',
        base_add=11583148,
        base_literal=11583180,
        boundary='ARM.exidx end 0x00b0bed0 (listing bound); next ObjC IMP 0x00b0bed0 Workbench -[craftProgressUI]',
        selectors={},
        imports={},
        ivars={
                 0xb0bec8: (17165436, 'OBJC_IVAR_$_Workbench.countLeft', 232),
        },
        classes={},
        instructions=[(11583124, 'sub sp, sp, 8'), (11583180, 'subseq r3, r5, r0, asr 24')],
        calls=[],
        branches=[],
        semantics=('[Workbench countLeft] (imp 0x00b0be94, 15w): read through **fffff188** - the remaining count.\n'),
    ),
    dict(
        name='wt_craftprog',
        method='Workbench -[craftProgressUI]',
        types='@8@0:4',
        start=11583184,
        end=11583468,
        disasm='disasm_worldtileloader_wt_craftprog.txt',
        base_add=11583208,
        base_literal=11583248,
        boundary='ARM.exidx end 0x00b0bfec (listing bound); next ObjC IMP 0x00b0bf14 Workbench -[setCraftProgressUI:]',
        selectors={},
        imports={},
        ivars={
                 0xb0bf0c: (17165472, 'OBJC_IVAR_$_Workbench.craftProgressUI', 184),
                 0xb0bf50: (17165472, 'OBJC_IVAR_$_Workbench.craftProgressUI', 184),
                 0xb0bf98: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
                 0xb0bfe4: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
        },
        classes={},
        instructions=[(11583184, 'sub sp, sp, 0xc'), (11583464, 'subseq r3, r5, ip, lsr 22')],
        calls=[],
        branches=[],
        semantics=('[Workbench craftProgressUI] (imp 0x00b0bed0, 71w): read through **fffff1ac** (+ fffff178 neighbor) - the crafting progress UI object.\n'),
    ),
    dict(
        name='wt_setcraftprog',
        method='Workbench -[setCraftProgressUI:]',
        types='v12@0:4@8',
        start=11583252,
        end=11583468,
        disasm='disasm_worldtileloader_wt_setcraftprog.txt',
        base_add=11583280,
        base_literal=11583316,
        boundary='ARM.exidx end 0x00b0bfec (listing bound); next ObjC IMP 0x00b0bf58 Workbench -[xScroll]',
        selectors={},
        imports={},
        ivars={
                 0xb0bf50: (17165472, 'OBJC_IVAR_$_Workbench.craftProgressUI', 184),
                 0xb0bf98: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
                 0xb0bfe4: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
        },
        classes={},
        instructions=[(11583252, 'sub sp, sp, 0xc'), (11583464, 'subseq r3, r5, ip, lsr 22')],
        calls=[],
        branches=[],
        semantics=('[Workbench setCraftProgressUI:] (imp 0x00b0bf14, 54w): write through **fffff1ac** (+ fffff178).\n'),
    ),
    dict(
        name='wt_xscroll',
        method='Workbench -[xScroll]',
        types='f8@0:4',
        start=11583320,
        end=11583468,
        disasm='disasm_worldtileloader_wt_xscroll.txt',
        base_add=11583344,
        base_literal=11583388,
        boundary='ARM.exidx end 0x00b0bfec (listing bound); next ObjC IMP 0x00b0bfa0 Workbench -[setXScroll:]',
        selectors={},
        imports={},
        ivars={
                 0xb0bf98: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
                 0xb0bfe4: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
        },
        classes={},
        instructions=[(11583320, 'sub sp, sp, 0xc'), (11583464, 'subseq r3, r5, ip, lsr 22')],
        calls=[],
        branches=[],
        semantics=('[Workbench xScroll] (imp 0x00b0bf58, 37w): read through **fffff178** - the crafting list scroll.\n'),
    ),
    dict(
        name='wt_setxscroll',
        method='Workbench -[setXScroll:]',
        types='v12@0:4f8',
        start=11583392,
        end=11583468,
        disasm='disasm_worldtileloader_wt_setxscroll.txt',
        base_add=11583424,
        base_literal=11583464,
        boundary='ARM.exidx end 0x00b0bfec (listing bound); next ObjC IMP 0x00b0cc48 CreateWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]',
        selectors={},
        imports={},
        ivars={
                 0xb0bfe4: (17165420, 'OBJC_IVAR_$_Workbench.xScroll', 172),
        },
        classes={},
        instructions=[(11583392, 'sub sp, sp, 0xc'), (11583464, 'subseq r3, r5, ip, lsr 22')],
        calls=[],
        branches=[],
        semantics=('[Workbench setXScroll:] (imp 0x00b0bfa0, 19w): write through **fffff178**.\n'),
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
        'batch': 'Workbench tail closure (E83): the render flags, the delegates, the upgrade names and the accessor cell map; 26 bodies',
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
                        default=NATIVE / 'workbench_tail.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale workbench_tail.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
