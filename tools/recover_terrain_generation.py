#!/usr/bin/env python3
"""Hash-gated recovery of the Terrain generation batch (E12).

Closes the named T2/T3 terrain slice of WorldTileLoader:
13 bodies, 5391 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/TRADE_PORTAL_ECON.md for the prose and boundaries.
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
    'bl 0x8540cc': 0x008540cc,
    'bl 0x8540fc': 0x008540fc,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_': 0x00a14f28,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_fmodf': 0x001c3d4c,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
}

SPECS = [
    dict(
        name='wtl_limestonefractionforx_',
        method='WorldTileLoader -[limestoneFractionForX:y:faultOffset:]',
        types='f20@0:4i8i12i16',
        start=8746628,
        end=8747192,
        disasm='disasm_worldtileloader_limestonefractionforx_y_faultoffset_.txt',
        base_add=8746644,
        base_literal=8747188,
        boundary='ARM.exidx end 0x008578b8 (listing bound); next ObjC IMP 0x008578b8 WorldTileLoader -[sandstoneFractionForX:y:faultOffset:limestoneFraction:]',
        selectors={
                 0x857894: (15213600, 'getX:Y:octaves:'),
                 0x8578b0: (15213480, 'worldWidthMacro'),
        },
        imports={
                 0x857890: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x85789c: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x8578a0: (17161632, 'OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction', 32),
                 0x8578ac: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        classes={},
        instructions=[(8746628, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8746672, 'vldr s4, [0x0085788c]'), (8746696, 'vldr s6, [0x00857898]'), (8746780, 'vldr s10, [0x008578a8]'), (8746864, 'bl loc.imp.objc_msgSend'), (8746872, 'lsl r0, r0, 5'), (8746900, 'vcvt.f64.f32 d6, s0'), (8746960, 'vcvt.f64.f32 d7, s0'), (8747008, 'blx lr'), (8747016, 'vcvt.f32.f64 s0, d6'), (8747080, 'vcmpe.f32 s6, s8'), (8747128, 'vmul.f32 s0, s2, s0'), (8747188, 'addeq r8, r0, r8, asr r4')],
        calls=[(8746864, 'bl loc.imp.objc_msgSend'), (8747008, 'blx lr')],
        branches=[(8747088, 'bpl', 8747104), (8747100, 'b', 8747112)],
        semantics=('limestoneFractionForX:y:faultOffset: is the noise-driven material fraction: the result is <second dispatch result> * min((faultOffset / 1024.0f) * 2.0f, 1.0f). The body primes 1.0f (vmov.f32 s0, 1 at 0x008576a0), 2.0f (0x008576a8), the f32 1024.0 (0x0085788c), f32 32.0 (0x00857898) and f32 39599.0 (0x008578a8), and fetches self->rockTypeNoiseFunction@32 (cell 0x008578a0) and self->world@4. The first dispatch (objc_msgSend at 0x00857770, selector cell 0x00857894 = getX:Y:octaves:, with y + 39599.0f at 0x00857714 and a 5 / 32 / 1024 constant frame) returns an int which the body scales (lsl r0, r0, 5 at 0x00857778) to form term A = (y + 39599.0f) / ((float)(ret << 5) * 2.0f) (0x00857788/0x00857790, vcvt.f64.f32 d6 at 0x00857794) and term B = (faultOffset - arg4) / (32.0f * self->yHeightDivider@244 * 2.0f) (0x008577c4/0x008577c8/0x008577cc, vcvt d7 at 0x008577d0). A second dispatch through the saved objc_msgSend (0x00857800, receiving both doubles) returns the scale (vcvt.f32.f64 at 0x00857808). The multiplier is min((faultOffset / 1024.0f) * 2.0f, 1.0f) (0x00857824/0x00857830 for the first term, the 1.0f from [sp,0x28], vcmpe.f32 at 0x00857848, min stored 0x00857868/0x0085786c) and the product is returned in r0 (vmul.f32 at 0x00857878, vmov r0, s0 at 0x00857880). Both denominators are measured; the semantic names of the 39599.0f offset and of yHeightDivider@244 are not.'),
    ),
    dict(
        name='wtl_sandstonefractionforx_',
        method='WorldTileLoader -[sandstoneFractionForX:y:faultOffset:limestoneFraction:]',
        types='f24@0:4i8i12i16f20',
        start=8747192,
        end=8747564,
        disasm='disasm_worldtileloader_sandstonefractionforx_y_faultoffset_lime.txt',
        base_add=8747320,
        base_literal=8747548,
        boundary='ARM.exidx end 0x00857a2c (listing bound); next ObjC IMP 0x00857a2c WorldTileLoader -[unmodifiedGroundLevelForX:]',
        selectors={
                 0x857a24: (15213580, 'isDesertForPos:height:'),
        },
        imports={},
        ivars={
                 0x857a18: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x857a20: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
        },
        classes={},
        instructions=[(8747192, 'push {fp, lr}'), (8747212, 'vldr d1, [0x00857a10]'), (8747248, 'vcmpe.f64 d2, d1'), (8747300, 'bl sym.makeIntpair_int__int_'), (8747368, 'add r0, r1, r0, lsl 2'), (8747416, 'ldr r0, [sp, 8]'), (8747472, 'bl loc.imp.objc_msgSend'), (8747492, 'vstr s0, [fp, -4]'), (8747500, 'mvn r0, 0'), (8747560, 'addeq r8, r0, r4, asr 2')],
        calls=[(8747300, 'bl sym.makeIntpair_int__int_'), (8747472, 'bl loc.imp.objc_msgSend')],
        branches=[(8747256, 'blt', 8747500), (8747392, 'bge', 8747408), (8747404, 'b', 8747416), (8747484, 'beq', 8747500), (8747496, 'b', 8747516)],
        semantics=('sandstoneFractionForX:y:faultOffset:limestoneFraction: returns the limestone fraction when the column is a desert and the sentinel -1.0f otherwise. It converts the incoming float to double and compares it with 0.45 (pool double at 0x00857a10, vldr d1 at 0x008578cc, vcmpe.f64 at 0x008578f0); below the cutoff it takes the -1.0f path (mvn r0, 0 at 0x008579ec, vmov.f32 s0, -1 at 0x008579f0). Otherwise it builds makeIntpair(x, y) (0x00857924), reads self->rockHeights@96 and self->dirtHeights@92 through their ivar cells (0x00857a18/0x00857a20, indexed [y] then [x] at 0x00857948/0x00857968), keeps the smaller of the two heights (cmp/bge 0x0085797c/0x00857980, min stored at 0x00857998) and dispatches [self isDesertForPos:pos height:minHeight] (selector cell 0x00857a24, call 0x008579d0). A desert answers with the limestoneFraction argument unchanged (0x008579e4); otherwise -1.0f.'),
    ),
    dict(
        name='wtl_isfloatingislandcavefo',
        method='WorldTileLoader -[isFloatingIslandCaveForX:y:]',
        types='c16@0:4i8i12',
        start=8749856,
        end=8750692,
        disasm='disasm_worldtileloader_isfloatingislandcaveforx_y_.txt',
        base_add=8749872,
        base_literal=8750688,
        boundary='ARM.exidx end 0x00858664 (listing bound); next ObjC IMP 0x00858664 WorldTileLoader -[sendBlockToClientWithoutSavingForBlock:pos:sendToClient:server:sendDynamicObjects:reliable:]',
        selectors={
                 0x858638: (15213556, 'customRules'),
                 0x858648: (15213600, 'getX:Y:octaves:'),
                 0x85865c: (15213480, 'worldWidthMacro'),
        },
        imports={
                 0x858640: (17151968, '__stack_chk_guard'),
                 0x858644: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x85863c: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85864c: (17161588, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionB', 56),
                 0x858650: (17161592, 'OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionA', 52),
                 0x858654: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
        },
        classes={},
        instructions=[(8749856, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8749980, 'bl loc.imp.objc_msgSend_stret'), (8750248, 'blx r2'), (8750312, 'vdiv.f32 s4, s4, s8'), (8750396, 'blx lr'), (8750488, 'blx lr'), (8750500, 'vmul.f64 d0, d0, d1'), (8750552, 'vcmpe.f64 d0, d5'), (8750624, 'sxtb r0, r0'), (8750688, 'strheq r7, [r0], ip')],
        calls=[(8749980, 'bl loc.imp.objc_msgSend_stret'), (8750016, 'bl sym.imp.memset'), (8750248, 'blx r2'), (8750396, 'blx lr'), (8750488, 'blx lr'), (8750636, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8749964, 'beq', 8749988), (8749984, 'b', 8750020), (8750028, 'bne', 8750044), (8750040, 'b', 8750584), (8750560, 'bpl', 8750576), (8750572, 'b', 8750584), (8750616, 'bne', 8750636)],
        semantics=("isFloatingIslandCaveForX:y: reads the 64-byte [world customRules] struct (objc_msgSend_stret at 0x0085839c, memset 0x40 when world is nil at 0x008583a8) and returns 0 unless byte +12 is non-zero (ldrsb [fp,-0x54]). It then computes x' = (x/32)/worldWidthMacro (0x008584a8/0x008584bc) and y' = (y/32)/self->yHeightDivider@244 (0x008584e8) and returns |noiseA + 0.5 * noiseB| < 0.2 (double at 0x00858630, vmul/vadd at 0x008585a4/0x008585b8, vcmpe at 0x008585d8, bpl 0x008585e0), where noiseA = [self->caveNoiseFunctionA@52 getX:Y:octaves:2] (0x0085853c) and noiseB = [self->caveNoiseFunctionB@56 getX:Y:octaves:1] (0x00858598), both sampled at (x'*8, y'*8)."),
    ),
    dict(
        name='wtl_sandfractionforpos_hig',
        method='WorldTileLoader -[sandFractionForPos:highRes:]',
        types='f20@0:4{?=ii}8c16',
        start=8759372,
        end=8760088,
        disasm='disasm_worldtileloader_sandfractionforpos_highres_.txt',
        base_add=8759436,
        base_literal=8760064,
        boundary='ARM.exidx end 0x0085ab18 (listing bound); next ObjC IMP 0x0085ab18 WorldTileLoader -[sandFractionForPos:height:highRes:]',
        selectors={
                 0x85aaf4: (15213480, 'worldWidthMacro'),
                 0x85ab10: (15213592, 'sandFractionForPos:height:highRes:'),
        },
        imports={},
        ivars={
                 0x85aaec: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85ab04: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x85ab0c: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
        },
        classes={},
        instructions=[(8759372, 'push {r4, sl, fp, lr}'), (8759488, 'add r0, r2, r0'), (8759604, 'lsl r0, r0, 5'), (8759908, 'cmp r2, r3'), (8759992, 'str r1, [r4, 4]'), (8760016, 'bl loc.imp.objc_msgSend'), (8760084, 'addeq r5, r0, r0, asr r0')],
        calls=[(8759472, 'bl loc.imp.objc_msgSend'), (8759596, 'bl loc.imp.objc_msgSend'), (8759688, 'bl loc.imp.objc_msgSend'), (8759744, 'bl loc.imp.objc_msgSend'), (8760016, 'bl loc.imp.objc_msgSend')],
        branches=[(8759416, 'bge', 8759536), (8759508, 'bge', 8759532), (8759528, 'b', 8760028), (8759532, 'b', 8759800), (8759620, 'blt', 8759796), (8759768, 'blt', 8759792), (8759788, 'b', 8760028), (8759792, 'b', 8759796), (8759796, 'b', 8759800), (8759920, 'bge', 8759936), (8759932, 'b', 8759944)],
        semantics=('sandFractionForPos:highRes: is the bounds-normalising delegate: it wraps pos.x into [0, worldWidthMacro * 32) by adding or subtracting the period once (0x0085a8b8/0x0085a8c0 for the negative side, 0x0085a934 for the upper side) and returns 0.0f (pool 0x0085aafc) when x is still out of range; then it takes h = max(rockHeights@96[x], dirtHeights@92[x]) (0x0085aa30/0x0085aa50/0x0085aa64, bge 0x0085aa80) and forwards [self sandFractionForPos:{x, y} height:h highRes:highRes] (selector cell 0x0085ab10, call 0x0085aad0, stack args h at 0x0085aabc and the sign-extended highRes at 0x0085aab8), returning that float unchanged.'),
    ),
    dict(
        name='wtl_sandfractionforpos_hei',
        method='WorldTileLoader -[sandFractionForPos:height:highRes:]',
        types='f24@0:4{?=ii}8i16c20',
        start=8760088,
        end=8761552,
        disasm='disasm_worldtileloader_sandfractionforpos_height_highres_.txt',
        base_add=8760104,
        base_literal=8761544,
        boundary='ARM.exidx end 0x0085b0d0 (listing bound); next ObjC IMP 0x0085b0d0 WorldTileLoader -[isDesertForPos:height:]',
        selectors={
                 0x85b0a4: (15213480, 'worldWidthMacro'),
                 0x85b0b8: (15213556, 'customRules'),
                 0x85b0bc: (15213600, 'getX:Y:octaves:'),
        },
        imports={
                 0x85b0a0: (17151904, 'objc_msgSend'),
                 0x85b0b0: (17151968, '__stack_chk_guard'),
        },
        ivars={
                 0x85b0a8: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85b0c0: (17161600, 'OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction', 44),
        },
        classes={},
        instructions=[(8760088, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8760300, 'vdiv.f32 s0, s4, s0'), (8760352, 'vdiv.f32 s0, s0, s4'), (8760396, 'cmp r0, 0x200'), (8760624, 'moveq r5, 4'), (8760664, 'blx lr'), (8760784, 'cmp r0, 4'), (8760852, 'vadd.f64 d0, d2, d0'), (8761040, 'ble 0x85b060'), (8761304, 'bl sym.imp.__wrap_fmodf'), (8761432, 'vmul.f32 s0, s2, s0'), (8761548, 'andeq r0, r0, r0')],
        calls=[(8760284, 'blx r5'), (8760392, 'blx r3'), (8760476, 'blx r2'), (8760664, 'blx lr'), (8760740, 'bl loc.imp.objc_msgSend_stret'), (8760776, 'bl sym.imp.memset'), (8761016, 'bl sym.clamp_float__float__float_'), (8761116, 'bl loc.imp.objc_msgSend_stret'), (8761156, 'bl sym.imp.memset'), (8761272, 'blx r2'), (8761304, 'bl sym.imp.__wrap_fmodf'), (8761412, 'bl sym.clamp_float__float__float_'), (8761492, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8760400, 'bge', 8760416), (8760412, 'b', 8760484), (8760724, 'beq', 8760748), (8760744, 'b', 8760780), (8760792, 'bhi', 8760964), (8760868, 'b', 8760968), (8760896, 'b', 8760968), (8760924, 'b', 8760968), (8760960, 'b', 8760968), (8760964, 'b', 8760968), (8761040, 'ble', 8761440), (8761100, 'beq', 8761128), (8761120, 'b', 8761160), (8761168, 'beq', 8761440), (8761472, 'bne', 8761492)],
        semantics=('sandFractionForPos:height:highRes: computes the sand fraction: width = MAX(512, [world worldWidthMacro]) (the send is re-issued by the MAX macro at 0x0085ac9c, floor compared against 0x200 at 0x0085ac4c), X = (pos.x / 32.0f) / width (0x0085abec) and Y = ((pos.y - 0.5 * h) / 32.0f) / width * 4.0f (0x0085ac20 and the 4.0f factor). It samples noise = [self->sandNoiseFunction@44 getX:X Y:Y octaves:(highRes ? 11 : 4)] (0x0085ad58, r5 = 11 with moveq r5, 4 at 0x0085ad30) and narrows the double to float (vcvt.f32.f64 at 0x0085ad60). The [world customRules] byte +8 then selects a delta through the 5-entry jump table at 0x0085adf0 (cmp r0, 4 at 0x0085add0): 0 -> +1.0, 1 -> +0.6, 2 -> none, 3 -> -0.6, 4 -> 1.0 - value, > 4 -> none (0x0085ae14); the sum is clamped to [-1, 1] (clamp call at 0x0085aeb8) and a value <= 0 returns immediately (0x0085aed0). Otherwise, when the customRules byte +8 is non-zero, the value is scaled by weight = clamp((1 - |fmodf((pos.x/32)/width, 0.5) - 0.25| / 0.25) * 3.0 - 0.5, 0, 1) (__wrap_fmodf at 0x0085afd8, clamp_float at 0x0085b044) and the product is returned (0x0085b058).'),
    ),
    dict(
        name='wtl_isdesertforpos_height_',
        method='WorldTileLoader -[isDesertForPos:height:]',
        types='c20@0:4{?=ii}8i16',
        start=8761552,
        end=8761744,
        disasm='disasm_worldtileloader_isdesertforpos_height_.txt',
        base_add=8761624,
        base_literal=8761740,
        boundary='ARM.exidx end 0x0085b190 (listing bound); next ObjC IMP 0x0085b190 WorldTileLoader -[isBeachForPos:height:]',
        selectors={
                 0x85b188: (15213592, 'sandFractionForPos:height:highRes:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(8761552, 'push {r4, sl, fp, lr}'), (8761568, 'vldr d0, [0x0085b180]'), (8761644, 'mov r4, 1'), (8761672, 'bl loc.imp.objc_msgSend'), (8761688, 'vcvt.f64.f32 d0, s2'), (8761708, 'movgt r0, 1'), (8761740, 'ldrdeq r4, r5, [r0], r4')],
        calls=[(8761672, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('isDesertForPos:height: = ([self sandFractionForPos:pos height:height highRes:YES] > 0.3). The body loads the double 0.3 from the pool (vldr d0, [0x0085b180] at 0x0085b0e0), dispatches the sand-fraction selector (cell 0x0085b188) with highRes = 1 (mov r4, 1 at 0x0085b12c, stack argument stored at 0x0085b130), converts the returned float to double (vmov s2, r0 at 0x0085b14c, vcvt.f64.f32 at 0x0085b158) and returns the comparison result (vcmpe.f64 at 0x0085b160, movgt r0, 1 at 0x0085b16c, sxtb at 0x0085b174). No ivar is touched.'),
    ),
    dict(
        name='wtl_isbeachforpos_height_',
        method='WorldTileLoader -[isBeachForPos:height:]',
        types='c20@0:4{?=ii}8i16',
        start=8761744,
        end=8762496,
        disasm='disasm_worldtileloader_isbeachforpos_height_.txt',
        base_add=8761760,
        base_literal=8762488,
        boundary='ARM.exidx end 0x0085b480 (listing bound); next ObjC IMP 0x0085b480 WorldTileLoader -[isDesertOrBeachForPos:height:]',
        selectors={
                 0x85b460: (15213480, 'worldWidthMacro'),
                 0x85b470: (15213600, 'getX:Y:octaves:'),
        },
        imports={
                 0x85b45c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x85b464: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85b474: (17161600, 'OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction', 44),
        },
        classes={},
        instructions=[(8761744, 'push {r4, r5, r6, sl, fp, lr}'), (8761804, 'add r1, r1, 0x1f0'), (8761848, 'add r0, r0, 0x210'), (8761928, 'vdiv.f32 s4, s4, s0'), (8762044, 'vsub.f64 d1, d1, d3'), (8762336, 'str r4, [sp, 8]'), (8762352, 'blx ip'), (8762420, 'vadd.f32 s2, s2, s8'), (8762436, 'movmi r0, 1'), (8762492, 'andeq r0, r0, r0')],
        calls=[(8761988, 'blx lr'), (8762096, 'blx r3'), (8762180, 'blx r2'), (8762352, 'blx ip')],
        branches=[(8761816, 'bge', 8761832), (8761828, 'b', 8762448), (8761856, 'ble', 8761872), (8761868, 'b', 8762448), (8761872, 'b', 8761876), (8762104, 'bge', 8762120), (8762116, 'b', 8762188)],
        semantics=('isBeachForPos:height: answers from the height band first: (float)Y < 1008 - H returns YES (512 - H + 0x1f0 at 0x0085b1cc, movw r0, 1 at 0x0085b1dc) and (float)Y > 1040 - H returns NO (512 - H + 0x210 at 0x0085b1f8, movw r0, 0 at 0x0085b204). Otherwise it samples noise: nx = ((float)X / 32.0f) / [world worldWidthMacro] (0x0085b248/0x0085b284) and ny = (((double)Y - 0.5 * H) / 32.0) / MAX(worldWidth, 512) * 4.0f (0x0085b2bc, 0x0085b2f4, 0x0085b394/0x0085b398), then dispatches [self->sandNoiseFunction@44 getX:nx Y:ny octaves:11] (0x0085b3f0, octaves 11 at 0x0085b3e0) and returns (float)Y < 512.0f - noise * 16.0f + (512 - H) = 1024 - 16 * noise - H (vadd.f32 at 0x0085b434, vcmpe at 0x0085b438, movmi r0, 1 at 0x0085b444). The 1008/1040 early-outs span exactly +/-16 around 1024 - H, consistent with the 16.0f noise weight.'),
    ),
    dict(
        name='wtl_isdesertorbeachforpos_',
        method='WorldTileLoader -[isDesertOrBeachForPos:height:]',
        types='c20@0:4{?=ii}8i16',
        start=8762496,
        end=8762800,
        disasm='disasm_worldtileloader_isdesertorbeachforpos_height_.txt',
        base_add=8762568,
        base_literal=8762788,
        boundary='ARM.exidx end 0x0085b5b0 (listing bound); next ObjC IMP 0x0085b5b0 WorldTileLoader -[fillDirtTile:worldPos:worldDirtHeight:parentType:]',
        selectors={
                 0x85b5a0: (15213596, 'isBeachForPos:height:'),
                 0x85b5a8: (15213592, 'sandFractionForPos:height:highRes:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(8762496, 'push {r4, sl, fp, lr}'), (8762608, 'bl loc.imp.objc_msgSend'), (8762628, 'bne 0x85b580'), (8762632, 'vldr d0, [0x0085b598]'), (8762716, 'bl loc.imp.objc_msgSend'), (8762744, 'movgt r0, 1'), (8762796, 'addeq r4, r0, r0, asr 11')],
        calls=[(8762608, 'bl loc.imp.objc_msgSend'), (8762716, 'bl loc.imp.objc_msgSend')],
        branches=[(8762628, 'bne', 8762752)],
        semantics=('isDesertOrBeachForPos:height: = [self isBeachForPos:pos height:height] ? YES : ([self sandFractionForPos:pos height:height highRes:YES] > 0.3). The first dispatch (selector cell 0x0085b5a0) at 0x0085b4f0 is sxtb-tested and a non-zero result takes the early return at 0x0085b504/0x0085b580 (r0 = 1); otherwise the second dispatch (cell 0x0085b5a8) at 0x0085b55c is compared against the double 0.3 (a separate pool copy at 0x0085b598, vldr at 0x0085b508, vcmpe.f64 at 0x0085b56c, movgt 1 at 0x0085b578). Both thresholds carry the same value (0.3) from two different pool copies.'),
    ),
    dict(
        name='wtl_filldirttile_worldpos_',
        method='WorldTileLoader -[fillDirtTile:worldPos:worldDirtHeight:parentType:]',
        types='v28@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12i20i24',
        start=8762800,
        end=8765972,
        disasm='disasm_worldtileloader_filldirttile_worldpos_worlddirtheight_pa.txt',
        base_add=8762816,
        base_literal=8765968,
        boundary='ARM.exidx end 0x0085c214 (listing bound); next ObjC IMP 0x0085c214 WorldTileLoader -[recursivelyFlowOutWaterFromTile:atPos:]',
        selectors={
                 0x85c1d0: (15213480, 'worldWidthMacro'),
                 0x85c1dc: (15213592, 'sandFractionForPos:height:highRes:'),
                 0x85c1e4: (15213596, 'isBeachForPos:height:'),
                 0x85c1f0: (15213556, 'customRules'),
                 0x85c1f4: (15213600, 'getX:Y:octaves:'),
                 0x85c1fc: (15213716, 'expertMode'),
        },
        imports={
                 0x85c1b8: (17151968, '__stack_chk_guard'),
                 0x85c1cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x85c1c0: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x85c1c8: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x85c1d4: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85c1f8: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x85c208: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
        },
        classes={},
        instructions=[(8762800, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8763056, 'strb r0, [fp, -0xc9]'), (8763168, 'bge 0x85b730'), (8763636, 'bl loc.imp.objc_msgSend'), (8763660, 'vcmpe.f64 d0, d4'), (8763752, 'bl loc.imp.objc_msgSend'), (8764000, 'strb r0, [r1]'), (8764588, 'blx lr'), (8764720, 'ldrsb r0, [fp, -0x51]'), (8764956, 'blx r2'), (8765064, 'strb r0, [r1, 3]'), (8765684, 'strb r0, [r1]'), (8765724, 'blt 0x85c184'), (8765968, 'addeq r4, r0, ip, lsr 10')],
        calls=[(8763320, 'blx r4'), (8763428, 'blx r3'), (8763512, 'blx r2'), (8763636, 'bl loc.imp.objc_msgSend'), (8763752, 'bl loc.imp.objc_msgSend'), (8764200, 'blx r4'), (8764308, 'blx r3'), (8764404, 'blx r2'), (8764588, 'blx lr'), (8764680, 'bl loc.imp.objc_msgSend_stret'), (8764716, 'bl sym.imp.memset'), (8764824, 'bl loc.imp.objc_msgSend_stret'), (8764860, 'bl sym.imp.memset'), (8764956, 'blx r2'), (8765264, 'blx r4'), (8765372, 'blx r3'), (8765464, 'blx r2'), (8765640, 'blx lr'), (8765864, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8762944, 'beq', 8763048), (8762964, 'beq', 8763048), (8762984, 'beq', 8763048), (8763004, 'beq', 8763048), (8763024, 'beq', 8763048), (8763068, 'bne', 8763792), (8763168, 'bge', 8763184), (8763180, 'b', 8763192), (8763436, 'bge', 8763452), (8763448, 'b', 8763520), (8763668, 'ble', 8763684), (8763680, 'b', 8763784), (8763764, 'beq', 8763780), (8763780, 'b', 8763784), (8763784, 'b', 8763916), (8763808, 'beq', 8763852), (8763828, 'beq', 8763852), (8763880, 'beq', 8763904), (8763924, 'beq', 8763992), (8763936, 'beq', 8763964), (8763960, 'b', 8763984), (8763984, 'b', 8764012), (8764020, 'bne', 8765076), (8764032, 'beq', 8764452), (8764316, 'bge', 8764344), (8764328, 'b', 8764412), (8764664, 'beq', 8764688), (8764684, 'b', 8764720), (8764728, 'bne', 8764752), (8764748, 'b', 8764896), (8764808, 'beq', 8764832), (8764828, 'b', 8764864), (8764872, 'bne', 8764892), (8764892, 'b', 8764896), (8764968, 'beq', 8765000), (8765016, 'ble', 8765036), (8765032, 'b', 8765072), (8765052, 'bpl', 8765068), (8765068, 'b', 8765072), (8765072, 'b', 8765076), (8765084, 'beq', 8765700), (8765096, 'beq', 8765512), (8765380, 'bge', 8765404), (8765392, 'b', 8765472), (8765672, 'ble', 8765696), (8765696, 'b', 8765700), (8765708, 'bne', 8765828), (8765724, 'blt', 8765828), (8765744, 'bne', 8765828), (8765804, 'bge', 8765828), (8765852, 'bne', 8765864)],
        semantics=('fillDirtTile:worldPos:worldDirtHeight:parentType: fills the passed Tile* (r2) during terrain generation. It tests whether parentType is one of {6, 7, 8, 27, 28, 58} (0x0085b6b0): when it is, the block id is inherited rather than computed (7 when parentType is in {7, 8, 58}, 8 when in {8, 58}, else 6; 0x0085b990..0x0085ba08). Otherwise it takes H = max(rockHeights@96[x], dirtHeights@92[x]) (0x0085b6e4/0x0085b720) and dispatches [self sandFractionForPos:{x,y} height:H highRes:1] (0x0085b8f4): the id becomes 7 when the fraction > 0.3 (double 0x3FD3333333333333 at 0x0085bbb0, vcmpe 0x0085b90c), otherwise 8 when [self isBeachForPos:{x,y} height:H] answers (0x0085b968), otherwise 6. tile[0] and tile[1] both receive that id (0x0085ba2c/0x0085ba44/0x0085ba60); byte 2 is never written here. Dirt tiles then sample [self.flintDensityNoiseFunction@36 getX:fracA Y:fracB octaves:3] (0x0085bcac) and store tile[3] = 1 above the high threshold and 2 below the low one (0x0085be64/0x0085be88); fracA = (x/32)/[world worldWidthMacro] and fracB = 4 * ((y - 0.5*H)/32) / MAX(512, [world worldWidthMacro]). Thresholds are 0.5 / -0.6 by default, 0.75 / -0.8 when customRules byte 15 == 1 (0x0085bd30), 0.125 / -0.15 when it is 3, and both are halved when [world expertMode] (0x0085be1c). Beach tiles re-sample the noise with fracA*0.0625, fracB*0.625 (0x0085c0c8) and overwrite tile[0]/tile[1] with block 58 when the result > 0.4f (0x0085c0f4, pool 0x0085c204). Finally a dirt tile with y >= 511, y == worldDirtHeight-1 and lakeHeights@100[x] < worldDirtHeight becomes 27 (0x0085c11c/0x0085c170).'),
    ),
    dict(
        name='wtl_recursivelyflowoutwate',
        method='WorldTileLoader -[recursivelyFlowOutWaterFromTile:atPos:]',
        types='v20@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12',
        start=8765972,
        end=8766744,
        disasm='disasm_worldtileloader_recursivelyflowoutwaterfromtile_atpos_.txt',
        base_add=8765988,
        base_literal=8766740,
        boundary='ARM.exidx end 0x0085c518 (listing bound); next ObjC IMP 0x0085c518 WorldTileLoader -[recursivelyFlowOutDirtFromTile:atPos:]',
        selectors={
                 0x85c504: (15213616, 'recursivelyFlowOutWaterFromTile:atPos:'),
        },
        imports={},
        ivars={
                 0x85c500: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        classes={},
        instructions=[(8765972, 'push {fp, lr}'), (8766036, 'bl sym.makeIntpair_int__int_'), (8766088, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766120, 'cmp r0, 2'), (8766136, 'cmp r0, 1'), (8766152, 'strb r1, [r0]'), (8766176, 'strb r1, [r0, 7]'), (8766236, 'bl loc.imp.objc_msgSend'), (8766740, 'addeq r3, r0, r8, asr 17')],
        calls=[(8766036, 'bl sym.makeIntpair_int__int_'), (8766088, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766236, 'bl loc.imp.objc_msgSend'), (8766256, 'bl sym.makeIntpair_int__int_'), (8766324, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766472, 'bl loc.imp.objc_msgSend'), (8766492, 'bl sym.makeIntpair_int__int_'), (8766560, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766708, 'bl loc.imp.objc_msgSend')],
        branches=[(8766108, 'beq', 8766240), (8766124, 'bne', 8766240), (8766140, 'bne', 8766240), (8766344, 'beq', 8766476), (8766360, 'bne', 8766476), (8766376, 'bne', 8766476), (8766580, 'beq', 8766712), (8766596, 'bne', 8766712), (8766612, 'bne', 8766712)],
        semantics=('recursivelyFlowOutWaterFromTile:atPos: is a depth-first flood fill from the argument tile over water-like neighbours: (x, y-1), (x+1, y) and (x-1, y) - (x, y+1) is never visited. Each neighbour comes from tileAtWorldPositionLoaded(a, b, self->world@4) (0x0085c288/0x0085c374/0x0085c460, coordinates built by makeIntpair at 0x0085c254/0x0085c330/0x0085c41c) and is accepted only when its byte0 == 2 (cmp at 0x0085c2a8) and byte2 == 1 (cmp at 0x0085c2b8); an accepted tile is rewritten in place - byte0 = 3 (0x0085c2c8), byte4 = 0xff (0x0085c2d4), byte7 = 0 (0x0085c2e0) - and the method recurses on it (self-recursive objc_msgSend at 0x0085c31c, selector cell 0x0085c504). The Tile byte field names are not in the listing; only the tested/written offsets are.'),
    ),
    dict(
        name='wtl_recursivelyflowoutdirt',
        method='WorldTileLoader -[recursivelyFlowOutDirtFromTile:atPos:]',
        types='v20@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12',
        start=8766744,
        end=8769120,
        disasm='disasm_worldtileloader_recursivelyflowoutdirtfromtile_atpos_.txt',
        base_add=8766760,
        base_literal=8769112,
        boundary='ARM.exidx end 0x0085ce60 (listing bound); next ObjC IMP 0x0085ce60 WorldTileLoader -[placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:]',
        selectors={
                 0x85ce1c: (15213720, 'fillDirtTile:worldPos:worldDirtHeight:parentType:'),
                 0x85ce24: (15213724, 'recursivelyFlowOutDirtFromTile:atPos:'),
                 0x85ce2c: (15213480, 'worldWidthMacro'),
        },
        imports={},
        ivars={
                 0x85ce18: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
        },
        classes={},
        instructions=[(8766744, 'push {r4, r5, r6, r7, fp, lr}'), (8766808, 'b 0x85ce10'), (8766888, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766952, 'cmp r0, 1'), (8767028, 'movt r1, 0x5f5'), (8767052, 'bl loc.imp.objc_msgSend'), (8767108, 'bl loc.imp.objc_msgSend'), (8767112, 'bl 0x8540cc'), (8767236, 'lsl r0, r0, 5'), (8767272, 'ble 0x85c868'), (8768720, 'ble 0x85ce10'), (8769116, 'andeq r0, r0, r0')],
        calls=[(8766836, 'bl sym.makeIntpair_int__int_'), (8766888, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8767052, 'bl loc.imp.objc_msgSend'), (8767108, 'bl loc.imp.objc_msgSend'), (8767112, 'bl 0x8540cc'), (8767136, 'bl 0x8540cc'), (8767228, 'bl loc.imp.objc_msgSend'), (8767296, 'bl sym.makeIntpair_int__int_'), (8767364, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8767528, 'bl loc.imp.objc_msgSend'), (8767584, 'bl loc.imp.objc_msgSend'), (8767656, 'bl loc.imp.objc_msgSend'), (8767736, 'bl loc.imp.objc_msgSend'), (8767804, 'bl sym.makeIntpair_int__int_'), (8767872, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8768036, 'bl loc.imp.objc_msgSend'), (8768092, 'bl loc.imp.objc_msgSend'), (8768168, 'bl loc.imp.objc_msgSend'), (8768236, 'bl sym.makeIntpair_int__int_'), (8768304, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8768468, 'bl loc.imp.objc_msgSend'), (8768524, 'bl loc.imp.objc_msgSend'), (8768596, 'bl loc.imp.objc_msgSend'), (8768676, 'bl loc.imp.objc_msgSend'), (8768744, 'bl sym.makeIntpair_int__int_'), (8768812, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8768976, 'bl loc.imp.objc_msgSend'), (8769032, 'bl loc.imp.objc_msgSend')],
        branches=[(8766804, 'bge', 8766820), (8766808, 'b', 8769040), (8766908, 'beq', 8767112), (8766924, 'beq', 8766944), (8766940, 'bne', 8767112), (8766956, 'bne', 8767112), (8767172, 'bge', 8767256), (8767272, 'ble', 8767592), (8767384, 'beq', 8767588), (8767400, 'beq', 8767420), (8767416, 'bne', 8767588), (8767432, 'bne', 8767588), (8767588, 'b', 8767592), (8767680, 'blt', 8767764), (8767780, 'ble', 8768100), (8767892, 'beq', 8768096), (8767908, 'beq', 8767928), (8767924, 'bne', 8768096), (8767940, 'bne', 8768096), (8768096, 'b', 8768100), (8768112, 'bge', 8768196), (8768212, 'ble', 8768532), (8768324, 'beq', 8768528), (8768340, 'beq', 8768360), (8768356, 'bne', 8768528), (8768372, 'bne', 8768528), (8768528, 'b', 8768532), (8768620, 'blt', 8768704), (8768720, 'ble', 8769040), (8768832, 'beq', 8769036), (8768848, 'beq', 8768868), (8768864, 'bne', 8769036), (8768880, 'bne', 8769036), (8769036, 'b', 8769040)],
        semantics=('recursivelyFlowOutDirtFromTile:atPos: is the recursive dirt redistributor: pos.y < 1 returns at once (0x0085c558). For the row above it probes (x, y-1) with tileAtWorldPositionLoaded(x, y-1, self->world@4) (0x0085c5a8): when the neighbour exists and its byte0 is 2 or 3 (0x0085c5c8/0x0085c5d8) with byte2 == 1 (0x0085c5e8) it sends [self fillDirtTile:t worldPos:{x,y-1} worldDirtHeight:99999999 (0x5f5e0ff, movt 0x5f5 at 0x0085c634) parentType:parentTile->byte0] (0x0085c64c) and then recurses with [self recursivelyFlowOutDirtFromTile:t atPos:{x,y-1}] (0x0085c684). It then draws f1, f2 = (float)lrand48() / 2147483648.0f from the four-instruction lrand48 wrapper at 0x8540cc (0x0085c688/0x0085c68c) and wraps x into [0, worldWidthMacro << 5) (0x0085c704 plus the four corrections). The same probe + fill + recurse triple runs on (x-1, y-1) when f1 > 0.7 (0.7f at 0x0085c560, gate 0x0085c728), on (x+1, y-1) when f2 > 0.7, on (x-2, y-1) when f1 > 0.9 (0.9f at 0x0085ce44, gate 0x0085ccd0) and on (x+2, y-1) when f2 > 0.9 - 30% per adjacent column, 10% per two-away column, always one row up. The `movw r0, 5` written before each worldWidthMacro send (0x0085c6c8 and siblings) lands in a stack slot that is never read back, i.e. a dead spill (the same shape recurs in the sibling bodies).'),
    ),
    dict(
        name='wtl_placegemsincaveforphys',
        method='WorldTileLoader -[placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:]',
        types='v28@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8i12i16i20i24',
        start=8769120,
        end=8775344,
        disasm='disasm_worldtileloader_placegemsincaveforphysicalblock_tileinde.txt',
        base_add=8769140,
        base_literal=8772776,
        boundary='ARM.exidx end 0x0085e6b0 (listing bound); next ObjC IMP 0x0085e6b0 WorldTileLoader -[loadPhysicalBlock:atXPos:yPos:createIfNotCreated:]',
        selectors={
                 0x85df6c: (15213728, 'isFloatingIslandCaveForX:y:'),
                 0x85df70: (15213576, 'isCaveForX:y:faultOffset:'),
                 0x85df74: (15213572, 'faultOffsetForX:y:'),
                 0x85df7c: (15213600, 'getX:Y:octaves:'),
                 0x85e100: (15213600, 'getX:Y:octaves:'),
                 0x85e114: (15213716, 'expertMode'),
                 0x85e124: (15213556, 'customRules'),
                 0x85e2a0: (15213556, 'customRules'),
                 0x85e670: (15213600, 'getX:Y:octaves:'),
                 0x85e67c: (15213556, 'customRules'),
        },
        imports={
                 0x85dcb0: (17151968, '__stack_chk_guard'),
                 0x85dd00: (17151904, 'objc_msgSend'),
                 0x85df68: (17151904, 'objc_msgSend'),
                 0x85e668: (17151968, '__stack_chk_guard'),
                 0x85e66c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x85dcac: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x85df80: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x85e104: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x85e108: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x85e10c: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85e674: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x85e678: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x85e684: (17161616, 'OBJC_IVAR_$_WorldTileLoader.gemNoiseFunction', 60),
        },
        classes={},
        instructions=[(8769120, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8769268, 'vadd.f32 s4, s6, s4'), (8769356, 'cmp r1, 0'), (8769432, 'blx ip'), (8769596, 'blx lr'), (8769616, 'bne 0x85d8f0'), (8769756, 'blx r4'), (8769984, 'bl loc.imp.objc_msgSend'), (8770140, 'bl loc.imp.objc_msgSend_stret'), (8770248, 'strb r0, [r2]'), (8771676, 'movw r0, 0x5e'), (8771888, 'strb r6, [r5, r4, lsl 6]'), (8772016, 'beq 0x85e610'), (8772040, 'movw r0, 0x3a'), (8773544, 'strb r0, [r2, 0xb]'), (8775340, 'andeq r0, r0, r0')],
        calls=[(8769432, 'blx ip'), (8769552, 'blx ip'), (8769596, 'blx lr'), (8769756, 'blx r4'), (8769984, 'bl loc.imp.objc_msgSend'), (8770140, 'bl loc.imp.objc_msgSend_stret'), (8770188, 'bl sym.imp.memset'), (8770564, 'blx r4'), (8770656, 'bl loc.imp.objc_msgSend_stret'), (8770724, 'bl sym.imp.memset'), (8770808, 'blx r2'), (8770968, 'bl loc.imp.objc_msgSend_stret'), (8771012, 'bl sym.imp.memset'), (8771160, 'bl loc.imp.objc_msgSend_stret'), (8771196, 'bl sym.imp.memset'), (8771368, 'bl loc.imp.objc_msgSend_stret'), (8771412, 'bl sym.imp.memset'), (8771964, 'bl loc.imp.objc_msgSend_stret'), (8772000, 'bl sym.imp.memset'), (8772340, 'blx lr'), (8772472, 'bl loc.imp.objc_msgSend_stret'), (8772508, 'bl sym.imp.memset'), (8772620, 'bl loc.imp.objc_msgSend_stret'), (8772656, 'bl sym.imp.memset'), (8772768, 'bl loc.imp.objc_msgSend_stret'), (8772896, 'bl sym.imp.memset'), (8773128, 'blx r4'), (8773416, 'blx lr'), (8773824, 'blx lr'), (8774240, 'blx lr'), (8774640, 'blx lr'), (8775032, 'blx lr'), (8775228, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8769368, 'beq', 8769444), (8769440, 'b', 8769604), (8769616, 'bne', 8771824), (8769780, 'beq', 8769804), (8769800, 'b', 8769848), (8769904, 'beq', 8770068), (8770044, 'ble', 8770264), (8770064, 'bpl', 8770264), (8770124, 'beq', 8770160), (8770144, 'b', 8770192), (8770200, 'bne', 8770260), (8770220, 'bne', 8770256), (8770256, 'b', 8770260), (8770260, 'b', 8771820), (8770640, 'beq', 8770696), (8770660, 'b', 8770728), (8770736, 'bne', 8770748), (8770820, 'beq', 8770840), (8770952, 'beq', 8770984), (8770972, 'b', 8771016), (8771024, 'bne', 8771088), (8771084, 'b', 8771464), (8771144, 'beq', 8771168), (8771164, 'b', 8771200), (8771212, 'bne', 8771296), (8771280, 'b', 8771460), (8771352, 'beq', 8771384), (8771372, 'b', 8771416), (8771428, 'bne', 8771456), (8771456, 'b', 8771460), (8771460, 'b', 8771464), (8771496, 'bpl', 8771512), (8771508, 'b', 8771520), (8771552, 'ble', 8771816), (8771572, 'bpl', 8771816), (8771652, 'ble', 8771756), (8771672, 'ble', 8771712), (8771708, 'b', 8771744), (8771744, 'b', 8771812), (8771772, 'ble', 8771808), (8771808, 'b', 8771812), (8771812, 'b', 8771816), (8771816, 'b', 8771820), (8771820, 'b', 8771824), (8771836, 'bne', 8775188), (8771948, 'beq', 8771972), (8771968, 'b', 8772004), (8772016, 'beq', 8775184), (8772036, 'bne', 8772052), (8772048, 'b', 8772160), (8772060, 'bne', 8772076), (8772072, 'b', 8772156), (8772084, 'bne', 8772100), (8772096, 'b', 8772152), (8772108, 'bne', 8772124), (8772120, 'b', 8772148), (8772132, 'bne', 8772144), (8772144, 'b', 8772148), (8772148, 'b', 8772152), (8772152, 'b', 8772156), (8772156, 'b', 8772160), (8772196, 'beq', 8772220), (8772216, 'b', 8772352), (8772376, 'beq', 8772400), (8772396, 'b', 8772540), (8772456, 'beq', 8772480), (8772476, 'b', 8772512), (8772604, 'beq', 8772628), (8772624, 'b', 8772660), (8772672, 'bne', 8772696), (8772692, 'b', 8772944), (8772752, 'beq', 8772868), (8772772, 'b', 8772900), (8772912, 'bne', 8772940), (8772940, 'b', 8772944), (8772956, 'ble', 8775180), (8773192, 'ble', 8773556), (8773212, 'bpl', 8773556), (8773224, 'bne', 8773264), (8773260, 'bpl', 8773556), (8773448, 'bpl', 8773552), (8773464, 'beq', 8773508), (8773476, 'b', 8773520), (8773516, 'b', 8773520), (8773552, 'b', 8773556), (8773604, 'ble', 8773976), (8773624, 'bpl', 8773976), (8773636, 'bne', 8773672), (8773668, 'bpl', 8773976), (8773856, 'bpl', 8773972), (8773872, 'beq', 8773928), (8773884, 'b', 8773940), (8773936, 'b', 8773940), (8773972, 'b', 8773976), (8774024, 'ble', 8774376), (8774044, 'bpl', 8774376), (8774056, 'bne', 8774092), (8774088, 'bpl', 8774376), (8774272, 'bpl', 8774372), (8774288, 'beq', 8774328), (8774300, 'b', 8774340), (8774336, 'b', 8774340), (8774372, 'b', 8774376), (8774424, 'ble', 8774768), (8774444, 'bpl', 8774768), (8774456, 'bne', 8774488), (8774484, 'bpl', 8774768), (8774672, 'bpl', 8774764), (8774688, 'beq', 8774720), (8774700, 'b', 8774732), (8774728, 'b', 8774732), (8774764, 'b', 8774768), (8774816, 'ble', 8775176), (8774836, 'bpl', 8775176), (8774848, 'bne', 8774884), (8774880, 'bpl', 8775176), (8775064, 'bpl', 8775172), (8775080, 'beq', 8775128), (8775092, 'b', 8775140), (8775136, 'b', 8775140), (8775172, 'b', 8775176), (8775176, 'b', 8775180), (8775180, 'b', 8775184), (8775184, 'b', 8775188), (8775212, 'bne', 8775228)],
        semantics=('placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType: stamps ore/gem bytes into one terrain tile (physicalBlock->tiles@8 + tileIndex*64). Normalisation: nx = ((float)worldX + 1453.0f)/32.0f/self->yHeightDivider@244 ([sp,0x268]) and ny = ((float)worldY + 1247.0f)/32.0f/yHeightDivider ([sp,0x264]) with the f32 pool 32.0 (0x0085d264), 1247.0 (0x0085d268) and 1453.0 (0x0085d26c). The cave predicate is chosen on floatingIslandType (cmp at 0x0085cf4c): non-zero dispatches [self isFloatingIslandCaveForX:worldX y:worldY-1] (0x0085cf98), zero dispatches [self faultOffsetForX:y:] (0x0085d010) and feeds it to [self isCaveForX:y:faultOffset:] (0x0085d03c); the BOOL lands at [sp,0x262]. The cave branch jumps straight to the gem body; the non-cave branch (0x0085d054) samples self->flintDensityNoiseFunction@36 through getX:Y:octaves: (0x0085d0dc, fractions nx*1.423 / ny*1.4536), reads [self->world@4 expertMode] (0x0085d1c0) to pick the 0.11 / 0.22 factor (pool 0x0085d5a0/0x0085d5a4) and the 64-byte [world customRules] struct (objc_msgSend_stret at 0x0085d25c, byte0 tested 0x0085d290), then writes the tile: byte0 = 16 when floatingIslandType == 0 (0x0085d2c8), otherwise byte0 = 2 (0x0085d818), byte4 = 0 and byte3 in {0x5e, 0x91, 0x90} (0x0085d85c/0x0085d880/0x0085d8c0). The gem body (0x0085d900) sets byte0 = 2 and byte4 = 0 (0x0085d930/0x0085d944) and returns early unless customRules byte 0x11 != 0 (0x0085d9b0); floatingIslandType 1..5 maps to gem ids {0x3a, 0x38, 0x36, 0x34, 0x3c} (0x0085d9c8..0x0085da28) and five band tests sample self->gemNoiseFunction@60 (cell 0x0085e684) through getX:Y:octaves:, writing the gem id or the branch fallback into tiles[tileIndex].byte0xb (0x0085dfa8 plus four siblings). Stack canary checked at 0x0085e614. The numeric block/gem ids are measured bytes; no game-side name table is asserted here.'),
    ),
    dict(
        name='wtl_findbeststartposition',
        method='WorldTileLoader -[findBestStartPosition]',
        types='{?=ii}8@0:4',
        start=8798600,
        end=8802420,
        disasm='disasm_worldtileloader_findbeststartposition.txt',
        base_add=8798616,
        base_literal=8802416,
        boundary='ARM.exidx end 0x00865074 (listing bound); next ObjC IMP 0x00865074 WorldTileLoader -[distanceOrderedFoodTypes]',
        selectors={
                 0x865014: (15213480, 'worldWidthMacro'),
                 0x86504c: (15213556, 'customRules'),
                 0x86505c: (15213780, 'isDesertOrBeachForPos:height:'),
                 0x865064: (15213784, 'unmodifiedGroundLevelForX:'),
        },
        imports={
                 0x865008: (17151968, '__stack_chk_guard'),
                 0x86502c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x865010: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x865040: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
                 0x865048: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x865054: (17161572, 'OBJC_IVAR_$_WorldTileLoader.lakeHeights', 100),
        },
        classes={},
        instructions=[(8798600, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8798752, 'lsl r0, r0, 5'), (8798780, 'bl sym.imp.__modsi3'), (8798912, 'vldr d0, [0x008644f8]'), (8799348, 'vmov.f64 d0, 9'), (8800452, 'ldr r1, [r2, r1, lsl 2]'), (8800584, 'bl sym.makeIntpair_int__int_'), (8800664, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_'), (8800788, 'ldrsb r0, [fp, -0x5d]'), (8801036, 'blt 0x864cbc'), (8801084, 'bl 0x8540fc'), (8801168, 'bl loc.imp.objc_msgSend'), (8801628, 'bge 0x864e7c'), (8801920, 'str r0, [fp, -0x17c]'), (8801972, 'mvn r0, 0'), (8802416, 'rsbseq fp, pc, r4, asr sb')],
        calls=[(8798696, 'bl 0x8540cc'), (8798744, 'bl loc.imp.objc_msgSend'), (8798780, 'bl sym.imp.__modsi3'), (8798884, 'bl loc.imp.objc_msgSend'), (8799000, 'bl loc.imp.objc_msgSend'), (8799012, 'bl sym.imp.__modsi3'), (8799060, 'bl loc.imp.objc_msgSend'), (8799180, 'bl loc.imp.objc_msgSend'), (8799300, 'bl loc.imp.objc_msgSend'), (8799420, 'bl loc.imp.objc_msgSend'), (8799604, 'bl loc.imp.objc_msgSend'), (8799628, 'bl sym.imp.__aeabi_idiv'), (8799676, 'blx ip'), (8799684, 'bl sym.imp.__aeabi_idiv'), (8799824, 'bl loc.imp.objc_msgSend'), (8799848, 'bl sym.imp.__aeabi_idiv'), (8799896, 'blx ip'), (8799904, 'bl sym.imp.__aeabi_idiv'), (8800052, 'bl loc.imp.objc_msgSend'), (8800076, 'bl sym.imp.__aeabi_idiv'), (8800132, 'blx ip'), (8800140, 'bl sym.imp.__aeabi_idiv'), (8800288, 'bl loc.imp.objc_msgSend'), (8800312, 'bl sym.imp.__aeabi_idiv'), (8800368, 'blx ip'), (8800376, 'bl sym.imp.__aeabi_idiv'), (8800584, 'bl sym.makeIntpair_int__int_'), (8800664, 'bl sym.baseTemperatureForWorldPos_intpair__float__float__float__World_'), (8800748, 'bl loc.imp.objc_msgSend_stret'), (8800784, 'bl sym.imp.memset'), (8801084, 'bl 0x8540fc'), (8801124, 'bl sym.makeIntpair_int__int_'), (8801168, 'bl loc.imp.objc_msgSend'), (8801256, 'bl loc.imp.objc_msgSend_stret'), (8801292, 'bl sym.imp.memset'), (8801380, 'bl loc.imp.objc_msgSend_stret'), (8801416, 'bl sym.imp.memset'), (8801556, 'blx r3'), (8801564, 'bl sym.imp.__aeabi_idiv'), (8801704, 'bl loc.imp.objc_msgSend_stret'), (8801740, 'bl sym.imp.memset'), (8801844, 'bl loc.imp.objc_msgSend_stret'), (8801884, 'bl sym.imp.memset'), (8801996, 'bl sym.makeIntpair_int__int_'), (8802060, 'bl 0x8540cc'), (8802168, 'bl loc.imp.objc_msgSend'), (8802204, 'bl sym.imp.__modsi3'), (8802244, 'blx ip'), (8802268, 'bl sym.makeIntpair_int__int_'), (8802308, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8798908, 'bge', 8801960), (8799104, 'bmi', 8799468), (8799224, 'ble', 8799348), (8799344, 'bmi', 8799468), (8799464, 'ble', 8799488), (8799476, 'b', 8801944), (8799704, 'ble', 8799928), (8799924, 'blt', 8800400), (8800160, 'ble', 8800412), (8800396, 'bge', 8800412), (8800408, 'b', 8801944), (8800412, 'b', 8800416), (8800528, 'bge', 8800544), (8800540, 'b', 8800552), (8800732, 'beq', 8800756), (8800752, 'b', 8800788), (8800796, 'beq', 8800888), (8800832, 'ble', 8800872), (8800884, 'b', 8800972), (8800920, 'ble', 8800960), (8801024, 'bne', 8801468), (8801036, 'blt', 8801468), (8801052, 'ble', 8801468), (8801068, 'beq', 8801468), (8801092, 'bge', 8801468), (8801180, 'beq', 8801432), (8801240, 'beq', 8801264), (8801260, 'b', 8801296), (8801304, 'beq', 8801432), (8801364, 'beq', 8801388), (8801384, 'b', 8801420), (8801428, 'bne', 8801468), (8801440, 'bne', 8801452), (8801464, 'b', 8801936), (8801584, 'bge', 8801600), (8801596, 'b', 8801608), (8801628, 'bge', 8801916), (8801688, 'beq', 8801712), (8801708, 'b', 8801744), (8801756, 'bne', 8801772), (8801768, 'bge', 8801916), (8801828, 'beq', 8801856), (8801848, 'b', 8801888), (8801900, 'bne', 8801928), (8801912, 'blt', 8801928), (8801924, 'b', 8801960), (8801956, 'b', 8798824), (8801968, 'bne', 8802004), (8802000, 'b', 8802272), (8802296, 'bne', 8802308)],
        semantics=('findBestStartPosition returns an intpair (two ints) through a hidden pointer in r0 (saved fp-0x1d8) after scanning for a spawn column. It takes a random start offset r = helper_0x8540cc() % (W*32) (lsl r0, r0, 5 at 0x00864220, __modsi3 at 0x0086423c, stored fp-0x16c) and sweeps x = (r+i) mod (W*32) for i = 0 .. W*32-1 (0x00864268..0x00864ea4). Per candidate it applies a band gate of [2W,14W] U [18W,30W] with the doubles 0.0625 (0x008644f8), 0.4375 (0x00864384), 0.5625 (0x008643fc) and 0.9375 (0x00864474) against [self->world worldWidthMacro]; reads dirtHeights@92[x] and rockHeights@96[x] and keeps ground = max (0x008648c4/0x008648e4); rejects lakeHeights@100[x] != 0, ground < 512 (0x00864b0c) and dirt <= rock; requires |prevGround - ground| < 2 through helper 0x8540fc (0x00864b3c) and a base temperature in (-10.0f, 40.0f) from baseTemperatureForWorldPos(intpair{x, dirt}, 0.25f, 0.25f, 0.0f, world) (0x00864998/0x00864a28/0x00864e3c), tightened to (-5.0f, 25.0f) when [world customRules] byte +3 == 2 (0x00864a14); it also requires NOT [self isDesertOrBeachForPos:{x, dirt-1} height:dirt] (0x00864b90), with customRules byte +8 == 1 or byte +2 in {3,4} overriding that test. An accepted-column streak (counter fp-0x174, first x fp-0x178) commits when it reaches min(256, W/2) (0x00864d5c) or 32/8 by rule byte +2; the committed x is (firstX + 4 + (rand()/2^31) * (streak-8)) mod (W*32) (0x00864e80) and y is [self unmodifiedGroundLevelForX:thatX]. When the sweep finds nothing the method returns (-1,-1) (mvn r0, 0 at 0x00864eb4).'),
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
        'batch': 'Terrain generation batch (E12): the WorldTileLoader material and shape bodies - the limestone/sandstone fraction pair, the sand fractions (high and low resolution), the desert / beach / desert-or-beach predicates, the floating-island cave test, fillDirtTile:worldPos:worldDirtHeight:parentType: (block-id choice and the flint tile[3] bands), the recursive dirt and water flow-out bodies, placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType: (the ore/gem stamping path) and findBestStartPosition (the spawn-column search); 13 bodies',
        'claim': ('static bounded-body maps with per-instruction anchors; the 64-byte world '
                  'customRules struct, the Tile byte field names, the noise function classes and '
                  'the game-side block/gem name tables are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'terrain_generation.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale trade_portal_econ.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
