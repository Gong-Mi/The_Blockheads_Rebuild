#!/usr/bin/env python3
"""Hash-gated recovery of the MJButton (E138).

MJButton lands: the batch sweeps mjbutton surface:
50 bodies, 6259 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/MJBUTTON.md for the prose and boundaries.
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
    'bl 0xd109bc': 0x00d109bc,
    'bl 0xd10be4': 0x00d10be4,
    'bl 0xd14f54': 0x00d14f54,
    'bl 0xd15514': 0x00d15514,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSendSuper2': 0x001c29fc,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDrawElements': 0x001c2df8,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.__wrap_glVertexAttribPointer': 0x001c2dec,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.imp.objc_copyStruct': 0x001c2888,
    'bl sym.imp.objc_setProperty_nonatomic': 0x001c2984,
}

SPECS = [
    dict(
        name='mj_00',
        method='MJButton -[.cxx_construct]',
        types='@8@0:4',
        start=13725748,
        end=13725772,
        disasm='disasm_worldtileloader_mj_00.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d1704c (listing bound); next ObjC IMP 0x00d170b0 SteamTrain -[loadDerivedStuff]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(13725748, 'sub sp, sp, 8'), (13725768, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[.cxx_construct]] (imp 0x00d17034, 6w): Empty Apportable .cxx_construct stub (0xd17034, 6 words): stores self, loads self, returns it - MJButton has no C++ member objects to construct..\n'),
    ),
    dict(
        name='mj_01',
        method='MJButton -[backgroundHighlightedSelectedTexture]',
        types='@8@0:4',
        start=13724284,
        end=13724344,
        disasm='disasm_worldtileloader_mj_01.txt',
        base_add=13724292,
        base_literal=13724340,
        boundary='ARM.exidx end 0x00d16ab8 (listing bound); next ObjC IMP 0x00d16ab8 MJButton -[setBackgroundHighlightedSelectedTexture:]',
        selectors={},
        imports={},
        ivars={
                 0xd16ab0: (17168196, 'OBJC_IVAR_$_MJButton.backgroundHighlightedSelectedTexture', 124),
        },
        classes={},
        instructions=[(13724284, 'sub sp, sp, 8'), (13724340, 'eorseq sb, r4, r8, rrx')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[backgroundHighlightedSelectedTexture]] (imp 0x00d16a7c, 15w): Getter -[backgroundHighlightedSelectedTexture] (0xd16a7c): Apportable offset-cell form (ldr cell 0xd16ab0 -> slot 0x0105f744 holds 124 -> self+0x7c); plain ldr return..\n'),
    ),
    dict(
        name='mj_02',
        method='MJButton -[backgroundHighlightedTexture]',
        types='@8@0:4',
        start=13724148,
        end=13724208,
        disasm='disasm_worldtileloader_mj_02.txt',
        base_add=13724156,
        base_literal=13724204,
        boundary='ARM.exidx end 0x00d16a30 (listing bound); next ObjC IMP 0x00d16a30 MJButton -[setBackgroundHighlightedTexture:]',
        selectors={},
        imports={},
        ivars={
                 0xd16a28: (17168200, 'OBJC_IVAR_$_MJButton.backgroundHighlightedTexture', 120),
        },
        classes={},
        instructions=[(13724148, 'sub sp, sp, 8'), (13724204, 'ldrshteq sb, [r4], -r0')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[backgroundHighlightedTexture]] (imp 0x00d169f4, 15w): Getter -[backgroundHighlightedTexture] (0xd169f4): same form; ivar @0x78 (offset 120)..\n'),
    ),
    dict(
        name='mj_03',
        method='MJButton -[backgroundSelectedTexture]',
        types='@8@0:4',
        start=13724012,
        end=13724072,
        disasm='disasm_worldtileloader_mj_03.txt',
        base_add=13724020,
        base_literal=13724068,
        boundary='ARM.exidx end 0x00d169a8 (listing bound); next ObjC IMP 0x00d169a8 MJButton -[setBackgroundSelectedTexture:]',
        selectors={},
        imports={},
        ivars={
                 0xd169a0: (17158048, 'OBJC_IVAR_$_MJButton.backgroundSelectedTexture', 116),
        },
        classes={},
        instructions=[(13724012, 'sub sp, sp, 8'), (13724068, 'eorseq sb, r4, r8, ror r1')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[backgroundSelectedTexture]] (imp 0x00d1696c, 15w): Getter -[backgroundSelectedTexture] (0xd1696c): same form; ivar @0x74 (offset 116)..\n'),
    ),
    dict(
        name='mj_04',
        method='MJButton -[backgroundTexture]',
        types='@8@0:4',
        start=13723876,
        end=13723936,
        disasm='disasm_worldtileloader_mj_04.txt',
        base_add=13723884,
        base_literal=13723932,
        boundary='ARM.exidx end 0x00d16920 (listing bound); next ObjC IMP 0x00d16920 MJButton -[setBackgroundTexture:]',
        selectors={},
        imports={},
        ivars={
                 0xd16918: (17158044, 'OBJC_IVAR_$_MJButton.backgroundTexture', 112),
        },
        classes={},
        instructions=[(13723876, 'sub sp, sp, 8'), (13723932, 'eorseq sb, r4, r0, lsl 4')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[backgroundTexture]] (imp 0x00d168e4, 15w): Getter -[backgroundTexture] (0xd168e4): same form; ivar @0x70 (offset 112)..\n'),
    ),
    dict(
        name='mj_05',
        method='MJButton -[createTitleBWithColor:]',
        types='v24@0:4{MJColor=ffff}8',
        start=13721884,
        end=13722776,
        disasm='disasm_worldtileloader_mj_05.txt',
        base_add=13721900,
        base_literal=13722772,
        boundary='ARM.exidx end 0x00d16498 (listing bound); next ObjC IMP 0x00d16498 MJButton -[setTitleB:color:]',
        selectors={
                 0xd16478: (15238340, 'alloc'),
                 0xd1648c: (15238344, 'standardFont'),
                 0xd16490: (15238348, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
        },
        imports={},
        ivars={
                 0xd16464: (17168252, 'OBJC_IVAR_$_MJButton.titleAlignmentB', 244),
                 0xd16468: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0xd1646c: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
                 0xd1647c: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0xd16480: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
                 0xd16484: (17168156, 'OBJC_IVAR_$_MJButton.titleB', 240),
        },
        classes={
                 0xd16474: (15251168, 'OBJC_CLASS_$_MJTextView'),
                 0xd16488: (15251172, 'OBJC_CLASS_$_BitmapFont'),
        },
        instructions=[(13721884, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13722772, 'eorseq sb, r4, r0, asr 19')],
        calls=[(13722360, 'bl 0xd109bc'), (13722384, 'bl loc.imp.objc_msgSend'), (13722536, 'bl loc.imp.objc_msgSend'), (13722692, 'bl loc.imp.objc_msgSend')],
        branches=[(13721996, 'bne', 13722064), (13722060, 'b', 13722244), (13722096, 'bne', 13722176), (13722172, 'b', 13722240), (13722208, 'bne', 13722236), (13722236, 'b', 13722240), (13722240, 'b', 13722244)],
        semantics=('[MJButton -[createTitleBWithColor:]] (imp 0x00d1611c, 223w): [read] -[createTitleBWithColor:] (0xd1611c): builds the B-title MJTextView. x offset by titleAlignmentB: 0 -> x+9.0, 1 -> x + 0.5*frame.width, 2 -> x + frame.width-9.0 (the 9/2/7 constants of the 2-arm are dead stores on the stack); rect = {x\', frame.y - frame.height/2 + 8.0, frame.width-4.0, frame.height} built through the 4-float writer 0xd109bc; then [MJTextView alloc] initWithFrame:rect cache:self.cache windowInfo:self.windowInfo string:self.titleB horizontalAlignment:self.titleAlignmentB font:[BitmapFont standardFont] color:color -> titleViewB..\n'),
    ),
    dict(
        name='mj_06',
        method='MJButton -[createTitleWithColor:]',
        types='v24@0:4{MJColor=ffff}8',
        start=13698624,
        end=13699516,
        disasm='disasm_worldtileloader_mj_06.txt',
        base_add=13698640,
        base_literal=13699512,
        boundary='ARM.exidx end 0x00d109bc (listing bound); next ObjC IMP 0x00d10a08 MJButton -[setTitleAlignment:]',
        selectors={
                 0xd1099c: (15238340, 'alloc'),
                 0xd109b0: (15238344, 'standardFont'),
                 0xd109b4: (15238348, 'initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color:'),
        },
        imports={},
        ivars={
                 0xd10988: (17168144, 'OBJC_IVAR_$_MJButton.titleAlignment', 104),
                 0xd1098c: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0xd10990: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd109a0: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0xd109a4: (17155636, 'OBJC_IVAR_$_MJView.windowInfo', 52),
                 0xd109a8: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
        },
        classes={
                 0xd10998: (15251168, 'OBJC_CLASS_$_MJTextView'),
                 0xd109ac: (15251172, 'OBJC_CLASS_$_BitmapFont'),
        },
        instructions=[(13698624, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13699512, 'mlaseq r4, ip, r4, pc')],
        calls=[(13699100, 'bl 0xd109bc'), (13699124, 'bl loc.imp.objc_msgSend'), (13699276, 'bl loc.imp.objc_msgSend'), (13699432, 'bl loc.imp.objc_msgSend')],
        branches=[(13698736, 'bne', 13698804), (13698800, 'b', 13698984), (13698836, 'bne', 13698916), (13698912, 'b', 13698980), (13698948, 'bne', 13698976), (13698976, 'b', 13698980), (13698980, 'b', 13698984)],
        semantics=('[MJButton -[createTitleWithColor:]] (imp 0x00d10640, 223w): [read] -[createTitleWithColor:] (0xd10640): A-title twin of mj_05 - the two bodies are instruction-identical (verified by pointer-normalized diff; only pool cells differ): same rect math and MJTextView init, reading title/titleView/titleAlignment, result -> titleView..\n'),
    ),
    dict(
        name='mj_07',
        method='MJButton -[dealloc]',
        types='v8@0:4',
        start=13706028,
        end=13706620,
        disasm='disasm_worldtileloader_mj_07.txt',
        base_add=13706044,
        base_literal=13706616,
        boundary='ARM.exidx end 0x00d1257c (listing bound); next ObjC IMP 0x00d1257c MJButton -[setTextureName:]',
        selectors={
                 0xd1254c: (15238400, 'dealloc'),
                 0xd12558: (15238352, 'release'),
        },
        imports={
                 0xd12548: (17151900, 'objc_msgSendSuper2'),
                 0xd12554: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd1255c: (17168176, 'OBJC_IVAR_$_MJButton.glyphTextureB', 192),
                 0xd12560: (17168180, 'OBJC_IVAR_$_MJButton.glyphTexture', 132),
                 0xd12564: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
                 0xd12568: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd1256c: (17158044, 'OBJC_IVAR_$_MJButton.backgroundTexture', 112),
                 0xd12570: (17168156, 'OBJC_IVAR_$_MJButton.titleB', 240),
                 0xd12574: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
        },
        classes={
                 0xd12550: (15253260, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(13706028, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13706616, 'ldrhteq sp, [r4], -r0')],
        calls=[(13706252, 'blx r5'), (13706312, 'blx lr'), (13706372, 'blx lr'), (13706408, 'blx r3'), (13706444, 'blx r3'), (13706480, 'blx r3'), (13706516, 'blx r3'), (13706556, 'blx r2')],
        branches=[],
        semantics=('[MJButton -[dealloc]] (imp 0x00d1232c, 148w): [read] -[dealloc] (0xd1232c): manual MRR teardown in order - title (release, then nil store), titleB (release, then nil store), backgroundTexture, titleView, titleViewB, glyphTexture, glyphTextureB, then [super dealloc] via objc_msgSendSuper2. backgroundSelectedTexture / backgroundHighlightedTexture / backgroundHighlightedSelectedTexture are not released here (as-read)..\n'),
    ),
    dict(
        name='mj_08',
        method='MJButton -[dontStretch]',
        types='c8@0:4',
        start=13725268,
        end=13725328,
        disasm='disasm_worldtileloader_mj_08.txt',
        base_add=13725276,
        base_literal=13725324,
        boundary='ARM.exidx end 0x00d16e90 (listing bound); next ObjC IMP 0x00d16e90 MJButton -[setDontStretch:]',
        selectors={},
        imports={},
        ivars={
                 0xd16e88: (17157040, 'OBJC_IVAR_$_MJButton.dontStretch', 189),
        },
        classes={},
        instructions=[(13725268, 'sub sp, sp, 8'), (13725324, 'mlaseq r4, r0, ip, r8')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[dontStretch]] (imp 0x00d16e54, 15w): Getter -[dontStretch] (0xd16e54): BOOL byte read via ldrsb; ivar @0xbd..\n'),
    ),
    dict(
        name='mj_09',
        method='MJButton -[glyphColor]',
        types='{MJColor=ffff}8@0:4',
        start=13725396,
        end=13725492,
        disasm='disasm_worldtileloader_mj_09.txt',
        base_add=13725412,
        base_literal=13725488,
        boundary='ARM.exidx end 0x00d16f34 (listing bound); next ObjC IMP 0x00d16f34 MJButton -[setGlyphColor:]',
        selectors={},
        imports={},
        ivars={
                 0xd16f2c: (17168160, 'OBJC_IVAR_$_MJButton.glyphColor', 152),
        },
        classes={},
        instructions=[(13725396, 'push {r4, r5, fp, lr}'), (13725488, 'eorseq r8, r4, r8, lsl 24')],
        calls=[(13725472, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[MJButton -[glyphColor]] (imp 0x00d16ed4, 24w): Getter -[glyphColor] (0xd16ed4): struct return via objc_copyStruct(dst=out buffer, src=self+0x98, 16, 1, 0) - MJColor 4-float copy..\n'),
    ),
    dict(
        name='mj_10',
        method='MJButton -[glyphFrame]',
        types='{CGRect={CGPoint=ff}{CGSize=ff}}8@0:4',
        start=13724820,
        end=13724916,
        disasm='disasm_worldtileloader_mj_10.txt',
        base_add=13724836,
        base_literal=13724912,
        boundary='ARM.exidx end 0x00d16cf4 (listing bound); next ObjC IMP 0x00d16cf4 MJButton -[setGlyphFrame:]',
        selectors={},
        imports={},
        ivars={
                 0xd16cec: (17168172, 'OBJC_IVAR_$_MJButton.glyphFrame', 136),
        },
        classes={},
        instructions=[(13724820, 'push {r4, r5, fp, lr}'), (13724912, 'eorseq r8, r4, r8, asr 28')],
        calls=[(13724896, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[MJButton -[glyphFrame]] (imp 0x00d16c94, 24w): Getter -[glyphFrame] (0xd16c94): struct return via objc_copyStruct(dst, self+0x88, 16, 1, 0) - CGRect..\n'),
    ),
    dict(
        name='mj_11',
        method='MJButton -[glyphFrameB]',
        types='{CGRect={CGPoint=ff}{CGSize=ff}}8@0:4',
        start=13725044,
        end=13725140,
        disasm='disasm_worldtileloader_mj_11.txt',
        base_add=13725060,
        base_literal=13725136,
        boundary='ARM.exidx end 0x00d16dd4 (listing bound); next ObjC IMP 0x00d16dd4 MJButton -[setGlyphFrameB:]',
        selectors={},
        imports={},
        ivars={
                 0xd16dcc: (17168168, 'OBJC_IVAR_$_MJButton.glyphFrameB', 196),
        },
        classes={},
        instructions=[(13725044, 'push {r4, r5, fp, lr}'), (13725136, 'eorseq r8, r4, r8, ror 26')],
        calls=[(13725120, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[MJButton -[glyphFrameB]] (imp 0x00d16d74, 24w): Getter -[glyphFrameB] (0xd16d74): struct return via objc_copyStruct(dst, self+0xc4, 16, 1, 0) - CGRect..\n'),
    ),
    dict(
        name='mj_12',
        method='MJButton -[glyphTexture]',
        types='@8@0:4',
        start=13724420,
        end=13724480,
        disasm='disasm_worldtileloader_mj_12.txt',
        base_add=13724428,
        base_literal=13724476,
        boundary='ARM.exidx end 0x00d16b40 (listing bound); next ObjC IMP 0x00d16b40 MJButton -[setGlyphTexture:]',
        selectors={},
        imports={},
        ivars={
                 0xd16b38: (17168180, 'OBJC_IVAR_$_MJButton.glyphTexture', 132),
        },
        classes={},
        instructions=[(13724420, 'sub sp, sp, 8'), (13724476, 'eorseq r8, r4, r0, ror 31')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[glyphTexture]] (imp 0x00d16b04, 15w): Getter -[glyphTexture] (0xd16b04): offset-cell getter; ivar @0x84 (132)..\n'),
    ),
    dict(
        name='mj_13',
        method='MJButton -[glyphTextureB]',
        types='@8@0:4',
        start=13724556,
        end=13724616,
        disasm='disasm_worldtileloader_mj_13.txt',
        base_add=13724564,
        base_literal=13724612,
        boundary='ARM.exidx end 0x00d16bc8 (listing bound); next ObjC IMP 0x00d16bc8 MJButton -[setGlyphTextureB:]',
        selectors={},
        imports={},
        ivars={
                 0xd16bc0: (17168176, 'OBJC_IVAR_$_MJButton.glyphTextureB', 192),
        },
        classes={},
        instructions=[(13724556, 'sub sp, sp, 8'), (13724612, 'eorseq r8, r4, r8, asr pc')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[glyphTextureB]] (imp 0x00d16b8c, 15w): Getter -[glyphTextureB] (0xd16b8c): offset-cell getter; ivar @0xc0 (192)..\n'),
    ),
    dict(
        name='mj_14',
        method='MJButton -[hoverSelectedDisabled]',
        types='c8@0:4',
        start=13724692,
        end=13724752,
        disasm='disasm_worldtileloader_mj_14.txt',
        base_add=13724700,
        base_literal=13724748,
        boundary='ARM.exidx end 0x00d16c50 (listing bound); next ObjC IMP 0x00d16c50 MJButton -[setHoverSelectedDisabled:]',
        selectors={},
        imports={},
        ivars={
                 0xd16c48: (17168192, 'OBJC_IVAR_$_MJButton.hoverSelectedDisabled', 169),
        },
        classes={},
        instructions=[(13724692, 'sub sp, sp, 8'), (13724748, 'ldrsbteq r8, [r4], -r0')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[hoverSelectedDisabled]] (imp 0x00d16c14, 15w): Getter -[hoverSelectedDisabled] (0xd16c14): ldrsb BOOL; ivar @0xa9..\n'),
    ),
    dict(
        name='mj_15',
        method='MJButton -[initWithFrame:cache:windowInfo:textureName:]',
        types='@36@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8@24^{WindowInfo=ffffffff}28@32',
        start=13703016,
        end=13704572,
        disasm='disasm_worldtileloader_mj_15.txt',
        base_add=13703032,
        base_literal=13704568,
        boundary='ARM.exidx end 0x00d11d7c (listing bound); next ObjC IMP 0x00d11d7c MJButton -[initWithFrame:cache:windowInfo:title:]',
        selectors={
                 0xd11d1c: (15238380, 'initWithFrame:cache:windowInfo:'),
                 0xd11d24: (14782032, 'ELF'),
                 0xd11d38: (15238392, 'shaderNamed:attributes:uniforms:'),
                 0xd11d48: (15238388, 'arrayWithObjects:'),
                 0xd11d60: (15238364, 'retain'),
                 0xd11d64: (15238384, 'textureNamed:'),
        },
        imports={
                 0xd11d30: (16440952, '__CFConstantStringClassReference'),
                 0xd11d34: (17151904, 'objc_msgSend'),
                 0xd11d3c: (16441000, '__CFConstantStringClassReference'),
                 0xd11d40: (16441016, '__CFConstantStringClassReference'),
                 0xd11d44: (16441032, '__CFConstantStringClassReference'),
                 0xd11d50: (16440968, '__CFConstantStringClassReference'),
                 0xd11d54: (16440984, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd11d20: (17168160, 'OBJC_IVAR_$_MJButton.glyphColor', 152),
                 0xd11d28: (17168164, 'OBJC_IVAR_$_MJButton.titleOffset', 232),
                 0xd11d2c: (17157540, 'OBJC_IVAR_$_MJButton.shader', 108),
                 0xd11d58: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0xd11d5c: (17158044, 'OBJC_IVAR_$_MJButton.backgroundTexture', 112),
                 0xd11d68: (17168144, 'OBJC_IVAR_$_MJButton.titleAlignment', 104),
                 0xd11d6c: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0xd11d70: (17168168, 'OBJC_IVAR_$_MJButton.glyphFrameB', 196),
                 0xd11d74: (17168172, 'OBJC_IVAR_$_MJButton.glyphFrame', 136),
        },
        classes={
                 0xd11d14: (15253260, 'OBJC_CLASS_$_MJButton'),
                 0xd11d4c: (15251176, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(13703016, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13704568, 'eorseq lr, r4, r4, ror r3')],
        calls=[(13703240, 'bl loc.imp.objc_msgSendSuper2'), (13703456, 'bl 0xd109bc'), (13703668, 'bl 0xd109bc'), (13704092, 'blx r4'), (13704108, 'blx r2'), (13704196, 'blx r4'), (13704252, 'blx r4'), (13704296, 'blx lr'), (13704408, 'bl 0xd10be4')],
        branches=[(13703268, 'bne', 13703284), (13703280, 'b', 13704456)],
        semantics=('[MJButton -[initWithFrame:cache:windowInfo:textureName:]] (imp 0x00d11768, 389w): [census-lite; register-traced end to end, 389w] -[initWithFrame:cache:windowInfo:textureName:] (0xd11768): [super initWithFrame:cache:windowInfo:] (objc_msgSendSuper2; nil result -> return nil); glyphFrame = {x+4, y+4, w-8, h-8} and glyphFrameB = {x+18, y+18, w-16, h-16} (both written by the 0xd109bc rect writer from the freshly stored self.frame); glyphColor = (1,1,1,1) white (written via 0xd10be4 writer); titleAlignment = 1; titleOffset = (0,0) copied from a static zero pair (slot 0x00e18e50); shader = [self.cache shaderNamed:@"MJButton" attributes:[NSArray arrayWithObjects:@"position", @"texCoord", nil] uniforms:[NSArray arrayWithObjects:@"mvp_matrix", @"texture", @"color", nil]]; backgroundTexture = [[self.cache textureNamed:textureName] retain]..\n'),
    ),
    dict(
        name='mj_16',
        method='MJButton -[initWithFrame:cache:windowInfo:title:]',
        types='@36@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8@24^{WindowInfo=ffffffff}28@32',
        start=13704572,
        end=13706028,
        disasm='disasm_worldtileloader_mj_16.txt',
        base_add=13704588,
        base_literal=13706024,
        boundary='ARM.exidx end 0x00d1232c (listing bound); next ObjC IMP 0x00d1232c MJButton -[dealloc]',
        selectors={
                 0xd122d4: (15238380, 'initWithFrame:cache:windowInfo:'),
                 0xd122dc: (14782032, 'ELF'),
                 0xd122f0: (15238392, 'shaderNamed:attributes:uniforms:'),
                 0xd12300: (15238388, 'arrayWithObjects:'),
                 0xd12314: (15238396, 'setTitle:'),
        },
        imports={
                 0xd122e8: (16440952, '__CFConstantStringClassReference'),
                 0xd122ec: (17151904, 'objc_msgSend'),
                 0xd122f4: (16441000, '__CFConstantStringClassReference'),
                 0xd122f8: (16441016, '__CFConstantStringClassReference'),
                 0xd122fc: (16441032, '__CFConstantStringClassReference'),
                 0xd12308: (16440968, '__CFConstantStringClassReference'),
                 0xd1230c: (16440984, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd122d8: (17168160, 'OBJC_IVAR_$_MJButton.glyphColor', 152),
                 0xd122e0: (17168164, 'OBJC_IVAR_$_MJButton.titleOffset', 232),
                 0xd122e4: (17157540, 'OBJC_IVAR_$_MJButton.shader', 108),
                 0xd12310: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
                 0xd12318: (17168144, 'OBJC_IVAR_$_MJButton.titleAlignment', 104),
                 0xd1231c: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0xd12320: (17168168, 'OBJC_IVAR_$_MJButton.glyphFrameB', 196),
                 0xd12324: (17168172, 'OBJC_IVAR_$_MJButton.glyphFrame', 136),
        },
        classes={
                 0xd122cc: (15253260, 'OBJC_CLASS_$_MJButton'),
                 0xd12304: (15251176, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(13704572, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13706024, 'eorseq sp, r4, r0, ror 26')],
        calls=[(13704796, 'bl loc.imp.objc_msgSendSuper2'), (13705012, 'bl 0xd109bc'), (13705224, 'bl 0xd109bc'), (13705592, 'blx r4'), (13705660, 'blx r4'), (13705716, 'blx r4'), (13705760, 'blx lr'), (13705872, 'bl 0xd10be4')],
        branches=[(13704824, 'bne', 13704840), (13704836, 'b', 13705920)],
        semantics=('[MJButton -[initWithFrame:cache:windowInfo:title:]] (imp 0x00d11d7c, 364w): [census-lite; register-traced end to end, 364w] -[initWithFrame:cache:windowInfo:title:] (0xd11d7c): same template as mj_15 (super init with nil-return gate; glyphFrame {x+4,y+4,w-8,h-8}; glyphFrameB {x+18,y+18,w-16,h-16}; glyphColor white; titleAlignment = 1; titleOffset = (0,0); shader built with the same attribute/uniform arrays) except the texture step is replaced by [self setTitle:title]; backgroundTexture is never touched (one msgSend fewer than mj_15 - no retain)..\n'),
    ),
    dict(
        name='mj_17',
        method='MJButton -[renderFrame:projectionMatrix:]',
        types='v76@0:4f8(_GLKMatrix4={?=ffffffffffffffff}[16f])12',
        start=13707008,
        end=13717332,
        disasm='disasm_worldtileloader_mj_17.txt',
        base_add=13707040,
        base_literal=13710100,
        boundary='ARM.exidx end 0x00d14f54 (listing bound); next ObjC IMP 0x00d156fc MJButton -[setSelected:]',
        selectors={
                 0xd13320: (15238408, 'timeIntervalSinceReferenceDate'),
                 0xd139e8: (15238420, 'program'),
                 0xd139f0: (15238416, 'maxS'),
                 0xd139f4: (15238412, 'maxT'),
                 0xd13eb0: (15238432, 'intValue'),
                 0xd13eb4: (15238428, 'objectAtIndex:'),
                 0xd13eb8: (15238424, 'uniformLocations'),
                 0xd146b0: (15238436, 'name'),
                 0xd14ee8: (15238432, 'intValue'),
                 0xd14eec: (15238428, 'objectAtIndex:'),
                 0xd14ef0: (15238424, 'uniformLocations'),
                 0xd14ef8: (15238416, 'maxS'),
                 0xd14efc: (15238412, 'maxT'),
                 0xd14f08: (15238436, 'name'),
                 0xd14f3c: (15238440, 'renderFrame:projectionMatrix:'),
        },
        imports={
                 0xd1331c: (17151904, 'objc_msgSend'),
                 0xd14ee0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd13318: (17168184, 'OBJC_IVAR_$_MJButton.lastRenderTime', 264),
                 0xd13328: (17155680, 'OBJC_IVAR_$_MJView.hidden', 4),
                 0xd1332c: (17164140, 'OBJC_IVAR_$_MJControl.startTouchAnimationTimer', 96),
                 0xd13330: (17168188, 'OBJC_IVAR_$_MJButton.isSelected', 168),
                 0xd13334: (17158044, 'OBJC_IVAR_$_MJButton.backgroundTexture', 112),
                 0xd13338: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0xd139c8: (17158064, 'OBJC_IVAR_$_MJControl.hover', 68),
                 0xd139cc: (17168192, 'OBJC_IVAR_$_MJButton.hoverSelectedDisabled', 169),
                 0xd139d0: (17158048, 'OBJC_IVAR_$_MJButton.backgroundSelectedTexture', 116),
                 0xd139d4: (17157536, 'OBJC_IVAR_$_MJButton.isHighlighted', 170),
                 0xd139d8: (17168196, 'OBJC_IVAR_$_MJButton.backgroundHighlightedSelectedTexture', 124),
                 0xd139dc: (17168200, 'OBJC_IVAR_$_MJButton.backgroundHighlightedTexture', 120),
                 0xd139e0: (17157040, 'OBJC_IVAR_$_MJButton.dontStretch', 189),
                 0xd139e4: (17168204, 'OBJC_IVAR_$_MJButton.tapAnimationDisabled', 272),
                 0xd139ec: (17157540, 'OBJC_IVAR_$_MJButton.shader', 108),
                 0xd13ebc: (17158036, 'OBJC_IVAR_$_MJControl.enabled', 71),
                 0xd13ec0: (17155708, 'OBJC_IVAR_$_MJView.color', 28),
                 0xd146b4: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
                 0xd146c0: (17168176, 'OBJC_IVAR_$_MJButton.glyphTextureB', 192),
                 0xd146c4: (17168208, 'OBJC_IVAR_$_MJButton.customGlyphTexCoordsB', 228),
                 0xd146c8: (17168168, 'OBJC_IVAR_$_MJButton.glyphFrameB', 196),
                 0xd146cc: (17168212, 'OBJC_IVAR_$_MJButton.glyphMaxTexBY', 224),
                 0xd146d0: (17168216, 'OBJC_IVAR_$_MJButton.glyphMinTexBY', 220),
                 0xd146d4: (17168220, 'OBJC_IVAR_$_MJButton.glyphMaxTexBX', 216),
                 0xd146d8: (17168224, 'OBJC_IVAR_$_MJButton.glyphMinTexBX', 212),
                 0xd14ed8: (17168180, 'OBJC_IVAR_$_MJButton.glyphTexture', 132),
                 0xd14edc: (17168228, 'OBJC_IVAR_$_MJButton.customGlyphTexCoords', 188),
                 0xd14ee4: (17158036, 'OBJC_IVAR_$_MJControl.enabled', 71),
                 0xd14ef4: (17157540, 'OBJC_IVAR_$_MJButton.shader', 108),
                 0xd14f00: (17155708, 'OBJC_IVAR_$_MJView.color', 28),
                 0xd14f04: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
                 0xd14f14: (17168180, 'OBJC_IVAR_$_MJButton.glyphTexture', 132),
                 0xd14f18: (17168172, 'OBJC_IVAR_$_MJButton.glyphFrame', 136),
                 0xd14f1c: (17168232, 'OBJC_IVAR_$_MJButton.glyphMaxTexY', 184),
                 0xd14f20: (17168236, 'OBJC_IVAR_$_MJButton.glyphMinTexY', 180),
                 0xd14f24: (17168240, 'OBJC_IVAR_$_MJButton.glyphMaxTexX', 176),
                 0xd14f28: (17168244, 'OBJC_IVAR_$_MJButton.glyphMinTexX', 172),
                 0xd14f2c: (17168160, 'OBJC_IVAR_$_MJButton.glyphColor', 152),
                 0xd14f30: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd14f34: (17168164, 'OBJC_IVAR_$_MJButton.titleOffset', 232),
                 0xd14f40: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
                 0xd14f44: (17168248, 'OBJC_IVAR_$_MJButton.titleOffsetB', 252),
        },
        classes={
                 0xd13324: (15251180, 'OBJC_CLASS_$_NSDate'),
                 0xd14f4c: (15253260, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(13707008, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13717328, 'eorseq sl, r4, r8, lsl 26')],
        calls=[(13707348, 'blx lr'), (13708700, 'bl 0xd109bc'), (13709112, 'blx r7'), (13709152, 'blx r3'), (13709200, 'blx r3'), (13709240, 'blx r3'), (13709304, 'blx r3'), (13709352, 'blx r3'), (13709392, 'blx r3'), (13709448, 'blx r3'), (13709488, 'blx r3'), (13709528, 'blx r3'), (13709592, 'blx ip'), (13709596, 'bl sym.imp.__wrap_glUseProgram'), (13709724, 'blx r6'), (13709744, 'blx r3'), (13709760, 'blx r2'), (13709768, 'bl sym.imp.__wrap_glUniform1i'), (13709944, 'blx r3'), (13709964, 'blx r3'), (13709980, 'blx r2'), (13710092, 'bl sym.imp.__wrap_glUniform4f'), (13710288, 'blx r3'), (13710308, 'blx r3'), (13710324, 'blx r2'), (13710440, 'bl sym.imp.__wrap_glUniform4f'), (13711280, 'bl 0xd14f54'), (13711412, 'blx r3'), (13711432, 'blx r3'), (13711448, 'blx r2'), (13711480, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (13711552, 'blx r3'), (13711572, 'bl sym.imp.__wrap_glBindTexture'), (13711620, 'bl sym.imp.__wrap_glVertexAttribPointer'), (13711664, 'bl sym.imp.__wrap_glVertexAttribPointer'), (13711720, 'blx r3'), (13711740, 'bl sym.imp.__wrap_glBindTexture'), (13711808, 'bl sym.imp.__wrap_glDrawElements'), (13711892, 'bl sym.imp.__wrap_glDrawElements'), (13712376, 'blx r2'), (13712440, 'blx ip'), (13712860, 'bl sym.imp.__wrap_glVertexAttribPointer'), (13712900, 'bl sym.imp.__wrap_glVertexAttribPointer'), (13712976, 'blx r3'), (13712996, 'bl sym.imp.__wrap_glBindTexture'), (13713064, 'bl sym.imp.__wrap_glDrawElements'), (13713120, 'bl sym.imp.__wrap_glDrawElements'), (13713604, 'blx r2'), (13713668, 'blx ip'), (13714228, 'blx ip'), (13714248, 'blx r3'), (13714264, 'blx r2'), (13714460, 'bl sym.imp.__wrap_glUniform4f'), (13714628, 'blx ip'), (13714648, 'blx r3'), (13714664, 'blx r2'), (13714864, 'bl sym.imp.__wrap_glUniform4f'), (13714908, 'bl sym.imp.__wrap_glVertexAttribPointer'), (13714948, 'bl sym.imp.__wrap_glVertexAttribPointer'), (13715024, 'blx r3'), (13715044, 'bl sym.imp.__wrap_glBindTexture'), (13715112, 'bl sym.imp.__wrap_glDrawElements'), (13715192, 'bl sym.imp.__wrap_glDrawElements'), (13715620, 'bl 0xd15514'), (13716000, 'bl loc.imp.objc_msgSend'), (13716424, 'bl 0xd15514'), (13716804, 'bl loc.imp.objc_msgSend'), (13717192, 'bl loc.imp.objc_msgSendSuper2')],
        branches=[(13707424, 'bpl', 13707444), (13707440, 'b', 13707460), (13707608, 'beq', 13707616), (13707612, 'b', 13717196), (13707736, 'bne', 13707840), (13707780, 'beq', 13707832), (13707888, 'beq', 13707940), (13707904, 'beq', 13707940), (13707972, 'beq', 13708152), (13708012, 'beq', 13708072), (13708028, 'beq', 13708072), (13708064, 'b', 13708148), (13708108, 'beq', 13708144), (13708144, 'b', 13708148), (13708148, 'b', 13708152), (13708224, 'beq', 13708256), (13708348, 'ble', 13708736), (13708384, 'bne', 13708736), (13709804, 'beq', 13710144), (13710096, 'b', 13710444), (13711496, 'beq', 13711900), (13711780, 'beq', 13711868), (13711812, 'b', 13711896), (13711896, 'b', 13711900), (13711936, 'beq', 13713128), (13712480, 'beq', 13712604), (13713036, 'beq', 13713096), (13713068, 'b', 13713124), (13713124, 'b', 13713128), (13713164, 'beq', 13715200), (13713708, 'beq', 13713832), (13714080, 'beq', 13714476), (13714464, 'b', 13714868), (13715084, 'beq', 13715168), (13715116, 'b', 13715196), (13715196, 'b', 13715200), (13715236, 'beq', 13716004), (13716040, 'beq', 13716808)],
        semantics=('[MJButton -[renderFrame:projectionMatrix:]] (imp 0x00d12700, 2581w): [census; not per-instruction. 2581w / 38 forward branches / ZERO backward branches (loop-free) / 68 call rows] -[renderFrame:projectionMatrix:] (0xd12700, args: float s0 then GLKMatrix4; ~0x118+0x800-byte stack frame). Phases: (1) timing 0xd12700-0xd12960: dt = [NSDate timeIntervalSinceReferenceDate] - self.lastRenderTime; self.lastRenderTime = now; t = max(floatArg, dt); self.startTouchAnimationTimer -= 4.0*t; if MJView.hidden != 0 jump to the super tail (0xd1295c). (2) background texture pick 0xd12960-0xd12b78: flag = isSelected || (hover && !hoverSelectedDisabled); tex = backgroundTexture; if flag and backgroundSelectedTexture -> backgroundSelectedTexture; if isHighlighted -> backgroundHighlightedSelectedTexture (if flag and non-nil) else backgroundHighlightedTexture. (3) quad sizing 0xd12b78-0xd12dc0: size term = frame.height*0.5 (overridden by 0.5*[block+0x368] when dontStretch); tap animation (only when countdown timer > 0 and tapAnimationDisabled == 0): scale = 1 - 0.125*|timer*timer - 0.5| (vabs/vmul, f64 mixes), shrink deltas [0x330] = [0x368]*(1-scale), [0x32c] = [0x36c]*(1-scale); final quad rect = { [0x360] + 0.5*[0x330], [0x364] + 0.5*[0x32c], [0x368]*scale, [0x36c]*scale } - written by 0xd109bc. (4) shader/uniforms 0xd12dc0-0xd13878: [self.shader program] -> glUseProgram; uniform locations via [shader.uniformLocations objectAtIndex:N] intValue, fetched in two groups (4-use cells 0xd13eb0-b8 in the enabled path, 2-use cells 0xd14ee8-f0 in the other); glUniform1i (sampler unit); glUniform4f x2 (0xd1330c, 0xd13468: the \'color\' uniform, computed from in-object color state (MJView.color cell 0xd13ec0) with alpha folded in); the background quad texcoords read 9x maxS/maxT from the chosen texture; mvp = 4x4 product helper 0xd14f54 (two stacked 16-float operands; per-element form dst[4c] = sum_k A[4k]*B[4c+k]) then glUniformMatrix4fv (0xd13878). (5) three quad groups, each glBindTexture + glVertexAttribPointer x2 (type 0x1406 GL_FLOAT) + glDrawElements x2 (mode 4, count 6, type 0x1403 GL_UNSIGNED_SHORT, shared index buffer @0x00e76c90 word 0x00060000): background @0xd138c0-0xd13a14; glyph B @0xd13a20-0xd13ee0 gated on glyphTextureB != nil (glyphFrameB + glyphMin/MaxTexB cells 0xd146cc-d8 + \'name\' selector); glyph A @0xd13ee8-0xd146f8 gated on glyphTexture != nil (glyphFrame + glyphMin/MaxTexX/Y cells) with two more glUniform4f @0xd1441c / 0xd145b0 (the glyph color computed from glyphColor x self.color terms, alpha folded in). (6) titles 0xd14700-0xd14d44: if titleView != nil -> translate helper 0xd15514 (4x4 rewrite of the translation row) with titleOffset @0xe8, then objc_msgSend [titleView renderFrame:float projectionMatrix:mvp\']; mirrored for titleViewB/titleOffsetB @0xfc. (7) [super renderFrame:projectionMatrix:] via objc_msgSendSuper2 (0xd14ec8)..\n'),
    ),
    dict(
        name='mj_18',
        method='MJButton -[setBackgroundHighlightedSelectedTexture:]',
        types='v12@0:4@8',
        start=13724344,
        end=13724420,
        disasm='disasm_worldtileloader_mj_18.txt',
        base_add=13724360,
        base_literal=13724416,
        boundary='ARM.exidx end 0x00d16b04 (listing bound); next ObjC IMP 0x00d16b04 MJButton -[glyphTexture]',
        selectors={},
        imports={},
        ivars={
                 0xd16afc: (17168196, 'OBJC_IVAR_$_MJButton.backgroundHighlightedSelectedTexture', 124),
        },
        classes={},
        instructions=[(13724344, 'push {fp, lr}'), (13724416, 'eorseq sb, r4, r4, lsr 32')],
        calls=[(13724400, 'bl sym.imp.objc_setProperty_nonatomic')],
        branches=[],
        semantics=('[MJButton -[setBackgroundHighlightedSelectedTexture:]] (imp 0x00d16ab8, 19w): Property setter -[setBackgroundHighlightedSelectedTexture:] (0xd16ab8): objc_setProperty_nonatomic(self, sel, value, 124)..\n'),
    ),
    dict(
        name='mj_19',
        method='MJButton -[setBackgroundHighlightedTexture:]',
        types='v12@0:4@8',
        start=13724208,
        end=13724284,
        disasm='disasm_worldtileloader_mj_19.txt',
        base_add=13724224,
        base_literal=13724280,
        boundary='ARM.exidx end 0x00d16a7c (listing bound); next ObjC IMP 0x00d16a7c MJButton -[backgroundHighlightedSelectedTexture]',
        selectors={},
        imports={},
        ivars={
                 0xd16a74: (17168200, 'OBJC_IVAR_$_MJButton.backgroundHighlightedTexture', 120),
        },
        classes={},
        instructions=[(13724208, 'push {fp, lr}'), (13724280, 'eorseq sb, r4, ip, lsr 1')],
        calls=[(13724264, 'bl sym.imp.objc_setProperty_nonatomic')],
        branches=[],
        semantics=('[MJButton -[setBackgroundHighlightedTexture:]] (imp 0x00d16a30, 19w): Property setter -[setBackgroundHighlightedTexture:] (0xd16a30): objc_setProperty_nonatomic(self, sel, value, 120)..\n'),
    ),
    dict(
        name='mj_20',
        method='MJButton -[setBackgroundSelectedTexture:]',
        types='v12@0:4@8',
        start=13724072,
        end=13724148,
        disasm='disasm_worldtileloader_mj_20.txt',
        base_add=13724088,
        base_literal=13724144,
        boundary='ARM.exidx end 0x00d169f4 (listing bound); next ObjC IMP 0x00d169f4 MJButton -[backgroundHighlightedTexture]',
        selectors={},
        imports={},
        ivars={
                 0xd169ec: (17158048, 'OBJC_IVAR_$_MJButton.backgroundSelectedTexture', 116),
        },
        classes={},
        instructions=[(13724072, 'push {fp, lr}'), (13724144, 'eorseq sb, r4, r4, lsr r1')],
        calls=[(13724128, 'bl sym.imp.objc_setProperty_nonatomic')],
        branches=[],
        semantics=('[MJButton -[setBackgroundSelectedTexture:]] (imp 0x00d169a8, 19w): Property setter -[setBackgroundSelectedTexture:] (0xd169a8): objc_setProperty_nonatomic(self, sel, value, 116)..\n'),
    ),
    dict(
        name='mj_21',
        method='MJButton -[setBackgroundTexture:]',
        types='v12@0:4@8',
        start=13723936,
        end=13724012,
        disasm='disasm_worldtileloader_mj_21.txt',
        base_add=13723952,
        base_literal=13724008,
        boundary='ARM.exidx end 0x00d1696c (listing bound); next ObjC IMP 0x00d1696c MJButton -[backgroundSelectedTexture]',
        selectors={},
        imports={},
        ivars={
                 0xd16964: (17158044, 'OBJC_IVAR_$_MJButton.backgroundTexture', 112),
        },
        classes={},
        instructions=[(13723936, 'push {fp, lr}'), (13724008, 'ldrhteq sb, [r4], -ip')],
        calls=[(13723992, 'bl sym.imp.objc_setProperty_nonatomic')],
        branches=[],
        semantics=('[MJButton -[setBackgroundTexture:]] (imp 0x00d16920, 19w): Property setter -[setBackgroundTexture:] (0xd16920): objc_setProperty_nonatomic(self, sel, value, 112)..\n'),
    ),
    dict(
        name='mj_22',
        method='MJButton -[setColor:]',
        types='v24@0:4{MJColor=ffff}8',
        start=13702028,
        end=13703016,
        disasm='disasm_worldtileloader_mj_22.txt',
        base_add=13702044,
        base_literal=13703012,
        boundary='ARM.exidx end 0x00d11768 (listing bound); next ObjC IMP 0x00d11768 MJButton -[initWithFrame:cache:windowInfo:textureName:]',
        selectors={
                 0xd11728: (15238376, 'setColor:'),
                 0xd11738: (15238352, 'release'),
                 0xd1174c: (15238356, 'createTitleWithColor:'),
                 0xd11760: (15238372, 'createTitleBWithColor:'),
        },
        imports={
                 0xd11734: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd1172c: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
                 0xd11730: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
                 0xd1173c: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd11740: (17158036, 'OBJC_IVAR_$_MJControl.enabled', 71),
                 0xd11744: (17155708, 'OBJC_IVAR_$_MJView.color', 28),
                 0xd11754: (17168156, 'OBJC_IVAR_$_MJButton.titleB', 240),
        },
        classes={
                 0xd11720: (15253260, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(13702028, 'push {r4, r5, r6, sl, fp, lr}'), (13703012, 'eorseq lr, r4, r0, asr r7')],
        calls=[(13702192, 'bl loc.imp.objc_msgSendSuper2'), (13702296, 'blx ip'), (13702356, 'blx lr'), (13702524, 'bl 0xd10be4'), (13702572, 'bl loc.imp.objc_msgSend'), (13702684, 'bl 0xd10be4'), (13702732, 'bl loc.imp.objc_msgSend'), (13702884, 'bl 0xd10be4'), (13702932, 'bl loc.imp.objc_msgSend')],
        branches=[(13702408, 'beq', 13702740), (13702444, 'beq', 13702580), (13702576, 'b', 13702736), (13702736, 'b', 13702740), (13702776, 'beq', 13702936)],
        semantics=('[MJButton -[setColor:]] (imp 0x00d1138c, 247w): [read] -[setColor:] (0xd1138c): [super setColor:]; releases and nils titleView and titleViewB; if self.title != nil -> [self createTitleWithColor:(enabled ? self.color : self.color*0.5)] (component-wise x0.5, alpha kept; ldrsb read of MJControl.enabled @0x47); if self.titleB != nil -> [self createTitleBWithColor:(self.color*0.67)] - 0x3f2b851f pool constant..\n'),
    ),
    dict(
        name='mj_23',
        method='MJButton -[setDontStretch:]',
        types='v12@0:4c8',
        start=13725328,
        end=13725396,
        disasm='disasm_worldtileloader_mj_23.txt',
        base_add=13725356,
        base_literal=13725392,
        boundary='ARM.exidx end 0x00d16ed4 (listing bound); next ObjC IMP 0x00d16ed4 MJButton -[glyphColor]',
        selectors={},
        imports={},
        ivars={
                 0xd16ecc: (17157040, 'OBJC_IVAR_$_MJButton.dontStretch', 189),
        },
        classes={},
        instructions=[(13725328, 'sub sp, sp, 0xc'), (13725392, 'eorseq r8, r4, r0, asr 24')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setDontStretch:]] (imp 0x00d16e90, 17w): -[setDontStretch:] (0xd16e90): atomic BOOL store - dmb ish; strb to self+0xbd; dmb ish..\n'),
    ),
    dict(
        name='mj_24',
        method='MJButton -[setEnabled:]',
        types='v12@0:4c8',
        start=13701060,
        end=13702028,
        disasm='disasm_worldtileloader_mj_24.txt',
        base_add=13701076,
        base_literal=13702024,
        boundary='ARM.exidx end 0x00d1138c (listing bound); next ObjC IMP 0x00d1138c MJButton -[setColor:]',
        selectors={
                 0xd11354: (15238368, 'setEnabled:'),
                 0xd11364: (15238352, 'release'),
                 0xd11370: (15238356, 'createTitleWithColor:'),
                 0xd11384: (15238372, 'createTitleBWithColor:'),
        },
        imports={
                 0xd11350: (17151900, 'objc_msgSendSuper2'),
                 0xd11360: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd1134c: (17158036, 'OBJC_IVAR_$_MJControl.enabled', 71),
                 0xd1135c: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd11368: (17155708, 'OBJC_IVAR_$_MJView.color', 28),
                 0xd11378: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
        },
        classes={
                 0xd11358: (15253260, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(13701060, 'push {r4, r5, fp, lr}'), (13702024, 'eorseq lr, r4, r8, lsl fp')],
        calls=[(13701220, 'blx r3'), (13701352, 'blx ip'), (13701484, 'bl 0xd10be4'), (13701532, 'bl loc.imp.objc_msgSend'), (13701644, 'bl 0xd10be4'), (13701692, 'bl loc.imp.objc_msgSend'), (13701788, 'bl loc.imp.objc_msgSend'), (13701900, 'bl 0xd10be4'), (13701948, 'bl loc.imp.objc_msgSend')],
        branches=[(13701136, 'beq', 13701148), (13701232, 'beq', 13701956), (13701272, 'beq', 13701700), (13701404, 'beq', 13701540), (13701536, 'b', 13701696), (13701696, 'b', 13701700), (13701736, 'beq', 13701952), (13701952, 'b', 13701956)],
        semantics=('[MJButton -[setEnabled:]] (imp 0x00d10fc4, 242w): [read] -[setEnabled:] (0xd10fc4): changed = (newEnabled != self.enabled); [super setEnabled:]; if changed: [titleView release], titleView = nil, then createTitleWithColor:(enabled ? self.color : self.color*0.5); [titleViewB release], titleViewB = nil, then createTitleBWithColor:(self.color*0.67). When the state did not change the whole rebuild is skipped..\n'),
    ),
    dict(
        name='mj_25',
        method='MJButton -[setFrame:]',
        types='v24@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8',
        start=13720292,
        end=13721480,
        disasm='disasm_worldtileloader_mj_25.txt',
        base_add=13720308,
        base_literal=13721476,
        boundary='ARM.exidx end 0x00d15f88 (listing bound); next ObjC IMP 0x00d15f88 MJButton -[setTitleOffset:]',
        selectors={
                 0xd15f64: (15238444, 'setFrame:'),
        },
        imports={},
        ivars={
                 0xd15f68: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd15f6c: (17155632, 'OBJC_IVAR_$_MJView.frame', 8),
                 0xd15f74: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
                 0xd15f7c: (17168168, 'OBJC_IVAR_$_MJButton.glyphFrameB', 196),
                 0xd15f80: (17168172, 'OBJC_IVAR_$_MJButton.glyphFrame', 136),
        },
        classes={
                 0xd15f5c: (15253260, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(13720292, 'push {r4, r5, fp, lr}'), (13721476, 'ldrshteq sb, [r4], -r8')],
        calls=[(13720456, 'bl loc.imp.objc_msgSendSuper2'), (13720632, 'bl 0xd109bc'), (13720728, 'bl loc.imp.objc_msgSend'), (13720904, 'bl 0xd109bc'), (13721000, 'bl loc.imp.objc_msgSend'), (13721176, 'bl 0xd109bc'), (13721388, 'bl 0xd109bc')],
        branches=[(13720496, 'beq', 13720732), (13720768, 'beq', 13721004)],
        semantics=('[MJButton -[setFrame:]] (imp 0x00d15ae4, 297w): [read] -[setFrame:] (0xd15ae4): [super setFrame:]; if titleView != nil -> [titleView setFrame:{x + 0.5*w, y - 0.5*h + 8.0, w, h}] (f64 math for the x center term); same rect sent to titleViewB; always: glyphFrame = {x+4, y+4, w-8, h-8} and glyphFrameB = {x+18, y+18, w-16, h-16} recomputed from the new frame via the 0xd109bc rect writer..\n'),
    ),
    dict(
        name='mj_26',
        method='MJButton -[setGlyphColor:]',
        types='v24@0:4{MJColor=ffff}8',
        start=13725492,
        end=13725620,
        disasm='disasm_worldtileloader_mj_26.txt',
        base_add=13725508,
        base_literal=13725616,
        boundary='ARM.exidx end 0x00d16fb4 (listing bound); next ObjC IMP 0x00d16fb4 MJButton -[tapAnimationDisabled]',
        selectors={},
        imports={},
        ivars={
                 0xd16fac: (17168160, 'OBJC_IVAR_$_MJButton.glyphColor', 152),
        },
        classes={},
        instructions=[(13725492, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13725616, 'eorseq r8, r4, r8, lsr 23')],
        calls=[(13725600, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[MJButton -[setGlyphColor:]] (imp 0x00d16f34, 32w): -[setGlyphColor:] (0xd16f34): objc_copyStruct(dst=self+0x98, src=stack arg, 16, 1, 0) - MJColor written into the ivar..\n'),
    ),
    dict(
        name='mj_27',
        method='MJButton -[setGlyphFrame:]',
        types='v24@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8',
        start=13724916,
        end=13725044,
        disasm='disasm_worldtileloader_mj_27.txt',
        base_add=13724932,
        base_literal=13725040,
        boundary='ARM.exidx end 0x00d16d74 (listing bound); next ObjC IMP 0x00d16d74 MJButton -[glyphFrameB]',
        selectors={},
        imports={},
        ivars={
                 0xd16d6c: (17168172, 'OBJC_IVAR_$_MJButton.glyphFrame', 136),
        },
        classes={},
        instructions=[(13724916, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13725040, 'eorseq r8, r4, r8, ror 27')],
        calls=[(13725024, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[MJButton -[setGlyphFrame:]] (imp 0x00d16cf4, 32w): -[setGlyphFrame:] (0xd16cf4): objc_copyStruct(dst=self+0x88, src=stack arg, 16, 1, 0) - CGRect..\n'),
    ),
    dict(
        name='mj_28',
        method='MJButton -[setGlyphFrameB:]',
        types='v24@0:4{CGRect={CGPoint=ff}{CGSize=ff}}8',
        start=13725140,
        end=13725268,
        disasm='disasm_worldtileloader_mj_28.txt',
        base_add=13725156,
        base_literal=13725264,
        boundary='ARM.exidx end 0x00d16e54 (listing bound); next ObjC IMP 0x00d16e54 MJButton -[dontStretch]',
        selectors={},
        imports={},
        ivars={
                 0xd16e4c: (17168168, 'OBJC_IVAR_$_MJButton.glyphFrameB', 196),
        },
        classes={},
        instructions=[(13725140, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13725264, 'eorseq r8, r4, r8, lsl 26')],
        calls=[(13725248, 'bl sym.imp.objc_copyStruct')],
        branches=[],
        semantics=('[MJButton -[setGlyphFrameB:]] (imp 0x00d16dd4, 32w): -[setGlyphFrameB:] (0xd16dd4): objc_copyStruct(dst=self+0xc4, src=stack arg, 16, 1, 0) - CGRect..\n'),
    ),
    dict(
        name='mj_29',
        method='MJButton -[setGlyphTexture:]',
        types='v12@0:4@8',
        start=13724480,
        end=13724556,
        disasm='disasm_worldtileloader_mj_29.txt',
        base_add=13724496,
        base_literal=13724552,
        boundary='ARM.exidx end 0x00d16b8c (listing bound); next ObjC IMP 0x00d16b8c MJButton -[glyphTextureB]',
        selectors={},
        imports={},
        ivars={
                 0xd16b84: (17168180, 'OBJC_IVAR_$_MJButton.glyphTexture', 132),
        },
        classes={},
        instructions=[(13724480, 'push {fp, lr}'), (13724552, 'mlaseq r4, ip, pc, r8')],
        calls=[(13724536, 'bl sym.imp.objc_setProperty_nonatomic')],
        branches=[],
        semantics=('[MJButton -[setGlyphTexture:]] (imp 0x00d16b40, 19w): Property setter -[setGlyphTexture:] (0xd16b40): objc_setProperty_nonatomic(self, sel, value, 132)..\n'),
    ),
    dict(
        name='mj_30',
        method='MJButton -[setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:]',
        types='v28@0:4@8f12f16f20f24',
        start=13719428,
        end=13719860,
        disasm='disasm_worldtileloader_mj_30.txt',
        base_add=13719444,
        base_literal=13719856,
        boundary='ARM.exidx end 0x00d15934 (listing bound); next ObjC IMP 0x00d15934 MJButton -[setGlyphTextureB:minTexX:maxTexX:minTexY:maxTexY:]',
        selectors={
                 0xd15928: (15238364, 'retain'),
                 0xd1592c: (15238352, 'release'),
        },
        imports={
                 0xd15924: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd1590c: (17168228, 'OBJC_IVAR_$_MJButton.customGlyphTexCoords', 188),
                 0xd15910: (17168232, 'OBJC_IVAR_$_MJButton.glyphMaxTexY', 184),
                 0xd15914: (17168236, 'OBJC_IVAR_$_MJButton.glyphMinTexY', 180),
                 0xd15918: (17168240, 'OBJC_IVAR_$_MJButton.glyphMaxTexX', 176),
                 0xd1591c: (17168244, 'OBJC_IVAR_$_MJButton.glyphMinTexX', 172),
                 0xd15920: (17168180, 'OBJC_IVAR_$_MJButton.glyphTexture', 132),
        },
        classes={},
        instructions=[(13719428, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13719856, 'eorseq sl, r4, r8, asr r3')],
        calls=[(13719648, 'blx sl'), (13719668, 'blx r2')],
        branches=[],
        semantics=('[MJButton -[setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:]] (imp 0x00d15784, 108w): [read] -[setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:] (0xd15784, args @8 texture / f12 minTexX / f16 maxTexX / f20 minTexY / f24 maxTexY): releases the old glyphTexture (msgSend \'release\'), retains the new texture ([tex retain]) and stores it into self+0x84; writes glyphMinTexX 0xac, glyphMaxTexX 0xb0, glyphMinTexY 0xb4, glyphMaxTexY 0xb8 (vstr), then sets customGlyphTexCoords 0xbc = 1 (strb)..\n'),
    ),
    dict(
        name='mj_31',
        method='MJButton -[setGlyphTextureB:]',
        types='v12@0:4@8',
        start=13724616,
        end=13724692,
        disasm='disasm_worldtileloader_mj_31.txt',
        base_add=13724632,
        base_literal=13724688,
        boundary='ARM.exidx end 0x00d16c14 (listing bound); next ObjC IMP 0x00d16c14 MJButton -[hoverSelectedDisabled]',
        selectors={},
        imports={},
        ivars={
                 0xd16c0c: (17168176, 'OBJC_IVAR_$_MJButton.glyphTextureB', 192),
        },
        classes={},
        instructions=[(13724616, 'push {fp, lr}'), (13724688, 'eorseq r8, r4, r4, lsl pc')],
        calls=[(13724672, 'bl sym.imp.objc_setProperty_nonatomic')],
        branches=[],
        semantics=('[MJButton -[setGlyphTextureB:]] (imp 0x00d16bc8, 19w): Property setter -[setGlyphTextureB:] (0xd16bc8): objc_setProperty_nonatomic(self, sel, value, 192)..\n'),
    ),
    dict(
        name='mj_32',
        method='MJButton -[setGlyphTextureB:minTexX:maxTexX:minTexY:maxTexY:]',
        types='v28@0:4@8f12f16f20f24',
        start=13719860,
        end=13720292,
        disasm='disasm_worldtileloader_mj_32.txt',
        base_add=13719876,
        base_literal=13720288,
        boundary='ARM.exidx end 0x00d15ae4 (listing bound); next ObjC IMP 0x00d15ae4 MJButton -[setFrame:]',
        selectors={
                 0xd15ad8: (15238364, 'retain'),
                 0xd15adc: (15238352, 'release'),
        },
        imports={
                 0xd15ad4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd15abc: (17168208, 'OBJC_IVAR_$_MJButton.customGlyphTexCoordsB', 228),
                 0xd15ac0: (17168212, 'OBJC_IVAR_$_MJButton.glyphMaxTexBY', 224),
                 0xd15ac4: (17168216, 'OBJC_IVAR_$_MJButton.glyphMinTexBY', 220),
                 0xd15ac8: (17168220, 'OBJC_IVAR_$_MJButton.glyphMaxTexBX', 216),
                 0xd15acc: (17168224, 'OBJC_IVAR_$_MJButton.glyphMinTexBX', 212),
                 0xd15ad0: (17168176, 'OBJC_IVAR_$_MJButton.glyphTextureB', 192),
        },
        classes={},
        instructions=[(13719860, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13720288, 'eorseq sl, r4, r8, lsr 3')],
        calls=[(13720080, 'blx sl'), (13720100, 'blx r2')],
        branches=[],
        semantics=('[MJButton -[setGlyphTextureB:minTexX:maxTexX:minTexY:maxTexY:]] (imp 0x00d15934, 108w): [read] -[setGlyphTextureB:minTexX:maxTexX:minTexY:maxTexY:] (0xd15934): B-twin of mj_30 - same instruction stream, cells differ (glyphTextureB 0xc0, glyphMinTexBX 0xd4, glyphMaxTexBX 0xd8, glyphMinTexBY 0xdc, glyphMaxTexBY 0xe0); ends with customGlyphTexCoordsB 0xe4 = 1..\n'),
    ),
    dict(
        name='mj_33',
        method='MJButton -[setHidden:]',
        types='v12@0:4c8',
        start=13706868,
        end=13707008,
        disasm='disasm_worldtileloader_mj_33.txt',
        base_add=13706884,
        base_literal=13707004,
        boundary='ARM.exidx end 0x00d12700 (listing bound); next ObjC IMP 0x00d12700 MJButton -[renderFrame:projectionMatrix:]',
        selectors={
                 0xd126f4: (15238404, 'setHidden:'),
        },
        imports={
                 0xd126f0: (17151900, 'objc_msgSendSuper2'),
        },
        ivars={},
        classes={
                 0xd126f8: (15253260, 'OBJC_CLASS_$_MJButton'),
        },
        instructions=[(13706868, 'push {r4, r5, fp, lr}'), (13707004, 'eorseq sp, r4, r8, ror 8')],
        calls=[(13706980, 'blx lr')],
        branches=[],
        semantics=('[MJButton -[setHidden:]] (imp 0x00d12674, 35w): [read] -[setHidden:] (0xd12674): pure forward to [super setHidden:] through objc_msgSendSuper2 (BOOL arg sign-extended with sxtb); no local state..\n'),
    ),
    dict(
        name='mj_34',
        method='MJButton -[setHighlighted:]',
        types='v12@0:4c8',
        start=13719360,
        end=13719428,
        disasm='disasm_worldtileloader_mj_34.txt',
        base_add=13719368,
        base_literal=13719424,
        boundary='ARM.exidx end 0x00d15784 (listing bound); next ObjC IMP 0x00d15784 MJButton -[setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:]',
        selectors={},
        imports={},
        ivars={
                 0xd1577c: (17157536, 'OBJC_IVAR_$_MJButton.isHighlighted', 170),
        },
        classes={},
        instructions=[(13719360, 'sub sp, sp, 0xc'), (13719424, 'eorseq sl, r4, r4, lsr 7')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setHighlighted:]] (imp 0x00d15740, 17w): -[setHighlighted:] (0xd15740): plain strb of the BOOL arg at self+0xaa - no memory barrier..\n'),
    ),
    dict(
        name='mj_35',
        method='MJButton -[setHoverSelectedDisabled:]',
        types='v12@0:4c8',
        start=13724752,
        end=13724820,
        disasm='disasm_worldtileloader_mj_35.txt',
        base_add=13724780,
        base_literal=13724816,
        boundary='ARM.exidx end 0x00d16c94 (listing bound); next ObjC IMP 0x00d16c94 MJButton -[glyphFrame]',
        selectors={},
        imports={},
        ivars={
                 0xd16c8c: (17168192, 'OBJC_IVAR_$_MJButton.hoverSelectedDisabled', 169),
        },
        classes={},
        instructions=[(13724752, 'sub sp, sp, 0xc'), (13724816, 'eorseq r8, r4, r0, lsl 29')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setHoverSelectedDisabled:]] (imp 0x00d16c50, 17w): -[setHoverSelectedDisabled:] (0xd16c50): atomic BOOL store - dmb ish; strb self+0xa9; dmb ish..\n'),
    ),
    dict(
        name='mj_36',
        method='MJButton -[setSelected:]',
        types='v12@0:4c8',
        start=13719292,
        end=13719360,
        disasm='disasm_worldtileloader_mj_36.txt',
        base_add=13719300,
        base_literal=13719356,
        boundary='ARM.exidx end 0x00d15784; body trimmed at the next IMP 0x00d15740 MJButton -[setHighlighted:]',
        selectors={},
        imports={},
        ivars={
                 0xd15738: (17168188, 'OBJC_IVAR_$_MJButton.isSelected', 168),
        },
        classes={},
        instructions=[(13719292, 'sub sp, sp, 0xc'), (13719356, 'eorseq sl, r4, r8, ror 7')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setSelected:]] (imp 0x00d156fc, 17w): -[setSelected:] (0xd156fc): plain strb at self+0xa8 (no barrier). Listing is trimmed at the next IMP 0xd15740 (shared exidx suffix 0xd15784; 17 words as received)..\n'),
    ),
    dict(
        name='mj_37',
        method='MJButton -[setTapAnimationDisabled:]',
        types='v12@0:4c8',
        start=13725680,
        end=13725748,
        disasm='disasm_worldtileloader_mj_37.txt',
        base_add=13725708,
        base_literal=13725744,
        boundary='ARM.exidx end 0x00d17034 (listing bound); next ObjC IMP 0x00d17034 MJButton -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0xd1702c: (17168204, 'OBJC_IVAR_$_MJButton.tapAnimationDisabled', 272),
        },
        classes={},
        instructions=[(13725680, 'sub sp, sp, 0xc'), (13725744, 'eorseq r8, r4, r0, ror 21')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setTapAnimationDisabled:]] (imp 0x00d16ff0, 17w): -[setTapAnimationDisabled:] (0xd16ff0): atomic BOOL store - dmb ish; strb self+0x110; dmb ish..\n'),
    ),
    dict(
        name='mj_38',
        method='MJButton -[setTextureName:]',
        types='v12@0:4@8',
        start=13706620,
        end=13706868,
        disasm='disasm_worldtileloader_mj_38.txt',
        base_add=13706636,
        base_literal=13706864,
        boundary='ARM.exidx end 0x00d12674 (listing bound); next ObjC IMP 0x00d12674 MJButton -[setHidden:]',
        selectors={
                 0xd12660: (15238364, 'retain'),
                 0xd12664: (15238384, 'textureNamed:'),
                 0xd1266c: (15238352, 'release'),
        },
        imports={
                 0xd1265c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd12658: (17158044, 'OBJC_IVAR_$_MJButton.backgroundTexture', 112),
                 0xd12668: (17155620, 'OBJC_IVAR_$_MJView.cache', 48),
        },
        classes={},
        instructions=[(13706620, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (13706864, 'eorseq sp, r4, r0, ror 10')],
        calls=[(13706752, 'blx lr'), (13706792, 'blx ip'), (13706808, 'blx r2')],
        branches=[],
        semantics=('[MJButton -[setTextureName:]] (imp 0x00d1257c, 62w): [read] -[setTextureName:] (0xd1257c): [self.backgroundTexture release]; self.backgroundTexture = [[self.cache textureNamed:name] retain] - the only in-class texture-name loader besides the ctor..\n'),
    ),
    dict(
        name='mj_39',
        method='MJButton -[setTitle:]',
        types='v12@0:4@8',
        start=13700144,
        end=13701000,
        disasm='disasm_worldtileloader_mj_39.txt',
        base_add=13700160,
        base_literal=13700996,
        boundary='ARM.exidx end 0x00d10f88 (listing bound); next ObjC IMP 0x00d10f88 MJButton -[title]',
        selectors={
                 0xd10f60: (15238360, 'isEqualToString:'),
                 0xd10f68: (15238352, 'release'),
                 0xd10f6c: (15238364, 'retain'),
                 0xd10f7c: (15238356, 'createTitleWithColor:'),
        },
        imports={
                 0xd10f5c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd10f58: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
                 0xd10f64: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd10f70: (17158036, 'OBJC_IVAR_$_MJControl.enabled', 71),
                 0xd10f74: (17155708, 'OBJC_IVAR_$_MJView.color', 28),
        },
        classes={},
        instructions=[(13700144, 'push {r4, r5, r6, r7, fp, lr}'), (13700996, 'eorseq lr, r4, ip, lsr 29')],
        calls=[(13700356, 'blx r3'), (13700480, 'blx lr'), (13700500, 'blx r2'), (13700556, 'blx ip'), (13700724, 'bl 0xd10be4'), (13700772, 'bl loc.imp.objc_msgSend'), (13700884, 'bl 0xd10be4'), (13700932, 'bl loc.imp.objc_msgSend')],
        branches=[(13700212, 'bne', 13700232), (13700228, 'bne', 13700372), (13700244, 'bne', 13700288), (13700284, 'bne', 13700372), (13700368, 'bne', 13700944), (13700608, 'beq', 13700940), (13700644, 'beq', 13700780), (13700776, 'b', 13700936), (13700936, 'b', 13700940), (13700940, 'b', 13700944)],
        semantics=('[MJButton -[setTitle:]] (imp 0x00d10c30, 214w): [read] -[setTitle:] (0xd10c30): early-out when old and new titles are equal (both-nil handled before the isEqualToString: compare); otherwise [self.title release]; self.title = [title retain]; [self.titleView release]; self.titleView = nil; if title != nil -> createTitleWithColor:(enabled ? self.color : self.color*0.5)..\n'),
    ),
    dict(
        name='mj_40',
        method='MJButton -[setTitleAlignment:]',
        types='v12@0:4i8',
        start=13699592,
        end=13700068,
        disasm='disasm_worldtileloader_mj_40.txt',
        base_add=13699608,
        base_literal=13700064,
        boundary='ARM.exidx end 0x00d10be4 (listing bound); next ObjC IMP 0x00d10c30 MJButton -[setTitle:]',
        selectors={
                 0xd10bc8: (15238352, 'release'),
                 0xd10bd4: (15238356, 'createTitleWithColor:'),
        },
        imports={
                 0xd10bc4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd10bbc: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
                 0xd10bc0: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
                 0xd10bcc: (17168144, 'OBJC_IVAR_$_MJButton.titleAlignment', 104),
                 0xd10bd0: (17158036, 'OBJC_IVAR_$_MJControl.enabled', 71),
        },
        classes={},
        instructions=[(13699592, 'push {r4, r5, r6, r7, fp, lr}'), (13700064, 'ldrsbteq pc, [r4], -r4')],
        calls=[(13699724, 'blx r5'), (13699856, 'bl 0xd10be4'), (13699908, 'bl loc.imp.objc_msgSend'), (13699960, 'bl 0xd10be4'), (13700012, 'bl loc.imp.objc_msgSend')],
        branches=[(13699776, 'beq', 13700020), (13699812, 'beq', 13699916), (13699912, 'b', 13700016), (13700016, 'b', 13700020)],
        semantics=('[MJButton -[setTitleAlignment:]] (imp 0x00d10a08, 119w): [read] -[setTitleAlignment:] (0xd10a08): self.titleAlignment = align; [titleView release]; titleView = nil; if title != nil -> createTitleWithColor:(enabled ? (1,1,1,1) : (0.5,0.5,0.5,1)). The alignment case does not re-use self.color - white or half-gray is written literally..\n'),
    ),
    dict(
        name='mj_41',
        method='MJButton -[setTitleAlignmentB:]',
        types='v12@0:4i8',
        start=13723464,
        end=13723792,
        disasm='disasm_worldtileloader_mj_41.txt',
        base_add=13723480,
        base_literal=13723788,
        boundary='ARM.exidx end 0x00d16890 (listing bound); next ObjC IMP 0x00d16890 MJButton -[setTitleOffsetB:]',
        selectors={
                 0xd1687c: (15238352, 'release'),
                 0xd16884: (15238372, 'createTitleBWithColor:'),
        },
        imports={
                 0xd16878: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd16870: (17168156, 'OBJC_IVAR_$_MJButton.titleB', 240),
                 0xd16874: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
                 0xd16880: (17168252, 'OBJC_IVAR_$_MJButton.titleAlignmentB', 244),
        },
        classes={},
        instructions=[(13723464, 'push {r4, r5, r6, r7, fp, lr}'), (13723788, 'mlaseq r4, r4, r3, sb')],
        calls=[(13723592, 'blx r5'), (13723696, 'bl 0xd10be4'), (13723748, 'bl loc.imp.objc_msgSend')],
        branches=[(13723644, 'beq', 13723752)],
        semantics=('[MJButton -[setTitleAlignmentB:]] (imp 0x00d16748, 82w): [read] -[setTitleAlignmentB:] (0xd16748): self.titleAlignmentB = align; [titleViewB release]; titleViewB = nil; if titleB != nil -> createTitleBWithColor:((0.67,0.67,0.67,1); movw/movt 0x3f2b851f)..\n'),
    ),
    dict(
        name='mj_42',
        method='MJButton -[setTitleB:color:]',
        types='v28@0:4@8{MJColor=ffff}12',
        start=13722776,
        end=13723404,
        disasm='disasm_worldtileloader_mj_42.txt',
        base_add=13722792,
        base_literal=13723400,
        boundary='ARM.exidx end 0x00d1670c (listing bound); next ObjC IMP 0x00d1670c MJButton -[titleB]',
        selectors={
                 0xd166f0: (15238360, 'isEqualToString:'),
                 0xd166f8: (15238352, 'release'),
                 0xd166fc: (15238364, 'retain'),
                 0xd16700: (15238372, 'createTitleBWithColor:'),
        },
        imports={
                 0xd166ec: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd166e8: (17168156, 'OBJC_IVAR_$_MJButton.titleB', 240),
                 0xd166f4: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
        },
        classes={},
        instructions=[(13722776, 'push {r4, r5, r6, r7, fp, lr}'), (13723400, 'eorseq sb, r4, r4, asr 12')],
        calls=[(13723016, 'blx r3'), (13723140, 'blx lr'), (13723160, 'blx r2'), (13723216, 'blx ip'), (13723352, 'bl loc.imp.objc_msgSend')],
        branches=[(13722872, 'bne', 13722892), (13722888, 'bne', 13723032), (13722904, 'bne', 13722948), (13722944, 'bne', 13723032), (13723028, 'bne', 13723360), (13723268, 'beq', 13723356), (13723356, 'b', 13723360)],
        semantics=('[MJButton -[setTitleB:color:]] (imp 0x00d16498, 157w): [read] -[setTitleB:color:] (0xd16498, args: title @8, MJColor @12 in r3 + stack): equal-gate on titleB (both-nil handled first); [self.titleB release]; self.titleB = [title retain]; [self.titleViewB release]; titleViewB = nil; if titleB != nil -> createTitleBWithColor:passed color..\n'),
    ),
    dict(
        name='mj_43',
        method='MJButton -[setTitleOffset:]',
        types='v16@0:4{CGSize=ff}8',
        start=13721480,
        end=13721564,
        disasm='disasm_worldtileloader_mj_43.txt',
        base_add=13721492,
        base_literal=13721560,
        boundary='ARM.exidx end 0x00d15fdc (listing bound); next ObjC IMP 0x00d15fdc MJButton -[titleViewActualDimensions]',
        selectors={},
        imports={},
        ivars={
                 0xd15fd4: (17168164, 'OBJC_IVAR_$_MJButton.titleOffset', 232),
        },
        classes={},
        instructions=[(13721480, 'push {fp, lr}'), (13721560, 'eorseq sb, r4, r8, asr fp')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setTitleOffset:]] (imp 0x00d15f88, 21w): -[setTitleOffset:] (0xd15f88): writes the 8-byte CGSize argument (r2/r3) at self+0xe8 (two str)..\n'),
    ),
    dict(
        name='mj_44',
        method='MJButton -[setTitleOffsetB:]',
        types='v16@0:4{CGSize=ff}8',
        start=13723792,
        end=13723876,
        disasm='disasm_worldtileloader_mj_44.txt',
        base_add=13723804,
        base_literal=13723872,
        boundary='ARM.exidx end 0x00d168e4 (listing bound); next ObjC IMP 0x00d168e4 MJButton -[backgroundTexture]',
        selectors={},
        imports={},
        ivars={
                 0xd168dc: (17168248, 'OBJC_IVAR_$_MJButton.titleOffsetB', 252),
        },
        classes={},
        instructions=[(13723792, 'push {fp, lr}'), (13723872, 'eorseq sb, r4, r0, asr r2')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[setTitleOffsetB:]] (imp 0x00d16890, 21w): -[setTitleOffsetB:] (0xd16890): writes the 8-byte CGSize argument at self+0xfc..\n'),
    ),
    dict(
        name='mj_45',
        method='MJButton -[tapAnimationDisabled]',
        types='c8@0:4',
        start=13725620,
        end=13725680,
        disasm='disasm_worldtileloader_mj_45.txt',
        base_add=13725628,
        base_literal=13725676,
        boundary='ARM.exidx end 0x00d16ff0 (listing bound); next ObjC IMP 0x00d16ff0 MJButton -[setTapAnimationDisabled:]',
        selectors={},
        imports={},
        ivars={
                 0xd16fe8: (17168204, 'OBJC_IVAR_$_MJButton.tapAnimationDisabled', 272),
        },
        classes={},
        instructions=[(13725620, 'sub sp, sp, 8'), (13725676, 'eorseq r8, r4, r0, lsr fp')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[tapAnimationDisabled]] (imp 0x00d16fb4, 15w): Getter -[tapAnimationDisabled] (0xd16fb4): ldrsb BOOL; ivar @0x110 (272)..\n'),
    ),
    dict(
        name='mj_46',
        method='MJButton -[title]',
        types='@8@0:4',
        start=13701000,
        end=13701060,
        disasm='disasm_worldtileloader_mj_46.txt',
        base_add=13701008,
        base_literal=13701056,
        boundary='ARM.exidx end 0x00d10fc4 (listing bound); next ObjC IMP 0x00d10fc4 MJButton -[setEnabled:]',
        selectors={},
        imports={},
        ivars={
                 0xd10fbc: (17157960, 'OBJC_IVAR_$_MJButton.title', 100),
        },
        classes={},
        instructions=[(13701000, 'sub sp, sp, 8'), (13701056, 'eorseq lr, r4, ip, asr fp')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[title]] (imp 0x00d10f88, 15w): Getter -[title] (0xd10f88): offset-cell getter; ivar @0x64 (100)..\n'),
    ),
    dict(
        name='mj_47',
        method='MJButton -[titleB]',
        types='@8@0:4',
        start=13723404,
        end=13723464,
        disasm='disasm_worldtileloader_mj_47.txt',
        base_add=13723412,
        base_literal=13723460,
        boundary='ARM.exidx end 0x00d16748 (listing bound); next ObjC IMP 0x00d16748 MJButton -[setTitleAlignmentB:]',
        selectors={},
        imports={},
        ivars={
                 0xd16740: (17168156, 'OBJC_IVAR_$_MJButton.titleB', 240),
        },
        classes={},
        instructions=[(13723404, 'sub sp, sp, 8'), (13723460, 'ldrsbteq sb, [r4], -r8')],
        calls=[],
        branches=[],
        semantics=('[MJButton -[titleB]] (imp 0x00d1670c, 15w): Getter -[titleB] (0xd1670c): offset-cell getter; ivar @0xf0 (240)..\n'),
    ),
    dict(
        name='mj_48',
        method='MJButton -[titleViewActualDimensions]',
        types='{CGSize=ff}8@0:4',
        start=13721564,
        end=13721724,
        disasm='disasm_worldtileloader_mj_48.txt',
        base_add=13721580,
        base_literal=13721720,
        boundary='ARM.exidx end 0x00d1607c (listing bound); next ObjC IMP 0x00d1607c MJButton -[titleViewBActualDimensions]',
        selectors={
                 0xd16070: (15238448, 'actualDimensions'),
        },
        imports={},
        ivars={
                 0xd16074: (17168148, 'OBJC_IVAR_$_MJButton.titleView', 128),
        },
        classes={},
        instructions=[(13721564, 'push {r4, sl, fp, lr}'), (13721720, 'eorseq sb, r4, r0, lsl 22')],
        calls=[(13721664, 'bl loc.imp.objc_msgSend_stret'), (13721700, 'bl sym.imp.memset')],
        branches=[(13721648, 'beq', 13721672), (13721668, 'b', 13721704)],
        semantics=('[MJButton -[titleViewActualDimensions]] (imp 0x00d15fdc, 40w): [read] -[titleViewActualDimensions] (0xd15fdc): if titleView != nil -> objc_msgSend_stret [titleView actualDimensions] into the return buffer, else memset(buffer, 0, 8) (CGSize zero) - checked with cmp against 0..\n'),
    ),
    dict(
        name='mj_49',
        method='MJButton -[titleViewBActualDimensions]',
        types='{CGSize=ff}8@0:4',
        start=13721724,
        end=13721884,
        disasm='disasm_worldtileloader_mj_49.txt',
        base_add=13721740,
        base_literal=13721880,
        boundary='ARM.exidx end 0x00d1611c (listing bound); next ObjC IMP 0x00d1611c MJButton -[createTitleBWithColor:]',
        selectors={
                 0xd16110: (15238448, 'actualDimensions'),
        },
        imports={},
        ivars={
                 0xd16114: (17168152, 'OBJC_IVAR_$_MJButton.titleViewB', 248),
        },
        classes={},
        instructions=[(13721724, 'push {r4, sl, fp, lr}'), (13721880, 'eorseq sb, r4, r0, ror 20')],
        calls=[(13721824, 'bl loc.imp.objc_msgSend_stret'), (13721860, 'bl sym.imp.memset')],
        branches=[(13721808, 'beq', 13721832), (13721828, 'b', 13721864)],
        semantics=('[MJButton -[titleViewBActualDimensions]] (imp 0x00d1607c, 40w): [read] -[titleViewBActualDimensions] (0xd1607c): identical template for titleViewB (0xd1607c)..\n'),
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
        'batch': 'MJButton (E138): the button widget; 50 bodies',
        'claim': ('the MJButton widget (geometry, hit-test, render)'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'mjbutton.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale mjbutton.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
