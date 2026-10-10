#!/usr/bin/env python3
"""Hash-gated recovery of the light-emission parameter trio.

Ten bounded bodies from the pinned original libApplication.so (1.7.6,
armeabi-v7a) that feed the artificial-light system: the base colour
(-[ArtificialLight lightColor]), the per-emitter RGB / position / glow-quad
flags (Torch, GlowBlock, FireObject getLightRGB / lightPos /
lightGlowQuadCount / isDownlight / isUplight). Every instruction word is
re-verified against the pinned ELF; tool refuses to emit on drift.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl loc.imp.objc_msgSend_stret': 0x001C2918,
    'bl method.Vector.Vector__': 0x004BED60,
    'bl method.Vector.Vector_float__float__float_': 0x004B52AC,
    'bl method.Vector.operator_float__': 0x004B5C08,
    'bl method.Vector2.operator_float__': 0x004BDAAC,
    'bl sym.imp.memset': 0x001C2924,
}

SEMANTICS = {}
SEMANTICS['al_lightcolor'] = (
    'Builds Vector((float)maxRed, (float)maxGreen, (float)maxBlue): reads the '
    'int fields maxRed@64 (cell 0xa93c5c), maxGreen@68 (0xa93c58), '
    'maxBlue@72 (0xa93c54), converts each with vcvt.f32.s32 and passes them '
    'as the Vector ctor (r1=maxRed, r2=maxGreen, r3=maxBlue).'
)
SEMANTICS['fire_getlightrgb'] = (
    'Constant Vector(128.0f, 64.0f, 1.0f): vldr s0,[0x6746fc]=0x43000000 '
    '(128.0), vldr s2,[0x674700]=0x42800000 (64.0), vmov.f32 s4, 1 (1.0), '
    'then Vector ctor(r1=128.0, r2=64.0, r3=1.0).'
)
SEMANTICS['glow_getlightrgb'] = (
    'When self.light@56 (cell 0xca83cc) == nil: memset(out, 0, 0x10) - a zero '
    'Vector. Otherwise objc_msgSend_stret(out, self.light, '
    '@selector(lightColor)) through the stret import 0x1c2918; the selector '
    'comes from the cell at 0xe87b14 and the receiver is the light object.'
)
SEMANTICS['glow_lightpos'] = (
    'Vector(floatPos.x, floatPos.y + 5.0f, 0.0f): reads DynamicObject.floatPos '
    '@24 (cell 0xca9604) through Vector2::operator float*(), takes [0]=x, '
    '[4]+5.0f as y (vadd with vmov.f32 s2, 5) and 0.0f (pool 0xca9600) as z.'
)
SEMANTICS['glow_glowquadcount'] = (
    'return (GlowBlock.tileType@60 (cell 0xca9554) != 0x4d); -> 1 normally, '
    '0 when the glow block tile is type 0x4d (the light-only variant).'
)
SEMANTICS['torch_glowquadcount'] = (
    'return (Torch.itemType@64 (cell 0x4bede4) != 0x9d); -> 1 normally, '
    '0 for item type 0x9d (the torch variant without a glow quad).'
)
SEMANTICS['torch_isdownlight'] = (
    'return (Torch.itemType@64 (cells 0x4bee34/0x4bee88) == 0xfe); -> true '
    'for item type 0xfe (254), the downlight torch.'
)
SEMANTICS['torch_isuplight'] = (
    'return (Torch.itemType@64 (cell 0x4bee88) == 0x102); -> true for item '
    'type 0x102 (258), the uplight torch.'
)
SEMANTICS['torch_getlightrgb'] = (
    'Item-type dispatch over Torch.itemType@64 (cell 0x4b52a4) producing an '
    'int (r,g,b) later converted with vcvt.f32.s32 and passed to the Vector '
    'ctor. Default (no match) = (253, 150, 55). Table: 0x2f -> (255,255,127); '
    '0xb7 -> (12,100,220); 0x96 / 0xfe / 0x102 -> (300,300,170); 0x94 -> '
    '(510,130,130); 0x93 -> (130,510,130); 0x92 -> (130,130,510); 0x91 -> '
    '(270,230,510); 0x95 -> (400,510,510); 0x4b -> (220,0,0); 0x4c -> '
    '(0,220,0); 0x56 -> (0,0,220); 0x57 -> (135,115,220); 0x58 -> '
    '(200,255,255). The 0x4b/0x4c/0x56/0x57/0x58 kinds are exactly the torch '
    'types spawned by addToTiles (cross-consistent).'
)
SEMANTICS['torch_lightpos'] = (
    'Type x connection dispatch producing the light position from '
    'DynamicObject.floatPos@24. Base: out = (floatPos.x, floatPos.y + 5.0, '
    '-1.0). Then: if Torch.chandelier@78 (ldrsb, cell 0xffffc890) != 0 -> '
    'out.y = floatPos.y - 0.1 (pool 0x4be5c8), out.z = -5.0, done. Else if '
    'Torch.flatOnSideAndBottom@77 (ldrsb, cell 0xffffc898) != 0 -> dispatch '
    'on Torch.connectionType@60 (cell 0xffffc8bc) only: 0 -> (x, y, -1); '
    '3 -> (x, y, -0.1 (pool 0x4be6dc)); 1 -> (x + 0.45 (pool 0x4be6e0), y+5, '
    '-1); -1 -> (x - 0.45, y+5, -1); 2 -> unchanged; -2 -> z = -2; else '
    'unchanged. Else dispatch on Torch.itemType@64 first, then '
    'connectionType: 0x96 -> y += 0.4 (pool 0x4be824); 0xfe / 0x102 -> y += '
    '0.4; 0x2f -> y += 0.4; anything else -> y += 0.6 (pool 0x4bed4c); then '
    'connectionType sub-chains: generic (0x96/0xfe/0x102): 3 -> z = -5; 1 -> '
    'x += 2 (0x96) / x += 0.4 (0xfe,0x102); -1 -> x -= 2 / x -= 0.4; 2 -> '
    'keep; -2 -> z = -2; else keep. 0x2f chain: 3 -> z = -5; 1 -> y = '
    'floatPos.y + 0.6 (pool 0x4bec90), x += 0.4; -1 -> y = floatPos.y + 0.6, '
    'x -= 0.4 (pool 0x4bed58); 2 -> y = floatPos.y + 0.9 (pool 0x4bed50); '
    '-2 -> y = floatPos.y + 0.9, z = -2; else keep. default chain: 3 -> z = '
    '-5; 1 -> y = floatPos.y + 0.9, x += 0.1; -1 -> y = floatPos.y + 0.9, '
    'x -= 0.1; 2 -> y = floatPos.y + 0.9; -2 -> y = floatPos.y + 0.9, z = '
    '-2; else keep. Written into the out Vector via 38 x Vector::operator '
    'float*() and 25 x Vector2::operator float*() calls (light-nibble reads '
    'of [0] = x and [4] = y); all call sites anchored.'
)

SPECS = [
    dict(
        name='al_lightcolor', method='ArtificialLight -[lightColor]',
        types='{Vector=[4f]}8@0:4', start=0x00A93BBC, end=0x00A93C64,
        disasm='disasm_artificiallight_lightcolor.txt',
        base_add=0x00A93BCC, base_literal=0x00A93C60,
        boundary='own ARM.exidx bound 0x00a93c64 (next method IMP 0x00a93c64 = -[initWithWorld:dynamicWorld:saveDict:cache:parentObject:])',
        selectors={}, imports={},
        ivars={
            0x00A93C5C: (0x0105EA2C, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
            0x00A93C58: (0x0105EA30, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
            0x00A93C54: (0x0105EA34, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
        },
        instructions=[
            (0x00A93C00, 'vmov s0, r1'), (0x00A93C04, 'vcvt.f32.s32 s0, s0'),
            (0x00A93C1C, 'vcvt.f32.s32 s2, s2'),
            (0x00A93C34, 'vcvt.f32.s32 s4, s4'),
            (0x00A93C44, 'bl method.Vector.Vector_float__float__float_'),
        ],
        semantics=SEMANTICS['al_lightcolor'],
        calls=[
            (0x00a93c44, 'bl method.Vector.Vector_float__float__float_'),
        ], branches=[],
    ),
    dict(
        name='fire_getlightrgb', method='FireObject -[getLightRGB]',
        types='{Vector=[4f]}8@0:4', start=0x006746A4, end=0x00674704,
        disasm='disasm_fireobject_getlightrgb.txt',
        base_add=None, base_literal=None,
        boundary='own ARM.exidx bound 0x00674704 (next method IMP 0x00674704 = -[initWithWorld:dynamicWorld:atPosition:cache:])',
        selectors={}, imports={}, ivars={},
        instructions=[
            (0x006746B4, 'vldr s0, [0x006746fc]'),
            (0x006746BC, 'vldr s2, [0x00674700]'),
            (0x006746C4, 'vmov.f32 s4, 1'),
            (0x006746EC, 'bl method.Vector.Vector_float__float__float_'),
        ],
        semantics=SEMANTICS['fire_getlightrgb'],
        calls=[
            (0x006746ec, 'bl method.Vector.Vector_float__float__float_'),
        ], branches=[],
    ),
    dict(
        name='glow_getlightrgb', method='GlowBlock -[getLightRGB]',
        types='{Vector=[4f]}8@0:4', start=0x00CA8334, end=0x00CA83D4,
        disasm='disasm_glowblock_getlightrgb.txt',
        base_add=0x00CA8344, base_literal=0x00CA83D0,
        boundary='own ARM.exidx bound 0x00ca83d4 (next method IMP 0x00ca83d4 = -[initWithWorld:dynamicWorld:atPosition:cache:tile:])',
        selectors={0x00CA83C8: (0x00E87B14, 'lightColor')}, imports={},
        ivars={0x00CA83CC: (0x0105F45C, 'OBJC_IVAR_$_GlowBlock.light', 56)},
        instructions=[
            (0x00CA8378, 'cmp r1, ip'),
            (0x00CA8398, 'bl loc.imp.objc_msgSend_stret'),
            (0x00CA83A4, 'movw r2, 0x10'),
            (0x00CA83BC, 'bl sym.imp.memset'),
        ],
        semantics=SEMANTICS['glow_getlightrgb'],
        calls=[
            (0x00ca8398, 'bl loc.imp.objc_msgSend_stret'),
            (0x00ca83bc, 'bl sym.imp.memset'),
        ], branches=[
            (0x00ca8388, 'beq', 0x00ca83a0),
            (0x00ca839c, 'b', 0x00ca83c0),
        ],
    ),
    dict(
        name='glow_lightpos', method='GlowBlock -[lightPos]',
        types='{Vector=[4f]}8@0:4', start=0x00CA955C, end=0x00CA960C,
        disasm='disasm_glowblock_lightpos.txt',
        base_add=0x00CA956C, base_literal=0x00CA9608,
        boundary='own ARM.exidx bound 0x00ca960c (next method IMP 0x00ca960c = -[addArtificialLightContributionForPhysicalBlockLoadedAtXPos:yPos:])',
        selectors={}, imports={},
        ivars={0x00CA9604: (0x0105C3D0, 'OBJC_IVAR_$_DynamicObject.floatPos', 24)},
        instructions=[
            (0x00CA95C4, 'vldr s0, [0x00ca9600]'),
            (0x00CA95C8, 'vmov.f32 s2, 5'),
            (0x00CA95D0, 'vadd.f32 s2, s4, s2'),
            (0x00CA95F0, 'bl method.Vector.Vector_float__float__float_'),
        ],
        semantics=SEMANTICS['glow_lightpos'],
        calls=[
            (0x00ca9598, 'bl method.Vector2.operator_float__'),
            (0x00ca95bc, 'bl method.Vector2.operator_float__'),
            (0x00ca95f0, 'bl method.Vector.Vector_float__float__float_'),
        ], branches=[],
    ),
    dict(
        name='glow_glowquadcount', method='GlowBlock -[lightGlowQuadCount]',
        types='i8@0:4', start=0x00CA9500, end=0x00CA955C,
        disasm='disasm_glowblock_glowquadcount.txt',
        base_add=0x00CA9508, base_literal=0x00CA9558,
        boundary='own ARM.exidx bound 0x00ca955c (next method IMP 0x00ca955c = -[lightPos])',
        selectors={}, imports={},
        ivars={0x00CA9554: (0x0105F460, 'OBJC_IVAR_$_GlowBlock.tileType', 60)},
        instructions=[
            (0x00CA952C, 'cmp r0, 0x4d'),
            (0x00CA9534, 'movw r0, 0'),
            (0x00CA9540, 'movw r0, 1'),
        ],
        semantics=SEMANTICS['glow_glowquadcount'],
        calls=[], branches=[
            (0x00ca9530, 'bne', 0x00ca9540),
            (0x00ca953c, 'b', 0x00ca9548),
        ],
    ),
    dict(
        name='torch_getlightrgb', method='Torch -[getLightRGB]',
        types='{Vector=[4f]}8@0:4', start=0x004B4E98, end=0x004B52AC,
        disasm='disasm_torch_getlightrgb.txt',
        base_add=0x004B4EA8, base_literal=0x004B52A8,
        boundary='own ARM.exidx bound 0x004b52ac (next method IMP 0x004b52ac = -[initWithWorld:dynamicWorld:atPosition:cache:type:dataA:dataB:saveDict:placedByClient:])',
        selectors={}, imports={},
        ivars={0x004B52A4: (0x0105C380, 'OBJC_IVAR_$_Torch.itemType', 64)},
        instructions=[
            (0x004B4EB4, 'movw lr, 0x37'), (0x004B4EB8, 'movw r4, 0x96'),
            (0x004B4EBC, 'movw r5, 0xfd'), (0x004B4EE4, 'cmp r1, 0x2f'),
            (0x004B4EF4, 'movw r0, 0x7f'), (0x004B4EF8, 'movw r1, 0xff'),
            (0x004B4F28, 'cmp r0, 0xb7'), (0x004B4F30, 'movw r0, 0xdc'),
            (0x004B4F34, 'movw r1, 0x64'), (0x004B4F38, 'movw r2, 0xc'),
            (0x004B4F68, 'cmp r0, 0x96'), (0x004B4F8C, 'cmp r0, 0xfe'),
            (0x004B4F94, 'movw r0, 0x102'), (0x004B4FB4, 'cmp r1, r0'),
            (0x004B4FBC, 'movw r0, 0xaa'), (0x004B4FC0, 'movw r1, 0x12c'),
            (0x004B4FF0, 'cmp r0, 0x94'), (0x004B4FF8, 'movw r0, 0x82'),
            (0x004B4FFC, 'movw r1, 0x1fe'), (0x004B502C, 'cmp r0, 0x93'),
            (0x004B5068, 'cmp r0, 0x92'), (0x004B5070, 'movw r0, 0x1fe'),
            (0x004B50A4, 'cmp r0, 0x91'), (0x004B50B0, 'movw r1, 0xe6'),
            (0x004B50B4, 'movw r2, 0x10e'), (0x004B50E4, 'cmp r0, 0x95'),
            (0x004B50F0, 'movw r1, 0x190'), (0x004B5120, 'cmp r0, 0x4b'),
            (0x004B512C, 'movw r1, 0xdc'), (0x004B515C, 'cmp r0, 0x4c'),
            (0x004B5198, 'cmp r0, 0x56'), (0x004B51D4, 'cmp r0, 0x57'),
            (0x004B51E0, 'movw r1, 0x73'), (0x004B51E4, 'movw r2, 0x87'),
            (0x004B5214, 'cmp r0, 0x58'), (0x004B521C, 'movw r0, 0xff'),
            (0x004B5220, 'movw r1, 0xc8'),
            (0x004B5264, 'vmov s0, r0'),
            (0x004B5294, 'bl method.Vector.Vector_float__float__float_'),
        ],
        semantics=SEMANTICS['torch_getlightrgb'],
        calls=[
            (0x004b5294, 'bl method.Vector.Vector_float__float__float_'),
        ], branches=[
            (0x004b4ef0, 'bne', 0x004b4f0c),
            (0x004b4f08, 'b', 0x004b5260),
            (0x004b4f2c, 'bne', 0x004b4f4c),
            (0x004b4f48, 'b', 0x004b525c),
            (0x004b4f6c, 'beq', 0x004b4fbc),
            (0x004b4f90, 'beq', 0x004b4fbc),
            (0x004b4fb8, 'bne', 0x004b4fd4),
            (0x004b4fd0, 'b', 0x004b5258),
            (0x004b4ff4, 'bne', 0x004b5010),
            (0x004b500c, 'b', 0x004b5254),
            (0x004b5030, 'bne', 0x004b504c),
            (0x004b5048, 'b', 0x004b5250),
            (0x004b506c, 'bne', 0x004b5088),
            (0x004b5084, 'b', 0x004b524c),
            (0x004b50a8, 'bne', 0x004b50c8),
            (0x004b50c4, 'b', 0x004b5248),
            (0x004b50e8, 'bne', 0x004b5104),
            (0x004b5100, 'b', 0x004b5244),
            (0x004b5124, 'bne', 0x004b5140),
            (0x004b513c, 'b', 0x004b5240),
            (0x004b5160, 'bne', 0x004b517c),
            (0x004b5178, 'b', 0x004b523c),
            (0x004b519c, 'bne', 0x004b51b8),
            (0x004b51b4, 'b', 0x004b5238),
            (0x004b51d8, 'bne', 0x004b51f8),
            (0x004b51f4, 'b', 0x004b5234),
            (0x004b5218, 'bne', 0x004b5230),
            (0x004b5230, 'b', 0x004b5234),
            (0x004b5234, 'b', 0x004b5238),
            (0x004b5238, 'b', 0x004b523c),
            (0x004b523c, 'b', 0x004b5240),
            (0x004b5240, 'b', 0x004b5244),
            (0x004b5244, 'b', 0x004b5248),
            (0x004b5248, 'b', 0x004b524c),
            (0x004b524c, 'b', 0x004b5250),
            (0x004b5250, 'b', 0x004b5254),
            (0x004b5254, 'b', 0x004b5258),
            (0x004b5258, 'b', 0x004b525c),
            (0x004b525c, 'b', 0x004b5260),
        ],
    ),
    dict(
        name='torch_glowquadcount', method='Torch -[lightGlowQuadCount]',
        types='i8@0:4', start=0x004BED90, end=0x004BEDEC,
        disasm='disasm_torch_glowquadcount.txt',
        base_add=0x004BED98, base_literal=0x004BEDE8,
        boundary='own ARM.exidx bound 0x004bedec (next method IMP 0x004bedec = -[isDownlight])',
        selectors={}, imports={},
        ivars={0x004BEDE4: (0x0105C380, 'OBJC_IVAR_$_Torch.itemType', 64)},
        instructions=[
            (0x004BEDBC, 'cmp r0, 0x9d'),
            (0x004BEDC4, 'movw r0, 0'),
            (0x004BEDD0, 'movw r0, 1'),
        ],
        semantics=SEMANTICS['torch_glowquadcount'],
        calls=[], branches=[
            (0x004bedc0, 'bne', 0x004bedd0),
            (0x004bedcc, 'b', 0x004bedd8),
        ],
    ),
    dict(
        name='torch_isdownlight', method='Torch -[isDownlight]',
        types='c8@0:4', start=0x004BEDEC, end=0x004BEE3C,
        disasm='disasm_torch_isdownlight.txt',
        base_add=0x004BEDF4, base_literal=0x004BEE38,
        boundary='IMP-bounded body end 0x004bee3c (next method IMP 0x004bee3c = -[isUplight]); the disassembly file carries the shared exidx bound 0x004beeac',
        selectors={}, imports={},
        ivars={
            0x004BEE34: (0x0105C380, 'OBJC_IVAR_$_Torch.itemType', 64),
            0x004BEE88: (0x0105C380, 'OBJC_IVAR_$_Torch.itemType', 64),
        },
        instructions=[
            (0x004BEE18, 'cmp r0, 0xfe'),
            (0x004BEE24, 'and r0, r0, 1'),
            (0x004BEE28, 'sxtb r0, r0'),
        ],
        semantics=SEMANTICS['torch_isdownlight'],
        calls=[], branches=[],
    ),
    dict(
        name='torch_isuplight', method='Torch -[isUplight]',
        types='c8@0:4', start=0x004BEE3C, end=0x004BEE90,
        disasm='disasm_torch_isuplight.txt',
        base_add=0x004BEE44, base_literal=0x004BEE8C,
        boundary='IMP-bounded body end 0x004bee90 (next method IMP 0x004bee90 = -[occupiesForegroundContents]); the disassembly file carries the shared exidx bound 0x004beeac',
        selectors={}, imports={},
        ivars={0x004BEE88: (0x0105C380, 'OBJC_IVAR_$_Torch.itemType', 64)},
        instructions=[
            (0x004BEE48, 'movw r3, 0x102'),
            (0x004BEE6C, 'cmp r0, r3'),
            (0x004BEE78, 'and r0, r0, 1'),
        ],
        semantics=SEMANTICS['torch_isuplight'],
        calls=[], branches=[],
    ),
    dict(
        name='torch_lightpos', method='Torch -[lightPos]',
        types='{Vector=[4f]}8@0:4', start=0x004BE0D4, end=0x004BED60,
        disasm='disasm_torch_lightpos.txt',
        base_add=0x004BE0E4, base_literal=0x004BED5C,
        boundary='own ARM.exidx bound 0x004bed60 (next method IMP 0x004bed60 = method.Vector::Vector() region)',
        selectors={}, imports={},
        ivars={
            0x004BED38: (0x0105C384, 'OBJC_IVAR_$_Torch.chandelier', 78),
            0x004BED3C: (0x0105C3D0, 'OBJC_IVAR_$_DynamicObject.floatPos', 24),
            0x004BED40: (0x0105C38C, 'OBJC_IVAR_$_Torch.flatOnSideAndBottom', 77),
            0x004BED44: (0x0105C380, 'OBJC_IVAR_$_Torch.itemType', 64),
            0x004BED48: (0x0105C3B0, 'OBJC_IVAR_$_Torch.connectionType', 60),
        },
        instructions=[
            (0x004BE0F8, 'bl method.Vector.Vector__'),
            (0x004BE154, 'vmov.f32 s0, 5'),
            (0x004BE15C, 'vadd.f32 s0, s2, s0'),
            (0x004BE18C, 'vmov.f32 s0, -1'),
            (0x004BE1A0, 'ldrsb r0, [r0]'),
            (0x004BE1CC, 'vldr s0, [0x004be5c8]'),
            (0x004BE1D4, 'vsub.f32 s0, s2, s0'),
            (0x004BE1F4, 'vmov.f32 s0, -5'),
            (0x004BE2F0, 'vldr s0, [0x004be6dc]'),
            (0x004BE33C, 'vldr s0, [0x004be6e0]'),
            (0x004BE45C, 'cmp r0, 0x96'),
            (0x004BE480, 'vldr s0, [0x004be824]'),
            (0x004BE4BC, 'cmp r0, 3'),
            (0x004BE638, 'cmp r0, 0xfe'),
            (0x004BE660, 'cmp r1, r0'),
            (0x004BE844, 'cmp r0, 0x2f'),
            (0x004BE8A4, 'cmp r0, 3'),
            (0x004BE8DC, 'cmp r0, 1'),
            (0x004BE900, 'vldr s0, [0x004bec90]'),
            (0x004BE97C, 'cmn r0, 1'),
            (0x004BE9A0, 'vldr s0, [0x004bed4c]'),
            (0x004BEA1C, 'cmp r0, 2'),
            (0x004BEA44, 'cmn r0, 2'),
            (0x004BEA94, 'vldr s0, [0x004bed4c]'),
            (0x004BEB2C, 'vldr s0, [0x004bed50]'),
            (0x004BEB68, 'vldr s0, [0x004bed54]'),
            (0x004BEC08, 'vldr s0, [0x004bed54]'),
            (0x004BEC6C, 'vldr s0, [0x004bed50]'),
            (0x004BECD4, 'vldr s0, [0x004bed50]'),
        ],
        semantics=SEMANTICS['torch_lightpos'],
        calls=[
            (0x004be0f8, 'bl method.Vector.Vector__'),
            (0x004be11c, 'bl method.Vector2.operator_float__'),
            (0x004be12c, 'bl method.Vector.operator_float__'),
            (0x004be150, 'bl method.Vector2.operator_float__'),
            (0x004be168, 'bl method.Vector.operator_float__'),
            (0x004be178, 'bl method.Vector.operator_float__'),
            (0x004be1c8, 'bl method.Vector2.operator_float__'),
            (0x004be1e0, 'bl method.Vector.operator_float__'),
            (0x004be1f0, 'bl method.Vector.operator_float__'),
            (0x004be260, 'bl method.Vector2.operator_float__'),
            (0x004be270, 'bl method.Vector.operator_float__'),
            (0x004be280, 'bl method.Vector.operator_float__'),
            (0x004be2cc, 'bl method.Vector2.operator_float__'),
            (0x004be2dc, 'bl method.Vector.operator_float__'),
            (0x004be2ec, 'bl method.Vector.operator_float__'),
            (0x004be338, 'bl method.Vector2.operator_float__'),
            (0x004be350, 'bl method.Vector.operator_float__'),
            (0x004be39c, 'bl method.Vector2.operator_float__'),
            (0x004be3b4, 'bl method.Vector.operator_float__'),
            (0x004be414, 'bl method.Vector.operator_float__'),
            (0x004be47c, 'bl method.Vector2.operator_float__'),
            (0x004be494, 'bl method.Vector.operator_float__'),
            (0x004be4c8, 'bl method.Vector.operator_float__'),
            (0x004be514, 'bl method.Vector2.operator_float__'),
            (0x004be52c, 'bl method.Vector.operator_float__'),
            (0x004be578, 'bl method.Vector2.operator_float__'),
            (0x004be590, 'bl method.Vector.operator_float__'),
            (0x004be5f4, 'bl method.Vector.operator_float__'),
            (0x004be680, 'bl method.Vector2.operator_float__'),
            (0x004be698, 'bl method.Vector.operator_float__'),
            (0x004be6cc, 'bl method.Vector.operator_float__'),
            (0x004be720, 'bl method.Vector2.operator_float__'),
            (0x004be738, 'bl method.Vector.operator_float__'),
            (0x004be784, 'bl method.Vector2.operator_float__'),
            (0x004be79c, 'bl method.Vector.operator_float__'),
            (0x004be7fc, 'bl method.Vector.operator_float__'),
            (0x004be864, 'bl method.Vector2.operator_float__'),
            (0x004be87c, 'bl method.Vector.operator_float__'),
            (0x004be8b0, 'bl method.Vector.operator_float__'),
            (0x004be8fc, 'bl method.Vector2.operator_float__'),
            (0x004be914, 'bl method.Vector.operator_float__'),
            (0x004be938, 'bl method.Vector2.operator_float__'),
            (0x004be950, 'bl method.Vector.operator_float__'),
            (0x004be99c, 'bl method.Vector2.operator_float__'),
            (0x004be9b4, 'bl method.Vector.operator_float__'),
            (0x004be9d8, 'bl method.Vector2.operator_float__'),
            (0x004be9f0, 'bl method.Vector.operator_float__'),
            (0x004bea50, 'bl method.Vector.operator_float__'),
            (0x004bea90, 'bl method.Vector2.operator_float__'),
            (0x004beaa8, 'bl method.Vector.operator_float__'),
            (0x004beadc, 'bl method.Vector.operator_float__'),
            (0x004beb28, 'bl method.Vector2.operator_float__'),
            (0x004beb40, 'bl method.Vector.operator_float__'),
            (0x004beb64, 'bl method.Vector2.operator_float__'),
            (0x004beb7c, 'bl method.Vector.operator_float__'),
            (0x004bebc8, 'bl method.Vector2.operator_float__'),
            (0x004bebe0, 'bl method.Vector.operator_float__'),
            (0x004bec04, 'bl method.Vector2.operator_float__'),
            (0x004bec1c, 'bl method.Vector.operator_float__'),
            (0x004bec68, 'bl method.Vector2.operator_float__'),
            (0x004bec80, 'bl method.Vector.operator_float__'),
            (0x004becd0, 'bl method.Vector2.operator_float__'),
            (0x004bece8, 'bl method.Vector.operator_float__'),
            (0x004becf8, 'bl method.Vector.operator_float__'),
        ], branches=[
            (0x004be1ac, 'beq', 0x004be200),
            (0x004be1fc, 'b', 0x004bed30),
            (0x004be220, 'beq', 0x004be440),
            (0x004be244, 'bne', 0x004be290),
            (0x004be28c, 'b', 0x004be43c),
            (0x004be2b0, 'bne', 0x004be2fc),
            (0x004be2f8, 'b', 0x004be438),
            (0x004be31c, 'bne', 0x004be360),
            (0x004be35c, 'b', 0x004be434),
            (0x004be380, 'bne', 0x004be3c4),
            (0x004be3c0, 'b', 0x004be430),
            (0x004be3e4, 'bne', 0x004be3ec),
            (0x004be3e8, 'b', 0x004be42c),
            (0x004be40c, 'bne', 0x004be428),
            (0x004be428, 'b', 0x004be42c),
            (0x004be42c, 'b', 0x004be430),
            (0x004be430, 'b', 0x004be434),
            (0x004be434, 'b', 0x004be438),
            (0x004be438, 'b', 0x004be43c),
            (0x004be43c, 'b', 0x004bed2c),
            (0x004be460, 'bne', 0x004be61c),
            (0x004be4c0, 'bne', 0x004be4d8),
            (0x004be4d4, 'b', 0x004be618),
            (0x004be4f8, 'bne', 0x004be53c),
            (0x004be538, 'b', 0x004be614),
            (0x004be55c, 'bne', 0x004be5a0),
            (0x004be59c, 'b', 0x004be610),
            (0x004be5c0, 'bne', 0x004be5cc),
            (0x004be5c4, 'b', 0x004be60c),
            (0x004be5ec, 'bne', 0x004be608),
            (0x004be608, 'b', 0x004be60c),
            (0x004be60c, 'b', 0x004be610),
            (0x004be610, 'b', 0x004be614),
            (0x004be614, 'b', 0x004be618),
            (0x004be618, 'b', 0x004bed28),
            (0x004be63c, 'beq', 0x004be668),
            (0x004be664, 'bne', 0x004be828),
            (0x004be6c4, 'bne', 0x004be6e4),
            (0x004be6d8, 'b', 0x004be820),
            (0x004be704, 'bne', 0x004be748),
            (0x004be744, 'b', 0x004be81c),
            (0x004be768, 'bne', 0x004be7ac),
            (0x004be7a8, 'b', 0x004be818),
            (0x004be7cc, 'bne', 0x004be7d4),
            (0x004be7d0, 'b', 0x004be814),
            (0x004be7f4, 'bne', 0x004be810),
            (0x004be810, 'b', 0x004be814),
            (0x004be814, 'b', 0x004be818),
            (0x004be818, 'b', 0x004be81c),
            (0x004be81c, 'b', 0x004be820),
            (0x004be820, 'b', 0x004bed24),
            (0x004be848, 'bne', 0x004bea78),
            (0x004be8a8, 'bne', 0x004be8c0),
            (0x004be8bc, 'b', 0x004bea74),
            (0x004be8e0, 'bne', 0x004be960),
            (0x004be95c, 'b', 0x004bea70),
            (0x004be980, 'bne', 0x004bea00),
            (0x004be9fc, 'b', 0x004bea6c),
            (0x004bea20, 'bne', 0x004bea28),
            (0x004bea24, 'b', 0x004bea68),
            (0x004bea48, 'bne', 0x004bea64),
            (0x004bea64, 'b', 0x004bea68),
            (0x004bea68, 'b', 0x004bea6c),
            (0x004bea6c, 'b', 0x004bea70),
            (0x004bea70, 'b', 0x004bea74),
            (0x004bea74, 'b', 0x004bed20),
            (0x004bead4, 'bne', 0x004beaec),
            (0x004beae8, 'b', 0x004bed1c),
            (0x004beb0c, 'bne', 0x004beb8c),
            (0x004beb88, 'b', 0x004bed18),
            (0x004bebac, 'bne', 0x004bec2c),
            (0x004bec28, 'b', 0x004bed14),
            (0x004bec4c, 'bne', 0x004bec94),
            (0x004bec8c, 'b', 0x004bed10),
            (0x004becb4, 'bne', 0x004bed0c),
            (0x004bed0c, 'b', 0x004bed10),
            (0x004bed10, 'b', 0x004bed14),
            (0x004bed14, 'b', 0x004bed18),
            (0x004bed18, 'b', 0x004bed1c),
            (0x004bed1c, 'b', 0x004bed20),
            (0x004bed20, 'b', 0x004bed24),
            (0x004bed24, 'b', 0x004bed28),
            (0x004bed28, 'b', 0x004bed2c),
            (0x004bed2c, 'b', 0x004bed30),
        ],
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

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in ELFFile(io.BytesIO(data)).iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)

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

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

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

        listed_branches = {(a, m.group(1), int(m.group(2), 16))
                           for a, ins in inrange.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
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
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'light-emission parameter trio (ArtificialLight/Torch/GlowBlock/FireObject)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'lightemitters.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale lightemitters.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
