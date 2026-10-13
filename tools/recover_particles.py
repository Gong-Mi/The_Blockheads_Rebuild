#!/usr/bin/env python3
"""Hash-gated recovery of the DynamicWorld block-load/accessor smalls (E35).

The electricity line: the ParticleEmitter (the electric arc visual system): the repair removal, the client-
blockhead receive, the portal checks, the loaded-count, the gather pair, the
client/server booleans, the net/all-blockhead merges, the portal-positions and
blockheads getters and the connection-loss stub:
1 body, 6662 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/PARTICLES.md for the prose and boundaries.
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
    'bl 0xd86ddc': 0x00d86ddc,
    'bl 0xd8c67c': 0x00d8c67c,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator__Vector_': 0x00668924,
    'bl method.Vector.operator_float_': 0x004da9cc,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.Vector2_float__float_': 0x004d0480,
    'bl method.Vector2.normal__': 0x00575108,
    'bl method.Vector2.operator__Vector2_': 0x004d04b4,
    'bl method.Vector2.operator__float_': 0x004d03c0,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::enable_if___is_forward_iterator_ElectrictyParticlePathIndex_::value__void_::type_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.assign_ElectrictyParticlePathIndex__ElectrictyParticlePathIndex__ElectrictyParticlePathIndex_': 0x00d8cd3c,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__': 0x005cb054,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.at_unsigned_long_': 0x00d87b04,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_': 0x005caef8,
    'bl sym.closestPointOnLineToPoint_Vector__Vector__Vector_': 0x00668a34,
    'bl sym.imp._Unwind_Resume': 0x001c29c0,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__wrap_calloc': 0x001c2fe4,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glDisableVertexAttribArray': 0x001c3d58,
    'bl sym.imp.__wrap_glDrawArrays': 0x001c2ccc,
    'bl sym.imp.__wrap_glDrawElements': 0x001c2df8,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glEnableVertexAttribArray': 0x001c2d5c,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.__wrap_glVertexAttribPointer': 0x001c2dec,
    'bl sym.linearInterpolatev_Vector__Vector__float_': 0x00c38b6c,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00a16e68,
    'bl sym.tileIsAir_Tile_': 0x00a12300,
}

SPECS = [
    dict(
        name='pe_init',
        method='ParticleEmitter -[init]',
        types='@8@0:4',
        start=14180248,
        end=14183900,
        disasm='disasm_worldtileloader_pe_init.txt',
        base_add=14180264,
        base_literal=14183896,
        boundary='ARM.exidx end 0x00d86ddc (listing bound); next ObjC IMP 0x00d86dec ParticleEmitter -[setWorld:]',
        selectors={
                 0xd86d1c: (15240396, 'init'),
                 0xd86d34: (15240392, 'alloc'),
                 0xd86d68: (15240420, 'initWithShaderVertexFile:fragmentFile:attributes:uniforms:'),
                 0xd86d70: (15240416, 'arrayWithObjects:'),
                 0xd86d84: (15240412, 'stringByAppendingPathComponent:'),
                 0xd86d8c: (15240408, 'resourcePath'),
                 0xd86d90: (15240404, 'mainBundle'),
                 0xd86da4: (15240428, 'initWithFrequencyX:frequencyY:frequencyZ:amplitude:seed:tileable:loop:persistance:'),
                 0xd86dc4: (15240424, 'initWithImagePath:'),
                 0xd86dd4: (15240400, 'addIndex:'),
        },
        imports={
                 0xd86d18: (17151900, 'objc_msgSendSuper2'),
                 0xd86d30: (17151904, 'objc_msgSend'),
                 0xd86d6c: (16444296, '__CFConstantStringClassReference'),
                 0xd86d78: (16444264, '__CFConstantStringClassReference'),
                 0xd86d7c: (16444280, '__CFConstantStringClassReference'),
                 0xd86d80: (16444248, '__CFConstantStringClassReference'),
                 0xd86d88: (16444216, '__CFConstantStringClassReference'),
                 0xd86d98: (16444232, '__CFConstantStringClassReference'),
                 0xd86db0: (16444376, '__CFConstantStringClassReference'),
                 0xd86db4: (16444360, '__CFConstantStringClassReference'),
                 0xd86db8: (16444344, '__CFConstantStringClassReference'),
                 0xd86dbc: (16444328, '__CFConstantStringClassReference'),
                 0xd86dc8: (16444312, '__CFConstantStringClassReference'),
        },
        ivars={
                 0xd86d24: (17168892, 'OBJC_IVAR_$_ParticleEmitter.glData', 24),
                 0xd86d28: (17168896, 'OBJC_IVAR_$_ParticleEmitter.particles', 8),
                 0xd86d2c: (17168900, 'OBJC_IVAR_$_ParticleEmitter.takenIndices', 20),
                 0xd86d3c: (17168904, 'OBJC_IVAR_$_ParticleEmitter.freeIndices', 16),
                 0xd86d40: (17168908, 'OBJC_IVAR_$_ParticleEmitter.electrictyGlData', 60),
                 0xd86d44: (17168912, 'OBJC_IVAR_$_ParticleEmitter.electrictyParticles', 48),
                 0xd86d48: (17168916, 'OBJC_IVAR_$_ParticleEmitter.electrictyTakenIndices', 56),
                 0xd86d4c: (17168920, 'OBJC_IVAR_$_ParticleEmitter.electrictyFreeIndices', 52),
                 0xd86d50: (17168924, 'OBJC_IVAR_$_ParticleEmitter.bonusGlIndices', 80),
                 0xd86d54: (17168928, 'OBJC_IVAR_$_ParticleEmitter.bonusGlData', 76),
                 0xd86d58: (17168932, 'OBJC_IVAR_$_ParticleEmitter.bonusParticles', 64),
                 0xd86d5c: (17168936, 'OBJC_IVAR_$_ParticleEmitter.bonusTakenIndices', 72),
                 0xd86d60: (17168940, 'OBJC_IVAR_$_ParticleEmitter.bonusFreeIndices', 68),
                 0xd86d64: (17168944, 'OBJC_IVAR_$_ParticleEmitter.shader', 28),
                 0xd86da0: (17168948, 'OBJC_IVAR_$_ParticleEmitter.noiseFunction', 12),
                 0xd86dac: (17168952, 'OBJC_IVAR_$_ParticleEmitter.bonusShader', 84),
                 0xd86dc0: (17168956, 'OBJC_IVAR_$_ParticleEmitter.bonusTexture', 88),
        },
        classes={
                 0xd86d20: (15253300, 'OBJC_CLASS_$_ParticleEmitter'),
                 0xd86d38: (15251412, 'OBJC_CLASS_$_NSMutableIndexSet'),
                 0xd86d74: (15251424, 'OBJC_CLASS_$_NSArray'),
                 0xd86d94: (15251420, 'OBJC_CLASS_$_NSBundle'),
                 0xd86d9c: (15251416, 'OBJC_CLASS_$_Shader'),
                 0xd86da8: (15251432, 'OBJC_CLASS_$_NoiseFunction'),
                 0xd86dcc: (15251428, 'OBJC_CLASS_$_CPTexture2D'),
        },
        instructions=[(14180248, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14180332, 'blx ip'), (14180612, 'ldr r3, [0x00d86d28]'), (14180696, 'cmp r0, 0x800'), (14183704, 'invalid'), (14183896, 'eoreq sb, sp, r4, asr 22')],
        calls=[(14180332, 'blx ip'), (14180484, 'blx ip'), (14180500, 'blx r2'), (14180552, 'blx ip'), (14180568, 'blx r2'), (14180600, 'bl sym.imp.__wrap_calloc'), (14180648, 'bl sym.imp.__wrap_calloc'), (14180772, 'blx r3'), (14180900, 'blx ip'), (14180916, 'blx r2'), (14180968, 'blx ip'), (14180984, 'blx r2'), (14181016, 'bl sym.imp.__wrap_calloc'), (14181064, 'bl sym.imp.__wrap_calloc'), (14181184, 'blx r3'), (14181584, 'blx lr'), (14181616, 'blx r2'), (14181632, 'blx r2'), (14181652, 'blx r3'), (14181672, 'blx r3'), (14181704, 'blx r2'), (14181720, 'blx r2'), (14181740, 'blx r3'), (14181760, 'blx r3'), (14181808, 'blx lr'), (14181848, 'blx ip'), (14181900, 'blx r4'), (14181952, 'blx ip'), (14181968, 'blx r2'), (14182020, 'blx ip'), (14182036, 'blx r2'), (14182068, 'bl sym.imp.__wrap_calloc'), (14182116, 'bl sym.imp.__wrap_calloc'), (14182164, 'bl sym.imp.__wrap_calloc'), (14182276, 'bl loc.imp.objc_msgSend'), (14182968, 'blx r2'), (14183000, 'blx r2'), (14183016, 'blx r2'), (14183036, 'blx r3'), (14183056, 'blx r3'), (14183088, 'blx r3'), (14183140, 'blx ip'), (14183172, 'blx r2'), (14183188, 'blx r2'), (14183208, 'blx r3'), (14183228, 'blx r3'), (14183260, 'blx r2'), (14183276, 'blx r2'), (14183296, 'blx r3'), (14183316, 'blx r3'), (14183372, 'blx r4'), (14183420, 'blx lr'), (14183472, 'blx r4'), (14183524, 'blx ip'), (14183532, 'bl 0xd86ddc'), (14183652, 'blx r4')],
        branches=[(14180360, 'bne', 14180376), (14180372, 'b', 14183684), (14180700, 'bge', 14180792), (14180788, 'b', 14180692), (14181112, 'bge', 14181204), (14181200, 'b', 14181104), (14182212, 'bge', 14182540), (14182536, 'b', 14182204)],
        semantics=('[ParticleEmitter init] (imp 0x00d85f98, 913w): the **particle pool allocator** - super ctor via ffffbca8 (@0xd85fec) + nil gate; then **__wrap_calloc(16384, 4)** (`movw r1, 0x4000; movw r2, 4` @0xd860fc-0xd86104: the 64 KB effect array) + a second **__wrap_calloc** (@0xd86128) for the parallel array; the pool cap **0x800 (2048)** (`movw r0, 0x800` @0xd86018, `cmp r0, 0x800; bge` @0xd86158) drives the init loop filling each slot with the zero state; the ivar-slot cells **ffffff08/ffffff0c/ffffff10/ffffff14** thread the members; 56 calls total.\n'),
    ),
    dict(
        name='pe_instance',
        method='ParticleEmitter -[instance]',
        types='@8@0:4',
        start=14180044,
        end=14180248,
        disasm='disasm_worldtileloader_pe_instance.txt',
        base_add=14180060,
        base_literal=14180240,
        boundary='ARM.exidx end 0x00d85f98 (listing bound); next ObjC IMP 0x00d85f98 ParticleEmitter -[init]',
        selectors={
                 0xd85f84: (15240396, 'init'),
                 0xd85f88: (15240392, 'alloc'),
        },
        imports={
                 0xd85f80: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={
                 0xd85f8c: (15251408, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(14180044, 'push {fp, lr}'), (14180068, 'ldr ip, [0x00d85f7c]'), (14180096, 'bne 0xd85f64'), (14180192, 'str r0, [r1]'), (14180244, 'andeq r0, r0, r0')],
        calls=[(14180168, 'blx r2'), (14180184, 'blx r2')],
        branches=[(14180096, 'bne', 14180196)],
        semantics=('[ParticleEmitter instance] (imp 0x00d85ecc, 51w): the **singleton** - the global cell 0x67a4 (`ldr ip, [0xd85f7c:4]=0x67a4` @0xd85ee4) checked against nil (`cmp r0, 0; bne` @0xd85f00: return the existing); if nil it allocs via the ffe291d4/bcdc chain and stores the singleton (@0xd85f60).\n'),
    ),
    dict(
        name='pe_reset',
        method='ParticleEmitter -[reset]',
        types='v8@0:4',
        start=14183984,
        end=14184500,
        disasm='disasm_worldtileloader_pe_reset.txt',
        base_add=14184000,
        base_literal=14184496,
        boundary='ARM.exidx end 0x00d87034 (listing bound); next ObjC IMP 0x00d87034 ParticleEmitter -[addParticleAtPos:velocity:color:gravityType:life:scale:]',
        selectors={
                 0xd87014: (15240432, 'removeAllIndexes'),
                 0xd87020: (15240400, 'addIndex:'),
        },
        imports={
                 0xd87010: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd87018: (17168936, 'OBJC_IVAR_$_ParticleEmitter.bonusTakenIndices', 72),
                 0xd8701c: (17168900, 'OBJC_IVAR_$_ParticleEmitter.takenIndices', 20),
                 0xd87024: (17168940, 'OBJC_IVAR_$_ParticleEmitter.bonusFreeIndices', 68),
                 0xd87028: (17168920, 'OBJC_IVAR_$_ParticleEmitter.electrictyFreeIndices', 52),
                 0xd8702c: (17168904, 'OBJC_IVAR_$_ParticleEmitter.freeIndices', 16),
        },
        classes={},
        instructions=[(14183984, 'push {r4, r5, fp, lr}'), (14184088, 'blx ip'), (14184496, 'eoreq r8, sp, ip, lsr 25')],
        calls=[(14184088, 'blx ip'), (14184124, 'blx r3'), (14184220, 'blx r3'), (14184328, 'blx r3'), (14184436, 'blx r3')],
        branches=[(14184148, 'bge', 14184240), (14184236, 'b', 14184140), (14184256, 'bge', 14184348), (14184344, 'b', 14184248), (14184364, 'bge', 14184456), (14184452, 'b', 14184356)],
        semantics=('[ParticleEmitter reset] (imp 0x00d86e30, 129w): clears the pool - the ffffbca8 super call + the ivar cells ffffff08/ffffff0c/ffffff10/ffffff14 (5 ivars); 5 calls.\n'),
    ),
    dict(
        name='pe_setworld',
        method='ParticleEmitter -[setWorld:]',
        types='v12@0:4@8',
        start=14183916,
        end=14183984,
        disasm='disasm_worldtileloader_pe_setworld.txt',
        base_add=14183924,
        base_literal=14183980,
        boundary='ARM.exidx end 0x00d86e30 (listing bound); next ObjC IMP 0x00d86e30 ParticleEmitter -[reset]',
        selectors={},
        imports={},
        ivars={
                 0xd86e28: (17168960, 'OBJC_IVAR_$_ParticleEmitter.world', 4),
        },
        classes={},
        instructions=[(14183916, 'sub sp, sp, 0xc'), (14183964, 'str r0, [r1]'), (14183980, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[ParticleEmitter setWorld:] (imp 0x00d86dec, 17w): plain ivar store through the **ffffff4c** cell (`str r0, [r1]` @0xd86e1c).\n'),
    ),
    dict(
        name='pe_setworldwidth',
        method='ParticleEmitter -[setWorldWidthMacro:]',
        types='v12@0:4i8',
        start=14208248,
        end=14208316,
        disasm='disasm_worldtileloader_pe_setworldwidth.txt',
        base_add=14208276,
        base_literal=14208312,
        boundary='ARM.exidx end 0x00d8cd3c (listing bound); next ObjC IMP 0x00d8d4b8 SnowSurfaceBlock -[initSubDerivedItems]',
        selectors={},
        imports={},
        ivars={
                 0xd8cd34: (17168968, 'OBJC_IVAR_$_ParticleEmitter.worldWidthMacro', 100),
        },
        classes={},
        instructions=[(14208248, 'sub sp, sp, 0xc'), (14208296, 'dmb ish'), (14208312, 'invalid')],
        calls=[],
        branches=[],
        semantics=('[ParticleEmitter setWorldWidthMacro:] (imp 0x00d8ccf8, 17w): **dmb ish-fenced** store through the **ffffff54** cell (`dmb ish; str r2, [r0, r1]; dmb ish` @0xd8cd20-0xd8cd28).\n'),
    ),
    dict(
        name='pe_worldwidth',
        method='ParticleEmitter -[worldWidthMacro]',
        types='i8@0:4',
        start=14208188,
        end=14208248,
        disasm='disasm_worldtileloader_pe_worldwidth.txt',
        base_add=14208212,
        base_literal=14208244,
        boundary='ARM.exidx end 0x00d8ccf8 (listing bound); next ObjC IMP 0x00d8ccf8 ParticleEmitter -[setWorldWidthMacro:]',
        selectors={},
        imports={},
        ivars={
                 0xd8ccf0: (17168968, 'OBJC_IVAR_$_ParticleEmitter.worldWidthMacro', 100),
        },
        classes={},
        instructions=[(14208188, 'sub sp, sp, 8'), (14208228, 'dmb ish'), (14208244, 'eoreq r2, sp, r8, lsl lr')],
        calls=[],
        branches=[],
        semantics=('[ParticleEmitter worldWidthMacro] (imp 0x00d8ccbc, 15w): the **dmb ish-fenced read** through the ffffff54 cell (@0xd8cce4).\n'),
    ),
    dict(
        name='pe_setstopall',
        method='ParticleEmitter -[setStopAllParticles:]',
        types='v12@0:4c8',
        start=14208120,
        end=14208188,
        disasm='disasm_worldtileloader_pe_setstopall.txt',
        base_add=14208148,
        base_literal=14208184,
        boundary='ARM.exidx end 0x00d8ccbc (listing bound); next ObjC IMP 0x00d8ccbc ParticleEmitter -[worldWidthMacro]',
        selectors={},
        imports={},
        ivars={
                 0xd8ccb4: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96),
        },
        classes={},
        instructions=[(14208120, 'sub sp, sp, 0xc'), (14208168, 'dmb ish'), (14208184, 'eoreq r2, sp, r8, asr lr')],
        calls=[],
        branches=[],
        semantics=('[ParticleEmitter setStopAllParticles:] (imp 0x00d8cc78, 17w): the **dmb ish-fenced byte store** through the **ffffff50** cell (`dmb ish; strb; dmb ish` @0xd8cca0-0xd8cca8) - the stop flag is SMP-safe.\n'),
    ),
    dict(
        name='pe_stopall',
        method='ParticleEmitter -[stopAllParticles]',
        types='c8@0:4',
        start=14208060,
        end=14208120,
        disasm='disasm_worldtileloader_pe_stopall.txt',
        base_add=14208068,
        base_literal=14208116,
        boundary='ARM.exidx end 0x00d8cc78 (listing bound); next ObjC IMP 0x00d8cc78 ParticleEmitter -[setStopAllParticles:]',
        selectors={},
        imports={},
        ivars={
                 0xd8cc70: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96),
        },
        classes={},
        instructions=[(14208060, 'sub sp, sp, 8'), (14208092, 'ldr r1, [r2]'), (14208116, 'eoreq r2, sp, r8, lsr 29')],
        calls=[],
        branches=[],
        semantics=('[ParticleEmitter stopAllParticles] (imp 0x00d8cc3c, 15w): `ldrsb` of the ffffff50 flag byte.\n'),
    ),
    dict(
        name='pe_addparticle',
        method='ParticleEmitter -[addParticleAtPos:velocity:color:gravityType:life:scale:]',
        types='v68@0:4{Vector=[4f]}8{Vector=[4f]}24{Vector=[4f]}40i56f60f64',
        start=14184500,
        end=14185064,
        disasm='disasm_worldtileloader_pe_addparticle.txt',
        base_add=14184816,
        base_literal=14185060,
        boundary='ARM.exidx end 0x00d87268 (listing bound); next ObjC IMP 0x00d87268 ParticleEmitter -[addParticleAtPos:velocity:color:gravityType:life:scale:center:]',
        selectors={
                 0xd87260: (15240436, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(14184500, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14184940, 'str r0, [r1, 0x38]'), (14185044, 'bl loc.imp.objc_msgSend'), (14185060, 'eoreq r8, sp, ip, ror sb')],
        calls=[(14185044, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[ParticleEmitter addParticleAtPos:velocity:color:gravityType:life:scale:] (imp 0x00d87034, 141w): marshals the args into the **particle record** (the field stores @0xd871ec-0xd87244: +0/+4 pos, +8/+0xc velocity, +0x10 color, +0x14 gravity/scale, +0x18, +0x1c/+0x20/+0x24, +0x28, +0x34/+0x38/+0x3c, +0x40) then calls the adder via the **ffe29200** chain (`bl loc.imp.objc_msgSend` @0xd87254).\n'),
    ),
    dict(
        name='pe_addparticle_center',
        method='ParticleEmitter -[addParticleAtPos:velocity:color:gravityType:life:scale:center:]',
        types='v84@0:4{Vector=[4f]}8{Vector=[4f]}24{Vector=[4f]}40i56f60f64{Vector=[4f]}68',
        start=14185064,
        end=14185788,
        disasm='disasm_worldtileloader_pe_addparticle_center.txt',
        base_add=14185476,
        base_literal=14185784,
        boundary='ARM.exidx end 0x00d8753c (listing bound); next ObjC IMP 0x00d8753c ParticleEmitter -[addElectricityParticleWithPath:size:]',
        selectors={
                 0xd87534: (15240440, 'addParticleAtPos:velocity:color:gravityType:life:scale:center:connectionGoal:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(14185064, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14185632, 'str r0, [r1, 0x48]'), (14185768, 'bl loc.imp.objc_msgSend'), (14185784, 'eoreq r8, sp, r8, ror 13')],
        calls=[(14185768, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[ParticleEmitter addParticleAtPos:velocity:color:gravityType:life:scale:center:] (imp 0x00d87268, 181w): the center variant marshals the same record **plus the center fields** (+0x44/+0x48/+0x4c/+0x50 stores @0xd874a0-0xd87504) and forwards via the **ffe29204** chain.\n'),
    ),
    dict(
        name='pe_addparticle_goal',
        method='ParticleEmitter -[addParticleAtPos:velocity:color:gravityType:life:scale:center:connectionGoal:]',
        types='v100@0:4{Vector=[4f]}8{Vector=[4f]}24{Vector=[4f]}40i56f60f64{Vector=[4f]}68{Vector=[4f]}84',
        start=14187404,
        end=14189188,
        disasm='disasm_worldtileloader_pe_addparticle_goal.txt',
        base_add=14187420,
        base_literal=14189184,
        boundary='ARM.exidx end 0x00d88284 (listing bound); next ObjC IMP 0x00d88284 ParticleEmitter -[addBonusParticleAtPos:color:bonusMultiplier:]',
        selectors={
                 0xd88260: (15240452, 'firstIndex'),
                 0xd8826c: (15240460, 'macroTiles'),
                 0xd88274: (15240400, 'addIndex:'),
                 0xd8827c: (15240456, 'removeIndex:'),
        },
        imports={
                 0xd8825c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd88244: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96),
                 0xd88248: (17168972, 'OBJC_IVAR_$_ParticleEmitter.cameraMinXWorld', 32),
                 0xd8824c: (17168976, 'OBJC_IVAR_$_ParticleEmitter.cameraMaxXWorld', 36),
                 0xd88250: (17168980, 'OBJC_IVAR_$_ParticleEmitter.cameraMinYWorld', 40),
                 0xd88254: (17168984, 'OBJC_IVAR_$_ParticleEmitter.cameraMaxYWorld', 44),
                 0xd88264: (17168904, 'OBJC_IVAR_$_ParticleEmitter.freeIndices', 16),
                 0xd88268: (17168960, 'OBJC_IVAR_$_ParticleEmitter.world', 4),
                 0xd88270: (17168896, 'OBJC_IVAR_$_ParticleEmitter.particles', 8),
                 0xd88278: (17168900, 'OBJC_IVAR_$_ParticleEmitter.takenIndices', 20),
        },
        classes={},
        instructions=[(14187404, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14187744, 'cmp r0, 0'), (14187812, 'bmi 0xd87ddc'), (14187992, 'ble 0xd87de0'), (14188000, 'ldr r0, [0x00d88258]'), (14188100, 'movw r1, 0x68'), (14189184, 'eoreq r7, sp, r0, asr pc')],
        calls=[(14187760, 'bl method.Vector.operator_float__'), (14187820, 'bl method.Vector.operator_float__'), (14187880, 'bl method.Vector.operator_float__'), (14187940, 'bl method.Vector.operator_float__'), (14188072, 'blx r3'), (14188216, 'blx ip'), (14188256, 'blx ip'), (14188372, 'bl method.Vector.operator_float__'), (14188400, 'bl method.Vector.operator_float__'), (14188424, 'bl sym.makeIntpair_int__int_'), (14188976, 'blx r2'), (14189020, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_')],
        branches=[(14187752, 'bne', 14187996), (14187812, 'bmi', 14187996), (14187872, 'bgt', 14187996), (14187932, 'bmi', 14187996), (14187992, 'ble', 14188000), (14187996, 'b', 14189116), (14188092, 'beq', 14189116), (14189040, 'beq', 14189112), (14189056, 'beq', 14189112), (14189112, 'b', 14189116)],
        semantics=('[ParticleEmitter addParticleAtPos:velocity:color:gravityType:life:scale:center:connectionGoal:] (imp 0x00d87b8c, 446w): the full adder - the **ffffff50 stop gate** (`ldrsb; cmp 0; bne` @0xd87ce0: stopped emitter rejects particles); the **world-width bounds gate**: the spawn position must lie inside the 4-tuple box read through the **ffffff58/ffffff5c/ffffff60/ffffff64** cells with the float compares (`vcvt.f32.s32; vcmpe; bmi/bgt/bmi/ble` @0xd87d24-0xd87dd8: x >= -W, x <= W, y >= .., y <= ..); then the **0x7fffffff sentinel lookup** (@0xd87de0 - the INT_MAX free-slot marker) with `cmp r0, r1; beq` reject; the slot payload is dispatched with `movw r1, 0x68` (104) via the ffe291dc/ffffff0c/ffffff14 chain.\n'),
    ),
    dict(
        name='pe_addbonus',
        method='ParticleEmitter -[addBonusParticleAtPos:color:bonusMultiplier:]',
        types='v44@0:4{Vector=[4f]}8{Vector=[4f]}24i40',
        start=14189188,
        end=14190192,
        disasm='disasm_worldtileloader_pe_addbonus.txt',
        base_add=14189204,
        base_literal=14190188,
        boundary='ARM.exidx end 0x00d88670 (listing bound); next ObjC IMP 0x00d88670 ParticleEmitter -[renderAndUpdate:pinchScale:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:windMovement:]',
        selectors={
                 0xd8864c: (15240452, 'firstIndex'),
                 0xd88660: (15240400, 'addIndex:'),
                 0xd88668: (15240456, 'removeIndex:'),
        },
        imports={
                 0xd88648: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd88630: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96),
                 0xd88634: (17168972, 'OBJC_IVAR_$_ParticleEmitter.cameraMinXWorld', 32),
                 0xd88638: (17168976, 'OBJC_IVAR_$_ParticleEmitter.cameraMaxXWorld', 36),
                 0xd8863c: (17168980, 'OBJC_IVAR_$_ParticleEmitter.cameraMinYWorld', 40),
                 0xd88640: (17168984, 'OBJC_IVAR_$_ParticleEmitter.cameraMaxYWorld', 44),
                 0xd88650: (17168940, 'OBJC_IVAR_$_ParticleEmitter.bonusFreeIndices', 68),
                 0xd88658: (17168988, 'OBJC_IVAR_$_ParticleEmitter.bonusDelay', 92),
                 0xd8865c: (17168932, 'OBJC_IVAR_$_ParticleEmitter.bonusParticles', 64),
                 0xd88664: (17168936, 'OBJC_IVAR_$_ParticleEmitter.bonusTakenIndices', 72),
        },
        classes={},
        instructions=[(14189188, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14189320, 'bne 0xd883fc'), (14189560, 'ble 0xd88400'), (14189568, 'ldr r0, [0x00d88644]'), (14190188, 'eoreq r7, sp, r8, asr r8')],
        calls=[(14189328, 'bl method.Vector.operator_float__'), (14189388, 'bl method.Vector.operator_float__'), (14189448, 'bl method.Vector.operator_float__'), (14189508, 'bl method.Vector.operator_float__'), (14189640, 'blx r3'), (14189808, 'blx lr'), (14189848, 'blx ip')],
        branches=[(14189320, 'bne', 14189564), (14189380, 'bmi', 14189564), (14189440, 'bgt', 14189564), (14189500, 'bmi', 14189564), (14189560, 'ble', 14189568), (14189564, 'b', 14190120), (14189660, 'beq', 14190120)],
        semantics=('[ParticleEmitter addBonusParticleAtPos:color:bonusMultiplier:] (imp 0x00d88284, 251w): same contract as the goal adder - the ffffff50 stop gate (@0xd88308), the **world-width 4-tuple gate** (ffffff58/5c/60/64 @0xd8833c-0xd883f8), the **0x7fffffff sentinel** (@0xd88400), then its own slot chain via ffffff38.\n'),
    ),
    dict(
        name='pe_addelectricity',
        method='ParticleEmitter -[addElectricityParticleWithPath:size:]',
        types='v24@0:4{vector<ElectrictyParticlePathIndex, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}^{ElectrictyParticlePathIndex}{__compressed_pair<ElectrictyParticlePathIndex *, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}}}8f20',
        start=14185788,
        end=14186160,
        disasm='disasm_worldtileloader_pe_addelectricity.txt',
        base_add=14185804,
        base_literal=14186156,
        boundary='ARM.exidx end 0x00d876b0 (listing bound); next ObjC IMP 0x00d876b0 ParticleEmitter -[doAddElectricityParticleWithPath:size:]',
        selectors={
                 0xd8769c: (15240444, 'sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:'),
                 0xd876a4: (15240448, 'doAddElectricityParticleWithPath:size:'),
        },
        imports={},
        ivars={
                 0xd87694: (17168960, 'OBJC_IVAR_$_ParticleEmitter.world', 4),
                 0xd876a0: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96),
        },
        classes={},
        instructions=[(14185788, 'push {fp, lr}'), (14185884, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (14185924, 'bl loc.imp.objc_msgSend'), (14186128, 'bl sym.imp._Unwind_Resume'), (14186156, 'eoreq r8, sp, r0, lsr 11')],
        calls=[(14185884, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (14185924, 'bl loc.imp.objc_msgSend'), (14185936, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186000, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186040, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (14186072, 'bl loc.imp.objc_msgSend'), (14186084, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186116, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186128, 'bl sym.imp._Unwind_Resume')],
        branches=[(14185928, 'b', 14185932), (14185976, 'beq', 14186012), (14185980, 'b', 14186092), (14186008, 'b', 14186124), (14186076, 'b', 14186080)],
        semantics=('[ParticleEmitter addElectricityParticleWithPath:size:] (imp 0x00d8753c, 93w): **the electricity arc entry** - copies a **`std::__1::vector<ElectrictyParticlePathIndex>`** (the mangled symbol pins the game\'s own spelling "Electricty") via the vector copy-ctor (@0xd8759c), forwards via objc_msgSend (@0xd875c4), destroys the temp vector (@0xd875d0); the exception path runs `_Unwind_Resume` (@0xd87690) and the second copy (@0xd87638) forwards to the doAdd bridge.\n'),
    ),
    dict(
        name='pe_doelectricity',
        method='ParticleEmitter -[doAddElectricityParticleWithPath:size:]',
        types='v24@0:4{vector<ElectrictyParticlePathIndex, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}^{ElectrictyParticlePathIndex}{__compressed_pair<ElectrictyParticlePathIndex *, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}}}8f20',
        start=14186160,
        end=14187268,
        disasm='disasm_worldtileloader_pe_doelectricity.txt',
        base_add=14186176,
        base_literal=14187264,
        boundary='ARM.exidx end 0x00d87b04 (listing bound); next ObjC IMP 0x00d87b8c ParticleEmitter -[addParticleAtPos:velocity:color:gravityType:life:scale:center:connectionGoal:]',
        selectors={
                 0xd87ad8: (15240452, 'firstIndex'),
                 0xd87ae4: (15240400, 'addIndex:'),
                 0xd87aec: (15240456, 'removeIndex:'),
        },
        imports={
                 0xd87ad4: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd87ac8: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96),
                 0xd87adc: (17168920, 'OBJC_IVAR_$_ParticleEmitter.electrictyFreeIndices', 52),
                 0xd87ae0: (17168912, 'OBJC_IVAR_$_ParticleEmitter.electrictyParticles', 48),
                 0xd87ae8: (17168916, 'OBJC_IVAR_$_ParticleEmitter.electrictyTakenIndices', 56),
                 0xd87af4: (17168968, 'OBJC_IVAR_$_ParticleEmitter.worldWidthMacro', 100),
        },
        classes={},
        instructions=[(14186160, 'push {r4, r5, r6, r7, fp, lr}'), (14186224, 'str ip, [sp, 0x5c]'), (14186300, 'ble 0xd87ab4'), (14186400, 'movw r0, 0x28'), (14186676, 'bl method.std::__1::enable_if___is_forward_iterator_ElectrictyParticlePathIndex_::value__void_::type_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.assign_ElectrictyParticlePathIndex__ElectrictyParticlePathIndex__ElectrictyParticlePathIndex_'), (14186716, 'add r1, r1, r1, lsl 2'), (14187264, 'eoreq r8, sp, ip, lsr 8')],
        calls=[(14186376, 'blx r3'), (14186508, 'blx r3'), (14186548, 'blx ip'), (14186676, 'bl method.std::__1::enable_if___is_forward_iterator_ElectrictyParticlePathIndex_::value__void_::type_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.assign_ElectrictyParticlePathIndex__ElectrictyParticlePathIndex__ElectrictyParticlePathIndex_'), (14186780, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.at_unsigned_long_'), (14186844, 'bl sym.imp.__modsi3'), (14186864, 'bl sym.imp.__aeabi_idiv'), (14186888, 'bl sym.makeIntpair_int__int_'), (14186996, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(14186232, 'beq', 14186240), (14186236, 'b', 14187188), (14186300, 'ble', 14187188), (14186396, 'beq', 14187180), (14186620, 'beq', 14186680), (14187176, 'b', 14187184), (14187180, 'b', 14187188), (14187184, 'b', 14186288)],
        semantics=('[ParticleEmitter doAddElectricityParticleWithPath:size:] (imp 0x00d876b0, 277w): **the electric-arc path builder**: the **ffffff50 stop gate** (@0xd876f0); the **size / 50 normalization** (`movw r1, 0x32` = 50 segments, `vcvt.f64.f32; vdiv.f64; vcvt.f32.f64` @0xd87714-0xd8771c) and the `vcmpe.f32 s0, 0; ble` guard (@0xd8773c); the **0x7fffffff sentinel** (@0xd87740); the path elements are **40-byte** `ElectrictyParticlePathIndex` records (`movw r0, 0x28` @0xd877a0; the index math `i*5*8 = i*40` @0xd878dc-0xd87900) with the **+0x1c** field; the path is written with **`vector<ElectrictyParticlePathIndex>::assign<E*>(first, last)`** (@0xd878b4) - the arc between the two endpoints interpolated into the path vector.\n'),
    ),
    dict(
        name='pe_render',
        method='ParticleEmitter -[renderAndUpdate:pinchScale:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:windMovement:]',
        types='v164@0:4f8f12(_GLKMatrix4={?=ffffffffffffffff}[16f])16(_GLKMatrix4={?=ffffffffffffffff}[16f])80i144i148i152i156f160',
        start=14190192,
        end=14206588,
        disasm='disasm_worldtileloader_pe_render.txt',
        base_add=14190216,
        base_literal=14194128,
        boundary='ARM.exidx end 0x00d8c67c (listing bound); next ObjC IMP 0x00d8cc3c ParticleEmitter -[stopAllParticles]',
        selectors={
                 0xd8998c: (15240464, 'lastIndex'),
                 0xd89aa0: (15240468, 'containsIndex:'),
                 0xd89aa4: (15240400, 'addIndex:'),
                 0xd89aac: (15240456, 'removeIndex:'),
                 0xd89ba4: (15240400, 'addIndex:'),
                 0xd89ba8: (15240456, 'removeIndex:'),
                 0xd8a1fc: (15240472, 'getX:Y:Z:octaves:'),
                 0xd8a36c: (15240472, 'getX:Y:Z:octaves:'),
                 0xd8aec4: (15240460, 'macroTiles'),
                 0xd8b5e0: (15240476, 'program'),
                 0xd8b5e8: (15240488, 'intValue'),
                 0xd8b5ec: (15240484, 'objectAtIndex:'),
                 0xd8b5f0: (15240480, 'uniformLocations'),
                 0xd8c004: (15240464, 'lastIndex'),
                 0xd8c010: (15240468, 'containsIndex:'),
                 0xd8c014: (15240400, 'addIndex:'),
                 0xd8c01c: (15240456, 'removeIndex:'),
                 0xd8c648: (15240488, 'intValue'),
                 0xd8c64c: (15240484, 'objectAtIndex:'),
                 0xd8c650: (15240480, 'uniformLocations'),
                 0xd8c654: (15240476, 'program'),
                 0xd8c660: (15240492, 'name'),
        },
        imports={
                 0xd89988: (17151904, 'objc_msgSend'),
                 0xd8b864: (17151904, 'objc_msgSend'),
                 0xd8c644: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0xd89854: (17168988, 'OBJC_IVAR_$_ParticleEmitter.bonusDelay', 92),
                 0xd89990: (17168900, 'OBJC_IVAR_$_ParticleEmitter.takenIndices', 20),
                 0xd89994: (17168992, 'OBJC_IVAR_$_ParticleEmitter.timer', 104),
                 0xd89998: (17168984, 'OBJC_IVAR_$_ParticleEmitter.cameraMaxYWorld', 44),
                 0xd8999c: (17168980, 'OBJC_IVAR_$_ParticleEmitter.cameraMinYWorld', 40),
                 0xd899a0: (17168976, 'OBJC_IVAR_$_ParticleEmitter.cameraMaxXWorld', 36),
                 0xd899a4: (17168972, 'OBJC_IVAR_$_ParticleEmitter.cameraMinXWorld', 32),
                 0xd89a9c: (17168896, 'OBJC_IVAR_$_ParticleEmitter.particles', 8),
                 0xd89aa8: (17168904, 'OBJC_IVAR_$_ParticleEmitter.freeIndices', 16),
                 0xd8a1f4: (17168948, 'OBJC_IVAR_$_ParticleEmitter.noiseFunction', 12),
                 0xd8aec0: (17168960, 'OBJC_IVAR_$_ParticleEmitter.world', 4),
                 0xd8aec8: (17168892, 'OBJC_IVAR_$_ParticleEmitter.glData', 24),
                 0xd8b5e4: (17168944, 'OBJC_IVAR_$_ParticleEmitter.shader', 28),
                 0xd8b5f4: (17168916, 'OBJC_IVAR_$_ParticleEmitter.electrictyTakenIndices', 56),
                 0xd8b860: (17168912, 'OBJC_IVAR_$_ParticleEmitter.electrictyParticles', 48),
                 0xd8b868: (17168920, 'OBJC_IVAR_$_ParticleEmitter.electrictyFreeIndices', 52),
                 0xd8b86c: (17168968, 'OBJC_IVAR_$_ParticleEmitter.worldWidthMacro', 100),
                 0xd8baf8: (17168908, 'OBJC_IVAR_$_ParticleEmitter.electrictyGlData', 60),
                 0xd8c008: (17168936, 'OBJC_IVAR_$_ParticleEmitter.bonusTakenIndices', 72),
                 0xd8c00c: (17168932, 'OBJC_IVAR_$_ParticleEmitter.bonusParticles', 64),
                 0xd8c018: (17168940, 'OBJC_IVAR_$_ParticleEmitter.bonusFreeIndices', 68),
                 0xd8c658: (17168924, 'OBJC_IVAR_$_ParticleEmitter.bonusGlIndices', 80),
                 0xd8c65c: (17168928, 'OBJC_IVAR_$_ParticleEmitter.bonusGlData', 76),
                 0xd8c664: (17168956, 'OBJC_IVAR_$_ParticleEmitter.bonusTexture', 88),
                 0xd8c668: (17168952, 'OBJC_IVAR_$_ParticleEmitter.bonusShader', 84),
        },
        classes={},
        instructions=[(14190192, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (14198328, 'bl 0xd8c67c'), (14201256, 'bl 0xd8c67c'), (14205668, 'bl 0xd8c67c'), (14206584, 'eoreq r3, sp, r4, lsr sp')],
        calls=[(14191232, 'blx r3'), (14191440, 'blx r3'), (14191548, 'blx ip'), (14191588, 'blx ip'), (14191752, 'bl method.Vector.operator_float__'), (14191808, 'bl method.Vector.operator_float__'), (14191832, 'bl method.Vector.operator_float__'), (14191852, 'bl method.Vector2.Vector2_float__float_'), (14191864, 'bl method.Vector.operator_float__'), (14191888, 'bl method.Vector.operator_float__'), (14191904, 'bl method.Vector2.Vector2_float__float_'), (14191932, 'bl method.Vector2.operator__Vector2_'), (14191948, 'bl method.Vector2.normal__'), (14191960, 'bl method.Vector.operator_float__'), (14191984, 'bl method.Vector.operator_float__'), (14192028, 'bl method.Vector2.operator__float_'), (14192036, 'bl method.Vector2.operator_float__'), (14192112, 'bl method.Vector.operator_float__'), (14192144, 'bl method.Vector2.operator_float__'), (14192220, 'bl method.Vector.operator_float__'), (14192296, 'bl method.Vector.operator_float__'), (14192588, 'bl sym.closestPointOnLineToPoint_Vector__Vector__Vector_'), (14192612, 'bl method.Vector.operator_float_'), (14192636, 'bl method.Vector.operator_float_'), (14192676, 'bl method.Vector.operator_Vector_'), (14192784, 'bl method.Vector.operator__Vector_'), (14192864, 'bl method.Vector.operator_float_'), (14192908, 'bl method.Vector.operator_float__'), (14192960, 'bl method.Vector.operator_float__'), (14192992, 'bl method.Vector.operator_float__'), (14193044, 'bl method.Vector.operator_float__'), (14193076, 'bl method.Vector.operator_float__'), (14193128, 'bl method.Vector.operator_float__'), (14193344, 'bl method.Vector.operator_float__'), (14193416, 'bl method.Vector.operator_float__'), (14193452, 'bl method.Vector.operator_float__'), (14193624, 'blx lr'), (14193692, 'bl method.Vector.operator_float__'), (14193752, 'bl method.Vector.operator_float__'), (14193796, 'bl method.Vector.operator_float__'), (14193972, 'blx r4'), (14194016, 'bl method.Vector.operator_float__'), (14194108, 'bl method.Vector.operator_float__'), (14194172, 'bl method.Vector.operator_float__'), (14194272, 'bl method.Vector.operator_float__'), (14194628, 'bl method.Vector.operator_float__'), (14194652, 'bl method.Vector.operator_float__'), (14194676, 'bl method.Vector.operator_float__'), (14194724, 'bl method.Vector.Vector_float__float__float_'), (14194992, 'bl method.Vector.Vector_float__float__float__float_'), (14195032, 'bl method.Vector.operator_Vector_'), (14195268, 'bl method.Vector.Vector_float__float__float__float_'), (14195312, 'bl method.Vector.operator__Vector_'), (14195456, 'bl method.Vector.operator_float__'), (14195476, 'bl method.Vector.operator_float__'), (14195496, 'bl method.Vector.operator_float__'), (14195560, 'bl method.Vector.Vector_float__float__float__float_'), (14195688, 'bl method.Vector.operator_float__'), (14195756, 'bl method.Vector.operator_float__'), (14195788, 'bl method.Vector.operator_float__'), (14195936, 'blx r4'), (14195976, 'bl method.Vector.operator_float__'), (14195996, 'bl method.Vector.operator_float__'), (14196064, 'bl method.Vector.operator_float__'), (14196104, 'bl method.Vector.operator_float__'), (14196272, 'blx r5'), (14196320, 'bl method.Vector.operator_float__'), (14196428, 'bl method.Vector.operator_float__'), (14196480, 'bl method.Vector.operator_float__'), (14196540, 'bl method.Vector.operator_float_'), (14196584, 'bl method.Vector.operator_Vector_'), (14196632, 'bl method.Vector.operator_float__'), (14196660, 'bl method.Vector.operator_float__'), (14196684, 'bl sym.makeIntpair_int__int_'), (14196824, 'blx r2'), (14196868, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (14196896, 'bl sym.tileIsAir_Tile_'), (14197020, 'bl method.Vector.operator_float__'), (14197080, 'bl method.Vector.operator_float__'), (14197132, 'bl method.Vector.operator_float__'), (14197380, 'bl method.Vector.operator_float__'), (14197432, 'bl method.Vector.operator_float__'), (14197484, 'bl method.Vector.operator_float__'), (14197536, 'bl method.Vector.operator_float__'), (14198328, 'bl 0xd8c67c'), (14198340, 'bl sym.pushDepthMaskState'), (14198404, 'blx r2'), (14198408, 'bl sym.imp.__wrap_glUseProgram'), (14198540, 'blx r3'), (14198560, 'blx r3'), (14198576, 'blx r2'), (14198608, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (14198672, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14198740, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14198760, 'bl sym.imp.__wrap_glDrawArrays'), (14198764, 'bl sym.popDepthMaskState'), (14198856, 'blx r3'), (14198972, 'blx r3'), (14199264, 'bl sym.imp.__aeabi_idiv'), (14199384, 'blx ip'), (14199424, 'blx ip'), (14199472, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.at_unsigned_long_'), (14199544, 'bl sym.imp.__modsi3'), (14199564, 'bl sym.imp.__aeabi_idiv'), (14199588, 'bl sym.makeIntpair_int__int_'), (14199620, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.at_unsigned_long_'), (14199676, 'bl sym.imp.__modsi3'), (14199696, 'bl sym.imp.__aeabi_idiv'), (14199724, 'bl sym.makeIntpair_int__int_'), (14199804, 'bl method.Vector.Vector_float__float__float_'), (14199860, 'bl method.Vector.Vector_float__float__float_'), (14199940, 'bl sym.linearInterpolatev_Vector__Vector__float_'), (14200036, 'bl method.Vector.operator_float__'), (14200084, 'bl method.Vector.operator_float__'), (14200120, 'bl method.Vector.operator_float__'), (14200180, 'bl method.Vector.operator_float__'), (14200228, 'bl method.Vector.operator_float__'), (14201256, 'bl 0xd8c67c'), (14201268, 'bl sym.pushDepthMaskState'), (14201332, 'blx r2'), (14201336, 'bl sym.imp.__wrap_glUseProgram'), (14201468, 'blx r3'), (14201488, 'blx r3'), (14201504, 'blx r2'), (14201536, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (14201600, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14201668, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14201688, 'bl sym.imp.__wrap_glDrawArrays'), (14201692, 'bl sym.popDepthMaskState'), (14201784, 'blx r3'), (14202004, 'blx r3'), (14202112, 'blx ip'), (14202152, 'blx ip'), (14202200, 'bl method.Vector.operator_float__'), (14202256, 'bl method.Vector.operator_float__'), (14202436, 'bl method.Vector.operator_float__'), (14202512, 'bl method.Vector.operator_float__'), (14202572, 'bl method.Vector.operator_float__'), (14202700, 'bl method.Vector.operator_float__'), (14202764, 'bl method.Vector.operator_float__'), (14202828, 'bl method.Vector.operator_float__'), (14202896, 'bl method.Vector.operator_float__'), (14203096, 'bl method.Vector.operator_float__'), (14203156, 'bl method.Vector.operator_float__'), (14203224, 'bl method.Vector.operator_float__'), (14203356, 'bl method.Vector.operator_float__'), (14203424, 'bl method.Vector.operator_float__'), (14203492, 'bl method.Vector.operator_float__'), (14203560, 'bl method.Vector.operator_float__'), (14203752, 'bl method.Vector.operator_float__'), (14203812, 'bl method.Vector.operator_float__'), (14203872, 'bl method.Vector.operator_float__'), (14204008, 'bl method.Vector.operator_float__'), (14204072, 'bl method.Vector.operator_float__'), (14204136, 'bl method.Vector.operator_float__'), (14204204, 'bl method.Vector.operator_float__'), (14204384, 'bl method.Vector.operator_float__'), (14204444, 'bl method.Vector.operator_float__'), (14204504, 'bl method.Vector.operator_float__'), (14204640, 'bl method.Vector.operator_float__'), (14204704, 'bl method.Vector.operator_float__'), (14204768, 'bl method.Vector.operator_float__'), (14204832, 'bl method.Vector.operator_float__'), (14205668, 'bl 0xd8c67c'), (14205680, 'bl sym.pushDepthMaskState'), (14205688, 'bl sym.imp.__wrap_glEnable'), (14205752, 'blx r2'), (14205756, 'bl sym.imp.__wrap_glUseProgram'), (14205888, 'blx r3'), (14205908, 'blx r3'), (14205924, 'blx r2'), (14205956, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (14206084, 'blx r6'), (14206104, 'blx r3'), (14206120, 'blx r2'), (14206128, 'bl sym.imp.__wrap_glUniform1i'), (14206204, 'blx r3'), (14206224, 'bl sym.imp.__wrap_glBindTexture'), (14206232, 'bl sym.imp.__wrap_glEnableVertexAttribArray'), (14206296, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14206364, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14206432, 'bl sym.imp.__wrap_glVertexAttribPointer'), (14206496, 'bl sym.imp.__wrap_glDrawElements'), (14206500, 'bl sym.popDepthMaskState'), (14206508, 'bl sym.imp.__wrap_glDisableVertexAttribArray'), (14206516, 'bl sym.imp.__wrap_glDisable')],
        branches=[(14190820, 'bpl', 14190848), (14190840, 'b', 14190864), (14190952, 'bpl', 14190996), (14191252, 'beq', 14198772), (14191276, 'bhi', 14197620), (14191368, 'bhi', 14191596), (14191452, 'beq', 14191592), (14191592, 'b', 14197592), (14191636, 'bne', 14191672), (14191652, 'beq', 14191672), (14191668, 'bne', 14191692), (14191704, 'bne', 14191784), (14191776, 'b', 14196360), (14191796, 'bne', 14192360), (14192328, 'b', 14196356), (14192372, 'bne', 14193156), (14193152, 'b', 14196352), (14193168, 'beq', 14193268), (14193184, 'beq', 14193268), (14193200, 'beq', 14193268), (14193216, 'beq', 14193268), (14193232, 'beq', 14193268), (14193248, 'beq', 14193268), (14193264, 'bne', 14195664), (14193296, 'beq', 14193316), (14193312, 'bne', 14193336), (14194004, 'bne', 14194164), (14194124, 'b', 14194288), (14194300, 'beq', 14194320), (14194316, 'bne', 14194800), (14194348, 'bpl', 14194396), (14194392, 'bge', 14194548), (14194424, 'bpl', 14194472), (14194468, 'bge', 14194548), (14194500, 'bpl', 14194768), (14194544, 'blt', 14194768), (14194768, 'b', 14195616), (14194812, 'beq', 14194832), (14194828, 'bne', 14195612), (14194876, 'bpl', 14195116), (14195072, 'b', 14195608), (14195148, 'bpl', 14195376), (14195352, 'b', 14195604), (14195604, 'b', 14195608), (14195608, 'b', 14195612), (14195612, 'b', 14195616), (14195616, 'b', 14196348), (14195676, 'bne', 14196344), (14196332, 'b', 14196344), (14196344, 'b', 14196348), (14196348, 'b', 14196352), (14196352, 'b', 14196356), (14196356, 'b', 14196360), (14196372, 'beq', 14196496), (14196388, 'beq', 14196496), (14196416, 'ble', 14196492), (14196492, 'b', 14196496), (14196704, 'bne', 14196728), (14196724, 'beq', 14196984), (14196888, 'beq', 14196932), (14196908, 'bne', 14196932), (14196944, 'beq', 14196980), (14196980, 'b', 14196984), (14197216, 'bpl', 14197248), (14197232, 'b', 14197260), (14197592, 'b', 14197596), (14197608, 'b', 14191264), (14197628, 'ble', 14198768), (14198768, 'b', 14198772), (14198876, 'beq', 14201700), (14198900, 'bhi', 14200548), (14198984, 'beq', 14200492), (14199052, 'ble', 14199084), (14199080, 'b', 14200488), (14199160, 'ble', 14199432), (14199280, 'blo', 14199428), (14199428, 'b', 14199432), (14199444, 'bne', 14200484), (14200000, 'ble', 14200052), (14200048, 'b', 14200096), (14200484, 'b', 14200488), (14200488, 'b', 14200492), (14200492, 'b', 14200496), (14200508, 'b', 14198888), (14200556, 'ble', 14201696), (14201696, 'b', 14201700), (14201804, 'beq', 14206524), (14201840, 'bhi', 14204960), (14201932, 'bhi', 14202160), (14202016, 'beq', 14202156), (14202156, 'b', 14204908), (14202188, 'ble', 14202196), (14202192, 'b', 14204904), (14202316, 'bpl', 14202364), (14202332, 'b', 14202376), (14202956, 'bpl', 14202996), (14202972, 'b', 14203008), (14203620, 'bpl', 14203648), (14203636, 'b', 14203660), (14204264, 'bpl', 14204284), (14204280, 'b', 14204296), (14204904, 'b', 14204908), (14204908, 'b', 14204912), (14204924, 'b', 14201828), (14204968, 'ble', 14206520), (14206520, 'b', 14206524)],
        semantics=('[ParticleEmitter renderAndUpdate:...] (imp 0x00d88670, 4099w): the particle simulation + render pass. **GL pipeline** (census of the 186 calls): `glUseProgram` x3, `glUniformMatrix4fv` x3, `glVertexAttribPointer` x7, **`glDrawArrays` x2 + `glDrawElements` x1** (the two particle passes + the arc pass), `glBindTexture`/`glEnable`/`glDisable`/attrib arrays, and **`pushDepthMaskState`/`popDepthMaskState` x3** (the depth-state management). **The electricity arc render**: `vector<ElectrictyParticlePathIndex>::at(unsigned long)` x2 (the path points read by index!) + **`closestPointOnLineToPoint(Vector, Vector, Vector)`** (the arc-vs-point hit test - the electrocution check) + `linearInterpolatev` (the interpolation) + `Vector2::normal()` (the ribbon normal). **World collision**: `tileAtWorldPosition(int, int, MacroTile*, World*)` + `tileIsAir(Tile*)` (particles die on solid tiles). Math: `makeIntpair` x3, `__aeabi_idiv` x3, `__modsi3` x2; constants **0.99f (0x3f7d70a4), 0.01f (0x3c23d70a), 0.7f (0x3f333333)** (the life/decay/drag factors); helpers 0xd8c67c (x3). The FLOAT work rides the Vector C++ ops (86 float* calls).\n'),
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
        'batch': 'ParticleEmitter class (E73): the electric arc visual system - the 2048-slot pool, the singleton, the record adders, the arc path builder and the GL render/update pass; 15 bodies',
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
                        default=NATIVE / 'particles.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale particles.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
