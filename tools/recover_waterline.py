#!/usr/bin/env python3
"""Hash-gated recovery of the Weather + water + temperature (E119).

The weather/water/temperature substrate opens: Weather (16 bodies), the
weather field chain, the water flow system and the temperature table:
43 bodies, 11897 instruction words, from the pinned original libApplication.so
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
reconstruction/reverse-v3/native/WATERLINE.md for the prose and boundaries.
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
    'bl 0x7e4b5c': 0x007e4b5c,
    'bl 0x7ea5fc': 0x007ea5fc,
    'bl 0x7ea7e4': 0x007ea7e4,
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl loc.imp.objc_msgSend_stret': 0x001c2918,
    'bl method.Vector.Vector__': 0x004bed60,
    'bl method.Vector.Vector_float__float__float_': 0x004b52ac,
    'bl method.Vector.Vector_float__float__float__float_': 0x004d0d08,
    'bl method.Vector.operator_Vector_': 0x004d6538,
    'bl method.Vector.operator_float__': 0x004b5c08,
    'bl method.Vector2.operator_float__': 0x004bdaac,
    'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_': 0x008bcf24,
    'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_': 0x0052d84c,
    'bl sym.Vector::operator_Vector_': 0x0058198c,
    'bl sym.clamp_float__float__float_': 0x004be068,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.imp.__modsi3': 0x001c3020,
    'bl sym.imp.__stack_chk_fail': 0x001c28b8,
    'bl sym.imp.__wrap_free': 0x001c2e64,
    'bl sym.imp.__wrap_glBindTexture': 0x001c2ad4,
    'bl sym.imp.__wrap_glDisable': 0x001c2c48,
    'bl sym.imp.__wrap_glDrawArrays': 0x001c2ccc,
    'bl sym.imp.__wrap_glEnable': 0x001c2b04,
    'bl sym.imp.__wrap_glLineWidth': 0x001c3f14,
    'bl sym.imp.__wrap_glTexParameteri': 0x001c2af8,
    'bl sym.imp.__wrap_glUniform1f': 0x001c3fb0,
    'bl sym.imp.__wrap_glUniform1i': 0x001c2de0,
    'bl sym.imp.__wrap_glUniform2f': 0x001c4178,
    'bl sym.imp.__wrap_glUniform4f': 0x001c3d64,
    'bl sym.imp.__wrap_glUniformMatrix4fv': 0x001c2dd4,
    'bl sym.imp.__wrap_glUseProgram': 0x001c2d38,
    'bl sym.imp.__wrap_glVertexAttribPointer': 0x001c2dec,
    'bl sym.imp.__wrap_malloc': 0x001c2e58,
    'bl sym.imp.memcpy': 0x001c2894,
    'bl sym.imp.memset': 0x001c2924,
    'bl sym.linearInterpolate_float__float__float_': 0x00582a14,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
    'bl sym.popDepthMaskState': 0x007c57ec,
    'bl sym.pushDepthMaskState': 0x007c55e4,
    'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_': 0x00a1915c,
    'bl sym.reloadDrawBlockWaterForTile_int__int__MacroTile__World_': 0x00a193a4,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00a12f24,
    'bl sym.tileIsAirOrSnow_Tile_': 0x00a12760,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00a126dc,
    'bl sym.tileIsAir_Tile_': 0x00a12300,
    'bl sym.tileIsSolid_Tile_': 0x00a1179c,
    'bl sym.tileIsWater_Tile_': 0x00a11690,
}

SPECS = [
    dict(
        name='aq_00',
        method='Weather -[initWithCache:world:worldTime:]',
        types='@20@0:4@8@12f16',
        start=8272424,
        end=8276828,
        disasm='disasm_worldtileloader_aq_00.txt',
        base_add=8272440,
        base_literal=8276376,
        boundary='ARM.exidx end 0x007e4b5c (listing bound); next ObjC IMP 0x007e4b6c Weather -[updateCloudsForLoadOrHDTeturesChange]',
        selectors={
                 0x7e4a44: (15210928, 'init'),
                 0x7e4a5c: (15210936, 'shaderNamed:attributes:uniforms:'),
                 0x7e4a70: (15210932, 'arrayWithObjects:'),
                 0x7e4aa0: (15210980, 'setVolume:'),
                 0x7e4aa8: (15210976, 'setLooping:'),
                 0x7e4ab0: (15210972, 'soundNamed:'),
                 0x7e4ab4: (15210968, 'instance'),
                 0x7e4ad4: (15210964, 'updateCloudsForLoadOrHDTeturesChange'),
                 0x7e4adc: (15210960, 'initWithPath:'),
                 0x7e4ae4: (15210956, 'stringByAppendingPathComponent:'),
                 0x7e4aec: (15210952, 'resourcePath'),
                 0x7e4af0: (15210948, 'mainBundle'),
                 0x7e4af8: (15210940, 'alloc'),
                 0x7e4b1c: (15210944, 'initWithFrequencyX:frequencyY:frequencyZ:amplitude:seed:tileable:loop:persistance:'),
                 0x7e4b30: (15210996, 'loadCricketSounds'),
                 0x7e4b3c: (15210984, 'stringWithFormat:'),
                 0x7e4b44: (15210988, 'multiSoundNamed:'),
                 0x7e4b4c: (15210992, 'setRandomPitchOffset:'),
        },
        imports={
                 0x7e4a40: (17151900, 'objc_msgSendSuper2'),
                 0x7e4a54: (16324152, '__CFConstantStringClassReference'),
                 0x7e4a58: (17151904, 'objc_msgSend'),
                 0x7e4a60: (16324088, '__CFConstantStringClassReference'),
                 0x7e4a64: (16324104, '__CFConstantStringClassReference'),
                 0x7e4a68: (16324120, '__CFConstantStringClassReference'),
                 0x7e4a6c: (16324168, '__CFConstantStringClassReference'),
                 0x7e4a78: (16324072, '__CFConstantStringClassReference'),
                 0x7e4a84: (16324056, '__CFConstantStringClassReference'),
                 0x7e4a88: (16324136, '__CFConstantStringClassReference'),
                 0x7e4aac: (16324312, '__CFConstantStringClassReference'),
                 0x7e4ac0: (16324296, '__CFConstantStringClassReference'),
                 0x7e4ac8: (16324280, '__CFConstantStringClassReference'),
                 0x7e4ad0: (16324264, '__CFConstantStringClassReference'),
                 0x7e4ae0: (16324248, '__CFConstantStringClassReference'),
                 0x7e4ae8: (16324184, '__CFConstantStringClassReference'),
                 0x7e4b04: (16324232, '__CFConstantStringClassReference'),
                 0x7e4b0c: (16324216, '__CFConstantStringClassReference'),
                 0x7e4b14: (16324200, '__CFConstantStringClassReference'),
                 0x7e4b40: (16324328, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7e4a4c: (17160740, 'OBJC_IVAR_$_Weather.randomNumbers', 452),
                 0x7e4a50: (17160744, 'OBJC_IVAR_$_Weather.snowShader', 484),
                 0x7e4a7c: (17160748, 'OBJC_IVAR_$_Weather.cache', 4),
                 0x7e4a80: (17160752, 'OBJC_IVAR_$_Weather.rainShader', 488),
                 0x7e4a90: (17160756, 'OBJC_IVAR_$_Weather.lastCloudCalcualtionRoundedTranslation', 628),
                 0x7e4a94: (17160760, 'OBJC_IVAR_$_Weather.world', 8),
                 0x7e4a98: (17160764, 'OBJC_IVAR_$_Weather.snowPoints', 12),
                 0x7e4aa4: (17160768, 'OBJC_IVAR_$_Weather.undergroundSound', 504),
                 0x7e4abc: (17160772, 'OBJC_IVAR_$_Weather.heavyRainSound', 500),
                 0x7e4ac4: (17160776, 'OBJC_IVAR_$_Weather.windSound', 508),
                 0x7e4acc: (17160780, 'OBJC_IVAR_$_Weather.lightRainSound', 496),
                 0x7e4ad8: (17160784, 'OBJC_IVAR_$_Weather.cloudColorBackgroundCloudyImageData', 660),
                 0x7e4b00: (17160788, 'OBJC_IVAR_$_Weather.cloudColorBackgroundImageData', 656),
                 0x7e4b08: (17160792, 'OBJC_IVAR_$_Weather.cloudColorForegroundCloudyImageData', 652),
                 0x7e4b10: (17160796, 'OBJC_IVAR_$_Weather.cloudColorForegroundImageData', 648),
                 0x7e4b18: (17160800, 'OBJC_IVAR_$_Weather.cloudNoiseFunction', 436),
                 0x7e4b24: (17160804, 'OBJC_IVAR_$_Weather.rainPoints', 16),
                 0x7e4b28: (17160808, 'OBJC_IVAR_$_Weather.lastSetUndergroundMix', 624),
                 0x7e4b2c: (17160812, 'OBJC_IVAR_$_Weather.randomBirdTimer', 620),
                 0x7e4b48: (17160816, 'OBJC_IVAR_$_Weather.birdsSound', 512),
        },
        classes={
                 0x7e4a48: (15252828, 'OBJC_CLASS_$_Weather'),
                 0x7e4a74: (15247204, 'OBJC_CLASS_$_NSArray'),
                 0x7e4ab8: (15247220, 'OBJC_CLASS_$_MJSoundManager'),
                 0x7e4af4: (15247216, 'OBJC_CLASS_$_NSBundle'),
                 0x7e4afc: (15247212, 'OBJC_CLASS_$_FNImageData'),
                 0x7e4b20: (15247208, 'OBJC_CLASS_$_NoiseFunction'),
                 0x7e4b38: (15247224, 'OBJC_CLASS_$_NSString'),
        },
        instructions=[(8272424, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8276824, 'ldrdeq fp, ip, [r7], ip')],
        calls=[(8272524, 'blx r4'), (8273004, 'blx ip'), (8273068, 'blx r5'), (8273112, 'blx lr'), (8273192, 'blx ip'), (8273256, 'blx r5'), (8273300, 'blx lr'), (8273328, 'bl sym.imp.__wrap_malloc'), (8273388, 'bl 0x7e4b5c'), (8273468, 'bl sym.imp.__wrap_malloc'), (8273528, 'bl 0x7e4b5c'), (8273612, 'bl 0x7e4b5c'), (8273672, 'bl 0x7e4b5c'), (8273796, 'bl sym.imp.__wrap_malloc'), (8273872, 'blx r3'), (8273880, 'bl 0x7e4b5c'), (8274656, 'blx ip'), (8274708, 'blx ip'), (8274740, 'blx r2'), (8274756, 'blx r2'), (8274776, 'blx r3'), (8274796, 'blx r3'), (8274828, 'blx r3'), (8274880, 'blx ip'), (8274912, 'blx r2'), (8274928, 'blx r2'), (8274948, 'blx r3'), (8274968, 'blx r3'), (8275000, 'blx r3'), (8275052, 'blx ip'), (8275084, 'blx r2'), (8275100, 'blx r2'), (8275120, 'blx r3'), (8275140, 'blx r3'), (8275172, 'blx r3'), (8275224, 'blx ip'), (8275256, 'blx r2'), (8275272, 'blx r2'), (8275292, 'blx r3'), (8275312, 'blx r3'), (8275344, 'blx r3'), (8275384, 'blx r3'), (8275416, 'blx r3'), (8275436, 'blx r3'), (8275496, 'blx ip'), (8275540, 'blx r3'), (8275572, 'blx r3'), (8275592, 'blx r3'), (8275652, 'blx ip'), (8275696, 'blx r3'), (8275728, 'blx r3'), (8275748, 'blx r3'), (8275808, 'blx ip'), (8275852, 'blx r3'), (8275884, 'blx r3'), (8275904, 'blx r3'), (8275964, 'blx ip'), (8276008, 'blx r3'), (8276076, 'bl loc.imp.objc_msgSend'), (8276128, 'bl loc.imp.objc_msgSend'), (8276160, 'bl loc.imp.objc_msgSend'), (8276352, 'blx lr'), (8276472, 'blx lr')],
        branches=[(8272552, 'bne', 8272568), (8272564, 'b', 8276532), (8273376, 'bhs', 8273464), (8273460, 'b', 8273368), (8273516, 'bhs', 8273792), (8273756, 'b', 8273508), (8276028, 'bhs', 8276380), (8276208, 'beq', 8276248), (8276220, 'beq', 8276248), (8276232, 'beq', 8276248), (8276244, 'bne', 8276356), (8276356, 'b', 8276360), (8276372, 'b', 8276020)],
        semantics=('[Weather -[initWithCache:world:worldTime:]] (imp 0x007e3a28, 1101w): the Weather construction - the cloud noise function (initWithFrequencyX:...persistance:), the rain/snow point shaders + arrays, the sound set (rain/wind/underground/birds), the cloud color image-data pack; 63 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='aq_01',
        method='Weather -[updateCloudsForLoadOrHDTeturesChange]',
        types='v8@0:4',
        start=8276844,
        end=8279400,
        disasm='disasm_worldtileloader_aq_01.txt',
        base_add=8276860,
        base_literal=8279396,
        boundary='ARM.exidx end 0x007e5568 (listing bound); next ObjC IMP 0x007e5568 Weather -[loadCricketSounds]',
        selectors={
                 0x7e54fc: (15210936, 'shaderNamed:attributes:uniforms:'),
                 0x7e550c: (15210932, 'arrayWithObjects:'),
                 0x7e5528: (15211000, 'textureNamed:'),
                 0x7e5550: (15211008, 'roundedTranslation'),
                 0x7e555c: (15211004, 'name'),
        },
        imports={
                 0x7e54f4: (16324520, '__CFConstantStringClassReference'),
                 0x7e54f8: (17151904, 'objc_msgSend'),
                 0x7e5500: (16324088, '__CFConstantStringClassReference'),
                 0x7e5504: (16324376, '__CFConstantStringClassReference'),
                 0x7e5508: (16324392, '__CFConstantStringClassReference'),
                 0x7e5514: (16324072, '__CFConstantStringClassReference'),
                 0x7e5518: (16324536, '__CFConstantStringClassReference'),
                 0x7e5524: (16324504, '__CFConstantStringClassReference'),
                 0x7e552c: (16324488, '__CFConstantStringClassReference'),
                 0x7e5530: (16324472, '__CFConstantStringClassReference'),
                 0x7e5534: (16324456, '__CFConstantStringClassReference'),
                 0x7e5538: (16324440, '__CFConstantStringClassReference'),
                 0x7e553c: (16324424, '__CFConstantStringClassReference'),
                 0x7e5540: (16324344, '__CFConstantStringClassReference'),
                 0x7e5544: (16324408, '__CFConstantStringClassReference'),
                 0x7e5548: (16324360, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7e54e4: (17160820, 'OBJC_IVAR_$_Weather.cloudPoints', 20),
                 0x7e54e8: (17160824, 'OBJC_IVAR_$_Weather.cloudsLoadedAsHD', 440),
                 0x7e54f0: (17160828, 'OBJC_IVAR_$_Weather.cloudShader', 492),
                 0x7e551c: (17160748, 'OBJC_IVAR_$_Weather.cache', 4),
                 0x7e5520: (17160832, 'OBJC_IVAR_$_Weather.cloudTextures', 412),
                 0x7e554c: (17160836, 'OBJC_IVAR_$_Weather.cloudQuadCount', 24),
                 0x7e5554: (17160760, 'OBJC_IVAR_$_Weather.world', 8),
                 0x7e5558: (17160840, 'OBJC_IVAR_$_Weather.clouds', 28),
        },
        classes={
                 0x7e5510: (15247204, 'OBJC_CLASS_$_NSArray'),
        },
        instructions=[(8276844, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8279396, 'addeq sl, r7, r0, ror pc')],
        calls=[(8276992, 'bl sym.imp.__wrap_free'), (8277424, 'blx ip'), (8277488, 'blx r5'), (8277532, 'blx lr'), (8277592, 'blx ip'), (8277652, 'blx ip'), (8277712, 'blx ip'), (8277772, 'blx ip'), (8277832, 'blx ip'), (8277892, 'blx ip'), (8278032, 'blx r3'), (8278052, 'bl sym.imp.__wrap_glBindTexture'), (8278068, 'bl sym.imp.__wrap_glTexParameteri'), (8278224, 'bl 0x7e4b5c'), (8278292, 'bl 0x7e4b5c'), (8278436, 'bl loc.imp.objc_msgSend_stret'), (8278472, 'bl sym.imp.memset'), (8278480, 'bl method.Vector2.operator_float__'), (8278700, 'bl sym.imp.__modsi3'), (8278868, 'bl sym.imp.__wrap_malloc'), (8279128, 'blx ip'), (8279184, 'blx r4'), (8279228, 'blx lr')],
        branches=[(8276892, 'beq', 8278796), (8276960, 'beq', 8277028), (8277932, 'bge', 8278088), (8278084, 'b', 8277924), (8278132, 'bge', 8278784), (8278420, 'beq', 8278444), (8278440, 'b', 8278476), (8278780, 'b', 8278124), (8278784, 'b', 8279252), (8278860, 'bne', 8278900)],
        semantics=('[Weather -[updateCloudsForLoadOrHDTeturesChange]] (imp 0x007e4b6c, 639w): the cloud texture (re)load - shaderNamed:attributes:uniforms: + textureNamed: + the roundedTranslation cache gate; 23 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='aq_02',
        method='Weather -[loadCricketSounds]',
        types='v8@0:4',
        start=8279400,
        end=8280848,
        disasm='disasm_worldtileloader_aq_02.txt',
        base_add=8279416,
        base_literal=8280844,
        boundary='ARM.exidx end 0x007e5b10 (listing bound); next ObjC IMP 0x007e5b10 Weather -[dealloc]',
        selectors={
                 0x7e5aa4: (15210984, 'stringWithFormat:'),
                 0x7e5ab0: (15210968, 'instance'),
                 0x7e5ab4: (15211012, 'externalMultiSoundWithKey:'),
                 0x7e5ac0: (15211028, 'registerExternalMultiSound:forKey:'),
                 0x7e5acc: (15210940, 'alloc'),
                 0x7e5ad4: (15210948, 'mainBundle'),
                 0x7e5ad8: (15210952, 'resourcePath'),
                 0x7e5adc: (15210956, 'stringByAppendingPathComponent:'),
                 0x7e5ae8: (15211016, 'initWithFile:'),
                 0x7e5af8: (15211024, 'setPitch:'),
                 0x7e5b08: (15211020, 'autorelease'),
        },
        imports={
                 0x7e5aa8: (16324552, '__CFConstantStringClassReference'),
                 0x7e5abc: (17151904, 'objc_msgSend'),
                 0x7e5ae0: (16324184, '__CFConstantStringClassReference'),
                 0x7e5ae4: (16324584, '__CFConstantStringClassReference'),
                 0x7e5b04: (16324568, '__CFConstantStringClassReference'),
        },
        ivars={
                 0x7e5ab8: (17160844, 'OBJC_IVAR_$_Weather.cricketSound', 568),
        },
        classes={
                 0x7e5a9c: (15247224, 'OBJC_CLASS_$_NSString'),
                 0x7e5aac: (15247220, 'OBJC_CLASS_$_MJSoundManager'),
                 0x7e5ac4: (15247228, 'OBJC_CLASS_$_MJMultiSound'),
                 0x7e5ad0: (15247216, 'OBJC_CLASS_$_NSBundle'),
        },
        instructions=[(8279400, 'push {r4, sl, fp, lr}'), (8280844, 'addeq sl, r7, r4, ror r5')],
        calls=[(8279528, 'bl loc.imp.objc_msgSend'), (8279556, 'bl loc.imp.objc_msgSend'), (8279576, 'bl loc.imp.objc_msgSend'), (8279716, 'bl loc.imp.objc_msgSend'), (8279752, 'bl loc.imp.objc_msgSend'), (8279768, 'bl loc.imp.objc_msgSend'), (8279800, 'bl loc.imp.objc_msgSend'), (8279824, 'bl loc.imp.objc_msgSend'), (8279856, 'bl loc.imp.objc_msgSend'), (8279872, 'bl loc.imp.objc_msgSend'), (8279936, 'bl 0x7e4b5c'), (8279992, 'bl loc.imp.objc_msgSend'), (8280016, 'bl loc.imp.objc_msgSend'), (8280064, 'blx ip'), (8280180, 'bl loc.imp.objc_msgSend'), (8280208, 'bl loc.imp.objc_msgSend'), (8280228, 'bl loc.imp.objc_msgSend'), (8280368, 'bl loc.imp.objc_msgSend'), (8280404, 'bl loc.imp.objc_msgSend'), (8280420, 'bl loc.imp.objc_msgSend'), (8280452, 'bl loc.imp.objc_msgSend'), (8280476, 'bl loc.imp.objc_msgSend'), (8280508, 'bl loc.imp.objc_msgSend'), (8280572, 'bl 0x7e4b5c'), (8280628, 'bl loc.imp.objc_msgSend'), (8280652, 'bl loc.imp.objc_msgSend'), (8280700, 'blx ip')],
        branches=[(8279452, 'bge', 8280088), (8279644, 'bne', 8280068), (8280068, 'b', 8280072), (8280084, 'b', 8279444), (8280104, 'bge', 8280724), (8280296, 'bne', 8280704), (8280704, 'b', 8280708), (8280720, 'b', 8280096)],
        semantics=('[Weather -[loadCricketSounds]] (imp 0x007e5568, 362w): the cricket-sound loader - registerExternalMultiSound:forKey: + externalMultiSoundWithKey: from the bundle; 27 calls.\n'),
    ),
    dict(
        name='aq_03',
        method='Weather -[dealloc]',
        types='v8@0:4',
        start=8280848,
        end=8281776,
        disasm='disasm_worldtileloader_aq_03.txt',
        base_add=8280864,
        base_literal=8281772,
        boundary='ARM.exidx end 0x007e5eb0 (listing bound); next ObjC IMP 0x007e5eb0 Weather -[update:rainFraction:snowFraction:]',
        selectors={
                 0x7e5e74: (15211040, 'dealloc'),
                 0x7e5e80: (15211032, 'release'),
                 0x7e5e94: (15211036, 'setPaused:'),
        },
        imports={
                 0x7e5e70: (17151900, 'objc_msgSendSuper2'),
                 0x7e5e7c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7e5e60: (17160820, 'OBJC_IVAR_$_Weather.cloudPoints', 20),
                 0x7e5e64: (17160740, 'OBJC_IVAR_$_Weather.randomNumbers', 452),
                 0x7e5e68: (17160804, 'OBJC_IVAR_$_Weather.rainPoints', 16),
                 0x7e5e6c: (17160764, 'OBJC_IVAR_$_Weather.snowPoints', 12),
                 0x7e5e84: (17160784, 'OBJC_IVAR_$_Weather.cloudColorBackgroundCloudyImageData', 660),
                 0x7e5e88: (17160788, 'OBJC_IVAR_$_Weather.cloudColorBackgroundImageData', 656),
                 0x7e5e8c: (17160792, 'OBJC_IVAR_$_Weather.cloudColorForegroundCloudyImageData', 652),
                 0x7e5e90: (17160796, 'OBJC_IVAR_$_Weather.cloudColorForegroundImageData', 648),
                 0x7e5e98: (17160768, 'OBJC_IVAR_$_Weather.undergroundSound', 504),
                 0x7e5e9c: (17160772, 'OBJC_IVAR_$_Weather.heavyRainSound', 500),
                 0x7e5ea0: (17160776, 'OBJC_IVAR_$_Weather.windSound', 508),
                 0x7e5ea4: (17160780, 'OBJC_IVAR_$_Weather.lightRainSound', 496),
                 0x7e5ea8: (17160800, 'OBJC_IVAR_$_Weather.cloudNoiseFunction', 436),
        },
        classes={
                 0x7e5e78: (15252828, 'OBJC_CLASS_$_Weather'),
        },
        instructions=[(8280848, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8281772, 'addeq sb, r7, ip, asr 31')],
        calls=[(8280904, 'bl sym.imp.__wrap_free'), (8280936, 'bl sym.imp.__wrap_free'), (8280968, 'bl sym.imp.__wrap_free'), (8281040, 'bl sym.imp.__wrap_free'), (8281324, 'blx r4'), (8281368, 'blx ip'), (8281412, 'blx ip'), (8281456, 'blx ip'), (8281500, 'blx ip'), (8281536, 'blx r3'), (8281572, 'blx r3'), (8281608, 'blx r3'), (8281644, 'blx r3'), (8281684, 'blx r2')],
        branches=[(8281008, 'beq', 8281076)],
        semantics=('[Weather -[dealloc]] (imp 0x007e5b10, 232w): releases the weather state (sounds, points, shaders, cloud color data, randomNumbers, cloud noise).\n'),
    ),
    dict(
        name='aq_04',
        method='Weather -[update:rainFraction:snowFraction:]',
        types='v20@0:4f8f12f16',
        start=8281776,
        end=8284784,
        disasm='disasm_worldtileloader_aq_04.txt',
        base_add=8281792,
        base_literal=8284780,
        boundary='ARM.exidx end 0x007e6a70 (listing bound); next ObjC IMP 0x007e6a70 Weather -[updateBirdSoundWithBirdFraction:dayNightMix:undergroundMix:dt:playPosition:]',
        selectors={},
        imports={},
        ivars={
                 0x7e6a18: (17160848, 'OBJC_IVAR_$_Weather.recalcRandomIndex', 464),
                 0x7e6a1c: (17160852, 'OBJC_IVAR_$_Weather.timeElapsed', 444),
                 0x7e6a24: (17160740, 'OBJC_IVAR_$_Weather.randomNumbers', 452),
                 0x7e6a28: (17160856, 'OBJC_IVAR_$_Weather.windMovement', 644),
                 0x7e6a34: (17160764, 'OBJC_IVAR_$_Weather.snowPoints', 12),
                 0x7e6a40: (17160860, 'OBJC_IVAR_$_Weather.rainXOffset', 468),
                 0x7e6a48: (17160864, 'OBJC_IVAR_$_Weather.rainZOffset', 476),
                 0x7e6a50: (17160868, 'OBJC_IVAR_$_Weather.rainYOffset', 472),
                 0x7e6a60: (17160804, 'OBJC_IVAR_$_Weather.rainPoints', 16),
        },
        classes={},
        instructions=[(8281776, 'push {r4, r5, fp, lr}'), (8284780, 'addeq sb, r7, ip, lsr 24')],
        calls=[(8282008, 'bl 0x7e4b5c'), (8282296, 'bl 0x7e4b5c'), (8282376, 'bl 0x7e4b5c'), (8282436, 'bl 0x7e4b5c'), (8283044, 'bl sym.linearInterpolate_float__float__float_'), (8283088, 'bl sym.linearInterpolate_float__float__float_')],
        branches=[(8281852, 'bmi', 8281896), (8281872, 'bpl', 8281928), (8281892, 'bpl', 8281928), (8281896, 'b', 8284652), (8282124, 'blt', 8282160), (8282224, 'ble', 8283552), (8282528, 'bhs', 8283548), (8283240, 'ble', 8283276), (8283268, 'b', 8283320), (8283288, 'bpl', 8283316), (8283316, 'b', 8283320), (8283344, 'ble', 8283384), (8283372, 'b', 8283428), (8283396, 'bpl', 8283424), (8283424, 'b', 8283428), (8283532, 'b', 8282520), (8283548, 'b', 8283552), (8283568, 'ble', 8284652), (8283592, 'bhs', 8284648), (8283652, 'blo', 8283780), (8283836, 'blo', 8283964), (8284020, 'blo', 8284152), (8284644, 'b', 8283584), (8284648, 'b', 8284652)],
        semantics=('[Weather -[update:rainFraction:snowFraction:]] (imp 0x007e5eb0, 752w): the rain/snow particle field update - the minimum-dt gate; rain points drift at 5*dt with the PRNG helper (the 0x1000 index wrap = recalcRandomIndex); the snow side (0x200 = 512 points) with linearInterpolate blends and windMovement; 24 branches - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='aq_05',
        method='Weather -[updateBirdSoundWithBirdFraction:dayNightMix:undergroundMix:dt:playPosition:]',
        types='v32@0:4f8f12f16f20{Vector2=[2f]}24',
        start=8284784,
        end=8286024,
        disasm='disasm_worldtileloader_aq_05.txt',
        base_add=8284800,
        base_literal=8286020,
        boundary='ARM.exidx end 0x007e6f48 (listing bound); next ObjC IMP 0x007e6f48 Weather -[updateRainSoundWithRainFraction:undergroundMix:position:]',
        selectors={
                 0x7e6f1c: (15211048, 'setLoopLength:'),
                 0x7e6f20: (15211044, 'playAtPosition:'),
                 0x7e6f38: (15210980, 'setVolume:'),
        },
        imports={
                 0x7e6f34: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7e6efc: (17160872, 'OBJC_IVAR_$_Weather.soundPaused', 616),
                 0x7e6f00: (17160812, 'OBJC_IVAR_$_Weather.randomBirdTimer', 620),
                 0x7e6f10: (17160844, 'OBJC_IVAR_$_Weather.cricketSound', 568),
                 0x7e6f24: (17160816, 'OBJC_IVAR_$_Weather.birdsSound', 512),
                 0x7e6f30: (17160808, 'OBJC_IVAR_$_Weather.lastSetUndergroundMix', 624),
        },
        classes={},
        instructions=[(8284784, 'push {r4, r5, r6, sl, fp, lr}'), (8286020, 'addeq sb, r7, ip, rrx')],
        calls=[(8285080, 'bl 0x7e4b5c'), (8285144, 'bl 0x7e4b5c'), (8285240, 'bl loc.imp.objc_msgSend'), (8285248, 'bl 0x7e4b5c'), (8285328, 'bl 0x7e4b5c'), (8285404, 'bl loc.imp.objc_msgSend'), (8285468, 'bl loc.imp.objc_msgSend'), (8285472, 'bl 0x7e4b5c'), (8285760, 'blx lr'), (8285912, 'blx lr')],
        branches=[(8284880, 'ble', 8285540), (8284916, 'bne', 8285540), (8284936, 'bpl', 8285540), (8285012, 'bpl', 8285536), (8285056, 'bne', 8285132), (8285076, 'ble', 8285128), (8285128, 'b', 8285132), (8285140, 'beq', 8285248), (8285244, 'b', 8285472), (8285536, 'b', 8285540), (8285592, 'ble', 8285936), (8285648, 'bge', 8285784), (8285776, 'b', 8285640), (8285800, 'bge', 8285932), (8285928, 'b', 8285792), (8285932, 'b', 8285936)],
        semantics=('[Weather -[updateBirdSoundWithBirdFraction:dayNightMix:undergroundMix:dt:playPosition:]] (imp 0x007e6a70, 310w): the bird/cricket ambience - randomBirdTimer-paced setVolume: with the dayNight/underground mixes; 16 branches.\n'),
    ),
    dict(
        name='aq_06',
        method='Weather -[updateRainSoundWithRainFraction:undergroundMix:position:]',
        types='v24@0:4f8f12{Vector2=[2f]}16',
        start=8286024,
        end=8288656,
        disasm='disasm_worldtileloader_aq_06.txt',
        base_add=8286040,
        base_literal=8288648,
        boundary='ARM.exidx end 0x007e7990 (listing bound); next ObjC IMP 0x007e7990 Weather -[updateCloudsWithTranslation:]',
        selectors={
                 0x7e7950: (15211052, 'windStrength'),
                 0x7e7960: (15211056, 'setPosition:'),
                 0x7e7964: (15211036, 'setPaused:'),
                 0x7e7968: (15210980, 'setVolume:'),
        },
        imports={
                 0x7e794c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7e7954: (17160872, 'OBJC_IVAR_$_Weather.soundPaused', 616),
                 0x7e7958: (17160776, 'OBJC_IVAR_$_Weather.windSound', 508),
                 0x7e796c: (17160772, 'OBJC_IVAR_$_Weather.heavyRainSound', 500),
                 0x7e7970: (17160780, 'OBJC_IVAR_$_Weather.lightRainSound', 496),
                 0x7e7980: (17160768, 'OBJC_IVAR_$_Weather.undergroundSound', 504),
        },
        classes={},
        instructions=[(8286024, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8288652, 'andeq r0, r0, r0')],
        calls=[(8286120, 'blx lr'), (8286344, 'bl loc.imp.objc_msgSend'), (8286580, 'blx r4'), (8286624, 'blx ip'), (8286716, 'blx ip'), (8286972, 'bl loc.imp.objc_msgSend'), (8287016, 'blx ip'), (8287212, 'blx r3'), (8287372, 'bl loc.imp.objc_msgSend'), (8287608, 'blx r4'), (8287652, 'blx ip'), (8287744, 'blx ip'), (8287848, 'blx r4'), (8287892, 'blx ip'), (8288036, 'bl loc.imp.objc_msgSend'), (8288240, 'blx r4'), (8288284, 'blx ip'), (8288372, 'blx ip'), (8288488, 'blx r5'), (8288532, 'blx ip'), (8288576, 'blx ip')],
        branches=[(8286148, 'ble', 8286636), (8286184, 'bne', 8286636), (8286204, 'bpl', 8286636), (8286448, 'bpl', 8286464), (8286460, 'b', 8286476), (8286628, 'b', 8286720), (8286736, 'ble', 8288380), (8286772, 'bne', 8288380), (8286808, 'bpl', 8287752), (8287112, 'bpl', 8287132), (8287124, 'b', 8287144), (8287232, 'ble', 8287664), (8287476, 'bpl', 8287492), (8287488, 'b', 8287504), (8287656, 'b', 8287748), (8287748, 'b', 8287896), (8287912, 'ble', 8288292), (8288112, 'bpl', 8288132), (8288124, 'b', 8288140), (8288288, 'b', 8288376), (8288376, 'b', 8288580)],
        semantics=('[Weather -[updateRainSoundWithRainFraction:undergroundMix:position:]] (imp 0x007e6f48, 658w): the rain sound mixer - the light/heavy rain, wind and underground sound volumes + setPosition: driven by windStrength; 21 calls.\n'),
    ),
    dict(
        name='aq_07',
        method='Weather -[updateCloudsWithTranslation:]',
        types='v12@0:4f8',
        start=8288656,
        end=8292520,
        disasm='disasm_worldtileloader_aq_07.txt',
        base_add=8288676,
        base_literal=8292516,
        boundary='ARM.exidx end 0x007e88a8 (listing bound); next ObjC IMP 0x007e88a8 Weather -[renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:]',
        selectors={
                 0x7e888c: (15211060, 'getX:Y:octaves:'),
        },
        imports={
                 0x7e8888: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7e8880: (17160836, 'OBJC_IVAR_$_Weather.cloudQuadCount', 24),
                 0x7e8884: (17167340, 'OBJC_IVAR_$_ChatView.seperator', 16),
                 0x7e8890: (17160800, 'OBJC_IVAR_$_Weather.cloudNoiseFunction', 436),
                 0x7e8898: (17160820, 'OBJC_IVAR_$_Weather.cloudPoints', 20),
                 0x7e889c: (17160840, 'OBJC_IVAR_$_Weather.clouds', 28),
                 0x7e88a0: (17168116, 'OBJC_IVAR_$_ServerClient.connected', 77),
        },
        classes={},
        instructions=[(8288656, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8292516, 'addeq r8, r7, r8, asr 2')],
        calls=[(8288996, 'bl 0x7e4b5c'), (8289032, 'bl sym.imp.__modsi3'), (8289332, 'bl 0x7e4b5c'), (8289368, 'bl sym.imp.__modsi3'), (8290004, 'blx lr'), (8290520, 'bl sym.clamp_float__float__float_'), (8290600, 'bl method.Vector.Vector_float__float__float__float_'), (8290736, 'bl method.Vector.operator_float__'), (8290776, 'bl method.Vector.operator_float__'), (8290816, 'bl method.Vector.operator_float__'), (8290856, 'bl method.Vector.operator_float__'), (8291008, 'bl method.Vector.operator_float__'), (8291048, 'bl method.Vector.operator_float__'), (8291088, 'bl method.Vector.operator_float__'), (8291128, 'bl method.Vector.operator_float__'), (8291280, 'bl method.Vector.operator_float__'), (8291320, 'bl method.Vector.operator_float__'), (8291360, 'bl method.Vector.operator_float__'), (8291400, 'bl method.Vector.operator_float__'), (8291552, 'bl method.Vector.operator_float__'), (8291592, 'bl method.Vector.operator_float__'), (8291632, 'bl method.Vector.operator_float__'), (8291672, 'bl method.Vector.operator_float__'), (8291824, 'bl method.Vector.operator_float__'), (8291864, 'bl method.Vector.operator_float__'), (8291904, 'bl method.Vector.operator_float__'), (8291944, 'bl method.Vector.operator_float__'), (8292096, 'bl method.Vector.operator_float__'), (8292136, 'bl method.Vector.operator_float__'), (8292176, 'bl method.Vector.operator_float__'), (8292216, 'bl method.Vector.operator_float__')],
        branches=[(8288716, 'beq', 8289440), (8288736, 'bge', 8289436), (8288816, 'ble', 8289076), (8288904, 'ble', 8288984), (8288980, 'b', 8288828), (8288992, 'bne', 8289072), (8289072, 'b', 8289416), (8289152, 'bpl', 8289412), (8289240, 'bpl', 8289320), (8289316, 'b', 8289164), (8289328, 'bne', 8289408), (8289408, 'b', 8289412), (8289412, 'b', 8289416), (8289416, 'b', 8289420), (8289432, 'b', 8288728), (8289436, 'b', 8292464), (8289488, 'bge', 8292460), (8289524, 'blt', 8289532), (8289528, 'b', 8292460), (8289652, 'bge', 8292440), (8289688, 'blt', 8289768), (8289692, 'b', 8292440), (8290180, 'bge', 8290216), (8290192, 'b', 8290224), (8290248, 'ble', 8292316), (8290276, 'bge', 8292312), (8292308, 'b', 8290264), (8292312, 'b', 8292420), (8292324, 'ble', 8292416), (8292336, 'bge', 8292376), (8292372, 'b', 8292408), (8292416, 'b', 8292420), (8292420, 'b', 8292424), (8292436, 'b', 8289644), (8292440, 'b', 8292444), (8292456, 'b', 8289480), (8292460, 'b', 8292464)],
        semantics=('[Weather -[updateCloudsWithTranslation:]] (imp 0x007e7990, 966w): the cloud field generation - cloudNoiseFunction getX:Y:Z:octaves: per cloud point into cloudPoints (cloudQuadCount); 31 calls, 37 branches - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='aq_08',
        method='Weather -[renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:]',
        types='v96@0:4(_GLKMatrix4={?=ffffffffffffffff}[16f])8{Vector2=[2f]}72f80f84f88f92',
        start=8292520,
        end=8300028,
        disasm='disasm_worldtileloader_aq_08.txt',
        base_add=8292548,
        base_literal=8295040,
        boundary='ARM.exidx end 0x007ea5fc (listing bound); next ObjC IMP 0x007ea820 Weather -[renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:]',
        selectors={
                 0x7e9ad0: (15210964, 'updateCloudsForLoadOrHDTeturesChange'),
                 0x7e9ae0: (15211064, 'worldWidthMacro'),
                 0x7e9dd4: (15211068, 'updateCloudsWithTranslation:'),
                 0x7e9fe8: (15211072, 'cloudColorForWeatherFraction:timeOfDayFraction:isBackground:'),
                 0x7e9ff0: (15211076, 'program'),
                 0x7e9ff8: (15211088, 'intValue'),
                 0x7e9ffc: (15211084, 'objectAtIndex:'),
                 0x7ea000: (15211080, 'uniformLocations'),
                 0x7ea5b8: (15211068, 'updateCloudsWithTranslation:'),
                 0x7ea5bc: (15211072, 'cloudColorForWeatherFraction:timeOfDayFraction:isBackground:'),
                 0x7ea5c8: (15211088, 'intValue'),
                 0x7ea5cc: (15211084, 'objectAtIndex:'),
                 0x7ea5d0: (15211080, 'uniformLocations'),
                 0x7ea5d8: (15211076, 'program'),
                 0x7ea5e0: (15211092, 'size'),
                 0x7ea5e8: (15211004, 'name'),
                 0x7ea5f4: (15211100, 'maxT'),
                 0x7ea5f8: (15211096, 'maxS'),
        },
        imports={
                 0x7e9acc: (17151904, 'objc_msgSend'),
                 0x7ea5b0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7e9978: (17160876, 'OBJC_IVAR_$_Weather.cloudDirectionChangeTimer', 640),
                 0x7e997c: (17160880, 'OBJC_IVAR_$_Weather.cloudWindOffset', 632),
                 0x7e9980: (17160856, 'OBJC_IVAR_$_Weather.windMovement', 644),
                 0x7e9984: (17160884, 'OBJC_IVAR_$_Weather.cloudGoingRight', 636),
                 0x7e9ac4: (17160824, 'OBJC_IVAR_$_Weather.cloudsLoadedAsHD', 440),
                 0x7e9ad8: (17160756, 'OBJC_IVAR_$_Weather.lastCloudCalcualtionRoundedTranslation', 628),
                 0x7e9adc: (17160760, 'OBJC_IVAR_$_Weather.world', 8),
                 0x7e9ff4: (17160828, 'OBJC_IVAR_$_Weather.cloudShader', 492),
                 0x7ea5ac: (17160880, 'OBJC_IVAR_$_Weather.cloudWindOffset', 632),
                 0x7ea5b4: (17160756, 'OBJC_IVAR_$_Weather.lastCloudCalcualtionRoundedTranslation', 628),
                 0x7ea5c0: (17160836, 'OBJC_IVAR_$_Weather.cloudQuadCount', 24),
                 0x7ea5c4: (17160820, 'OBJC_IVAR_$_Weather.cloudPoints', 20),
                 0x7ea5d4: (17160828, 'OBJC_IVAR_$_Weather.cloudShader', 492),
                 0x7ea5e4: (17160840, 'OBJC_IVAR_$_Weather.clouds', 28),
                 0x7ea5f0: (17160832, 'OBJC_IVAR_$_Weather.cloudTextures', 412),
        },
        classes={},
        instructions=[(8292520, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8300024, 'invalid')],
        calls=[(8293388, 'blx r2'), (8293444, 'bl method.Vector2.operator_float__'), (8293556, 'bl loc.imp.objc_msgSend'), (8293580, 'bl sym.imp.__aeabi_idiv'), (8293700, 'bl loc.imp.objc_msgSend'), (8293840, 'bl loc.imp.objc_msgSend'), (8293856, 'bl sym.imp.__aeabi_idiv'), (8293976, 'bl loc.imp.objc_msgSend'), (8294196, 'blx r3'), (8294264, 'bl sym.pushDepthMaskState'), (8294272, 'bl sym.imp.__wrap_glEnable'), (8294364, 'bl loc.imp.objc_msgSend'), (8294472, 'bl loc.imp.objc_msgSend'), (8294612, 'bl loc.imp.objc_msgSend'), (8294740, 'blx r3'), (8294880, 'bl loc.imp.objc_msgSend_stret'), (8294920, 'bl sym.imp.memset'), (8295032, 'bl loc.imp.objc_msgSend_stret'), (8295076, 'bl sym.imp.memset'), (8295452, 'bl 0x7ea5fc'), (8295520, 'bl sym.imp.memcpy'), (8295556, 'blx r3'), (8295560, 'bl sym.imp.__wrap_glUseProgram'), (8295692, 'blx r3'), (8295712, 'blx r3'), (8295728, 'blx r2'), (8295760, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8295892, 'blx r6'), (8295912, 'blx r3'), (8295928, 'blx r2'), (8295944, 'bl method.Vector.operator_float__'), (8295968, 'bl method.Vector.operator_float__'), (8295992, 'bl method.Vector.operator_float__'), (8296048, 'bl sym.imp.__wrap_glUniform4f'), (8296180, 'blx r6'), (8296200, 'blx r3'), (8296216, 'blx r2'), (8296232, 'bl method.Vector.operator_float__'), (8296256, 'bl method.Vector.operator_float__'), (8296280, 'bl method.Vector.operator_float__'), (8296336, 'bl sym.imp.__wrap_glUniform4f'), (8296464, 'blx r6'), (8296484, 'blx r3'), (8296500, 'blx r2'), (8296508, 'bl sym.imp.__wrap_glUniform1i'), (8296692, 'blx r3'), (8296712, 'bl sym.imp.__wrap_glBindTexture'), (8296816, 'bl loc.imp.objc_msgSend_stret'), (8296876, 'bl sym.imp.memset'), (8297148, 'bl loc.imp.objc_msgSend_stret'), (8297224, 'bl sym.imp.memset'), (8297636, 'blx lr'), (8297676, 'blx r3'), (8297844, 'bl sym.imp.__wrap_glVertexAttribPointer'), (8297884, 'bl sym.imp.__wrap_glVertexAttribPointer'), (8297900, 'bl sym.imp.__wrap_glDrawArrays'), (8297924, 'bl sym.imp.__wrap_glDisable'), (8297928, 'bl sym.popDepthMaskState'), (8297956, 'bl method.Vector2.operator_float__'), (8298072, 'bl 0x7ea7e4'), (8298156, 'blx r3'), (8298192, 'bl sym.pushDepthMaskState'), (8298200, 'bl sym.imp.__wrap_glDisable'), (8298308, 'bl loc.imp.objc_msgSend_stret'), (8298348, 'bl sym.imp.memset'), (8298456, 'bl loc.imp.objc_msgSend_stret'), (8298528, 'bl sym.imp.memset'), (8298892, 'bl 0x7ea5fc'), (8298960, 'bl sym.imp.memcpy'), (8298996, 'blx r3'), (8299000, 'bl sym.imp.__wrap_glUseProgram'), (8299132, 'blx r3'), (8299152, 'blx r3'), (8299168, 'blx r2'), (8299200, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8299328, 'blx r6'), (8299348, 'blx r3'), (8299364, 'blx r2'), (8299380, 'bl method.Vector.operator_float__'), (8299400, 'bl method.Vector.operator_float__'), (8299420, 'bl method.Vector.operator_float__'), (8299476, 'bl sym.imp.__wrap_glUniform4f'), (8299604, 'blx r6'), (8299624, 'blx r3'), (8299640, 'blx r2'), (8299656, 'bl method.Vector.operator_float__'), (8299676, 'bl method.Vector.operator_float__'), (8299696, 'bl method.Vector.operator_float__'), (8299752, 'bl sym.imp.__wrap_glUniform4f'), (8299816, 'bl sym.imp.__wrap_glVertexAttribPointer'), (8299884, 'bl sym.imp.__wrap_glVertexAttribPointer'), (8299932, 'bl sym.imp.__wrap_glDrawArrays'), (8299936, 'bl sym.popDepthMaskState')],
        branches=[(8292916, 'bpl', 8292944), (8292932, 'b', 8292956), (8293172, 'bpl', 8293300), (8293196, 'bpl', 8293300), (8293344, 'beq', 8293392), (8293412, 'beq', 8297948), (8293604, 'blt', 8293740), (8293736, 'b', 8294092), (8293880, 'bpl', 8294032), (8294012, 'b', 8294084), (8294124, 'blt', 8294236), (8294416, 'ble', 8294508), (8294504, 'b', 8294772), (8294664, 'bpl', 8294768), (8294768, 'b', 8294772), (8294832, 'beq', 8294888), (8294884, 'b', 8294924), (8294984, 'beq', 8295044), (8295036, 'b', 8295080), (8296556, 'bge', 8297920), (8296796, 'beq', 8296844), (8296820, 'b', 8296880), (8297132, 'beq', 8297196), (8297152, 'b', 8297228), (8297916, 'b', 8296520), (8297932, 'b', 8299940), (8298080, 'ble', 8298184), (8298264, 'beq', 8298320), (8298312, 'b', 8298352), (8298412, 'beq', 8298500), (8298460, 'b', 8298532)],
        semantics=('[Weather -[renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:]] (imp 0x007e88a8, 1877w): the cloud renderer - the per-quad uniform work, cloudTextures objectAtIndex:, the direction-change timer (cloudGoingRight/windMovement), cloudColorForWeatherFraction:... x2 and the updateClouds* calls; 93 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='aq_09',
        method='Weather -[renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:]',
        types='v104@0:4(_GLKMatrix4={?=ffffffffffffffff}[16f])8f72{Vector=[4f]}76f92f96f100',
        start=8300576,
        end=8303848,
        disasm='disasm_worldtileloader_aq_09.txt',
        base_add=8300596,
        base_literal=8303844,
        boundary='ARM.exidx end 0x007eb4e8 (listing bound); next ObjC IMP 0x007eb4e8 Weather -[setSoundPaused:]',
        selectors={
                 0x7eb4c4: (15211088, 'intValue'),
                 0x7eb4c8: (15211084, 'objectAtIndex:'),
                 0x7eb4cc: (15211080, 'uniformLocations'),
                 0x7eb4d4: (15211076, 'program'),
        },
        imports={
                 0x7eb4c0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7eb4b8: (17160804, 'OBJC_IVAR_$_Weather.rainPoints', 16),
                 0x7eb4d0: (17160752, 'OBJC_IVAR_$_Weather.rainShader', 488),
                 0x7eb4dc: (17160764, 'OBJC_IVAR_$_Weather.snowPoints', 12),
                 0x7eb4e0: (17160744, 'OBJC_IVAR_$_Weather.snowShader', 484),
        },
        classes={},
        instructions=[(8300576, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8303844, 'strheq r5, [r7], r8')],
        calls=[(8301044, 'bl method.Vector.operator_float__'), (8301140, 'bl method.Vector.operator_float__'), (8301160, 'bl method.Vector.operator_float__'), (8301256, 'bl method.Vector.operator_float__'), (8301276, 'bl method.Vector.operator_float__'), (8301384, 'bl method.Vector.operator_float__'), (8301456, 'blx r3'), (8301460, 'bl sym.imp.__wrap_glUseProgram'), (8301588, 'blx r6'), (8301608, 'blx r3'), (8301624, 'blx r2'), (8301632, 'bl sym.imp.__wrap_glUniform1i'), (8301764, 'blx r3'), (8301784, 'blx r3'), (8301800, 'blx r2'), (8301832, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8301960, 'blx r6'), (8301980, 'blx r3'), (8301996, 'blx r2'), (8302012, 'bl method.Vector.operator_float__'), (8302032, 'bl method.Vector.operator_float__'), (8302052, 'bl method.Vector.operator_float__'), (8302104, 'bl sym.imp.__wrap_glUniform4f'), (8302240, 'blx r6'), (8302260, 'blx r3'), (8302276, 'blx r2'), (8302304, 'bl sym.imp.__wrap_glUniform1f'), (8302360, 'bl sym.imp.__wrap_glLineWidth'), (8302428, 'bl sym.imp.__wrap_glVertexAttribPointer'), (8302480, 'bl sym.imp.__wrap_glDrawArrays'), (8302552, 'bl method.Vector.Vector_float__float__float__float_'), (8302592, 'bl method.Vector.operator_Vector_'), (8302600, 'bl method.Vector.operator_float__'), (8302628, 'bl method.Vector.operator_float__'), (8302648, 'bl method.Vector.operator_float__'), (8302676, 'bl method.Vector.operator_float__'), (8302696, 'bl method.Vector.operator_float__'), (8302724, 'bl method.Vector.operator_float__'), (8302796, 'blx r3'), (8302800, 'bl sym.imp.__wrap_glUseProgram'), (8302928, 'blx r6'), (8302948, 'blx r3'), (8302964, 'blx r2'), (8302972, 'bl sym.imp.__wrap_glUniform1i'), (8303104, 'blx r3'), (8303124, 'blx r3'), (8303140, 'blx r2'), (8303172, 'bl sym.imp.__wrap_glUniformMatrix4fv'), (8303300, 'blx r6'), (8303320, 'blx r3'), (8303336, 'blx r2'), (8303352, 'bl method.Vector.operator_float__'), (8303372, 'bl method.Vector.operator_float__'), (8303392, 'bl method.Vector.operator_float__'), (8303448, 'bl sym.imp.__wrap_glUniform4f'), (8303588, 'blx r3'), (8303608, 'blx r3'), (8303624, 'blx r2'), (8303672, 'bl sym.imp.__wrap_glUniform2f'), (8303740, 'bl sym.imp.__wrap_glVertexAttribPointer'), (8303788, 'bl sym.imp.__wrap_glDrawArrays')],
        branches=[(8300908, 'ble', 8302500), (8300968, 'bpl', 8300984), (8300980, 'b', 8300992), (8301096, 'bpl', 8301112), (8301108, 'b', 8301120), (8301212, 'bpl', 8301228), (8301224, 'b', 8301236), (8301328, 'bpl', 8301356), (8301340, 'b', 8301364), (8302484, 'b', 8302500), (8302516, 'ble', 8303792)],
        semantics=('[Weather -[renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:]] (imp 0x007ea820, 818w): the rain/snow renderer - rainShader/snowShader uniformLocations + the rainPoints/snowPoints draws; 61 calls - census-grade, not a per-instruction walkthrough.\n'),
    ),
    dict(
        name='aq_10',
        method='Weather -[setSoundPaused:]',
        types='v12@0:4c8',
        start=8303848,
        end=8304276,
        disasm='disasm_worldtileloader_aq_10.txt',
        base_add=8303864,
        base_literal=8304272,
        boundary='ARM.exidx end 0x007eb694 (listing bound); next ObjC IMP 0x007eb694 Weather -[cloudColorForWeatherFraction:timeOfDayFraction:isBackground:]',
        selectors={
                 0x7eb67c: (15211036, 'setPaused:'),
        },
        imports={
                 0x7eb678: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x7eb674: (17160872, 'OBJC_IVAR_$_Weather.soundPaused', 616),
                 0x7eb680: (17160776, 'OBJC_IVAR_$_Weather.windSound', 508),
                 0x7eb684: (17160768, 'OBJC_IVAR_$_Weather.undergroundSound', 504),
                 0x7eb688: (17160772, 'OBJC_IVAR_$_Weather.heavyRainSound', 500),
                 0x7eb68c: (17160780, 'OBJC_IVAR_$_Weather.lightRainSound', 496),
        },
        classes={},
        instructions=[(8303848, 'push {r4, r5, r6, sl, fp, lr}'), (8304272, 'strdeq r4, r5, [r7], r4')],
        calls=[(8304096, 'blx r6'), (8304140, 'blx ip'), (8304184, 'blx ip'), (8304228, 'blx ip')],
        branches=[(8303916, 'beq', 8304236), (8303972, 'beq', 8304232), (8304232, 'b', 8304236)],
        semantics=('[Weather -[setSoundPaused:]] (imp 0x007eb4e8, 107w): the sound pause switch - stores the bool and setPaused: on the five sounds.\n'),
    ),
    dict(
        name='aq_11',
        method='Weather -[cloudColorForWeatherFraction:timeOfDayFraction:isBackground:]',
        types='{Vector=[4f]}20@0:4f8f12c16',
        start=8304276,
        end=8306400,
        disasm='disasm_worldtileloader_aq_11.txt',
        base_add=8304292,
        base_literal=8306396,
        boundary='ARM.exidx end 0x007ebee0 (listing bound); next ObjC IMP 0x007ebee0 Weather -[windStrength]',
        selectors={
                 0x7ebec0: (15211104, 'data'),
                 0x7ebec8: (15211108, 'width'),
                 0x7ebed0: (15211112, 'customRules'),
        },
        imports={
                 0x7ebea8: (17151968, '__stack_chk_guard'),
        },
        ivars={
                 0x7ebeac: (17160796, 'OBJC_IVAR_$_Weather.cloudColorForegroundImageData', 648),
                 0x7ebeb0: (17160788, 'OBJC_IVAR_$_Weather.cloudColorBackgroundImageData', 656),
                 0x7ebeb4: (17160792, 'OBJC_IVAR_$_Weather.cloudColorForegroundCloudyImageData', 652),
                 0x7ebeb8: (17160784, 'OBJC_IVAR_$_Weather.cloudColorBackgroundCloudyImageData', 660),
                 0x7ebed4: (17160760, 'OBJC_IVAR_$_Weather.world', 8),
        },
        classes={},
        instructions=[(8304276, 'push {r4, r5, fp, lr}'), (8306396, 'addeq r4, r7, r8, asr 8')],
        calls=[(8304352, 'bl method.Vector.Vector__'), (8304468, 'bl sym.clamp_float__float__float_'), (8304764, 'bl loc.imp.objc_msgSend'), (8304788, 'bl loc.imp.objc_msgSend'), (8304884, 'bl sym.linearInterpolate_float__float__float_'), (8304956, 'bl sym.linearInterpolate_float__float__float_'), (8305048, 'bl sym.linearInterpolate_float__float__float_'), (8305132, 'bl loc.imp.objc_msgSend'), (8305156, 'bl loc.imp.objc_msgSend'), (8305252, 'bl sym.linearInterpolate_float__float__float_'), (8305324, 'bl sym.linearInterpolate_float__float__float_'), (8305416, 'bl sym.linearInterpolate_float__float__float_'), (8305468, 'bl sym.linearInterpolate_float__float__float_'), (8305484, 'bl method.Vector.operator_float__'), (8305520, 'bl sym.linearInterpolate_float__float__float_'), (8305536, 'bl method.Vector.operator_float__'), (8305572, 'bl sym.linearInterpolate_float__float__float_'), (8305588, 'bl method.Vector.operator_float__'), (8305624, 'bl sym.linearInterpolate_float__float__float_'), (8305648, 'bl method.Vector.operator_float__'), (8305732, 'bl loc.imp.objc_msgSend_stret'), (8305768, 'bl sym.imp.memset'), (8305856, 'bl loc.imp.objc_msgSend_stret'), (8305896, 'bl sym.imp.memset'), (8305940, 'bl method.Vector.operator_float__'), (8306032, 'bl loc.imp.objc_msgSend_stret'), (8306068, 'bl sym.imp.memset'), (8306112, 'bl method.Vector.operator_float__'), (8306204, 'bl loc.imp.objc_msgSend_stret'), (8306240, 'bl sym.imp.memset'), (8306284, 'bl method.Vector.operator_float__'), (8306340, 'bl sym.imp.__stack_chk_fail')],
        branches=[(8304388, 'ble', 8304480), (8304524, 'beq', 8304564), (8304560, 'b', 8304596), (8304612, 'beq', 8304664), (8304648, 'b', 8304696), (8304720, 'bpl', 8305076), (8305088, 'ble', 8305444), (8305716, 'beq', 8305740), (8305736, 'b', 8305772), (8305780, 'beq', 8306304), (8305840, 'beq', 8305868), (8305860, 'b', 8305900), (8306016, 'beq', 8306040), (8306036, 'b', 8306072), (8306188, 'beq', 8306212), (8306208, 'b', 8306244), (8306328, 'bne', 8306340)],
        semantics=('[Weather -[cloudColorForWeatherFraction:timeOfDayFraction:isBackground:]] (imp 0x007eb694, 531w): the cloud tint - samples the four cloudColor*ImageData buffers (foreground/background x normal/cloudy) by weatherFraction and timeOfDayFraction; 32 calls.\n'),
    ),
    dict(
        name='aq_12',
        method='Weather -[windStrength]',
        types='f8@0:4',
        start=8306400,
        end=8306528,
        disasm='disasm_worldtileloader_aq_12.txt',
        base_add=8306432,
        base_literal=8306524,
        boundary='ARM.exidx end 0x007ebf60 (listing bound); next ObjC IMP 0x007ebf60 Weather -[windMovement]',
        selectors={},
        imports={},
        ivars={
                 0x7ebf58: (17160856, 'OBJC_IVAR_$_Weather.windMovement', 644),
        },
        classes={},
        instructions=[(8306400, 'push {fp, lr}'), (8306524, 'addeq r3, r7, ip, ror 23')],
        calls=[(8306492, 'bl sym.clamp_float__float__float_')],
        branches=[],
        semantics=('[Weather -[windStrength]] (imp 0x007ebee0, 32w): windStrength = clamp((windMovement - 5) / 32, 0, 3) - the constants 5.0/32.0 and the [0,3] clamp (aq_06 consumes it).\n'),
    ),
    dict(
        name='aq_13',
        method='Weather -[windMovement]',
        types='f8@0:4',
        start=8306528,
        end=8306600,
        disasm='disasm_worldtileloader_aq_13.txt',
        base_add=8306552,
        base_literal=8306596,
        boundary='ARM.exidx end 0x007ebff4; body trimmed at the next IMP 0x007ebfa8 Weather -[setWindMovement:]',
        selectors={},
        imports={},
        ivars={
                 0x7ebfa0: (17160856, 'OBJC_IVAR_$_Weather.windMovement', 644),
        },
        classes={},
        instructions=[(8306528, 'sub sp, sp, 0xc'), (8306596, 'addeq r3, r7, r4, ror fp')],
        calls=[],
        branches=[],
        semantics=('[Weather -[windMovement]] (imp 0x007ebf60, 18w): bare getter (windMovement).\n'),
    ),
    dict(
        name='aq_14',
        method='Weather -[setWindMovement:]',
        types='v12@0:4f8',
        start=8306600,
        end=8306676,
        disasm='disasm_worldtileloader_aq_14.txt',
        base_add=8306632,
        base_literal=8306672,
        boundary='ARM.exidx end 0x007ebff4 (listing bound); next ObjC IMP 0x007ebff4 Weather -[.cxx_construct]',
        selectors={},
        imports={},
        ivars={
                 0x7ebfec: (17160856, 'OBJC_IVAR_$_Weather.windMovement', 644),
        },
        classes={},
        instructions=[(8306600, 'sub sp, sp, 0xc'), (8306672, 'addeq r3, r7, r4, lsr 22')],
        calls=[],
        branches=[],
        semantics=('[Weather -[setWindMovement:]] (imp 0x007ebfa8, 19w): bare setter.\n'),
    ),
    dict(
        name='aq_15',
        method='Weather -[.cxx_construct]',
        types='@8@0:4',
        start=8306676,
        end=8306700,
        disasm='disasm_worldtileloader_aq_15.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x007ec00c (listing bound); next ObjC IMP 0x007ec070 LoadWorldUI -[initWithDelegate:windowInfo:cache:cloudInterface:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(8306676, 'sub sp, sp, 8'), (8306696, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[Weather -[.cxx_construct]] (imp 0x007ebff4, 6w): the C++ ctor anchor (no ObjC work).\n'),
    ),
    dict(
        name='aq_16',
        method='World -[getWeatherFractionForPos:]',
        types='f16@0:4{?=ii}8',
        start=5778000,
        end=5778136,
        disasm='disasm_worldtileloader_aq_16.txt',
        base_add=5778060,
        base_literal=5778128,
        boundary='ARM.exidx end 0x00582ad8 (listing bound); next ObjC IMP 0x00582ad8 World -[getDayNightFractionForX:atWorldTime:]',
        selectors={
                 0x582ad4: (15197080, 'getWeatherFractionForPos:atWorldTime:'),
        },
        imports={},
        ivars={
                 0x582acc: (17155924, 'OBJC_IVAR_$_World.worldTime', 648),
        },
        classes={},
        instructions=[(5778000, 'push {fp, lr}'), (5778132, 'invalid')],
        calls=[(5778104, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[getWeatherFractionForPos:]] (imp 0x00582a50, 34w): getWeatherFractionForPos: = the atWorldTime: variant with self.worldTime (the default time source).\n'),
    ),
    dict(
        name='aq_17',
        method='World -[getWeatherFractionForPos:atWorldTime:]',
        types='f24@0:4{?=ii}8d16',
        start=5776392,
        end=5776520,
        disasm='disasm_worldtileloader_aq_17.txt',
        base_add=5776460,
        base_literal=5776516,
        boundary='ARM.exidx end 0x00582488 (listing bound); next ObjC IMP 0x00582488 World -[getWeatherFractionForPos:atWorldTime:ignoreSandFraction:]',
        selectors={
                 0x582480: (15197068, 'getWeatherFractionForPos:atWorldTime:ignoreSandFraction:'),
        },
        imports={},
        ivars={},
        classes={},
        instructions=[(5776392, 'push {fp, lr}'), (5776516, 'adceq sp, sp, r0, lsr 13')],
        calls=[(5776492, 'bl loc.imp.objc_msgSend')],
        branches=[],
        semantics=('[World -[getWeatherFractionForPos:atWorldTime:]] (imp 0x00582408, 32w): getWeatherFractionForPos:atWorldTime: = the ignoreSandFraction: variant with flag 0 (sand suppression ON).\n'),
    ),
    dict(
        name='aq_18',
        method='World -[getWeatherFractionForPos:atWorldTime:ignoreSandFraction:]',
        types='f28@0:4{?=ii}8d16c24',
        start=5776520,
        end=5777940,
        disasm='disasm_worldtileloader_aq_18.txt',
        base_add=5776536,
        base_literal=5777936,
        boundary='ARM.exidx end 0x00582a14 (listing bound); next ObjC IMP 0x00582a50 World -[getWeatherFractionForPos:]',
        selectors={
                 0x5829d0: (15197072, 'getX:Y:Z:octaves:'),
                 0x5829f4: (15197076, 'sandFractionForPos:highRes:'),
        },
        imports={
                 0x5829cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5829c8: (17156060, 'OBJC_IVAR_$_World.customRules', 160),
                 0x5829d4: (17156148, 'OBJC_IVAR_$_World.weatherNoiseFunction', 656),
                 0x5829dc: (17155880, 'OBJC_IVAR_$_World.worldWidthMacro', 12),
                 0x5829e8: (17156104, 'OBJC_IVAR_$_World.worldTileLoader', 420),
                 0x5829ec: (17156024, 'OBJC_IVAR_$_World.clientTileLoader', 972),
                 0x582a0c: (17155920, 'OBJC_IVAR_$_World.noRainTimer', 940),
        },
        classes={},
        instructions=[(5776520, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5777936, 'adceq sp, sp, r4, asr r6')],
        calls=[(5776724, 'bl sym.imp.__aeabi_idiv'), (5776792, 'blx lr'), (5777092, 'bl loc.imp.objc_msgSend'), (5777180, 'bl loc.imp.objc_msgSend'), (5777300, 'bl sym.clamp_float__float__float_'), (5777756, 'bl sym.clamp_float__float__float_'), (5777804, 'bl sym.linearInterpolate_float__float__float_'), (5777832, 'bl sym.clamp_float__float__float_')],
        branches=[(5776832, 'beq', 5776952), (5776868, 'bne', 5776892), (5776888, 'b', 5776948), (5776924, 'bne', 5776944), (5776944, 'b', 5776948), (5776948, 'b', 5776952), (5776976, 'bne', 5777196), (5777016, 'beq', 5777108), (5777104, 'b', 5777192), (5777192, 'b', 5777196), (5777344, 'ble', 5777384), (5777380, 'b', 5777492), (5777396, 'ble', 5777464), (5777440, 'b', 5777488), (5777488, 'b', 5777492), (5777540, 'bpl', 5777816), (5777576, 'beq', 5777652), (5777612, 'beq', 5777816), (5777648, 'beq', 5777816)],
        semantics=('[World -[getWeatherFractionForPos:atWorldTime:ignoreSandFraction:]] (imp 0x00582488, 355w): the weather field - W = the 3D weatherNoiseFunction sample; + loader-type offsets (byte@8 == 3: +const; == 4: +5.0); - the altitude fade clamp((y-512-C)/C, 0, 1); x the noRainTimer ramp (W *= clamp((noRainTimer-d2)/d2, 0, 1)) when the timer is under d2 and the loader type is not 3/4; - the sand suppression with S = sandFractionForPos:highRes:0: W -= 3S when S > 0.2, -= S*S for 0 < S <= 0.2, -= S*C otherwise; clamped [-1, 2] unless ignoreSandFraction.\n'),
    ),
    dict(
        name='aq_19',
        method='World -[weatherFraction]',
        types='f8@0:4',
        start=6134448,
        end=6134520,
        disasm='disasm_worldtileloader_aq_19.txt',
        base_add=6134472,
        base_literal=6134516,
        boundary='ARM.exidx end 0x005d9b88; body trimmed at the next IMP 0x005d9af8 World -[rainFraction]',
        selectors={},
        imports={},
        ivars={
                 0x5d9af0: (17156544, 'OBJC_IVAR_$_World.weatherFraction', 916),
        },
        classes={},
        instructions=[(6134448, 'sub sp, sp, 0xc'), (6134516, 'adceq r6, r8, r4, lsr 32')],
        calls=[],
        branches=[],
        semantics=('[World -[weatherFraction]] (imp 0x005d9ab0, 18w): bare getter (weatherFraction).\n'),
    ),
    dict(
        name='aq_20',
        method='World -[rainFractionNotIncludingSnow]',
        types='f8@0:4',
        start=6134592,
        end=6134664,
        disasm='disasm_worldtileloader_aq_20.txt',
        base_add=6134616,
        base_literal=6134660,
        boundary='ARM.exidx end 0x005d9b88 (listing bound); next ObjC IMP 0x005d9b88 World -[dayColor]',
        selectors={},
        imports={},
        ivars={
                 0x5d9b80: (17156532, 'OBJC_IVAR_$_World.rainFractionNotIncludingSnow', 924),
        },
        classes={},
        instructions=[(6134592, 'sub sp, sp, 0xc'), (6134660, 'umlaleq r5, r8, r4, pc')],
        calls=[],
        branches=[],
        semantics=('[World -[rainFractionNotIncludingSnow]] (imp 0x005d9b40, 18w): bare getter (rainFractionNotIncludingSnow).\n'),
    ),
    dict(
        name='aq_21',
        method='World -[removeWaterTileAtPos:]',
        types='v16@0:4{?=ii}8',
        start=5735472,
        end=5736992,
        disasm='disasm_worldtileloader_aq_21.txt',
        base_add=5735488,
        base_literal=5736988,
        boundary='ARM.exidx end 0x00578a20 (listing bound); next ObjC IMP 0x00578a20 World -[updateTileGraphicForWorkbenchOfType:atPos:level:]',
        selectors={
                 0x5789d4: (15195644, 'sendDataToServer:reliable:'),
                 0x5789d8: (15195632, 'appendBytes:length:'),
                 0x5789dc: (15195552, 'dataWithBytes:length:'),
                 0x5789e4: (15196792, 'isAdmin'),
                 0x5789f4: (15196812, 'loadSnowSurfaceBlockAtPos:loadSnow:'),
                 0x5789fc: (15196816, 'loadSurfaceBlockAtPos:'),
                 0x578a10: (15196824, 'waterChangedAtPos:fullBlock:'),
                 0x578a18: (15196756, 'updateSunLightForTile:atPos:world:'),
        },
        imports={
                 0x5789d0: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x5789cc: (17155972, 'OBJC_IVAR_$_World.client', 960),
                 0x5789ec: (17155996, 'OBJC_IVAR_$_World.dynamicWorld', 416),
                 0x578a08: (17156340, 'OBJC_IVAR_$_World.macroTiles', 412),
        },
        classes={
                 0x5789e0: (15245284, 'OBJC_CLASS_$_NSMutableData'),
                 0x578a14: (15245460, 'OBJC_CLASS_$_WorldHelper'),
        },
        instructions=[(5735472, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (5736988, 'adceq r7, lr, ip, lsr 13')],
        calls=[(5735756, 'bl loc.imp.objc_msgSend'), (5735832, 'blx lr'), (5735876, 'blx ip'), (5735924, 'blx lr'), (5735940, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736036, 'bl sym.tileIsAir_Tile_'), (5736068, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736096, 'bl sym.tileIsSolid_Tile_'), (5736116, 'bl sym.tileIsWater_Tile_'), (5736220, 'bl loc.imp.objc_msgSend'), (5736240, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736268, 'bl sym.tileIsWater_Tile_'), (5736360, 'bl loc.imp.objc_msgSend'), (5736384, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736412, 'bl sym.tileIsWater_Tile_'), (5736504, 'bl loc.imp.objc_msgSend'), (5736528, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (5736556, 'bl sym.tileIsWater_Tile_'), (5736648, 'bl loc.imp.objc_msgSend'), (5736776, 'bl loc.imp.objc_msgSend'), (5736848, 'bl loc.imp.objc_msgSend'), (5736896, 'bl sym.reloadDrawBlockGeometryForTile_int__int__MacroTile__World__signed_char_')],
        branches=[(5735544, 'beq', 5735928), (5735960, 'bne', 5735968), (5735964, 'b', 5736900), (5736028, 'bne', 5736664), (5736048, 'beq', 5736664), (5736088, 'beq', 5736224), (5736108, 'bne', 5736148), (5736128, 'beq', 5736224), (5736144, 'ble', 5736224), (5736260, 'beq', 5736368), (5736280, 'beq', 5736368), (5736296, 'ble', 5736368), (5736364, 'b', 5736660), (5736404, 'beq', 5736512), (5736424, 'beq', 5736512), (5736440, 'ble', 5736512), (5736508, 'b', 5736656), (5736548, 'beq', 5736652), (5736568, 'beq', 5736652), (5736584, 'ble', 5736652), (5736652, 'b', 5736656), (5736656, 'b', 5736660), (5736660, 'b', 5736664)],
        semantics=('[World -[removeWaterTileAtPos:]] (imp 0x00578430, 380w): the water-tile removal - the admin network record (0x18 bytes via dataWithBytes:length:/appendBytes:) + sendDataToServer:reliable:; the tile rewrite (byte0 = 2, byte4 = 0); the column walk with tileIsAir/Solid/Water and the byte4>0/>1 gates detaching the surface attachments (loadSurfaceBlockAtPos:/loadSnowSurfaceBlockAtPos:loadSnow:) + the geometry reload.\n'),
    ),
    dict(
        name='aq_22',
        method='World -[waterMovedFrom:fromTile:to:toTile:amount:]',
        types='v36@0:4{?=ii}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}16{?=ii}20^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}28i32',
        start=6036956,
        end=6039440,
        disasm='disasm_worldtileloader_aq_22.txt',
        base_add=6036972,
        base_literal=6039436,
        boundary='ARM.exidx end 0x005c2790 (listing bound); next ObjC IMP 0x005c2790 World -[iapStarted]',
        selectors={
                 0x5c2778: (15195544, 'instance'),
                 0x5c2788: (15197032, 'addParticleAtPos:velocity:color:gravityType:life:scale:'),
        },
        imports={},
        ivars={
                 0x5c2750: (17156644, 'OBJC_IVAR_$_World.cameraMinXWorld', 3044),
                 0x5c2754: (17156640, 'OBJC_IVAR_$_World.cameraMaxXWorld', 3048),
                 0x5c2758: (17156636, 'OBJC_IVAR_$_World.cameraMinYWorld', 3052),
                 0x5c275c: (17156632, 'OBJC_IVAR_$_World.cameraMaxYWorld', 3056),
                 0x5c2764: (17156516, 'OBJC_IVAR_$_World.dayColor', 888),
                 0x5c277c: (17156704, 'OBJC_IVAR_$_World.particleRandomNumberIndex', 3024),
                 0x5c2780: (17156344, 'OBJC_IVAR_$_World.particleRandomNumbers', 1024),
        },
        classes={
                 0x5c2770: (15245388, 'OBJC_CLASS_$_ParticleEmitter'),
        },
        instructions=[(6036956, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (6039436, 'adceq sp, sb, r0, lsl 26')],
        calls=[(6037604, 'bl method.Vector.Vector_float__float__float_'), (6037612, 'bl method.Vector.operator_float__'), (6037688, 'bl method.Vector.operator_float__'), (6037720, 'bl method.Vector.operator_float__'), (6037776, 'bl method.Vector.operator_float__'), (6037808, 'bl method.Vector.operator_float__'), (6037864, 'bl method.Vector.operator_float__'), (6037916, 'bl method.Vector.Vector_float__float__float_'), (6037976, 'bl method.Vector.Vector_float__float__float__float_'), (6037984, 'bl method.Vector.operator_float__'), (6038000, 'bl method.Vector.operator_float__'), (6038016, 'bl method.Vector.operator_float__'), (6038048, 'bl method.Vector.Vector_float__float__float__float_'), (6038088, 'bl sym.Vector::operator_Vector_'), (6038248, 'bl method.Vector.Vector_float__float__float_'), (6038312, 'bl method.Vector.Vector_float__float__float_'), (6038348, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6038360, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (6038440, 'bl method.Vector.operator_float__'), (6038488, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (6038500, 'bl sym.tileIsAirWaterOrSnow_Tile_'), (6038580, 'bl method.Vector.operator_float__'), (6038608, 'bl method.Vector.operator_float__'), (6038644, 'bl method.Vector.operator_float__'), (6038676, 'bl method.Vector.operator_float__'), (6038712, 'bl method.Vector.operator_float__'), (6038768, 'bl sym.imp.__aeabi_idiv'), (6038820, 'bl loc.imp.objc_msgSend'), (6039064, 'bl method.Vector.Vector_float__float__float_'), (6039104, 'bl method.Vector.operator_Vector_'), (6039348, 'bl loc.imp.objc_msgSend')],
        branches=[(6037068, 'blt', 6037208), (6037108, 'bgt', 6037208), (6037148, 'blt', 6037208), (6037188, 'bgt', 6037208), (6037204, 'bgt', 6037212), (6037208, 'b', 6039368), (6037336, 'bpl', 6037352), (6037348, 'b', 6037360), (6037400, 'bpl', 6037420), (6037412, 'b', 6037428), (6037468, 'ble', 6037536), (6038372, 'beq', 6038472), (6038460, 'b', 6038604), (6038512, 'beq', 6038600), (6038600, 'b', 6038604), (6038636, 'ble', 6038672), (6038664, 'b', 6038736), (6038704, 'bpl', 6038732), (6038732, 'b', 6038736), (6038784, 'bge', 6039368), (6039364, 'b', 6038748)],
        semantics=('[World -[waterMovedFrom:fromTile:to:toTile:amount:]] (imp 0x005c1ddc, 621w): the water-move splash - camera-bounds culled; the light-channel tint (tile +0xe/+0x10/+0x12 /1024) into the splash color (0.808/0.854/0.886); the ParticleEmitter loop scaled by the move amount (/0x20 count) with the PRNG and tileIsAirWaterOrSnow neighbour tests, marker 0x64.\n'),
    ),
    dict(
        name='aq_23',
        method='World -[waterAnimationIndex]',
        types='i8@0:4',
        start=6137284,
        end=6137344,
        disasm='disasm_worldtileloader_aq_23.txt',
        base_add=6137308,
        base_literal=6137340,
        boundary='ARM.exidx end 0x005da63c; body trimmed at the next IMP 0x005da600 World -[hasJustTakenPhoto]',
        selectors={},
        imports={},
        ivars={
                 0x5da5f8: (17156572, 'OBJC_IVAR_$_World.waterAnimationIndex', 1008),
        },
        classes={},
        instructions=[(6137284, 'sub sp, sp, 8'), (6137340, 'adceq r5, r8, r0, lsl r5')],
        calls=[],
        branches=[],
        semantics=('[World -[waterAnimationIndex]] (imp 0x005da5c4, 15w): bare getter (waterAnimationIndex).\n'),
    ),
    dict(
        name='aq_24',
        method='WorldTileLoader -[recursivelyFlowOutWaterFromTile:atPos:]',
        types='v20@0:4^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}8{?=ii}12',
        start=8765972,
        end=8766744,
        disasm='disasm_worldtileloader_aq_24.txt',
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
        instructions=[(8765972, 'push {fp, lr}'), (8766740, 'addeq r3, r0, r8, asr 17')],
        calls=[(8766036, 'bl sym.makeIntpair_int__int_'), (8766088, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766236, 'bl loc.imp.objc_msgSend'), (8766256, 'bl sym.makeIntpair_int__int_'), (8766324, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766472, 'bl loc.imp.objc_msgSend'), (8766492, 'bl sym.makeIntpair_int__int_'), (8766560, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8766708, 'bl loc.imp.objc_msgSend')],
        branches=[(8766108, 'beq', 8766240), (8766124, 'bne', 8766240), (8766140, 'bne', 8766240), (8766344, 'beq', 8766476), (8766360, 'bne', 8766476), (8766376, 'bne', 8766476), (8766580, 'beq', 8766712), (8766596, 'bne', 8766712), (8766612, 'bne', 8766712)],
        semantics=('[WorldTileLoader -[recursivelyFlowOutWaterFromTile:atPos:]] (imp 0x0085c214, 193w): the recursive flow-out - reads the tile above (y-1) and the two side tiles (x+/-1); each tile matching (byte0 == 2 && byte2 == 1) is rewritten (byte0 = 3, byte4 = 0xff, byte7 = 0) and notifies (sel ffe2293c) - the still->flowing water conversion with recursion.\n'),
    ),
    dict(
        name='aq_25',
        method='DynamicWorld -[waterChangedAtPos:fullBlock:]',
        types='v20@0:4{?=ii}8c16',
        start=9308880,
        end=9311120,
        disasm='disasm_worldtileloader_aq_25.txt',
        base_add=9308896,
        base_literal=9311116,
        boundary='ARM.exidx end 0x008e1390 (listing bound); next ObjC IMP 0x008e1390 DynamicWorld -[dynamicWorldChangedAtPos:objectType:]',
        selectors={
                 0x8e1384: (15216036, 'macroTiles'),
        },
        imports={
                 0x8e1380: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8e1374: (17162420, 'OBJC_IVAR_$_DynamicWorld.waterChangedPositions', 6504),
                 0x8e1378: (17162340, 'OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions', 7320),
                 0x8e137c: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8e1388: (17162344, 'OBJC_IVAR_$_DynamicWorld.worldChangedSendUnreliablyMacroPositions', 6084),
        },
        classes={},
        instructions=[(9308880, 'push {r4, sl, fp, lr}'), (9311116, 'rsbseq pc, r7, ip')],
        calls=[(9309688, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_'), (9309776, 'blx r2'), (9309820, 'bl sym.reloadDrawBlockWaterForTile_int__int__MacroTile__World_'), (9309844, 'bl sym.imp.__aeabi_idiv'), (9309864, 'bl sym.imp.__aeabi_idiv'), (9309888, 'bl sym.makeIntpair_int__int_'), (9311072, 'bl method.void_std::__1::vector_intpair__std::__1::allocator_intpair___.__push_back_slow_path_intpair_const__intpair_const_')],
        branches=[(9308936, 'beq', 9309700), (9309224, 'beq', 9309368), (9309272, 'bne', 9309304), (9309288, 'bne', 9309304), (9309300, 'b', 9309368), (9309304, 'b', 9309308), (9309364, 'b', 9309052), (9309376, 'bne', 9309696), (9309468, 'beq', 9309680), (9309616, 'beq', 9309660), (9309676, 'b', 9309692), (9309692, 'b', 9309696), (9309696, 'b', 9309700), (9310176, 'beq', 9310320), (9310224, 'bne', 9310256), (9310240, 'bne', 9310256), (9310252, 'b', 9310320), (9310256, 'b', 9310260), (9310316, 'b', 9310004), (9310328, 'bne', 9311084), (9310608, 'beq', 9310752), (9310656, 'bne', 9310688), (9310672, 'bne', 9310688), (9310684, 'b', 9310752), (9310688, 'b', 9310692), (9310748, 'b', 9310436), (9310760, 'bne', 9311080), (9310852, 'beq', 9311064), (9311000, 'beq', 9311044), (9311060, 'b', 9311076), (9311076, 'b', 9311080), (9311080, 'b', 9311084)],
        semantics=('[DynamicWorld -[waterChangedAtPos:fullBlock:]] (imp 0x008e0ad0, 560w): the water-change bookkeeping - reloadDrawBlockWaterForTile for the tile macro cell; appends the pos to waterChangedPositions (deduped) and, unless the fullBlock gate fires, the worldChanged*MacroPositions pair (macro coords /32).\n'),
    ),
    dict(
        name='aq_26',
        method='SurfaceBlock -[subtractWater:fromOtherTile:atPos:]',
        types='v24@0:4i8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}12{?=ii}16',
        start=8462724,
        end=8462888,
        disasm='disasm_worldtileloader_aq_26.txt',
        base_add=8462816,
        base_literal=8462880,
        boundary='ARM.exidx end 0x00812228 (listing bound); next ObjC IMP 0x00812228 SurfaceBlock -[takeAnyWaterFromTileAtPos:tile:]',
        selectors={
                 0x812224: (15211960, 'loadSurfaceBlockAtPos:'),
        },
        imports={},
        ivars={
                 0x81221c: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(8462724, 'push {fp, lr}'), (8462884, 'invalid')],
        calls=[(8462864, 'bl loc.imp.objc_msgSend')],
        branches=[(8462776, 'bne', 8462784), (8462780, 'b', 8462868)],
        semantics=('[SurfaceBlock -[subtractWater:fromOtherTile:atPos:]] (imp 0x00812184, 41w): the water subtraction write - writes tile byte4 = amount and fires waterChangedAtPos:fullBlock: (skips at amount 0).\n'),
    ),
    dict(
        name='aq_27',
        method='SurfaceBlock -[takeAnyWaterFromTileAtPos:tile:]',
        types='c20@0:4{?=ii}8^{Tile=CCCCCCCCCCCCCSSSsCISSSSSQ[8S]}16',
        start=8462888,
        end=8465652,
        disasm='disasm_worldtileloader_aq_27.txt',
        base_add=8462904,
        base_literal=8465648,
        boundary='ARM.exidx end 0x00812cf4 (listing bound); next ObjC IMP 0x00812cf4 SurfaceBlock -[initWithWorld:dynamicWorld:atPosition:cache:]',
        selectors={
                 0x812cb0: (15211964, 'subtractWater:fromOtherTile:atPos:'),
                 0x812cc0: (15211968, 'waterChangedAtPos:fullBlock:'),
                 0x812cc8: (15211960, 'loadSurfaceBlockAtPos:'),
                 0x812cec: (15211972, 'waterMovedFrom:fromTile:to:toTile:amount:'),
        },
        imports={},
        ivars={
                 0x812ca4: (17155016, 'OBJC_IVAR_$_DynamicObject.needsRemoved', 48),
                 0x812ca8: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x812cac: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x812cb8: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
                 0x812cd4: (17161124, 'OBJC_IVAR_$_SurfaceBlock.removeNextFrame', 62),
                 0x812ce4: (17161128, 'OBJC_IVAR_$_SurfaceBlock.currentlyRequiresPhysicalBlock', 61),
        },
        classes={},
        instructions=[(8462888, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8465648, 'strheq sp, [r4], r4')],
        calls=[(8463028, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8463040, 'bl sym.tileIsWater_Tile_'), (8463516, 'bl loc.imp.objc_msgSend'), (8463632, 'bl loc.imp.objc_msgSend'), (8463708, 'bl sym.tileIsWater_Tile_'), (8463812, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8463824, 'bl sym.tileIsAirOrSnow_Tile_'), (8463924, 'bl sym.makeIntpair_int__int_'), (8463952, 'bl loc.imp.objc_msgSend'), (8464032, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8464044, 'bl sym.tileIsAirOrSnow_Tile_'), (8464144, 'bl sym.makeIntpair_int__int_'), (8464172, 'bl loc.imp.objc_msgSend'), (8464252, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8464264, 'bl sym.tileIsAirOrSnow_Tile_'), (8464364, 'bl sym.makeIntpair_int__int_'), (8464392, 'bl loc.imp.objc_msgSend'), (8464404, 'bl sym.tileIsWater_Tile_'), (8464560, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8464572, 'bl sym.tileIsAirOrSnow_Tile_'), (8464672, 'bl sym.makeIntpair_int__int_'), (8464700, 'bl loc.imp.objc_msgSend'), (8464780, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8464792, 'bl sym.tileIsAirOrSnow_Tile_'), (8464892, 'bl sym.makeIntpair_int__int_'), (8464920, 'bl loc.imp.objc_msgSend'), (8465000, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8465012, 'bl sym.tileIsAirOrSnow_Tile_'), (8465112, 'bl sym.makeIntpair_int__int_'), (8465140, 'bl loc.imp.objc_msgSend'), (8465340, 'bl loc.imp.objc_msgSend'), (8465440, 'bl loc.imp.objc_msgSend'), (8465508, 'bl loc.imp.objc_msgSend')],
        branches=[(8462964, 'beq', 8462980), (8462976, 'b', 8465560), (8463052, 'beq', 8465552), (8463116, 'ble', 8463208), (8463164, 'bge', 8463180), (8463176, 'b', 8463188), (8463204, 'b', 8463312), (8463264, 'bge', 8463280), (8463276, 'b', 8463288), (8463320, 'ble', 8465548), (8463380, 'bpl', 8463408), (8463400, 'b', 8463416), (8463448, 'ble', 8465544), (8463532, 'beq', 8463636), (8463656, 'blt', 8464400), (8463720, 'bne', 8463736), (8463836, 'beq', 8463956), (8464056, 'beq', 8464176), (8464276, 'beq', 8464396), (8464396, 'b', 8465152), (8464416, 'bne', 8464448), (8464444, 'b', 8464468), (8464480, 'ble', 8465148), (8464584, 'beq', 8464704), (8464804, 'beq', 8464924), (8465024, 'beq', 8465144), (8465144, 'b', 8465148), (8465148, 'b', 8465152), (8465540, 'b', 8465560), (8465544, 'b', 8465548), (8465548, 'b', 8465552)],
        semantics=('[SurfaceBlock -[takeAnyWaterFromTileAtPos:tile:]] (imp 0x00812228, 691w): the surface water pump - takes up to 0xff units (level reads + min), rewrites the source (byte0 = 3, byte4 = 0xff), spreads into the three air-or-snow neighbours (tileIsAirOrSnow x3 + the fillTile-family notify), the byte4>1 updates, removeNextFrame/needsRemoved handling; 33 calls.\n'),
    ),
    dict(
        name='aq_28',
        method='SurfaceBlock -[removeIfFloatingAndEmptyOfWater]',
        types='v8@0:4',
        start=8471720,
        end=8472760,
        disasm='disasm_worldtileloader_aq_28.txt',
        base_add=8471736,
        base_literal=8472756,
        boundary='ARM.exidx end 0x008148b8 (listing bound); next ObjC IMP 0x008148b8 SurfaceBlock -[requiresPhysicalBlock]',
        selectors={
                 0x8148a0: (15212016, 'isClient'),
                 0x8148a8: (15211988, 'setNeedsRemoved:'),
                 0x8148b0: (15212020, 'removeWaterTileAtPos:'),
        },
        imports={
                 0x81489c: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x814890: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4),
                 0x814894: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16),
                 0x814898: (17161140, 'OBJC_IVAR_$_SurfaceBlock.removeNextFrameEmpty', 63),
                 0x8148a4: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        classes={},
        instructions=[(8471720, 'push {r4, r5, fp, lr}'), (8472756, 'addeq fp, r4, r4, lsr r6')],
        calls=[(8471820, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8471832, 'bl sym.tileIsWater_Tile_'), (8471940, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8471968, 'bl sym.tileIsWater_Tile_'), (8472076, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8472104, 'bl sym.tileIsWater_Tile_'), (8472212, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'), (8472240, 'bl sym.tileIsWater_Tile_'), (8472392, 'blx lr'), (8472428, 'blx r3'), (8472528, 'bl loc.imp.objc_msgSend')],
        branches=[(8471844, 'beq', 8471864), (8471860, 'bne', 8472680), (8471960, 'beq', 8472644), (8471980, 'beq', 8472000), (8471996, 'bne', 8472644), (8472096, 'beq', 8472608), (8472116, 'beq', 8472136), (8472132, 'bgt', 8472608), (8472232, 'beq', 8472572), (8472252, 'beq', 8472272), (8472268, 'bgt', 8472572), (8472304, 'beq', 8472536), (8472440, 'bne', 8472532), (8472532, 'b', 8472568), (8472568, 'b', 8472604), (8472604, 'b', 8472640), (8472640, 'b', 8472676), (8472676, 'b', 8472712)],
        semantics=('[SurfaceBlock -[removeIfFloatingAndEmptyOfWater]] (imp 0x008144a8, 260w): the floating cleanup - when the support is gone: removeWaterTileAtPos: + setNeedsRemoved: (removeNextFrameEmpty); 18 branches.\n'),
    ),
    dict(
        name='aq_29',
        method='DynamicObject -[waterContentChanged:]',
        types='v12@0:4^{vector<intpair, std::__1::allocator<intpair> >=^{?}^{?}{__compressed_pair<intpair *, std::__1::allocator<intpair> >=^{?}}}8',
        start=8631800,
        end=8631884,
        disasm='disasm_worldtileloader_aq_29.txt',
        base_add=8631816,
        base_literal=8631880,
        boundary='ARM.exidx end 0x0083b64c (listing bound); next ObjC IMP 0x0083b64c DynamicObject -[creationNetDataForClient:]',
        selectors={
                 0x83b644: (15213012, 'worldChanged:'),
        },
        imports={
                 0x83b640: (17151904, 'objc_msgSend'),
        },
        ivars={},
        classes={},
        instructions=[(8631800, 'push {fp, lr}'), (8631880, 'addeq r4, r2, r4, ror 9')],
        calls=[(8631860, 'blx ip')],
        branches=[],
        semantics=('[DynamicObject -[waterContentChanged:]] (imp 0x0083b5f8, 21w): the generic water-content reaction - forwards to worldChanged:.\n'),
    ),
    dict(
        name='aq_30',
        method='DynamicWorld -[placeBoatInWaterAtPos:saveDict:placedByClient:]',
        types='v24@0:4{?=ii}8@16@20',
        start=9363952,
        end=9364456,
        disasm='disasm_worldtileloader_aq_30.txt',
        base_add=9363968,
        base_literal=9364452,
        boundary='ARM.exidx end 0x008ee3e8 (listing bound); next ObjC IMP 0x008ee3e8 DynamicWorld -[checkForBoatUnderTap:]',
        selectors={
                 0x8ee3bc: (15215804, 'alloc'),
                 0x8ee3c8: (15216980, 'initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:'),
                 0x8ee3d0: (15216020, 'sendNetDataIfNeededForObject:isCreation:'),
                 0x8ee3d4: (15216168, 'objectType'),
                 0x8ee3e0: (15216160, 'uniqueID'),
        },
        imports={
                 0x8ee3cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x8ee3c0: (17162200, 'OBJC_IVAR_$_DynamicWorld.world', 4),
                 0x8ee3c4: (17162232, 'OBJC_IVAR_$_DynamicWorld.cache', 7336),
                 0x8ee3dc: (17162308, 'OBJC_IVAR_$_DynamicWorld.dynamicObjectsToAdd', 840),
        },
        classes={
                 0x8ee3b4: (15248000, 'OBJC_CLASS_$_Boat'),
        },
        instructions=[(9363952, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (9364452, 'rsbseq r1, r7, ip, ror 17')],
        calls=[(9364048, 'bl loc.imp.objc_msgSend'), (9364172, 'bl loc.imp.objc_msgSend'), (9364236, 'bl loc.imp.objc_msgSend'), (9364296, 'bl loc.imp.objc_msgSend'), (9364316, 'bl method.std::__1::map_unsigned_long_long__DynamicObject__std::__1::less_unsigned_long_long___std::__1::allocator_std::__1::pair_unsigned_long_long_const__DynamicObject_____.operator___unsigned_long_long_'), (9364392, 'blx r4')],
        branches=[(9364192, 'beq', 9364396)],
        semantics=('[DynamicWorld -[placeBoatInWaterAtPos:saveDict:placedByClient:]] (imp 0x008ee1f0, 126w): the boat placement - alloc/init the boat (initWithWorld:dynamicWorld:atPosition:cache:saveDict:placedByClient:) into dynamicObjectsToAdd + sendNetDataIfNeededForObject:isCreation:.\n'),
    ),
    dict(
        name='aq_31',
        method='Blockhead -[environmentTemperature]',
        types='f8@0:4',
        start=12110392,
        end=12110456,
        disasm='disasm_worldtileloader_aq_31.txt',
        base_add=12110416,
        base_literal=12110452,
        boundary='ARM.exidx end 0x00b8cc0c; body trimmed at the next IMP 0x00b8ca78 Blockhead -[environmentExposure]',
        selectors={},
        imports={},
        ivars={
                 0xb8ca70: (17166416, 'OBJC_IVAR_$_Blockhead.state', 56),
        },
        classes={},
        instructions=[(12110392, 'sub sp, sp, 8'), (12110452, 'umaaleq r3, sp, ip, r0')],
        calls=[],
        branches=[],
        semantics=('[Blockhead -[environmentTemperature]] (imp 0x00b8ca38, 16w): returns the float field at +0x3c (the environment temperature).\n'),
    ),
    dict(
        name='aq_32',
        method='Blockhead -[currentTemperature]',
        types='f8@0:4',
        start=13149504,
        end=13149576,
        disasm='disasm_worldtileloader_aq_32.txt',
        base_add=13149528,
        base_literal=13149572,
        boundary='ARM.exidx end 0x00c8a588 (listing bound); next ObjC IMP 0x00c8a588 Blockhead -[cancelSimulateDueToCollapse]',
        selectors={},
        imports={},
        ivars={
                 0xc8a580: (17166988, 'OBJC_IVAR_$_Blockhead.currentTemperature', 636),
        },
        classes={},
        instructions=[(13149504, 'sub sp, sp, 0xc'), (13149572, 'mlaseq sp, r4, r5, r5')],
        calls=[],
        branches=[],
        semantics=('[Blockhead -[currentTemperature]] (imp 0x00c8a540, 18w): bare getter (currentTemperature).\n'),
    ),
    dict(
        name='aq_33',
        method='ChilliPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=7053748,
        end=7053776,
        disasm='disasm_worldtileloader_aq_33.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ba1d0 (listing bound); next ObjC IMP 0x006ba1d0 ChilliPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7053748, 'sub sp, sp, 8'), (7053772, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[ChilliPlant -[minAllowedTemperature]] (imp 0x006ba1b4, 7w): returns -1 (ChilliPlant).\n'),
    ),
    dict(
        name='aq_34',
        method='WheatPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=7148604,
        end=7148632,
        disasm='disasm_worldtileloader_aq_34.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006d1458 (listing bound); next ObjC IMP 0x006d1458 WheatPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7148604, 'sub sp, sp, 8'), (7148628, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[WheatPlant -[minAllowedTemperature]] (imp 0x006d143c, 7w): returns -15 (WheatPlant).\n'),
    ),
    dict(
        name='aq_35',
        method='TomatoPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=7339016,
        end=7339044,
        disasm='disasm_worldtileloader_aq_35.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x006ffc24 (listing bound); next ObjC IMP 0x006ffc24 TomatoPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7339016, 'sub sp, sp, 8'), (7339040, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[TomatoPlant -[minAllowedTemperature]] (imp 0x006ffc08, 7w): returns -2 (TomatoPlant).\n'),
    ),
    dict(
        name='aq_36',
        method='CarrotPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=7608696,
        end=7608724,
        disasm='disasm_worldtileloader_aq_36.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00741994 (listing bound); next ObjC IMP 0x00741994 CarrotPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7608696, 'sub sp, sp, 8'), (7608720, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[CarrotPlant -[minAllowedTemperature]] (imp 0x00741978, 7w): returns -20 (CarrotPlant).\n'),
    ),
    dict(
        name='aq_37',
        method='FlaxPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=7802156,
        end=7802184,
        disasm='disasm_worldtileloader_aq_37.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00770d48 (listing bound); next ObjC IMP 0x00770d48 FlaxPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(7802156, 'sub sp, sp, 8'), (7802180, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[FlaxPlant -[minAllowedTemperature]] (imp 0x00770d2c, 7w): returns -20 (FlaxPlant).\n'),
    ),
    dict(
        name='aq_38',
        method='SunflowerPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=10208752,
        end=10208780,
        disasm='disasm_worldtileloader_aq_38.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x009bc60c (listing bound); next ObjC IMP 0x009bc60c SunflowerPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10208752, 'sub sp, sp, 8'), (10208776, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[SunflowerPlant -[minAllowedTemperature]] (imp 0x009bc5f0, 7w): returns -5 (SunflowerPlant).\n'),
    ),
    dict(
        name='aq_39',
        method='NormalPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=10900820,
        end=10900848,
        disasm='disasm_worldtileloader_aq_39.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00a655c4; body trimmed at the next IMP 0x00a65570 NormalPlant -[seedItemType]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(10900820, 'sub sp, sp, 8'), (10900844, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NormalPlant -[minAllowedTemperature]] (imp 0x00a65554, 7w): returns -20 (NormalPlant).\n'),
    ),
    dict(
        name='aq_40',
        method='CornPlant -[minAllowedTemperature]',
        types='i8@0:4',
        start=11862600,
        end=11862628,
        disasm='disasm_worldtileloader_aq_40.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00b50264 (listing bound); next ObjC IMP 0x00b50264 CornPlant -[floweringSeason:]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(11862600, 'sub sp, sp, 8'), (11862624, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[CornPlant -[minAllowedTemperature]] (imp 0x00b50248, 7w): returns -10 (CornPlant).\n'),
    ),
    dict(
        name='aq_41',
        method='NPC -[suffersDamageAtHighTemperatures]',
        types='c8@0:4',
        start=6621768,
        end=6621796,
        disasm='disasm_worldtileloader_aq_41.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00650b10; body trimmed at the next IMP 0x00650a64 NPC -[ridableWhenTamed]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(6621768, 'sub sp, sp, 8'), (6621792, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[NPC -[suffersDamageAtHighTemperatures]] (imp 0x00650a48, 7w): returns 1 (true) - NPCs take damage at high temperatures.\n'),
    ),
    dict(
        name='aq_42',
        method='CaveTroll -[suffersDamageAtHighTemperatures]',
        types='c8@0:4',
        start=14176816,
        end=14176844,
        disasm='disasm_worldtileloader_aq_42.txt',
        base_add=None,
        base_literal=None,
        boundary='ARM.exidx end 0x00d85268; body trimmed at the next IMP 0x00d8524c CaveTroll -[riderDPadShouldGiveDiscreteValues]',
        selectors={},
        imports={},
        ivars={},
        classes={},
        instructions=[(14176816, 'sub sp, sp, 8'), (14176840, 'bx lr')],
        calls=[],
        branches=[],
        semantics=('[CaveTroll -[suffersDamageAtHighTemperatures]] (imp 0x00d85230, 7w): returns 0 (false) - the CaveTroll does not.\n'),
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
        'batch': 'Weather + water + temperature (E119): the Weather class, the weather field chain, the water flow system and the temperature table; 43 bodies',
        'claim': ('the weather/water/temperature substrate; six Weather giants are census-grade and the sound/noise/sand-fraction contracts are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'waterline.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale waterline.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
