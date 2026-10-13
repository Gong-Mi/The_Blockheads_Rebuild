#!/usr/bin/env python3
"""Hash-gated recovery of the electricity consumers/producers closure.

11 bodies, 1400 instruction words total, from the pinned original libApplication.so (1.7.6, armeabi-v7a):
Workbench combinedLightForSolarPanelWithFullSunlight (182w), combinedLightForSolarPanel (306w), availableElectricity (15w),
conductsElectricity (47w), subtractElectricty: (242w), generatesElectricity (34w), usesStoresConductsOrProducesElectricity (133w),
requiresElectricty (38w); DynamicWorld findAndSubtractAllPowerUpTo:forUser: forwarder (33w); ParticleEmitter
addElectricityParticleWithPath:size: (93w) + doAddElectricityParticleWithPath:size: (277w).
Every instruction word is re-verified; tool refuses to emit on drift.
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
    'bl 0xae3574': 0X00AE3574,
    'bl loc.imp.objc_msgSend': 0X001C281C,
    'bl method.Vector.Vector_float__float__float_': 0X004B52AC,
    'bl method.std::__1::enable_if___is_forward_iterator_ElectrictyParticlePathIndex_::value__void_::type_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.assign_ElectrictyParticlePathIndex__ElectrictyParticlePathIndex__ElectrictyParticlePathIndex_': 0X00D8CD3C,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__': 0X005CB054,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.at_unsigned_long_': 0X00D87B04,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_': 0X005CAEF8,
    'bl sym.imp._Unwind_Resume': 0X001C29C0,
    'bl sym.imp.__aeabi_idiv': 0X001C3728,
    'bl sym.imp.__modsi3': 0X001C3020,
    'bl sym.imp.__wrap_powf': 0X001C3F98,
    'bl sym.makeIntpair_int__int_': 0X004B49FC,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0X00A16E68,
    'bl sym.tileIsAirOrSnow_Tile_': 0X00A12760,
    'bl sym.tileIsTree_Tile_': 0X00A13214,
}

SPECS = [
    dict(
        name='wb_fullsun',
        method='Workbench -[combinedLightForSolarPanelWithFullSunlight]',
        types='f8@0:4',
        start=11461128,
        end=11461856,
        disasm='disasm_workbench_combinedlightfullsun.txt',
        base_add=11461144,
        base_literal=11461888,
        boundary='body 0x00aee208..0x00aee4e0; trailing literal pool 0x00aee4e0..0x00aee508 excluded (own ARM.exidx bound)',
        selectors={11461872: (15228680, 'macroTiles')},
        imports={11461868: (17151904, 'objc_msgSend')},
        ivars={11461864: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 11461876: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={},
        instructions=[(11461128, 'push {r4, sl, fp, lr}'), (11461320, 'bl sym.tileIsAirOrSnow_Tile_'), (11461344, 'cmp r0, 0x2e'), (11461428, 'bl sym.imp.__wrap_powf'), (11461632, 'movw r0, 0x7d0'), (11461772, 'bl sym.tileIsTree_Tile_'), (11461852, 'pop {r4, sl, fp, pc}')],
        semantics=('Solar-panel light input with full sunlight. (float, no args). world@4 -> macroTiles lookup -> tileAtWorldPosition(pos.x+1, pos.y, macroTile, world); gates: !tileIsAirOrSnow(tile) or tile[3]==0x2e -> return 0.0. Light = powf(tile[7]/255.0, 4.0); A = clamp(powf, 0, 1); B = min(sum16(tile+0xe, +0x10, +0x12), 2000.0) (the L2a light-word accumulators); total = A + B * 1e-4 (f64 const 0x3f1a36e2eb1c432d); tileIsTree(tile) -> total /= 2.0; return.'),
        calls=[(11461264, 'blx ip'), (11461308, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11461320, 'bl sym.tileIsAirOrSnow_Tile_'), (11461428, 'bl sym.imp.__wrap_powf'), (11461772, 'bl sym.tileIsTree_Tile_')],
        branches=[(11461332, 'beq', 11461824), (11461348, 'beq', 11461824), (11461524, 'bpl', 11461540), (11461536, 'b', 11461548), (11461604, 'bpl', 11461620), (11461616, 'b', 11461628), (11461684, 'bpl', 11461700), (11461696, 'b', 11461716), (11461784, 'beq', 11461812), (11461820, 'b', 11461840)],
    ),
    dict(
        name='wb_solarpanel',
        method='Workbench -[combinedLightForSolarPanel]',
        types='f8@0:4',
        start=11461896,
        end=11463120,
        disasm='disasm_workbench_combinedlightsolarpanel.txt',
        base_add=11461912,
        base_literal=11463184,
        boundary='body 0x00aee508..0x00aee9d0; trailing literal pool 0x00aee9d0..0x00aeea18 excluded (own ARM.exidx bound)',
        selectors={11463152: (15228680, 'macroTiles'), 11463168: (15229076, 'getDayNightFractionForX:atWorldTime:'), 11463172: (15228756, 'worldTime'), 11463180: (15229080, 'getWeatherFractionForPos:')},
        imports={11463148: (17151904, 'objc_msgSend')},
        ivars={11463144: (17154964, 'OBJC_IVAR_$_DynamicObject.world', 4), 11463156: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16)},
        classes={},
        instructions=[(11461896, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (11462092, 'bl sym.tileIsAirOrSnow_Tile_'), (11462116, 'cmp r0, 0x2e'), (11462200, 'bl sym.imp.__wrap_powf'), (11462216, 'movw r1, 6'), (11462896, 'movw r0, 0x7d0'), (11463036, 'bl sym.tileIsTree_Tile_'), (11463116, 'pop {r4, r5, r6, r7, r8, sl, fp, pc}')],
        semantics=('Solar-panel light input with live daylight. Same skeleton as combinedLightForSolarPanelWithFullSunlight, but daylight is measured: day = [world getDayNightFractionForX:(pos.x+1) atWorldTime:[world worldTime]]; light = clamp((day - 0.23f) * 4.0, 0, 1) * powf(tile[7]/255.0, 4.0); weather = [world getWeatherFractionForPos:pos]; when weather > 0 -> light *= (1 - min(weather, 0.2) * 4); clamp light >= 0; total = light + min(sum16(tile+0xe, +0x10, +0x12), 2000.0) * 1e-4; tileIsTree(tile) -> total /= 2.0; return.'),
        calls=[(11462036, 'blx ip'), (11462080, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'), (11462092, 'bl sym.tileIsAirOrSnow_Tile_'), (11462200, 'bl sym.imp.__wrap_powf'), (11462428, 'blx r2'), (11462468, 'blx r3'), (11462668, 'bl loc.imp.objc_msgSend'), (11463036, 'bl sym.tileIsTree_Tile_')],
        branches=[(11462104, 'beq', 11463088), (11462120, 'beq', 11463088), (11462544, 'bpl', 11462560), (11462556, 'b', 11462568), (11462696, 'ble', 11462828), (11462736, 'bpl', 11462756), (11462752, 'b', 11462764), (11462868, 'bpl', 11462884), (11462880, 'b', 11462892), (11462948, 'bpl', 11462964), (11462960, 'b', 11462980), (11463048, 'beq', 11463076), (11463084, 'b', 11463104)],
    ),
    dict(
        name='wb_avail',
        method='Workbench -[availableElectricity]',
        types='S8@0:4',
        start=11539076,
        end=11539136,
        disasm='disasm_workbench_availableelectricity.txt',
        base_add=11539084,
        base_literal=11539132,
        boundary='consecutive IMPs: [conductsElectricity] follows at 0x00b012c0',
        selectors={},
        imports={},
        ivars={11539128: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222)},
        classes={},
        instructions=[(11539076, 'sub sp, sp, 8'), (11539116, 'ldrh r0, [r0]'), (11539124, 'bx lr')],
        semantics=('(uint16 getter) return *(uint16 *)((char *)self + 222) - Workbench.availableElectricity@222; pure leaf read (sub sp/add sp/bx lr).'),
        calls=[],
        branches=[],
    ),
    dict(
        name='wb_conducts',
        method='Workbench -[conductsElectricity]',
        types='c8@0:4',
        start=11539136,
        end=11539324,
        disasm='disasm_workbench_conductselectricity.txt',
        base_add=11539152,
        base_literal=11539320,
        boundary='consecutive IMPs: [subtractElectricty:] follows at 0x00b0137c',
        selectors={11539312: (15229284, 'isStorageDevice'), 11539316: (15229288, 'generatesElectricity')},
        imports={11539308: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(11539136, 'push {fp, lr}'), (11539200, 'blx ip'), (11539264, 'blx r2'), (11539304, 'pop {fp, pc}')],
        semantics=('return [self isStorageDevice] || [self generatesElectricity]; short-circuit through two objc_msgSend blx trampolines + sxtb normalisation (the second call only runs when the first is false).'),
        calls=[(11539200, 'blx ip'), (11539264, 'blx r2')],
        branches=[(11539220, 'bne', 11539288)],
    ),
    dict(
        name='wb_subtract',
        method='Workbench -[subtractElectricty:]',
        types='c12@0:4S8',
        start=11539324,
        end=11540292,
        disasm='disasm_workbench_subtractelectricty.txt',
        base_add=11539340,
        base_literal=11540300,
        boundary='body 0x00b0137c..0x00b01744; tail pool 0x00b01744..0x00b01750 excluded (float consts 0.1 / 0.000583 / literal)',
        selectors={11540260: (15228872, 'objectType'), 11540264: (15228876, 'dynamicWorldChangedAtPos:objectType:'), 11540284: (15229088, 'updateHasFuel')},
        imports={11540280: (17151904, 'objc_msgSend')},
        ivars={11540240: (17165380, 'OBJC_IVAR_$_Workbench.availableElectricity', 222), 11540248: (17155020, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49), 11540252: (17154984, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 11540256: (17154960, 'OBJC_IVAR_$_DynamicObject.pos', 16), 11540268: (17165332, 'OBJC_IVAR_$_Workbench.type', 120), 11540272: (17165376, 'OBJC_IVAR_$_Workbench.fuelFraction', 212), 11540276: (17165468, 'OBJC_IVAR_$_Workbench.particleCreateTimerSteamEngine', 280)},
        classes={},
        instructions=[(11539324, 'push {r4, r5, r6, sl, fp, lr}'), (11539548, 'bl loc.imp.objc_msgSend'), (11539692, 'cmp r0, 0x64'), (11539884, 'add r3, r3, 0xa'), (11540236, 'pop {r4, r5, r6, sl, fp, pc}')],
        semantics=('(uint16 amount) -> BOOL deducted. If amount > availableElectricity@222 -> skip deduction (flag stays 0). Else available -= amount (strh), flag := 1, updateNeedsToBeSent@49 := 1; re-broadcast through the objectType / dynamicWorldChangedAtPos:objectType: pair. Then when Workbench.type@120 == 0xf: steam regeneration loop while fuelFraction@212 > 0.0f && available < 100 (0x64): fuelFraction -= 0.000583f (0x3a18d478); available += 10; particleCreateTimerSteamEngine@280 += 0.1f (0x3dcccccd); after the loop clamp particleCreateTimerSteamEngine <= 4.0f; tail: objectType/dynamicWorldChangedAtPos: pair + updateHasFuel + updateNeedsToBeSent@49 := 1. Return the flag byte [fp,-0x1b] (ldrsb).'),
        calls=[(11539548, 'bl loc.imp.objc_msgSend'), (11539584, 'bl loc.imp.objc_msgSend'), (11540140, 'bl loc.imp.objc_msgSend'), (11540176, 'bl loc.imp.objc_msgSend'), (11540220, 'blx ip')],
        branches=[(11539400, 'bgt', 11539588), (11539620, 'bne', 11540228), (11539660, 'ble', 11540224), (11539696, 'bge', 11540224), (11539700, 'b', 11539704), (11539748, 'ble', 11539796), (11539804, 'beq', 11539920), (11539916, 'b', 11539704), (11539968, 'ble', 11540012), (11540224, 'b', 11540228)],
    ),
    dict(
        name='wb_generates',
        method='Workbench -[generatesElectricity]',
        types='c8@0:4',
        start=11541540,
        end=11541676,
        disasm='disasm_workbench_generateselectricity.txt',
        base_add=11541548,
        base_literal=11541672,
        boundary='body trimmed to next IMP [usesStoresConductsOrProducesElectricity] 0x00b01cac (exidx over-covered 0x00b01ec0)',
        selectors={},
        imports={},
        ivars={11541668: (17165332, 'OBJC_IVAR_$_Workbench.type', 120)},
        classes={},
        instructions=[(11541540, 'sub sp, sp, 0x10'), (11541588, 'cmp r0, 0xf'), (11541632, 'cmp r0, 0x14'), (11541664, 'bx lr')],
        semantics=('return Workbench.type@120 == 0xf || type == 0x14 (two compares; moveq).'),
        calls=[],
        branches=[(11541600, 'beq', 11541648)],
    ),
    dict(
        name='wb_usesstores',
        method='Workbench -[usesStoresConductsOrProducesElectricity]',
        types='c8@0:4',
        start=11541676,
        end=11542208,
        disasm='disasm_workbench_usesstoresconductsorproduces.txt',
        base_add=11541684,
        base_literal=11542204,
        boundary='consecutive IMPs: [energyFraction] follows at 0x00b01ec0',
        selectors={},
        imports={},
        ivars={11542200: (17165332, 'OBJC_IVAR_$_Workbench.type', 120)},
        classes={},
        instructions=[(11541676, 'sub sp, sp, 0x10'), (11541860, 'cmp r1, 0x11'), (11542164, 'cmp r0, 0x1e'), (11542196, 'bx lr')],
        semantics=('return type in {0xf, 0x14, 0x15, 0x11, 0x10, 0x1b, 0x12, 0x13, 0x1a, 0x1d, 0x1e} - an 11-compare whitelist over Workbench.type@120 (each match returns 1; the final 0x1e compare stores moveq).'),
        calls=[],
        branches=[(11541736, 'beq', 11542180), (11541780, 'beq', 11542180), (11541824, 'beq', 11542180), (11541868, 'beq', 11542180), (11541912, 'beq', 11542180), (11541956, 'beq', 11542180), (11542000, 'beq', 11542180), (11542044, 'beq', 11542180), (11542088, 'beq', 11542180), (11542132, 'beq', 11542180)],
    ),
    dict(
        name='wb_requires',
        method='Workbench -[requiresElectricty]',
        types='c8@0:4',
        start=11581392,
        end=11581544,
        disasm='disasm_workbench_requireselectricty.txt',
        base_add=11581408,
        base_literal=11581540,
        boundary='body trimmed to next IMP [upgradeName] 0x00b0b868 (exidx over-covered 0x00b0bca4)',
        selectors={11581532: (15229320, 'level'), 11581536: (15229316, 'type')},
        imports={11581528: (17151904, 'objc_msgSend')},
        ivars={},
        classes={},
        instructions=[(11581392, 'push {fp, lr}'), (11581460, 'blx r3'), (11581524, 'pop {fp, pc}')],
        semantics=("return H([self type], [self level]) - two objc_msgSend blx trampolines ('type' then 'level') whose results feed the shared helper bl 0xae3574 (internals out of body); sxtb result."),
        calls=[(11581460, 'blx r3'), (11581492, 'blx r3'), (11581512, 'bl 0xae3574')],
        branches=[],
    ),
    dict(
        name='dw_findsub',
        method='DynamicWorld -[findAndSubtractAllPowerUpTo:forUser:]',
        types='i16@0:4S8@12',
        start=9428712,
        end=9428844,
        disasm='disasm_dynamicworld_findandsubtractpower.txt',
        base_add=9428728,
        base_literal=9428840,
        boundary='consecutive IMPs: [pathUsers] follows at 0x008fdf6c',
        selectors={9428832: (15217184, 'findAndSubtractAllPowerUpTo:forUser:')},
        imports={9428828: (17151904, 'objc_msgSend')},
        ivars={9428836: (17162272, 'OBJC_IVAR_$_DynamicWorld.wirePathCreator', 9496)},
        classes={},
        instructions=[(9428712, 'push {r4, r5, fp, lr}'), (9428816, 'blx lr'), (9428812, 'uxth r2, r2'), (9428824, 'pop {r4, r5, fp, pc}')],
        semantics=('Forwarder: return [self.wirePathCreator@9496 findAndSubtractAllPowerUpTo:upTo forUser:user] - one objc_msgSend (uxth on upTo); the engine itself is the WirePathCreator body 0x00db2690 (E2 batch).'),
        calls=[(9428816, 'blx lr')],
        branches=[],
    ),
    dict(
        name='pe_add',
        method='ParticleEmitter -[addElectricityParticleWithPath:size:]',
        types='v24@0:4{vector<ElectrictyParticlePathIndex, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}^{ElectrictyParticlePathIndex}{__compressed_pair<ElectrictyParticlePathIndex *, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}}}8f20',
        start=14185788,
        end=14186160,
        disasm='disasm_particleemitter_addelectricityparticle.txt',
        base_add=14185804,
        base_literal=14186156,
        boundary='consecutive IMPs: [doAddElectricityParticleWithPath:size:] follows at 0x00d876b0',
        selectors={14186140: (15240444, 'sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:'), 14186148: (15240448, 'doAddElectricityParticleWithPath:size:')},
        imports={},
        ivars={14186132: (17168960, 'OBJC_IVAR_$_ParticleEmitter.world', 4), 14186144: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96)},
        classes={},
        instructions=[(14185788, 'push {fp, lr}'), (14185884, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (14185924, 'bl loc.imp.objc_msgSend'), (14186096, 'pop {fp, pc}')],
        semantics=('if [self.world@4 sendNetDataForElectricityParticlePathIfRequired:(vector copy) size:size ignoreClient:0]; then when !stopAllParticles@96 -> [self doAddElectricityParticleWithPath:(vector copy) size:size]. Two vector copies on the stack; ~vector x3 unwind paths + _Unwind_Resume (0x00d87690).'),
        calls=[(14185884, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (14185924, 'bl loc.imp.objc_msgSend'), (14185936, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186000, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186040, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'), (14186072, 'bl loc.imp.objc_msgSend'), (14186084, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186116, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'), (14186128, 'bl sym.imp._Unwind_Resume')],
        branches=[(14185928, 'b', 14185932), (14185976, 'beq', 14186012), (14185980, 'b', 14186092), (14186008, 'b', 14186124), (14186076, 'b', 14186080)],
    ),
    dict(
        name='pe_doadd',
        method='ParticleEmitter -[doAddElectricityParticleWithPath:size:]',
        types='v24@0:4{vector<ElectrictyParticlePathIndex, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}^{ElectrictyParticlePathIndex}{__compressed_pair<ElectrictyParticlePathIndex *, std::__1::allocator<ElectrictyParticlePathIndex> >=^{ElectrictyParticlePathIndex}}}8f20',
        start=14186160,
        end=14187268,
        disasm='disasm_particleemitter_doaddelectricityparticle.txt',
        base_add=14186176,
        base_literal=14187264,
        boundary='ARM.exidx bound 0x00d87b04 (next IMP [addParticleAtPos:...connectionGoal:] at 0x00d87b8c; trailing pool/alignment excluded)',
        selectors={14187224: (15240452, 'firstIndex'), 14187236: (15240400, 'addIndex:'), 14187244: (15240456, 'removeIndex:')},
        imports={14187220: (17151904, 'objc_msgSend')},
        ivars={14187208: (17168964, 'OBJC_IVAR_$_ParticleEmitter.stopAllParticles', 96), 14187228: (17168920, 'OBJC_IVAR_$_ParticleEmitter.electrictyFreeIndices', 52), 14187232: (17168912, 'OBJC_IVAR_$_ParticleEmitter.electrictyParticles', 48), 14187240: (17168916, 'OBJC_IVAR_$_ParticleEmitter.electrictyTakenIndices', 56), 14187252: (17168968, 'OBJC_IVAR_$_ParticleEmitter.worldWidthMacro', 100)},
        classes={},
        instructions=[(14186160, 'push {r4, r5, r6, r7, fp, lr}'), (14186844, 'bl sym.imp.__modsi3'), (14186888, 'bl sym.makeIntpair_int__int_'), (14186996, 'bl method.Vector.Vector_float__float__float_'), (14187096, 'vstr s2, [r4, 0x20]'), (14187192, 'pop {r4, r5, r6, r7, fp, pc}')],
        semantics=('Segment allocator for the electricity particle path visual. Guard: stopAllParticles@96 != 0 -> return. step = 50.0/size (f64 0x4049000000000000); remaining = size; t = 0.0f. Loop while remaining > 0: index = [electrictyFreeIndices@52 firstIndex]; 0x7fffffff (NSNotFound) -> return; index moves free -> taken (removeIndex:/addIndex: on the two NSMutableIndexSet ivars); slot = electrictyParticles@48 + index*40; slot+0x10 vector <- path (vector::assign); cursor +0x1c := 0; {x,y} = slot.path.at(cursor); macro = makeIntpair(x mod (worldWidthMacro@100<<5), y / (worldWidthMacro<<5)); pos Vector = (macro.x+5, macro.y+5, z) with z = (low byte of y == 1) ? 0.03f : -1.47f (0x3cf5c28f / 0xbfbc28f6); slot+0x20 = 0.0f; slot+0x24 = t; t += step; remaining -= 5.0f.'),
        calls=[(14186376, 'blx r3'), (14186508, 'blx r3'), (14186548, 'blx ip'), (14186676, 'bl method.std::__1::enable_if___is_forward_iterator_ElectrictyParticlePathIndex_::value__void_::type_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.assign_ElectrictyParticlePathIndex__ElectrictyParticlePathIndex__ElectrictyParticlePathIndex_'), (14186780, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.at_unsigned_long_'), (14186844, 'bl sym.imp.__modsi3'), (14186864, 'bl sym.imp.__aeabi_idiv'), (14186888, 'bl sym.makeIntpair_int__int_'), (14186996, 'bl method.Vector.Vector_float__float__float_')],
        branches=[(14186232, 'beq', 14186240), (14186236, 'b', 14187188), (14186300, 'ble', 14187188), (14186396, 'beq', 14187180), (14186620, 'beq', 14186680), (14187176, 'b', 14187184), (14187180, 'b', 14187188), (14187184, 'b', 14186288)],
    ),]

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

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

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
        'batch': 'electricity consumers + producers closure: Workbench electric API (combinedLightForSolarPanelWithFullSunlight / combinedLightForSolarPanel / availableElectricity / conductsElectricity / subtractElectricty: / generatesElectricity / usesStoresConductsOrProducesElectricity / requiresElectricty), DynamicWorld findAndSubtractAllPowerUpTo:forUser: forwarder, ParticleEmitter add/doAddElectricityParticleWithPath:size:',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'power_workbench.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale power_workbench.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
