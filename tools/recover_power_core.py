#!/usr/bin/env python3
"""Hash-gated recovery of the electricity-domain core.

Four bodies from the pinned original libApplication.so (1.7.6, armeabi-v7a):
Wire -[updateWireConfiguration] (the conductivity/connection recompute),
WirePathCreator -[tileDerivedPropertiesAtWorldIndex:] (the memoized per-tile
property slots) and ElevatorMotor -[hasRequiredPower] / -[usePower] (the
consumer side). Every instruction word re-verified; tool refuses to emit on
drift.
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
    'bl loc.imp.objc_msgSend': 0x001C281C,
    'bl sym.makeIntpair_int__int_': 0x004B49FC,
    'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_': 0x00A19598,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': 0x00A12F24,
    'bl sym.tileConductsElectricity_Tile_': 0x00A11818,
    'bl sym.tileIsSolid_Tile_': 0x00A1179C,
    'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_': 0x0086C818,
}
SEMANTICS = {}
SEMANTICS['wire_updateconfig'] = (
    'Four-direction connection recompute + configuration combine + change notification. For each direction (up (x,y+1), right (x+1,y), down (x,y-1), left (x-1,y)): tile = tileAtWorldPositionLoaded(nx, ny, self.world); nil -> no connection; else connect = tileConductsElectricity(tile) || (tile[3] == 0x68) || ((tile[3] == 0x2e || tile[3] == 0x2f) && [[self.dynamicWorld workbenchAtPos:(nx,ny)] usesStoresConductsOrProducesElectricity]); when connected: connFlag = 1 and openFlag = !tileIsSolid(tile). Then two combiners keyed (up,right,down,left): connection bitmap -> moving value: 1111->1, 1110->4, 1101->5, 1100->3, 1011->7, 1010->0xa, 1001->0xc, 1000->3, 0111->8, 0110->9, 0101->0xb, 0100->3, 0011->6, 0010->6, 0001->6, 0000->2. If selfSolid (self tile tileIsSolid): cover bitmap -> cover value (initial 3): 1111->2, 1110->5, 1101->6, 1100->4, 1011->9, 1010->0xc, 1001->0xe, 1000->0x10, 0111->0xa, 0110->0xb, 0101->0xd, 0100->0x11, 0011->7, 0010->8, 0001->0xf, 0000->keep 3; if not selfSolid cover value = 1 and the cover combiner is skipped. Store only when changed: Wire.currentConfiguration@60 = moving; Wire.currentSolidConfiguration@64 = cover; if both were unchanged -> return. On change and when !DynamicObject.isNet@52: DynamicObject.updateNeedsToBeSent@49 = 1; [self.dynamicWorld dynamicWorldChangedAtPos:intpair(self.x, self.y) objectType:[self objectType]]; reloadDrawBlockDynamicObjectStaticGeometryForTile(intpair, [self.world macroTiles], self.world). All neighbour tiles and the tail dispatches are anchored; the per-direction special dispatch is the workbench/production query.'
)
SEMANTICS['wpc_tilederived'] = (
    'Memoized per-tile property slot. If WirePathCreator.derivedTileCount@24 == 0x1ff (511, the array is full) -> return 0. cached = WirePathCreator.derivedTileIndices@28 (std::__1::map<int,int>)[worldIndex]; when cached != 0 -> return &derivedTilePropertiesArray@20[cached] (12-byte {int,int,int} slots, mul by 0xc). Otherwise ++derivedTileCount, write map[worldIndex] = newCount and return &array[newCount] (array base + newCount*12).'
)
SEMANTICS['em_hasreqpower'] = (
    'return (ElevatorMotor.availableElectricity@60 (uint16 halfword) >= 10); movge r0, 1.'
)
SEMANTICS['em_usepower'] = (
    'if DynamicObject.isNet@52: availableElectricity@60 += 10; else: when availableElectricity > 0: ElevatorMotor.timeUntilNextPowerCheck@72 = 0.0f (pool 0x702994); then when availableElectricity > 10: availableElectricity -= 10 else availableElectricity = 0. In every path: DynamicObject.updateNeedsToBeSent@49 = 1.'
)

SPECS = [
    dict(
        name='wire_updateconfig', method='Wire -[updateWireConfiguration]',
        types='v8@0:4', start=0x0094F000, end=0x0094FCA0,
        disasm='disasm_wire_updatewireconfiguration.txt',
        base_add=0x0094F010, base_literal=0x0094FC9C,
        boundary='own ARM.exidx bound 0x0094fca0 (next method IMP 0x0094fca0 = -[initSubDerivedItems])',
        selectors={0x0094FC5C: (0x00E839EC, 'usesStoresConductsOrProducesElectricity'), 0x0094FC68: (0x00E839E8, 'workbenchAtPos:'), 0x0094FC8C: (0x00E839F0, 'objectType'), 0x0094FC90: (0x00E839F4, 'dynamicWorldChangedAtPos:objectType:'), 0x0094FC98: (0x00E839F8, 'macroTiles')}, imports={0x0094FC58: (0x0105B7A0, 'objc_msgSend')}, ivars={0x0094FC50: (0x0105C394, 'OBJC_IVAR_$_DynamicObject.world', 4), 0x0094FC54: (0x0105C390, 'OBJC_IVAR_$_DynamicObject.pos', 16), 0x0094FC60: (0x0105C3A8, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8), 0x0094FC78: (0x0105E2F8, 'OBJC_IVAR_$_Wire.currentConfiguration', 60), 0x0094FC7C: (0x0105E2FC, 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 64), 0x0094FC80: (0x0105C5C0, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 0x0094FC84: (0x0105C3CC, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49)},
        instructions=[
            (0x0094F124, 'cmp r0, 0x68'),
            (0x0094F140, 'cmp r0, 0x2e'),
            (0x0094F150, 'cmp r0, 0x2f'),
            (0x0094F1F0, 'blx r2'),
            (0x0094F784, 'movw r1, 2'),
            (0x0094F788, 'str r1, [sp, 0x6c]'),
            (0x0094F7A4, 'str r0, [sp, 0x68]'),
            (0x0094F7D8, 'movw r0, 1'),
            (0x0094F7E4, 'movw r0, 4'),
            (0x0094F7FC, 'movw r0, 5'),
            (0x0094F808, 'movw r0, 3'),
            (0x0094F830, 'movw r0, 7'),
            (0x0094F83C, 'movw r0, 0xa'),
            (0x0094F854, 'movw r0, 0xc'),
            (0x0094F898, 'movw r0, 8'),
            (0x0094F8A4, 'movw r0, 9'),
            (0x0094F8BC, 'movw r0, 0xb'),
            (0x0094F8F0, 'movw r0, 6'),
            (0x0094F93C, 'movw r0, 2'),
            (0x0094F948, 'movw r0, 5'),
            (0x0094F960, 'movw r0, 6'),
            (0x0094F96C, 'movw r0, 4'),
            (0x0094F994, 'movw r0, 9'),
            (0x0094F9A0, 'movw r0, 0xc'),
            (0x0094F9B8, 'movw r0, 0xe'),
            (0x0094F9C4, 'movw r0, 0x10'),
            (0x0094F9FC, 'movw r0, 0xa'),
            (0x0094FA08, 'movw r0, 0xb'),
            (0x0094FA20, 'movw r0, 0xd'),
            (0x0094FA2C, 'movw r0, 0x11'),
            (0x0094FA54, 'movw r0, 7'),
            (0x0094FA60, 'movw r0, 8'),
            (0x0094FA78, 'movw r0, 0xf'),
            (0x0094FB0C, 'str ip, [r3]'),
            (0x0094FB20, 'str r3, [r2]'),
            (0x0094FB58, 'strb r3, [r0, r1]'),
        ],
        semantics=SEMANTICS['wire_updateconfig'],
        calls=[
            (0x0094f06c, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
            (0x0094f078, 'bl sym.tileIsSolid_Tile_'),
            (0x0094f0e8, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
            (0x0094f10c, 'bl sym.tileConductsElectricity_Tile_'),
            (0x0094f1bc, 'bl sym.makeIntpair_int__int_'),
            (0x0094f1d8, 'bl loc.imp.objc_msgSend'),
            (0x0094f1f0, 'blx r2'),
            (0x0094f228, 'bl sym.tileIsSolid_Tile_'),
            (0x0094f2a4, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
            (0x0094f2c8, 'bl sym.tileConductsElectricity_Tile_'),
            (0x0094f378, 'bl sym.makeIntpair_int__int_'),
            (0x0094f394, 'bl loc.imp.objc_msgSend'),
            (0x0094f3ac, 'blx r2'),
            (0x0094f3e4, 'bl sym.tileIsSolid_Tile_'),
            (0x0094f460, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
            (0x0094f484, 'bl sym.tileConductsElectricity_Tile_'),
            (0x0094f534, 'bl sym.makeIntpair_int__int_'),
            (0x0094f550, 'bl loc.imp.objc_msgSend'),
            (0x0094f568, 'blx r2'),
            (0x0094f5a0, 'bl sym.tileIsSolid_Tile_'),
            (0x0094f61c, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
            (0x0094f640, 'bl sym.tileConductsElectricity_Tile_'),
            (0x0094f6f0, 'bl sym.makeIntpair_int__int_'),
            (0x0094f70c, 'bl loc.imp.objc_msgSend'),
            (0x0094f724, 'blx r2'),
            (0x0094f75c, 'bl sym.tileIsSolid_Tile_'),
            (0x0094fba4, 'bl loc.imp.objc_msgSend'),
            (0x0094fbc8, 'bl loc.imp.objc_msgSend'),
            (0x0094fc18, 'bl loc.imp.objc_msgSend'),
            (0x0094fc44, 'bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'),
        ], branches=[
            (0x0094f084, 'beq', 0x0094f090),
            (0x0094f0fc, 'beq', 0x0094f24c),
            (0x0094f118, 'bne', 0x0094f12c),
            (0x0094f128, 'bne', 0x0094f138),
            (0x0094f134, 'b', 0x0094f210),
            (0x0094f144, 'beq', 0x0094f158),
            (0x0094f154, 'bne', 0x0094f20c),
            (0x0094f1fc, 'beq', 0x0094f208),
            (0x0094f208, 'b', 0x0094f20c),
            (0x0094f20c, 'b', 0x0094f210),
            (0x0094f218, 'beq', 0x0094f248),
            (0x0094f248, 'b', 0x0094f24c),
            (0x0094f2b8, 'beq', 0x0094f408),
            (0x0094f2d4, 'bne', 0x0094f2e8),
            (0x0094f2e4, 'bne', 0x0094f2f4),
            (0x0094f2f0, 'b', 0x0094f3cc),
            (0x0094f300, 'beq', 0x0094f314),
            (0x0094f310, 'bne', 0x0094f3c8),
            (0x0094f3b8, 'beq', 0x0094f3c4),
            (0x0094f3c4, 'b', 0x0094f3c8),
            (0x0094f3c8, 'b', 0x0094f3cc),
            (0x0094f3d4, 'beq', 0x0094f404),
            (0x0094f404, 'b', 0x0094f408),
            (0x0094f474, 'beq', 0x0094f5c4),
            (0x0094f490, 'bne', 0x0094f4a4),
            (0x0094f4a0, 'bne', 0x0094f4b0),
            (0x0094f4ac, 'b', 0x0094f588),
            (0x0094f4bc, 'beq', 0x0094f4d0),
            (0x0094f4cc, 'bne', 0x0094f584),
            (0x0094f574, 'beq', 0x0094f580),
            (0x0094f580, 'b', 0x0094f584),
            (0x0094f584, 'b', 0x0094f588),
            (0x0094f590, 'beq', 0x0094f5c0),
            (0x0094f5c0, 'b', 0x0094f5c4),
            (0x0094f630, 'beq', 0x0094f780),
            (0x0094f64c, 'bne', 0x0094f660),
            (0x0094f65c, 'bne', 0x0094f66c),
            (0x0094f668, 'b', 0x0094f744),
            (0x0094f678, 'beq', 0x0094f68c),
            (0x0094f688, 'bne', 0x0094f740),
            (0x0094f730, 'beq', 0x0094f73c),
            (0x0094f73c, 'b', 0x0094f740),
            (0x0094f740, 'b', 0x0094f744),
            (0x0094f74c, 'beq', 0x0094f77c),
            (0x0094f77c, 'b', 0x0094f780),
            (0x0094f7b0, 'beq', 0x0094f874),
            (0x0094f7bc, 'beq', 0x0094f818),
            (0x0094f7c8, 'beq', 0x0094f7f0),
            (0x0094f7d4, 'beq', 0x0094f7e4),
            (0x0094f7e0, 'b', 0x0094f7ec),
            (0x0094f7ec, 'b', 0x0094f814),
            (0x0094f7f8, 'beq', 0x0094f808),
            (0x0094f804, 'b', 0x0094f810),
            (0x0094f810, 'b', 0x0094f814),
            (0x0094f814, 'b', 0x0094f870),
            (0x0094f820, 'beq', 0x0094f848),
            (0x0094f82c, 'beq', 0x0094f83c),
            (0x0094f838, 'b', 0x0094f844),
            (0x0094f844, 'b', 0x0094f86c),
            (0x0094f850, 'beq', 0x0094f860),
            (0x0094f85c, 'b', 0x0094f868),
            (0x0094f868, 'b', 0x0094f86c),
            (0x0094f86c, 'b', 0x0094f870),
            (0x0094f870, 'b', 0x0094f900),
            (0x0094f87c, 'beq', 0x0094f8d8),
            (0x0094f888, 'beq', 0x0094f8b0),
            (0x0094f894, 'beq', 0x0094f8a4),
            (0x0094f8a0, 'b', 0x0094f8ac),
            (0x0094f8ac, 'b', 0x0094f8d4),
            (0x0094f8b8, 'beq', 0x0094f8c8),
            (0x0094f8c4, 'b', 0x0094f8d0),
            (0x0094f8d0, 'b', 0x0094f8d4),
            (0x0094f8d4, 'b', 0x0094f8fc),
            (0x0094f8e0, 'bne', 0x0094f8f0),
            (0x0094f8ec, 'beq', 0x0094f8f8),
            (0x0094f8f8, 'b', 0x0094f8fc),
            (0x0094f8fc, 'b', 0x0094f900),
            (0x0094f908, 'beq', 0x0094fa90),
            (0x0094f914, 'beq', 0x0094f9d8),
            (0x0094f920, 'beq', 0x0094f97c),
            (0x0094f92c, 'beq', 0x0094f954),
            (0x0094f938, 'beq', 0x0094f948),
            (0x0094f944, 'b', 0x0094f950),
            (0x0094f950, 'b', 0x0094f978),
            (0x0094f95c, 'beq', 0x0094f96c),
            (0x0094f968, 'b', 0x0094f974),
            (0x0094f974, 'b', 0x0094f978),
            (0x0094f978, 'b', 0x0094f9d4),
            (0x0094f984, 'beq', 0x0094f9ac),
            (0x0094f990, 'beq', 0x0094f9a0),
            (0x0094f99c, 'b', 0x0094f9a8),
            (0x0094f9a8, 'b', 0x0094f9d0),
            (0x0094f9b4, 'beq', 0x0094f9c4),
            (0x0094f9c0, 'b', 0x0094f9cc),
            (0x0094f9cc, 'b', 0x0094f9d0),
            (0x0094f9d0, 'b', 0x0094f9d4),
            (0x0094f9d4, 'b', 0x0094fa8c),
            (0x0094f9e0, 'beq', 0x0094fa3c),
            (0x0094f9ec, 'beq', 0x0094fa14),
            (0x0094f9f8, 'beq', 0x0094fa08),
            (0x0094fa04, 'b', 0x0094fa10),
            (0x0094fa10, 'b', 0x0094fa38),
            (0x0094fa1c, 'beq', 0x0094fa2c),
            (0x0094fa28, 'b', 0x0094fa34),
            (0x0094fa34, 'b', 0x0094fa38),
            (0x0094fa38, 'b', 0x0094fa88),
            (0x0094fa44, 'beq', 0x0094fa6c),
            (0x0094fa50, 'beq', 0x0094fa60),
            (0x0094fa5c, 'b', 0x0094fa68),
            (0x0094fa68, 'b', 0x0094fa84),
            (0x0094fa74, 'beq', 0x0094fa80),
            (0x0094fa80, 'b', 0x0094fa84),
            (0x0094fa84, 'b', 0x0094fa88),
            (0x0094fa88, 'b', 0x0094fa8c),
            (0x0094fa8c, 'b', 0x0094fa90),
            (0x0094fab4, 'bne', 0x0094fae0),
            (0x0094fadc, 'beq', 0x0094fc48),
            (0x0094fb38, 'bne', 0x0094fbcc),
        ],
    ),
    dict(
        name='wpc_tilederived', method='WirePathCreator -[tileDerivedPropertiesAtWorldIndex:]',
        types='^{WirePathTileProperties=iii}12@0:4i8', start=0x00DB20B4, end=0x00DB222C,
        disasm='disasm_wirepathcreator_tilederivedproperties.txt',
        base_add=0x00DB20C4, base_literal=0x00DB2228,
        boundary='own ARM.exidx bound 0x00db222c (next method IMP 0x00db2690 = -[findAndSubtractAllPowerUpTo:forUser:]; gap carries pool/alignment)',
        selectors={}, imports={}, ivars={0x00DB221C: (0x0105FAE8, 'OBJC_IVAR_$_WirePathCreator.derivedTileCount', 24), 0x00DB2220: (0x0105FAEC, 'OBJC_IVAR_$_WirePathCreator.derivedTileIndices', 28), 0x00DB2224: (0x0105FAD8, 'OBJC_IVAR_$_WirePathCreator.derivedTilePropertiesArray', 20)},
        instructions=[
            (0x00DB20C8, 'movw ip, 0x1ff'),
            (0x00DB20F0, 'cmp r0, ip'),
            (0x00DB2160, 'ldr lr, [ip]'),
            (0x00DB2164, 'add lr, lr, 1'),
            (0x00DB2168, 'str lr, [ip]'),
            (0x00DB2190, 'movw r1, 0xc'),
            (0x00DB21D0, 'mul r0, r0, r1'),
            (0x00DB21D4, 'add r0, r2, r0'),
            (0x00DB2204, 'mul r0, r3, r0'),
            (0x00DB2208, 'add r0, r1, r0'),
        ],
        semantics=SEMANTICS['wpc_tilederived'],
        calls=[
            (0x00db2124, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_'),
            (0x00db218c, 'bl method.std::__1::map_int__int__std::__1::less_int___std::__1::allocator_std::__1::pair_int_const__int_____.operator___int_const_'),
        ], branches=[
            (0x00db20f8, 'bne', 0x00db2108),
            (0x00db2104, 'b', 0x00db2210),
            (0x00db2138, 'bne', 0x00db21e0),
            (0x00db21dc, 'b', 0x00db2210),
        ],
    ),
    dict(
        name='em_hasreqpower', method='ElevatorMotor -[hasRequiredPower]',
        types='c8@0:4', start=0x007027F8, end=0x00702848,
        disasm='disasm_elevatormotor_hasrequiredpower.txt',
        base_add=0x00702800, base_literal=0x00702844,
        boundary='own ARM.exidx bound 0x00702848 (next method IMP 0x00702848 = -[usePower])',
        selectors={}, imports={}, ivars={0x00702840: (0x0105D310, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60)},
        instructions=[
            (0x00702820, 'ldrh r0, [r0]'),
            (0x00702824, 'cmp r0, 0xa'),
            (0x0070282C, 'movge r0, 1'),
        ],
        semantics=SEMANTICS['em_hasreqpower'],
        calls=[], branches=[],
    ),
    dict(
        name='em_usepower', method='ElevatorMotor -[usePower]',
        types='v8@0:4', start=0x00702848, end=0x007029A8,
        disasm='disasm_elevatormotor_usepower.txt',
        base_add=0x00702850, base_literal=0x007029A4,
        boundary='own ARM.exidx bound 0x007029a8 (next method IMP 0x007029a8 = -[occupiesNormalContents])',
        selectors={}, imports={}, ivars={0x0070298C: (0x0105C5C0, 'OBJC_IVAR_$_DynamicObject.isNet', 52), 0x00702990: (0x0105D310, 'OBJC_IVAR_$_ElevatorMotor.availableElectricity', 60), 0x00702998: (0x0105D318, 'OBJC_IVAR_$_ElevatorMotor.timeUntilNextPowerCheck', 72), 0x0070299C: (0x0105D314, 'OBJC_IVAR_$_ElevatorMotor.clientPowerUsage', 62), 0x007029A0: (0x0105C3CC, 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent', 49)},
        instructions=[
            (0x00702870, 'ldrsb r0, [r0]'),
            (0x0070289C, 'add r2, r2, 0xa'),
            (0x007028A0, 'strh r2, [r0]'),
            (0x007028D0, 'vldr s0, [0x00702994]'),
            (0x007028EC, 'vstr s0, [r1]'),
            (0x00702930, 'ldrh r2, [r0]'),
            (0x00702934, 'sub r2, r2, 0xa'),
            (0x0070295C, 'strh r0, [r1]'),
            (0x00702964, 'movw r0, 1'),
            (0x00702980, 'strb r0, [r1]'),
        ],
        semantics=SEMANTICS['em_usepower'],
        calls=[], branches=[
            (0x0070287c, 'beq', 0x007028a8),
            (0x007028a4, 'b', 0x00702964),
            (0x007028c8, 'ble', 0x007028f4),
            (0x00702914, 'ble', 0x00702940),
            (0x0070293c, 'b', 0x00702960),
            (0x00702960, 'b', 0x00702964),
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
        'batch': 'electricity-domain core (Wire/WirePathCreator/ElevatorMotor)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'power_core.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale power_core.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
