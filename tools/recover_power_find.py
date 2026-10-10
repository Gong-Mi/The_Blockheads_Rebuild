#!/usr/bin/env python3
"""Hash-gated recovery of the electricity power-flow search engine.

WirePathCreator -[findAndSubtractAllPowerUpTo:forUser:] 0x00db2690..0x00db51d4
(2769 words; exidx-bounded body 0xdb2690..0xdb51d4) from the pinned original libApplication.so (1.7.6, armeabi-v7a):
the A*-flavored wire-network power search - open/closed NSMutableIndexSets,
4 direction probes through the 13-argument testTile helper, per-source
availableElectricity -> subtractElectricty: with 16-bit accounting, and the
electricity particle path handed to [ParticleEmitter instance]
addElectricityParticleWithPath:size:. Every instruction word is re-verified;
tool refuses to emit on drift.
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
    'bl loc.imp.objc_msgSend_stret': 0x001C2918,
    'bl sym.imp.memset': 0x001C2924,
    'bl sym.imp.__aeabi_idiv': 0x001C3728,
    'bl sym.imp._Block_object_dispose': 0x001C2870,
    'bl sym.imp._Unwind_Resume': 0x001C29C0,
    'bl sym.getWorldPosForWorldIndex_int__int__int__World_': 0x00A15518,
    'bl sym.tileAtWorldIndexLoaded_int__World_': 0x00A16944,
    'bl sym.tileIsSolid_Tile_': 0x00A1179C,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': 0x00A156A8,
    'bl sym.testTile_int__int__NSMutableIndexSet__NSMutableIndexSet__int__Tile__WirePathTileProperties__int__int__unsigned_short__World__WirePathCreator__signed_char_': 0x00DB222C,
    'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.clear__': 0x00CA60CC,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__': 0x005CB054,
    'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_': 0x005CAEF8,
    'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_': 0x005DB5B4,
}

SEMANTICS = (
"Power-flow search (index-set Dijkstra-flavored) that finds wire-connected sources and subtracts up to `upTo` power for the user. (int16 upTo, id user). 1) Prologue: derivedTileIndices map cleared (std::__tree<...>::clear at 0xdb2840); state struct at [sp,0x230] reset: uint16 remaining = uint16 initial = upTo (strh r2,[ip,8]; ldrh; strh [ip]); a field zeroed; a 0x88-byte user payload copied via objc_msgSend_stret (or memset 0 when user == nil) plus the user flag byte at [sp,0x487]; startIndex@16 = worldIndexAtWorldPosition(wrapped start pos); start tile = tileAtWorldIndexLoaded - nil -> return 0. openList@8 / closedList@12 (NSMutableIndexSet) are prepared through the alloc/init msgSend trampolines; four __block captures built (descriptor flags 0x20000000 / 0xc2000000, one capture = 0x98967f = 9,999,999). 2) The open list is enumerated through [openList enumerateIndexesUsingBlock:] (0xe88f48) with a block; each enumerated index resolves to (x,y) via getWorldPosForWorldIndex and probes four directions through the 13-argument C helper testTile(x-1,y / x+1,y / x,y-1 / x,y+1, openList, closedList, 10, tile, props, idx, idx2, budget, world, self, flag) at 0xdb222c (10 = probe budget). 3) Main loop: while [openList count] (0xe88f44) > 0 (back edge 0xdb50fc -> 0xdb2a78; drain exit 0xdb2abc -> 0xdb5140). Per direction (left/right/down/up), the testTile result list is walked via its [+8] chain (sentinel -1; removeIndex:/addIndex: maintain the open/closed sets): each candidate's availableElectricity (0xe88f28) is read as uint16, amount = min(available, remaining) through the min-selection chains (state offsets +0x3a/+0x5a/...+0xfa), when > 0: remaining -= amount; the source is updated via [candidate subtractElectricty:amount] (0xe88f50, original spelling); the path tile {x, y, -1} (12-byte ElectrictyParticlePathIndex) is pushed into a per-direction std::vector; the vector is copied and handed to [[ParticleEmitter instance] addElectricityParticleWithPath:vectorCopy size:count] (0xe88f54 / 0xe88f58) - the electricity particle visual; direction finish: remaining == 0 -> exit returning upTo (flag 1), else continue (flag 0). 4) Epilogue: _Block_object_dispose x4; when the open list drains: return = uint16 initial - remaining (0xdb5140-0xdb5150) = the power actually delivered (int16). All 120 call sites, 232 branches (5 loops), the 20 named cells (index sets, selectors, ParticleEmitter class), the 16-bit power fields, the 10^7 guard and the 13-arg testTile signature are anchored. Boundary: the C helper testTile (0xdb222c) and the block closures are separate objects; their every invocation site and argument setup are pinned here, but their internals are outside this body."
)

SPECS = [
    dict(
        name='wpc_findpower', method='WirePathCreator -[findAndSubtractAllPowerUpTo:forUser:]',
        types='i16@0:4S8@12', start=0x00DB2690, end=0x00DB51D4,
        disasm='disasm_wirepathcreator_findandsubtractpower.txt',
        base_add=0x00DB26B4, base_literal=0x00DB36AC,
        boundary='own ARM.exidx bound 0x00db51d4 (body 0xdb2690..0xdb51d4; next method IMP region follows with pool/alignment)',
        selectors={0x00DB36BC: (0x00E88F0C, 'init'), 0x00DB36C0: (0x00E88F3C, 'alloc'), 0x00DB36CC: (0x00E88F10, 'release'), 0x00DB36D0: (0x00E88F40, 'pos'), 0x00DB36DC: (0x00E88F30, 'isStorageDevice'), 0x00DB3944: (0x00E88F1C, 'tileDerivedPropertiesAtWorldIndex:'), 0x00DB3948: (0x00E88F38, 'addIndex:'), 0x00DB3A38: (0x00E88F44, 'count'), 0x00DB3A4C: (0x00E88F48, 'enumerateIndexesUsingBlock:'), 0x00DB3BE8: (0x00E88F4C, 'removeIndex:'), 0x00DB3BF4: (0x00E88F28, 'availableElectricity'), 0x00DB3DC0: (0x00E88F50, 'subtractElectricty:'), 0x00DB434C: (0x00E88F54, 'instance'), 0x00DB44B8: (0x00E88F58, 'addElectricityParticleWithPath:size:')}, imports={0x00DB36B8: (0x0105B7A0, 'objc_msgSend'), 0x00DB3A40: (0x0105B7B8, '_NSConcreteStackBlock')}, ivars={0x00DB36B0: (0x0105FAEC, 'OBJC_IVAR_$_WirePathCreator.derivedTileIndices', 28), 0x00DB36B4: (0x0105FAE0, 'OBJC_IVAR_$_WirePathCreator.closedList', 12), 0x00DB36C8: (0x0105FAE4, 'OBJC_IVAR_$_WirePathCreator.openList', 8), 0x00DB36D4: (0x0105FAE8, 'OBJC_IVAR_$_WirePathCreator.derivedTileCount', 24), 0x00DB36D8: (0x0105FADC, 'OBJC_IVAR_$_WirePathCreator.world', 4), 0x00DB36E0: (0x0105FAF0, 'OBJC_IVAR_$_WirePathCreator.startIndex', 16)}, classes={0x00DB4344: (0x00E8B848, 'OBJC_CLASS_$_ParticleEmitter')},
        instructions=[
            (0x00DB2720, 'strh r2, [ip, 8]'),
            (0x00DB2728, 'ldrh r1, [ip, 8]'),
            (0x00DB272C, 'strh r1, [ip]'),
            (0x00DB2AFC, 'movw lr, 0x967f'),
            (0x00DB2B00, 'movt lr, 0x98'),
            (0x00DB2B64, 'mov r3, 0xc2000000'),
            (0x00DB2D38, 'mov r3, 0xa'),
            (0x00DB3300, 'vcvt.f32.s32 s0, s0'),
            (0x00DB3304, 'vstr s0, [r0, 0x20]'),
            (0x00DB3098, 'movw r0, 0'),
            (0x00DB30A0, 'cmn r1, 1'),
            (0x00DB3670, 'strh r0, [r1, 6]'),
            (0x00DB3FB8, 'strh r0, [r1, 0xa6]'),
            (0x00DB48A4, 'strh r0, [r1, 0x46]'),
            (0x00DB5140, 'ldr r0, [sp, 0x238]'),
            (0x00DB5144, 'ldrh r1, [r0, 8]'),
            (0x00DB5148, 'ldrh r2, [r0]'),
            (0x00DB514C, 'sub r1, r1, r2'),
            (0x00DB5150, 'str r1, [sp, 0x4a8]'),
            (0x00DB5154, 'ldr r0, [sp, 0x4a8]'),
            (0x00DB5158, 'sub sp, fp, 0x18'),
        ],
        semantics=SEMANTICS,
        calls=[
            (0x00db2778, 'blx r8'),
            (0x00db279c, 'blx r3'),
            (0x00db27bc, 'blx r3'),
            (0x00db27cc, 'blx r2'),
            (0x00db2800, 'blx ip'),
            (0x00db2810, 'blx r2'),
            (0x00db2840, 'bl method.std::__1::__tree_std::__1::pair_int__int___std::__1::__map_value_compare_int__int__std::__1::less_int___true___std::__1::allocator_std::__1::pair_int__int_____.clear__'),
            (0x00db2894, 'bl loc.imp.objc_msgSend_stret'),
            (0x00db28bc, 'bl sym.imp.memset'),
            (0x00db28ec, 'blx r2'),
            (0x00db2920, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db2968, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db29d8, 'blx r3'),
            (0x00db2a74, 'blx r3'),
            (0x00db2ab4, 'blx r2'),
            (0x00db2bb8, 'bl loc.imp.objc_msgSend'),
            (0x00db2c38, 'bl sym.getWorldPosForWorldIndex_int__int__int__World_'),
            (0x00db2c78, 'bl loc.imp.objc_msgSend'),
            (0x00db2cb8, 'bl loc.imp.objc_msgSend'),
            (0x00db2d64, 'bl sym.testTile_int__int__NSMutableIndexSet__NSMutableIndexSet__int__Tile__WirePathTileProperties__int__int__unsigned_short__World__WirePathCreator__signed_char_'),
            (0x00db2d9c, 'bl loc.imp.objc_msgSend'),
            (0x00db2e30, 'bl loc.imp.objc_msgSend'),
            (0x00db2ed8, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db2f08, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db2f1c, 'bl sym.tileIsSolid_Tile_'),
            (0x00db3050, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db3084, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db3100, 'bl loc.imp.objc_msgSend'),
            (0x00db315c, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db3170, 'bl sym.tileIsSolid_Tile_'),
            (0x00db32a4, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db32ec, 'bl sym.imp.__aeabi_idiv'),
            (0x00db3344, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db3358, 'bl sym.tileIsSolid_Tile_'),
            (0x00db348c, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db34b4, 'bl loc.imp.objc_msgSend'),
            (0x00db34c8, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'),
            (0x00db34ec, 'bl loc.imp.objc_msgSend'),
            (0x00db34f8, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3514, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3554, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3570, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3624, 'bl sym.testTile_int__int__NSMutableIndexSet__NSMutableIndexSet__int__Tile__WirePathTileProperties__int__int__unsigned_short__World__WirePathCreator__signed_char_'),
            (0x00db365c, 'bl loc.imp.objc_msgSend'),
            (0x00db372c, 'bl loc.imp.objc_msgSend'),
            (0x00db37d4, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db3804, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db3818, 'bl sym.tileIsSolid_Tile_'),
            (0x00db3954, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db3988, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db3a04, 'bl loc.imp.objc_msgSend'),
            (0x00db3a78, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db3a8c, 'bl sym.tileIsSolid_Tile_'),
            (0x00db3bc0, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db3c24, 'bl sym.imp.__aeabi_idiv'),
            (0x00db3c80, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db3c94, 'bl sym.tileIsSolid_Tile_'),
            (0x00db3dd0, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db3df8, 'bl loc.imp.objc_msgSend'),
            (0x00db3e0c, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'),
            (0x00db3e30, 'bl loc.imp.objc_msgSend'),
            (0x00db3e3c, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3e58, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3e98, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3eb4, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db3f6c, 'bl sym.testTile_int__int__NSMutableIndexSet__NSMutableIndexSet__int__Tile__WirePathTileProperties__int__int__unsigned_short__World__WirePathCreator__signed_char_'),
            (0x00db3fa4, 'bl loc.imp.objc_msgSend'),
            (0x00db4044, 'bl loc.imp.objc_msgSend'),
            (0x00db40e4, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db4114, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db4128, 'bl sym.tileIsSolid_Tile_'),
            (0x00db4260, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db4294, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db4310, 'bl loc.imp.objc_msgSend'),
            (0x00db4378, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db438c, 'bl sym.tileIsSolid_Tile_'),
            (0x00db44c8, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db4518, 'bl sym.imp.__aeabi_idiv'),
            (0x00db4570, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db4584, 'bl sym.tileIsSolid_Tile_'),
            (0x00db46bc, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db46e4, 'bl loc.imp.objc_msgSend'),
            (0x00db46f8, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'),
            (0x00db471c, 'bl loc.imp.objc_msgSend'),
            (0x00db4728, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db4744, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db4784, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db47a0, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db4858, 'bl sym.testTile_int__int__NSMutableIndexSet__NSMutableIndexSet__int__Tile__WirePathTileProperties__int__int__unsigned_short__World__WirePathCreator__signed_char_'),
            (0x00db4890, 'bl loc.imp.objc_msgSend'),
            (0x00db4930, 'bl loc.imp.objc_msgSend'),
            (0x00db49d0, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db4a00, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db4a14, 'bl sym.tileIsSolid_Tile_'),
            (0x00db4b48, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db4b7c, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00db4bf8, 'bl loc.imp.objc_msgSend'),
            (0x00db4c58, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db4c6c, 'bl sym.tileIsSolid_Tile_'),
            (0x00db4da0, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db4df4, 'bl sym.imp.__aeabi_idiv'),
            (0x00db4e4c, 'bl sym.tileAtWorldIndexLoaded_int__World_'),
            (0x00db4e60, 'bl sym.tileIsSolid_Tile_'),
            (0x00db4f98, 'bl method.void_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'),
            (0x00db4fc0, 'bl loc.imp.objc_msgSend'),
            (0x00db4fd4, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___.vector_std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex____const_'),
            (0x00db4ff8, 'bl loc.imp.objc_msgSend'),
            (0x00db5004, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db5020, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db5064, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db5080, 'bl method.std::__1::vector_ElectrictyParticlePathIndex__std::__1::allocator_ElectrictyParticlePathIndex___._vector__'),
            (0x00db50ac, 'bl sym.imp._Block_object_dispose'),
            (0x00db50b8, 'bl sym.imp._Block_object_dispose'),
            (0x00db50c8, 'bl sym.imp._Block_object_dispose'),
            (0x00db50d4, 'bl sym.imp._Block_object_dispose'),
            (0x00db5110, 'bl sym.imp._Block_object_dispose'),
            (0x00db511c, 'bl sym.imp._Block_object_dispose'),
            (0x00db512c, 'bl sym.imp._Block_object_dispose'),
            (0x00db5138, 'bl sym.imp._Block_object_dispose'),
            (0x00db5164, 'bl sym.imp._Unwind_Resume'),
        ],
        branches=[
            (0x00db2880, 'beq', 0x00db289c),
            (0x00db2898, 'b', 0x00db28c0),
            (0x00db297c, 'bne', 0x00db298c),
            (0x00db2988, 'b', 0x00db5154),
            (0x00db29ec, 'bne', 0x00db29fc),
            (0x00db29f8, 'b', 0x00db5154),
            (0x00db2abc, 'bls', 0x00db5140),
            (0x00db2bbc, 'b', 0x00db2bc0),
            (0x00db2bd0, 'bne', 0x00db2c00),
            (0x00db2bf0, 'b', 0x00db509c),
            (0x00db2bfc, 'b', 0x00db5104),
            (0x00db2c3c, 'b', 0x00db2c40),
            (0x00db2c7c, 'b', 0x00db2c80),
            (0x00db2cbc, 'b', 0x00db2cc0),
            (0x00db2d6c, 'b', 0x00db2d70),
            (0x00db2d84, 'beq', 0x00db3580),
            (0x00db2da4, 'b', 0x00db2da8),
            (0x00db2dd4, 'bge', 0x00db2de8),
            (0x00db2de4, 'b', 0x00db2df4),
            (0x00db2e10, 'ble', 0x00db357c),
            (0x00db2e38, 'b', 0x00db2e3c),
            (0x00db2ee0, 'b', 0x00db2ee4),
            (0x00db2f10, 'b', 0x00db2f14),
            (0x00db2f24, 'b', 0x00db2f28),
            (0x00db2f74, 'beq', 0x00db3048),
            (0x00db3008, 'beq', 0x00db3034),
            (0x00db3044, 'b', 0x00db305c),
            (0x00db3054, 'b', 0x00db3058),
            (0x00db3058, 'b', 0x00db305c),
            (0x00db305c, 'b', 0x00db3060),
            (0x00db308c, 'b', 0x00db3090),
            (0x00db30a8, 'beq', 0x00db30dc),
            (0x00db30e4, 'beq', 0x00db32c4),
            (0x00db3108, 'b', 0x00db310c),
            (0x00db3120, 'bne', 0x00db3134),
            (0x00db3124, 'b', 0x00db32c4),
            (0x00db3130, 'b', 0x00db356c),
            (0x00db3164, 'b', 0x00db3168),
            (0x00db3178, 'b', 0x00db317c),
            (0x00db31c8, 'beq', 0x00db329c),
            (0x00db325c, 'beq', 0x00db3288),
            (0x00db3298, 'b', 0x00db32b0),
            (0x00db32a8, 'b', 0x00db32ac),
            (0x00db32ac, 'b', 0x00db32b0),
            (0x00db32b0, 'b', 0x00db32b4),
            (0x00db32c0, 'b', 0x00db3098),
            (0x00db32f4, 'bls', 0x00db3520),
            (0x00db334c, 'b', 0x00db3350),
            (0x00db3360, 'b', 0x00db3364),
            (0x00db33b0, 'beq', 0x00db3484),
            (0x00db3444, 'beq', 0x00db3470),
            (0x00db3480, 'b', 0x00db3498),
            (0x00db3490, 'b', 0x00db3494),
            (0x00db3494, 'b', 0x00db3498),
            (0x00db3498, 'b', 0x00db349c),
            (0x00db34bc, 'b', 0x00db34c0),
            (0x00db34cc, 'b', 0x00db34d0),
            (0x00db34f0, 'b', 0x00db34f4),
            (0x00db3500, 'b', 0x00db3520),
            (0x00db351c, 'b', 0x00db356c),
            (0x00db352c, 'bne', 0x00db3548),
            (0x00db3544, 'b', 0x00db3550),
            (0x00db3560, 'bne', 0x00db509c),
            (0x00db3564, 'b', 0x00db3568),
            (0x00db3568, 'b', 0x00db357c),
            (0x00db3578, 'b', 0x00db5104),
            (0x00db357c, 'b', 0x00db3580),
            (0x00db362c, 'b', 0x00db3630),
            (0x00db3644, 'beq', 0x00db3ecc),
            (0x00db3664, 'b', 0x00db3668),
            (0x00db3698, 'bge', 0x00db36e4),
            (0x00db36a8, 'b', 0x00db36f0),
            (0x00db370c, 'ble', 0x00db3ec8),
            (0x00db3734, 'b', 0x00db3738),
            (0x00db37dc, 'b', 0x00db37e0),
            (0x00db380c, 'b', 0x00db3810),
            (0x00db3820, 'b', 0x00db3824),
            (0x00db3870, 'beq', 0x00db394c),
            (0x00db3904, 'beq', 0x00db3930),
            (0x00db3940, 'b', 0x00db3960),
            (0x00db3958, 'b', 0x00db395c),
            (0x00db395c, 'b', 0x00db3960),
            (0x00db3960, 'b', 0x00db3964),
            (0x00db3990, 'b', 0x00db3994),
            (0x00db39ac, 'beq', 0x00db39e0),
            (0x00db39e8, 'beq', 0x00db3bfc),
            (0x00db3a0c, 'b', 0x00db3a10),
            (0x00db3a24, 'bne', 0x00db3a50),
            (0x00db3a28, 'b', 0x00db3bfc),
            (0x00db3a34, 'b', 0x00db3eb0),
            (0x00db3a80, 'b', 0x00db3a84),
            (0x00db3a94, 'b', 0x00db3a98),
            (0x00db3ae4, 'beq', 0x00db3bb8),
            (0x00db3b78, 'beq', 0x00db3ba4),
            (0x00db3bb4, 'b', 0x00db3bcc),
            (0x00db3bc4, 'b', 0x00db3bc8),
            (0x00db3bc8, 'b', 0x00db3bcc),
            (0x00db3bcc, 'b', 0x00db3bd0),
            (0x00db3bdc, 'b', 0x00db399c),
            (0x00db3c2c, 'bls', 0x00db3e64),
            (0x00db3c88, 'b', 0x00db3c8c),
            (0x00db3c9c, 'b', 0x00db3ca0),
            (0x00db3cec, 'beq', 0x00db3dc8),
            (0x00db3d80, 'beq', 0x00db3dac),
            (0x00db3dbc, 'b', 0x00db3ddc),
            (0x00db3dd4, 'b', 0x00db3dd8),
            (0x00db3dd8, 'b', 0x00db3ddc),
            (0x00db3ddc, 'b', 0x00db3de0),
            (0x00db3e00, 'b', 0x00db3e04),
            (0x00db3e10, 'b', 0x00db3e14),
            (0x00db3e34, 'b', 0x00db3e38),
            (0x00db3e44, 'b', 0x00db3e64),
            (0x00db3e60, 'b', 0x00db3eb0),
            (0x00db3e70, 'bne', 0x00db3e8c),
            (0x00db3e88, 'b', 0x00db3e94),
            (0x00db3ea4, 'bne', 0x00db509c),
            (0x00db3ea8, 'b', 0x00db3eac),
            (0x00db3eac, 'b', 0x00db3ec8),
            (0x00db3ebc, 'b', 0x00db5104),
            (0x00db3ec8, 'b', 0x00db3ecc),
            (0x00db3f74, 'b', 0x00db3f78),
            (0x00db3f8c, 'beq', 0x00db47b8),
            (0x00db3fac, 'b', 0x00db3fb0),
            (0x00db3fdc, 'bge', 0x00db3ffc),
            (0x00db3fec, 'b', 0x00db4008),
            (0x00db4024, 'ble', 0x00db47b4),
            (0x00db404c, 'b', 0x00db4050),
            (0x00db40ec, 'b', 0x00db40f0),
            (0x00db411c, 'b', 0x00db4120),
            (0x00db4130, 'b', 0x00db4134),
            (0x00db4180, 'beq', 0x00db4258),
            (0x00db4214, 'beq', 0x00db4240),
            (0x00db4250, 'b', 0x00db426c),
            (0x00db4264, 'b', 0x00db4268),
            (0x00db4268, 'b', 0x00db426c),
            (0x00db426c, 'b', 0x00db4270),
            (0x00db429c, 'b', 0x00db42a0),
            (0x00db42b8, 'beq', 0x00db42ec),
            (0x00db42f4, 'beq', 0x00db44f0),
            (0x00db4318, 'b', 0x00db431c),
            (0x00db4330, 'bne', 0x00db4350),
            (0x00db4334, 'b', 0x00db44f0),
            (0x00db4340, 'b', 0x00db479c),
            (0x00db4380, 'b', 0x00db4384),
            (0x00db4394, 'b', 0x00db4398),
            (0x00db43e4, 'beq', 0x00db44c0),
            (0x00db4478, 'beq', 0x00db44a4),
            (0x00db44b4, 'b', 0x00db44d4),
            (0x00db44cc, 'b', 0x00db44d0),
            (0x00db44d0, 'b', 0x00db44d4),
            (0x00db44d4, 'b', 0x00db44d8),
            (0x00db44e4, 'b', 0x00db42a8),
            (0x00db4520, 'bls', 0x00db4750),
            (0x00db4578, 'b', 0x00db457c),
            (0x00db458c, 'b', 0x00db4590),
            (0x00db45dc, 'beq', 0x00db46b4),
            (0x00db4670, 'beq', 0x00db469c),
            (0x00db46ac, 'b', 0x00db46c8),
            (0x00db46c0, 'b', 0x00db46c4),
            (0x00db46c4, 'b', 0x00db46c8),
            (0x00db46c8, 'b', 0x00db46cc),
            (0x00db46ec, 'b', 0x00db46f0),
            (0x00db46fc, 'b', 0x00db4700),
            (0x00db4720, 'b', 0x00db4724),
            (0x00db4730, 'b', 0x00db4750),
            (0x00db474c, 'b', 0x00db479c),
            (0x00db475c, 'bne', 0x00db4778),
            (0x00db4774, 'b', 0x00db4780),
            (0x00db4790, 'bne', 0x00db509c),
            (0x00db4794, 'b', 0x00db4798),
            (0x00db4798, 'b', 0x00db47b4),
            (0x00db47a8, 'b', 0x00db5104),
            (0x00db47b4, 'b', 0x00db47b8),
            (0x00db4860, 'b', 0x00db4864),
            (0x00db4878, 'beq', 0x00db5094),
            (0x00db4898, 'b', 0x00db489c),
            (0x00db48c8, 'bge', 0x00db48e8),
            (0x00db48d8, 'b', 0x00db48f4),
            (0x00db4910, 'ble', 0x00db5090),
            (0x00db4938, 'b', 0x00db493c),
            (0x00db49d8, 'b', 0x00db49dc),
            (0x00db4a08, 'b', 0x00db4a0c),
            (0x00db4a1c, 'b', 0x00db4a20),
            (0x00db4a6c, 'beq', 0x00db4b40),
            (0x00db4b00, 'beq', 0x00db4b2c),
            (0x00db4b3c, 'b', 0x00db4b54),
            (0x00db4b4c, 'b', 0x00db4b50),
            (0x00db4b50, 'b', 0x00db4b54),
            (0x00db4b54, 'b', 0x00db4b58),
            (0x00db4b84, 'b', 0x00db4b88),
            (0x00db4ba0, 'beq', 0x00db4bd4),
            (0x00db4bdc, 'beq', 0x00db4dcc),
            (0x00db4c00, 'b', 0x00db4c04),
            (0x00db4c18, 'bne', 0x00db4c30),
            (0x00db4c1c, 'b', 0x00db4dcc),
            (0x00db4c28, 'b', 0x00db507c),
            (0x00db4c60, 'b', 0x00db4c64),
            (0x00db4c74, 'b', 0x00db4c78),
            (0x00db4cc4, 'beq', 0x00db4d98),
            (0x00db4d58, 'beq', 0x00db4d84),
            (0x00db4d94, 'b', 0x00db4dac),
            (0x00db4da4, 'b', 0x00db4da8),
            (0x00db4da8, 'b', 0x00db4dac),
            (0x00db4dac, 'b', 0x00db4db0),
            (0x00db4dbc, 'b', 0x00db4b90),
            (0x00db4dfc, 'bls', 0x00db5030),
            (0x00db4e54, 'b', 0x00db4e58),
            (0x00db4e68, 'b', 0x00db4e6c),
            (0x00db4eb8, 'beq', 0x00db4f90),
            (0x00db4f4c, 'beq', 0x00db4f78),
            (0x00db4f88, 'b', 0x00db4fa4),
            (0x00db4f9c, 'b', 0x00db4fa0),
            (0x00db4fa0, 'b', 0x00db4fa4),
            (0x00db4fa4, 'b', 0x00db4fa8),
            (0x00db4fc8, 'b', 0x00db4fcc),
            (0x00db4fd8, 'b', 0x00db4fdc),
            (0x00db4ffc, 'b', 0x00db5000),
            (0x00db500c, 'b', 0x00db5030),
            (0x00db5028, 'b', 0x00db507c),
            (0x00db503c, 'bne', 0x00db5058),
            (0x00db5054, 'b', 0x00db5060),
            (0x00db5070, 'bne', 0x00db509c),
            (0x00db5074, 'b', 0x00db5078),
            (0x00db5078, 'b', 0x00db5090),
            (0x00db5088, 'b', 0x00db5104),
            (0x00db5090, 'b', 0x00db5094),
            (0x00db50e4, 'beq', 0x00db5154),
            (0x00db50e8, 'b', 0x00db50ec),
            (0x00db50f4, 'bne', 0x00db5168),
            (0x00db50f8, 'b', 0x00db50fc),
            (0x00db50fc, 'b', 0x00db2a78),
            (0x00db513c, 'b', 0x00db5160),
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
        'batch': 'electricity power-flow search (WirePathCreator findAndSubtractAllPowerUpTo:forUser:)',
        'claim': ('static bounded-body maps with per-instruction anchors; '
                  'runtime values and the render consumers are outside these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'power_find.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale power_find.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
