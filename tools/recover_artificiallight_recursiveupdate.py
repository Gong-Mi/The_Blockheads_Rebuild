#!/usr/bin/env python3
"""Hash-gated recovery of the artificial-light propagation engine.

-[ArtificialLight recursivelyUpdateLightWithList:] 0x00a8f22c .. 0x00a91d30
(2753 instructions) from the pinned original libApplication.so (1.7.6,
armeabi-v7a): the engine behind addToTiles / addContributionForPhysicalBlockLoaded.

Shape: pop one world index off the work list; wrap its x into +-w/2 of the
light; read the grid cell (own cell overrides to radius*10); relax the cell's
value over the 8-neighbourhood (orthogonal + diagonal) with per-medium and
direction-dependent attenuation, saturating via max; commit the new value back
into the grid (int16 at idx*5+0); if it grew, enqueue the four orthogonal
neighbours (guarded std::list inserts). Every instruction word is re-verified
against the pinned ELF; tool refuses to emit on drift.
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
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.pop_front__': 0x00A91D30,
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_': 0x00A91E48,
    'bl sym.getWorldPosForWorldIndex_int__int__int__World_': 0x00A15518,
    'bl sym.imp.__aeabi_idiv': 0x001C3728,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00A16E68,
    'bl sym.tileIsAirWaterOrSnow_Tile_': 0x00A126DC,
    'bl sym.tileIsSemiTransparentSolidBlock_Tile_': 0x00A128B0,
    'bl sym.tileIsWater_Tile_': 0x00A11690,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': 0x00A156A8,
}

SEMANTICS = (
    'Single-step relaxation of one world index. '
    '1) pop_front the work list, idx = the popped world index; '
    'getWorldPosForWorldIndex(idx, &x, &y, self.world); mt = [self.world '
    'macroTiles]; tile = tileAtWorldPosition(x, y, mt, self.world); '
    'if (!tile) return. '
    '2) wrap x into +-w16 of self.pos.x where w16 = ([self.world '
    'worldWidthMacro] << 5) / 2 (via __aeabi_idiv): x - pos.x >= w16 -> '
    'x -= w*32; x - pos.x < -w16 -> x += w*32 (three staged sub-branches at '
    '0xa8f334/0xa8f434/0xa8f4ac). y never wraps. '
    '3) dx = x - contributionGridOrigin.x; dy = y - origin.y; cull unless '
    '0 <= dx < diameter and 0 <= dy < diameter (else return). '
    'idx5 = dy*diameter + dx; v = (int16)contributionGrid[idx5*5]. '
    'If (x,y) == self.pos: v = radius*10 and skip straight to commit. '
    '4) Eight neighbour relaxations (N/S/E/W/NE/SE/NW/SW). Per neighbour: '
    'rel = (dx+/-1, dy+/-1); cull against the same grid bounds; nv = '
    '(int16)contributionGrid[rel_idx*5]; skip when nv <= 1; ntile = '
    'tileAtWorldPosition(x+/-1, y+/-1, mt, self.world); skip when !ntile; '
    'then with dir = self.lightDirection - '
    'orthogonal water/air/solid: water -> nv -= max((radius*5)/6, 5); air -> '
    'nv -= 10; solid or dir-matched -> direction path; '
    'diagonal water/air/solid: water -> nv -= max((radius*7)/6, 7); air -> '
    'nv -= 14; solid or dir-matched -> direction path; '
    'direction paths: N/NE/NW -> dir==2 yields nv = 0, otherwise nv -= '
    'max((radius*K)/6, K); S/SE/SW -> dir==1 yields nv = 0, otherwise nv -= '
    'max((radius*K)/6, K); E/W -> dir in {1,2}: nv -= max((radius*20)/6, 20), '
    'dir in {0,3}: nv -= max((radius*10)/6, 10); K = 10 orthogonal, 14 '
    'diagonal. Solid tiles route into the same direction paths (E/W with dir '
    '{0,3} -> 10/6). Then v = max(v, nv) (saturating merge into the running '
    'value). '
    '5) commit: if (v <= stored grid16[idx5*5]) return; else store '
    'grid16[idx5*5] = (int16)v (strh at 0xa9155c) and for each orthogonal '
    'neighbour whose stored value the new v exceeds (guards at '
    '0xa91564/0xa91748/0xa91924/0xa91b04 against [fp,-0x230] (init 0, never '
    're-written), the S/E/W neighbour values), enqueue that neighbour via '
    'worldIndexAtWorldPosition(x, y+1 / x, y-1 / x+1, y / x-1, y, self.world) '
    'and a std::list insertion sequence (node scans at 0xa91628/0xa91808/'
    '0xa919e4/0xa91bc4 walk prev/next links and compare element values at '
    'node+8; push_back at 0xa9173c/0xa91918/0xa91af8/0xa91cd4). '
    'Boundary: the std::list scan scaffolds are compiler bookkeeping; only '
    'their input (the neighbour index) and guard conditions are semantic.'
)

SPECS = [
    dict(
        name='recursivelyUpdateLightWithList:',
        method='ArtificialLight -[recursivelyUpdateLightWithList:]',
        types='v12@0:4^{list<unsigned int, std::__1::allocator<unsigned int> >}',
        start=0x00A8F22C, end=0x00A91D30,
        disasm='disasm_artificiallight_recursiveupdate.txt',
        base_add=0x00A8F23C, base_literal=0x00A90170,
        boundary='own ARM.exidx bound 0x00a91d30 (end of the region; next method IMP 0x00a91d30 = std::__1::list<unsigned int>::pop_front)',
        selectors={
            0x00A9017C: (0x00E854CC, 'macroTiles'),
            0x00A90188: (0x00E854D0, 'worldWidthMacro'),
            0x00A91CF8: (0x00E854CC, 'macroTiles'),
        },
        ivars={
            0x00A90174: (0x0105C394, 'OBJC_IVAR_$_DynamicObject.world', 4),
            0x00A90180: (0x0105C390, 'OBJC_IVAR_$_DynamicObject.pos', 16),
            0x00A904A4: (0x0105EA14, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
            0x00A90554: (0x0105EA18, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
            0x00A905E4: (0x0105EA1C, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
            0x00A905E8: (0x0105EA20, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
            0x00A905F0: (0x0105EA24, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
            0x00A91CF0: (0x0105C394, 'OBJC_IVAR_$_DynamicObject.world', 4),
            0x00A91CFC: (0x0105EA14, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
            0x00A91D00: (0x0105EA18, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
            0x00A91D04: (0x0105EA1C, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
            0x00A91D08: (0x0105EA24, 'OBJC_IVAR_$_ArtificialLight.lightDirection', 96),
            0x00A91D0C: (0x0105EA20, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
        },
        imports={
            0x00A90178: (0x0105B7A0, 'objc_msgSend'),
            0x00A91CF4: (0x0105B7A0, 'objc_msgSend'),
        },
        instructions=[
            (0x00A8F3C0, 'lsl r0, r0, 5'),
            (0x00A8F418, 'mov r1, r0'),
            (0x00A8F41C, 'lsl r0, r0, 5'),
            (0x00A8F490, 'rsb r0, r0, 0'),
            (0x00A8F5E0, 'mla r3, r3, ip, lr'),
            (0x00A8F600, 'add r3, ip, r3, lsl 1'),
            (0x00A8F604, 'ldrsh r3, [r3]'),
            (0x00A8F654, 'movw r0, 0xa'),
            (0x00A8F674, 'mul r0, r1, r0'),
            (0x00A9155C, 'strh r1, [r2]'),
            (0x00A91560, 'ldr r1, [fp, -0x25c]'),
            (0x00A9165C, 'movw r0, 0'),
            (0x00A91660, 'moveq r0, 1'),
            (0x00A91664, 'eor r0, r0, 1'),
            (0x00A91668, 'tst r0, 1'),
            (0x00A916B8, 'add r0, sp, 0x250'),
            (0x00A91894, 'add r0, sp, 0x228'),
            (0x00A91A74, 'add r0, sp, 0x200'),
            (0x00A91C50, 'add r0, sp, 0x1d8'),
            (0x00A91CE8, 'sub sp, fp, 8'),
            (0x00A91CEC, 'pop {r4, sl, fp, pc}'),
        ] + [
            (0x00A8F730, 'movw r0, 1'), (0x00A8F814, 'movw r1, 0'),
            (0x00A8F888, 'movw r0, 5'), (0x00A8F88C, 'movw r1, 6'),
            (0x00A8F914, 'sub r0, r0, 0xa'), (0x00A8F944, 'movw r0, 0xa'),
            (0x00A8F948, 'movw r1, 6'), (0x00A8F9CC, 'movw r0, 0'),
            (0x00A8F844, 'cmp r0, 2'), (0x00A8F93C, 'cmp r0, 2'),
            (0x00A8FA28, 'sub r2, r2, 1'), (0x00A8FAAC, 'movw r0, 1'),
            (0x00A8FB34, 'sub r1, lr, 1'), (0x00A8FB90, 'movw r1, 0'),
            (0x00A8FC04, 'movw r0, 5'), (0x00A8FC08, 'movw r1, 6'),
            (0x00A8FC90, 'sub r0, r0, 0xa'), (0x00A8FCC0, 'movw r0, 0xa'),
            (0x00A8FCC4, 'movw r1, 6'), (0x00A8FD48, 'movw r0, 0'),
            (0x00A8FBC0, 'cmp r0, 1'), (0x00A8FCB8, 'cmp r0, 1'),
            (0x00A8FE28, 'movw r0, 1'), (0x00A8FF0C, 'movw r1, 0'),
            (0x00A8FFA4, 'movw r0, 5'), (0x00A8FFA8, 'movw r1, 6'),
            (0x00A90030, 'sub r0, r0, 0xa'), (0x00A90084, 'movw r0, 0xa'),
            (0x00A90088, 'movw r1, 6'), (0x00A9010C, 'movw r0, 0x14'),
            (0x00A90110, 'movw r1, 6'),
            (0x00A8FF3C, 'cmp r0, 1'), (0x00A8FF60, 'cmp r0, 2'),
            (0x00A90058, 'cmp r0, 1'), (0x00A9007C, 'cmp r0, 2'),
            (0x00A901EC, 'sub r2, r2, 1'), (0x00A9028C, 'movw r0, 1'),
            (0x00A90310, 'sub ip, ip, 1'), (0x00A90370, 'movw r1, 0'),
            (0x00A90408, 'movw r0, 5'), (0x00A9040C, 'movw r1, 6'),
            (0x00A90494, 'sub r0, r0, 0xa'), (0x00A904F0, 'movw r0, 0xa'),
            (0x00A904F4, 'movw r1, 6'), (0x00A90580, 'movw r0, 0x14'),
            (0x00A90584, 'movw r1, 6'),
            (0x00A903A0, 'cmp r0, 1'), (0x00A903C4, 'cmp r0, 2'),
            (0x00A904C4, 'cmp r0, 1'), (0x00A904E8, 'cmp r0, 2'),
            (0x00A906F0, 'movw r0, 1'), (0x00A907D8, 'movw r1, 0'),
            (0x00A90870, 'movw r0, 7'), (0x00A90874, 'movw r1, 6'),
            (0x00A908FC, 'sub r0, r0, 0xe'), (0x00A9092C, 'movw r0, 0xe'),
            (0x00A90930, 'movw r1, 6'), (0x00A909B8, 'movw r0, 0'),
            (0x00A90808, 'cmp r0, 1'), (0x00A9082C, 'cmp r0, 2'),
            (0x00A90924, 'cmp r0, 2'),
            (0x00A90A18, 'sub r2, r2, 1'), (0x00A90A9C, 'movw r0, 1'),
            (0x00A90B28, 'sub r1, lr, 1'), (0x00A90B84, 'movw r1, 0'),
            (0x00A90C1C, 'movw r0, 7'), (0x00A90C20, 'movw r1, 6'),
            (0x00A90CA8, 'sub r0, r0, 0xe'), (0x00A90CD8, 'movw r0, 0xe'),
            (0x00A90CDC, 'movw r1, 6'), (0x00A90D64, 'movw r0, 0'),
            (0x00A90BB4, 'cmp r0, 1'), (0x00A90BD8, 'cmp r0, 2'),
            (0x00A90CD0, 'cmp r0, 1'),
            (0x00A90DA4, 'sub r2, r2, 1'), (0x00A90E48, 'movw r0, 1'),
            (0x00A90ECC, 'sub ip, ip, 1'), (0x00A90F30, 'movw r1, 0'),
            (0x00A90FC8, 'movw r0, 7'), (0x00A90FCC, 'movw r1, 6'),
            (0x00A91054, 'sub r0, r0, 0xe'), (0x00A91084, 'movw r0, 0xe'),
            (0x00A91088, 'movw r1, 6'), (0x00A91110, 'movw r0, 0'),
            (0x00A90F60, 'cmp r0, 1'), (0x00A90F84, 'cmp r0, 2'),
            (0x00A9107C, 'cmp r0, 2'),
            (0x00A91150, 'sub r2, r2, 1'), (0x00A91170, 'sub r2, r2, 1'),
            (0x00A911F4, 'movw r0, 1'), (0x00A91278, 'sub ip, ip, 1'),
            (0x00A91280, 'sub r1, lr, 1'), (0x00A912DC, 'movw r1, 0'),
            (0x00A91374, 'movw r0, 7'), (0x00A91378, 'movw r1, 6'),
            (0x00A91400, 'sub r0, r0, 0xe'), (0x00A91430, 'movw r0, 0xe'),
            (0x00A91434, 'movw r1, 6'), (0x00A914B8, 'movw r0, 0'),
            (0x00A9130C, 'cmp r0, 1'), (0x00A91330, 'cmp r0, 2'),
            (0x00A91428, 'cmp r0, 1'),
        ],
        semantics=SEMANTICS,
        calls=[
            (0x00a8f26c, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.pop_front__'),
            (0x00a8f2a8, 'bl sym.getWorldPosForWorldIndex_int__int__int__World_'),
            (0x00a8f2f8, 'blx r2'),
            (0x00a8f324, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a8f3b8, 'bl loc.imp.objc_msgSend'),
            (0x00a8f3d0, 'bl sym.imp.__aeabi_idiv'),
            (0x00a8f414, 'bl loc.imp.objc_msgSend'),
            (0x00a8f48c, 'bl loc.imp.objc_msgSend'),
            (0x00a8f49c, 'bl sym.imp.__aeabi_idiv'),
            (0x00a8f4e0, 'bl loc.imp.objc_msgSend'),
            (0x00a8f7e4, 'blx r2'),
            (0x00a8f810, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a8f850, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a8f864, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a8f878, 'bl sym.tileIsWater_Tile_'),
            (0x00a8f8c0, 'bl sym.imp.__aeabi_idiv'),
            (0x00a8f97c, 'bl sym.imp.__aeabi_idiv'),
            (0x00a8fb60, 'blx r2'),
            (0x00a8fb8c, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a8fbcc, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a8fbe0, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a8fbf4, 'bl sym.tileIsWater_Tile_'),
            (0x00a8fc3c, 'bl sym.imp.__aeabi_idiv'),
            (0x00a8fcf8, 'bl sym.imp.__aeabi_idiv'),
            (0x00a8fedc, 'blx r2'),
            (0x00a8ff08, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a8ff6c, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a8ff80, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a8ff94, 'bl sym.tileIsWater_Tile_'),
            (0x00a8ffdc, 'bl sym.imp.__aeabi_idiv'),
            (0x00a900bc, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90144, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90340, 'blx r2'),
            (0x00a9036c, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a903d0, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a903e4, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a903f8, 'bl sym.tileIsWater_Tile_'),
            (0x00a90440, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90528, 'bl sym.imp.__aeabi_idiv'),
            (0x00a905b8, 'bl sym.imp.__aeabi_idiv'),
            (0x00a907a8, 'blx r2'),
            (0x00a907d4, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a90838, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a9084c, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a90860, 'bl sym.tileIsWater_Tile_'),
            (0x00a908a8, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90964, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90b54, 'blx r2'),
            (0x00a90b80, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a90be4, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a90bf8, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a90c0c, 'bl sym.tileIsWater_Tile_'),
            (0x00a90c54, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90d10, 'bl sym.imp.__aeabi_idiv'),
            (0x00a90f00, 'blx r2'),
            (0x00a90f2c, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a90f90, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a90fa4, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a90fb8, 'bl sym.tileIsWater_Tile_'),
            (0x00a91000, 'bl sym.imp.__aeabi_idiv'),
            (0x00a910bc, 'bl sym.imp.__aeabi_idiv'),
            (0x00a912ac, 'blx r2'),
            (0x00a912d8, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
            (0x00a9133c, 'bl sym.tileIsAirWaterOrSnow_Tile_'),
            (0x00a91350, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
            (0x00a91364, 'bl sym.tileIsWater_Tile_'),
            (0x00a913ac, 'bl sym.imp.__aeabi_idiv'),
            (0x00a91468, 'bl sym.imp.__aeabi_idiv'),
            (0x00a915b0, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00a9173c, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'),
            (0x00a91790, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00a91918, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'),
            (0x00a9196c, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00a91af8, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'),
            (0x00a91b4c, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
            (0x00a91cd4, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'),
        ],
        branches=[
            (0x00a8f338, 'beq', 0x00a91ce8),
            (0x00a8f3dc, 'ble', 0x00a8f434),
            (0x00a8f430, 'b', 0x00a8f500),
            (0x00a8f4a8, 'bge', 0x00a8f4fc),
            (0x00a8f4fc, 'b', 0x00a8f500),
            (0x00a8f54c, 'blt', 0x00a91ce4),
            (0x00a8f574, 'bge', 0x00a91ce4),
            (0x00a8f580, 'blt', 0x00a91ce4),
            (0x00a8f5a8, 'bge', 0x00a91ce4),
            (0x00a8f628, 'bne', 0x00a8f680),
            (0x00a8f650, 'bne', 0x00a8f680),
            (0x00a8f67c, 'b', 0x00a914ec),
            (0x00a8f6d0, 'blt', 0x00a8f9fc),
            (0x00a8f6f8, 'bge', 0x00a8f9fc),
            (0x00a8f704, 'blt', 0x00a8f9fc),
            (0x00a8f72c, 'bge', 0x00a8f9fc),
            (0x00a8f790, 'ble', 0x00a8f9f8),
            (0x00a8f824, 'beq', 0x00a8f9f4),
            (0x00a8f848, 'beq', 0x00a8f920),
            (0x00a8f85c, 'bne', 0x00a8f874),
            (0x00a8f870, 'beq', 0x00a8f920),
            (0x00a8f884, 'beq', 0x00a8f910),
            (0x00a8f8dc, 'bge', 0x00a8f8ec),
            (0x00a8f8e8, 'b', 0x00a8f8f4),
            (0x00a8f90c, 'b', 0x00a8f91c),
            (0x00a8f91c, 'b', 0x00a8f9d8),
            (0x00a8f940, 'beq', 0x00a8f9cc),
            (0x00a8f998, 'bge', 0x00a8f9a8),
            (0x00a8f9a4, 'b', 0x00a8f9b0),
            (0x00a8f9c8, 'b', 0x00a8f9d4),
            (0x00a8f9d4, 'b', 0x00a8f9d8),
            (0x00a8f9e4, 'ble', 0x00a8f9f0),
            (0x00a8f9f0, 'b', 0x00a8f9f4),
            (0x00a8f9f4, 'b', 0x00a8f9f8),
            (0x00a8f9f8, 'b', 0x00a8f9fc),
            (0x00a8fa4c, 'blt', 0x00a8fd78),
            (0x00a8fa74, 'bge', 0x00a8fd78),
            (0x00a8fa80, 'blt', 0x00a8fd78),
            (0x00a8faa8, 'bge', 0x00a8fd78),
            (0x00a8fb0c, 'ble', 0x00a8fd74),
            (0x00a8fba0, 'beq', 0x00a8fd70),
            (0x00a8fbc4, 'beq', 0x00a8fc9c),
            (0x00a8fbd8, 'bne', 0x00a8fbf0),
            (0x00a8fbec, 'beq', 0x00a8fc9c),
            (0x00a8fc00, 'beq', 0x00a8fc8c),
            (0x00a8fc58, 'bge', 0x00a8fc68),
            (0x00a8fc64, 'b', 0x00a8fc70),
            (0x00a8fc88, 'b', 0x00a8fc98),
            (0x00a8fc98, 'b', 0x00a8fd54),
            (0x00a8fcbc, 'beq', 0x00a8fd48),
            (0x00a8fd14, 'bge', 0x00a8fd24),
            (0x00a8fd20, 'b', 0x00a8fd2c),
            (0x00a8fd44, 'b', 0x00a8fd50),
            (0x00a8fd50, 'b', 0x00a8fd54),
            (0x00a8fd60, 'ble', 0x00a8fd6c),
            (0x00a8fd6c, 'b', 0x00a8fd70),
            (0x00a8fd70, 'b', 0x00a8fd74),
            (0x00a8fd74, 'b', 0x00a8fd78),
            (0x00a8fdc8, 'blt', 0x00a901dc),
            (0x00a8fdf0, 'bge', 0x00a901dc),
            (0x00a8fdfc, 'blt', 0x00a901dc),
            (0x00a8fe24, 'bge', 0x00a901dc),
            (0x00a8fe88, 'ble', 0x00a901d8),
            (0x00a8ff1c, 'beq', 0x00a901d4),
            (0x00a8ff40, 'beq', 0x00a9003c),
            (0x00a8ff64, 'beq', 0x00a9003c),
            (0x00a8ff78, 'bne', 0x00a8ff90),
            (0x00a8ff8c, 'beq', 0x00a9003c),
            (0x00a8ffa0, 'beq', 0x00a9002c),
            (0x00a8fff8, 'bge', 0x00a90008),
            (0x00a90004, 'b', 0x00a90010),
            (0x00a90028, 'b', 0x00a90038),
            (0x00a90038, 'b', 0x00a901b8),
            (0x00a9005c, 'beq', 0x00a9010c),
            (0x00a90080, 'beq', 0x00a9010c),
            (0x00a900d8, 'bge', 0x00a900e8),
            (0x00a900e4, 'b', 0x00a900f0),
            (0x00a90108, 'b', 0x00a901b4),
            (0x00a90160, 'bge', 0x00a90194),
            (0x00a9016c, 'b', 0x00a9019c),
            (0x00a901b4, 'b', 0x00a901b8),
            (0x00a901c4, 'ble', 0x00a901d0),
            (0x00a901d0, 'b', 0x00a901d4),
            (0x00a901d4, 'b', 0x00a901d8),
            (0x00a901d8, 'b', 0x00a901dc),
            (0x00a9022c, 'blt', 0x00a9063c),
            (0x00a90254, 'bge', 0x00a9063c),
            (0x00a90260, 'blt', 0x00a9063c),
            (0x00a90288, 'bge', 0x00a9063c),
            (0x00a902ec, 'ble', 0x00a90638),
            (0x00a90380, 'beq', 0x00a90634),
            (0x00a903a4, 'beq', 0x00a904a8),
            (0x00a903c8, 'beq', 0x00a904a8),
            (0x00a903dc, 'bne', 0x00a903f4),
            (0x00a903f0, 'beq', 0x00a904a8),
            (0x00a90404, 'beq', 0x00a90490),
            (0x00a9045c, 'bge', 0x00a9046c),
            (0x00a90468, 'b', 0x00a90474),
            (0x00a9048c, 'b', 0x00a9049c),
            (0x00a9049c, 'b', 0x00a90618),
            (0x00a904c8, 'beq', 0x00a90580),
            (0x00a904ec, 'beq', 0x00a90580),
            (0x00a90544, 'bge', 0x00a90558),
            (0x00a90550, 'b', 0x00a90560),
            (0x00a90578, 'b', 0x00a90614),
            (0x00a905d4, 'bge', 0x00a905f4),
            (0x00a905e0, 'b', 0x00a905fc),
            (0x00a90614, 'b', 0x00a90618),
            (0x00a90624, 'ble', 0x00a90630),
            (0x00a90630, 'b', 0x00a90634),
            (0x00a90634, 'b', 0x00a90638),
            (0x00a90638, 'b', 0x00a9063c),
            (0x00a90690, 'blt', 0x00a909e8),
            (0x00a906b8, 'bge', 0x00a909e8),
            (0x00a906c4, 'blt', 0x00a909e8),
            (0x00a906ec, 'bge', 0x00a909e8),
            (0x00a90750, 'ble', 0x00a909e4),
            (0x00a907e8, 'beq', 0x00a909e0),
            (0x00a9080c, 'beq', 0x00a90908),
            (0x00a90830, 'beq', 0x00a90908),
            (0x00a90844, 'bne', 0x00a9085c),
            (0x00a90858, 'beq', 0x00a90908),
            (0x00a9086c, 'beq', 0x00a908f8),
            (0x00a908c4, 'bge', 0x00a908d4),
            (0x00a908d0, 'b', 0x00a908dc),
            (0x00a908f4, 'b', 0x00a90904),
            (0x00a90904, 'b', 0x00a909c4),
            (0x00a90928, 'beq', 0x00a909b8),
            (0x00a90980, 'bge', 0x00a90990),
            (0x00a9098c, 'b', 0x00a90998),
            (0x00a909b0, 'b', 0x00a909c0),
            (0x00a909c0, 'b', 0x00a909c4),
            (0x00a909d0, 'ble', 0x00a909dc),
            (0x00a909dc, 'b', 0x00a909e0),
            (0x00a909e0, 'b', 0x00a909e4),
            (0x00a909e4, 'b', 0x00a909e8),
            (0x00a90a3c, 'blt', 0x00a90d94),
            (0x00a90a64, 'bge', 0x00a90d94),
            (0x00a90a70, 'blt', 0x00a90d94),
            (0x00a90a98, 'bge', 0x00a90d94),
            (0x00a90afc, 'ble', 0x00a90d90),
            (0x00a90b94, 'beq', 0x00a90d8c),
            (0x00a90bb8, 'beq', 0x00a90cb4),
            (0x00a90bdc, 'beq', 0x00a90cb4),
            (0x00a90bf0, 'bne', 0x00a90c08),
            (0x00a90c04, 'beq', 0x00a90cb4),
            (0x00a90c18, 'beq', 0x00a90ca4),
            (0x00a90c70, 'bge', 0x00a90c80),
            (0x00a90c7c, 'b', 0x00a90c88),
            (0x00a90ca0, 'b', 0x00a90cb0),
            (0x00a90cb0, 'b', 0x00a90d70),
            (0x00a90cd4, 'beq', 0x00a90d64),
            (0x00a90d2c, 'bge', 0x00a90d3c),
            (0x00a90d38, 'b', 0x00a90d44),
            (0x00a90d5c, 'b', 0x00a90d6c),
            (0x00a90d6c, 'b', 0x00a90d70),
            (0x00a90d7c, 'ble', 0x00a90d88),
            (0x00a90d88, 'b', 0x00a90d8c),
            (0x00a90d8c, 'b', 0x00a90d90),
            (0x00a90d90, 'b', 0x00a90d94),
            (0x00a90de8, 'blt', 0x00a91140),
            (0x00a90e10, 'bge', 0x00a91140),
            (0x00a90e1c, 'blt', 0x00a91140),
            (0x00a90e44, 'bge', 0x00a91140),
            (0x00a90ea8, 'ble', 0x00a9113c),
            (0x00a90f40, 'beq', 0x00a91138),
            (0x00a90f64, 'beq', 0x00a91060),
            (0x00a90f88, 'beq', 0x00a91060),
            (0x00a90f9c, 'bne', 0x00a90fb4),
            (0x00a90fb0, 'beq', 0x00a91060),
            (0x00a90fc4, 'beq', 0x00a91050),
            (0x00a9101c, 'bge', 0x00a9102c),
            (0x00a91028, 'b', 0x00a91034),
            (0x00a9104c, 'b', 0x00a9105c),
            (0x00a9105c, 'b', 0x00a9111c),
            (0x00a91080, 'beq', 0x00a91110),
            (0x00a910d8, 'bge', 0x00a910e8),
            (0x00a910e4, 'b', 0x00a910f0),
            (0x00a91108, 'b', 0x00a91118),
            (0x00a91118, 'b', 0x00a9111c),
            (0x00a91128, 'ble', 0x00a91134),
            (0x00a91134, 'b', 0x00a91138),
            (0x00a91138, 'b', 0x00a9113c),
            (0x00a9113c, 'b', 0x00a91140),
            (0x00a91194, 'blt', 0x00a914e8),
            (0x00a911bc, 'bge', 0x00a914e8),
            (0x00a911c8, 'blt', 0x00a914e8),
            (0x00a911f0, 'bge', 0x00a914e8),
            (0x00a91254, 'ble', 0x00a914e4),
            (0x00a912ec, 'beq', 0x00a914e0),
            (0x00a91310, 'beq', 0x00a9140c),
            (0x00a91334, 'beq', 0x00a9140c),
            (0x00a91348, 'bne', 0x00a91360),
            (0x00a9135c, 'beq', 0x00a9140c),
            (0x00a91370, 'beq', 0x00a913fc),
            (0x00a913c8, 'bge', 0x00a913d8),
            (0x00a913d4, 'b', 0x00a913e0),
            (0x00a913f8, 'b', 0x00a91408),
            (0x00a91408, 'b', 0x00a914c4),
            (0x00a9142c, 'beq', 0x00a914b8),
            (0x00a91484, 'bge', 0x00a91494),
            (0x00a91490, 'b', 0x00a9149c),
            (0x00a914b4, 'b', 0x00a914c0),
            (0x00a914c0, 'b', 0x00a914c4),
            (0x00a914d0, 'ble', 0x00a914dc),
            (0x00a914dc, 'b', 0x00a914e0),
            (0x00a914e0, 'b', 0x00a914e4),
            (0x00a914e4, 'b', 0x00a914e8),
            (0x00a914e8, 'b', 0x00a914ec),
            (0x00a91528, 'ble', 0x00a91ce0),
            (0x00a91570, 'ble', 0x00a91744),
            (0x00a9166c, 'beq', 0x00a916b8),
            (0x00a91690, 'bne', 0x00a91698),
            (0x00a91694, 'b', 0x00a916b8),
            (0x00a916b0, 'b', 0x00a91628),
            (0x00a91728, 'bne', 0x00a91740),
            (0x00a91740, 'b', 0x00a91744),
            (0x00a91750, 'ble', 0x00a91920),
            (0x00a9184c, 'beq', 0x00a91894),
            (0x00a91870, 'bne', 0x00a91878),
            (0x00a91874, 'b', 0x00a91894),
            (0x00a91890, 'b', 0x00a91808),
            (0x00a91904, 'bne', 0x00a9191c),
            (0x00a9191c, 'b', 0x00a91920),
            (0x00a9192c, 'ble', 0x00a91b00),
            (0x00a91a28, 'beq', 0x00a91a74),
            (0x00a91a4c, 'bne', 0x00a91a54),
            (0x00a91a50, 'b', 0x00a91a74),
            (0x00a91a6c, 'b', 0x00a919e4),
            (0x00a91ae4, 'bne', 0x00a91afc),
            (0x00a91afc, 'b', 0x00a91b00),
            (0x00a91b0c, 'ble', 0x00a91cdc),
            (0x00a91c08, 'beq', 0x00a91c50),
            (0x00a91c2c, 'bne', 0x00a91c34),
            (0x00a91c30, 'b', 0x00a91c50),
            (0x00a91c4c, 'b', 0x00a91bc4),
            (0x00a91cc0, 'bne', 0x00a91cd8),
            (0x00a91cd8, 'b', 0x00a91cdc),
            (0x00a91cdc, 'b', 0x00a91ce0),
            (0x00a91ce0, 'b', 0x00a91ce4),
            (0x00a91ce4, 'b', 0x00a91ce8),
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

        listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
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
                           for a, ins in rows.items()
                           for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                           if m and m.group(1) not in ('bl', 'blx')}
        expected_branches = {(a, mn, d) for a, mn, d in spec['branches']}
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
            'pic_base': f'0x{base:08x}',
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
        'batch': 'ArtificialLight propagation engine (recursivelyUpdateLightWithList:)',
        'claim': ('static bounded-body map with per-instruction anchors; the '
                  'contributing selectors/tiles functions are pinned by '
                  'address; runtime values are outside this body'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'artificiallight_recursiveupdate.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale artificiallight_recursiveupdate.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
