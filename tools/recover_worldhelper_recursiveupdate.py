#!/usr/bin/env python3
"""Hash-gated recovery of WorldHelper +[recursivelyUpdateSunLightWithList:…].

One class body from the pinned original libApplication.so (1.7.6,
armeabi-v7a, SHA-256 733d8210…b94c7):

  +[WorldHelper recursivelyUpdateSunLightWithList:openIndices:world:]
    0x00a19c0c .. 0x00a1b7d4 (1778 words)

The single-step light-up engine of the sunlight system — the updater twin of
the removal engine (WORLDHELPER_RECURSIVE_REMOVE.md). One call pops one work
item, either floods a lit tile (tile[7] = 0xff / 0xef) with a 4-neighbour
spread, or recomputes a shadowed tile from the six-neighbour stencil
(N/S/E/W + NE/NW, window and attenuation rules) and, on a raise, runs the
server content activation (torch kinds by tile[0xb], glow blocks, treasure
chest / troll spawn by tile[3]) before the six re-enqueue checks. All 164
branches are forward — the caller's drain loop drives iteration.

Every instruction word is re-verified against the pinned ELF; PIC base,
selector/classref/import cells, all 116 call sites (with pinned direct-bl
targets), all 164 branches and key instructions are anchored.
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
MSGSEND_GOT_SLOT = 0x0105B7A0
MSGSEND_STUB = 0x001C281C
RECALC_DRAW = 0x00A18F68
MAKE_INTPAIR = 0x004B49FC
TILE_AT_LOADED = 0x00A12F24
TILE_AT_MACRO = 0x00A16E68
AIR_OR_SNOW = 0x00A12760
SEMI_TRANSPARENT = 0x00A128B0
REQUIRES_GLOW = 0x00A14824
GET_WORLD_POS = 0x00A15518
WORLD_INDEX = 0x00A156A8

ROUTE_TARGETS = {
    'bl sym.getWorldPosForWorldIndex_int__int__int__World_': GET_WORLD_POS,
    'bl sym.tileAtWorldPositionLoaded_int__int__World_': TILE_AT_LOADED,
    'bl sym.tileIsAirOrSnow_Tile_': AIR_OR_SNOW,
    'bl sym.tileIsSemiTransparentSolidBlock_Tile_': SEMI_TRANSPARENT,
    'bl sym.tileRequiresGlowBlock_Tile_': REQUIRES_GLOW,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': WORLD_INDEX,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': TILE_AT_MACRO,
    'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_': RECALC_DRAW,
    'bl loc.imp.objc_msgSend': MSGSEND_STUB,
    'bl sym.makeIntpair_int__int_': MAKE_INTPAIR,
}

SEMANTICS = (
    'Single-step work item. Pop: obj = [list objectAtIndex:0]; idx = [obj intValue]; '
    '[list removeObjectAtIndex:0]; [openIndices removeIndex:idx]; '
    'dw = [world dynamicWorld]; isClient = [dw isClient]; '
    'getWorldPosForWorldIndex(idx, &x, &y, world); '
    'tile = tileAtWorldPosition(x, y, [world macroTiles], world); '
    'if (tile == 0) return; if ((signed char)tile[9] <= 0) return. '
    'LIT PATH - when (tileIsAirOrSnow(tile) && tile[1] == 2) or tile[0xc] in {0x45, 0x5f}: '
    'tile[7] = 0xff, or 0xef when tile[0xc] in {0x45, 0x5f}; '
    'recalculateDrawBlockLightingForTile(x, y, [world macroTiles], world); '
    'then four neighbour enqueues (y+1, y-1, x+1, x-1): skip if !tn; skip if '
    'tn[7] == 0xff; skip if tn[0xc] in {0x45, 0x5f}; nidx = '
    'worldIndexAtWorldPosition(...); skip if nidx < 0 or [openIndices '
    'containsIndex:nidx]; else [list addObject:[NSNumber numberWithInt:nidx]] '
    '+ [openIndices addIndex:nidx]; return. '
    'SHADOW PATH - otherwise: cur = tile[7]; collect contributions from six '
    'neighbours in order y+1, y-1, x+1, x-1, (+1,+1), (-1,+1); contribution: '
    '0 when !tn; 0xff for the y+1 window (air-or-snow with back wall 2 or 3), '
    '0xe0 for the other five windows; else base = (tn[7] > 0xef) ? 2 : 8, '
    'raised to 0x10 when (tn[0] == 3 or tileIsSemiTransparentSolidBlock(tn)), '
    'or to 0x41 when !tileIsAirOrSnow(tn); contribution = max(tn[7] - base, 0); '
    'max = max over contributions. If (max <= tile[7]) return. Otherwise: '
    'tile[7] = max; [world saveSunlightChangedAtPos:makeIntpair(x, y)]; '
    'server only (!isClient): tile[0xb] content activation - 0x34->0x33 torch '
    '0x4b, 0x36->0x35 torch 0x4c, 0x38->0x37 torch 0x56, 0x3a->0x39 torch '
    '0x57, 0x3c->0x3b torch 0x58 (each via [dw addTorchAtPos:pair '
    'ofType:kind dataA:0 dataB:0 saveDict:nil placedByClient:0]); then when '
    'tile[3] in {0x5e, 0x90, 0x91}: loadTroll = (tile[3] != 0x91), '
    'loadTreasure = (tile[3] != 0x90), tile[3] = 0, and when tile[0] == 2: '
    '[dw createTreasureChestOrTrollAtTile:tile atPos:pair loadTroll: '
    'loadTreasure:]. Common tail: recalculateDrawBlockLightingForTile(x, y, '
    '[world macroTiles], world); then six re-enqueue checks in the same '
    'neighbour order: when max > contribution_k and nidx valid and not in '
    '[openIndices], enqueue the neighbour. Exactly one work item per call - '
    'the caller drain loop re-invokes until the list empties.'
)

SPEC = dict(
    name='recursivelyUpdateSunLightWithList',
    method='WorldHelper +[recursivelyUpdateSunLightWithList:openIndices:world:]',
    types='v20@0:4@8@12@16',
    start=0x00A19C0C, end=0x00A1B7D4,
    disasm='disasm_worldhelper_recursiveupdatesunlight.txt',
    base_add=0x00A19C1C, base_literal=0x00A1AA9C,
    boundary=('no own ARM.exidx entry; closed by the next method IMP '
              '0x00a1b7d4 (+[updateSunLightForTile:atPos:world:])'),
    selectors={
        0x00A1AC38: (0x00E84C8C, 'isClient'),
        0x00A1AC3C: (0x00E84C2C, 'dynamicWorld'),
        0x00A1AC40: (0x00E84C88, 'removeIndex:'),
        0x00A1AC44: (0x00E84C84, 'removeObjectAtIndex:'),
        0x00A1AC48: (0x00E84C80, 'intValue'),
        0x00A1AC4C: (0x00E84C7C, 'objectAtIndex:'),
        0x00A1AD70: (0x00E84C70, 'macroTiles'),
        0x00A1AF24: (0x00E84C90, 'containsIndex:'),
        0x00A1AF28: (0x00E84C9C, 'addIndex:'),
        0x00A1AF2C: (0x00E84C98, 'addObject:'),
        0x00A1AF30: (0x00E84C94, 'numberWithInt:'),
        0x00A1B788: (0x00E84C70, 'macroTiles'),
        0x00A1B78C: (0x00E84C2C, 'dynamicWorld'),
        0x00A1B790: (0x00E84CA0, 'saveSunlightChangedAtPos:'),
        0x00A1B79C: (0x00E84CAC, 'createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:'),
        0x00A1B7A4: (0x00E84CA8, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
        0x00A1B7BC: (0x00E84CA4, 'loadGlowBlockIfNeededAtPos:tile:'),
        0x00A1B7C0: (0x00E84C90, 'containsIndex:'),
        0x00A1B7C4: (0x00E84C9C, 'addIndex:'),
        0x00A1B7C8: (0x00E84C98, 'addObject:'),
        0x00A1B7CC: (0x00E84C94, 'numberWithInt:'),
    },
    classrefs={0x00A1AF34: (0x00E8AE74, 'OBJC_CLASS_$_NSNumber')},
    imports={
        0x00A1AAA0: (MSGSEND_GOT_SLOT, 'objc_msgSend'),
        0x00A1B784: (MSGSEND_GOT_SLOT, 'objc_msgSend'),
    },
    instructions=[
        (0x00A19DF0, 'ldrb r0, [r0, 9]'),
        (0x00A19E48, 'strb r0, [r1, 7]'),
        (0x00A19E6C, 'movw r0, 0xef'),
        (0x00A19E74, 'strb r0, [r1, 7]'),
        (0x00A19F00, 'ldrb r0, [r0, 7]'),
        (0x00A1A4E4, 'movw r0, 2'),
        (0x00A1A504, 'movw r0, 8'),
        (0x00A1A530, 'movw r0, 0x10'),
        (0x00A1A550, 'movw r0, 0x41'),
        (0x00A1AB70, 'strb r0, [r1, 7]'),
        (0x00A1AC64, 'mov r1, 0x33'),
        (0x00A1ACF4, 'mov r1, 0x35'),
        (0x00A1AE18, 'mov r1, 0x39'),
        (0x00A1AEA8, 'mov r1, 0x3b'),
        (0x00A1AFA8, 'strb r0, [r1, 3]'),
    ],
    calls=[

        (0x00a19ce4, 'blx r6'),
        (0x00a19cf4, 'blx r2'),
        (0x00a19d10, 'blx r3'),
        (0x00a19d28, 'blx r3'),
        (0x00a19d50, 'blx r3'),
        (0x00a19d60, 'blx r2'),
        (0x00a19d78, 'bl sym.getWorldPosForWorldIndex_int__int__int__World_'),
        (0x00a19db8, 'blx r2'),
        (0x00a19dd4, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
        (0x00a19e00, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a19eb4, 'blx r2'),
        (0x00a19ed0, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'),
        (0x00a19ee4, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a19f3c, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a19f80, 'blx r3'),
        (0x00a19ff8, 'blx r4'),
        (0x00a1a018, 'blx r3'),
        (0x00a1a030, 'blx r3'),
        (0x00a1a048, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a0a0, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1a0e4, 'blx r3'),
        (0x00a1a15c, 'blx r4'),
        (0x00a1a17c, 'blx r3'),
        (0x00a1a194, 'blx r3'),
        (0x00a1a1ac, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a204, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1a248, 'blx r3'),
        (0x00a1a2c0, 'blx r4'),
        (0x00a1a2e0, 'blx r3'),
        (0x00a1a2f8, 'blx r3'),
        (0x00a1a310, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a368, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1a3ac, 'blx r3'),
        (0x00a1a424, 'blx r4'),
        (0x00a1a444, 'blx r3'),
        (0x00a1a45c, 'blx r3'),
        (0x00a1a48c, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a4a8, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a520, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
        (0x00a1a540, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a5bc, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a5d8, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a640, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a664, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
        (0x00a1a6dc, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a6f8, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a760, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a784, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
        (0x00a1a7fc, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a818, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a880, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a8a4, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
        (0x00a1a920, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1a93c, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a9a4, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1a9c8, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
        (0x00a1aa44, 'bl sym.tileAtWorldPositionLoaded_int__int__World_'),
        (0x00a1aa60, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1aad0, 'bl sym.tileIsAirOrSnow_Tile_'),
        (0x00a1aaf4, 'bl sym.tileIsSemiTransparentSolidBlock_Tile_'),
        (0x00a1ab8c, 'bl sym.makeIntpair_int__int_'),
        (0x00a1abac, 'bl loc.imp.objc_msgSend'),
        (0x00a1abc0, 'bl sym.tileRequiresGlowBlock_Tile_'),
        (0x00a1abe8, 'bl loc.imp.objc_msgSend'),
        (0x00a1ac00, 'bl sym.makeIntpair_int__int_'),
        (0x00a1ac30, 'bl loc.imp.objc_msgSend'),
        (0x00a1ac84, 'bl loc.imp.objc_msgSend'),
        (0x00a1ac9c, 'bl sym.makeIntpair_int__int_'),
        (0x00a1acd8, 'bl loc.imp.objc_msgSend'),
        (0x00a1ad14, 'bl loc.imp.objc_msgSend'),
        (0x00a1ad2c, 'bl sym.makeIntpair_int__int_'),
        (0x00a1ad68, 'bl loc.imp.objc_msgSend'),
        (0x00a1ada8, 'bl loc.imp.objc_msgSend'),
        (0x00a1adc0, 'bl sym.makeIntpair_int__int_'),
        (0x00a1adfc, 'bl loc.imp.objc_msgSend'),
        (0x00a1ae38, 'bl loc.imp.objc_msgSend'),
        (0x00a1ae50, 'bl sym.makeIntpair_int__int_'),
        (0x00a1ae8c, 'bl loc.imp.objc_msgSend'),
        (0x00a1aec8, 'bl loc.imp.objc_msgSend'),
        (0x00a1aee0, 'bl sym.makeIntpair_int__int_'),
        (0x00a1af1c, 'bl loc.imp.objc_msgSend'),
        (0x00a1afd4, 'bl loc.imp.objc_msgSend'),
        (0x00a1aff8, 'bl sym.makeIntpair_int__int_'),
        (0x00a1b040, 'bl loc.imp.objc_msgSend'),
        (0x00a1b0a0, 'blx r2'),
        (0x00a1b0bc, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'),
        (0x00a1b0e0, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1b124, 'blx r3'),
        (0x00a1b19c, 'blx r4'),
        (0x00a1b1bc, 'blx r3'),
        (0x00a1b1d4, 'blx r3'),
        (0x00a1b1fc, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1b240, 'blx r3'),
        (0x00a1b2b8, 'blx r4'),
        (0x00a1b2d8, 'blx r3'),
        (0x00a1b2f0, 'blx r3'),
        (0x00a1b318, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1b35c, 'blx r3'),
        (0x00a1b3d4, 'blx r4'),
        (0x00a1b3f4, 'blx r3'),
        (0x00a1b40c, 'blx r3'),
        (0x00a1b434, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1b478, 'blx r3'),
        (0x00a1b4f0, 'blx r4'),
        (0x00a1b510, 'blx r3'),
        (0x00a1b528, 'blx r3'),
        (0x00a1b554, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1b598, 'blx r3'),
        (0x00a1b610, 'blx r4'),
        (0x00a1b630, 'blx r3'),
        (0x00a1b648, 'blx r3'),
        (0x00a1b674, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a1b6b8, 'blx r3'),
        (0x00a1b730, 'blx r4'),
        (0x00a1b750, 'blx r3'),
        (0x00a1b768, 'blx r3'),
    ],
    branches=[
        (0x00a19de8, 'beq', 0x00a1b77c),
        (0x00a19df8, 'ble', 0x00a1b77c),
        (0x00a19e0c, 'beq', 0x00a19e20),
        (0x00a19e1c, 'beq', 0x00a19e40),
        (0x00a19e2c, 'beq', 0x00a19e40),
        (0x00a19e3c, 'bne', 0x00a1a468),
        (0x00a19e58, 'beq', 0x00a19e6c),
        (0x00a19e68, 'bne', 0x00a19e78),
        (0x00a19ef8, 'beq', 0x00a1a038),
        (0x00a19f08, 'beq', 0x00a1a038),
        (0x00a19f18, 'beq', 0x00a1a038),
        (0x00a19f28, 'beq', 0x00a1a038),
        (0x00a19f4c, 'blt', 0x00a1a034),
        (0x00a19f8c, 'bne', 0x00a1a034),
        (0x00a1a034, 'b', 0x00a1a038),
        (0x00a1a05c, 'beq', 0x00a1a19c),
        (0x00a1a06c, 'beq', 0x00a1a19c),
        (0x00a1a07c, 'beq', 0x00a1a19c),
        (0x00a1a08c, 'beq', 0x00a1a19c),
        (0x00a1a0b0, 'blt', 0x00a1a198),
        (0x00a1a0f0, 'bne', 0x00a1a198),
        (0x00a1a198, 'b', 0x00a1a19c),
        (0x00a1a1c0, 'beq', 0x00a1a300),
        (0x00a1a1d0, 'beq', 0x00a1a300),
        (0x00a1a1e0, 'beq', 0x00a1a300),
        (0x00a1a1f0, 'beq', 0x00a1a300),
        (0x00a1a214, 'blt', 0x00a1a2fc),
        (0x00a1a254, 'bne', 0x00a1a2fc),
        (0x00a1a2fc, 'b', 0x00a1a300),
        (0x00a1a324, 'beq', 0x00a1a464),
        (0x00a1a334, 'beq', 0x00a1a464),
        (0x00a1a344, 'beq', 0x00a1a464),
        (0x00a1a354, 'beq', 0x00a1a464),
        (0x00a1a378, 'blt', 0x00a1a460),
        (0x00a1a3b8, 'bne', 0x00a1a460),
        (0x00a1a460, 'b', 0x00a1a464),
        (0x00a1a464, 'b', 0x00a1b778),
        (0x00a1a4a0, 'beq', 0x00a1a5a4),
        (0x00a1a4b4, 'beq', 0x00a1a4e4),
        (0x00a1a4c4, 'beq', 0x00a1a4d8),
        (0x00a1a4d4, 'bne', 0x00a1a4e4),
        (0x00a1a4e0, 'b', 0x00a1a588),
        (0x00a1a500, 'bgt', 0x00a1a50c),
        (0x00a1a518, 'beq', 0x00a1a530),
        (0x00a1a52c, 'beq', 0x00a1a53c),
        (0x00a1a538, 'b', 0x00a1a55c),
        (0x00a1a54c, 'bne', 0x00a1a558),
        (0x00a1a558, 'b', 0x00a1a55c),
        (0x00a1a574, 'bge', 0x00a1a580),
        (0x00a1a594, 'ble', 0x00a1a5a0),
        (0x00a1a5a0, 'b', 0x00a1a5a4),
        (0x00a1a5d0, 'beq', 0x00a1a6c4),
        (0x00a1a5e4, 'beq', 0x00a1a614),
        (0x00a1a5f4, 'beq', 0x00a1a608),
        (0x00a1a604, 'bne', 0x00a1a614),
        (0x00a1a610, 'b', 0x00a1a6a8),
        (0x00a1a630, 'bgt', 0x00a1a63c),
        (0x00a1a64c, 'bne', 0x00a1a67c),
        (0x00a1a65c, 'beq', 0x00a1a67c),
        (0x00a1a670, 'bne', 0x00a1a67c),
        (0x00a1a694, 'bge', 0x00a1a6a0),
        (0x00a1a6b4, 'ble', 0x00a1a6c0),
        (0x00a1a6c0, 'b', 0x00a1a6c4),
        (0x00a1a6f0, 'beq', 0x00a1a7e4),
        (0x00a1a704, 'beq', 0x00a1a734),
        (0x00a1a714, 'beq', 0x00a1a728),
        (0x00a1a724, 'bne', 0x00a1a734),
        (0x00a1a730, 'b', 0x00a1a7c8),
        (0x00a1a750, 'bgt', 0x00a1a75c),
        (0x00a1a76c, 'bne', 0x00a1a79c),
        (0x00a1a77c, 'beq', 0x00a1a79c),
        (0x00a1a790, 'bne', 0x00a1a79c),
        (0x00a1a7b4, 'bge', 0x00a1a7c0),
        (0x00a1a7d4, 'ble', 0x00a1a7e0),
        (0x00a1a7e0, 'b', 0x00a1a7e4),
        (0x00a1a810, 'beq', 0x00a1a904),
        (0x00a1a824, 'beq', 0x00a1a854),
        (0x00a1a834, 'beq', 0x00a1a848),
        (0x00a1a844, 'bne', 0x00a1a854),
        (0x00a1a850, 'b', 0x00a1a8e8),
        (0x00a1a870, 'bgt', 0x00a1a87c),
        (0x00a1a88c, 'bne', 0x00a1a8bc),
        (0x00a1a89c, 'beq', 0x00a1a8bc),
        (0x00a1a8b0, 'bne', 0x00a1a8bc),
        (0x00a1a8d4, 'bge', 0x00a1a8e0),
        (0x00a1a8f4, 'ble', 0x00a1a900),
        (0x00a1a900, 'b', 0x00a1a904),
        (0x00a1a934, 'beq', 0x00a1aa28),
        (0x00a1a948, 'beq', 0x00a1a978),
        (0x00a1a958, 'beq', 0x00a1a96c),
        (0x00a1a968, 'bne', 0x00a1a978),
        (0x00a1a974, 'b', 0x00a1aa0c),
        (0x00a1a994, 'bgt', 0x00a1a9a0),
        (0x00a1a9b0, 'bne', 0x00a1a9e0),
        (0x00a1a9c0, 'beq', 0x00a1a9e0),
        (0x00a1a9d4, 'bne', 0x00a1a9e0),
        (0x00a1a9f8, 'bge', 0x00a1aa04),
        (0x00a1aa18, 'ble', 0x00a1aa24),
        (0x00a1aa24, 'b', 0x00a1aa28),
        (0x00a1aa58, 'beq', 0x00a1ab54),
        (0x00a1aa6c, 'beq', 0x00a1aaa4),
        (0x00a1aa7c, 'beq', 0x00a1aa90),
        (0x00a1aa8c, 'bne', 0x00a1aaa4),
        (0x00a1aa98, 'b', 0x00a1ab38),
        (0x00a1aac0, 'bgt', 0x00a1aacc),
        (0x00a1aadc, 'bne', 0x00a1ab0c),
        (0x00a1aaec, 'beq', 0x00a1ab0c),
        (0x00a1ab00, 'bne', 0x00a1ab0c),
        (0x00a1ab24, 'bge', 0x00a1ab30),
        (0x00a1ab44, 'ble', 0x00a1ab50),
        (0x00a1ab50, 'b', 0x00a1ab54),
        (0x00a1ab64, 'ble', 0x00a1b774),
        (0x00a1abb8, 'bne', 0x00a1b064),
        (0x00a1abcc, 'beq', 0x00a1ac50),
        (0x00a1ac34, 'b', 0x00a1b060),
        (0x00a1ac5c, 'bne', 0x00a1ace0),
        (0x00a1acdc, 'b', 0x00a1b05c),
        (0x00a1acec, 'bne', 0x00a1ad74),
        (0x00a1ad6c, 'b', 0x00a1b058),
        (0x00a1ad80, 'bne', 0x00a1ae04),
        (0x00a1ae00, 'b', 0x00a1b054),
        (0x00a1ae10, 'bne', 0x00a1ae94),
        (0x00a1ae90, 'b', 0x00a1b050),
        (0x00a1aea0, 'bne', 0x00a1af38),
        (0x00a1af20, 'b', 0x00a1b04c),
        (0x00a1af44, 'beq', 0x00a1af68),
        (0x00a1af54, 'beq', 0x00a1af68),
        (0x00a1af64, 'bne', 0x00a1b048),
        (0x00a1afb8, 'bne', 0x00a1b044),
        (0x00a1b044, 'b', 0x00a1b048),
        (0x00a1b048, 'b', 0x00a1b04c),
        (0x00a1b04c, 'b', 0x00a1b050),
        (0x00a1b050, 'b', 0x00a1b054),
        (0x00a1b054, 'b', 0x00a1b058),
        (0x00a1b058, 'b', 0x00a1b05c),
        (0x00a1b05c, 'b', 0x00a1b060),
        (0x00a1b060, 'b', 0x00a1b064),
        (0x00a1b0cc, 'ble', 0x00a1b1dc),
        (0x00a1b0f0, 'blt', 0x00a1b1d8),
        (0x00a1b130, 'bne', 0x00a1b1d8),
        (0x00a1b1d8, 'b', 0x00a1b1dc),
        (0x00a1b1e8, 'ble', 0x00a1b2f8),
        (0x00a1b20c, 'blt', 0x00a1b2f4),
        (0x00a1b24c, 'bne', 0x00a1b2f4),
        (0x00a1b2f4, 'b', 0x00a1b2f8),
        (0x00a1b304, 'ble', 0x00a1b414),
        (0x00a1b328, 'blt', 0x00a1b410),
        (0x00a1b368, 'bne', 0x00a1b410),
        (0x00a1b410, 'b', 0x00a1b414),
        (0x00a1b420, 'ble', 0x00a1b530),
        (0x00a1b444, 'blt', 0x00a1b52c),
        (0x00a1b484, 'bne', 0x00a1b52c),
        (0x00a1b52c, 'b', 0x00a1b530),
        (0x00a1b53c, 'ble', 0x00a1b650),
        (0x00a1b564, 'blt', 0x00a1b64c),
        (0x00a1b5a4, 'bne', 0x00a1b64c),
        (0x00a1b64c, 'b', 0x00a1b650),
        (0x00a1b65c, 'ble', 0x00a1b770),
        (0x00a1b684, 'blt', 0x00a1b76c),
        (0x00a1b6c4, 'bne', 0x00a1b76c),
        (0x00a1b76c, 'b', 0x00a1b770),
        (0x00a1b770, 'b', 0x00a1b774),
        (0x00a1b774, 'b', 0x00a1b778),
        (0x00a1b778, 'b', 0x00a1b77c),
    ],
)


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def reloc_symbols(path: Path) -> dict:
    elf = ELFFile(io.BytesIO(path.read_bytes()))
    out = {}
    for section in elf.iter_sections():
        if not hasattr(section, 'iter_relocations'):
            continue
        try:
            symbols = elf.get_section(section['sh_link'])
        except Exception:
            continue
        for rel in section.iter_relocations():
            if rel['r_info_sym']:
                out[rel['r_offset']] = symbols.get_symbol(rel['r_info_sym']).name
    return out


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    relocs = reloc_symbols(path)

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    spec = SPEC
    text = (NATIVE / spec['disasm']).read_text()
    words = verify_disassembly(memory, text, spec['start'], spec['end'])
    rows = {}
    for m in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
        rows[int(m.group(1), 16)] = m.group(2).split(';')[0].strip()

    base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
    if base != EXPECTED_BASE:
        raise ValueError(f'PIC base drift {base:#x}')

    selectors = {}
    for cell, (expected_slot, expected_name) in spec['selectors'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'selector cell {cell:#x} -> {slot:#x}, expected {expected_slot:#x}')
        got = cstr(memory.word(slot))
        if got != expected_name:
            raise ValueError(f'selector cell drifted at {cell:#x}: {got!r} != {expected_name!r}')
        selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

    classrefs = {}
    for cell, (expected_slot, expected_symbol) in spec['classrefs'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'classref cell {cell:#x} -> {slot:#x}')
        got = relocs.get(slot)
        if got != expected_symbol:
            raise ValueError(f'classref drifted at {cell:#x}: {got!r}')
        classrefs[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got}

    for cell, (expected_slot, expected_name) in spec['imports'].items():
        slot = (base + signed(memory.word(cell))) & 0xffffffff
        if slot != expected_slot:
            raise ValueError(f'import cell {cell:#x} -> {slot:#x}')
        got = memory.imports.get(slot)
        if got != expected_name:
            raise ValueError(f'import drifted at {cell:#x}: {got!r}')
        selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got}

    listed = {a for a, ins in rows.items() if re.match(r'^blx?\s', ins)}
    expected_sites = {site for site, _ in spec['calls']}
    if listed != expected_sites:
        raise ValueError(f'call site set drifted: {sorted(listed ^ expected_sites)}')
    calls = []
    for site, route in spec['calls']:
        if rows[site] != route:
            raise ValueError(f'call route drifted at {site:#x}: {rows[site]!r} != {route!r}')
        target = None
        if route.startswith('bl '):
            target = bl_target(site, memory.word(site))
            expected = ROUTE_TARGETS.get(route)
            if expected is None:
                raise ValueError(f'no pinned target for route {route!r}')
            if target != expected:
                raise ValueError(f'bl target drifted at {site:#x}: {target:#x} != {expected:#x}')
        calls.append({'site': f'0x{site:08x}', 'route': route,
                      'callee': f'0x{target:08x}' if target else None})

    listed_branches = {(a, m.group(1), int(m.group(2), 16))
                       for a, ins in rows.items()
                       for m in [re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)]
                       if m and m.group(1) not in ('bl', 'blx')}
    expected_branches = {(a, mn, d) for a, mn, d in spec['branches']}
    if listed_branches != expected_branches:
        raise ValueError(f'branch set drifted: {sorted(listed_branches ^ expected_branches)}')

    for address, expected_text in spec['instructions']:
        if rows.get(address) != expected_text:
            raise ValueError(f'instruction drifted at {address:#x}: '
                             f'{rows.get(address)!r} != {expected_text!r}')

    method = {
        'name': spec['name'],
        'method': spec['method'],
        'types': spec['types'],
        'imp': f"0x{spec['start']:08x}",
        'boundary_end': f"0x{spec['end']:08x}",
        'boundary': spec['boundary'],
        'verified_words': words,
        'pic_base': f'0x{base:08x}',
        'selectors': selectors,
        'classrefs': classrefs,
        'calls': calls,
        'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                      'destination': f'0x{d:08x}'}
                     for a, mn, d in spec['branches']],
        'semantics': SEMANTICS,
    }
    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': 'WorldHelper recursivelyUpdateSunLightWithList: (single-step light-up engine)',
        'claim': ('static bounded-body map with per-instruction anchors; the '
                  'dynamic-object factories behind the content activation, '
                  'Tile/MacroTile internals and runtime values are outside '
                  'this body'),
        'classes': [method],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'worldhelper_recursiveupdate.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale worldhelper_recursiveupdate.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
