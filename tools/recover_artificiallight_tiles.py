#!/usr/bin/env python3
"""Hash-gated recovery of the ArtificialLight register/unregister pair.

Two bodies from the pinned original libApplication.so (1.7.6, armeabi-v7a,
SHA-256 733d8210…b94c7):

  -[ArtificialLight addToTiles]        0x00a92238 .. 0x00a93160 (984 words)
  -[ArtificialLight removeFromTiles]   0x00a93198 .. 0x00a93728 (356 words)

The artificial-light (torch/lamp) half of the lighting system: addToTiles
seeds an std::list with the light's own world index and drains it through
-[self recursivelyUpdateLightWithList:] (the 3075-word engine, NOT mapped
here), then walks the light's contributionGrid/diameter square applying the
per-channel colour/heats (maxRed..maxHeat scaled by v0/(radius*10)) to the
tiles' 16-bit accumulators (tile[0xe]/[0x10]/[0x12]/[0x14]), marks the
addedGrid cell, loads glow blocks or spawns the torch kinds (tile[0xb]
0x34..0x3c), recalcs the draw block and reports lightChangedAtMacroPos:.
removeFromTiles is the exact inverse: clears the mark, subtracts the grid
contributions, zeroes all four accumulators when any exceeds the 0xdfff
underflow guard, recalcs and reports.

Every instruction word is re-verified against the pinned ELF; PIC base,
selector/ivar/import cells, all call sites (with pinned direct-bl targets),
all branches and key instructions are anchored.
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
    'bl sym.imp._Unwind_Resume': 0x001C29C0,
    'bl sym.makeIntpair_int__int_': 0x004B49FC,
    'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_': 0x00A18F68,
    'bl sym.tileAtWorldPosition_int__int__MacroTile__World_': 0x00A16E68,
    'bl sym.tileRequiresGlowBlock_Tile_': 0x00A14824,
    'bl sym.worldIndexAtWorldPosition_int__int__World_': 0x00A156A8,
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_': 0x00A91E48,
    'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___._list__': 0x00A93160,
}

SEMANTICS_ADD = (
    'Step 1 - propagation seed: an std::list<unsigned int> work list is '
    'constructed and push_back(worldIndexAtWorldPosition(self.pos.x, self.pos.y, '
    'self.world)); the body drains it through '
    '-[self recursivelyUpdateLightWithList:&list] behind a compiler-generated '
    'list-state loop (condition byte-tested at the list scaffold 0xa92324..0xa9236c, '
    'call at 0xa92388) - the propagation engine itself is outside this body. '
    'Step 2 - contribution square: for i in [0, diameter) and j in [0, diameter): '
    'idx = i*diameter + j; skip unless addedGrid[idx] == 0; v = '
    'contributionGrid[idx*5] (int16); skip when v <= 0; '
    'x = contributionGridOrigin.x + j; y = contributionGridOrigin.y + i; '
    'mt = [self.world macroTiles]; tile = tileAtWorldPosition(x, y, mt, self.world); '
    'skip when !tile; '
    'v0 = (float)v / ((float)radius * 5 * 2) i.e. /(radius*10); '
    'contributionGrid[idx*5+1] = (int16)(maxRed   * v0); '
    'contributionGrid[idx*5+2] = (int16)(maxGreen * v0); '
    'contributionGrid[idx*5+3] = (int16)(maxBlue  * v0); '
    'contributionGrid[idx*5+4] = (int16)(maxHeat  * v0); '
    'tile[0xe] += grid[+1]; tile[0x10] += grid[+2]; tile[0x12] += grid[+3]; '
    'tile[0x14] += grid[+4] (16-bit unsigned adds); addedGrid[idx] = 1; '
    'then content activation: when tileRequiresGlowBlock(tile) -> '
    '[dw loadGlowBlockIfNeededAtPos:(x, y) tile:tile] with '
    'dw = [self.world dynamicWorld]; else the tile[0xb] chain rewrites the '
    'byte down one and spawns via [dw addTorchAtPos:(x, y) ofType:kind dataA:0 '
    'dataB:0 saveDict:nil placedByClient:0]: 0x34->0x33 kind 0x4b, 0x36->0x35 '
    'kind 0x4c, 0x38->0x37 kind 0x56, 0x3a->0x39 kind 0x57, 0x3c->0x3b kind '
    '0x58; when tile[3] in {0x5e, 0x90, 0x91}: loadTroll = (tile[3] != 0x91), '
    'loadTreasure = (tile[3] != 0x90), tile[3] = 0, and when tile[0] == 2: '
    '[dw createTreasureChestOrTrollAtTile:tile atPos:(x, y) loadTroll: '
    'loadTreasure:]. '
    'Per-cell tail: wrap px = origin.x + j by worldWidthMacro (px += w*32 when '
    'px < 0, px -= w*32 when px >= w*32), py = origin.y + i; '
    'recalculateDrawBlockLightingForTile(px, py, [self.world macroTiles], '
    'self.world); then [dw lightChangedAtMacroPos:(px>>5, py>>5) sendReliably:1].'
)

SEMANTICS_REMOVE = (
    'The exact inverse walk. For i in [0, diameter) and j in [0, diameter): '
    'idx = i*diameter + j; skip unless addedGrid[idx] == 1; v = '
    'contributionGrid[idx*5] (int16); skip when v <= 0; addedGrid[idx] = 0; '
    'x = contributionGridOrigin.x + j; y = contributionGridOrigin.y + i; '
    'mt = [self.world macroTiles]; tile = tileAtWorldPosition(x, y, mt, '
    'self.world); skip when !tile; '
    'tile[0xe] -= grid[+1]; tile[0x10] -= grid[+2]; tile[0x12] -= grid[+3]; '
    'tile[0x14] -= grid[+4]; underflow guard: when any of tile[0xe], '
    'tile[0x10], tile[0x12] (unsigned 16-bit) exceeds 0xdfff (movw 0xdfff '
    'anchored), all four accumulators are zeroed; '
    'px = origin.x + j wrapped by worldWidthMacro (px >= w*32 -> px -= w*32, '
    'then px < 0 -> px += w*32); recalculateDrawBlockLightingForTile(x, y, mt, '
    'self.world); then [self.dynamicWorld lightChangedAtMacroPos:(px>>5, '
    'py>>5) sendReliably:1]. No list, no propagation engine - the removal is '
    'purely the contribution subtraction plus reporting.'
)

SEMANTICS = (
    'Gates: if (clientLightBlockIndex == 0) return; dw = [world dynamicWorld]; '
    'if ([dw isClient]) return; if ([blockhead '
    'isClientBlockheadBeingControlledByServer]) return. '
    'bx32 = physicalBlock->blockX << 5; by32 = physicalBlock->blockY << 5; '
    'extra = (clientLightBlockIndex != -1) ? physicalBlock[0x20 + idx*4] : 0; '
    'when extra != 0 it is first loaded via [world '
    'loadLightBlockForClientLightBlockIndex:idx intoPhysicalBlock:pb]. '
    'center = blockhead ? [blockhead pos] : [world startPortalPos] (nil world -> '
    '{0,0}); vr = blockhead ? [blockhead viewRadius] : 4; margin = max(22 - vr, 0). '
    'Wrap center.x into the macro width: if (center.x - bx32 < -(w<<4)) center.x += w<<5; '
    'if (center.x - bx32 > (w<<4)) center.x -= w<<5 (w = [world worldWidthMacro]); same for '
    'center.y. Cull: return unless center.x in (bx32-vr, bx32+32+vr) and center.y in '
    '(by32-vr, by32+32+vr). '
    'Per tile loop (i = 0..31 rows, j = 0..31 cols): tile = '
    'physicalBlock->tiles + (i*32+j)*64; worldPos = (bx32+j, by32+i); '
    'srcByte = extra ? extra[i*32+j] : tile[6]; dx = center.x - (bx32+j), '
    'if (dx < 0) dx += 1, then wrapped by the same +-w<<4 / w<<5 rule; dy analog; '
    'd2 = dx*dx + dy*dy; if (d2 >= 0x1e4) continue; '
    't = ((float)sqrtf(d2) + (float)margin) / 2.0f; u = 4.0f - t * 4.0f; '
    'lightI = (int)(255.0f * u); newLight = (lightI > srcByte) ? min(lightI, 0xff) : srcByte; '
    'if (tile[9] == 0) { if (newLight > 0) { tile[9] = newLight; flag36 = 1; '
    'if (backWallIsMutable(tile) && !tileIsSolid(tile) && tile[3] == 0 && tile[0] != 3) '
    '[WorldHelper updateSunLightForTile:tile atPos:worldPos world:world]; } } '
    'else if (newLight > tile[9]) { tile[9] = newLight; flag36 = 1; } '
    'if (tile[0] == 3) { weather = [world getWeatherFractionForPos:worldPos]; '
    'dayNight = [world getDayNightFractionForX:(float)worldPos.x '
    'atWorldTime:(double)[world worldTime]]; season = seasonForWorldX(worldPos.x, '
    '(double)[world worldTime], world); temp = currentTemperatureForTileAtWorldPos(tile, '
    'worldPos, weather, dayNight, season, world); '
    'if (temp < 0) [world fillTile:tile atPos:worldPos withType:0x422]; } '
    'if (newLight != srcByte) { if (extra) extra[i*32+j] = newLight; else tile[6] = newLight; '
    'flag35 = 1; } '
    'After the loops: if (flag36) [dw lightChangedAtMacroPos:makeIntpair(pb.blockX, '
    'pb.blockY) sendReliably:0 sendAtAll:0]; if (flag35) [dw '
    'exploreLightChangedAtMacroPos:makeIntpair(pb.blockX, pb.blockY) '
    'clientLightBlockIndex:idx]. '
    'The light falloff is the exact arithmetic: light = (int)(255.0f * (4.0f - 2.0f*'
    '(((float)sqrtf(dx*dx+dy*dy) + (float)margin) / 2.0f)) as the ARM computes it '
    '(margins max(22-vr,0)); tiles at d2 >= 0x1e4 are skipped.'
)

SPECS = [
    dict(
        name='addToTiles',
        method='ArtificialLight -[addToTiles]',
        types='v8@0:4',
        start=0x00A92238, end=0x00A93160,
        disasm='disasm_artificiallight_addtotiles.txt',
        base_add=0x00A92248, base_literal=0x00A9315C,
        boundary='own ARM.exidx bound 0x00a93160 (end of the region; next method IMP 0x00a93198)',
        selectors={
            0x00A930A8: (0x00E854CC, 'macroTiles'),
            0x00A930CC: (0x00E854D8, 'dynamicWorld'),
            0x00A930D4: (0x00E854E4, 'createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:'),
            0x00A930E4: (0x00E854E0, 'addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:'),
            0x00A93124: (0x00E854DC, 'loadGlowBlockIfNeededAtPos:tile:'),
            0x00A93138: (0x00E854D0, 'worldWidthMacro'),
            0x00A9314C: (0x00E854E8, 'lightChangedAtMacroPos:sendReliably:'),
            0x00A93154: (0x00E854D4, 'recursivelyUpdateLightWithList:'),
        },
        ivars={
            0x00A93084: (0x0105C390, 'OBJC_IVAR_$_DynamicObject.pos', 16),
            0x00A9308C: (0x0105C394, 'OBJC_IVAR_$_DynamicObject.world', 4),
            0x00A93090: (0x0105EA18, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
            0x00A93094: (0x0105EA28, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
            0x00A93098: (0x0105EA1C, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
            0x00A930A0: (0x0105EA14, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
            0x00A930B4: (0x0105EA20, 'OBJC_IVAR_$_ArtificialLight.radius', 80),
            0x00A930B8: (0x0105EA2C, 'OBJC_IVAR_$_ArtificialLight.maxRed', 64),
            0x00A930BC: (0x0105EA30, 'OBJC_IVAR_$_ArtificialLight.maxGreen', 68),
            0x00A930C0: (0x0105EA34, 'OBJC_IVAR_$_ArtificialLight.maxBlue', 72),
            0x00A930C4: (0x0105EA38, 'OBJC_IVAR_$_ArtificialLight.maxHeat', 76),
        },
        imports={},
        instructions=[
            (0x00A924A0, 'ldrsh r1, [r1]'),
            (0x00A9253C + 4, 'movs r0, r0'),
        ] if False else [
            (0x00A924A0, 'ldrsh r1, [r1]'),
            (0x00A926E0, 'ldrsh r0, [r0, 2]'),
            (0x00A926F0, 'strh r0, [r1, 0xe]'),
            (0x00A9271C, 'strh r0, [r1, 0x10]'),
            (0x00A92748, 'strh r0, [r1, 0x12]'),
            (0x00A92774, 'strh r0, [r1, 0x14]'),
            (0x00A92794, 'strb r2, [r1, r0]'),
            (0x00A92910, 'mov ip, 0x4b'),
            (0x00A929E0, 'mov ip, 0x4c'),
            (0x00A92AB0, 'mov ip, 0x56'),
            (0x00A92B80, 'mov ip, 0x57'),
            (0x00A92C50, 'mov ip, 0x58'),
        ],
        semantics=SEMANTICS_ADD,
        calls=[
        (0x00a922f8, 'bl sym.worldIndexAtWorldPosition_int__int__World_'),
        (0x00a92318, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'),
        (0x00a92388, 'bl loc.imp.objc_msgSend'),
        (0x00a923a4, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___._list__'),
        (0x00a92508, 'bl loc.imp.objc_msgSend'),
        (0x00a9253c, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
        (0x00a9279c, 'bl sym.tileRequiresGlowBlock_Tile_'),
        (0x00a927dc, 'bl loc.imp.objc_msgSend'),
        (0x00a9281c, 'bl sym.makeIntpair_int__int_'),
        (0x00a9284c, 'bl loc.imp.objc_msgSend'),
        (0x00a92898, 'bl loc.imp.objc_msgSend'),
        (0x00a928d8, 'bl sym.makeIntpair_int__int_'),
        (0x00a9291c, 'bl loc.imp.objc_msgSend'),
        (0x00a92968, 'bl loc.imp.objc_msgSend'),
        (0x00a929a8, 'bl sym.makeIntpair_int__int_'),
        (0x00a929ec, 'bl loc.imp.objc_msgSend'),
        (0x00a92a38, 'bl loc.imp.objc_msgSend'),
        (0x00a92a78, 'bl sym.makeIntpair_int__int_'),
        (0x00a92abc, 'bl loc.imp.objc_msgSend'),
        (0x00a92b08, 'bl loc.imp.objc_msgSend'),
        (0x00a92b48, 'bl sym.makeIntpair_int__int_'),
        (0x00a92b8c, 'bl loc.imp.objc_msgSend'),
        (0x00a92bd8, 'bl loc.imp.objc_msgSend'),
        (0x00a92c18, 'bl sym.makeIntpair_int__int_'),
        (0x00a92c5c, 'bl loc.imp.objc_msgSend'),
        (0x00a92d10, 'bl loc.imp.objc_msgSend'),
        (0x00a92d68, 'bl sym.makeIntpair_int__int_'),
        (0x00a92da8, 'bl loc.imp.objc_msgSend'),
        (0x00a92e28, 'bl loc.imp.objc_msgSend'),
        (0x00a92e5c, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'),
        (0x00a92eb4, 'bl loc.imp.objc_msgSend'),
        (0x00a92f00, 'bl loc.imp.objc_msgSend'),
        (0x00a92f5c, 'bl loc.imp.objc_msgSend'),
        (0x00a92fac, 'bl loc.imp.objc_msgSend'),
        (0x00a93000, 'bl sym.makeIntpair_int__int_'),
        (0x00a93030, 'bl loc.imp.objc_msgSend'),
        (0x00a9306c, 'bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___._list__'),
        (0x00a93080, 'bl sym.imp._Unwind_Resume'),
        ],
        branches=[
        (0x00a92300, 'b', 0x00a92304),
        (0x00a9231c, 'b', 0x00a92320),
        (0x00a92320, 'b', 0x00a92324),
        (0x00a9236c, 'beq', 0x00a923b0),
        (0x00a9238c, 'b', 0x00a92390),
        (0x00a92390, 'b', 0x00a92324),
        (0x00a923ac, 'b', 0x00a9307c),
        (0x00a923e0, 'bge', 0x00a93068),
        (0x00a92414, 'bge', 0x00a93054),
        (0x00a92470, 'bne', 0x00a93040),
        (0x00a924ac, 'ble', 0x00a93040),
        (0x00a92510, 'b', 0x00a92514),
        (0x00a92544, 'b', 0x00a92548),
        (0x00a9255c, 'beq', 0x00a9303c),
        (0x00a927a4, 'b', 0x00a927a8),
        (0x00a927b4, 'beq', 0x00a92858),
        (0x00a927e4, 'b', 0x00a927e8),
        (0x00a92820, 'b', 0x00a92824),
        (0x00a92850, 'b', 0x00a92854),
        (0x00a92854, 'b', 0x00a92dd0),
        (0x00a92864, 'bne', 0x00a92928),
        (0x00a928a0, 'b', 0x00a928a4),
        (0x00a928dc, 'b', 0x00a928e0),
        (0x00a92920, 'b', 0x00a92924),
        (0x00a92924, 'b', 0x00a92dcc),
        (0x00a92934, 'bne', 0x00a929f8),
        (0x00a92970, 'b', 0x00a92974),
        (0x00a929ac, 'b', 0x00a929b0),
        (0x00a929f0, 'b', 0x00a929f4),
        (0x00a929f4, 'b', 0x00a92dc8),
        (0x00a92a04, 'bne', 0x00a92ac8),
        (0x00a92a40, 'b', 0x00a92a44),
        (0x00a92a7c, 'b', 0x00a92a80),
        (0x00a92ac0, 'b', 0x00a92ac4),
        (0x00a92ac4, 'b', 0x00a92dc4),
        (0x00a92ad4, 'bne', 0x00a92b98),
        (0x00a92b10, 'b', 0x00a92b14),
        (0x00a92b4c, 'b', 0x00a92b50),
        (0x00a92b90, 'b', 0x00a92b94),
        (0x00a92b94, 'b', 0x00a92dc0),
        (0x00a92ba4, 'bne', 0x00a92c68),
        (0x00a92be0, 'b', 0x00a92be4),
        (0x00a92c1c, 'b', 0x00a92c20),
        (0x00a92c60, 'b', 0x00a92c64),
        (0x00a92c64, 'b', 0x00a92dbc),
        (0x00a92c74, 'beq', 0x00a92c98),
        (0x00a92c84, 'beq', 0x00a92c98),
        (0x00a92c94, 'bne', 0x00a92db8),
        (0x00a92ce8, 'bne', 0x00a92db4),
        (0x00a92d18, 'b', 0x00a92d1c),
        (0x00a92d6c, 'b', 0x00a92d70),
        (0x00a92dac, 'b', 0x00a92db0),
        (0x00a92db0, 'b', 0x00a92db4),
        (0x00a92db4, 'b', 0x00a92db8),
        (0x00a92db8, 'b', 0x00a92dbc),
        (0x00a92dbc, 'b', 0x00a92dc0),
        (0x00a92dc0, 'b', 0x00a92dc4),
        (0x00a92dc4, 'b', 0x00a92dc8),
        (0x00a92dc8, 'b', 0x00a92dcc),
        (0x00a92dcc, 'b', 0x00a92dd0),
        (0x00a92e30, 'b', 0x00a92e34),
        (0x00a92e60, 'b', 0x00a92e64),
        (0x00a92ebc, 'b', 0x00a92ec0),
        (0x00a92ed8, 'blt', 0x00a92f2c),
        (0x00a92f08, 'b', 0x00a92f0c),
        (0x00a92f28, 'b', 0x00a92f88),
        (0x00a92f34, 'bge', 0x00a92f84),
        (0x00a92f64, 'b', 0x00a92f68),
        (0x00a92f84, 'b', 0x00a92f88),
        (0x00a92fb4, 'b', 0x00a92fb8),
        (0x00a93004, 'b', 0x00a93008),
        (0x00a93034, 'b', 0x00a93038),
        (0x00a93038, 'b', 0x00a9303c),
        (0x00a9303c, 'b', 0x00a93040),
        (0x00a93040, 'b', 0x00a93044),
        (0x00a93050, 'b', 0x00a923f0),
        (0x00a93054, 'b', 0x00a93058),
        (0x00a93064, 'b', 0x00a923bc),
        ],
    ),
    dict(
        name='removeFromTiles',
        method='ArtificialLight -[removeFromTiles]',
        types='v8@0:4',
        start=0x00A93198, end=0x00A93728,
        disasm='disasm_artificiallight_removefromtiles.txt',
        base_add=0x00A931A8, base_literal=0x00A93724,
        boundary='own ARM.exidx bound 0x00a93728 (end of the region; next method IMP 0x00a93728 = +[objectType])',
        selectors={
            0x00A93700: (0x00E854CC, 'macroTiles'),
            0x00A93710: (0x00E854D0, 'worldWidthMacro'),
            0x00A93720: (0x00E854E8, 'lightChangedAtMacroPos:sendReliably:'),
        },
        ivars={
            0x00A936E8: (0x0105EA18, 'OBJC_IVAR_$_ArtificialLight.diameter', 92),
            0x00A936EC: (0x0105EA28, 'OBJC_IVAR_$_ArtificialLight.addedGrid', 60),
            0x00A936F0: (0x0105EA1C, 'OBJC_IVAR_$_ArtificialLight.contributionGrid', 56),
            0x00A936F8: (0x0105C394, 'OBJC_IVAR_$_DynamicObject.world', 4),
            0x00A93704: (0x0105EA14, 'OBJC_IVAR_$_ArtificialLight.contributionGridOrigin', 84),
            0x00A93718: (0x0105C3A8, 'OBJC_IVAR_$_DynamicObject.dynamicWorld', 8),
        },
        imports={0x00A936FC: (0x0105B7A0, 'objc_msgSend')},
        instructions=[
            (0x00A93300, 'strb lr, [r4]'),
            (0x00A933D0, 'ldrsh r2, [r2, 2]'),
            (0x00A933E0, 'strh r2, [r3, 0xe]'),
            (0x00A9340C, 'strh r2, [r3, 0x10]'),
            (0x00A93438, 'strh r2, [r3, 0x12]'),
            (0x00A93468, 'strh r2, [r3, 0x14]'),
            (0x00A93470, 'ldrh r2, [r2, 0xe]'),
            (0x00A93480, 'movw r0, 0xdfff'),
        ],
        semantics=SEMANTICS_REMOVE,
        calls=[
        (0x00a9335c, 'blx r2'),
        (0x00a93388, 'bl sym.tileAtWorldPosition_int__int__MacroTile__World_'),
        (0x00a9353c, 'bl loc.imp.objc_msgSend'),
        (0x00a93564, 'bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'),
        (0x00a935a8, 'bl loc.imp.objc_msgSend'),
        (0x00a935f8, 'bl loc.imp.objc_msgSend'),
        (0x00a93688, 'bl sym.makeIntpair_int__int_'),
        (0x00a936b0, 'bl loc.imp.objc_msgSend'),
        ],
        branches=[
        (0x00a931e8, 'bge', 0x00a936e0),
        (0x00a9321c, 'bge', 0x00a936cc),
        (0x00a93278, 'bne', 0x00a936b8),
        (0x00a932b4, 'ble', 0x00a936b8),
        (0x00a9339c, 'beq', 0x00a936b4),
        (0x00a9347c, 'bgt', 0x00a934a8),
        (0x00a93490, 'bgt', 0x00a934a8),
        (0x00a934a4, 'ble', 0x00a934cc),
        (0x00a935c0, 'blt', 0x00a93614),
        (0x00a936b4, 'b', 0x00a936b8),
        (0x00a936b8, 'b', 0x00a936bc),
        (0x00a936c8, 'b', 0x00a931f8),
        (0x00a936cc, 'b', 0x00a936d0),
        (0x00a936dc, 'b', 0x00a931c4),
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

    elf = None
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
            # symbol check via dynsym
            if not hasattr(recover, '_dynsym'):
                from elftools.elf.elffile import ELFFile as _ELF
                e = _ELF(io.BytesIO(data))
                syms = {}
                for sec in e.iter_sections():
                    if sec.name == '.dynsym':
                        for s in sec.iter_symbols():
                            if s['st_value']:
                                syms.setdefault(s['st_value'], s.name)
                recover._dynsym = syms
            symbol = recover._dynsym.get(entry, '')
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
        'batch': 'ArtificialLight register/unregister pair (addToTiles / removeFromTiles)',
        'claim': ('static bounded-body maps with per-instruction anchors; the '
                  'recursivelyUpdateLightWithList: propagation engine, '
                  'Tile/MacroTile internals and runtime values are outside '
                  'these bodies'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'artificiallight_tiles.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale artificiallight_tiles.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
