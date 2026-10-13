#!/usr/bin/env python3
"""Contract test for the ArtificialLight register/unregister batch.

Pins the doc and JSON to each other and to the recovered semantics: both
IMP/boundary pairs, per-class anchor counts, the contribution-square
semantics (grid scaling, tile accumulator offsets, torch kinds, underflow
guard, macro wrap) and the propagation-engine boundary.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/ARTIFICIALLIGHT_TILES.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/artificiallight_tiles.json').read_text())

def test_bodies():
    m = {c['name']: c for c in DATA['classes']}
    assert set(m) == {'addToTiles', 'removeFromTiles'}
    assert m['addToTiles']['imp'] == '0x00a92238'
    assert m['addToTiles']['boundary_end'] == '0x00a93160'
    assert m['addToTiles']['verified_words'] == 970
    assert m['removeFromTiles']['imp'] == '0x00a93198'
    assert m['removeFromTiles']['boundary_end'] == '0x00a93728'
    assert m['removeFromTiles']['verified_words'] == 356
    assert sum(c['verified_words'] for c in DATA['classes']) == 1326
    for needle in ('0x00a92238', '0x00a93160', '0x00a93198', '0x00a93728',
                   '970', '356', '1326'):
        assert needle in DOC, needle

def test_anchor_counts():
    m = {c['name']: c for c in DATA['classes']}
    assert len(m['addToTiles']['selectors']) == 8
    assert len(m['addToTiles']['ivars']) == 11
    assert len(m['addToTiles']['calls']) == 38
    assert len(m['addToTiles']['branches']) == 78
    assert len(m['removeFromTiles']['selectors']) == 4
    assert len(m['removeFromTiles']['ivars']) == 6
    assert len(m['removeFromTiles']['calls']) == 8
    assert len(m['removeFromTiles']['branches']) == 14

def test_semantics_add():
    s = next(c['semantics'] for c in DATA['classes'] if c['name'] == 'addToTiles')
    for needle in ('push_back(worldIndexAtWorldPosition(self.pos.x, self.pos.y, '
                   'self.world))',
                   '-[self recursivelyUpdateLightWithList:&list]',
                   'idx = i*diameter + j',
                   'skip unless addedGrid[idx] == 0',
                   'contributionGrid[idx*5] (int16)',
                   '(float)v / ((float)radius * 5 * 2)',
                   'contributionGrid[idx*5+1] = (int16)(maxRed   * v0)',
                   'tile[0xe] += grid[+1]',
                   'tile[0x14] += grid[+4]',
                   'addedGrid[idx] = 1',
                   '[dw loadGlowBlockIfNeededAtPos:(x, y) tile:tile]',
                   '0x34->0x33 kind 0x4b',
                   '0x3c->0x3b kind 0x58',
                   'loadTroll = (tile[3] != 0x91)',
                   'loadTreasure = (tile[3] != 0x90)',
                   '[dw lightChangedAtMacroPos:(px>>5, py>>5) sendReliably:1]',
                   'px -= w*32'):
        assert needle in s, needle
    for needle in ('push_back(worldIndexAtWorldPosition', 'recursivelyUpdateLightWithList:&list',
                   'addedGrid[idx] == 0', '(float)radius * 5 * 2',
                   'contributionGrid[idx*5+1] = (int16)(maxRed*v0)',
                   'tile[0xe] += grid[+1]', 'tile[0x10] += grid[+2]',
                   'tile[0x12] += grid[+3]', 'tile[0x14] += grid[+4]',
                   '0x34->0x33', '0x36->0x35', '0x38->0x37', '0x3a->0x39',
                   '0x3c->0x3b', 'kind `0x4b`', 'kind `0x4c`', 'kind `0x56`',
                   'kind `0x57`', 'kind `0x58`', 'loadTroll = (tile[3] != 0x91)',
                   'loadTreasure = (tile[3] != 0x90)',
                   'lightChangedAtMacroPos:(px>>5, py>>5)',
                   'px += w*32', 'recalculateDrawBlockLightingForTile(px, py'):
        assert needle in DOC, needle

def test_semantics_remove():
    s = next(c['semantics'] for c in DATA['classes'] if c['name'] == 'removeFromTiles')
    for needle in ('skip unless addedGrid[idx] == 1',
                   'addedGrid[idx] = 0',
                   'tile[0xe] -= grid[+1]',
                   'exceeds 0xdfff',
                   'movw 0xdfff',
                   'px >= w*32 -> px -= w*32',
                   'self.dynamicWorld lightChangedAtMacroPos:(px>>5,',
                   'No list, no propagation engine'):
        assert needle in s, needle
    for needle in ('addedGrid[idx] == 1', 'tile[0xe] -= grid[+1]',
                   'tile[0x10] -= grid[+2]', 'tile[0x12] -= grid[+3]',
                   'tile[0x14] -= grid[+4]', '0xdfff', '`movw r0, 0xdfff`',
                   '`px >= w*32`', 'px -= w*32', 'px += w*32',
                   'lightChangedAtMacroPos:(px>>5, py>>5) sendReliably:1',
                   'Underflow guard'):
        assert needle in DOC, needle

def test_anchor_samples():
    m = {c['name']: c for c in DATA['classes']}
    add = m['addToTiles']
    rem = m['removeFromTiles']
    assert add['selectors']['0x00a930a8'] == {
        'slot': '0x00e854cc', 'selector': 'macroTiles'}
    assert add['selectors']['0x00a9314c']['selector'] == 'lightChangedAtMacroPos:sendReliably:'
    assert add['ivars']['0x00a93098'] == {
        'slot': '0x0105ea1c', 'symbol': 'OBJC_IVAR_$_ArtificialLight.contributionGrid',
        'offset': 56}
    assert add['ivars']['0x00a930c4']['offset'] == 76  # maxHeat
    assert rem['ivars']['0x00a93718']['offset'] == 8   # DynamicObject.dynamicWorld
    assert rem['selectors']['0x00a936fc'] == {
        'slot': '0x0105b7a0', 'import': 'objc_msgSend'}
    callees = {c['route']: c['callee'] for c in add['calls'] if c['callee']}
    assert callees['bl sym.tileAtWorldPosition_int__int__MacroTile__World_'] == '0x00a16e68'
    assert callees['bl sym.worldIndexAtWorldPosition_int__int__World_'] == '0x00a156a8'
    assert callees['bl sym.recalculateDrawBlockLightingForTile_int__int__MacroTile__World_'] == '0x00a18f68'
    assert callees['bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'] == '0x00a91e48'
    for needle in ('ArtificialLight.contributionGrid', 'offset',
                   '0xa16e68', '0xa14824', '0x4b49fc', '0xa91e48'):
        assert needle in DOC, needle

def test_boundary_statement():
    assert 'recursivelyUpdateLightWithList' in DATA['claim']
    assert 'outside' in DATA['claim']
    assert 'propagation engine' in DOC
    assert 'NOT mapped here' in DOC

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_semantics_add()
    test_semantics_remove()
    test_anchor_samples()
    test_boundary_statement()
    print('artificiallight tiles contract: OK')
