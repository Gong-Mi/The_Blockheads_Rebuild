#!/usr/bin/env python3
"""Contract test for the ArtificialLight propagation-engine batch.

Pins doc and JSON to each other and to the recovered semantics: the pop/wrap
prologue, the own-cell radius*10 override, the 8-neighbour attenuation table
(5/6,7/6,10/6,14/6,20/6 with air -10/-14 and zero directions), the commit and
the guarded four-way enqueue, plus the 76/241 anchor counts.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/ARTIFICIALLIGHT_RECURSIVE_UPDATE.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/artificiallight_recursiveupdate.json').read_text())

def test_body():
    m = DATA['classes'][0]
    assert m['name'] == 'recursivelyUpdateLightWithList:'
    assert m['imp'] == '0x00a8f22c'
    assert m['boundary_end'] == '0x00a91d30'
    assert m['verified_words'] == 2753
    for needle in ('0x00a8f22c', '0x00a91d30', '2753'):
        assert needle in DOC, needle

def test_anchor_counts():
    m = DATA['classes'][0]
    assert len(m['selectors']) == 5
    assert len(m['ivars']) == 13
    assert len(m['calls']) == 76
    assert len(m['branches']) == 241
    bl = [c for c in m['calls'] if c['callee']]
    assert len(bl) == 67
    assert len(m['calls']) - len(bl) == 9

def test_semantics():
    s = DATA['classes'][0]['semantics']
    for needle in ('pop_front the work list',
                   'getWorldPosForWorldIndex(idx, &x, &y, self.world)',
                   'w16 = ([self.world worldWidthMacro] << 5) / 2',
                   'x - pos.x >= w16 -> x -= w*32',
                   'v = radius*10',
                   'max((radius*5)/6, 5)',
                   'max((radius*7)/6, 7)',
                   'max((radius*20)/6, 20)',
                   'K = 10 orthogonal, 14 diagonal',
                   'dir==2 yields nv = 0',
                   'dir==1 yields nv = 0',
                   'orthogonal water/air/solid',
                   'grid16[idx5*5] = (int16)v (strh at 0xa9155c)',
                   '0xa9173c/0xa91918/0xa91af8/0xa91cd4',
                   'init 0, never '):
        assert needle in s, needle
    for needle in ('max(r*5/6, 5)', 'max(r*7/6, 7)', 'max(r*20/6, 20)',
                   'max(r*10/6, 10)', 'max(r*14/6, 14)', '-14', '-10',
                   'dir==2 → `0`', 'dir==1 → `0`', 'x-cylindrical',
                   'pop_front', '0xa91628', '0xa91d30', 'radius*10',
                   'lightDirection'):
        assert needle in DOC, needle

def test_anchor_samples():
    m = DATA['classes'][0]
    assert m['selectors']['0x00a90188'] == {
        'slot': '0x00e854d0', 'selector': 'worldWidthMacro'}
    assert m['selectors']['0x00a9017c']['selector'] == 'macroTiles'
    assert m['selectors']['0x00a90178'] == {
        'slot': '0x0105b7a0', 'import': 'objc_msgSend'}
    assert m['ivars']['0x00a90180']['offset'] == 16   # pos
    assert m['ivars']['0x00a905f0']['offset'] == 96   # lightDirection
    assert m['ivars']['0x00a90554']['offset'] == 92   # diameter
    callees = {c['route']: c['callee'] for c in m['calls'] if c['callee']}
    assert callees['bl sym.tileIsWater_Tile_'] == '0x00a11690'
    assert callees['bl sym.tileIsAirWaterOrSnow_Tile_'] == '0x00a126dc'
    assert callees['bl sym.tileIsSemiTransparentSolidBlock_Tile_'] == '0x00a128b0'
    assert callees['bl sym.tileAtWorldPosition_int__int__MacroTile__World_'] == '0x00a16e68'
    assert callees['bl sym.worldIndexAtWorldPosition_int__int__World_'] == '0x00a156a8'
    assert callees['bl sym.getWorldPosForWorldIndex_int__int__int__World_'] == '0x00a15518'
    assert callees['bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.pop_front__'] == '0x00a91d30'
    assert callees['bl method.std::__1::list_unsigned_int__std::__1::allocator_unsigned_int___.push_back_unsigned_int_'] == '0x00a91e48'
    for needle in ('0xa11690', '0xa126dc', '0xa128b0', '0xa156a8',
                   '0xa15518', '0xa91e48', 'contributionGridOrigin', 'diameter'):
        assert needle in DOC, needle

def test_boundary_statement():
    assert 'established' not in DATA['claim']
    assert 'compiler bookkeeping' in DATA['claim'] + DOC
    assert 'node+8' in DATA['classes'][0]['semantics']

if __name__ == '__main__':
    test_body()
    test_anchor_counts()
    test_semantics()
    test_anchor_samples()
    test_boundary_statement()
    print('artificiallight recursiveupdate contract: OK')
