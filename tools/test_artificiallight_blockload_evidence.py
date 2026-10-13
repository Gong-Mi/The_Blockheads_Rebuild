#!/usr/bin/env python3
"""Contract test for the ArtificialLight physical-block-load hook batch.

Pins doc and JSON to each other and to the recovered semantics: the corner
pairs, the h/wrap culls (x-only), the remove -> memset -> add re-registration
tail, the staged argument block note, and the 17/12 anchor counts.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/ARTIFICIALLIGHT_BLOCKLOAD.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/artificiallight_blockload.json').read_text())

def test_body():
    m = DATA['classes'][0]
    assert m['name'] == 'addContributionForPhysicalBlockLoadedAtXPos:yPos:'
    assert m['imp'] == '0x00a95248'
    assert m['boundary_end'] == '0x00a958bc'
    assert m['verified_words'] == 413
    assert m['types'] == 'v16@0:4i8i12'
    for needle in ('0x00a95248', '0x00a958bc', '413', 'v16@0:4i8i12'):
        assert needle in DOC, needle

def test_anchor_counts():
    m = DATA['classes'][0]
    assert len(m['selectors']) == 4
    assert len(m['ivars']) == 5
    assert len(m['calls']) == 17
    assert len(m['branches']) == 12

def test_semantics():
    s = DATA['classes'][0]['semantics']
    for needle in ('pair1 = makeIntpair(xPos << 5, yPos << 5)',
                   'With h = ([self.world worldWidthMacro] << 5) / 2 (via '
                   '__aeabi_idiv)',
                   '(dx1 >= h -> dx1 -= w*32; dx1 < -h -> dx1 += w*32)',
                   'dx1 < -radius',
                   'dx2 >= radius',
                   'dy2 = self.pos.y - (yPos+1)*32 >= radius',
                   'y never wraps - the world is x-cylindrical',
                   '@selector(removeFromTiles)',
                   'staged argument block',
                   'memset(self.contributionGrid, 0, diameter*diameter*2*5)',
                   '(diameter<<1) * diameter * 5',
                   '@selector(addToTiles)) is issued through the saved '
                   'objc_msgSend function',
                   'blx r2'):
        assert needle in s, needle
    for needle in ('x-cylindrical', 'removeFromTiles', 'addToTiles',
                   'staged argument block', 'memset', 'blx r2',
                   'mul r0, r0, r3', 'and r1, r1, 0xff'):
        assert needle in DOC, needle

def test_anchor_samples():
    m = DATA['classes'][0]
    assert m['selectors']['0x00a9587c'] == {
        'slot': '0x00e854d0', 'selector': 'worldWidthMacro'}
    assert m['selectors']['0x00a958a4'] == {
        'slot': '0x00e854f8', 'selector': 'addToTiles'}
    assert m['selectors']['0x00a958ac'] == {
        'slot': '0x00e85518', 'selector': 'removeFromTiles'}
    assert m['selectors']['0x00a958a0'] == {
        'slot': '0x0105b7a0', 'import': 'objc_msgSend'}
    assert m['ivars']['0x00a95870']['offset'] == 16   # DynamicObject.pos
    assert m['ivars']['0x00a9588c']['offset'] == 80   # radius
    assert m['ivars']['0x00a958a8']['offset'] == 92   # diameter
    assert m['ivars']['0x00a958b4']['offset'] == 56   # contributionGrid
    callees = {c['route']: c['callee'] for c in m['calls'] if c['callee']}
    assert callees['bl sym.makeIntpair_int__int_'] == '0x004b49fc'
    assert callees['bl sym.imp.__aeabi_idiv'] == '0x001c3728'
    assert callees['bl sym.imp.memset'] == '0x001c2924'
    assert callees['bl loc.imp.objc_msgSend'] == '0x001c281c'
    blx = [c for c in m['calls'] if c['route'] == 'blx r2']
    assert len(blx) == 1 and blx[0]['callee'] is None
    for needle in ('0xe854f8', '0xe85518', '0x0105b7a0', '0x4b49fc',
                   '0x1c3728', '0x1c2924'):
        assert needle in DOC, needle

def test_boundary_statement():
    assert 'ARTIFICIALLIGHT_TILES.md' in DOC
    assert 'engine-boundary claim' in DOC
    assert 'mapped in the tiles pair batch' in DATA['claim']

if __name__ == '__main__':
    test_body()
    test_anchor_counts()
    test_semantics()
    test_anchor_samples()
    test_boundary_statement()
    print('artificiallight blockload contract: OK')
