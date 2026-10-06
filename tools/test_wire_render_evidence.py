#!/usr/bin/env python3
"""Contract test for the Wire render trio batch.

Pins doc and JSON to each other and to the recovered semantics: the draw:
frame canonicaliser, the staticGeometryDrawCubeCount config/solid group
counting, and the addDrawCubeData:fromIndex: fillBuffer: draw-cube builder.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/WIRE_RENDER.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/wire_render.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

FILLBUFFER = 'fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ:topMinS:topMaxS:topMinT:topMaxT:sideMinS:sideMaxS:sideMinT:sideMaxT:macroWorldX:macroWorldY:'

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == ['w_draw', 'w_sgcdc', 'w_addcube']
    assert [BY[n]['imp'] for n in BY] == ['0x009510f8', '0x00951f2c', '0x00952770']
    assert [BY[n]['boundary_end'] for n in BY] == ['0x00951320', '0x00952770', '0x009549b8']
    words = [BY[n]['verified_words'] for n in BY]
    assert words == [138, 529, 2194]
    assert sum(words) == 2861
    for needle in ('2861', '0x00952770', '0x009549b8', 'fillBuffer:',
                   'texCoordsForImageIndex', '0x70', 'floatPos@24',
                   'macroTileOwner', 'staticGeometryDrawCubeCount', 'DrawCube'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in BY}
    assert counts == {
        'w_draw': (0, 0, 0, 0),
        'w_sgcdc': (0, 2, 0, 54),
        'w_addcube': (6, 8, 14, 61),
    }

def test_draw_canonicaliser():
    d = BY['w_draw']
    assert d['selectors'] == {} and d['ivars'] == {} and d['calls'] == [] and d['branches'] == []
    assert 'canonicaliser' in d['semantics']
    assert 'No call sites' in d['semantics']

def test_sgcdc_groups():
    s = BY['w_sgcdc']
    assert s['ivars']['0x00952764'] == {
        'slot': '0x0105e2f8', 'symbol': 'OBJC_IVAR_$_Wire.currentConfiguration', 'offset': 60}
    assert s['ivars']['0x00952768'] == {
        'slot': '0x0105e2fc', 'symbol': 'OBJC_IVAR_$_Wire.currentSolidConfiguration', 'offset': 64}
    sem = s['semantics']
    for needle in ('{1,2,3,4,5}', '{7,10,12}', '{8,9,11}', '{4,9,10}', '{5,11,12}',
                   '{2,4,5,6,9,12,14,16}', '{2,4,5,6,10,11,13,17}',
                   '{2,5,7,8,9,10,11,12}', '{2,6,7,9,10,13,14,15}', '0..10'):
        assert needle in sem, needle
    assert len(s['branches']) == 54

def test_addcube_builder():
    a = BY['w_addcube']
    for cell in ('0x00952804', '0x00954988', '0x009549a4'):
        assert a['selectors'][cell] == {'slot': '0x00e83a6c', 'selector': FILLBUFFER}
    for cell in ('0x009527f0', '0x00953510', '0x0095499c'):
        assert a['selectors'][cell] == {'slot': '0x00e8abb4', 'class': 'OBJC_CLASS_$_DrawCube'}
    assert a['ivars']['0x009527e8'] == {
        'slot': '0x0105c3d0', 'symbol': 'OBJC_IVAR_$_DynamicObject.floatPos', 'offset': 24}
    assert a['ivars']['0x00952800'] == {
        'slot': '0x0105c3b8', 'symbol': 'OBJC_IVAR_$_DynamicObject.macroTileOwner', 'offset': 12}
    assert a['ivars']['0x009527e0']['offset'] == 64
    assert a['ivars']['0x009527ec']['offset'] == 60
    callees = {c['route']: c['callee'] for c in a['calls'] if c['callee']}
    assert callees['bl 0x9549b8'] == '0x009549b8'
    assert callees['bl sym.texCoordsForImageIndex_int_'] == '0x004d6820'
    assert callees['bl method.Vector2.operator_float__'] == '0x004bdaac'
    assert callees['bl loc.imp.objc_msgSend'] == '0x001c281c'
    sem = a['semantics']
    for needle in ('floatPos@24', '5.0', '0.05', '0.45', '0.525', '0x70',
                   'fromIndex + running count', FILLBUFFER[:20]):
        assert needle in sem, needle
    for needle in ('0.05', '0.45', '0.525', '0.4f', '1.525f', '5.0'):
        assert needle in DOC, needle

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_draw_canonicaliser()
    test_sgcdc_groups()
    test_addcube_builder()
    test_hashes_and_claim()
    print('wire render contract: OK')
