#!/usr/bin/env python3
"""Contract test for the electricity power-flow search batch.

Pins doc and JSON to each other and to the recovered semantics: the prologue
power-state setup, the index-set search flow, the four testTile direction
probes, the availableElectricity -> subtractElectricty accounting and the
ParticleEmitter path emission.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/POWER_FIND.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/power_find.json').read_text())

def test_body():
    m = DATA['classes'][0]
    assert m['name'] == 'wpc_findpower'
    assert m['imp'] == '0x00db2690'
    assert m['boundary_end'] == '0x00db51d4'
    assert m['verified_words'] == 2769
    for needle in ('2769', '0x00db2690', '0x00db51d4'):
        assert needle in DOC, needle

def test_anchor_counts():
    m = DATA['classes'][0]
    assert len(m['selectors']) == 17
    assert len(m['ivars']) == 6
    assert len(m['calls']) == 120
    assert len(m['branches']) == 232

def test_semantics():
    s = DATA['classes'][0]['semantics']
    for needle in ('remaining = uint16 initial = upTo',
                   '0x98967f = 9,999,999',
                   '[openList enumerateIndexesUsingBlock:]',
                   'testTile(x-1,y / x+1,y / x,y-1 / x,y+1',
                   'min(available, remaining)',
                   'subtractElectricty:amount',
                   'addElectricityParticleWithPath:vectorCopy',
                   'initial - remaining',
                   '13-argument',
                   'Boundary: the C helper testTile'):
        assert needle in s, needle
    for needle in ('availableElectricity', 'subtractElectricty:',
                   'addElectricityParticleWithPath:size:', 'openList@8',
                   'closedList@12', 'testTile', '9,999,999', '0xdb50fc',
                   'ParticleEmitter', 'ElectrictyParticlePathIndex'):
        assert needle in DOC, needle

def test_anchor_samples():
    m = DATA['classes'][0]
    assert m['selectors']['0x00db3bf4'] == {
        'slot': '0x00e88f28', 'selector': 'availableElectricity'}
    assert m['selectors']['0x00db3dc0'] == {
        'slot': '0x00e88f50', 'selector': 'subtractElectricty:'}
    assert m['selectors']['0x00db44b8'] == {
        'slot': '0x00e88f58', 'selector': 'addElectricityParticleWithPath:size:'}
    assert m['selectors']['0x00db4344'] == {
        'slot': '0x00e8b848', 'class': 'OBJC_CLASS_$_ParticleEmitter'}
    assert m['ivars']['0x00db36c8']['offset'] == 8    # openList
    assert m['ivars']['0x00db36b4']['offset'] == 12   # closedList
    assert m['ivars']['0x00db36e0']['offset'] == 16   # startIndex
    callees = {c['route']: c['callee'] for c in m['calls'] if c['callee']}
    assert callees['bl sym.testTile_int__int__NSMutableIndexSet__NSMutableIndexSet__int__Tile__WirePathTileProperties__int__int__unsigned_short__World__WirePathCreator__signed_char_'] == '0x00db222c'
    assert callees['bl sym.tileAtWorldIndexLoaded_int__World_'] == '0x00a16944'
    assert callees['bl sym.getWorldPosForWorldIndex_int__int__int__World_'] == '0x00a15518'
    blx = [c for c in m['calls'] if c['route'].startswith('blx')]
    assert len(blx) == 10
    for needle in ('0xe88f28', '0xe88f50', '0xe88f58', '0xdb4344',
                   '0xdb222c', '0xdb3a40'):
        assert needle in DOC, needle

def test_boundary_statement():
    assert 'separate objects' in DATA['classes'][0]['semantics']
    assert 'next-IMP gap' in DOC

if __name__ == '__main__':
    test_body()
    test_anchor_counts()
    test_semantics()
    test_anchor_samples()
    test_boundary_statement()
    print('power find contract: OK')
