#!/usr/bin/env python3
"""Contract test for the electricity-domain core batch.

Pins doc and JSON to each other and to the recovered semantics: the wire
four-direction conductivity recompute, both 16-entry configuration tables,
the change-gated commit with isNet door, the WirePathCreator memoized slot
allocator and the ElevatorMotor consumer pair.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/POWER_CORE.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/power_core.json').read_text())

def test_bodies():
    m = {c['name']: c for c in DATA['classes']}
    assert set(m) == {'wire_updateconfig', 'wpc_tilederived',
                      'em_hasreqpower', 'em_usepower'}
    assert sum(c['verified_words'] for c in DATA['classes']) == 1010
    assert m['wire_updateconfig']['verified_words'] == 808
    assert m['wpc_tilederived']['verified_words'] == 94
    assert m['em_usepower']['verified_words'] == 88
    for needle in ('1010', '0x0094f000', '0x00db20b4', '0x007027f8',
                   '0x00702848'):
        assert needle in DOC, needle

def test_anchor_counts():
    m = {c['name']: c for c in DATA['classes']}
    assert len(m['wire_updateconfig']['selectors']) == 6
    assert len(m['wire_updateconfig']['ivars']) == 7
    assert len(m['wire_updateconfig']['calls']) == 30
    assert len(m['wire_updateconfig']['branches']) == 118
    assert len(m['wpc_tilederived']['ivars']) == 3
    assert len(m['wpc_tilederived']['calls']) == 2
    assert len(m['wpc_tilederived']['branches']) == 4
    assert len(m['em_hasreqpower']['ivars']) == 1
    assert len(m['em_usepower']['ivars']) == 5
    assert len(m['em_usepower']['branches']) == 6

def test_semantics():
    s = {c['name']: c['semantics'] for c in DATA['classes']}
    w = s['wire_updateconfig']
    for needle in ('tileConductsElectricity(tile) || (tile[3] == 0x68)',
                   'workbenchAtPos:(nx,ny)',
                   'usesStoresConductsOrProducesElectricity',
                   '1111->1', '0000->2', '0001->6', '1000->3',
                   '1111->2', '0001->0xf', '0000->keep 3',
                   'currentConfiguration@60',
                   'currentSolidConfiguration@64',
                   'updateNeedsToBeSent@49 = 1',
                   'dynamicWorldChangedAtPos:intpair'):
        assert needle in w, needle
    t = s['wpc_tilederived']
    for needle in ('0x1ff', 'derivedTileIndices@28', 'derivedTilePropertiesArray@20',
                   'return &array[newCount]', 'mul by 0xc'):
        assert needle in t, needle
    h = s['em_hasreqpower']
    for needle in ('availableElectricity@60', '>= 10'):
        assert needle in h, needle
    u = s['em_usepower']
    for needle in ('isNet@52', 'availableElectricity@60 += 10',
                   'timeUntilNextPowerCheck@72 = 0.0f',
                   'updateNeedsToBeSent@49 = 1'):
        assert needle in u, needle
    for needle in ('usesStoresConductsOrProducesElectricity', 'currentConfiguration@60',
                   'currentSolidConfiguration@64', 'derivedTileCount', '0x1ff',
                   'availableElectricity', 'updateNeedsToBeSent',
                   'workbenchAtPos', 'reloadDrawBlockDynamicObjectStaticGeometryForTile'):
        assert needle in DOC, needle

def test_anchor_samples():
    m = {c['name']: c for c in DATA['classes']}
    w = m['wire_updateconfig']
    assert w['selectors']['0x0094fc5c'] == {
        'slot': '0x00e839ec', 'selector': 'usesStoresConductsOrProducesElectricity'}
    assert w['selectors']['0x0094fc68'] == {
        'slot': '0x00e839e8', 'selector': 'workbenchAtPos:'}
    assert w['selectors']['0x0094fc90']['selector'] == 'dynamicWorldChangedAtPos:objectType:'
    assert w['ivars']['0x0094fc78']['offset'] == 60   # currentConfiguration
    assert w['ivars']['0x0094fc7c']['offset'] == 64   # currentSolidConfiguration
    assert w['ivars']['0x0094fc80']['offset'] == 52   # isNet
    callees = {c['route']: c['callee'] for c in w['calls'] if c['callee']}
    assert callees['bl sym.tileConductsElectricity_Tile_'] == '0x00a11818'
    assert callees['bl sym.tileAtWorldPositionLoaded_int__int__World_'] == '0x00a12f24'
    assert callees['bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'] == '0x00a19598'
    t = m['wpc_tilederived']
    assert t['ivars']['0x00db221c']['offset'] == 24   # derivedTileCount
    assert t['ivars']['0x00db2224']['offset'] == 20   # derivedTilePropertiesArray
    assert t['calls'][0]['callee'] == '0x0086c818'
    u = m['em_usepower']
    assert u['ivars']['0x00702998']['offset'] == 72   # timeUntilNextPowerCheck
    assert u['ivars']['0x0070299c']['offset'] == 62   # clientPowerUsage
    for needle in ('0x94fc5c', '0x94fc68', '0xa11818', '0xa19598',
                   '0x86c818', 'derivedTilePropertiesArray', 'timeUntilNextPowerCheck'):
        assert needle in DOC, needle

def test_boundary_statement():
    assert 'findAndSubtractAllPowerUpTo' in DOC
    assert 'NOT in this batch' in DOC
    assert 'outside' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_semantics()
    test_anchor_samples()
    test_boundary_statement()
    print('power core contract: OK')
