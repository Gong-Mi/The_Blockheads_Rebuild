#!/usr/bin/env python3
"""Contract test for the Wire class closure (non-render) batch.

Pins doc and JSON to each other and to the recovered semantics: the
init/save/net construction trio, save-dict + net-data serialization
(gzipInflate/gzipDeflate), remoteUpdate change detection, dealloc, the
sub-derived static-geometry reload, freeblock-creation constants, the
worldChanged: adjacency refresh and the two occupancy predicates.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/WIRE_CLOSURE.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/wire_closure.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['w_subderived', 'w_objtype', 'w_initpos', 'w_initsave', 'w_initnet',
         'w_dealloc', 'w_getsave', 'w_updnet', 'w_creationnet', 'w_remoteupd',
         'w_fbitem', 'w_fbsave', 'w_fba', 'w_fbb', 'w_worldchanged',
         'w_rmmacro', 'w_occfg', 'w_occnormal']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == [
        '0x0094fca0', '0x0094fd48', '0x0094fd64', '0x0095002c', '0x0095034c',
        '0x009506ac', '0x00950770', '0x00950a64', '0x00950ab8', '0x00950f28',
        '0x00951320', '0x0095135c', '0x00951378', '0x00951394', '0x009513b0',
        '0x00954a2c', '0x00954b34', '0x00954bd4']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [42, 7, 178, 200, 207, 49, 189, 21, 193, 116, 15, 7, 7, 7, 720, 66, 40, 40]
    assert sum(words) == 2104
    for needle in ('2104', '0x0094fca0', '0x00950ab8', '0x009513b0',
                   'worldChanged:', '0xb2', '0x26', '0x60', '0x00951ef0',
                   'gzipInflate', 'gzipDeflate', 'createFreeBlockAtPosition:'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        'w_subderived': (1, 2, 2, 0), 'w_objtype': (0, 0, 0, 0),
        'w_initpos': (7, 2, 7, 6), 'w_initsave': (8, 4, 10, 3),
        'w_initnet': (11, 4, 10, 3), 'w_dealloc': (5, 1, 2, 0),
        'w_getsave': (6, 4, 8, 1), 'w_updnet': (2, 0, 1, 0),
        'w_creationnet': (7, 4, 9, 3), 'w_remoteupd': (6, 4, 4, 2),
        'w_fbitem': (0, 1, 0, 0), 'w_fbsave': (0, 0, 0, 0),
        'w_fba': (0, 0, 0, 0), 'w_fbb': (0, 0, 0, 0),
        'w_worldchanged': (6, 6, 25, 48), 'w_rmmacro': (4, 2, 3, 0),
        'w_occfg': (0, 2, 1, 2), 'w_occnormal': (0, 2, 1, 2),
    }

def test_objecttype_and_constants():
    assert 'return 0x26' in BY['w_objtype']['semantics']
    assert 'return 0x26' in DOC
    for n in ('w_fbsave', 'w_fba', 'w_fbb'):
        assert len(BY[n]['selectors']) == 0 and len(BY[n]['calls']) == 0
    assert 'nil' in BY['w_fbsave']['semantics']
    assert BY['w_fbitem']['ivars']['0x00951354'] == {
        'slot': '0x0105e300', 'symbol': 'OBJC_IVAR_$_Wire.itemType', 'offset': 56}

def test_init_trio():
    p = BY['w_initpos']
    assert p['selectors']['0x00950004'] == {
        'slot': '0x00e839fc', 'selector': 'initWithWorld:dynamicWorld:atPosition:cache:'}
    assert p['selectors']['0x00950020'] == {'slot': '0x00e83a0c', 'selector': 'initSubDerivedItems'}
    assert p['selectors']['0x00950024'] == {'slot': '0x00e83a08', 'selector': 'updateWireConfiguration'}
    assert p['selectors']['0x0094fffc'] == {'slot': '0x00e8bdc0', 'class': 'OBJC_CLASS_$_Wire'}
    assert p['ivars']['0x00950008'] == {
        'slot': '0x0105e300', 'symbol': 'OBJC_IVAR_$_Wire.itemType', 'offset': 56}
    s = BY['w_initsave']['semantics']
    for needle in ('currentConfiguration@60', 'currentSolidConfiguration@64', 'intValue'):
        assert needle in s, needle
    n = BY['w_initnet']
    assert n['selectors']['0x00950650'] == {'slot': '0x00e83a20', 'selector': 'length'}
    s2 = n['semantics']
    for needle in ('gzipInflate', 'subdataWithRange:', 'getBytes:length:', '0x950688'):
        assert needle in s2, needle

def test_serialization_pair():
    g = BY['w_getsave']
    assert g['selectors']['0x00950a3c'] == {'slot': '0x00e83a3c', 'selector': 'setObject:forKey:'}
    assert g['selectors']['0x00950a40'] == {'slot': '0x00e83a38', 'selector': 'numberWithInt:'}
    assert g['selectors']['0x00950a28'] == {'slot': '0x00e83a34', 'selector': 'getSaveDict'}
    c = BY['w_creationnet']
    for cell, sel, slot in (
            ('0x00950d8c', 'dictionary', '0x00e83a4c'),
            ('0x00950d94', 'dataWithBytes:length:', '0x00e83a48'),
            ('0x00950db4', 'gzipDeflate', '0x00e83a50'),
            ('0x00950db0', 'appendData:', '0x00e83a54')):
        assert c['selectors'][cell] == {'slot': slot, 'selector': sel}
    assert '0x950dbc' in c['semantics']
    r = BY['w_remoteupd']
    assert r['selectors']['0x009510cc'] == {'slot': '0x00e83a58', 'selector': 'remoteUpdate:'}
    callees = {x['route']: x['callee'] for x in r['calls'] if x['callee']}
    assert callees['bl sym.reloadDrawBlockDynamicObjectStaticGeometryForTile_intpair__MacroTile__World_'] == '0x00a19598'

def test_lifecycle_and_reload():
    d = BY['w_dealloc']
    assert d['selectors']['0x00950758'] == {'slot': '0x00e83a30', 'selector': 'dealloc'}
    assert d['selectors']['0x00950764'] == {'slot': '0x00e83a2c', 'selector': 'release'}
    assert d['ivars'] and list(d['ivars'].values())[0]['offset'] == 36
    sub = BY['w_subderived']
    assert sub['selectors']['0x0094fd44'] == {'slot': '0x00e839f8', 'selector': 'macroTiles'}
    assert sub['ivars']['0x0094fd38']['offset'] == 16
    assert sub['ivars']['0x0094fd40']['offset'] == 4
    rm = BY['w_rmmacro']
    assert rm['selectors']['0x00954b18'] == {'slot': '0x00e83a70', 'selector': 'removeFromMacroBlock'}

def test_worldchanged_and_occupancy():
    w = BY['w_worldchanged']
    assert w['selectors']['0x00951eb4'] == {'slot': '0x00e83a68', 'selector': 'worldWidthMacro'}
    assert w['selectors']['0x00951ecc'] == {'slot': '0x00e83a08', 'selector': 'updateWireConfiguration'}
    assert w['selectors']['0x00951ed0'] == {'slot': '0x00e83a5c', 'selector': 'isClient'}
    assert w['selectors']['0x00951edc'] == {'slot': '0x00e83a64', 'selector': 'removeStandardObject:'}
    assert w['selectors']['0x00951ee4']['selector'].startswith('createFreeBlockAtPosition:')
    assert w['ivars']['0x00951ea4']['offset'] == 56
    assert w['ivars']['0x00951ec4']['offset'] == 60
    assert w['ivars']['0x00951ed4']['offset'] == 8
    assert w['ivars']['0x00951ed8']['offset'] == 48
    callees = {x['route']: x['callee'] for x in w['calls'] if x['callee']}
    assert callees['bl sym.tileIsWater_Tile_'] == '0x00a11690'
    assert callees['bl sym.tileIsSolid_Tile_'] == '0x00a1179c'
    assert callees['bl 0x951ef0'] == '0x00951ef0'
    fg = BY['w_occfg']
    assert fg['ivars']['0x00954bc8']['offset'] == 4
    assert 'tile[0xb] == 0x60' in fg['semantics']
    nm = BY['w_occnormal']
    assert 'tile[3] == 0x60' in nm['semantics']

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_objecttype_and_constants()
    test_init_trio()
    test_serialization_pair()
    test_lifecycle_and_reload()
    test_worldchanged_and_occupancy()
    test_hashes_and_claim()
    print('wire closure contract: OK')
