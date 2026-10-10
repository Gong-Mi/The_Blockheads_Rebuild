#!/usr/bin/env python3
"""Contract test for the electric lighting cluster (E68)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'ELECTRIC_LIGHTING.md').read_text()
DATA = json.loads((NATIVE / 'electric_lighting.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['al_ctor_color', 'al_ctor_save', 'al_dealloc', 'al_worldchanged', 'al_rmmacro',
         'al_cxx_construct', 'gb_initsubderived', 'gb_ctor', 'gb_dealloc', 'gb_rmmacro',
         'gb_worldchanged', 'gb_setneedsremoved', 'gb_addlightcont', 'wpc_cxx_destruct',
         'wpc_cxx_construct', 'es_cxx_construct']

IMPS = ['0x00a93744', '0x00a93c64', '0x00a947ac', '0x00a94898', '0x00a9519c', '0x00a958bc',
        '0x00ca8304', '0x00ca83d4', '0x00ca8e64', '0x00ca8f4c', '0x00ca90bc', '0x00ca93ac',
        '0x00ca960c', '0x00db5454', '0x00db549c', '0x00cb15a4']

COUNTS = {
    'al_ctor_color': (4, 1, 1, 13, 7, 4),
    'al_ctor_save': (7, 11, 1, 11, 24, 5),
    'al_dealloc': (2, 2, 1, 2, 4, 0),
    'al_worldchanged': (3, 1, 0, 7, 16, 25),
    'al_rmmacro': (2, 2, 1, 0, 2, 0),
    'al_cxx_construct': (0, 0, 0, 0, 0, 0),
    'gb_initsubderived': (0, 0, 0, 0, 0, 0),
    'gb_ctor': (5, 1, 2, 6, 6, 25),
    'gb_dealloc': (2, 2, 1, 1, 2, 0),
    'gb_rmmacro': (3, 1, 1, 3, 5, 0),
    'gb_worldchanged': (2, 1, 0, 4, 3, 7),
    'gb_setneedsremoved': (3, 1, 1, 3, 4, 1),
    'gb_addlightcont': (1, 1, 0, 1, 1, 0),
    'wpc_cxx_destruct': (0, 0, 0, 2, 6, 0),
    'wpc_cxx_construct': (0, 0, 0, 1, 5, 0),
    'es_cxx_construct': (0, 0, 0, 0, 0, 0),
}

WORDS = [286, 412, 59, 577, 43, 6, 12, 339, 58, 92, 188, 85, 29, 108, 90, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2390
    for needle in ('2390', 'ffffef20', 'reloadDrawBlockLightGlowQuadsForTile', 'map<int, int>',
                   '0x4d', 'ffe259f8', 'lsl r0, r0, 5'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_light_and_glow():
    s = BY['al_ctor_color']['semantics']
    for needle in ('ffffef20', 'ivar-cell', 'super2'):
        assert needle in s, needle
    s = BY['gb_rmmacro']['semantics']
    assert 'reloadDrawBlockLightGlowQuadsForTile' in s
    s = BY['gb_setneedsremoved']['semantics']
    assert 'reloadDrawBlockLightGlowQuadsForTile' in s
    s = BY['gb_ctor']['semantics']
    for needle in ('0x10', '0x19', '0x4d'):
        assert needle in s, needle
    s = BY['gb_addlightcont']['semantics']
    assert 'artificial-light contributor' in s


def test_wire_and_shaft():
    s = BY['wpc_cxx_destruct']['semantics']
    assert 'map<int, int>' in s
    s = BY['es_cxx_construct']['semantics']
    assert 'empty' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_light_and_glow()
    test_wire_and_shaft()
    print('test_electric_lighting_evidence: OK')
