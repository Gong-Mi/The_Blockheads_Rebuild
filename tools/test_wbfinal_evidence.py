#!/usr/bin/env python3
"""Contract test for the Workbench true closure (E84)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_FINAL.md').read_text()
DATA = json.loads((NATIVE / 'workbench_final.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wz_adddrawquad', 'wz_adddrawcube', 'wz_ctor_placed', 'wz_initsubderived',
         'wz_craftableitems', 'wz_hurrycost', 'wz_rmmacro', 'wz_lightpos',
         'wz_addartistlight', 'wz_staticquadcount', 'wz_staticcubecount']
IMPS = ['0x00b02608', '0x00b05f90', '0x00ae42c0', '0x00ae3634', '0x00afb128', '0x00b0bc24',
        '0x00b0aec0', '0x00b0b51c', '0x00b0b664', '0x00b0222c', '0x00b05ec4']

COUNTS = {
    'wz_adddrawquad': (2, 1, 0, 26, 52, 51),
    'wz_adddrawcube': (3, 0, 2, 8, 41, 15),
    'wz_ctor_placed': (13, 5, 3, 13, 26, 32),
    'wz_initsubderived': (9, 9, 1, 11, 19, 3),
    'wz_craftableitems': (0, 0, 0, 1, 0, 0),
    'wz_hurrycost': (0, 0, 0, 0, 1, 2),
    'wz_rmmacro': (6, 2, 1, 5, 12, 4),
    'wz_lightpos': (0, 0, 0, 2, 4, 2),
    'wz_addartistlight': (1, 1, 0, 1, 1, 0),
    'wz_staticquadcount': (1, 1, 0, 3, 1, 30),
    'wz_staticcubecount': (0, 0, 0, 1, 0, 6),
}

WORDS = [3631, 4847, 774, 394, 15, 32, 231, 75, 29, 247, 51]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 10326
    for needle in ('10326', 'fillQuadBuffer', 'texCoordsForImageIndex',
                   'reloadDrawBlockLightGlowQuadsForTile', 'ceil(remaining / 10)',
                   'fffff11c', 'fff3bea4', '96/96'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_closers():
    s = BY['wz_rmmacro']['semantics']
    assert 'reloadDrawBlockLightGlowQuadsForTile' in s
    s = BY['wz_hurrycost']['semantics']
    assert 'ceil(remaining / 10)' in s
    s = BY['wz_staticcubecount']['semantics']
    assert '-> 4' in s and '-> 9' in s
    s = BY['wz_craftableitems']['semantics']
    assert 'fffff11c' in s
    s = BY['wz_rmmacro']['semantics']
    assert 'three workbench sites' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_closers()
    print('test_wbfinal_evidence: OK')
