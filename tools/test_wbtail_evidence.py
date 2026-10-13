#!/usr/bin/env python3
"""Contract test for the Workbench tail closure (E83)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_TAIL.md').read_text()
DATA = json.loads((NATIVE / 'workbench_tail.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wt_destroyitem', 'wt_fueluipos', 'wt_renderquad', 'wt_rendercubes', 'wt_bhunloaded',
         'wt_glowquadcount', 'wt_occupiesnormal', 'wt_expertuse', 'wt_requiresfuel',
         'wt_upgradename', 'wt_fueltypescount', 'wt_fueltypes', 'wt_upgradenamecraft',
         'wt_numcraftable', 'wt_numcraftablelevel', 'wt_type', 'wt_level', 'wt_selindex',
         'wt_setselindex', 'wt_craftobj', 'wt_count', 'wt_countleft', 'wt_craftprog',
         'wt_setcraftprog', 'wt_xscroll', 'wt_setxscroll']

IMPS = ['0x00b02150', '0x00b021b4', '0x00b0ab4c', '0x00b0ae18', '0x00b0b25c', '0x00b0b398',
        '0x00b0b648', '0x00b0b6d8', '0x00b0b738', '0x00b0b868', '0x00b0ba64', '0x00b0baf8',
        '0x00b0bbd8', '0x00b0bca4', '0x00b0bce0', '0x00b0bd1c', '0x00b0bd58', '0x00b0bd94',
        '0x00b0bdd0', '0x00b0be14', '0x00b0be58', '0x00b0be94', '0x00b0bed0', '0x00b0bf14',
        '0x00b0bf58', '0x00b0bfa0']

COUNTS = {
    'wt_destroyitem': (0, 0, 0, 3, 3, 0),
    'wt_fueluipos': (0, 0, 0, 1, 2, 0),
    'wt_renderquad': (0, 0, 0, 2, 0, 31),
    'wt_rendercubes': (0, 0, 0, 1, 0, 4),
    'wt_bhunloaded': (2, 2, 1, 2, 2, 1),
    'wt_glowquadcount': (0, 0, 0, 2, 0, 10),
    'wt_occupiesnormal': (0, 0, 0, 0, 0, 0),
    'wt_expertuse': (14, 15, 1, 0, 20, 12),
    'wt_requiresfuel': (13, 14, 1, 0, 19, 12),
    'wt_upgradename': (9, 12, 1, 0, 13, 12),
    'wt_fueltypescount': (6, 4, 0, 0, 9, 2),
    'wt_fueltypes': (4, 3, 0, 0, 6, 2),
    'wt_upgradenamecraft': (1, 1, 0, 0, 2, 2),
    'wt_numcraftable': (0, 0, 0, 5, 0, 0),
    'wt_numcraftablelevel': (0, 0, 0, 4, 0, 0),
    'wt_type': (0, 0, 0, 3, 0, 0),
    'wt_level': (0, 0, 0, 2, 0, 0),
    'wt_selindex': (0, 0, 0, 1, 0, 0),
    'wt_setselindex': (0, 0, 0, 2, 0, 0),
    'wt_craftobj': (0, 0, 0, 1, 0, 0),
    'wt_count': (0, 0, 0, 2, 0, 0),
    'wt_countleft': (0, 0, 0, 1, 0, 0),
    'wt_craftprog': (0, 0, 0, 4, 0, 0),
    'wt_setcraftprog': (0, 0, 0, 3, 0, 0),
    'wt_xscroll': (0, 0, 0, 2, 0, 0),
    'wt_setxscroll': (0, 0, 0, 1, 0, 0),
}

WORDS = [55, 30, 221, 42, 79, 97, 7, 371, 347, 271, 144, 107, 51, 75, 60, 45, 30, 15, 34,
         17, 30, 15, 71, 54, 37, 19]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2324
    for needle in ('2324', '0x18 (24)', 'fffff17c', 'dmb ish', '0xb0b958', '0xafd54c', '2.0f'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_tables_and_map():
    s = BY['wt_rendercubes']['semantics']
    assert '0x1a (26)' in s and '0x1d (29)' in s
    s = BY['wt_numcraftable']['semantics']
    assert 'fffff128' in s and 'dmb ish' in s
    s = BY['wt_type']['semantics']
    assert 'fffff120' in s
    s = BY['wt_upgradename']['semantics']
    assert '0xb0b958' in s
    s = BY['wt_fueluipos']['semantics']
    assert '2.0f' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_tables_and_map()
    print('test_wbtail_evidence: OK')
