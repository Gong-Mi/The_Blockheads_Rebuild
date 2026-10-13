#!/usr/bin/env python3
"""Contract test for the Tree base class (E89)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TREE_BASE.md').read_text()
DATA = json.loads((NATIVE / 'tree_base.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['tr_rmmacro', 'tr_initstatic', 'tr_ctor', 'tr_compost', 'tr_fruititem', 'tr_shouldfall', 'tr_fruitseason', 'tr_fallenfruits', 'tr_ctorsave', 'tr_dealloc', 'tr_worldchanged', 'tr_incheight', 'tr_update', 'tr_growth', 'tr_kindself', 'tr_makedead', 'tr_killtiles', 'tr_checkdead', 'tr_killabove', 'tr_removeall', 'tr_updateidsize', 'tr_soiltype', 'tr_treetype', 'tr_maxheightgene', 'tr_growthgene', 'tr_height', 'tr_isstatic', 'tr_occupiesnormal']
IMPS = ['0x004c0320', '0x004c03d4', '0x004c0638', '0x004c1f84', '0x004c205c', '0x004c2078', '0x004c2094', '0x004c20b4', '0x004c39a0', '0x004c3be8', '0x004c4974', '0x004c576c', '0x004c57b0', '0x004c6898', '0x004c68b0', '0x004c68d0', '0x004c68e8', '0x004c6b50', '0x004c7008', '0x004c7354', '0x004c76d8', '0x004c78dc', '0x004c7978', '0x004c7994', '0x004c7a44', '0x004c7af4', '0x004c7b30', '0x004c7b4c']
COUNTS = {'tr_rmmacro': (2, 2, 1, 0, 2, 0), 'tr_initstatic': (3, 1, 1, 5, 5, 5), 'tr_ctor': (4, 1, 1, 9, 13, 11), 'tr_compost': (0, 0, 0, 2, 1, 6), 'tr_fruititem': (0, 0, 0, 0, 0, 0), 'tr_shouldfall': (0, 0, 0, 0, 0, 0), 'tr_fruitseason': (0, 0, 0, 0, 0, 0), 'tr_fallenfruits': (7, 1, 0, 7, 14, 18), 'tr_ctorsave': (5, 3, 1, 3, 6, 2), 'tr_dealloc': (1, 1, 1, 1, 2, 1), 'tr_worldchanged': (9, 1, 0, 9, 28, 53), 'tr_incheight': (0, 0, 0, 1, 0, 0), 'tr_update': (12, 1, 0, 18, 36, 47), 'tr_growth': (0, 0, 0, 0, 0, 0), 'tr_kindself': (0, 0, 0, 0, 0, 0), 'tr_makedead': (0, 0, 0, 0, 0, 0), 'tr_killtiles': (2, 0, 0, 5, 4, 10), 'tr_checkdead': (3, 1, 0, 5, 6, 14), 'tr_killabove': (3, 1, 0, 4, 5, 12), 'tr_removeall': (3, 1, 0, 4, 5, 13), 'tr_updateidsize': (0, 0, 0, 4, 1, 9), 'tr_soiltype': (0, 0, 0, 0, 0, 5), 'tr_treetype': (0, 0, 0, 0, 0, 0), 'tr_maxheightgene': (0, 0, 0, 2, 4, 0), 'tr_growthgene': (0, 0, 0, 1, 2, 0), 'tr_height': (0, 0, 0, 1, 0, 0), 'tr_isstatic': (0, 0, 0, 0, 0, 0), 'tr_occupiesnormal': (0, 0, 0, 0, 0, 0)}
WORDS = [45, 153, 334, 54, 14, 7, 8, 301, 146, 49, 879, 17, 1082, 20, 14, 6, 154, 302, 211, 225, 129, 39, 7, 88, 44, 29, 14, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4378
    for needle in ('4378', 'clampi', 'baseGrowthRateForTreeType', '__wrap_calloc',
                   'tileIsTreeTrunk', '0x4c0bc4', '0x3c'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_base():
    s = BY['tr_ctor']['semantics']
    assert 'clampi(1, 0xff)' in s and 'baseGrowthRateForTreeType' in s
    s = BY['tr_checkdead']['semantics']
    assert 'vdiv.f64' in s and 'tileIsTreeTrunk' in s
    s = BY['tr_isstatic']['semantics']
    assert 'returns **0**' in s
    s = BY['tr_occupiesnormal']['semantics']
    assert 'returns **1**' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_base()
    print('test_treebase_evidence: OK')
