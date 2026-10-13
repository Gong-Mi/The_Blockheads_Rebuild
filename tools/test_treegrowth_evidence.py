#!/usr/bin/env python3
"""Contract test for the tree growth + update giants (E87)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TREE_GROWTH.md').read_text()
DATA = json.loads((NATIVE / 'tree_growth.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cf_growth', 'cf_update', 'lt_growth', 'lt_update', 'at_growth', 'at_update', 'ot_growth', 'ot_update', 'cn_growth', 'cn_update', 'ct_growth', 'ct_update', 'pt_growth', 'pt_update', 'ch_growth', 'ch_update', 'mg_growth', 'mg_update', 'mp_growth', 'mp_update']
IMPS = ['0x007deca0', '0x007e0c8c', '0x00809db0', '0x0080bc80', '0x009bd680', '0x009bf5f0', '0x00a96778', '0x00a98648', '0x00a99b30', '0x00a9aa30', '0x00b53a50', '0x00b54c60', '0x00b652f8', '0x00b66fa8', '0x00d0e0a0', '0x00d0fdb4', '0x00d4b668', '0x00d4d314', '0x00db6128', '0x00db8078']
COUNTS = {'cf_growth': (12, 2, 0, 17, 54, 106), 'cf_update': (8, 2, 1, 8, 15, 20), 'lt_growth': (16, 2, 0, 19, 62, 95), 'lt_update': (9, 2, 1, 8, 16, 20), 'at_growth': (14, 2, 0, 21, 56, 101), 'at_update': (10, 2, 1, 9, 19, 28), 'ot_growth': (16, 2, 0, 19, 62, 95), 'ot_update': (9, 2, 1, 8, 16, 20), 'cn_growth': (5, 1, 0, 9, 30, 89), 'cn_update': (9, 2, 1, 9, 18, 27), 'ct_growth': (5, 1, 0, 15, 39, 70), 'ct_update': (10, 2, 1, 8, 19, 33), 'pt_growth': (11, 2, 0, 19, 49, 102), 'pt_update': (12, 2, 1, 9, 23, 31), 'ch_growth': (12, 2, 0, 19, 52, 94), 'ch_update': (8, 2, 1, 8, 15, 20), 'mg_growth': (12, 2, 0, 19, 52, 94), 'mg_update': (9, 2, 1, 8, 16, 20), 'mp_growth': (11, 2, 0, 18, 52, 102), 'mp_update': (9, 2, 1, 8, 16, 20)}
WORDS = [2017, 439, 1972, 458, 1986, 585, 1972, 458, 960, 526, 1156, 623, 1810, 668, 1835, 438, 1835, 457, 1978, 457]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 22630
    for needle in ('22630', 'reloadDrawBlockGeometryForTile', 'seasonForWorldX',
                   'tileIsDeadTree', 'tileIsBush', '0x9be67c'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_family():
    s = BY['at_growth']['semantics']
    assert 'reloadDrawBlockGeometryForTile' in s and '0x7f' in s
    s = BY['cn_growth']['semantics']
    assert 'tileIsBush' in s
    s = BY['pt_update']['semantics']
    assert 'fmodf' in s
    s = BY['at_update']['semantics']
    assert 'seasonForWorldX' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_family()
    print('test_treegrowth_evidence: OK')
