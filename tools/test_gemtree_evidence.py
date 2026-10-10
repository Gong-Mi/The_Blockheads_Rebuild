#!/usr/bin/env python3
"""Contract test for GemTree (E95)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'GEM_TREE.md').read_text()
DATA = json.loads((NATIVE / 'gem_tree.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['g_objecttype', 'g_fruititem', 'g_fruitseason', 'g_shouldfall', 'g_ctor', 'g_growth', 'g_bushcontents', 'g_trunkcontents', 'g_trunkbushcontents', 'g_makedead', 'g_update', 'g_worldchanged', 'g_recursivetiles', 'g_treetype', 'g_gemitem', 'g_kindself', 'g_isstatic']
IMPS = ['0x005275b4', '0x005275d0', '0x00527620', '0x0052772c', '0x00527748', '0x00529578', '0x00529590', '0x00529648', '0x00529700', '0x005297b8', '0x005298e0', '0x0052a078', '0x0052b750', '0x0052bae4', '0x0052bb20', '0x0052bbdc', '0x0052be44']
COUNTS = {'g_objecttype': (0, 0, 0, 0, 0, 0), 'g_fruititem': (1, 1, 0, 0, 1, 0), 'g_fruitseason': (1, 1, 0, 2, 2, 2), 'g_shouldfall': (0, 0, 0, 0, 0, 0), 'g_ctor': (12, 2, 1, 17, 62, 88), 'g_growth': (0, 0, 0, 0, 0, 0), 'g_bushcontents': (0, 0, 0, 3, 0, 18), 'g_trunkcontents': (0, 0, 0, 2, 0, 12), 'g_trunkbushcontents': (0, 0, 0, 1, 0, 6), 'g_makedead': (3, 1, 0, 0, 3, 5), 'g_update': (8, 2, 1, 8, 17, 22), 'g_worldchanged': (7, 0, 0, 7, 53, 109), 'g_recursivetiles': (2, 1, 0, 2, 13, 5), 'g_treetype': (0, 0, 0, 1, 0, 0), 'g_gemitem': (0, 0, 0, 1, 0, 7), 'g_kindself': (0, 0, 0, 1, 0, 20), 'g_isstatic': (0, 0, 0, 0, 0, 0)}
WORDS = [7, 20, 67, 7, 1640, 6, 138, 92, 46, 74, 486, 1436, 229, 15, 47, 154, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4471
    for needle in ('4471', '0x6e,0x71,0x74', '0x57,0x56,0x4c', '0xe10', 'worldIndexAtWorldPosition',
                   'recursively'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_gem():
    s = BY['g_bushcontents']['semantics']
    assert '0x6e,0x71,0x74' in s
    s = BY['g_gemitem']['semantics']
    assert '0x57,0x56,0x4c' in s
    s = BY['g_worldchanged']['semantics']
    assert 'worldIndexAtWorldPosition' in s
    s = BY['g_recursivetiles']['semantics']
    assert 'recursive' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_gem()
    print('test_gemtree_evidence: OK')
