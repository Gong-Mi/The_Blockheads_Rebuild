#!/usr/bin/env python3
"""Contract test for the tree ctor family (E86)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TREE_CTORS.md').read_text()
DATA = json.loads((NATIVE / 'tree_ctors.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cf_ctor', 'lt_ctor', 'at_ctor', 'ot_ctor', 'cn_ctor', 'ct_ctor', 'pt_ctor', 'pt_ctorsave', 'ch_ctor', 'mg_ctor', 'mp_ctor']
IMPS = ['0x007de1c0', '0x00809278', '0x009bca70', '0x00a95c40', '0x00a990a0', '0x00b52850', '0x00b643d0', '0x00b64f48', '0x00d0d670', '0x00d4ab38', '0x00db56d0']
COUNTS = {'cf_ctor': (5, 1, 1, 11, 11, 17), 'lt_ctor': (5, 1, 1, 11, 12, 17), 'at_ctor': (5, 1, 1, 12, 11, 17), 'ot_ctor': (5, 1, 1, 11, 12, 17), 'cn_ctor': (5, 1, 1, 11, 9, 17), 'ct_ctor': (5, 1, 1, 15, 16, 20), 'pt_ctor': (8, 1, 1, 13, 16, 25), 'pt_ctorsave': (4, 4, 1, 2, 6, 2), 'ch_ctor': (5, 1, 1, 11, 9, 17), 'mg_ctor': (5, 1, 1, 11, 12, 17), 'mp_ctor': (5, 1, 1, 11, 10, 17)}
WORDS = [598, 621, 588, 621, 550, 727, 730, 157, 555, 619, 565]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6331
    for needle in ('6331', 'growthVigorForTreeTypeAtPos', '0x1869f', '0x3fffffff',
                   '0x30/31/32', 'fff3e324'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_contract():
    s = BY['at_ctor']['semantics']
    assert 'growthVigorForTreeTypeAtPos' in s and '0x1869f' in s
    s = BY['ct_ctor']['semantics']
    assert '0x3fffffff' in s
    s = BY['cn_ctor']['semantics']
    assert 'OWN growth path' in s
    s = BY['pt_ctorsave']['semantics']
    assert 'fff3e324' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_contract()
    print('test_treectors_evidence: OK')
