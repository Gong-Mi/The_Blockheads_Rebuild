#!/usr/bin/env python3
"""Contract test for the DynamicWorld last smalls (E43)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'LAST_SMALLS.md').read_text()
DATA = json.loads((NATIVE / 'last_smalls.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_openelevatoratpos_', 'wtl_elevatormotoratpos_', 'wtl_addelevatormotoratpos_',
         'wtl_removeelevatormotoratp', 'wtl_getrailatpos_', 'wtl_removerailatpos_',
         'wtl_treeatpos_', 'wtl_sendpaintingdataforpai']

IMPS = ['0x008ebd50', '0x008ebed0', '0x008ecd4c', '0x008ecdf0', '0x008ed254', '0x008ed2c4',
        '0x008ef618', '0x009016c0']

COUNTS = {
    'wtl_openelevatoratpos_': (5, 2, 1, 0, 9, 0),
    'wtl_elevatormotoratpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addelevatormotoratpos_': (1, 0, 0, 0, 1, 0),
    'wtl_removeelevatormotoratp': (2, 1, 0, 0, 2, 0),
    'wtl_getrailatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_removerailatpos_': (3, 1, 0, 0, 3, 0),
    'wtl_treeatpos_': (1, 0, 0, 0, 1, 5),
    'wtl_sendpaintingdataforpai': (9, 1, 2, 1, 9, 4),
}

WORDS = [96, 28, 41, 45, 28, 56, 56, 186]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 536
    for needle in ('536', '0x37 (55)', '0x28 (40)', '0x00E4AA64', 'ffe23640', 'ffe23648',
                   '0xfff34174'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_triplets_and_tree():
    s = BY['wtl_elevatormotoratpos_']['semantics']
    assert '0x37 (55)' in s and 'ffe235f0' in s
    s = BY['wtl_removeelevatormotoratp']['semantics']
    assert 'ffe23640' in s and 'ffe23600' in s
    s = BY['wtl_removerailatpos_']['semantics']
    for needle in ('ffe235e0', 'ffe23648', 'ffe23600'):
        assert needle in s, needle
    s = BY['wtl_treeatpos_']['semantics']
    for needle in ('0xb', '0x00E4AA64', '11'):
        assert needle in s, needle


def test_elevator_and_painting():
    s = BY['wtl_openelevatoratpos_']['semantics']
    for needle in ('ffe2af10', '0xfff34174', 'vcvt'):
        assert needle in s, needle
    s = BY['wtl_sendpaintingdataforpai']['semantics']
    for needle in ('ffe23348', 'ffe23788', '8-byte'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_triplets_and_tree()
    test_elevator_and_painting()
    print('test_last_smalls_evidence: OK')
