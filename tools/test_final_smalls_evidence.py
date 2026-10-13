#!/usr/bin/env python3
"""Contract test for the DynamicWorld final smalls (E42)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'FINAL_SMALLS.md').read_text()
DATA = json.loads((NATIVE / 'final_smalls.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_playtimecrystalreceive', 'wtl_freeblockwithuniqueid_', 'wtl_lightchangedatmacropos',
         'wtl_activeblockhead', 'wtl_activeblockheadindex', 'wtl_selectedblockheadchang']

IMPS = ['0x008de650', '0x008df2a8', '0x008e1b68', '0x008e2bac', '0x008e2cbc', '0x008e2cf8']

COUNTS = {
    'wtl_playtimecrystalreceive': (3, 2, 1, 1, 8, 1),
    'wtl_freeblockwithuniqueid_': (0, 0, 0, 2, 4, 4),
    'wtl_lightchangedatmacropos': (1, 0, 0, 0, 1, 0),
    'wtl_activeblockhead': (2, 1, 0, 2, 2, 2),
    'wtl_activeblockheadindex': (0, 0, 0, 1, 0, 0),
    'wtl_selectedblockheadchang': (1, 1, 0, 2, 1, 2),
}

WORDS = [140, 71, 34, 68, 15, 52]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 380
    for needle in ('380', 'ffffe55c', 'ffffe5a4', '0xa8', 'ffe23580', '0xfff34074'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_slots_and_lookups():
    s = BY['wtl_activeblockheadindex']['semantics']
    assert 'ffffe55c' in s
    s = BY['wtl_selectedblockheadchang']['semantics']
    for needle in ('ffffe55c', 'bhs', 'ffe23204'):
        assert needle in s, needle
    s = BY['wtl_freeblockwithuniqueid_']['semantics']
    for needle in ('0xa8', 'ffffe54c', 'ffffe550', '__count_unique'):
        assert needle in s, needle
    s = BY['wtl_playtimecrystalreceive']['semantics']
    for needle in ('ffffe5a4', 'vcmpe', '0xfff34074', 'vcvt'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_slots_and_lookups()
    print('test_final_smalls_evidence: OK')
