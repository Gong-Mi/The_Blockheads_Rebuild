#!/usr/bin/env python3
"""Contract test for the World internals pair (E113)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_CXX.md').read_text()
DATA = json.loads((NATIVE / 'world_cxx.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wc_00', 'wc_01']
IMPS = ['0x005dab64', '0x005b4a00']
COUNTS = {'wc_00': (0, 0, 0, 12, 10, 0), 'wc_01': (6, 4, 2, 7, 36, 45)}
WORDS = [324, 1022]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1346
    for needle in ('1346', '324', '1022', 'macroTileAtMacroPostion',
                   'requestBlockFromServerAtPos',
                   'addArtificialLightContributionForPhysicalBlockLoadedAtXPos',
                   'std::__1::__tree', 'usedPhysicalBlocks', '45 branches', '0xc0'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_cxx():
    s = BY['wc_00']['semantics']
    assert '__tree' in s
    assert 'Vector2::Vector2() x6' in s
    s = BY['wc_01']['semantics']
    assert 'requestBlockFromServerAtPos' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.freePhysicalBlocks' in symbols
    assert 'OBJC_IVAR_$_World.usedPhysicalBlocks' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_cxx()
    print('test_worldcxx_evidence: OK')
