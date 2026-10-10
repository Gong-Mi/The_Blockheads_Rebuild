#!/usr/bin/env python3
"""Contract test for the Workbench twin giants closure (E80)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_GIANTS.md').read_text()
DATA = json.loads((NATIVE / 'workbench_giants.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wg_update', 'wg_draw']
IMPS = ['0x00aeea18', '0x00af11f0']
COUNTS = {
    'wg_update': (31, 2, 0, 41, 78, 122),
    'wg_draw': (41, 24, 7, 50, 259, 238),
}
WORDS = [2550, 8600]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 11150
    for needle in ('11150', 'tileIsBurnable', 'fillQuadBuffer', 'itemTypeIsPainting',
                   'updateQuadBufferTexCoords', '0.8078', '96/96'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_censuses():
    s = BY['wg_update']['semantics']
    for needle in ('tileIsBurnable', 'tileIsWater', 'fmodf'):
        assert needle in s, needle
    s = BY['wg_draw']['semantics']
    for needle in ('fillQuadBuffer', 'itemTypeIsPainting', '0.8078', '8600'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_censuses()
    print('test_wbgiants_evidence: OK')
