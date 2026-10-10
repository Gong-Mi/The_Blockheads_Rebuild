#!/usr/bin/env python3
"""Contract test for the DynamicWorld draw cluster (E41)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DRAW_PASS.md').read_text()
DATA = json.loads((NATIVE / 'draw_pass.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_predrawupdate_camerami', 'wtl_drawopaqueobjects_proj', 'wtl_drawfreeblocks_project']

IMPS = ['0x008d11a8', '0x008d17ec', '0x008d4760']

COUNTS = {
    'wtl_predrawupdate_camerami': (2, 1, 0, 3, 15, 15),
    'wtl_drawopaqueobjects_proj': (4, 2, 0, 4, 17, 23),
    'wtl_drawfreeblocks_project': (3, 0, 0, 1, 11, 15),
}

WORDS = [401, 1395, 548]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2344
    for needle in ('2344', 'ffe23538', 'ffe23534', '0xa8', '0x00E4AA1C', 'map<int, int>',
                   '0xb'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_predraw():
    s = BY['wtl_predrawupdate_camerami']['semantics']
    for needle in ('ffffe4f4', 'ffffe4f0', 'ffe23534', 'lsl 2'):
        assert needle in s, needle


def test_draws():
    s = BY['wtl_drawopaqueobjects_proj']['semantics']
    for needle in ('ffffe4f4', 'ffffe4f0', 'ffe23538', '0x00E4AA1C'):
        assert needle in s, needle
    s = BY['wtl_drawfreeblocks_project']['semantics']
    for needle in ('0xa8', 'map<int, int>', '0xb', 'ffe23538', '~map<int,int>()'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_predraw()
    test_draws()
    print('test_draw_pass_evidence: OK')
