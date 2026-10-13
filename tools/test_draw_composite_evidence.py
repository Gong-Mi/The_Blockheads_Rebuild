#!/usr/bin/env python3
"""Contract test for the DynamicWorld giant draw composite (E44)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DRAW_COMPOSITE.md').read_text()
DATA = json.loads((NATIVE / 'draw_composite.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_draw_projectionmatrix_']
IMPS = ['0x008d4ff0']
COUNTS = {'wtl_draw_projectionmatrix_': (6, 1, 0, 7, 51, 60)}
WORDS = [7203]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 7203
    for needle in ('7203', 'ffe2353c', 'ffe23538', '0x00E4AA3C', '0x00E4AA0C',
                   '9.3 KB', 'structural pass', '0x8d6264'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_structure_claims():
    s = BY['wtl_draw_projectionmatrix_']['semantics']
    for needle in ('ffe2353c', 'ffe23538', 'ffffe4f4', 'ffffe4f0', 'ffffe4f8',
                   'ffffe54c', 'tree_next', '0x8d5258', '0x8dc05c', 'deferred'):
        assert needle in s, needle


def test_boundary_flag():
    s = BY['wtl_draw_projectionmatrix_']['semantics']
    assert 'STRUCTURAL pass' in s
    assert 'word-by-word transcription' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_structure_claims()
    test_boundary_flag()
    print('test_draw_composite_evidence: OK')
