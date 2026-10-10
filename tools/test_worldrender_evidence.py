#!/usr/bin/env python3
"""Contract test for the World renderer (E102)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_RENDER.md').read_text()
DATA = json.loads((NATIVE / 'world_render.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wd_00', 'wd_01', 'wd_02', 'wd_03', 'wd_04', 'wd_05', 'wd_06', 'wd_07', 'wd_08', 'wd_09', 'wd_10', 'wd_11', 'wd_12', 'wd_13']
IMPS = ['0x0058c7f8', '0x005aa5c8', '0x005ab5bc', '0x005b3e78', '0x005b3fb0', '0x005b466c', '0x005b6698', '0x005b6820', '0x005c29c0', '0x005c3800', '0x005c5ce0', '0x005c5fa8', '0x005c6414', '0x005d5534']
COUNTS = {'wd_00': (101, 16, 3, 240, 1121, 394), 'wd_01': (1, 1, 0, 8, 43, 26), 'wd_02': (0, 0, 0, 8, 16, 10), 'wd_03': (3, 1, 1, 1, 3, 3), 'wd_04': (4, 1, 0, 3, 7, 14), 'wd_05': (1, 1, 1, 3, 6, 6), 'wd_06': (2, 1, 1, 1, 3, 6), 'wd_07': (1, 0, 0, 1, 29, 20), 'wd_08': (5, 1, 1, 7, 19, 14), 'wd_09': (9, 3, 3, 2, 21, 1), 'wd_10': (0, 0, 0, 5, 8, 4), 'wd_11': (2, 1, 0, 0, 3, 1), 'wd_12': (4, 2, 0, 2, 11, 15), 'wd_13': (0, 0, 0, 1, 0, 0)}
WORDS = [29808, 761, 732, 78, 213, 229, 98, 482, 558, 329, 178, 65, 289, 20]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 33840
    for needle in ('33840', '29808', 'glVertexAttribPointer', 'glBindTexture', 'pushDepthMaskState', '0xbe2', '0x1406'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_render():
    s = BY['wd_00']['semantics']
    assert 'glVertexAttribPointer' in s and 'x92' in s
    assert '0x84c0' in s
    s = BY['wd_09']['semantics']
    assert 'exportCurrentFrame' in s.lower() or 'frame exporter' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_render()
    print('test_worldrender_evidence: OK')
