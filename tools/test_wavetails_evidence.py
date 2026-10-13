#!/usr/bin/env python3
"""Contract test for WaveTails (E153)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WAVETAILS.md').read_text()
DATA = json.loads((NATIVE / 'wavetails.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtx_00', 'wtx_01', 'wtx_02', 'wtx_03', 'wtx_04', 'wtx_05', 'wtx_06', 'wtx_07', 'wtx_08', 'wtx_09', 'wtx_10', 'wtx_11', 'wtx_12', 'wtx_13', 'wtx_14', 'wtx_15', 'wtx_16', 'wtx_17', 'wtx_18', 'wtx_19', 'wtx_20', 'wtx_21', 'wtx_22', 'wtx_23', 'wtx_24', 'wtx_25', 'wtx_26', 'wtx_27']
IMPS = ['0x0096b52c', '0x0096de60', '0x00cb4ec4', '0x00cb95b0', '0x00cbc4f0', '0x0078e76c', '0x00797300', '0x00a6bb04', '0x00a781c8', '0x007ab240', '0x00625fe8', '0x00629804', '0x0062bfe8', '0x00a3f85c', '0x00a40940', '0x00a41860', '0x005f4218', '0x005f5de4', '0x00894080', '0x008a45f0', '0x007c8c34', '0x007d6470', '0x005f9ae4', '0x005fca18', '0x005e48f8', '0x005e4914', '0x005e5718', '0x005ebe98']
COUNTS = {'wtx_00': (0, 0, 0, 0, 0, 0), 'wtx_01': (14, 2, 0, 24, 74, 109), 'wtx_02': (0, 0, 0, 0, 0, 0), 'wtx_03': (1, 1, 0, 1, 1, 0), 'wtx_04': (2, 2, 1, 7, 2, 7), 'wtx_05': (1, 1, 1, 0, 1, 0), 'wtx_06': (32, 4, 2, 53, 130, 266), 'wtx_07': (1, 1, 1, 0, 1, 0), 'wtx_08': (48, 8, 5, 76, 267, 351), 'wtx_09': (58, 14, 5, 86, 257, 372), 'wtx_10': (0, 0, 0, 0, 0, 0), 'wtx_11': (12, 14, 3, 11, 40, 15), 'wtx_12': (27, 5, 1, 28, 184, 220), 'wtx_13': (0, 0, 0, 0, 0, 0), 'wtx_14': (1, 1, 1, 0, 1, 0), 'wtx_15': (25, 2, 1, 40, 240, 168), 'wtx_16': (0, 0, 0, 0, 0, 0), 'wtx_17': (8, 1, 0, 8, 13, 15), 'wtx_18': (1, 1, 1, 0, 1, 0), 'wtx_19': (54, 11, 4, 85, 237, 378), 'wtx_20': (1, 1, 1, 0, 1, 0), 'wtx_21': (48, 12, 5, 78, 189, 369), 'wtx_22': (0, 0, 0, 0, 0, 0), 'wtx_23': (1, 1, 1, 1, 1, 2), 'wtx_24': (0, 0, 0, 0, 0, 0), 'wtx_25': (8, 2, 2, 2, 12, 9), 'wtx_26': (6, 6, 1, 4, 11, 3), 'wtx_27': (1, 1, 1, 1, 1, 2)}
WORDS = [7, 2233, 7, 34, 133, 31, 4153, 31, 6542, 6542, 7, 814, 3583, 7, 31, 3996, 7, 364, 31, 6737, 31, 6103, 7, 54, 7, 243, 223, 54]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 42012
    for needle in ('42012', 'objectType', 'getSaveDict', 'update'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_wavetails():
    assert len(DATA['classes']) == 28
    s = BY['wtx_00']['semantics']
    assert '0x96b52c' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_wavetails()
    print('test_wavetails_evidence: OK')
