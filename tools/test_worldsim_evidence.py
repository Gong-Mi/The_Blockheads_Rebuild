#!/usr/bin/env python3
"""Contract test for the World simulation core (E101)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_SIMULATION.md').read_text()
DATA = json.loads((NATIVE / 'world_simulation.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['ws_00', 'ws_01', 'ws_02', 'ws_03', 'ws_04', 'ws_05', 'ws_06', 'ws_07', 'ws_08', 'ws_09', 'ws_10', 'ws_11']
IMPS = ['0x00564c64', '0x00564f2c', '0x005650d8', '0x00566e64', '0x00567878', '0x0056884c', '0x0056b278', '0x0056dd38', '0x0056dd78', '0x00583c50', '0x005ac1a4', '0x005c78c4']
COUNTS = {'ws_00': (6, 1, 1, 4, 7, 3), 'ws_01': (4, 1, 0, 3, 5, 0), 'ws_02': (11, 4, 1, 68, 96, 36), 'ws_03': (20, 4, 5, 11, 26, 27), 'ws_04': (15, 6, 2, 2, 58, 30), 'ws_05': (59, 7, 0, 22, 121, 131), 'ws_06': (11, 1, 3, 6, 12, 0), 'ws_07': (0, 0, 0, 1, 0, 0), 'ws_08': (140, 25, 12, 71, 348, 299), 'ws_09': (42, 14, 6, 60, 251, 197), 'ws_10': (3, 1, 0, 4, 4, 3), 'ws_11': (19, 1, 1, 6, 22, 13)}
WORDS = [178, 107, 1564, 630, 937, 2699, 255, 16, 7369, 7877, 107, 500]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 22239
    for needle in ('22239', '7369', '7877', 'glDeleteTextures', 'itemTypeIsSowable', '0x15180', 'linearInterpolate'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_sim():
    s = BY['ws_08']['semantics']
    assert '0x258' in s and '0xe10' in s
    s = BY['ws_09']['semantics']
    assert 'linearInterpolate' in s
    s = BY['ws_02']['semantics']
    assert 'glDeleteTextures' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_sim()
    print('test_worldsim_evidence: OK')
