#!/usr/bin/env python3
"""Contract test for FreeBlock (E152)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'FREEBLOCK.md').read_text()
DATA = json.loads((NATIVE / 'freeblock.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['fb_00', 'fb_01', 'fb_02', 'fb_03', 'fb_04', 'fb_05', 'fb_06', 'fb_07', 'fb_08', 'fb_09', 'fb_10', 'fb_11', 'fb_12', 'fb_13', 'fb_14', 'fb_15', 'fb_16', 'fb_17', 'fb_18', 'fb_19', 'fb_20', 'fb_21', 'fb_22', 'fb_23', 'fb_24', 'fb_25', 'fb_26', 'fb_27', 'fb_28', 'fb_29', 'fb_30']
IMPS = ['0x0062a6f0', '0x0062b260', '0x00634914', '0x006346c0', '0x00634744', '0x00629500', '0x0062f868', '0x00634850', '0x006343f4', '0x0062bcd8', '0x00634894', '0x00625c90', '0x00626004', '0x00627f74', '0x006280cc', '0x00634640', '0x0063480c', '0x0063451c', '0x0062ba94', '0x00629670', '0x0063495c', '0x006346fc', '0x00634780', '0x006348d0', '0x0063467c', '0x006349e4', '0x00634624', '0x006349a8', '0x006347c8', '0x0062a4bc', '0x00626940']
COUNTS = {'fb_00': (12, 3, 3, 12, 25, 21), 'fb_01': (11, 3, 3, 0, 23, 19), 'fb_02': (0, 0, 0, 1, 0, 0), 'fb_03': (0, 0, 0, 1, 0, 0), 'fb_04': (0, 0, 0, 1, 0, 0), 'fb_05': (2, 2, 1, 4, 5, 0), 'fb_06': (5, 1, 0, 15, 47, 34), 'fb_07': (0, 0, 0, 1, 0, 0), 'fb_08': (1, 1, 0, 3, 3, 2), 'fb_09': (5, 1, 2, 1, 16, 0), 'fb_10': (0, 0, 0, 1, 0, 0), 'fb_11': (5, 3, 1, 6, 8, 1), 'fb_12': (8, 1, 2, 14, 22, 19), 'fb_13': (1, 0, 0, 0, 4, 1), 'fb_14': (21, 5, 3, 17, 40, 44), 'fb_15': (0, 0, 0, 1, 0, 0), 'fb_16': (0, 0, 0, 1, 0, 0), 'fb_17': (3, 0, 0, 4, 3, 0), 'fb_18': (3, 2, 1, 6, 3, 4), 'fb_19': (2, 2, 1, 3, 2, 5), 'fb_20': (0, 0, 0, 1, 0, 0), 'fb_21': (0, 0, 0, 1, 0, 0), 'fb_22': (0, 0, 0, 1, 0, 0), 'fb_23': (0, 0, 0, 1, 0, 0), 'fb_24': (0, 0, 0, 1, 0, 0), 'fb_25': (0, 0, 0, 1, 0, 0), 'fb_26': (0, 0, 0, 0, 0, 0), 'fb_27': (0, 0, 0, 1, 0, 0), 'fb_28': (0, 0, 0, 1, 0, 0), 'fb_29': (3, 1, 1, 5, 4, 2), 'fb_30': (2, 0, 1, 2, 2, 2)}
WORDS = [641, 525, 18, 15, 15, 92, 1789, 17, 74, 196, 15, 210, 591, 72, 964, 15, 17, 66, 145, 101, 19, 18, 18, 17, 17, 17, 7, 15, 17, 141, 74]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5938
    for needle in ('5938', 'FreeBlock', 'hovers', 'light'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_freeblock():
    assert len(DATA['classes']) == 31
    s = BY['fb_00']['semantics']
    assert '0x62a6f0' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_freeblock()
    print('test_freeblock_evidence: OK')
