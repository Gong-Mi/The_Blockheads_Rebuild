#!/usr/bin/env python3
"""Contract test for LoadWorldUI (E157)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'LOADWORLDUI.md').read_text()
DATA = json.loads((NATIVE / 'loadworldui.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ["lwu_00", "lwu_01", "lwu_02", "lwu_03", "lwu_04", "lwu_05", "lwu_06", "lwu_07", "lwu_08", "lwu_09", "lwu_10", "lwu_11", "lwu_12", "lwu_13", "lwu_14", "lwu_15", "lwu_16", "lwu_17", "lwu_18", "lwu_19", "lwu_20", "lwu_21", "lwu_22", "lwu_23", "lwu_24", "lwu_25", "lwu_26", "lwu_27", "lwu_28", "lwu_29", "lwu_30", "lwu_31", "lwu_32", "lwu_33", "lwu_34", "lwu_35"]
IMPS = ["0x00805554", "0x007fe59c", "0x008079b8", "0x0080781c", "0x008076c8", "0x007f36d0", "0x007edb5c", "0x007fe6ec", "0x007ed954", "0x00804c78", "0x007ff328", "0x007fff48", "0x0080658c", "0x00807660", "0x00806ac0", "0x008074c8", "0x008087b0", "0x00808728", "0x0080876c", "0x00806df0", "0x00806c20", "0x007ec070", "0x007ff8d0", "0x00804630", "0x00807a1c", "0x00806934", "0x00808088", "0x007f94ec", "0x007f91d8", "0x007f6428", "0x00803bf4", "0x008087ec", "0x008052c0", "0x0080609c", "0x007ee100", "0x00806120"]
COUNTS = {"lwu_00": [23, 5, 6, 7, 38, 20], "lwu_01": [0, 0, 0, 1, 0, 10], "lwu_02": [1, 1, 0, 1, 1, 0], "lwu_03": [3, 3, 0, 2, 4, 1], "lwu_04": [2, 2, 0, 3, 2, 0], "lwu_05": [46, 32, 9, 16, 130, 74], "lwu_06": [4, 2, 1, 23, 25, 0], "lwu_07": [12, 10, 2, 3, 17, 3], "lwu_08": [2, 1, 0, 3, 6, 0], "lwu_09": [1, 0, 0, 16, 19, 13], "lwu_10": [7, 4, 1, 4, 9, 9], "lwu_11": [36, 17, 8, 20, 76, 187], "lwu_12": [12, 4, 1, 3, 12, 0], "lwu_13": [1, 1, 0, 1, 1, 0], "lwu_14": [2, 0, 0, 2, 4, 2], "lwu_15": [3, 2, 1, 2, 3, 0], "lwu_16": [0, 0, 0, 1, 0, 0], "lwu_17": [0, 0, 0, 1, 0, 0], "lwu_18": [0, 0, 0, 1, 0, 0], "lwu_19": [16, 5, 4, 4, 24, 5], "lwu_20": [2, 0, 0, 0, 9, 7], "lwu_21": [20, 13, 8, 13, 42, 34], "lwu_22": [10, 7, 2, 2, 9, 1], "lwu_23": [1, 0, 0, 16, 19, 13], "lwu_24": [9, 6, 2, 1, 7, 1], "lwu_25": [2, 0, 0, 2, 4, 2], "lwu_26": [10, 13, 2, 2, 20, 2], "lwu_27": [44, 29, 7, 30, 110, 220], "lwu_28": [5, 5, 0, 3, 9, 5], "lwu_29": [6, 1, 0, 28, 33, 20], "lwu_30": [1, 0, 0, 16, 19, 32], "lwu_31": [0, 0, 0, 1, 0, 0], "lwu_32": [7, 1, 1, 0, 10, 6], "lwu_33": [1, 1, 0, 1, 1, 0], "lwu_34": [7, 4, 0, 32, 83, 286], "lwu_35": [14, 5, 1, 3, 17, 0]}
WORDS = [722, 84, 25, 103, 85, 2843, 361, 483, 130, 402, 362, 3883, 234, 26, 88, 102, 15, 17, 17, 438, 116, 1538, 264, 402, 231, 88, 424, 5164, 197, 2924, 655, 15, 165, 33, 5492, 283]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 28411
    for needle in ('28411', 'worldName', 'playButton', 'deleteWorldButton'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == tuple(COUNTS[n]), (n, kinds(BY[n]))


def test_loadworldui():
    assert len(DATA['classes']) == 36
    s = BY['lwu_05']['semantics']
    assert '0x7f36d0' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_loadworldui()
    print('test_loadworldui_evidence: OK')
