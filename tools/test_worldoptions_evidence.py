#!/usr/bin/env python3
"""Contract test for MultiplayerWorldOptionsUI (E158)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLDOPTIONS.md').read_text()
DATA = json.loads((NATIVE / 'worldoptions.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ["mwou_00", "mwou_01", "mwou_02", "mwou_03", "mwou_04", "mwou_05", "mwou_06", "mwou_07", "mwou_08", "mwou_09", "mwou_10", "mwou_11", "mwou_12", "mwou_13", "mwou_14", "mwou_15", "mwou_16", "mwou_17", "mwou_18", "mwou_19", "mwou_20", "mwou_21", "mwou_22", "mwou_23", "mwou_24", "mwou_25", "mwou_26", "mwou_27", "mwou_28", "mwou_29", "mwou_30", "mwou_31", "mwou_32", "mwou_33", "mwou_34"]
IMPS = ["0x004f5774", "0x004f5484", "0x004f356c", "0x004f4738", "0x004f3c10", "0x004f56ac", "0x004f5648", "0x004f5578", "0x004f54f8", "0x004f5264", "0x004f0a2c", "0x004f4a44", "0x004f07cc", "0x004f53c0", "0x004f400c", "0x004f31b0", "0x004f5710", "0x004f55e4", "0x004edab4", "0x004f4b00", "0x004f2df4", "0x004f4c68", "0x004f46e8", "0x004f4400", "0x004f3780", "0x004f35d4", "0x004f0f7c", "0x004f4b1c", "0x004f3718", "0x004f297c", "0x004f3b58", "0x004f3f88", "0x004f28fc", "0x004f287c", "0x004f0dc8"]
COUNTS = {"mwou_00": [0, 0, 0, 0, 0, 0], "mwou_01": [1, 1, 0, 1, 1, 0], "mwou_02": [1, 1, 0, 1, 1, 0], "mwou_03": [7, 1, 1, 6, 7, 3], "mwou_04": [9, 1, 0, 4, 11, 3], "mwou_05": [1, 1, 0, 1, 1, 0], "mwou_06": [1, 1, 0, 1, 1, 0], "mwou_07": [1, 1, 0, 1, 1, 0], "mwou_08": [1, 1, 0, 1, 1, 0], "mwou_09": [2, 1, 1, 4, 2, 1], "mwou_10": [3, 2, 1, 14, 16, 0], "mwou_11": [1, 1, 0, 3, 1, 1], "mwou_12": [5, 1, 0, 4, 8, 0], "mwou_13": [1, 1, 0, 3, 1, 2], "mwou_14": [12, 5, 1, 2, 12, 1], "mwou_15": [1, 0, 0, 12, 11, 4], "mwou_16": [1, 1, 0, 1, 1, 0], "mwou_17": [1, 1, 0, 1, 1, 0], "mwou_18": [55, 35, 14, 30, 119, 33], "mwou_19": [0, 0, 0, 0, 0, 0], "mwou_20": [1, 0, 0, 12, 11, 4], "mwou_21": [9, 6, 2, 1, 7, 1], "mwou_22": [1, 1, 0, 0, 1, 0], "mwou_23": [7, 3, 0, 4, 8, 2], "mwou_24": [8, 3, 0, 5, 12, 2], "mwou_25": [2, 1, 0, 3, 2, 0], "mwou_26": [10, 1, 0, 21, 48, 10], "mwou_27": [3, 1, 0, 3, 3, 2], "mwou_28": [1, 1, 0, 1, 1, 0], "mwou_29": [2, 0, 0, 12, 11, 4], "mwou_30": [2, 0, 0, 0, 3, 0], "mwou_31": [1, 1, 0, 1, 1, 0], "mwou_32": [0, 0, 0, 1, 0, 0], "mwou_33": [0, 0, 0, 1, 0, 0], "mwou_34": [1, 1, 0, 4, 4, 0]}
WORDS = [6, 29, 26, 195, 222, 25, 25, 27, 32, 87, 231, 47, 152, 49, 253, 239, 25, 25, 2762, 7, 239, 231, 20, 186, 246, 81, 1600, 83, 26, 286, 46, 33, 32, 32, 109]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 7714
    for needle in ('7714', 'passwordToggleButton', 'addCreditButton', 'ownerPortalButton'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == tuple(COUNTS[n]), (n, kinds(BY[n]))


def test_worldoptions():
    assert len(DATA['classes']) == 35
    s = BY['mwou_18']['semantics']
    assert '0x4edab4' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_worldoptions()
    print('test_worldoptions_evidence: OK')
