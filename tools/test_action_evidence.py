#!/usr/bin/env python3
"""Contract test for Action (E154)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'ACTION.md').read_text()
DATA = json.loads((NATIVE / 'action.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ["ac_00", "ac_01", "ac_02", "ac_03", "ac_04", "ac_05", "ac_06", "ac_07", "ac_08", "ac_09", "ac_10", "ac_11", "ac_12", "ac_13", "ac_14", "ac_15", "ac_16", "ac_17", "ac_18", "ac_19", "ac_20", "ac_21", "ac_22", "ac_23", "ac_24", "ac_25", "ac_26", "ac_27", "ac_28", "ac_29", "ac_30", "ac_31", "ac_32", "ac_33", "ac_34"]
IMPS = ["0x0073710c", "0x00736e14", "0x00736fb0", "0x00736860", "0x00736f2c", "0x00736ea8", "0x0073664c", "0x00736c94", "0x007368e0", "0x007367e0", "0x00734e64", "0x00736a34", "0x00736ab8", "0x00736b3c", "0x00736bc0", "0x00737034", "0x007369b0", "0x00736d94", "0x00736d14", "0x00736e5c", "0x00736fe8", "0x0073689c", "0x00736f68", "0x00736ee0", "0x00736cd0", "0x00736940", "0x0073681c", "0x00736a6c", "0x00736af4", "0x00736b78", "0x00736c24", "0x00737094", "0x007369e8", "0x00736dd0", "0x00736d50"]
COUNTS = {"ac_00": [0, 0, 0, 0, 0, 0], "ac_01": [0, 0, 0, 1, 0, 0], "ac_02": [0, 0, 0, 1, 0, 0], "ac_03": [0, 0, 0, 1, 0, 0], "ac_04": [0, 0, 0, 1, 0, 0], "ac_05": [0, 0, 0, 1, 0, 0], "ac_06": [3, 2, 1, 4, 5, 0], "ac_07": [0, 0, 0, 1, 0, 0], "ac_08": [0, 0, 0, 1, 1, 0], "ac_09": [0, 0, 0, 1, 0, 0], "ac_10": [2, 2, 1, 11, 4, 2], "ac_11": [0, 0, 0, 1, 0, 0], "ac_12": [0, 0, 0, 1, 0, 0], "ac_13": [0, 0, 0, 1, 0, 0], "ac_14": [0, 0, 0, 1, 1, 0], "ac_15": [0, 0, 0, 1, 1, 0], "ac_16": [0, 0, 0, 1, 0, 0], "ac_17": [0, 0, 0, 1, 0, 0], "ac_18": [0, 0, 0, 1, 0, 0], "ac_19": [0, 0, 0, 1, 0, 0], "ac_20": [0, 0, 0, 1, 1, 0], "ac_21": [0, 0, 0, 1, 0, 0], "ac_22": [0, 0, 0, 1, 0, 0], "ac_23": [0, 0, 0, 1, 1, 0], "ac_24": [0, 0, 0, 1, 0, 0], "ac_25": [0, 0, 0, 1, 1, 0], "ac_26": [0, 0, 0, 1, 0, 0], "ac_27": [0, 0, 0, 1, 1, 0], "ac_28": [0, 0, 0, 1, 0, 0], "ac_29": [0, 0, 0, 1, 0, 0], "ac_30": [0, 0, 0, 1, 1, 0], "ac_31": [0, 0, 0, 1, 1, 0], "ac_32": [0, 0, 0, 1, 1, 0], "ac_33": [0, 0, 0, 1, 0, 0], "ac_34": [0, 0, 0, 1, 0, 0]}
WORDS = [6, 18, 14, 15, 15, 14, 101, 15, 24, 15, 205, 14, 15, 15, 25, 24, 14, 15, 15, 19, 19, 17, 18, 19, 17, 28, 17, 19, 18, 18, 28, 30, 19, 17, 17]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 899
    for needle in ('899', 'goalTilePos', 'pathType', 'isAI'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == tuple(COUNTS[n]), (n, kinds(BY[n]))


def test_action():
    assert len(DATA['classes']) == 35
    s = BY['ac_00']['semantics']
    assert '0x73710c' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_action()
    print('test_action_evidence: OK')
