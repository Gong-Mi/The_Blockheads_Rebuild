#!/usr/bin/env python3
"""Contract test for TrainStation (E155)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TRAINSTATION.md').read_text()
DATA = json.loads((NATIVE / 'trainstation.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ["ts_00", "ts_01", "ts_02", "ts_03", "ts_04", "ts_05", "ts_06", "ts_07", "ts_08", "ts_09", "ts_10", "ts_11", "ts_12", "ts_13", "ts_14", "ts_15", "ts_16", "ts_17", "ts_18", "ts_19", "ts_20", "ts_21", "ts_22", "ts_23", "ts_24", "ts_25", "ts_26"]
IMPS = ["0x00b3f7f0", "0x00b395e4", "0x00b39df0", "0x00b3f17c", "0x00b3a2b0", "0x00b3e730", "0x00b3e74c", "0x00b3e6e4", "0x00b3e6c8", "0x00b380dc", "0x00b38978", "0x00b3912c", "0x00b3a290", "0x00b3f9d0", "0x00b3f9ec", "0x00b39acc", "0x00b3e768", "0x00b3f108", "0x00b3f160", "0x00b3ecdc", "0x00b3ef34", "0x00b3f124", "0x00b3eea4", "0x00b39f60", "0x00b39590", "0x00b3f198", "0x00b380c0"]
COUNTS = {"ts_00": [5, 2, 1, 2, 5, 5], "ts_01": [6, 4, 2, 3, 11, 5], "ts_02": [2, 2, 1, 4, 5, 0], "ts_03": [0, 0, 0, 0, 0, 0], "ts_04": [17, 2, 0, 12, 158, 32], "ts_05": [0, 0, 0, 0, 0, 0], "ts_06": [0, 0, 0, 0, 0, 0], "ts_07": [1, 1, 0, 0, 1, 0], "ts_08": [0, 0, 0, 0, 0, 0], "ts_09": [8, 18, 2, 8, 19, 0], "ts_10": [7, 3, 2, 3, 14, 6], "ts_11": [7, 5, 1, 3, 12, 2], "ts_12": [0, 0, 0, 0, 0, 0], "ts_13": [0, 0, 0, 0, 0, 0], "ts_14": [0, 0, 0, 0, 0, 0], "ts_15": [8, 5, 1, 3, 13, 1], "ts_16": [7, 1, 0, 9, 12, 9], "ts_17": [0, 0, 0, 0, 0, 0], "ts_18": [0, 0, 0, 0, 0, 0], "ts_19": [2, 1, 1, 2, 6, 0], "ts_20": [7, 1, 0, 3, 7, 1], "ts_21": [0, 0, 0, 1, 0, 0], "ts_22": [1, 2, 1, 1, 1, 0], "ts_23": [5, 2, 3, 4, 7, 1], "ts_24": [1, 1, 0, 0, 1, 0], "ts_25": [2, 1, 0, 3, 16, 21], "ts_26": [0, 0, 0, 0, 0, 0]}
WORDS = [120, 223, 92, 7, 3729, 7, 7, 19, 7, 551, 388, 204, 8, 7, 7, 201, 349, 7, 7, 114, 117, 15, 36, 174, 21, 391, 7]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6815
    for needle in ('6815', 'updateBitmapString', 'setText', 'initSubDerivedItems'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == tuple(COUNTS[n]), (n, kinds(BY[n]))


def test_trainstation():
    assert len(DATA['classes']) == 27
    s = BY['ts_01']['semantics']
    assert '0xb395e4' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_trainstation()
    print('test_trainstation_evidence: OK')
