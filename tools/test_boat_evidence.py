#!/usr/bin/env python3
"""Contract test for Boat (E148)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BOAT.md').read_text()
DATA = json.loads((NATIVE / 'boat.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['bo_00', 'bo_01', 'bo_02', 'bo_03', 'bo_04', 'bo_05', 'bo_06', 'bo_07', 'bo_08', 'bo_09', 'bo_10', 'bo_11', 'bo_12', 'bo_13', 'bo_14', 'bo_15', 'bo_16', 'bo_17', 'bo_18', 'bo_19', 'bo_20', 'bo_21', 'bo_22', 'bo_23', 'bo_24', 'bo_25', 'bo_26', 'bo_27', 'bo_28', 'bo_29', 'bo_30', 'bo_31', 'bo_32', 'bo_33', 'bo_34']
IMPS = ['0x00977f2c', '0x0097772c', '0x00977da8', '0x00976de8', '0x0096dc38', '0x00977dc4', '0x0096be3c', '0x00977568', '0x0096c674', '0x0096cb54', '0x00970180', '0x0096b510', '0x0096b548', '0x0096bab8', '0x0097775c', '0x00977c80', '0x0096aedc', '0x00976c00', '0x0096cd18', '0x00977214', '0x00976c1c', '0x00977d8c', '0x00977c9c', '0x009774f8', '0x0097753c', '0x00977f10', '0x00976dcc', '0x00976c98', '0x00977b78', '0x00976d58', '0x009774e4', '0x00977778', '0x0096cb00', '0x0096dcd4', '0x00977714']
COUNTS = {'bo_00': (0, 0, 0, 0, 0, 0), 'bo_01': (0, 1, 0, 0, 0, 0), 'bo_02': (0, 0, 0, 0, 0, 0), 'bo_03': (8, 1, 0, 7, 9, 9), 'bo_04': (0, 0, 0, 2, 0, 1), 'bo_05': (1, 1, 0, 4, 1, 1), 'bo_06': (8, 1, 0, 6, 9, 6), 'bo_07': (2, 0, 0, 2, 6, 2), 'bo_08': (7, 2, 2, 3, 9, 4), 'bo_09': (3, 2, 1, 5, 6, 0), 'bo_10': (17, 2, 0, 15, 156, 44), 'bo_11': (0, 0, 0, 0, 0, 0), 'bo_12': (4, 2, 1, 3, 7, 6), 'bo_13': (8, 3, 1, 4, 11, 3), 'bo_14': (0, 0, 0, 0, 0, 0), 'bo_15': (0, 0, 0, 0, 0, 0), 'bo_16': (5, 11, 2, 11, 15, 1), 'bo_17': (0, 0, 0, 0, 0, 0), 'bo_18': (10, 2, 1, 8, 34, 53), 'bo_19': (5, 1, 0, 7, 5, 5), 'bo_20': (0, 0, 0, 1, 2, 0), 'bo_21': (0, 0, 0, 0, 0, 0), 'bo_22': (0, 0, 0, 2, 0, 4), 'bo_23': (0, 0, 0, 1, 0, 0), 'bo_24': (0, 0, 0, 0, 0, 0), 'bo_25': (0, 0, 0, 0, 0, 0), 'bo_26': (0, 0, 0, 0, 0, 0), 'bo_27': (0, 0, 0, 1, 3, 0), 'bo_28': (2, 2, 1, 2, 2, 2), 'bo_29': (0, 0, 0, 1, 1, 0), 'bo_30': (0, 0, 0, 0, 0, 0), 'bo_31': (1, 0, 0, 2, 20, 9), 'bo_32': (1, 1, 0, 0, 1, 0), 'bo_33': (3, 1, 1, 3, 3, 3), 'bo_34': (0, 0, 0, 0, 0, 0)}
WORDS = [6, 12, 7, 267, 39, 83, 255, 107, 200, 113, 5837, 7, 180, 216, 7, 7, 397, 7, 968, 180, 31, 7, 60, 17, 11, 7, 7, 48, 66, 29, 5, 256, 21, 99, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 9565
    for needle in ('9565', 'Boat', 'sail', 'remoteUpdate'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_boat():
    assert len(DATA['classes']) == 35
    s = BY['bo_00']['semantics']
    assert '0x977f2c' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_boat()
    print('test_boat_evidence: OK')
