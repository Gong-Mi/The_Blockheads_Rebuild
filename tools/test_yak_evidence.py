#!/usr/bin/env python3
"""Contract test for the Yak (E98)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'YAK.md').read_text()
DATA = json.loads((NATIVE / 'yak.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['y_00', 'y_01', 'y_02', 'y_03', 'y_04', 'y_05', 'y_06', 'y_07', 'y_08', 'y_09', 'y_10', 'y_11', 'y_12', 'y_13', 'y_14', 'y_15', 'y_16', 'y_17', 'y_18', 'y_19', 'y_20', 'y_21', 'y_22', 'y_23', 'y_24', 'y_25', 'y_26', 'y_27', 'y_28', 'y_29', 'y_30', 'y_31', 'y_32']
IMPS = ['0x0095c7c4', '0x0095c7e0', '0x0095c810', '0x0095c844', '0x0095c874', '0x0095c890', '0x0095c8c0', '0x0095c8dc', '0x0095c8f8', '0x0095c914', '0x0095c9c0', '0x0095cba8', '0x0095d640', '0x0095d65c', '0x0095d868', '0x0095dcfc', '0x0095e0a8', '0x0095e270', '0x0095e47c', '0x0095e568', '0x0095e6a0', '0x0095e834', '0x0095e99c', '0x0095e9b8', '0x00963040', '0x00965850', '0x009658b4', '0x0096596c', '0x00965c1c', '0x00965cd4', '0x00965fb0', '0x00966388', '0x009663a4']
COUNTS = {'y_00': (0, 0, 0, 0, 0, 0), 'y_01': (0, 0, 0, 0, 0, 0), 'y_02': (0, 0, 0, 0, 0, 0), 'y_03': (0, 0, 0, 0, 0, 0), 'y_04': (0, 1, 0, 0, 0, 0), 'y_05': (0, 1, 0, 0, 0, 0), 'y_06': (0, 0, 0, 0, 0, 0), 'y_07': (0, 0, 0, 0, 0, 0), 'y_08': (0, 0, 0, 0, 0, 0), 'y_09': (1, 1, 1, 2, 1, 0), 'y_10': (0, 0, 0, 11, 0, 3), 'y_11': (7, 12, 3, 18, 29, 1), 'y_12': (0, 0, 0, 0, 0, 0), 'y_13': (2, 2, 1, 7, 8, 0), 'y_14': (4, 3, 1, 2, 6, 3), 'y_15': (2, 2, 1, 3, 2, 2), 'y_16': (1, 0, 0, 2, 3, 6), 'y_17': (4, 1, 1, 0, 8, 4), 'y_18': (2, 1, 1, 0, 3, 2), 'y_19': (1, 1, 0, 3, 1, 1), 'y_20': (3, 1, 1, 1, 3, 1), 'y_21': (3, 1, 1, 0, 3, 0), 'y_22': (0, 0, 0, 0, 0, 0), 'y_23': (1, 0, 1, 20, 35, 7), 'y_24': (10, 2, 0, 11, 54, 2), 'y_25': (0, 0, 0, 1, 0, 0), 'y_26': (0, 0, 0, 2, 0, 1), 'y_27': (5, 1, 0, 8, 5, 4), 'y_28': (0, 0, 0, 2, 0, 1), 'y_29': (5, 1, 0, 10, 5, 4), 'y_30': (2, 1, 0, 4, 11, 12), 'y_31': (0, 0, 0, 0, 0, 0), 'y_32': (0, 0, 0, 0, 0, 0)}
WORDS = [7, 37, 25, 12, 40, 33, 21, 14, 7, 43, 122, 678, 7, 131, 159, 122, 114, 131, 59, 78, 101, 90, 7, 3592, 2196, 25, 46, 172, 46, 183, 246, 13, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 8563
    for needle in ('8563', '0x13f', '0x143', '0x141', 'powf', 'lrand48'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_yak():
    s = BY['y_27']['semantics']
    assert '0x13f' in s
    s = BY['y_29']['semantics']
    assert '0x143' in s
    s = BY['y_23']['semantics']
    assert 'powf' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_yak()
    print('test_yak_evidence: OK')
