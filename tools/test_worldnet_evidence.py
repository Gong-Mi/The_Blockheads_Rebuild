#!/usr/bin/env python3
"""Contract test for the World net/admin core (E103)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_NET.md').read_text()
DATA = json.loads((NATIVE / 'world_net.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wn_00', 'wn_01', 'wn_02', 'wn_03', 'wn_04', 'wn_05', 'wn_06', 'wn_07', 'wn_08', 'wn_09', 'wn_10', 'wn_11', 'wn_12', 'wn_13', 'wn_14', 'wn_15', 'wn_16', 'wn_17', 'wn_18', 'wn_19', 'wn_20']
IMPS = ['0x005536ec', '0x005547f8', '0x00554cfc', '0x00554f04', '0x0055555c', '0x00557bd4', '0x0056b674', '0x0056dbd8', '0x0056dc8c', '0x005b9e10', '0x005ba014', '0x005bfcb0', '0x005c01a4', '0x005c0570', '0x005c0698', '0x005c07c0', '0x005c0b4c', '0x005c0f54', '0x005c1298', '0x005c15dc', '0x005c1920']
COUNTS = {'wn_00': (16, 26, 4, 17, 41, 17), 'wn_01': (7, 1, 1, 7, 11, 11), 'wn_02': (5, 1, 0, 4, 5, 5), 'wn_03': (11, 3, 1, 11, 14, 21), 'wn_04': (10, 4, 4, 3, 15, 7), 'wn_05': (1, 1, 0, 0, 1, 0), 'wn_06': (18, 36, 4, 0, 102, 122), 'wn_07': (2, 1, 0, 1, 2, 0), 'wn_08': (2, 1, 0, 1, 2, 0), 'wn_09': (5, 1, 2, 2, 5, 1), 'wn_10': (37, 15, 4, 5, 85, 57), 'wn_11': (14, 2, 1, 6, 20, 8), 'wn_12': (7, 2, 0, 5, 11, 7), 'wn_13': (3, 1, 0, 1, 4, 1), 'wn_14': (3, 1, 0, 1, 4, 1), 'wn_15': (6, 1, 1, 2, 10, 10), 'wn_16': (9, 1, 3, 2, 12, 5), 'wn_17': (8, 1, 3, 2, 9, 4), 'wn_18': (8, 1, 3, 2, 9, 4), 'wn_19': (8, 1, 3, 2, 9, 4), 'wn_20': (1, 1, 0, 2, 1, 0)}
WORDS = [1000, 321, 130, 406, 330, 27, 2312, 45, 43, 129, 1416, 317, 243, 74, 74, 227, 258, 209, 209, 209, 37]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 8016
    for needle in ('8016', '2312', '1416', '0xc350', '0x7fffffff', '0x3e7', 'remote quartet'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_net():
    s = BY['wn_10']['semantics']
    assert '0xc350' in s
    s = BY['wn_11']['semantics']
    assert '0x7fffffff' in s
    s = BY['wn_12']['semantics']
    assert '0x3e7' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_net()
    print('test_worldnet_evidence: OK')
