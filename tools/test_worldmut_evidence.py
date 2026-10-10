#!/usr/bin/env python3
"""Contract test for the World tile-mutation core (E100)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_MUTATION.md').read_text()
DATA = json.loads((NATIVE / 'world_mutation.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wm_00', 'wm_01', 'wm_02', 'wm_03', 'wm_04', 'wm_05', 'wm_06', 'wm_07', 'wm_08', 'wm_09', 'wm_10', 'wm_11', 'wm_12', 'wm_13', 'wm_14', 'wm_15', 'wm_16', 'wm_17', 'wm_18', 'wm_19', 'wm_20', 'wm_21', 'wm_22', 'wm_23', 'wm_24', 'wm_25', 'wm_26', 'wm_27', 'wm_28', 'wm_52', 'wm_51', 'wm_50', 'wm_55', 'wm_53', 'wm_56', 'wm_54']
IMPS = ['0x005751f8', '0x005759bc', '0x00575ac8', '0x00575d44', '0x005762c8', '0x00576518', '0x00578430', '0x00578a20', '0x00578c94', '0x00579d58', '0x0057b700', '0x0057bd70', '0x0057bf90', '0x00580f88', '0x0058122c', '0x00581a38', '0x00582364', '0x00582408', '0x00582488', '0x00582a50', '0x00582ad8', '0x00583578', '0x0058c350', '0x0058c408', '0x0058c558', '0x0058c6b8', '0x005b3b70', '0x005c1ddc', '0x005d6fc8', '0x00576120', '0x005761e0', '0x00576878', '0x00579074', '0x0057a30c', '0x0057c034', '0x0057c11c']
COUNTS = {'wm_00': (1, 0, 1, 3, 8, 19), 'wm_01': (2, 0, 0, 1, 2, 1), 'wm_02': (4, 1, 0, 3, 6, 7), 'wm_03': (8, 1, 0, 3, 11, 11), 'wm_04': (2, 1, 0, 4, 3, 11), 'wm_05': (6, 1, 2, 3, 9, 4), 'wm_06': (8, 1, 2, 3, 22, 23), 'wm_07': (2, 1, 0, 3, 5, 17), 'wm_08': (10, 5, 0, 2, 16, 6), 'wm_09': (15, 6, 1, 2, 22, 12), 'wm_10': (12, 5, 0, 3, 22, 14), 'wm_11': (4, 1, 0, 2, 7, 7), 'wm_12': (1, 0, 0, 0, 1, 0), 'wm_13': (5, 1, 1, 3, 5, 6), 'wm_14': (4, 1, 1, 3, 31, 17), 'wm_15': (13, 1, 1, 3, 25, 39), 'wm_16': (1, 0, 0, 0, 1, 0), 'wm_17': (1, 0, 0, 0, 1, 0), 'wm_18': (2, 1, 0, 6, 8, 19), 'wm_19': (1, 0, 0, 1, 1, 0), 'wm_20': (0, 0, 0, 0, 13, 0), 'wm_21': (4, 1, 0, 4, 25, 5), 'wm_22': (0, 0, 0, 1, 3, 0), 'wm_23': (0, 0, 0, 3, 3, 0), 'wm_24': (0, 0, 0, 3, 3, 0), 'wm_25': (0, 0, 0, 3, 3, 0), 'wm_26': (5, 1, 1, 3, 5, 5), 'wm_27': (2, 0, 1, 7, 31, 21), 'wm_28': (2, 1, 0, 1, 2, 0), 'wm_52': (1, 1, 0, 0, 1, 0), 'wm_51': (1, 1, 0, 0, 1, 0), 'wm_50': (38, 6, 7, 8, 98, 137), 'wm_55': (24, 6, 5, 3, 37, 29), 'wm_53': (24, 6, 4, 4, 81, 71), 'wm_56': (1, 0, 0, 0, 1, 0), 'wm_54': (50, 5, 5, 6, 162, 518)}
WORDS = [485, 67, 159, 247, 148, 216, 380, 157, 248, 365, 390, 136, 41, 169, 472, 587, 41, 32, 355, 34, 202, 438, 46, 84, 88, 80, 194, 621, 59, 48, 58, 1774, 629, 1206, 58, 4785]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 15099
    for needle in ('15099', '4785', '900', '450', 'polarToRectangular', 'linearInterpolate', '0x1f4'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_core():
    s = BY['wm_54']['semantics']
    assert '4785w' in s and 'x68' in s
    s = BY['wm_20']['semantics']
    assert 'polarToRectangular' in s
    s = BY['wm_18']['semantics']
    assert '900' in s and '450' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_core()
    print('test_worldmut_evidence: OK')
