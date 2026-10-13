#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCKHEAD3.md').read_text()
DATA = json.loads((NATIVE / 'blockhead3.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['hc_00', 'hc_01', 'hc_02', 'hc_03', 'hc_04', 'hc_05', 'hc_06', 'hc_07', 'hc_08', 'hc_09', 'hc_10', 'hc_11', 'hc_12', 'hc_13', 'hc_14', 'hc_15', 'hc_16', 'hc_17', 'hc_18', 'hc_19', 'hc_20', 'hc_21', 'hc_22', 'hc_23', 'hc_24', 'hc_25', 'hc_26', 'hc_27', 'hc_28', 'hc_29', 'hc_30', 'hc_31', 'hc_32', 'hc_33', 'hc_34', 'hc_35', 'hc_36', 'hc_37', 'hc_38', 'hc_39', 'hc_40', 'hc_41', 'hc_42', 'hc_43', 'hc_44', 'hc_45', 'hc_46', 'hc_47', 'hc_48', 'hc_49', 'hc_50', 'hc_51', 'hc_52', 'hc_53', 'hc_54', 'hc_55']
IMPS = ['0x00c80fec', '0x00b9b86c', '0x00b9d894', '0x00c73804', '0x00c73288', '0x00c73b38', '0x00c8a688', '0x00c49968', '0x00c71800', '0x00c80fb0', '0x00c7bb4c', '0x00bb3468', '0x00c86434', '0x00c863e0', '0x00c867d8', '0x00c6cb00', '0x00c6cd08', '0x00c6d618', '0x00b95fe4', '0x00c638a0', '0x00c64ca4', '0x00c7156c', '0x00c6ebc0', '0x00bac9e4', '0x00c6a070', '0x00c72628', '0x00c71fa0', '0x00bb8fa4', '0x00be91fc', '0x00bb0a1c', '0x00be5d40', '0x00c69424', '0x00c68f4c', '0x00be5854', '0x00bb8d6c', '0x00c7ca5c', '0x00c746d0', '0x00c7c5f0', '0x00c722e8', '0x00c73d6c', '0x00c8a1b4', '0x00c753d4', '0x00c73518', '0x00c7162c', '0x00c75364', '0x00b9be40', '0x00c68964', '0x00c683c0', '0x00c87060', '0x00c80e34', '0x00c6595c', '0x00c6a4f8', '0x00c6a55c', '0x00c65204', '0x00c6455c', '0x00c79598']
COUNTS = {'hc_00': (4, 1, 0, 3, 4, 5), 'hc_01': (3, 1, 0, 1, 8, 6), 'hc_02': (6, 5, 3, 16, 10, 5), 'hc_03': (5, 1, 0, 2, 14, 8), 'hc_04': (5, 1, 0, 2, 11, 6), 'hc_05': (5, 1, 0, 2, 9, 7), 'hc_06': (0, 0, 0, 1, 1, 0), 'hc_07': (30, 5, 0, 39, 273, 41), 'hc_08': (13, 7, 1, 7, 27, 26), 'hc_09': (0, 0, 0, 1, 0, 0), 'hc_10': (1, 1, 0, 5, 9, 2), 'hc_11': (0, 0, 0, 0, 0, 0), 'hc_12': (2, 1, 0, 2, 2, 5), 'hc_13': (0, 0, 0, 1, 0, 0), 'hc_14': (2, 1, 0, 4, 2, 5), 'hc_15': (1, 1, 0, 0, 1, 0), 'hc_16': (16, 3, 1, 6, 33, 33), 'hc_17': (14, 2, 1, 7, 25, 23), 'hc_18': (68, 27, 8, 61, 246, 130), 'hc_19': (0, 0, 0, 1, 0, 0), 'hc_20': (5, 1, 0, 1, 23, 22), 'hc_21': (1, 1, 0, 2, 1, 1), 'hc_22': (27, 13, 3, 37, 133, 109), 'hc_23': (0, 0, 0, 0, 1, 72), 'hc_24': (4, 1, 0, 3, 11, 12), 'hc_25': (7, 1, 0, 3, 40, 50), 'hc_26': (4, 1, 0, 1, 11, 10), 'hc_27': (0, 0, 0, 1, 0, 0), 'hc_28': (56, 18, 5, 16, 183, 169), 'hc_29': (11, 1, 1, 3, 15, 8), 'hc_30': (35, 3, 3, 3, 185, 164), 'hc_31': (5, 1, 0, 1, 17, 28), 'hc_32': (5, 1, 0, 1, 14, 28), 'hc_33': (1, 1, 0, 4, 4, 21), 'hc_34': (2, 2, 1, 1, 2, 2), 'hc_35': (8, 1, 2, 1, 11, 8), 'hc_36': (7, 1, 0, 4, 18, 17), 'hc_37': (4, 1, 0, 3, 12, 19), 'hc_38': (6, 1, 0, 3, 10, 15), 'hc_39': (0, 0, 0, 0, 26, 31), 'hc_40': (0, 0, 0, 1, 0, 0), 'hc_41': (0, 0, 0, 1, 0, 0), 'hc_42': (7, 1, 0, 3, 11, 8), 'hc_43': (4, 1, 1, 3, 4, 5), 'hc_44': (0, 0, 0, 1, 0, 1), 'hc_45': (11, 4, 1, 23, 51, 19), 'hc_46': (5, 1, 0, 1, 25, 22), 'hc_47': (5, 1, 0, 1, 22, 22), 'hc_48': (11, 2, 2, 14, 28, 4), 'hc_49': (2, 1, 0, 5, 2, 1), 'hc_50': (17, 2, 0, 8, 106, 136), 'hc_51': (1, 1, 0, 0, 1, 0), 'hc_52': (25, 4, 2, 5, 87, 89), 'hc_53': (0, 0, 0, 0, 28, 29), 'hc_54': (0, 0, 0, 0, 24, 31), 'hc_55': (22, 6, 2, 16, 52, 80)}
WORDS = [125, 131, 402, 205, 164, 141, 24, 11170, 488, 15, 121, 8, 69, 21, 87, 21, 580, 454, 4618, 15, 344, 48, 2667, 202, 290, 682, 210, 15, 3452, 277, 3375, 319, 310, 315, 58, 227, 360, 283, 208, 601, 17, 15, 187, 117, 28, 1056, 378, 361, 640, 95, 2111, 25, 1595, 470, 466, 1428]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 42091
    for needle in ('42091',
                   'inventory model',
                   'selectedToolIndex',
                   '0xc5eaa8',
                   '0xa6'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_blockhead3():
    assert len(DATA['classes']) == 56
    s = BY['hc_07']['semantics']
    assert 'niform' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_blockhead3()
    print('test_blockhead3_evidence: OK')
