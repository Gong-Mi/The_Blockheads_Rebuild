#!/usr/bin/env python3
"""Contract test for the WorldUI class line (E135)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLDUI2.md').read_text()
DATA = json.loads((NATIVE / 'worldui2.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wv_00', 'wv_01', 'wv_02', 'wv_03', 'wv_04', 'wv_05', 'wv_06', 'wv_07', 'wv_08', 'wv_09', 'wv_10', 'wv_11', 'wv_12', 'wv_13', 'wv_14', 'wv_15', 'wv_16', 'wv_17', 'wv_18', 'wv_19', 'wv_20', 'wv_21', 'wv_22', 'wv_23', 'wv_24', 'wv_25', 'wv_26', 'wv_27', 'wv_28', 'wv_29', 'wv_30', 'wv_31', 'wv_32', 'wv_33', 'wv_34', 'wv_35', 'wv_36', 'wv_37', 'wv_38', 'wv_39', 'wv_40', 'wv_41', 'wv_42', 'wv_43', 'wv_44', 'wv_45', 'wv_46', 'wv_47', 'wv_48', 'wv_49', 'wv_50', 'wv_51', 'wv_52', 'wv_53', 'wv_54', 'wv_55', 'wv_56', 'wv_57', 'wv_58', 'wv_59', 'wv_60', 'wv_61', 'wv_62', 'wv_63', 'wv_64', 'wv_65', 'wv_66', 'wv_67', 'wv_68']
IMPS = ['0x00cffd68', '0x00cff838', '0x00cf9258', '0x00cebc7c', '0x00cfcf34', '0x00ce1930', '0x00cff074', '0x00cfb644', '0x00cf2e2c', '0x00cfec68', '0x00cf9fd4', '0x00cfb310', '0x00cffaf8', '0x00cffb60', '0x00cf5594', '0x00cfd938', '0x00ce1584', '0x00cfec20', '0x00cffc70', '0x00cffcac', '0x00cf3998', '0x00cfa448', '0x00cf61d8', '0x00cfe9d0', '0x00cddc10', '0x00ce1f94', '0x00cf6154', '0x00cf6de8', '0x00cff700', '0x00cff30c', '0x00cfd298', '0x00cfcc84', '0x00cffce8', '0x00cfed38', '0x00ce3e68', '0x00ce90f8', '0x00ceb020', '0x00ceb5a0', '0x00cff78c', '0x00cfccec', '0x00cfb378', '0x00cebb04', '0x00cff7d4', '0x00cfd3f8', '0x00cfe704', '0x00cf1468', '0x00cffba4', '0x00cffd24', '0x00ce1458', '0x00cffc2c', '0x00cf2114', '0x00cf60bc', '0x00cf6270', '0x00cf5874', '0x00cfd2b0', '0x00cfcc1c', '0x00cf4d70', '0x00cffbe8', '0x00ce3cd4', '0x00cebf78', '0x00cec248', '0x00cf1d98', '0x00cf1c38', '0x00cf1e94', '0x00cf1554', '0x00cf8430', '0x00cff698', '0x00ce20e8', '0x00cfd310']
COUNTS = {'wv_00': (0, 0, 0, 0, 0, 0), 'wv_01': (3, 1, 0, 3, 6, 12), 'wv_02': (20, 1, 1, 16, 32, 28), 'wv_03': (8, 1, 0, 1, 10, 7), 'wv_04': (3, 1, 0, 4, 7, 8), 'wv_05': (7, 1, 0, 3, 12, 11), 'wv_06': (4, 1, 0, 1, 7, 8), 'wv_07': (26, 2, 1, 15, 60, 68), 'wv_08': (7, 1, 0, 3, 47, 40), 'wv_09': (3, 1, 0, 1, 3, 0), 'wv_10': (5, 1, 0, 11, 8, 8), 'wv_11': (1, 1, 0, 1, 1, 0), 'wv_12': (1, 1, 0, 1, 1, 0), 'wv_13': (0, 0, 0, 1, 0, 0), 'wv_14': (3, 1, 0, 3, 6, 6), 'wv_15': (9, 3, 2, 6, 28, 25), 'wv_16': (2, 2, 1, 15, 16, 0), 'wv_17': (0, 0, 0, 1, 0, 0), 'wv_18': (0, 0, 0, 1, 0, 0), 'wv_19': (0, 0, 0, 1, 0, 0), 'wv_20': (24, 2, 1, 23, 42, 42), 'wv_21': (9, 1, 0, 17, 41, 36), 'wv_22': (1, 0, 0, 0, 1, 0), 'wv_23': (4, 1, 0, 4, 7, 7), 'wv_24': (54, 27, 13, 35, 127, 51), 'wv_25': (0, 0, 0, 1, 0, 3), 'wv_26': (1, 0, 0, 0, 1, 0), 'wv_27': (22, 3, 1, 34, 59, 50), 'wv_28': (1, 1, 0, 1, 1, 0), 'wv_29': (6, 1, 0, 2, 13, 8), 'wv_30': (0, 0, 0, 0, 0, 0), 'wv_31': (1, 1, 0, 1, 1, 0), 'wv_32': (0, 0, 0, 1, 0, 0), 'wv_33': (5, 1, 0, 2, 12, 8), 'wv_34': (72, 11, 7, 42, 155, 113), 'wv_35': (27, 2, 2, 19, 80, 47), 'wv_36': (7, 2, 2, 4, 15, 7), 'wv_37': (5, 1, 0, 5, 24, 2), 'wv_38': (0, 0, 0, 1, 0, 0), 'wv_39': (4, 1, 0, 4, 5, 3), 'wv_40': (5, 1, 0, 1, 9, 7), 'wv_41': (2, 1, 0, 3, 3, 1), 'wv_42': (1, 1, 0, 1, 1, 0), 'wv_43': (9, 1, 0, 5, 14, 12), 'wv_44': (2, 1, 0, 3, 5, 8), 'wv_45': (3, 0, 0, 1, 3, 0), 'wv_46': (0, 0, 0, 1, 0, 0), 'wv_47': (0, 0, 0, 1, 0, 0), 'wv_48': (1, 1, 0, 3, 2, 1), 'wv_49': (0, 0, 0, 1, 0, 0), 'wv_50': (21, 2, 2, 15, 37, 27), 'wv_51': (1, 0, 0, 0, 1, 0), 'wv_52': (7, 1, 0, 18, 22, 41), 'wv_53': (6, 1, 0, 5, 23, 26), 'wv_54': (1, 1, 0, 0, 1, 2), 'wv_55': (1, 1, 0, 1, 1, 0), 'wv_56': (6, 1, 0, 10, 21, 35), 'wv_57': (0, 0, 0, 1, 0, 0), 'wv_58': (3, 1, 0, 2, 3, 3), 'wv_59': (2, 0, 0, 2, 4, 7), 'wv_60': (11, 5, 3, 5, 21, 14), 'wv_61': (3, 1, 0, 1, 3, 2), 'wv_62': (4, 1, 0, 1, 4, 4), 'wv_63': (5, 1, 0, 4, 7, 4), 'wv_64': (14, 3, 1, 5, 21, 13), 'wv_65': (15, 2, 1, 12, 40, 29), 'wv_66': (1, 1, 0, 1, 1, 0), 'wv_67': (16, 2, 0, 14, 53, 47), 'wv_68': (3, 1, 0, 1, 3, 1)}
WORDS = [6, 176, 863, 191, 217, 409, 166, 1398, 632, 52, 285, 26, 26, 17, 184, 883, 235, 18, 15, 15, 1270, 946, 38, 148, 3467, 85, 33, 1426, 35, 227, 6, 26, 15, 207, 4431, 1994, 352, 345, 18, 146, 168, 94, 25, 336, 179, 59, 17, 17, 75, 17, 838, 38, 734, 530, 24, 26, 521, 17, 101, 180, 423, 63, 88, 160, 441, 906, 26, 1787, 58]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 28977
    for needle in ('28977', 'WorldUI', 'inventory', 'button'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_worldui():
    assert len(DATA['classes']) == 69
    s = BY['wv_05']['semantics']
    assert '0xce1cac' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_worldui()
    print('test_worldui2_evidence: OK')
