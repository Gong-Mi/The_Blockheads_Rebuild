#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'MAINMENU.md').read_text()
DATA = json.loads((NATIVE / 'mainmenu.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['mm_00', 'mm_01', 'mm_02', 'mm_03', 'mm_04', 'mm_05', 'mm_06', 'mm_07', 'mm_08', 'mm_09', 'mm_10', 'mm_11', 'mm_12', 'mm_13', 'mm_14', 'mm_15', 'mm_16', 'mm_17', 'mm_18', 'mm_19', 'mm_20', 'mm_21', 'mm_22', 'mm_23', 'mm_24', 'mm_25', 'mm_26', 'mm_27', 'mm_28', 'mm_29', 'mm_30', 'mm_31', 'mm_32', 'mm_33', 'mm_34', 'mm_35', 'mm_36', 'mm_37', 'mm_38', 'mm_39', 'mm_40', 'mm_41', 'mm_42', 'mm_43', 'mm_44', 'mm_45', 'mm_46', 'mm_47', 'mm_48', 'mm_49', 'mm_50', 'mm_51', 'mm_52', 'mm_53', 'mm_54', 'mm_55', 'mm_56', 'mm_57', 'mm_58', 'mm_59', 'mm_60', 'mm_61', 'mm_62', 'mm_63', 'mm_64', 'mm_65', 'mm_66', 'mm_67', 'mm_68', 'mm_69', 'mm_70', 'mm_71', 'mm_72', 'mm_73', 'mm_74', 'mm_75', 'mm_76', 'mm_77']
IMPS = ['0x00a10360', '0x00a0fdd0', '0x00a0fee0', '0x00a101d8', '0x00a0fc64', '0x00a0ff44', '0x009f90cc', '0x00a0fc4c', '0x00a0fc30', '0x00a0f314', '0x009f7620', '0x00a0f288', '0x00a0c7f0', '0x00a10294', '0x00a0e40c', '0x00a10214', '0x009fc874', '0x009f76e0', '0x00a0cfe0', '0x009fc3f4', '0x00a0e2b0', '0x00a0fbd4', '0x009fc610', '0x00a10070', '0x00a100b0', '0x00a0ff80', '0x00a0de90', '0x00a0dca0', '0x009f91a8', '0x00a0fd68', '0x00a0d1e4', '0x00a0ef70', '0x00a0f024', '0x00a0ef0c', '0x00a0f12c', '0x009f93a8', '0x00a0d9c8', '0x00a0fc14', '0x00a0cf30', '0x00a0ca4c', '0x00a0cbd0', '0x00a102d8', '0x00a0c3c8', '0x00a10250', '0x00a0d060', '0x00a0e218', '0x00a0a4c4', '0x00a0da84', '0x009fc510', '0x00a0f4c8', '0x00a0d0e0', '0x009fdf68', '0x009f8294', '0x009f824c', '0x009f7ee4', '0x00a0dac4', '0x00a0c014', '0x009f7710', '0x00a0da04', '0x00a0e0d8', '0x00a0f3fc', '0x009f7ec8', '0x00a10174', '0x00a0e2c4', '0x00a0c9e4', '0x00a0f1a8', '0x00a0f0c8', '0x009f8bf4', '0x00a0d488', '0x00a1031c', '0x00a0e080', '0x00a0f088', '0x00a09d70', '0x009f8be0', '0x009f82a8', '0x009fc270', '0x00a0e29c', '0x009fcf64']
COUNTS = {'mm_00': (0, 0, 0, 6, 6, 1), 'mm_01': (2, 1, 0, 2, 2, 2), 'mm_02': (1, 1, 0, 1, 1, 0), 'mm_03': (0, 0, 0, 1, 0, 0), 'mm_04': (0, 0, 0, 4, 0, 3), 'mm_05': (0, 0, 0, 1, 0, 0), 'mm_06': (2, 1, 0, 2, 2, 0), 'mm_07': (0, 0, 0, 0, 0, 0), 'mm_08': (0, 0, 0, 0, 0, 0), 'mm_09': (1, 1, 0, 2, 1, 0), 'mm_10': (2, 2, 1, 0, 3, 0), 'mm_11': (1, 2, 0, 1, 1, 0), 'mm_12': (5, 1, 0, 3, 5, 2), 'mm_13': (0, 0, 0, 1, 0, 0), 'mm_14': (9, 3, 2, 4, 24, 17), 'mm_15': (0, 0, 0, 1, 0, 0), 'mm_16': (8, 2, 2, 21, 28, 2), 'mm_17': (0, 1, 0, 0, 0, 0), 'mm_18': (1, 1, 0, 2, 1, 0), 'mm_19': (2, 1, 1, 0, 2, 2), 'mm_20': (0, 0, 0, 0, 0, 0), 'mm_21': (0, 0, 0, 1, 0, 0), 'mm_22': (3, 1, 0, 6, 8, 0), 'mm_23': (0, 0, 0, 1, 0, 0), 'mm_24': (3, 1, 1, 1, 3, 0), 'mm_25': (2, 2, 1, 0, 2, 3), 'mm_26': (3, 1, 0, 7, 3, 0), 'mm_27': (3, 1, 0, 7, 3, 0), 'mm_28': (4, 1, 1, 5, 4, 1), 'mm_29': (1, 1, 0, 1, 1, 0), 'mm_30': (7, 1, 0, 3, 7, 2), 'mm_31': (2, 1, 0, 2, 2, 0), 'mm_32': (1, 1, 0, 1, 1, 0), 'mm_33': (1, 1, 0, 1, 1, 0), 'mm_34': (1, 1, 0, 1, 1, 0), 'mm_35': (45, 31, 17, 43, 149, 32), 'mm_36': (0, 0, 0, 1, 0, 0), 'mm_37': (0, 0, 0, 0, 0, 0), 'mm_38': (1, 1, 0, 1, 1, 0), 'mm_39': (3, 1, 0, 3, 3, 1), 'mm_40': (10, 4, 1, 3, 10, 3), 'mm_41': (0, 0, 0, 1, 0, 0), 'mm_42': (7, 7, 0, 4, 13, 7), 'mm_43': (0, 0, 0, 1, 0, 0), 'mm_44': (1, 1, 0, 2, 1, 0), 'mm_45': (1, 2, 1, 0, 2, 0), 'mm_46': (3, 1, 0, 19, 14, 28), 'mm_47': (0, 0, 0, 1, 0, 0), 'mm_48': (3, 1, 1, 1, 3, 2), 'mm_49': (4, 1, 1, 5, 7, 1), 'mm_50': (3, 1, 0, 2, 3, 1), 'mm_51': (42, 9, 1, 93, 247, 205), 'mm_52': (0, 0, 0, 0, 0, 0), 'mm_53': (0, 0, 0, 1, 0, 0), 'mm_54': (6, 2, 1, 2, 9, 8), 'mm_55': (3, 1, 0, 7, 3, 0), 'mm_56': (3, 1, 0, 8, 3, 4), 'mm_57': (1, 0, 0, 5, 10, 7), 'mm_58': (1, 1, 0, 1, 1, 0), 'mm_59': (2, 1, 1, 3, 2, 1), 'mm_60': (1, 0, 0, 1, 1, 0), 'mm_61': (0, 0, 0, 0, 0, 0), 'mm_62': (1, 1, 0, 1, 1, 0), 'mm_63': (2, 1, 1, 3, 2, 1), 'mm_64': (0, 0, 0, 1, 0, 1), 'mm_65': (1, 0, 0, 1, 1, 0), 'mm_66': (1, 1, 0, 1, 1, 0), 'mm_67': (11, 3, 3, 5, 14, 12), 'mm_68': (7, 4, 4, 5, 12, 9), 'mm_69': (0, 0, 0, 1, 0, 0), 'mm_70': (1, 1, 0, 0, 1, 0), 'mm_71': (0, 0, 0, 1, 0, 0), 'mm_72': (0, 0, 0, 1, 0, 0), 'mm_73': (0, 0, 0, 0, 0, 0), 'mm_74': (16, 6, 4, 4, 36, 9), 'mm_75': (3, 1, 1, 0, 4, 2), 'mm_76': (0, 0, 0, 0, 0, 0), 'mm_77': (4, 1, 0, 17, 29, 18)}
WORDS = [80, 68, 25, 15, 65, 15, 55, 6, 7, 58, 48, 35, 125, 17, 704, 15, 444, 12, 32, 71, 5, 16, 153, 16, 49, 60, 124, 124, 128, 26, 169, 45, 25, 25, 31, 2904, 15, 7, 44, 97, 216, 17, 266, 17, 32, 33, 595, 16, 64, 159, 65, 10738, 5, 18, 218, 119, 237, 475, 32, 80, 51, 7, 25, 82, 26, 56, 25, 310, 336, 17, 22, 16, 32, 5, 560, 97, 5, 1019]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 22053
    for needle in ('22053', 'MainMenuUI', 'menu', 'save'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_mainmenu():
    assert len(DATA['classes']) == 78
    s = BY['mm_00']['semantics']
    assert '0x88' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_mainmenu()
    print('test_mainmenu_evidence: OK')
