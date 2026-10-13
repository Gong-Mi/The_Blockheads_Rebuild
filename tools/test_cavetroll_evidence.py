#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CAVETROLL.md').read_text()
DATA = json.loads((NATIVE / 'cavetroll.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cw_00', 'cw_01', 'cw_02', 'cw_03', 'cw_04', 'cw_05', 'cw_06', 'cw_07', 'cw_08', 'cw_09', 'cw_10', 'cw_11', 'cw_12', 'cw_13', 'cw_14', 'cw_15', 'cw_16', 'cw_17', 'cw_18', 'cw_19', 'cw_20', 'cw_21', 'cw_22', 'cw_23', 'cw_24', 'cw_25', 'cw_26', 'cw_27', 'cw_28', 'cw_29', 'cw_30', 'cw_31', 'cw_32', 'cw_33', 'cw_34', 'cw_35', 'cw_36', 'cw_37', 'cw_38', 'cw_39', 'cw_40', 'cw_41', 'cw_42', 'cw_43', 'cw_44', 'cw_45', 'cw_46', 'cw_47', 'cw_48', 'cw_49', 'cw_50', 'cw_51', 'cw_52', 'cw_53', 'cw_54', 'cw_55', 'cw_56', 'cw_57', 'cw_58', 'cw_59', 'cw_60', 'cw_61', 'cw_62', 'cw_63', 'cw_64', 'cw_65', 'cw_66', 'cw_67', 'cw_68', 'cw_69', 'cw_70', 'cw_71']
IMPS = ['0x00d853c0', '0x00d84ee8', '0x00d850f4', '0x00d846a8', '0x00d84ccc', '0x00d84898', '0x00d84080', '0x00d8487c', '0x00d848bc', '0x00d52c24', '0x00d54378', '0x00d56338', '0x00d54908', '0x00d54604', '0x00d83ae0', '0x00d52ae4', '0x00d55038', '0x00d552b8', '0x00d54e2c', '0x00d56190', '0x00d52b70', '0x00d52b54', '0x00d55720', '0x00d7e358', '0x00d83b68', '0x00d52bbc', '0x00d52bd8', '0x00d52c08', '0x00d842ac', '0x00d83320', '0x00d52c40', '0x00d535f8', '0x00d53f2c', '0x00d55074', '0x00d851dc', '0x00d52b20', '0x00d83c24', '0x00d849a0', '0x00d85268', '0x00d535dc', '0x00d852c8', '0x00d5f4b8', '0x00d84a4c', '0x00d84118', '0x00d55ef4', '0x00d55bcc', '0x00d84fe8', '0x00d8409c', '0x00d84df0', '0x00d84d58', '0x00d85214', '0x00d8524c', '0x00d84c6c', '0x00d851f8', '0x00d85348', '0x00d83a64', '0x00d82ccc', '0x00d85304', '0x00d85380', '0x00d84d9c', '0x00d839f0', '0x00d52b8c', '0x00d552f4', '0x00d55518', '0x00d83c40', '0x00d56160', '0x00d56460', '0x00d560f8', '0x00d5481c', '0x00d83aa4', '0x00d832f0', '0x00d83308']
COUNTS = {'cw_00': (0, 0, 0, 6, 12, 0), 'cw_01': (1, 1, 1, 2, 2, 1), 'cw_02': (1, 1, 0, 2, 1, 2), 'cw_03': (2, 2, 1, 4, 3, 2), 'cw_04': (1, 0, 0, 0, 2, 2), 'cw_05': (0, 0, 0, 0, 0, 0), 'cw_06': (0, 0, 0, 0, 0, 0), 'cw_07': (0, 0, 0, 0, 0, 0), 'cw_08': (2, 2, 1, 0, 2, 2), 'cw_09': (0, 0, 0, 0, 0, 0), 'cw_10': (1, 0, 0, 8, 3, 2), 'cw_11': (1, 1, 0, 2, 1, 3), 'cw_12': (0, 0, 0, 0, 0, 0), 'cw_13': (4, 1, 1, 0, 8, 4), 'cw_14': (0, 0, 0, 1, 0, 1), 'cw_15': (0, 0, 0, 1, 0, 0), 'cw_16': (0, 0, 0, 1, 0, 0), 'cw_17': (0, 0, 0, 1, 0, 0), 'cw_18': (2, 2, 1, 7, 8, 0), 'cw_19': (4, 2, 2, 3, 4, 2), 'cw_20': (0, 0, 0, 0, 0, 0), 'cw_21': (0, 0, 0, 0, 0, 0), 'cw_22': (0, 0, 0, 16, 4, 3), 'cw_23': (12, 2, 0, 24, 153, 13), 'cw_24': (1, 1, 0, 2, 1, 1), 'cw_25': (0, 0, 0, 0, 0, 0), 'cw_26': (0, 0, 0, 0, 0, 0), 'cw_27': (0, 0, 0, 0, 0, 0), 'cw_28': (6, 3, 1, 8, 11, 15), 'cw_29': (3, 6, 2, 5, 24, 7), 'cw_30': (8, 21, 3, 12, 24, 1), 'cw_31': (2, 1, 1, 8, 3, 2), 'cw_32': (4, 2, 1, 14, 5, 6), 'cw_33': (4, 2, 0, 3, 5, 8), 'cw_34': (0, 0, 0, 0, 0, 0), 'cw_35': (0, 0, 0, 0, 0, 0), 'cw_36': (0, 0, 0, 0, 0, 0), 'cw_37': (1, 0, 0, 0, 4, 2), 'cw_38': (0, 0, 0, 1, 1, 0), 'cw_39': (0, 0, 0, 0, 0, 0), 'cw_40': (0, 0, 0, 1, 0, 0), 'cw_41': (11, 2, 4, 95, 466, 494), 'cw_42': (4, 3, 2, 3, 7, 0), 'cw_43': (3, 1, 1, 5, 4, 1), 'cw_44': (3, 1, 1, 0, 3, 0), 'cw_45': (5, 2, 1, 4, 5, 6), 'cw_46': (1, 1, 1, 2, 2, 1), 'cw_47': (0, 0, 0, 1, 2, 0), 'cw_48': (0, 0, 0, 2, 2, 4), 'cw_49': (0, 0, 0, 1, 0, 0), 'cw_50': (0, 0, 0, 0, 0, 0), 'cw_51': (0, 0, 0, 0, 0, 0), 'cw_52': (0, 0, 0, 1, 0, 0), 'cw_53': (0, 0, 0, 0, 0, 0), 'cw_54': (0, 0, 0, 0, 0, 0), 'cw_55': (0, 0, 0, 1, 0, 0), 'cw_56': (9, 2, 0, 11, 13, 20), 'cw_57': (0, 0, 0, 1, 0, 0), 'cw_58': (0, 0, 0, 0, 0, 0), 'cw_59': (0, 0, 0, 1, 0, 0), 'cw_60': (0, 0, 0, 2, 0, 0), 'cw_61': (0, 1, 0, 0, 0, 0), 'cw_62': (4, 1, 1, 6, 5, 1), 'cw_63': (3, 1, 0, 7, 3, 1), 'cw_64': (1, 0, 0, 3, 20, 11), 'cw_65': (0, 0, 0, 0, 0, 0), 'cw_66': (60, 19, 4, 105, 250, 581), 'cw_67': (0, 0, 0, 1, 0, 1), 'cw_68': (2, 1, 1, 0, 3, 2), 'cw_69': (0, 0, 0, 1, 0, 0), 'cw_70': (0, 0, 0, 0, 0, 0), 'cw_71': (0, 0, 0, 0, 0, 0)}
WORDS = [227, 64, 58, 117, 35, 9, 7, 7, 57, 7, 163, 74, 7, 134, 34, 15, 15, 15, 131, 106, 7, 7, 299, 4333, 47, 7, 12, 7, 255, 436, 611, 181, 275, 145, 7, 13, 7, 43, 24, 7, 15, 30803, 136, 101, 129, 202, 67, 31, 62, 17, 7, 7, 24, 7, 14, 16, 393, 17, 16, 21, 29, 12, 137, 130, 272, 12, 9034, 26, 59, 15, 6, 6]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 49828
    for needle in ('49828',
                   'CAVE TROLL',
                   'Trollface',
                   'npcType = 6',
                   'recoilTimer'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_cavetroll():
    assert len(DATA['classes']) == 72
    s = BY['cw_41']['semantics']
    assert 'sinf' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_cavetroll()
    print('test_cavetroll_evidence: OK')
