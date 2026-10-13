#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CBASE.md').read_text()
DATA = json.loads((NATIVE / 'cbase.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cx_00', 'cx_01', 'cx_02', 'cx_03', 'cx_04', 'cx_05', 'cx_06', 'cx_07', 'cx_08', 'cx_09', 'cx_10', 'cx_11', 'cx_12', 'cx_13', 'cx_14', 'cx_15', 'cx_16', 'cx_17', 'cx_18', 'cx_19', 'cx_20', 'cx_21', 'cx_22', 'cx_23', 'cx_24', 'cx_25', 'cx_26', 'cx_27', 'cx_28', 'cx_29', 'cx_30', 'cx_31', 'cx_32', 'cx_33', 'cx_34', 'cx_35', 'cx_36', 'cx_37', 'cx_38', 'cx_39', 'cx_40', 'cx_41', 'cx_42', 'cx_43', 'cx_44', 'cx_45', 'cx_46', 'cx_47', 'cx_48', 'cx_49', 'cx_50', 'cx_51', 'cx_52', 'cx_53', 'cx_54', 'cx_55', 'cx_56', 'cx_57', 'cx_58', 'cx_59', 'cx_60', 'cx_61', 'cx_62', 'cx_63', 'cx_64', 'cx_65', 'cx_66', 'cx_67', 'cx_68', 'cx_69', 'cx_70', 'cx_71']
IMPS = ['0x004bdaac', '0x004b5c08', '0x004b49fc', '0x004b52ac', '0x004d0480', '0x004be068', '0x00582a14', '0x004d0418', '0x004d0d08', '0x004d0368', '0x004c0b70', '0x004d04b4', '0x004bed60', '0x004d5170', '0x004d6538', '0x005ac12c', '0x004da9cc', '0x00575108', '0x005be75c', '0x0057509c', '0x005be888', '0x005bf2b4', '0x005bf378', '0x00668924', '0x00820690', '0x004d03c0', '0x00a1179c', '0x00a11690', '0x00a126dc', '0x00a12760', '0x00a13214', '0x00a128b0', '0x00a138fc', '0x00a12300', '0x00a127cc', '0x00a14450', '0x00a13a4c', '0x00a11390', '0x00a12818', '0x00a13ce0', '0x00a1436c', '0x00a14824', '0x00a11818', '0x00a1234c', '0x00a12864', '0x00a146a0', '0x00a13694', '0x00a12608', '0x00a12410', '0x00a13778', '0x00a12f24', '0x00a16e68', '0x00a156a8', '0x00a15838', '0x00a16ccc', '0x00a1770c', '0x00a16594', '0x00a174a4', '0x00a173c4', '0x00a16944', '0x00a15518', '0x00a149f8', '0x00a151d0', '0x00a148b0', '0x008bcacc', '0x008b68ac', '0x008ba904', '0x00903420', '0x008b6a8c', '0x008bc974', '0x008bca20', '0x008c4b74']
COUNTS = {'cx_00': (0, 0, 0, 0, 0, 0), 'cx_01': (0, 0, 0, 0, 0, 0), 'cx_02': (0, 0, 0, 0, 0, 0), 'cx_03': (0, 0, 0, 0, 0, 0), 'cx_04': (0, 0, 0, 0, 0, 0), 'cx_05': (0, 0, 0, 0, 0, 2), 'cx_06': (0, 0, 0, 0, 0, 0), 'cx_07': (0, 0, 0, 0, 1, 0), 'cx_08': (0, 0, 0, 0, 0, 0), 'cx_09': (0, 0, 0, 0, 1, 0), 'cx_10': (0, 0, 0, 0, 0, 2), 'cx_11': (0, 0, 0, 0, 1, 0), 'cx_12': (0, 0, 0, 0, 0, 0), 'cx_13': (0, 0, 0, 0, 0, 0), 'cx_14': (0, 0, 0, 0, 1, 0), 'cx_15': (0, 0, 0, 0, 0, 2), 'cx_16': (0, 0, 0, 0, 1, 0), 'cx_17': (0, 0, 0, 0, 6, 3), 'cx_18': (0, 0, 0, 0, 8, 3), 'cx_19': (0, 0, 0, 0, 2, 2), 'cx_20': (0, 0, 0, 0, 4, 0), 'cx_21': (0, 0, 0, 0, 1, 3), 'cx_22': (0, 0, 0, 0, 1, 0), 'cx_23': (0, 0, 0, 0, 1, 0), 'cx_24': (0, 0, 0, 0, 1, 0), 'cx_25': (0, 0, 0, 0, 1, 0), 'cx_26': (0, 0, 0, 0, 0, 3), 'cx_27': (0, 0, 0, 0, 0, 1), 'cx_28': (0, 0, 0, 0, 0, 3), 'cx_29': (0, 0, 0, 0, 0, 2), 'cx_30': (0, 0, 0, 0, 1, 16), 'cx_31': (0, 0, 0, 0, 1, 4), 'cx_32': (0, 0, 0, 0, 1, 11), 'cx_33': (0, 0, 0, 0, 0, 1), 'cx_34': (0, 0, 0, 0, 0, 1), 'cx_35': (4, 1, 0, 0, 6, 24), 'cx_36': (0, 0, 0, 0, 0, 25), 'cx_37': (0, 0, 0, 0, 1, 29), 'cx_38': (0, 0, 0, 0, 0, 1), 'cx_39': (0, 0, 0, 0, 0, 14), 'cx_40': (0, 0, 0, 0, 0, 2), 'cx_41': (0, 0, 0, 0, 1, 6), 'cx_42': (0, 0, 0, 0, 0, 12), 'cx_43': (0, 0, 0, 0, 0, 6), 'cx_44': (0, 0, 0, 0, 0, 1), 'cx_45': (0, 0, 0, 0, 0, 17), 'cx_46': (0, 0, 0, 0, 0, 7), 'cx_47': (0, 0, 0, 0, 1, 11), 'cx_48': (0, 0, 0, 0, 1, 0), 'cx_49': (0, 0, 0, 0, 1, 5), 'cx_50': (1, 0, 0, 0, 5, 11), 'cx_51': (1, 0, 0, 0, 5, 11), 'cx_52': (1, 0, 0, 0, 4, 9), 'cx_53': (1, 0, 0, 0, 4, 9), 'cx_54': (1, 1, 0, 0, 4, 9), 'cx_55': (1, 1, 0, 0, 6, 8), 'cx_56': (1, 0, 0, 0, 6, 10), 'cx_57': (1, 1, 0, 0, 4, 5), 'cx_58': (1, 0, 0, 0, 6, 0), 'cx_59': (3, 1, 0, 0, 12, 8), 'cx_60': (1, 0, 0, 0, 4, 0), 'cx_61': (0, 0, 0, 0, 1, 0), 'cx_62': (1, 1, 0, 0, 5, 2), 'cx_63': (1, 0, 0, 0, 2, 2), 'cx_64': (0, 0, 0, 0, 0, 5), 'cx_65': (0, 0, 0, 0, 3, 20), 'cx_66': (0, 0, 0, 0, 1, 0), 'cx_67': (0, 0, 0, 0, 2, 4), 'cx_68': (0, 0, 0, 0, 1, 0), 'cx_69': (0, 0, 0, 0, 0, 5), 'cx_70': (0, 0, 0, 0, 0, 5), 'cx_71': (0, 0, 0, 0, 0, 5)}
WORDS = [5, 5, 9, 21, 13, 27, 15, 26, 21, 22, 21, 26, 12, 10, 43, 30, 33, 60, 75, 27, 68, 49, 108, 43, 26, 22, 31, 19, 33, 27, 114, 43, 84, 19, 19, 148, 165, 192, 19, 99, 27, 34, 51, 49, 19, 97, 57, 53, 9, 28, 126, 147, 100, 100, 103, 122, 99, 83, 56, 226, 49, 20, 141, 82, 43, 120, 9, 38, 13, 43, 43, 43]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 4059
    for needle in ('4059', 'worldWidthMacro', 'dynamicObjectTypeForNPCType', 'fmod(d / 900.0',
                   '((y & 31) << 5)', '0xe4aa1c', '463', 'polarToRectangular'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_cbase():
    assert len(DATA['classes']) == 72
    s = BY['cx_71']['semantics']
    assert '0x3f' in s and 'dynamicObjectTypeForNPCType' in s
    s = BY['cx_50']['semantics']
    assert '64-byte' in s and '463' in s
    s = BY['cx_61']['semantics']
    assert '3600' in s
    s = BY['cx_02']['semantics']
    assert 'intpair' in s
    s = BY['cx_26']['semantics']
    assert '3 (water)' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_cbase()
    print('test_cbase_evidence: OK')
