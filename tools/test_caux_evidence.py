#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CAUX.md').read_text()
DATA = json.loads((NATIVE / 'caux.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cy_00', 'cy_01', 'cy_02', 'cy_03', 'cy_04', 'cy_05', 'cy_06', 'cy_07', 'cy_08', 'cy_09', 'cy_10', 'cy_11', 'cy_12', 'cy_13', 'cy_14', 'cy_15', 'cy_16', 'cy_17', 'cy_18', 'cy_19', 'cy_20', 'cy_21', 'cy_22', 'cy_23', 'cy_24', 'cy_25', 'cy_26', 'cy_27', 'cy_28', 'cy_29', 'cy_30', 'cy_31', 'cy_32', 'cy_33', 'cy_34', 'cy_35', 'cy_36', 'cy_37', 'cy_38', 'cy_39', 'cy_40', 'cy_41', 'cy_42', 'cy_43', 'cy_44', 'cy_45', 'cy_46', 'cy_47', 'cy_48', 'cy_49', 'cy_50', 'cy_51', 'cy_52', 'cy_53', 'cy_54', 'cy_55', 'cy_56', 'cy_57', 'cy_58', 'cy_59', 'cy_60', 'cy_61', 'cy_62', 'cy_63', 'cy_64', 'cy_65', 'cy_66', 'cy_67', 'cy_68', 'cy_69']
IMPS = ['0x00a1915c', '0x00a19670', '0x00a197b4', '0x00a19598', '0x00a18f68', '0x00a193a4', '0x00d948fc', '0x00d94c88', '0x00d91b30', '0x00d91c6c', '0x00d96f5c', '0x00d98190', '0x007c55e4', '0x007c57ec', '0x007c5238', '0x007c5438', '0x007c43dc', '0x007c4790', '0x004d6820', '0x004d6040', '0x004c0bd4', '0x00854138', '0x004c1e84', '0x00b597bc', '0x005f3f50', '0x008bc89c', '0x006495a0', '0x006437e4', '0x0064be74', '0x006caf24', '0x00580e5c', '0x00a653d8', '0x008e4b2c', '0x008e4c98', '0x008c3a88', '0x004ea3cc', '0x0056871c', '0x005b902c', '0x004d6128', '0x0057b5e4', '0x0057b630', '0x0057b6bc', '0x005b291c', '0x005b2b0c', '0x004cc11c', '0x004daf58', '0x0057bd18', '0x00580be0', '0x00580c20', '0x00580cdc', '0x00580f24', '0x005b23b8', '0x005b2aa0', '0x005b2ad4', '0x005b2ca0', '0x005df794', '0x00a118e4', '0x00a15e28', '0x00a10a48', '0x00a18044', '0x004b4444', '0x00db222c', '0x00aed208', '0x00582e00', '0x00668a34', '0x008546e0', '0x00c38b6c', '0x005aa394', '0x0058198c', '0x0020ca1c']
COUNTS = {'cy_00': (0, 0, 0, 0, 7, 30), 'cy_01': (0, 0, 0, 0, 1, 3), 'cy_02': (0, 0, 0, 0, 1, 3), 'cy_03': (0, 0, 0, 0, 1, 3), 'cy_04': (1, 0, 0, 0, 8, 16), 'cy_05': (0, 0, 0, 0, 7, 21), 'cy_06': (0, 0, 0, 0, 2, 0), 'cy_07': (0, 0, 0, 0, 35, 2), 'cy_08': (0, 0, 0, 0, 0, 0), 'cy_09': (0, 0, 0, 0, 10, 2), 'cy_10': (0, 0, 0, 0, 27, 2), 'cy_11': (0, 0, 0, 0, 6, 2), 'cy_12': (0, 1, 0, 0, 4, 10), 'cy_13': (0, 0, 0, 0, 2, 9), 'cy_14': (0, 1, 0, 0, 4, 10), 'cy_15': (0, 0, 0, 0, 2, 9), 'cy_16': (0, 0, 0, 0, 3, 0), 'cy_17': (0, 0, 0, 0, 2, 0), 'cy_18': (0, 0, 0, 0, 2, 0), 'cy_19': (0, 0, 0, 0, 2, 0), 'cy_20': (4, 4, 0, 0, 53, 45), 'cy_21': (2, 2, 0, 0, 14, 13), 'cy_22': (0, 0, 0, 0, 0, 11), 'cy_23': (1, 1, 64, 0, 64, 66), 'cy_24': (1, 1, 9, 0, 9, 10), 'cy_25': (0, 0, 0, 0, 0, 11), 'cy_26': (0, 0, 0, 0, 0, 10), 'cy_27': (1, 1, 8, 0, 8, 10), 'cy_28': (0, 0, 0, 0, 0, 9), 'cy_29': (1, 4, 1, 0, 2, 3), 'cy_30': (0, 0, 0, 0, 0, 11), 'cy_31': (0, 0, 0, 0, 0, 11), 'cy_32': (0, 0, 0, 0, 0, 29), 'cy_33': (0, 0, 0, 0, 0, 42), 'cy_34': (0, 0, 0, 0, 0, 17), 'cy_35': (0, 0, 0, 0, 2, 5), 'cy_36': (0, 0, 0, 0, 0, 22), 'cy_37': (0, 0, 0, 0, 0, 10), 'cy_38': (0, 0, 0, 0, 0, 10), 'cy_39': (0, 0, 0, 0, 0, 4), 'cy_40': (0, 0, 0, 0, 2, 7), 'cy_41': (0, 0, 0, 0, 0, 3), 'cy_42': (0, 0, 0, 0, 0, 28), 'cy_43': (0, 0, 0, 0, 0, 28), 'cy_44': (0, 0, 0, 0, 1, 38), 'cy_45': (0, 0, 0, 0, 0, 49), 'cy_46': (0, 0, 0, 0, 0, 5), 'cy_47': (0, 0, 0, 0, 0, 3), 'cy_48': (0, 0, 0, 0, 0, 13), 'cy_49': (0, 0, 0, 0, 0, 26), 'cy_50': (0, 0, 0, 0, 1, 4), 'cy_51': (0, 0, 0, 0, 0, 89), 'cy_52': (0, 0, 0, 0, 1, 0), 'cy_53': (0, 0, 0, 0, 1, 0), 'cy_54': (0, 0, 0, 0, 3, 44), 'cy_55': (0, 0, 0, 0, 0, 18), 'cy_56': (8, 1, 0, 0, 19, 110), 'cy_57': (0, 0, 0, 0, 0, 104), 'cy_58': (0, 0, 0, 0, 28, 29), 'cy_59': (5, 1, 0, 0, 11, 227), 'cy_60': (0, 0, 0, 0, 24, 73), 'cy_61': (9, 1, 0, 0, 14, 22), 'cy_62': (0, 0, 0, 0, 0, 22), 'cy_63': (0, 0, 0, 0, 5, 0), 'cy_64': (0, 0, 0, 0, 6, 4), 'cy_65': (0, 0, 0, 0, 1, 2), 'cy_66': (0, 0, 0, 0, 3, 0), 'cy_67': (0, 0, 0, 0, 0, 0), 'cy_68': (0, 0, 0, 0, 1, 0), 'cy_69': (0, 3, 0, 0, 9, 4)}
WORDS = [146, 27, 27, 27, 125, 125, 227, 1297, 79, 744, 1165, 762, 130, 109, 128, 107, 94, 52, 49, 58, 1196, 362, 64, 1115, 178, 54, 52, 161, 46, 61, 50, 71, 91, 107, 96, 61, 76, 37, 62, 19, 35, 17, 97, 101, 153, 196, 22, 16, 47, 96, 25, 345, 13, 14, 266, 62, 622, 475, 563, 874, 366, 281, 68, 45, 165, 31, 56, 7, 43, 562]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 15100
    for needle in ('15100', 'dynamicObjectTypeForInteractionObjectType', 'tameCountRequirementForNPCType',
                   '0x1fe01', '86-value', 'q_sort', 'GLKMathUnproject', 'paintedIndexForImageIndex'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_caux():
    assert len(DATA['classes']) == 70
    s = BY['cy_51']['semantics']
    assert '86-value' in s
    s = BY['cy_62']['semantics']
    assert '0x1fe01' in s and 'E75' in s
    s = BY['cy_28']['semantics']
    assert 'tame' in s
    s = BY['cy_69']['semantics']
    assert 'GLKit' in s
    s = BY['cy_25']['semantics']
    assert '0x40' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_caux()
    print('test_caux_evidence: OK')
