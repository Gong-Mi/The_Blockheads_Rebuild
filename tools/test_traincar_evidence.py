#!/usr/bin/env python3
"""Contract test for TrainCar (E99)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TRAIN_CAR.md').read_text()
DATA = json.loads((NATIVE / 'train_car.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['tc_00', 'tc_01', 'tc_02', 'tc_03', 'tc_04', 'tc_05', 'tc_06', 'tc_07', 'tc_08', 'tc_09', 'tc_10', 'tc_11', 'tc_12', 'tc_13', 'tc_14', 'tc_15', 'tc_16', 'tc_17', 'tc_18', 'tc_19', 'tc_20', 'tc_21', 'tc_22', 'tc_23', 'tc_24', 'tc_25', 'tc_26', 'tc_27', 'tc_28', 'tc_29', 'tc_30', 'tc_31', 'tc_32', 'tc_33', 'tc_34', 'tc_35', 'tc_36', 'tc_37', 'tc_38', 'tc_39', 'tc_40', 'tc_41', 'tc_42', 'tc_43', 'tc_44', 'tc_45', 'tc_46', 'tc_47', 'tc_48', 'tc_49', 'tc_50', 'tc_51', 'tc_52', 'tc_53', 'tc_54', 'tc_55', 'tc_56']
IMPS = ['0x00a37550', '0x00a385f8', '0x00a38614', '0x00a38ed8', '0x00a390cc', '0x00a39d64', '0x00a39db0', '0x00a3a26c', '0x00a3a34c', '0x00a3a3a0', '0x00a3a5d8', '0x00a3c13c', '0x00a3c264', '0x00a3c488', '0x00a3ca44', '0x00a3cc6c', '0x00a3cc88', '0x00a3cd00', '0x00a3cd28', '0x00a3cd78', '0x00a3cd94', '0x00a3cdb0', '0x00a3d384', '0x00a3d5ec', '0x00a3d600', '0x00a3d630', '0x00a3d6bc', '0x00a3db70', '0x00a3dba0', '0x00a3dbbc', '0x00a3dc08', '0x00a3dff8', '0x00a3e180', '0x00a3e19c', '0x00a3e1b8', '0x00a3e1e4', '0x00a3e210', '0x00a3e22c', '0x00a3e248', '0x00a3e260', '0x00a3e27c', '0x00a3e2c4', '0x00a3e30c', '0x00a3e454', '0x00a3e59c', '0x00a3e5d8', '0x00a3e614', '0x00a3e6a4', '0x00a3eb0c', '0x00a3eb28', '0x00a3eb44', '0x00a3eb58', '0x00a3ecac', '0x00a3ed50', '0x00a3ef44', '0x00a3ef60', '0x00a3ef7c']
COUNTS = {'tc_00': (6, 17, 1, 15, 59, 14), 'tc_01': (0, 0, 0, 0, 0, 0), 'tc_02': (4, 2, 1, 3, 8, 6), 'tc_03': (3, 2, 1, 2, 5, 2), 'tc_04': (9, 1, 0, 3, 10, 7), 'tc_05': (1, 1, 0, 0, 1, 0), 'tc_06': (2, 0, 0, 10, 16, 7), 'tc_07': (3, 2, 1, 0, 4, 2), 'tc_08': (1, 1, 0, 0, 1, 0), 'tc_09': (4, 2, 1, 4, 6, 2), 'tc_10': (26, 3, 1, 22, 68, 108), 'tc_11': (1, 1, 0, 2, 1, 7), 'tc_12': (4, 1, 1, 3, 4, 7), 'tc_13': (3, 1, 0, 9, 9, 21), 'tc_14': (0, 0, 0, 0, 0, 0), 'tc_15': (0, 0, 0, 0, 0, 0), 'tc_16': (0, 0, 0, 1, 4, 0), 'tc_17': (0, 0, 0, 0, 2, 0), 'tc_18': (0, 0, 0, 0, 1, 0), 'tc_19': (0, 0, 0, 0, 0, 0), 'tc_20': (0, 0, 0, 0, 0, 0), 'tc_21': (9, 1, 0, 4, 13, 19), 'tc_22': (5, 1, 0, 4, 5, 6), 'tc_23': (0, 0, 0, 0, 0, 0), 'tc_24': (0, 0, 0, 0, 0, 0), 'tc_25': (1, 0, 0, 0, 2, 2), 'tc_26': (5, 1, 0, 7, 7, 19), 'tc_27': (0, 1, 0, 0, 0, 0), 'tc_28': (0, 0, 0, 0, 0, 0), 'tc_29': (1, 1, 0, 0, 1, 0), 'tc_30': (1, 0, 0, 2, 20, 9), 'tc_31': (3, 2, 1, 2, 3, 5), 'tc_32': (0, 0, 0, 0, 0, 0), 'tc_33': (0, 0, 0, 0, 0, 0), 'tc_34': (0, 0, 0, 0, 0, 0), 'tc_35': (0, 0, 0, 0, 0, 0), 'tc_36': (0, 0, 0, 0, 0, 0), 'tc_37': (0, 0, 0, 0, 0, 0), 'tc_38': (0, 0, 0, 0, 0, 0), 'tc_39': (0, 0, 0, 2, 0, 0), 'tc_40': (0, 0, 0, 2, 0, 0), 'tc_41': (0, 0, 0, 1, 0, 0), 'tc_42': (2, 1, 0, 3, 2, 2), 'tc_43': (2, 1, 0, 3, 2, 2), 'tc_44': (0, 0, 0, 2, 0, 0), 'tc_45': (0, 0, 0, 1, 0, 0), 'tc_46': (1, 1, 0, 1, 1, 2), 'tc_47': (6, 1, 0, 6, 9, 15), 'tc_48': (0, 0, 0, 0, 0, 0), 'tc_49': (0, 0, 0, 0, 0, 0), 'tc_50': (0, 0, 0, 0, 0, 0), 'tc_51': (2, 1, 0, 1, 2, 4), 'tc_52': (2, 2, 1, 0, 2, 0), 'tc_53': (1, 1, 0, 5, 5, 0), 'tc_54': (0, 0, 0, 0, 0, 0), 'tc_55': (0, 0, 0, 0, 0, 0), 'tc_56': (0, 0, 0, 5, 9, 0)}
WORDS = [1066, 7, 198, 125, 249, 19, 303, 77, 21, 142, 1753, 74, 137, 367, 138, 7, 60, 30, 20, 7, 7, 373, 154, 5, 12, 35, 301, 19, 7, 19, 252, 98, 14, 7, 22, 11, 14, 7, 6, 43, 36, 18, 82, 82, 30, 15, 36, 282, 19, 12, 5, 85, 41, 125, 14, 7, 124]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 7219
    for needle in ('7219', 'setRightCar', 'setEngineCar', 'connectsToOtherCars', '0xbf00', 'clamp_float'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_car():
    s = BY['tc_42']['semantics']
    assert 'no-op' in s
    s = BY['tc_54']['semantics']
    assert '**1**' in s
    s = BY['tc_39']['semantics']
    assert '**0**' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_car()
    print('test_traincar_evidence: OK')
