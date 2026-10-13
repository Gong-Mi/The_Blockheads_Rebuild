#!/usr/bin/env python3
"""Contract test for CreateWorldUI (E136)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CREATEWORLDUI.md').read_text()
DATA = json.loads((NATIVE / 'createworldui.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cwu_00', 'cwu_01', 'cwu_02', 'cwu_03', 'cwu_04', 'cwu_05', 'cwu_06', 'cwu_07', 'cwu_08', 'cwu_09', 'cwu_10', 'cwu_11', 'cwu_12', 'cwu_13', 'cwu_14', 'cwu_15', 'cwu_16', 'cwu_17', 'cwu_18', 'cwu_19', 'cwu_20', 'cwu_21', 'cwu_22', 'cwu_23', 'cwu_24', 'cwu_25', 'cwu_26', 'cwu_27', 'cwu_28', 'cwu_29', 'cwu_30', 'cwu_31', 'cwu_32', 'cwu_33', 'cwu_34', 'cwu_35', 'cwu_36', 'cwu_37', 'cwu_38', 'cwu_39', 'cwu_40', 'cwu_41', 'cwu_42', 'cwu_43', 'cwu_44', 'cwu_45', 'cwu_46', 'cwu_47', 'cwu_48', 'cwu_49', 'cwu_50', 'cwu_51', 'cwu_52']
IMPS = ['0x00b1f6fc', '0x00b30dfc', '0x00b32ddc', '0x00b32d70', '0x00b32e40', '0x00b32d0c', '0x00b32bc8', '0x00b3299c', '0x00b32858', '0x00b326d8', '0x00b32280', '0x00b1f354', '0x00b32fc0', '0x00b3308c', '0x00b32f10', '0x00b2dd6c', '0x00b2ea30', '0x00b11088', '0x00b32680', '0x00b10d08', '0x00b3029c', '0x00b2defc', '0x00b33148', '0x00b1aae8', '0x00b1f7c0', '0x00b31e20', '0x00b31c50', '0x00b0cc48', '0x00b2e6a4', '0x00b2f9d0', '0x00b317f0', '0x00b31b10', '0x00b2dc74', '0x00b2df78', '0x00b330d0', '0x00b0f5cc', '0x00b17148', '0x00b1e614', '0x00b0fac0', '0x00b2edbc', '0x00b33184', '0x00b30b68', '0x00b313c0', '0x00b2dcf0', '0x00b2e304', '0x00b3310c', '0x00b0eca4', '0x00b33004', '0x00b33048', '0x00b1e22c', '0x00b11750', '0x00b31444', '0x00b2da8c']
COUNTS = {'cwu_00': (1, 1, 0, 1, 1, 4), 'cwu_01': (12, 3, 1, 6, 20, 9), 'cwu_02': (1, 1, 0, 1, 1, 0), 'cwu_03': (1, 1, 0, 1, 1, 0), 'cwu_04': (1, 1, 0, 3, 1, 0), 'cwu_05': (1, 1, 0, 1, 1, 0), 'cwu_06': (3, 1, 0, 3, 3, 6), 'cwu_07': (4, 2, 0, 6, 4, 0), 'cwu_08': (3, 1, 0, 3, 3, 6), 'cwu_09': (5, 2, 0, 2, 4, 2), 'cwu_10': (8, 5, 2, 5, 11, 13), 'cwu_11': (3, 9, 0, 2, 12, 0), 'cwu_12': (0, 0, 0, 1, 0, 0), 'cwu_13': (0, 0, 0, 1, 0, 0), 'cwu_14': (1, 1, 0, 2, 1, 2), 'cwu_15': (2, 3, 0, 3, 3, 4), 'cwu_16': (6, 5, 1, 1, 5, 1), 'cwu_17': (4, 2, 1, 28, 31, 0), 'cwu_18': (1, 1, 0, 0, 1, 0), 'cwu_19': (4, 1, 0, 5, 12, 0), 'cwu_20': (2, 1, 0, 17, 18, 34), 'cwu_21': (1, 1, 0, 1, 1, 0), 'cwu_22': (0, 0, 0, 1, 0, 0), 'cwu_23': (7, 4, 0, 12, 66, 181), 'cwu_24': (96, 57, 17, 66, 279, 507), 'cwu_25': (0, 0, 0, 0, 15, 5), 'cwu_26': (2, 0, 0, 0, 9, 7), 'cwu_27': (34, 26, 11, 18, 63, 46), 'cwu_28': (6, 5, 1, 1, 5, 1), 'cwu_29': (2, 1, 0, 17, 18, 34), 'cwu_30': (10, 5, 1, 2, 10, 0), 'cwu_31': (2, 0, 0, 1, 4, 2), 'cwu_32': (1, 1, 0, 1, 1, 0), 'cwu_33': (6, 5, 1, 1, 5, 1), 'cwu_34': (0, 0, 0, 1, 0, 0), 'cwu_35': (10, 4, 0, 2, 17, 11), 'cwu_36': (5, 2, 0, 32, 36, 26), 'cwu_37': (9, 5, 2, 2, 7, 1), 'cwu_38': (23, 8, 4, 12, 36, 38), 'cwu_39': (2, 1, 0, 17, 18, 51), 'cwu_40': (0, 0, 0, 1, 0, 0), 'cwu_41': (7, 1, 1, 0, 10, 6), 'cwu_42': (1, 1, 0, 1, 1, 0), 'cwu_43': (1, 1, 0, 1, 1, 0), 'cwu_44': (6, 4, 1, 2, 5, 1), 'cwu_45': (0, 0, 0, 1, 0, 0), 'cwu_46': (16, 1, 4, 7, 29, 21), 'cwu_47': (0, 0, 0, 1, 0, 0), 'cwu_48': (0, 0, 0, 1, 0, 0), 'cwu_49': (3, 9, 0, 3, 12, 0), 'cwu_50': (13, 11, 0, 33, 104, 255), 'cwu_51': (12, 4, 1, 3, 12, 0), 'cwu_52': (3, 1, 0, 2, 5, 5)}
WORDS = [49, 369, 25, 27, 52, 25, 81, 139, 81, 96, 247, 234, 17, 17, 44, 100, 162, 434, 22, 224, 563, 31, 15, 3537, 12536, 280, 116, 2035, 162, 563, 200, 80, 31, 162, 15, 317, 3688, 236, 1170, 773, 15, 165, 33, 31, 167, 15, 575, 17, 17, 250, 5758, 235, 122]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 36355
    for needle in ('36355', 'cloud', 'receipt', 'worldSize'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_createworldui():
    assert len(DATA['classes']) == 53
    s = BY['cwu_00']['semantics']
    assert '0xcc' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_createworldui()
    print('test_createworldui_evidence: OK')
