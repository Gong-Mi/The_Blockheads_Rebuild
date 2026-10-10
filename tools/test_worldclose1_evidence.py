#!/usr/bin/env python3
"""Contract test for the World closure sweep part 1 (E114)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_CLOSE1.md').read_text()
DATA = json.loads((NATIVE / 'world_close1.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wx_00', 'wx_01', 'wx_02', 'wx_03', 'wx_04', 'wx_05', 'wx_06', 'wx_07', 'wx_08', 'wx_09', 'wx_10', 'wx_11', 'wx_12', 'wx_13', 'wx_14', 'wx_15', 'wx_16', 'wx_17', 'wx_18', 'wx_19', 'wx_20', 'wx_21', 'wx_22', 'wx_23', 'wx_24', 'wx_25', 'wx_26', 'wx_27', 'wx_28', 'wx_29', 'wx_30', 'wx_31', 'wx_32', 'wx_33', 'wx_34', 'wx_35', 'wx_36', 'wx_37', 'wx_38', 'wx_39', 'wx_40', 'wx_41', 'wx_42', 'wx_43', 'wx_44', 'wx_45', 'wx_46', 'wx_47', 'wx_48', 'wx_49', 'wx_50', 'wx_51', 'wx_52', 'wx_53', 'wx_54', 'wx_55', 'wx_56', 'wx_57', 'wx_58', 'wx_59', 'wx_60', 'wx_61', 'wx_62', 'wx_63', 'wx_64', 'wx_65', 'wx_66', 'wx_67', 'wx_68', 'wx_69']
IMPS = ['0x005d5f80', '0x005d7f2c', '0x005d2c7c', '0x005d855c', '0x005c47b8', '0x005d6910', '0x005d6590', '0x005c8284', '0x005ab274', '0x005d6cb8', '0x00566948', '0x005d179c', '0x005d1484', '0x005cf470', '0x005d8acc', '0x00566c14', '0x005c61d4', '0x005cf858', '0x005c8094', '0x005d7d54', '0x005cdfbc', '0x005b6410', '0x005cf010', '0x005d79c8', '0x005cf1b8', '0x005cf6f0', '0x005ceebc', '0x005d7b9c', '0x005c1cd0', '0x005c8d90', '0x005cf370', '0x005d2098', '0x005ce174', '0x005d2b90', '0x005c875c', '0x005b65bc', '0x005d2ab8', '0x005daa8c', '0x00552d58', '0x005d848c', '0x005ab1ac', '0x005d3348', '0x005d3474', '0x005be2cc', '0x005d13d8', '0x005b6368', '0x005cfe00', '0x005bddac', '0x005c8660', '0x005d5684', '0x005d89ec', '0x005d560c', '0x005d8974', '0x005c86ec', '0x005c8844', '0x005cee00', '0x005d7ce8', '0x005d8f0c', '0x005da33c', '0x005c8d28', '0x005d0c5c', '0x005d0cc4', '0x005d704c', '0x005c2790', '0x005c27f4', '0x005c4b60', '0x005c4bc4', '0x005c85fc', '0x005d3410', '0x005d8a68']
COUNTS = {'wx_00': (10, 5, 3, 3, 19, 7), 'wx_01': (11, 1, 0, 1, 16, 18), 'wx_02': (0, 0, 0, 1, 1, 0), 'wx_03': (2, 1, 0, 2, 9, 14), 'wx_04': (11, 3, 5, 0, 11, 1), 'wx_05': (9, 2, 4, 3, 9, 8), 'wx_06': (3, 5, 1, 3, 13, 1), 'wx_07': (8, 1, 0, 6, 10, 4), 'wx_08': (5, 0, 0, 1, 7, 6), 'wx_09': (7, 2, 3, 3, 7, 2), 'wx_10': (6, 1, 1, 4, 6, 4), 'wx_11': (6, 5, 2, 3, 7, 7), 'wx_12': (7, 2, 2, 3, 8, 3), 'wx_13': (5, 1, 1, 5, 5, 4), 'wx_14': (4, 1, 0, 1, 7, 5), 'wx_15': (4, 1, 0, 4, 6, 4), 'wx_16': (3, 1, 0, 1, 6, 5), 'wx_17': (4, 3, 0, 3, 5, 1), 'wx_18': (4, 1, 0, 3, 4, 7), 'wx_19': (4, 1, 1, 3, 4, 1), 'wx_20': (5, 1, 1, 1, 5, 3), 'wx_21': (4, 2, 0, 2, 4, 2), 'wx_22': (5, 1, 1, 2, 5, 0), 'wx_23': (4, 2, 1, 1, 4, 3), 'wx_24': (2, 3, 0, 3, 3, 0), 'wx_25': (3, 1, 0, 3, 3, 4), 'wx_26': (3, 0, 0, 2, 3, 0), 'wx_27': (2, 2, 1, 1, 2, 1), 'wx_28': (3, 1, 0, 1, 3, 2), 'wx_29': (3, 1, 0, 1, 4, 0), 'wx_30': (3, 2, 0, 1, 3, 0), 'wx_31': (2, 1, 0, 1, 2, 1), 'wx_32': (2, 1, 0, 1, 2, 0), 'wx_33': (3, 1, 0, 1, 3, 0), 'wx_34': (3, 1, 0, 2, 3, 0), 'wx_35': (1, 1, 0, 0, 3, 0), 'wx_36': (1, 1, 0, 2, 1, 1), 'wx_37': (0, 0, 0, 3, 4, 0), 'wx_38': (2, 3, 1, 0, 3, 0), 'wx_39': (1, 1, 0, 2, 1, 2), 'wx_40': (2, 0, 0, 1, 2, 0), 'wx_41': (1, 0, 0, 0, 1, 0), 'wx_42': (2, 1, 0, 2, 2, 0), 'wx_43': (1, 0, 0, 1, 2, 0), 'wx_44': (2, 1, 0, 1, 2, 0), 'wx_45': (2, 1, 0, 1, 2, 1), 'wx_46': (2, 1, 0, 1, 2, 0), 'wx_47': (2, 1, 0, 1, 2, 0), 'wx_48': (2, 1, 0, 1, 2, 0), 'wx_49': (2, 1, 0, 1, 2, 0), 'wx_50': (1, 1, 0, 1, 1, 0), 'wx_51': (1, 1, 0, 1, 1, 0), 'wx_52': (1, 1, 0, 1, 1, 0), 'wx_53': (1, 1, 0, 1, 1, 0), 'wx_54': (1, 1, 0, 1, 1, 0), 'wx_55': (1, 1, 0, 0, 1, 0), 'wx_56': (1, 1, 0, 1, 1, 0), 'wx_57': (1, 1, 0, 1, 1, 0), 'wx_58': (0, 0, 0, 1, 1, 0), 'wx_59': (1, 1, 0, 1, 1, 0), 'wx_60': (1, 1, 0, 0, 1, 0), 'wx_61': (1, 1, 0, 0, 1, 0), 'wx_62': (1, 1, 0, 0, 1, 0), 'wx_63': (1, 1, 0, 0, 1, 0), 'wx_64': (1, 1, 0, 0, 1, 0), 'wx_65': (1, 1, 0, 0, 1, 0), 'wx_66': (1, 1, 0, 0, 1, 0), 'wx_67': (1, 1, 0, 0, 1, 0), 'wx_68': (1, 1, 0, 1, 1, 0), 'wx_69': (1, 1, 0, 0, 1, 0)}
WORDS = [388, 344, 19, 262, 212, 234, 224, 222, 167, 196, 179, 179, 168, 160, 156, 148, 144, 125, 124, 118, 110, 107, 106, 102, 95, 90, 85, 68, 67, 66, 64, 61, 59, 59, 58, 55, 54, 54, 52, 52, 50, 50, 49, 43, 43, 42, 41, 36, 35, 35, 31, 30, 30, 28, 27, 27, 27, 27, 27, 26, 26, 26, 26, 25, 25, 25, 25, 25, 25, 25]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6190
    for needle in ('6190', '388', '344', 'GKAchievement', 'std::unordered_set<PhysicalBlock>',
                   '.cxx_destruct', '0x55468c', 'Reachability', '__android_log_print',
                   'objc_copyStruct'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_close1():
    s = BY['wx_00']['semantics']
    assert 'itemTypeIsStackable' in s
    s = BY['wx_04']['semantics']
    assert 'GKAchievement' in s
    s = BY['wx_35']['semantics']
    assert '__android_log_print' in s
    s = BY['wx_37']['semantics']
    assert 'unordered_set' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.foundItemsList' in symbols
    assert 'OBJC_IVAR_$_World.motionUpdateTimer' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_close1()
    print('test_worldclose1_evidence: OK')
