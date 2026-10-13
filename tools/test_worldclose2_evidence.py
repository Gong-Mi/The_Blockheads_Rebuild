#!/usr/bin/env python3
"""Contract test for the World closure sweep part 2 (E115)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_CLOSE2.md').read_text()
DATA = json.loads((NATIVE / 'world_close2.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wy_00', 'wy_01', 'wy_02', 'wy_03', 'wy_04', 'wy_05', 'wy_06', 'wy_07', 'wy_08', 'wy_09', 'wy_10', 'wy_11', 'wy_12', 'wy_13', 'wy_14', 'wy_15', 'wy_16', 'wy_17', 'wy_18', 'wy_19', 'wy_20', 'wy_21', 'wy_22', 'wy_23', 'wy_24', 'wy_25', 'wy_26', 'wy_27', 'wy_28', 'wy_29', 'wy_30', 'wy_31', 'wy_32', 'wy_33', 'wy_34', 'wy_35', 'wy_36', 'wy_37', 'wy_38', 'wy_39', 'wy_40', 'wy_41', 'wy_42', 'wy_43', 'wy_44', 'wy_45', 'wy_46', 'wy_47', 'wy_48', 'wy_49', 'wy_50', 'wy_51', 'wy_52', 'wy_53', 'wy_54', 'wy_55', 'wy_56', 'wy_57', 'wy_58', 'wy_59', 'wy_60', 'wy_61', 'wy_62', 'wy_63', 'wy_64', 'wy_65', 'wy_66', 'wy_67', 'wy_68', 'wy_69', 'wy_70', 'wy_71']
IMPS = ['0x005da2d8', '0x005bde3c', '0x005d9b88', '0x005d9d24', '0x005da3e4', '0x005d7970', '0x005cedac', '0x005cee6c', '0x005d5584', '0x005c6eb0', '0x005d9ab0', '0x005d9af8', '0x005d9b40', '0x005d989c', '0x005d98e0', '0x005d9924', '0x005d9c24', '0x005d9ce0', '0x005d9d84', '0x005d9dc8', '0x005d9e0c', '0x005d9ec8', '0x005d9f48', '0x005d9fc8', '0x005da048', '0x005da0c8', '0x005da1d0', '0x005da250', '0x005da294', '0x005da480', '0x005da4c4', '0x005da544', '0x005da63c', '0x005da680', '0x005d8e90', '0x005da6c4', '0x005da704', '0x005bdd70', '0x005cfa4c', '0x005d1724', '0x005d1760', '0x005d1a68', '0x005d55d0', '0x005d7b60', '0x005d7cac', '0x005d8ed0', '0x005d9860', '0x005d9968', '0x005d9f0c', '0x005d9f8c', '0x005da00c', '0x005da08c', '0x005da194', '0x005da214', '0x005da3a8', '0x005da508', '0x005da588', '0x005da5c4', '0x005da744', '0x005da780', '0x005da7bc', '0x005da7f8', '0x005da834', '0x005da870', '0x005da8ac', '0x005da8e8', '0x005da924', '0x005da960', '0x005da99c', '0x005da9d8', '0x005daa50', '0x005d8e58']
COUNTS = {'wy_00': (0, 0, 0, 1, 1, 0), 'wy_01': (0, 0, 0, 2, 0, 0), 'wy_02': (0, 0, 0, 1, 1, 0), 'wy_03': (0, 0, 0, 1, 1, 0), 'wy_04': (0, 0, 0, 1, 1, 0), 'wy_05': (1, 0, 0, 1, 1, 0), 'wy_06': (0, 0, 0, 1, 0, 0), 'wy_07': (1, 1, 0, 0, 1, 0), 'wy_08': (0, 0, 0, 1, 1, 0), 'wy_09': (0, 0, 0, 1, 0, 0), 'wy_10': (0, 0, 0, 1, 0, 0), 'wy_11': (0, 0, 0, 1, 0, 0), 'wy_12': (0, 0, 0, 1, 0, 0), 'wy_13': (0, 0, 0, 1, 0, 0), 'wy_14': (0, 0, 0, 1, 0, 0), 'wy_15': (0, 0, 0, 1, 0, 0), 'wy_16': (0, 0, 0, 1, 0, 0), 'wy_17': (0, 0, 0, 1, 0, 0), 'wy_18': (0, 0, 0, 1, 0, 0), 'wy_19': (0, 0, 0, 1, 0, 0), 'wy_20': (0, 0, 0, 1, 0, 0), 'wy_21': (0, 0, 0, 1, 0, 0), 'wy_22': (0, 0, 0, 1, 0, 0), 'wy_23': (0, 0, 0, 1, 0, 0), 'wy_24': (0, 0, 0, 1, 0, 0), 'wy_25': (0, 0, 0, 1, 0, 0), 'wy_26': (0, 0, 0, 1, 0, 0), 'wy_27': (0, 0, 0, 1, 0, 0), 'wy_28': (0, 0, 0, 1, 0, 0), 'wy_29': (0, 0, 0, 1, 0, 0), 'wy_30': (0, 0, 0, 1, 0, 0), 'wy_31': (0, 0, 0, 1, 0, 0), 'wy_32': (0, 0, 0, 1, 0, 0), 'wy_33': (0, 0, 0, 1, 0, 0), 'wy_34': (0, 0, 0, 1, 0, 0), 'wy_35': (0, 0, 0, 0, 0, 0), 'wy_36': (0, 0, 0, 0, 0, 0), 'wy_37': (0, 0, 0, 1, 0, 0), 'wy_38': (0, 0, 0, 1, 0, 0), 'wy_39': (0, 0, 0, 1, 0, 0), 'wy_40': (0, 0, 0, 1, 0, 0), 'wy_41': (0, 0, 0, 1, 0, 0), 'wy_42': (0, 0, 0, 1, 0, 0), 'wy_43': (0, 0, 0, 1, 0, 0), 'wy_44': (0, 0, 0, 1, 0, 0), 'wy_45': (0, 0, 0, 1, 0, 0), 'wy_46': (0, 0, 0, 1, 0, 0), 'wy_47': (0, 0, 0, 1, 0, 0), 'wy_48': (0, 0, 0, 1, 0, 0), 'wy_49': (0, 0, 0, 1, 0, 0), 'wy_50': (0, 0, 0, 1, 0, 0), 'wy_51': (0, 0, 0, 1, 0, 0), 'wy_52': (0, 0, 0, 1, 0, 0), 'wy_53': (0, 0, 0, 1, 0, 0), 'wy_54': (0, 0, 0, 1, 0, 0), 'wy_55': (0, 0, 0, 1, 0, 0), 'wy_56': (0, 0, 0, 1, 0, 0), 'wy_57': (0, 0, 0, 1, 0, 0), 'wy_58': (0, 0, 0, 0, 0, 0), 'wy_59': (0, 0, 0, 0, 0, 0), 'wy_60': (0, 0, 0, 0, 0, 0), 'wy_61': (0, 0, 0, 0, 0, 0), 'wy_62': (0, 0, 0, 0, 0, 0), 'wy_63': (0, 0, 0, 0, 0, 0), 'wy_64': (0, 0, 0, 0, 0, 0), 'wy_65': (0, 0, 0, 0, 0, 0), 'wy_66': (0, 0, 0, 0, 0, 0), 'wy_67': (0, 0, 0, 0, 0, 0), 'wy_68': (0, 0, 0, 0, 0, 0), 'wy_69': (0, 0, 0, 0, 0, 0), 'wy_70': (0, 0, 0, 0, 0, 0), 'wy_71': (0, 0, 0, 1, 0, 0)}
WORDS = [25, 24, 24, 24, 24, 22, 21, 20, 19, 18, 18, 18, 18, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 16, 16, 16, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 14]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1204
    for needle in ('1204', 'objc_copyStruct', 'windStrength', 'ldrsb',
                   'workbenchProgressBarUIDisplayed', 'tradingPostBuyUIDisplayed',
                   'setIsOwner:', 'usedPhysicalBlocks'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_close2():
    s = BY['wy_00']['semantics']
    assert 'objc_copyStruct' in s
    s = BY['wy_05']['semantics']
    assert 'weather' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_World.randomSeed' in symbols
    assert 'OBJC_IVAR_$_World.weatherFraction' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_close2()
    print('test_worldclose2_evidence: OK')
