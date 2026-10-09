#!/usr/bin/env python3
"""Contract test for the DynamicObject base class (E116)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DYNAMICOBJECT.md').read_text()
DATA = json.loads((NATIVE / 'dynobj.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['dob_00', 'dob_01', 'dob_02', 'dob_03', 'dob_04', 'dob_05', 'dob_06', 'dob_07', 'dob_08', 'dob_09', 'dob_10', 'dob_11', 'dob_12', 'dob_13', 'dob_14', 'dob_15', 'dob_16', 'dob_17', 'dob_18', 'dob_19', 'dob_20', 'dob_21', 'dob_22', 'dob_23', 'dob_24', 'dob_25', 'dob_26', 'dob_27', 'dob_28', 'dob_29', 'dob_30', 'dob_31', 'dob_32', 'dob_33', 'dob_34', 'dob_35', 'dob_36', 'dob_37', 'dob_38', 'dob_39', 'dob_40', 'dob_41', 'dob_42', 'dob_43', 'dob_44', 'dob_45', 'dob_46', 'dob_47', 'dob_48', 'dob_49', 'dob_50', 'dob_51', 'dob_52', 'dob_53', 'dob_54', 'dob_55', 'dob_56', 'dob_57', 'dob_58', 'dob_59', 'dob_60', 'dob_61', 'dob_62', 'dob_63', 'dob_64', 'dob_65']
IMPS = ['0x00839508', '0x008398d0', '0x00839a18', '0x00839af8', '0x0083a3c0', '0x0083a740', '0x0083aabc', '0x0083ac20', '0x0083ae78', '0x0083b554', '0x0083b570', '0x0083b588', '0x0083b5a4', '0x0083b5f8', '0x0083b64c', '0x0083b66c', '0x0083b68c', '0x0083b7b0', '0x0083b8d4', '0x0083b8f0', '0x0083b9c4', '0x0083b9e0', '0x0083b9fc', '0x0083ba20', '0x0083ba44', '0x0083ba68', '0x0083ba8c', '0x0083bac4', '0x0083bafc', '0x0083bb18', '0x0083bb3c', '0x0083bb58', '0x0083bb74', '0x0083bb98', '0x0083bbb4', '0x0083bbd8', '0x0083bbf4', '0x0083c890', '0x0083c8a8', '0x0083c960', '0x0083c97c', '0x0083c9dc', '0x0083ca98', '0x0083cab4', '0x0083cad0', '0x0083caec', '0x0083cb28', '0x0083cb7c', '0x0083ce9c', '0x0083ceb8', '0x0083ced4', '0x0083cf5c', '0x0083cf78', '0x0083cf94', '0x0083cfb0', '0x0083d0f0', '0x0083d12c', '0x0083d170', '0x0083d1ac', '0x0083d1f0', '0x0083d22c', '0x0083d270', '0x0083d2ac', '0x0083d2f0', '0x0083d32c', '0x0083d370']
COUNTS = {'dob_00': (7, 1, 0, 4, 9, 10), 'dob_01': (4, 1, 0, 3, 4, 2), 'dob_02': (1, 0, 0, 0, 1, 2), 'dob_03': (4, 2, 1, 6, 8, 10), 'dob_04': (6, 2, 1, 7, 8, 6), 'dob_05': (1, 1, 1, 0, 1, 0), 'dob_06': (1, 0, 0, 4, 1, 2), 'dob_07': (0, 0, 0, 0, 0, 0), 'dob_08': (11, 2, 0, 6, 20, 21), 'dob_09': (0, 0, 0, 0, 0, 0), 'dob_10': (0, 0, 0, 0, 0, 0), 'dob_11': (0, 0, 0, 0, 0, 0), 'dob_12': (1, 1, 0, 0, 1, 0), 'dob_13': (1, 1, 0, 0, 1, 0), 'dob_14': (0, 0, 0, 0, 0, 0), 'dob_15': (0, 0, 0, 0, 0, 0), 'dob_16': (3, 1, 0, 3, 3, 1), 'dob_17': (3, 1, 0, 3, 3, 1), 'dob_18': (0, 0, 0, 0, 0, 0), 'dob_19': (1, 0, 0, 1, 4, 0), 'dob_20': (0, 0, 0, 0, 0, 0), 'dob_21': (0, 0, 0, 0, 0, 0), 'dob_22': (0, 0, 0, 0, 0, 0), 'dob_23': (0, 0, 0, 0, 0, 0), 'dob_24': (0, 0, 0, 0, 0, 0), 'dob_25': (0, 0, 0, 0, 0, 0), 'dob_26': (0, 0, 0, 0, 0, 0), 'dob_27': (0, 0, 0, 0, 0, 0), 'dob_28': (0, 0, 0, 0, 0, 0), 'dob_29': (0, 0, 0, 0, 0, 0), 'dob_30': (0, 0, 0, 0, 0, 0), 'dob_31': (0, 0, 0, 0, 0, 0), 'dob_32': (0, 0, 0, 0, 0, 0), 'dob_33': (0, 0, 0, 0, 0, 0), 'dob_34': (0, 0, 0, 0, 0, 0), 'dob_35': (0, 0, 0, 0, 0, 0), 'dob_36': (0, 0, 0, 0, 0, 0), 'dob_37': (0, 0, 0, 0, 0, 0), 'dob_38': (0, 0, 0, 0, 0, 0), 'dob_39': (0, 0, 0, 0, 0, 0), 'dob_40': (0, 0, 0, 0, 0, 0), 'dob_41': (0, 0, 0, 3, 0, 2), 'dob_42': (0, 0, 0, 0, 0, 0), 'dob_43': (0, 0, 0, 0, 0, 0), 'dob_44': (0, 0, 0, 0, 0, 0), 'dob_45': (0, 0, 0, 1, 0, 0), 'dob_46': (0, 0, 0, 1, 0, 0), 'dob_47': (10, 1, 0, 3, 10, 10), 'dob_48': (0, 0, 0, 0, 0, 0), 'dob_49': (0, 0, 0, 0, 0, 0), 'dob_50': (1, 0, 0, 0, 2, 2), 'dob_51': (0, 0, 0, 0, 0, 0), 'dob_52': (0, 0, 0, 0, 0, 0), 'dob_53': (0, 0, 0, 0, 0, 0), 'dob_54': (0, 0, 0, 0, 0, 0), 'dob_55': (0, 0, 0, 1, 0, 0), 'dob_56': (0, 0, 0, 1, 0, 0), 'dob_57': (0, 0, 0, 1, 0, 0), 'dob_58': (0, 0, 0, 1, 0, 0), 'dob_59': (0, 0, 0, 1, 0, 0), 'dob_60': (0, 0, 0, 1, 0, 0), 'dob_61': (0, 0, 0, 1, 0, 0), 'dob_62': (0, 0, 0, 1, 0, 0), 'dob_63': (0, 0, 0, 1, 0, 0), 'dob_64': (0, 0, 0, 1, 0, 0), 'dob_65': (0, 0, 0, 1, 3, 0)}
WORDS = [242, 75, 56, 289, 224, 27, 89, 12, 439, 7, 6, 7, 21, 21, 8, 8, 73, 73, 7, 53, 7, 7, 9, 9, 9, 9, 14, 14, 7, 9, 7, 7, 9, 7, 9, 7, 9, 6, 5, 7, 7, 47, 7, 7, 7, 15, 21, 200, 7, 7, 34, 7, 7, 7, 7, 15, 17, 15, 17, 15, 17, 15, 17, 15, 17, 72]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2523
    for needle in ('2523', '439', '289', '224', 'canBeRemovedByBlockhead',
                   'getNextDynamicObjectID', 'cosf', 'mayOnlyBeRemovedByOwner',
                   'loadPhysicalBlockForMacroTile'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_dynobj():
    s = BY['dob_08']['semantics']
    assert 'setNeedsRemoved' in s
    s = BY['dob_47']['semantics']
    assert 'playerIsAdminWithID' in s
    s = BY['dob_65']['semantics']
    assert 'cosf' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_DynamicObject.floatPos' in symbols
    assert 'OBJC_IVAR_$_DynamicObject.ownerID' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_dynobj()
    print('test_dynobj_evidence: OK')
