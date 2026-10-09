#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCKHEAD.md').read_text()
DATA = json.loads((NATIVE / 'blockhead.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['hd_00', 'hd_01', 'hd_02', 'hd_03', 'hd_04', 'hd_05', 'hd_06', 'hd_07', 'hd_08', 'hd_09', 'hd_10', 'hd_11', 'hd_12', 'hd_13', 'hd_14', 'hd_15', 'hd_16', 'hd_17', 'hd_18', 'hd_19', 'hd_20', 'hd_21', 'hd_22', 'hd_23', 'hd_24', 'hd_25', 'hd_26', 'hd_27', 'hd_28', 'hd_29', 'hd_30', 'hd_31', 'hd_32', 'hd_33', 'hd_34', 'hd_35', 'hd_36', 'hd_37', 'hd_38', 'hd_39', 'hd_40', 'hd_41', 'hd_42', 'hd_43', 'hd_44', 'hd_45', 'hd_46', 'hd_47', 'hd_48', 'hd_49', 'hd_50', 'hd_51', 'hd_52', 'hd_53', 'hd_54', 'hd_55', 'hd_56', 'hd_57', 'hd_58', 'hd_59', 'hd_60', 'hd_61', 'hd_62']
IMPS = ['0x00c7af40', '0x00bb564c', '0x00bb51c0', '0x00bb4cfc', '0x00b8c850', '0x00bb5740', '0x00c82a88', '0x00b8caf8', '0x00b8c910', '0x00b8c8d0', '0x00b8c890', '0x00b8c810', '0x00b8cb38', '0x00c82104', '0x00c7afc8', '0x00b8c9b8', '0x00bb6e68', '0x00bb6b48', '0x00bb7054', '0x00c7b15c', '0x00c7b054', '0x00bec89c', '0x00c82a2c', '0x00c8a3c0', '0x00c8a3fc', '0x00c7b2d8', '0x00c7b018', '0x00b8cb90', '0x00c81cd8', '0x00c82f18', '0x00c820e8', '0x00bb47d0', '0x00bb63b8', '0x00c8a588', '0x00bb8fe0', '0x00c79510', '0x00c7b0a0', '0x00c87bc8', '0x00bb8e54', '0x00c7adbc', '0x00c86934', '0x00b8cbd0', '0x00c828c4', '0x00c86548', '0x00c80de0', '0x00bac054', '0x00bac004', '0x00bac624', '0x00c8a4c0', '0x00c8a4fc', '0x00c69920', '0x00c7c4a8', '0x00c805c0', '0x00c8a5c4', '0x00c8a600', '0x00c82e90', '0x00c8a090', '0x00c86584', '0x00c87b8c', '0x00c87a60', '0x00bb9238', '0x00c8a768', '0x00c8a6e8']
COUNTS = {'hd_00': (0, 0, 0, 1, 0, 1), 'hd_01': (0, 0, 0, 1, 0, 3), 'hd_02': (1, 1, 0, 10, 5, 19), 'hd_03': (1, 1, 0, 10, 5, 20), 'hd_04': (0, 0, 0, 1, 0, 0), 'hd_05': (18, 3, 1, 15, 38, 46), 'hd_06': (8, 2, 1, 5, 12, 3), 'hd_07': (0, 0, 0, 1, 0, 0), 'hd_08': (0, 0, 0, 1, 0, 2), 'hd_09': (0, 0, 0, 1, 0, 0), 'hd_10': (0, 0, 0, 1, 0, 0), 'hd_11': (0, 0, 0, 1, 0, 0), 'hd_12': (0, 0, 0, 1, 0, 0), 'hd_13': (0, 0, 0, 2, 0, 1), 'hd_14': (0, 0, 0, 1, 0, 0), 'hd_15': (0, 0, 0, 1, 0, 0), 'hd_16': (7, 1, 0, 4, 7, 3), 'hd_17': (10, 3, 1, 6, 13, 5), 'hd_18': (3, 1, 0, 0, 3, 2), 'hd_19': (2, 1, 0, 2, 3, 6), 'hd_20': (1, 1, 0, 0, 1, 0), 'hd_21': (12, 5, 1, 15, 36, 100), 'hd_22': (0, 0, 0, 0, 0, 0), 'hd_23': (0, 0, 0, 1, 0, 0), 'hd_24': (0, 0, 0, 1, 0, 0), 'hd_25': (0, 0, 0, 1, 0, 0), 'hd_26': (0, 0, 0, 1, 0, 0), 'hd_27': (0, 0, 0, 1, 0, 0), 'hd_28': (1, 1, 0, 3, 1, 2), 'hd_29': (1, 1, 0, 1, 1, 1), 'hd_30': (0, 0, 0, 0, 0, 0), 'hd_31': (0, 0, 0, 7, 3, 25), 'hd_32': (16, 5, 1, 10, 20, 20), 'hd_33': (0, 0, 0, 1, 0, 0), 'hd_34': (4, 1, 0, 2, 4, 8), 'hd_35': (0, 0, 0, 1, 0, 1), 'hd_36': (1, 1, 0, 2, 1, 1), 'hd_37': (0, 0, 0, 0, 0, 0), 'hd_38': (4, 1, 0, 1, 4, 6), 'hd_39': (3, 1, 0, 3, 3, 4), 'hd_40': (3, 1, 0, 2, 3, 4), 'hd_41': (0, 0, 0, 1, 0, 0), 'hd_42': (0, 0, 0, 1, 0, 0), 'hd_43': (0, 0, 0, 1, 0, 0), 'hd_44': (0, 0, 0, 1, 0, 0), 'hd_45': (0, 0, 0, 1, 0, 0), 'hd_46': (0, 0, 0, 1, 0, 0), 'hd_47': (0, 0, 0, 1, 0, 0), 'hd_48': (0, 0, 0, 1, 0, 0), 'hd_49': (0, 0, 0, 1, 0, 0), 'hd_50': (6, 1, 0, 1, 26, 24), 'hd_51': (3, 1, 1, 1, 3, 4), 'hd_52': (5, 5, 2, 3, 8, 16), 'hd_53': (0, 0, 0, 1, 0, 0), 'hd_54': (0, 0, 0, 1, 0, 0), 'hd_55': (1, 1, 0, 1, 1, 0), 'hd_56': (0, 0, 0, 1, 0, 0), 'hd_57': (6, 1, 0, 4, 8, 2), 'hd_58': (0, 0, 0, 1, 0, 0), 'hd_59': (3, 1, 0, 0, 3, 6), 'hd_60': (329, 106, 29, 313, 1056, 1771), 'hd_61': (0, 0, 0, 16, 15, 0), 'hd_62': (0, 0, 0, 1, 2, 0)}
WORDS = [34, 61, 291, 305, 16, 798, 258, 16, 42, 16, 16, 16, 22, 38, 20, 16, 123, 200, 48, 95, 19, 1092, 8, 15, 17, 17, 15, 16, 51, 43, 7, 331, 484, 15, 114, 34, 47, 8, 84, 97, 108, 15, 15, 15, 21, 20, 20, 20, 15, 17, 468, 82, 224, 15, 17, 34, 17, 149, 15, 75, 37886, 194, 32]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 44419
    for needle in ('44419', 'Blockhead', '37,886', '0x116',
                   'checkCanEnterTile', '0x50'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_blockhead():
    assert len(DATA['classes']) == 63
    s = BY['hd_60']['semantics']
    assert '37,886' in s and 'checkCanEnterTile' in s
    s = BY['hd_29']['semantics']
    assert '0x116' in s
    s = BY['hd_46']['semantics']
    assert '== 4' in s
    s = BY['hd_11']['semantics']
    assert '0x20' in s
    s = BY['hd_05']['semantics']
    assert '1.0f' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_blockhead()
    print('test_blockhead_evidence: OK')
