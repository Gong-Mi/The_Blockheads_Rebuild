#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'NPC2.md').read_text()
DATA = json.loads((NATIVE / 'npc2.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['nq_00', 'nq_01', 'nq_02', 'nq_03', 'nq_04', 'nq_05', 'nq_06', 'nq_07', 'nq_08', 'nq_09', 'nq_10', 'nq_11', 'nq_12', 'nq_13', 'nq_14', 'nq_15', 'nq_16', 'nq_17', 'nq_18', 'nq_19', 'nq_20', 'nq_21', 'nq_22', 'nq_23', 'nq_24', 'nq_25', 'nq_26', 'nq_27', 'nq_28', 'nq_29', 'nq_30', 'nq_31', 'nq_32', 'nq_33', 'nq_34', 'nq_35', 'nq_36', 'nq_37', 'nq_38', 'nq_39', 'nq_40', 'nq_41', 'nq_42', 'nq_43', 'nq_44', 'nq_45', 'nq_46', 'nq_47', 'nq_48', 'nq_49', 'nq_50', 'nq_51', 'nq_52', 'nq_53', 'nq_54', 'nq_55', 'nq_56', 'nq_57', 'nq_58', 'nq_59', 'nq_60', 'nq_61', 'nq_62', 'nq_63', 'nq_64', 'nq_65', 'nq_66', 'nq_67', 'nq_68', 'nq_69', 'nq_70', 'nq_71', 'nq_72']
IMPS = ['0x0064a78c', '0x0064fd44', '0x00651314', '0x0064ed9c', '0x00649fc8', '0x0064ee04', '0x006513a8', '0x0064ad30', '0x0064fc64', '0x0064a744', '0x0064a554', '0x0064a7e4', '0x0064a64c', '0x0064ee48', '0x0064a768', '0x0064a49c', '0x0064a574', '0x0064a66c', '0x0064a2d0', '0x0064a2b4', '0x00649f04', '0x00650a80', '0x00644704', '0x00649358', '0x00643b04', '0x00643ab4', '0x0064a298', '0x00649428', '0x0064acf8', '0x0064ad14', '0x00649390', '0x0064a208', '0x0064a7c8', '0x00649f8c', '0x0064fcf0', '0x00643a84', '0x00649374', '0x0064a62c', '0x00643ad0', '0x0064a83c', '0x0064e5c8', '0x00650980', '0x00643a68', '0x006455d4', '0x00649550', '0x0065096c', '0x00649880', '0x00647c84', '0x0064a9bc', '0x0064a98c', '0x00649ebc', '0x0064fd28', '0x006501b8', '0x00650a64', '0x0064fd0c', '0x0064fc04', '0x0064fc34', '0x00650a2c', '0x0065019c', '0x006500c0', '0x0064a9d8', '0x0064a86c', '0x0065135c', '0x006445e8', '0x00650180', '0x0064a724', '0x00650abc', '0x0064a268', '0x0064fbf0', '0x0064e81c', '0x0064952c', '0x006459c0', '0x00649e20']
COUNTS = {'nq_00': (0, 0, 0, 1, 0, 0), 'nq_01': (0, 0, 0, 0, 0, 0), 'nq_02': (0, 0, 0, 1, 0, 0), 'nq_03': (0, 0, 0, 2, 0, 0), 'nq_04': (0, 0, 0, 0, 0, 0), 'nq_05': (0, 0, 0, 1, 0, 0), 'nq_06': (0, 0, 0, 1, 0, 0), 'nq_07': (1, 1, 0, 0, 1, 0), 'nq_08': (1, 0, 0, 0, 2, 2), 'nq_09': (0, 0, 0, 0, 0, 0), 'nq_10': (0, 0, 0, 0, 0, 0), 'nq_11': (1, 1, 0, 0, 1, 0), 'nq_12': (0, 0, 0, 0, 0, 0), 'nq_13': (0, 0, 0, 3, 0, 2), 'nq_14': (0, 0, 0, 0, 0, 0), 'nq_15': (2, 2, 1, 0, 2, 0), 'nq_16': (2, 2, 1, 0, 2, 0), 'nq_17': (2, 2, 1, 0, 2, 0), 'nq_18': (0, 0, 0, 0, 0, 0), 'nq_19': (0, 0, 0, 0, 0, 0), 'nq_20': (1, 0, 0, 0, 2, 2), 'nq_21': (0, 0, 0, 1, 0, 0), 'nq_22': (0, 0, 0, 0, 0, 0), 'nq_23': (0, 0, 0, 0, 0, 0), 'nq_24': (0, 0, 0, 0, 0, 0), 'nq_25': (0, 0, 0, 0, 0, 0), 'nq_26': (0, 0, 0, 0, 0, 0), 'nq_27': (1, 1, 0, 1, 2, 2), 'nq_28': (0, 0, 0, 0, 0, 0), 'nq_29': (0, 0, 0, 0, 0, 0), 'nq_30': (1, 0, 0, 1, 2, 0), 'nq_31': (0, 0, 0, 2, 0, 0), 'nq_32': (0, 0, 0, 0, 0, 0), 'nq_33': (0, 0, 0, 1, 0, 0), 'nq_34': (0, 0, 0, 0, 0, 0), 'nq_35': (0, 0, 0, 0, 0, 0), 'nq_36': (0, 0, 0, 0, 0, 0), 'nq_37': (0, 0, 0, 0, 0, 0), 'nq_38': (0, 0, 0, 0, 0, 0), 'nq_39': (0, 0, 0, 0, 0, 0), 'nq_40': (0, 0, 0, 1, 0, 0), 'nq_41': (1, 0, 0, 0, 4, 2), 'nq_42': (0, 0, 0, 0, 0, 0), 'nq_43': (1, 0, 0, 0, 3, 2), 'nq_44': (1, 1, 0, 0, 2, 0), 'nq_45': (0, 0, 0, 0, 0, 0), 'nq_46': (0, 0, 0, 0, 0, 0), 'nq_47': (1, 1, 1, 0, 1, 0), 'nq_48': (0, 0, 0, 0, 0, 0), 'nq_49': (0, 1, 0, 0, 0, 0), 'nq_50': (0, 0, 0, 1, 0, 0), 'nq_51': (0, 0, 0, 0, 0, 0), 'nq_52': (0, 0, 0, 1, 0, 2), 'nq_53': (0, 0, 0, 0, 0, 0), 'nq_54': (0, 0, 0, 0, 0, 0), 'nq_55': (0, 0, 0, 0, 0, 0), 'nq_56': (0, 0, 0, 0, 0, 0), 'nq_57': (0, 0, 0, 0, 0, 0), 'nq_58': (0, 0, 0, 0, 0, 0), 'nq_59': (0, 0, 0, 1, 5, 0), 'nq_60': (0, 0, 0, 0, 0, 0), 'nq_61': (3, 2, 0, 1, 3, 4), 'nq_62': (0, 0, 0, 1, 0, 0), 'nq_63': (0, 0, 0, 4, 2, 0), 'nq_64': (0, 0, 0, 0, 0, 0), 'nq_65': (0, 0, 0, 0, 0, 0), 'nq_66': (0, 0, 0, 1, 0, 0), 'nq_67': (0, 1, 0, 0, 0, 0), 'nq_68': (0, 0, 0, 0, 0, 0), 'nq_69': (0, 0, 0, 3, 0, 2), 'nq_70': (0, 0, 0, 0, 0, 0), 'nq_71': (2, 1, 1, 0, 3, 2), 'nq_72': (1, 1, 0, 1, 1, 0)}
WORDS = [15, 7, 18, 26, 9, 17, 15, 20, 35, 9, 8, 22, 8, 54, 9, 46, 46, 46, 8, 7, 34, 15, 5, 7, 7, 7, 7, 65, 7, 7, 38, 24, 7, 15, 7, 12, 7, 8, 13, 12, 15, 43, 7, 42, 20, 5, 5, 29, 7, 12, 18, 7, 24, 7, 7, 12, 12, 7, 7, 48, 8, 72, 19, 71, 7, 8, 21, 12, 5, 47, 9, 59, 39]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1440
    for needle in ('1440',
                   'RIDE',
                   'SET FREE',
                   'CRITTER',
                   'fullnessFraction'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_npc2():
    assert len(DATA['classes']) == 73
    s = BY['nq_61']['semantics']
    assert 'RIDE' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_npc2()
    print('test_npc2_evidence: OK')
