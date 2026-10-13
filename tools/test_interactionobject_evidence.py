#!/usr/bin/env python3
"""Contract test for InteractionObject (E146)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'INTERACTIONOBJECT.md').read_text()
DATA = json.loads((NATIVE / 'interactionobject.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['io_00', 'io_01', 'io_02', 'io_03', 'io_04', 'io_05', 'io_06', 'io_07', 'io_08', 'io_09', 'io_10', 'io_11', 'io_12', 'io_13', 'io_14', 'io_15', 'io_16', 'io_17', 'io_18', 'io_19', 'io_20', 'io_21', 'io_22', 'io_23', 'io_24', 'io_25', 'io_26', 'io_27', 'io_28', 'io_29', 'io_30', 'io_31', 'io_32']
IMPS = ['0x005f6738', '0x005f741c', '0x005f6ffc', '0x005f4d4c', '0x005f6f44', '0x005f6fe0', '0x005f5bf0', '0x005f75f4', '0x005f5c44', '0x005f6620', '0x005f7674', '0x005f4234', '0x005f4bb4', '0x005f58c0', '0x005f66ec', '0x005f6658', '0x005f6604', '0x005f7638', '0x005f7594', '0x005f76b0', '0x005f75b0', '0x005f6de4', '0x005f6784', '0x005f6674', '0x005f6f28', '0x005f5dc8', '0x005f7314', '0x005f7384', '0x005f732c', '0x005f6394', '0x005f6708', '0x005f663c', '0x005f5b10']
COUNTS = {'io_00': (1, 1, 0, 0, 1, 0), 'io_01': (2, 1, 0, 4, 2, 4), 'io_02': (8, 1, 0, 7, 8, 4), 'io_03': (6, 1, 0, 5, 7, 10), 'io_04': (0, 0, 0, 2, 0, 1), 'io_05': (0, 0, 0, 0, 0, 0), 'io_06': (1, 1, 0, 0, 1, 0), 'io_07': (0, 0, 0, 1, 0, 0), 'io_08': (3, 2, 1, 3, 5, 0), 'io_09': (0, 0, 0, 0, 0, 0), 'io_10': (0, 0, 0, 1, 0, 0), 'io_11': (4, 4, 1, 4, 10, 8), 'io_12': (2, 1, 1, 4, 2, 2), 'io_13': (3, 1, 0, 5, 5, 8), 'io_14': (0, 0, 0, 0, 0, 0), 'io_15': (0, 0, 0, 0, 0, 0), 'io_16': (0, 0, 0, 0, 0, 0), 'io_17': (0, 0, 0, 1, 0, 0), 'io_18': (0, 0, 0, 0, 0, 0), 'io_19': (0, 0, 0, 1, 0, 0), 'io_20': (0, 0, 0, 1, 0, 0), 'io_21': (1, 1, 0, 4, 1, 4), 'io_22': (8, 2, 1, 8, 12, 23), 'io_23': (0, 0, 0, 2, 0, 3), 'io_24': (0, 0, 0, 0, 0, 0), 'io_25': (0, 0, 0, 0, 0, 0), 'io_26': (0, 0, 0, 0, 0, 0), 'io_27': (1, 1, 0, 1, 1, 1), 'io_28': (0, 0, 0, 1, 0, 0), 'io_29': (6, 1, 0, 6, 6, 3), 'io_30': (0, 1, 0, 0, 0, 0), 'io_31': (0, 0, 0, 0, 0, 0), 'io_32': (2, 1, 1, 0, 3, 2)}
WORDS = [19, 94, 198, 219, 39, 7, 21, 17, 97, 7, 15, 256, 102, 148, 7, 7, 7, 15, 7, 17, 17, 81, 408, 30, 7, 7, 6, 38, 22, 156, 12, 7, 56]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2146
    for needle in ('2146', 'InteractionObject', 'remoteUpdate', 'ownership'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_interactionobject():
    assert len(DATA['classes']) == 33
    s = BY['io_00']['semantics']
    assert '0x5f6738' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_interactionobject()
    print('test_interactionobject_evidence: OK')
