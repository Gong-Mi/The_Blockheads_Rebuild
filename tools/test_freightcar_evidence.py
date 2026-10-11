#!/usr/bin/env python3
"""Contract test for FreightCar (E149)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'FREIGHTCAR.md').read_text()
DATA = json.loads((NATIVE / 'freightcar.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['fc_00', 'fc_01', 'fc_02', 'fc_03', 'fc_04', 'fc_05', 'fc_06', 'fc_07', 'fc_08', 'fc_09', 'fc_10', 'fc_11', 'fc_12', 'fc_13', 'fc_14', 'fc_15', 'fc_16', 'fc_17', 'fc_18', 'fc_19', 'fc_20', 'fc_21', 'fc_22', 'fc_23', 'fc_24', 'fc_25', 'fc_26']
IMPS = ['0x00a4d7fc', '0x00a4e0f8', '0x00a4d82c', '0x00a4e238', '0x00a4d73c', '0x00a4e134', '0x00a40b0c', '0x00a41294', '0x00a456d0', '0x00a40a20', '0x00a409bc', '0x00a3f878', '0x00a40600', '0x00a4d7e0', '0x00a3f1d0', '0x00a4e604', '0x00a41530', '0x00a4cfc8', '0x00a4e4d0', '0x00a4e640', '0x00a4e4ec', '0x00a4d7c4', '0x00a4e2f0', '0x00a4d850', '0x00a4e3dc', '0x00a40f98', '0x00a4144c']
COUNTS = {'fc_00': (0, 1, 0, 0, 0, 0), 'fc_01': (0, 0, 0, 1, 0, 0), 'fc_02': (0, 0, 0, 0, 0, 0), 'fc_03': (1, 2, 1, 1, 2, 0), 'fc_04': (1, 0, 0, 0, 2, 2), 'fc_05': (2, 0, 0, 4, 2, 0), 'fc_06': (7, 3, 2, 2, 11, 4), 'fc_07': (3, 2, 1, 4, 6, 0), 'fc_08': (26, 3, 1, 22, 217, 46), 'fc_09': (2, 2, 0, 1, 3, 0), 'fc_10': (1, 1, 0, 1, 1, 0), 'fc_11': (16, 2, 3, 9, 36, 38), 'fc_12': (9, 3, 2, 6, 12, 2), 'fc_13': (0, 0, 0, 0, 0, 0), 'fc_14': (3, 2, 2, 6, 15, 1), 'fc_15': (0, 0, 0, 1, 0, 0), 'fc_16': (7, 3, 1, 6, 10, 6), 'fc_17': (0, 0, 0, 3, 11, 0), 'fc_18': (0, 0, 0, 0, 0, 0), 'fc_19': (0, 0, 0, 1, 0, 0), 'fc_20': (1, 2, 1, 2, 2, 2), 'fc_21': (0, 0, 0, 0, 0, 0), 'fc_22': (1, 2, 1, 1, 2, 1), 'fc_23': (1, 0, 0, 4, 36, 9), 'fc_24': (1, 2, 1, 1, 2, 1), 'fc_25': (8, 2, 2, 2, 11, 5), 'fc_26': (2, 0, 1, 2, 2, 0)}
WORDS = [12, 15, 9, 46, 34, 65, 200, 110, 6993, 59, 25, 732, 199, 7, 419, 15, 204, 289, 7, 17, 70, 7, 59, 554, 61, 191, 57]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 10456
    for needle in ('10456', 'FreightCar', 'rail', 'wheel'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_freightcar():
    assert len(DATA['classes']) == 27
    s = BY['fc_00']['semantics']
    assert '0xa4d7fc' in s
    empties = [n for n, e in BY.items() if not str(e.get('semantics', '')).strip()]
    assert not empties


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_freightcar()
    print('test_freightcar_evidence: OK')
