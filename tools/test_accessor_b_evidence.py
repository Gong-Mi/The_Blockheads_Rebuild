#!/usr/bin/env python3
"""Contract test for the DynamicWorld structure-part accessor family B (E37)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'ACCESSOR_B.md').read_text()
DATA = json.loads((NATIVE / 'accessor_b.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_ladderatpos_', 'wtl_addladderatpos_oftype_', 'wtl_removeladderatpos_',
         'wtl_columnatpos_', 'wtl_addcolumnatpos_oftype_', 'wtl_removecolumnatpos_',
         'wtl_stairsatpos_', 'wtl_addstairsatpos_oftype_', 'wtl_removestairsatpos_',
         'wtl_elevatorshaftatpos_', 'wtl_addelevatorshaftatpos_', 'wtl_removeelevatorshaftatp']

IMPS = ['0x008eb468', '0x008eb4d8', '0x008eb57c', '0x008eb630', '0x008eb6a0', '0x008eb744',
        '0x008eb7f8', '0x008eb868', '0x008eb90c', '0x008ebb88', '0x008ebbf8', '0x008ebc9c']

COUNTS = {
    'wtl_ladderatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addladderatpos_oftype_': (1, 0, 0, 0, 1, 0),
    'wtl_removeladderatpos_': (2, 1, 0, 0, 2, 0),
    'wtl_columnatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addcolumnatpos_oftype_': (1, 0, 0, 0, 1, 0),
    'wtl_removecolumnatpos_': (2, 1, 0, 0, 2, 0),
    'wtl_stairsatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addstairsatpos_oftype_': (1, 0, 0, 0, 1, 0),
    'wtl_removestairsatpos_': (2, 1, 0, 0, 2, 0),
    'wtl_elevatorshaftatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_addelevatorshaftatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_removeelevatorshaftatp': (2, 1, 0, 0, 2, 0),
}

WORDS = [28, 41, 45, 28, 41, 45, 28, 41, 45, 28, 41, 45]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 456
    for needle in ('456', '0x13 (19)', '0x35 (53)', '0x36 (54)', '0x38 (56)',
                   'ffe235f0', 'ffe23624', 'ffe23600'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_triplets():
    for atpos, add, rm in (('wtl_ladderatpos_', 'wtl_addladderatpos_oftype_', 'wtl_removeladderatpos_'),
                           ('wtl_columnatpos_', 'wtl_addcolumnatpos_oftype_', 'wtl_removecolumnatpos_'),
                           ('wtl_stairsatpos_', 'wtl_addstairsatpos_oftype_', 'wtl_removestairsatpos_'),
                           ('wtl_elevatorshaftatpos_', 'wtl_addelevatorshaftatpos_', 'wtl_removeelevatorshaftatp')):
        s = BY[atpos]['semantics']
        assert 'ffe235f0' in s, atpos
        s = BY[add]['semantics']
        assert 'ffe23624' in s, add
        s = BY[rm]['semantics']
        assert 'ffe23600' in s, rm
    s = BY['wtl_ladderatpos_']['semantics']
    assert '0x13 (19)' in s
    s = BY['wtl_elevatorshaftatpos_']['semantics']
    assert '0x38 (56)' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_triplets()
    print('test_accessor_b_evidence: OK')
