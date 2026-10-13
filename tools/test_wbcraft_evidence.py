#!/usr/bin/env python3
"""Contract test for the Workbench crafting engine cluster (E78)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_CRAFTING.md').read_text()
DATA = json.loads((NATIVE / 'workbench_crafting.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wc_craftcompleted', 'wc_craftitem', 'wc_bhownership', 'wc_abortcraft', 'wc_abortrestore']
IMPS = ['0x00aeb47c', '0x00afb164', '0x00ae7248', '0x00ae9b78', '0x00aeaac4']

COUNTS = {
    'wc_craftcompleted': (38, 22, 4, 21, 77, 116),
    'wc_craftitem': (43, 6, 5, 22, 73, 52),
    'wc_bhownership': (23, 13, 6, 16, 54, 28),
    'wc_abortcraft': (26, 3, 2, 10, 46, 40),
    'wc_abortrestore': (19, 3, 2, 9, 30, 21),
}

WORDS = [1891, 1478, 994, 979, 622]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5964
    for needle in ('5964', 'preserveItemDataAInCraftedItem', 'fff3c074', '39 objc_msgSend', '0x00aebb94'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_engine():
    s = BY['wc_craftcompleted']['semantics']
    assert 'preserveItemDataAInCraftedItem' in s
    s = BY['wc_craftitem']['semantics']
    assert 'fff3c074' in s
    s = BY['wc_abortcraft']['semantics']
    assert 'ffffcffd0' in s
    s = BY['wc_abortrestore']['semantics']
    assert 'immediate' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_engine()
    print('test_wbcraft_evidence: OK')
