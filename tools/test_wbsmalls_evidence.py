#!/usr/bin/env python3
"""Contract test for the Workbench mid/smalls closure (E79)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_SMALLS.md').read_text()
DATA = json.loads((NATIVE / 'workbench_smalls.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['ws_initlevel', 'ws_title', 'ws_reqphys', 'ws_fbitem', 'ws_fbsavedict', 'ws_fbdataa',
         'ws_fbdatab', 'ws_objecttype', 'ws_actiontitle', 'ws_titlecraft']
IMPS = ['0x00ae1acc', '0x00afa7e8', '0x00afe67c', '0x00afd4e8', '0x00afd7f0', '0x00afd83c',
        '0x00afd858', '0x00ae1ab0', '0x00b01750', '0x00b0bb8c']

COUNTS = {
    'ws_initlevel': (3, 2, 0, 8, 15, 9),
    'ws_title': (1, 1, 0, 3, 2, 0),
    'ws_reqphys': (2, 2, 1, 6, 2, 11),
    'ws_fbitem': (0, 0, 0, 2, 1, 0),
    'ws_fbsavedict': (1, 1, 0, 0, 1, 0),
    'ws_fbdataa': (0, 0, 0, 0, 0, 0),
    'ws_fbdatab': (0, 0, 0, 0, 0, 0),
    'ws_objecttype': (0, 0, 0, 0, 0, 0),
    'ws_actiontitle': (1, 1, 0, 2, 2, 0),
    'ws_titlecraft': (2, 2, 0, 0, 3, 2),
}

WORDS = [363, 50, 187, 25, 19, 14, 7, 7, 44, 70]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 786
    for needle in ('786', '0x2d (45)', 'fffff11c', '__wrap_malloc', 'ffe26678'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_facts():
    s = BY['ws_initlevel']['semantics']
    assert '__wrap_malloc' in s and 'fffff11c' in s
    s = BY['ws_objecttype']['semantics']
    assert '0x2d (45)' in s
    for n in ('ws_fbdataa', 'ws_fbdatab'):
        assert 'returns **0**' in BY[n]['semantics'], n
    s = BY['ws_actiontitle']['semantics']
    assert 'ffe26678' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_facts()
    print('test_wbsmalls_evidence: OK')
