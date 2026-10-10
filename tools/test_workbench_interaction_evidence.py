#!/usr/bin/env python3
"""Contract test for the DynamicWorld workbench/interaction cluster (E39)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORKBENCH_INTERACTION.md').read_text()
DATA = json.loads((NATIVE / 'workbench_interaction.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_workbenchatpos_', 'wtl_workbenchhasbeencrafte', 'wtl_assigncraftprogressuit',
         'wtl_interactionobjectwithi', 'wtl_interactionobjecttypef', 'wtl_removeworkbenchatpos_r',
         'wtl_removeinteractionobjec', 'wtl_freeblocksexistatpos_', 'wtl_getnextdynamicobjectid',
         'wtl_portal']

IMPS = ['0x008efe3c', '0x008f015c', '0x008f0198', '0x008f1048', '0x008f1284', '0x008f1354',
        '0x008f145c', '0x008f1564', '0x008f1a78', '0x008f0090']

COUNTS = {
    'wtl_workbenchatpos_': (3, 1, 0, 0, 7, 10),
    'wtl_workbenchhasbeencrafte': (0, 0, 0, 1, 0, 0),
    'wtl_assigncraftprogressuit': (1, 1, 0, 2, 4, 4),
    'wtl_interactionobjectwithi': (0, 0, 0, 2, 4, 7),
    'wtl_interactionobjecttypef': (2, 1, 0, 0, 2, 2),
    'wtl_removeworkbenchatpos_r': (3, 1, 0, 0, 3, 2),
    'wtl_removeinteractionobjec': (3, 1, 0, 0, 3, 2),
    'wtl_freeblocksexistatpos_': (0, 0, 0, 2, 3, 1),
    'wtl_getnextdynamicobjectid': (0, 0, 0, 1, 0, 0),
    'wtl_portal': (2, 0, 0, 1, 3, 2),
}

WORDS = [149, 15, 238, 143, 52, 66, 66, 86, 21, 51]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 887
    for needle in ('887', '0x2d (45)', '0x00E4AA90', '0x21c', 'ffffe588', 'ffffe560',
                   'strh'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_workbench_and_interaction():
    s = BY['wtl_workbenchatpos_']['semantics']
    for needle in ('0x2d', 'sub ip, ip, 1', 'makeIntpair', 'ffe23678'):
        assert needle in s, needle
    s = BY['wtl_workbenchhasbeencrafte']['semantics']
    assert 'ffffe558' in s
    s = BY['wtl_interactionobjectwithi']['semantics']
    for needle in ('0x00E4AA90', '9-arm', '__count_unique'):
        assert needle in s, needle
    s = BY['wtl_interactionobjecttypef']['semantics']
    for needle in ('ffe23688', 'uint16', 'strh'):
        assert needle in s, needle


def test_registry_and_counter():
    s = BY['wtl_freeblocksexistatpos_']['semantics']
    for needle in ('ffffe588', '__count_unique', 'worldIndexAtWorldPos'):
        assert needle in s, needle
    s = BY['wtl_getnextdynamicobjectid']['semantics']
    for needle in ('ffffe560', 'adds', 'adc'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_workbench_and_interaction()
    test_registry_and_counter()
    print('test_workbench_interaction_evidence: OK')
