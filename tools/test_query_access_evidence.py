#!/usr/bin/env python3
"""Contract test for the DynamicWorld query/accessor smalls (E34)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'QUERY_ACCESS.md').read_text()
DATA = json.loads((NATIVE / 'query_access.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_npcwithid_', 'wtl_harmabledynamicobjectw', 'wtl_blockheadwithidincludi',
         'wtl_localanddisconnectedcl', 'wtl_localnetid', 'wtl_pathusers',
         'wtl_railorstationnamechang', 'wtl_haslightstoadd']

IMPS = ['0x008f23f4', '0x008f2630', '0x008f932c', '0x008f67f8', '0x008f6568', '0x008fdf6c',
        '0x008fe280', '0x009034b8']

COUNTS = {
    'wtl_npcwithid_': (0, 0, 0, 2, 4, 7),
    'wtl_harmabledynamicobjectw': (4, 1, 0, 0, 7, 11),
    'wtl_blockheadwithidincludi': (3, 1, 0, 0, 6, 9),
    'wtl_localanddisconnectedcl': (2, 1, 0, 3, 2, 4),
    'wtl_localnetid': (1, 2, 0, 2, 2, 4),
    'wtl_pathusers': (6, 2, 1, 2, 8, 11),
    'wtl_railorstationnamechang': (1, 1, 0, 1, 2, 5),
    'wtl_haslightstoadd': (0, 0, 0, 1, 1, 6),
}

WORDS = [143, 157, 144, 87, 76, 334, 137, 55]

FILES = ['disasm_worldtileloader_npcwithid_.txt', 'disasm_worldtileloader_harmabledynamicobjectwithid_.txt',
         'disasm_worldtileloader_blockheadwithidincludingnet_.txt',
         'disasm_worldtileloader_localanddisconnectedclientblockheads.txt',
         'disasm_worldtileloader_localnetid.txt', 'disasm_worldtileloader_pathusers.txt',
         'disasm_worldtileloader_railorstationnamechanged.txt', 'disasm_worldtileloader_haslightstoadd.txt']


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1133
    for needle in ('1133', '0x00E4AA1C', '0x00E4AA0C', '0x1d4', 'eor/orr', 'ffffe4f0',
                   'objectTypeMayHaveArtificalLight'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_lookups():
    s = BY['wtl_npcwithid_']['semantics']
    for needle in ('0x00E4AA1C', '12-byte', '__count_unique', 'ffffe550'):
        assert needle in s, needle
    s = BY['wtl_blockheadwithidincludi']['semantics']
    for needle in ('eor', 'orr', 'ffe2332c'):
        assert needle in s, needle


def test_collector_and_lights():
    s = BY['wtl_pathusers']['semantics']
    for needle in ('0x1d4', 'ffe23730', 'ffe23294', '__tree_next'):
        assert needle in s, needle
    s = BY['wtl_haslightstoadd']['semantics']
    for needle in ('objectTypeMayHaveArtificalLight', 'ffffe550', '0xc'):
        assert needle in s, needle
    s = BY['wtl_railorstationnamechang']['semantics']
    for needle in ('0x00E4AA0C', 'ffe235e0'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_lookups()
    test_collector_and_lights()
    print('test_query_access_evidence: OK')
