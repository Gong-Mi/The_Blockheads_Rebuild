#!/usr/bin/env python3
"""Contract test for the DynamicWorld remote-receive/painting/chest smalls (E32)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'REMOTE_RECEIVE.md').read_text()
DATA = json.loads((NATIVE / 'remote_receive.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_remotecreationdataupda', 'wtl_remoteupdate_forobject', 'wtl_snowchangedatmacropos_',
         'wtl_npcexistsatpos_ignoren', 'wtl_freeblockpositionchang', 'wtl_requestpaintingdatafor',
         'wtl_paintingdatarecievedfr', 'wtl_chestinventorydatareci']

IMPS = ['0x008c3e64', '0x008c3fa0', '0x008e1bf0', '0x008f28a4', '0x00906998', '0x00901560',
        '0x009019a8', '0x00902164']

COUNTS = {
    'wtl_remotecreationdataupda': (3, 1, 1, 1, 3, 1),
    'wtl_remoteupdate_forobject': (7, 1, 1, 2, 7, 9),
    'wtl_snowchangedatmacropos_': (0, 0, 0, 1, 1, 11),
    'wtl_npcexistsatpos_ignoren': (1, 0, 0, 1, 5, 14),
    'wtl_freeblockpositionchang': (1, 0, 0, 2, 10, 5),
    'wtl_requestpaintingdatafor': (4, 1, 1, 1, 4, 0),
    'wtl_paintingdatarecievedfr': (5, 1, 0, 0, 6, 4),
    'wtl_chestinventorydatareci': (9, 1, 1, 1, 10, 3),
}

WORDS = [79, 155, 202, 196, 205, 88, 108, 164]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1197
    for needle in ('1197', '0x00E4AA1C', 'ffffe588', 'ffffe580', 'ffffe544', 'ffffe51c',
                   'worldIndexAtWorldPos', '__erase_unique', '0x3c'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_registry_and_npc():
    s = BY['wtl_freeblockpositionchang']['semantics']
    for needle in ('__count_unique', '__erase_unique', 'worldIndexAtWorldPos', 'ffffe588'):
        assert needle in s, needle
    s = BY['wtl_npcexistsatpos_ignoren']['semantics']
    for needle in ('0x00E4AA1C', '0x8f28e0', 'ffffe54c', '12-byte'):
        assert needle in s, needle


def test_receive_pairs():
    s = BY['wtl_paintingdatarecievedfr']['semantics']
    for needle in ('sub r0, r0, 8', 'ffe23348', 'ffe23790'):
        assert needle in s, needle
    s = BY['wtl_chestinventorydatareci']['semantics']
    for needle in ('cmp r0, 8', 'ffe2af7c', 'ffe23348'):
        assert needle in s, needle
    s = BY['wtl_remoteupdate_forobject']['semantics']
    for needle in ('0x3c', 'ffffe51c', 'ffe23438'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_registry_and_npc()
    test_receive_pairs()
    print('test_remote_receive_evidence: OK')
