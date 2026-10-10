#!/usr/bin/env python3
"""Contract test for the DynamicWorld world-mutation cluster (E26).

Pins the JSON artifact and the prose doc to the recovered semantics of the seven
bodies: the queue producer, the interaction placement, the removals with relight,
the client free-block materialization, the departure sweep and the train placer.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_MUTATE.md').read_text()
DATA = json.loads((NATIVE / 'world_mutate.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_worldcontentschangedat', 'wtl_interactionobjectplace', 'wtl_removestandardobject_',
         'wtl_removedooratpos_', 'wtl_createclientfreeblocks', 'wtl_removedynamicobjectsbe',
         'wtl_placetraincaratpos_oft']

IMPS = ['0x008e046c', '0x008e7a60', '0x008e88fc', '0x008edc38', '0x008d0c90', '0x00904e18', '0x008ee700']

COUNTS = {
    'wtl_worldcontentschangedat': (0, 0, 0, 2, 5, 22),
    'wtl_interactionobjectplace': (11, 1, 0, 4, 17, 10),
    'wtl_removestandardobject_': (8, 2, 0, 1, 34, 33),
    'wtl_removedooratpos_': (6, 1, 0, 1, 20, 15),
    'wtl_createclientfreeblocks': (7, 1, 1, 5, 16, 9),
    'wtl_removedynamicobjectsbe': (3, 1, 0, 2, 9, 13),
    'wtl_placetraincaratpos_oft': (6, 1, 4, 3, 27, 39),
}

WORDS = [409, 281, 443, 366, 326, 316, 532]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 2673
    for needle in ('2673', 'ffffe5c4', 'classForInteractionObjectType',
                   'recalculateDrawBlockLightingForTile', '0x62', 'tileIsSolid', '0x130'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_producer_and_placement():
    s = BY['wtl_worldcontentschangedat']['semantics']
    for needle in ('ffffe5c4', '0x20', 'makeIntpair', 'ffffe570', '__aeabi_idiv'):
        assert needle in s, needle
    s = BY['wtl_interactionobjectplace']['semantics']
    for needle in ('classForInteractionObjectType', 'ffffe550', 'ffffe554',
                   'worldIndexAtWorldPos', 'operator[]', 'type == 8', 'type == 6'):
        assert needle in s, needle


def test_removals():
    s = BY['wtl_removestandardobject_']['semantics']
    for needle in ('0xfff34154', 'objectTypeIsInteractionObject', 'strb [tile+3] = 0',
                   '[tile+0xb]', 'ffe235e8'):
        assert needle in s, needle
    s = BY['wtl_removedooratpos_']['semantics']
    for needle in ('0x34', '0xa4', 'recalculateDrawBlockLightingForTile', '0x130',
                   'strb [tile+0xc] = 0'):
        assert needle in s, needle


def test_client_and_train():
    s = BY['wtl_createclientfreeblocks']['semantics']
    for needle in ('0x8b1db0', 'ffffe54c', 'uniqueID', 'ffffe588', 'worldIndexAtWorldPos'):
        assert needle in s, needle
    s = BY['wtl_removedynamicobjectsbe']['semantics']
    for needle in ('0x41 (65)', 'objectTypeCanBeLoadedOnlyWhenClientOwnerOnline', 'ffffe54c',
                   'ffffe550', 'ffe2349c'):
        assert needle in s, needle
    s = BY['wtl_placetraincaratpos_oft']['semantics']
    for needle in ('0x62', '0xcc', '0xcd', '0xce', '0xd0', 'tileIsSolid', 'Vector2',
                   'makeIntpair', 'ffffe550'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_producer_and_placement()
    test_removals()
    test_client_and_train()
    print('test_world_mutate_evidence: OK')
