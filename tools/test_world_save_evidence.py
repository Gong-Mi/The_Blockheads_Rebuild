#!/usr/bin/env python3
"""Contract test for the DynamicWorld world-save cluster (E22).

Pins the JSON artifact and the prose doc to the recovered semantics of the six
bodies: the world-dict builder with the five-container dirty sweep, the blockhead
save collector, the per-macro-tile dynamic-object saver, the object unloader, the
world-position change marker and the client-connect handler.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WORLD_SAVE.md').read_text()
DATA = json.loads((NATIVE / 'world_save.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_savegamewithworlddata_', 'wtl_saveblockheads', 'wtl_savedynamicobjectsform',
         'wtl_removedynamicobjectsfo', 'wtl_worldchangedatpos_send', 'wtl_clientconnected_']

IMPS = ['0x008b29bc', '0x008b6f0c', '0x008b933c', '0x008b5e54', '0x008df7a4', '0x008f7428']

COUNTS = {
    'wtl_savegamewithworlddata_': (30, 13, 8, 18, 75, 45),
    'wtl_saveblockheads': (32, 14, 8, 5, 65, 53),
    'wtl_savedynamicobjectsform': (29, 14, 6, 6, 73, 67),
    'wtl_removedynamicobjectsfo': (9, 1, 0, 9, 40, 22),
    'wtl_worldchangedatpos_send': (0, 0, 0, 3, 7, 44),
    'wtl_clientconnected_': (18, 1, 1, 4, 32, 23),
}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == [2063, 1391, 1394, 662, 818, 730]
    assert sum(BY[n]['verified_words'] for n in NAMES) == 7058
    for needle in ('7058', 'five-container dirty sweep', 'macroTileAtMacroPostion',
                   'savePhysicalBlockForMacroTile:', '5000', 'worldIndexAtWorldPos',
                   'objectTypeCanBeLoadedOnlyWhenClientOwnerOnline', 'unordered_set<PhysicalBlock*>',
                   'blockheadWillBeUnloaded:', 'makeIntpair', 'NSKeyedArchiver'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_world_save():
    s = BY['wtl_savegamewithworlddata_']['semantics']
    for needle in ('signOwnershipData', 'signOwnershipData branch', 'five 8-byte-stride',
                   'ffffe570', 'ffffe574', 'ffffe578', 'ffffe57c', 'ffffe580',
                   'macroTileAtMacroPostion', 'savePhysicalBlockForMacroTile:', 'sendReliably'):
        assert needle in s, needle


def test_save_objects_and_blockheads():
    s = BY['wtl_savedynamicobjectsform']['semantics']
    for needle in ('objectType == 0xf', 'objectType == 0x15', '0x2e', 'macroIndexAtMacroPosition',
                   'objectTypeCanBeLoadedOnlyWhenClientOwnerOnline', 'map<unsigned int, std::__1::set<unsigned int>*>::at',
                   '__erase_unique', '0x1388', '0x8b84c8', 'setObject:forKey:',
                   'dynamic-object database', '0xfff33f44'):
        assert needle in s, needle
    s = BY['wtl_saveblockheads']['semantics']
    for needle in ('ffffe4f8', 'ffffe518', 'bl 0x8b84c8', 'NSKeyedArchiver',
                   'initForWritingWithMutableData:', 'removeObject:', 'ffffe590'):
        assert needle in s, needle


def test_remove_and_marker():
    s = BY['wtl_removedynamicobjectsfo']['semantics']
    for needle in ('0x18', 'netBlockheads', 'blockheadWillBeUnloaded:', 'uniqueID',
                   'ffffe54c', 'ffffe550', 'ffffe584', 'ffffe588',
                   'objectTypeHasStaticPosition', 'objectTypeRequiresPartialUpdate',
                   'std::__1::vector<DynamicObject*>::erase'):
        assert needle in s, needle
    s = BY['wtl_worldchangedatpos_send']['semantics']
    for needle in ('ffffe5b8', '0x20', 'makeIntpair', 'sendReliably', 'ffffe570', 'ffffe574'):
        assert needle in s, needle


def test_client_connected():
    s = BY['wtl_clientconnected_']['semantics']
    for needle in ('clientID', 'ffffe4f0', 'removeObject:', 'blockheadWillBeUnloaded:',
                   'unordered_set<PhysicalBlock*>', 'copy-constructed', '[block+0xc]', 'dirty'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_world_save()
    test_save_objects_and_blockheads()
    test_remove_and_marker()
    test_client_connected()
    print('test_world_save_evidence: OK')
