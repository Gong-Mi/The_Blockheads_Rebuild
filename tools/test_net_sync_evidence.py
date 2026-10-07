#!/usr/bin/env python3
"""Contract test for the DynamicWorld net-sync + blockhead-load cluster (E21).

Pins the JSON artifact and the prose doc to the recovered semantics of the six
bodies: the dirty-tile flush, the 65-slot reconciliation loop (four phases),
the per-object packet sender (server + client, needs-flag clearing), the
disconnected-client restore, the inventory receiver and the client-data loader.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'NET_SYNC.md').read_text()
DATA = json.loads((NATIVE / 'net_sync.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_saveandsendonlyblockst', 'wtl_updatenetobjects', 'wtl_sendnetdataifneededfor',
         'wtl_loadanyblockheadsfordi', 'wtl_clientblockheadinvento', 'wtl_loadclientblockheadsda']

IMPS = ['0x008b49f8', '0x008c4c20', '0x008c7fe4', '0x008c9cac', '0x008fb288', '0x008fbe90']

COUNTS = {
    'wtl_saveandsendonlyblockst': (2, 1, 0, 4, 10, 22),
    'wtl_updatenetobjects': (44, 10, 4, 20, 177, 173),
    'wtl_sendnetdataifneededfor': (42, 2, 4, 5, 82, 86),
    'wtl_loadanyblockheadsfordi': (47, 16, 7, 13, 107, 77),
    'wtl_clientblockheadinvento': (25, 3, 7, 2, 40, 23),
    'wtl_loadclientblockheadsda': (52, 16, 12, 6, 102, 54),
}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == [578, 3313, 1495, 2040, 770, 1880]
    assert sum(BY[n]['verified_words'] for n in NAMES) == 10076
    for needle in ('10076', 'dirty-macro-tile', '65-slot', 'remoteCreationDataUpdate:',
                   'setNeedsRemoved: 1', 'gzipDeflate', 'sendDataToServer:',
                   'blockheadWillBeUnloaded:', 'liveServerClientBlockheadInventories',
                   'initForReadingWithData:'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_flush():
    s = BY['wtl_saveandsendonlyblockst']['semantics']
    for needle in ('worldChangedMacroPositions', 'worldChangedSendUnreliablyMacroPositions',
                   'macroTileAtMacroPostion', 'savePhysicalBlockForMacroTile:', 'sendReliably:1',
                   'sendReliably:0', '__aeabi_memmove'):
        assert needle in s, needle


def test_reconciliation():
    s = BY['wtl_updatenetobjects']['semantics']
    for needle in ('netCreateDynamicObjects', 'netRemoveDynamicObjects', 'getBytes:length:8',
                   'addIndex:', 'FreeBlock', 'freeBlockSoundDelay', 'remoteCreationDataUpdate:',
                   'remoteUpdate:', 'setNeedsRemoved: 1', 'removeAllObjects', 'netBlockheads'):
        assert needle in s, needle


def test_sender():
    s = BY['wtl_sendnetdataifneededfor']['semantics']
    for needle in ('needsNetDataToBeSent', 'creationDataNeedsToBeSent', 'updateNeedsToBeSent',
                   'macroPosForWorldPos', 'wireDynamicObject:', 'unwireDynamicObject:',
                   'addRemovalObjectDataToSend:', 'addCreationObjectDataToSend:',
                   'addUpdateObjectDataToSend:', 'gzipDeflate', 'sendDataToServer:',
                   'setUpdateNeedsToBeSent:0', '0x8b84c8'):
        assert needle in s, needle


def test_restore_and_inventory():
    s = BY['wtl_loadanyblockheadsfordi']['semantics']
    for needle in ('disconnectedClientsSaveDirNames', 'hasFinishedDatabaseMigrationTo17',
                   'setClientID:', 'blockheadWillBeUnloaded:', 'fullyLoadIfNeededAroundPos:',
                   'playerInfoForPeerID:', 'notifyPlayersChanged'):
        assert needle in s, needle
    s = BY['wtl_clientblockheadinvento']['semantics']
    for needle in ('liveServerClientBlockheadInventories', 'gzipInflate', 'propertyListWithData:',
                   'initWithSaveData:', 'updateSubItemSlot:atIndex:', 'gzipDeflate'):
        assert needle in s, needle
    s = BY['wtl_loadclientblockheadsda']['semantics']
    for needle in ('welcomeBackEventsMessageForClientID:', 'initForWritingWithMutableData:',
                   'encodeObject:forKey:', 'finishEncoding', 'initForReadingWithData:',
                   'decodeObjectForKey:', 'liveServerClientBlockheadInventories'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_flush()
    test_reconciliation()
    test_sender()
    test_restore_and_inventory()
    print('test_net_sync_evidence: OK')
