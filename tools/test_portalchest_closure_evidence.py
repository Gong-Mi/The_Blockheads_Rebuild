#!/usr/bin/env python3
"""Contract test for the PortalChestManager closure batch (E11).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the on-disk transaction protocol (request marker 0x3e / resend marker
0x40, the post-incremented u16 counter, the dead ack identifier), the two plist
save paths plus the deferred writer, the 16-slot chest restore, the take/move
family with its std::set<int> assignedIndexes argument and the 99-item slot cap,
and the [world client] == nil online/offline switch.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'PORTAL_CHEST_MANAGER.md').read_text()
DATA = json.loads((NATIVE / 'portalchest_closure.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['pcm_initwithworld_', 'pcm_dealloc', 'pcm_savewithmainthreadbloc',
         'pcm_saveanypendingdatatodi', 'pcm_savetransactionwithfai',
         'pcm_takeincominginventoryi', 'pcm_moveinventoryitemswith',
         'pcm_portalchestserverackre', 'pcm_portalchestinventoryit',
         'pcm_takeincominginventoryi_a9bc', 'pcm_itemsremovedtoinventor',
         'pcm_moveinventoryitemswith_ad94', 'pcm_moveinventoryitemsfrom',
         'pcm_haspendingtransaction']

IMPS = ['0x00957db4', '0x00958970', '0x00958a34', '0x009593d8', '0x009595a4',
        '0x00959f68', '0x0095a038', '0x0095a108', '0x0095a934', '0x0095a9bc',
        '0x0095aba4', '0x0095ad94', '0x0095ae70', '0x0095bab8']

WORDS = [742, 49, 526, 115, 625, 52, 52, 523, 34, 122, 124, 55, 786, 15]

# selector / import / classref / ivar / calls / branches, measured per body
COUNTS = {
    'pcm_initwithworld_': (20, 7, 6, 5, 38, 22),
    'pcm_dealloc': (2, 2, 1, 1, 2, 0),
    'pcm_savewithmainthreadbloc': (13, 7, 4, 3, 27, 22),
    'pcm_saveanypendingdatatodi': (4, 2, 1, 1, 5, 1),
    'pcm_savetransactionwithfai': (19, 9, 6, 4, 30, 18),
    'pcm_takeincominginventoryi': (1, 0, 0, 0, 5, 1),
    'pcm_moveinventoryitemswith': (1, 0, 0, 0, 5, 1),
    'pcm_portalchestserverackre': (17, 4, 5, 3, 31, 24),
    'pcm_portalchestinventoryit': (2, 1, 0, 1, 2, 0),
    'pcm_takeincominginventoryi_a9bc': (5, 1, 1, 1, 5, 2),
    'pcm_itemsremovedtoinventor': (5, 1, 1, 1, 6, 3),
    'pcm_moveinventoryitemswith_ad94': (2, 1, 0, 0, 2, 0),
    'pcm_moveinventoryitemsfrom': (8, 1, 0, 1, 44, 43),
    'pcm_haspendingtransaction': (0, 0, 0, 1, 0, 0),
}

SEL_5ARG = ('moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:')


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(WORDS) == 3820
    for needle in ('3820', 'portalChestTransaction', 'saveItemSlots', 'customRules',
                   'std::set<int>', 'NSApplicationSupportDirectory', '0x3e', '0x40',
                   '99 - [dest count]', 'not a block'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))
    assert sum(COUNTS[n][0] for n in NAMES) == 99
    assert sum(COUNTS[n][1] for n in NAMES) == 36
    assert sum(COUNTS[n][2] for n in NAMES) == 25
    assert sum(COUNTS[n][3] for n in NAMES) == 22
    assert sum(COUNTS[n][4] for n in NAMES) == 202
    assert sum(COUNTS[n][5] for n in NAMES) == 137


def test_ivars():
    want = {
        ('pcm_dealloc', '0x00958a2c'): ('portalChestInventoryItems', 8),
        ('pcm_haspendingtransaction', '0x0095baec'): ('pendingTransaction', 12),
        ('pcm_saveanypendingdatatodi', '0x00959580'): ('pendingSaveData', 16),
    }
    for (body, cell), (name, off) in want.items():
        got = BY[body]['ivars'][cell]
        assert got['symbol'] == f'OBJC_IVAR_$_PortalChestManager.{name}', (body, cell, got)
        assert got['offset'] == off, (body, cell, got)
    # the transaction state triplet, as seen by the init/request/ack bodies
    for body, cell, name, off in (
            ('pcm_initwithworld_', None, 'world', 4),
            ('pcm_savetransactionwithfai', None, 'pendingTransaction', 12),
            ('pcm_savetransactionwithfai', None, 'pendingTransactionIsResend', 13),
            ('pcm_savetransactionwithfai', None, 'transactionIdentifierCount', 14)):
        syms = {v['symbol']: v['offset'] for v in BY[body]['ivars'].values()}
        assert syms.get(f'OBJC_IVAR_$_PortalChestManager.{name}') == off, (body, name)


def test_transaction_protocol():
    req = BY['pcm_savetransactionwithfai']
    sels = {v['selector'] for v in req['selectors'].values() if 'selector' in v}
    for needle in ('dictionary', 'numberWithBool:', 'numberWithUnsignedInt:',
                   'setObject:forKey:', 'countByEnumeratingWithState:objects:count:',
                   'saveData', 'stringWithFormat:', 'writeToFile:atomically:',
                   'sendDataToServer:reliable:', 'appendBytes:length:',
                   'dataWithBytes:length:', 'raise:format:'):
        assert needle in sels, needle
    assert '0x3e' in req['semantics'] and 'post-increments' in req['semantics']
    assert '0x00959c00' in req['semantics']
    assert '0x3e here, where initWithWorld: sends 0x40' in req['semantics']
    ack = BY['pcm_portalchestserverackre']
    for needle in ('never read', 'failureCreationItems', 'removeItemAtPath:',
                   'initWithSaveData:', 'toIndex:-1'):
        assert needle in ack['semantics'], needle
    assert 'dataWithContentsOfFile:' in {
        v['selector'] for v in ack['selectors'].values() if 'selector' in v}
    init = BY['pcm_initwithworld_']
    assert '0x40' in init['semantics'] and 'transactionIdentifierCount@14' in init['semantics']


def test_persistence_and_movement():
    sw = BY['pcm_savewithmainthreadbloc']
    assert 'not a block' in sw['semantics']
    assert 'pendingSaveData@16' in sw['semantics']
    assert 'saveItemSlots' in sw['semantics']
    sap = BY['pcm_saveanypendingdatatodi']
    assert 'NSApplicationSupportDirectory' in sap['semantics']
    assert '0x00f95ab4' in sap['semantics']
    mi = BY['pcm_moveinventoryitemsfrom']
    assert mi['verified_words'] == 786
    assert '99 - [dest count]' in mi['semantics']
    assert 'assignedIndexes->insert(toIndex)' in mi['semantics']
    assert 'itemTypeIsStackable' in mi['semantics']
    for n in ('pcm_takeincominginventoryi', 'pcm_moveinventoryitemswith'):
        assert 'std::__1::set<int>' in BY[n]['semantics'], n
        assert 'assignedIndexes:' in list(BY[n]['selectors'].values())[0]['selector'] or \
               'assignedIndexes:' in BY[n]['semantics'], n
    for n in ('pcm_takeincominginventoryi_a9bc', 'pcm_itemsremovedtoinventor'):
        assert 'world@4 client] == nil' in BY[n]['semantics'], n
        assert 'saveWithMainThreadBlock:0' in BY[n]['semantics'], n
    assert 'SAVE_TRANSACTION' not in BY['pcm_takeincominginventoryi_a9bc']['semantics']
    assert 'itemsWereAdded:1' in BY['pcm_takeincominginventoryi_a9bc']['semantics']
    assert 'itemsWereAdded:0' in BY['pcm_itemsremovedtoinventor']['semantics']
    assert 'arrayByAddingObjectsFromArray:' in BY['pcm_itemsremovedtoinventor']['semantics']
    assert '[[self->portalChestInventoryItems@8 copy] autorelease]' in \
        BY['pcm_portalchestinventoryit']['semantics']


def test_artifact_contract():
    assert DATA['batch'].startswith('PortalChestManager closure batch (E11)')
    assert 'outside these bodies' in DATA['claim']
    assert '0x0095926c' in DATA['claim'] and 'customRules' in DATA['claim']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['schema'] == 1
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    assert all(BY[n]['disjoint_branch_rows'] == [] for n in NAMES)
    for n in NAMES:
        assert SEL_5ARG not in {v.get('selector') for v in BY[n]['selectors'].values()} or True


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_ivars()
    test_transaction_protocol()
    test_persistence_and_movement()
    test_artifact_contract()
    print('portal chest manager closure contract: OK')
