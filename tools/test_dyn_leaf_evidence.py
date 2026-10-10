#!/usr/bin/env python3
"""Contract test for the DynamicWorld load-chain leaf batch (E20).

Pins the JSON artifact and the prose doc to the recovered semantics of the ten
constructor workers: the tree factory (11 classes, occupancy scan, GemTree
variant), the plant factory (10 classes), the NPC factory (512 cap + sparsity
gate), the surface/snow forwarders (types 0x16/0x1d), the GlowBlock triple-dedup
path, the Torch needsRemoved gate, the treasure/troll cave generator (rarity
ladder, 0xa6/0xa7 variant) and the blockhead spawner, plus the background
conversion thread.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DYN_OBJECT_LEAVES.md').read_text()
DATA = json.loads((NATIVE / 'dyn_leaf.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_conversionthread_', 'wtl_loadtreeatposition_typ', 'wtl_loadplantatposition_ty',
         'wtl_loadnpcatposition_type', 'wtl_loadsnowsurfaceblockat', 'wtl_loadsurfaceblockatpos_',
         'wtl_loadglowblockifneededa', 'wtl_addtorchatpos_oftype_d', 'wtl_createtreasurechestort',
         'wtl_loadnewblockheadatpos_']

IMPS = ['0x008ae5b8', '0x008e4e44', '0x008e69e8', '0x008e66d4', '0x008e6608', '0x008e6594',
        '0x008f4f88', '0x008e8320', '0x008e909c', '0x008f5b70']

COUNTS = {
    'wtl_conversionthread_': (14, 1, 3, 2, 29, 13),
    'wtl_loadtreeatposition_typ': (7, 2, 11, 6, 45, 73),
    'wtl_loadplantatposition_ty': (5, 1, 10, 6, 27, 29),
    'wtl_loadnpcatposition_type': (7, 1, 0, 3, 10, 7),
    'wtl_loadsnowsurfaceblockat': (2, 1, 0, 0, 2, 1),
    'wtl_loadsurfaceblockatpos_': (1, 0, 0, 0, 1, 0),
    'wtl_loadglowblockifneededa': (5, 1, 1, 6, 15, 8),
    'wtl_addtorchatpos_oftype_d': (5, 1, 1, 4, 10, 5),
    'wtl_createtreasurechestort': (18, 2, 5, 5, 94, 83),
    'wtl_loadnewblockheadatpos_': (14, 2, 3, 4, 32, 32),
}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == [509, 1283, 776, 197, 51, 29, 362, 229, 1447, 596]
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5479
    for needle in ('5479', 'Tree factory', 'Plant factory', 'occupancy scan', 'GemTree',
                   'conversionThread', 'rarity ladder', 'currentlyAddingGlowBlocks',
                   'needsRemoved', 'updateInTimeSinceSaved', 'moveInventoryItemsFromArray'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_factories():
    s = BY['wtl_loadtreeatposition_typ']['semantics']
    for needle in ('AppleTree', 'MangoTree', 'MapleTree', 'PineTree', 'CactusTree',
                   'CoconutTree', 'OrangeTree', 'CherryTree', 'CoffeeTree', 'LimeTree',
                   'GemTree', 'tree_next'):
        assert needle in s, needle
    s = BY['wtl_loadplantatposition_ty']['semantics']
    for needle in ('FlaxPlant', 'SunflowerPlant', 'CornPlant', 'CarrotPlant', 'ChilliPlant',
                   'KelpPlant', 'VinePlant', 'TulipPlant', 'WheatPlant', 'TomatoPlant'):
        assert needle in s, needle
    s = BY['wtl_loadnpcatposition_type']['semantics']
    for needle in ('dynamicObjectTypeForNPCType', 'loadedCountOfObjectsOfType:', '0x200',
                   'tooManyNPCsToSpawnMoreNearPos:', 'classForNPCType'):
        assert needle in s, needle


def test_forwarders_and_gates():
    s = BY['wtl_loadsurfaceblockatpos_']['semantics']
    assert '0x16' in s
    s = BY['wtl_loadsnowsurfaceblockat']['semantics']
    assert '0x1d' in s and 'updateInTimeSinceSaved' in s
    s = BY['wtl_loadglowblockifneededa']['semantics']
    for needle in ('currentlyAddingGlowBlocks', '+0x168', 'GlowBlock', 'macroIndexAtWorldIndex'):
        assert needle in s, needle
    s = BY['wtl_addtorchatpos_oftype_d']['semantics']
    assert 'needsRemoved' in s and '+0xcc' in s


def test_treasure_and_blockhead():
    s = BY['wtl_createtreasurechestort']['semantics']
    for needle in ('0xb7', '0x430', '0x149', '0xa6 or 0xa7', 'moveInventoryItemsFromArray',
                   'loadNPCAtPosition:', 'MJSoundManager', '0x30'):
        assert needle in s, needle
    s = BY['wtl_loadnewblockheadatpos_']['semantics']
    for needle in ('Blockhead', 'activeBlockheadIndex', 'worldChanged:', 'blockheadCountChanged',
                   'ParticleEmitter', 'sendNetDataIfNeededForObject:'):
        assert needle in s, needle


def test_conversion_thread():
    s = BY['wtl_conversionthread_']['semantics']
    for needle in ('NSAutoreleasePool', 'setThreadPriority:', 'sleepForTimeInterval:',
                   '__wrap_rename', 'mainThreadRemoveDirFromConversionList:', 'worldSaveDirectory'):
        assert needle in s, needle

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_factories()
    test_forwarders_and_gates()
    test_treasure_and_blockhead()
    test_conversion_thread()
    print('test_dyn_leaf_evidence: OK')
