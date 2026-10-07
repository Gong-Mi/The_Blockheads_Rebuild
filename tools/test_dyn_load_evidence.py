#!/usr/bin/env python3
"""Contract test for the DynamicWorld dynamic-object load-chain batch (E19).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics of the three-body chain: the per-macro-tile restore (version ladder
2/6/7/8 with the updatePhysicalBlockToLatestVersion caller, tree-promise pool,
marker scan, surface pass), the world-level restore (three-source fetch,
one-to-two conversion thread, NSKeyedUnarchiver portal set, gzipInflate,
Blockhead construction) and the per-type constructor worker (reentrancy guard,
dedup gates, class dispatch, container registration).
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'DYN_OBJECT_LOAD.md').read_text()
DATA = json.loads((NATIVE / 'dyn_load.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_loaddynamicobjectsform', 'wtl_loaddynamicobjects_rep', 'wtl_loaddynamicobjectsofty']

IMPS = ['0x008bd9b8', '0x008aedac', '0x008baa54']

WORDS = [6196, 3073, 1938]

COUNTS = {
    'wtl_loaddynamicobjectsform': (58, 9, 4, 15, 222, 363),
    'wtl_loaddynamicobjects_rep': (56, 25, 9, 20, 151, 125),
    'wtl_loaddynamicobjectsofty': (28, 16, 5, 21, 109, 90),
}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(WORDS) == 11207
    for needle in ('11207', 'dynamic-object', 'version ladder', 'tree-promise', 'gzipInflate',
                   'conversionThread', 'NSKeyedUnarchiver', 'currentlyLoadingMacroBlocks',
                   'blockheadWithIDIncludingNet', 'surface pass',
                   'updatePhysicalBlockToLatestVersion'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_macro_tile_restore():
    s = BY['wtl_loaddynamicobjectsform']['semantics']
    for needle in ('versionOneToTwoConversionList', '__wrap_rename',
                   'updatePhysicalBlockToLatestVersion:physicalBlock',
                   'treeTypeForTreePromise', 'loadTreeAtPosition:',
                   'loadPlantAtPosition:type:maxAgeGene:growthRateGene:adult:',
                   'loadNPCAtPosition:', 'loadSnowSurfaceBlockAtPos:loadSnow:',
                   'loadSurfaceBlockAtPos:'):
        assert needle in s, needle


def test_world_level_restore():
    s = BY['wtl_loaddynamicobjects_rep']['semantics']
    for needle in ('dataForKey:', 'dataWithContentsOfFile:', 'dictionaryWithContentsOfFile:',
                   '0x7fffffff', 'conversionThread:', 'NSKeyedUnarchiver',
                   'portalPositions', 'gzipInflate', 'blockheadWithIDIncludingNet:',
                   'NSPropertyListSerialization', 'savedInventorySlots', 'clientLocallySavedDict',
                   'fullyLoadIfNeededAroundPos:', 'std::__1::__tree_next'):
        assert needle in s, needle


def test_type_worker():
    s = BY['wtl_loaddynamicobjectsofty']['semantics']
    for needle in ('currentlyLoadingMacroBlocks', 'currentlyAddingObjectIDs',
                   'dynamicObjectTypeForInteractionObjectType', 'classForDynamicObjectType',
                   'classForInteractionObjectType', 'Workbench', 'dynamicWorldChangedAtPos:objectType:',
                   'worldIndexAtWorldPos', 'setLevelSilently:3', 'blockheadsLoaded'):
        assert needle in s, needle
