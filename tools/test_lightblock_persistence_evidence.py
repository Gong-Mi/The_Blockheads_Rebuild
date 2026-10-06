#!/usr/bin/env python3
"""Contract test for the light-block persistence batch (E13).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the legacy->per-block archive migration, the archive writer, the
per-block load/save pair, the client send path and the bulk-transaction pair.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'LIGHTBLOCK_PERSISTENCE.md').read_text()
DATA = json.loads((NATIVE / 'lightblock_persistence.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_unarchivelightblocksfo', 'wtl_archivelightblocksforc',
         'wtl_loadlightblockforclien', 'wtl_sendlightblocktoclient',
         'wtl_savelightblockforclien', 'wtl_startbulklightblocktra',
         'wtl_finishbulklightblocktr']

IMPS = ['0x0086652c', '0x00866f30', '0x00867a58', '0x008681e4', '0x00868700',
        '0x00868b70', '0x00868bd8']

WORDS = [632, 456, 483, 327, 284, 52, 26]

COUNTS = {
    'wtl_unarchivelightblocksfo': (20, 7, 2, 2, 37, 14),
    'wtl_archivelightblocksforc': (18, 9, 5, 1, 32, 19),
    'wtl_loadlightblockforclien': (13, 4, 3, 3, 22, 13),
    'wtl_sendlightblocktoclient': (11, 1, 3, 1, 14, 6),
    'wtl_savelightblockforclien': (11, 2, 2, 2, 14, 6),
    'wtl_startbulklightblocktra': (2, 2, 0, 2, 2, 0),
    'wtl_finishbulklightblocktr': (1, 1, 0, 1, 1, 0),
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
    assert sum(WORDS) == 2260
    for needle in ('2260', 'lightBlockDatabase@252', 'lightBlockDatabaseEnvironment@248',
                   '1024', 'macroPosForMacroIndex', 'macroIndexAtMacroPosition',
                   'startBulkTransaction', 'finishBulkTransaction', 'gzipDeflate',
                   'tiles[32]@0x20', 'flags[32]@0xA0', 'hasFinishedDatabaseMigrationTo17',
                   'playerLightBlocks', 'sendNetworkData:', 'toPeers:'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))
    assert sum(COUNTS[n][0] for n in NAMES) == 76
    assert sum(COUNTS[n][1] for n in NAMES) == 26
    assert sum(COUNTS[n][2] for n in NAMES) == 15
    assert sum(COUNTS[n][3] for n in NAMES) == 12
    assert sum(COUNTS[n][4] for n in NAMES) == 122
    assert sum(COUNTS[n][5] for n in NAMES) == 58


def test_migration():
    u = BY['wtl_unarchivelightblocksfo']
    for needle in ('%@_archiveKeys', '%@_archiveData', '1024 * [plist count]',
                   'componentsSeparatedByString', 'macroIndexAtMacroPosition',
                   'allLightBlockIndices', 'saveLightBlockIndices',
                   'startBulkLightBlockTransaction', 'unarchived %d LightBlocks',
                   'Measured caveat'):
        assert needle in u['semantics'], needle
    syms = {v['symbol'] for v in u['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase' in syms
    a = BY['wtl_archivelightblocksforc']
    for needle in ('%@_allIndexes', 'initForReadingWithData', 'decodeObjectForKey',
                   'enumerateIndexesUsingBlock', 'macroPosForMacroIndex', 'memcpy',
                   'dataWithBytes:', 'gzipDeflate', 'format:100',
                   '%@_archiveKeys', '%@_archiveData'):
        assert needle in a['semantics'], needle


def test_load_save():
    l = BY['wtl_loadlightblockforclien']
    for needle in ('%@_%d_%d', 'hasFinishedDatabaseMigrationTo17',
                   'playerLightBlocks/', '%@%d_%d_lightBlock', 'fileExistsAtPath',
                   'gzipInflate', 'malloc(0x400)', 'calloc(1, 0x400)',
                   'fullyLoadIfNeededAroundPos:', 'forBlockhead:nil',
                   'startPortalPos'):
        assert needle in l['semantics'], needle
    for needle in ('x@0', 'y@4', 'tiles[32]@0x20', 'flags[32]@0xA0'):
        assert needle in l['semantics'], needle
    s = BY['wtl_savelightblockforclien']
    for needle in ('setData:', 'dataWithBytes', '0x400', 'containsIndex',
                   'saveLightBlockIndices', 'sendNow', 'not gated by the flag'):
        assert needle in s['semantics'], needle


def test_send_and_transactions():
    t = BY['wtl_sendlightblocktoclient']
    for needle in ('sendNetworkData', 'arrayWithObject', 'connected', 'lightBlockIndex',
                   'gzipDeflate', 'returning'):
        assert needle in t['semantics'], needle
    st = BY['wtl_startbulklightblocktra']
    assert 'startBulkTransaction' in st['semantics'] and '248' in st['semantics']
    fi = BY['wtl_finishbulklightblocktr']
    assert 'finishBulkTransaction' in fi['semantics'] and 'sxtb' in fi['semantics']


def test_artifact_contract():
    assert DATA['batch'].startswith('Light-block persistence batch (E13)')
    assert 'outside these bodies' in DATA['claim']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['schema'] == 1
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    assert all(BY[n]['disjoint_branch_rows'] == [] for n in NAMES)


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_migration()
    test_load_save()
    test_send_and_transactions()
    test_artifact_contract()
    print('light-block persistence contract: OK')
