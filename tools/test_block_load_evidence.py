#!/usr/bin/env python3
"""Contract test for the physical-block load-path batch (E16).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the database-or-file fetch with the 0x10001 length check, the
memcpy of the 64 KB tile image, the version byte at payload offset 0x10000,
the create path (timestamp, x/y, pointer-slot free loop, version cleared), the
loaded-repair sky pass, the generation gates (customRules[14] + row band), the
marker ladders, the spawn/quarter-column markers ((W*32)/4 grid), the deep
byte3=0x5e ore band, the final loop's tree stamping (lrand48 fruit markers,
cosf canopy, placeGems on floating-island caves) and the stack-guard finish.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCK_LOAD.md').read_text()
DATA = json.loads((NATIVE / 'block_load.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_loadphysicalblock_atxp']

IMPS = ['0x0085e6b0']

WORDS = [5736]

COUNTS = {
    'wtl_loadphysicalblock_atxp': (43, 9, 5, 18, 133, 397),
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
    assert sum(WORDS) == 5736
    for needle in ('5736', 'block-load orchestrator', 'bestStartPosition', 'quarter-column',
                   '0x5e', 'placeGemsInCaveForPhysicalBlock', 'floatingIslandType', '0x10001'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_fetch_and_unpack():
    s = BY['wtl_loadphysicalblock_atxp']['semantics']
    for needle in ('require the data non-nil and [data length] >= 0x10001',
                   'memcpy(dst = *(PhysicalBlock+8) = the tile image',
                   'PhysicalBlock+0xd (the version field)',
                   'the loaded flag [fp,-0x33d] = 1'):
        assert needle in s, needle


def test_generation():
    s = BY['wtl_loadphysicalblock_atxp']['semantics']
    for needle in ('version byte cleared to 0 (0x0085f650)',
                   'customRules[14]',
                   'byte3 = 0x5e',
                   'bestStartPosition@76',
                   'The pair as read is (yPos*32, yPos*32)',
                   'bl 0x008540cc',
                   'cosf at 0x00863c74',
                   'floatingIslandType:marker]',
                   '__stack_chk_fail (0x0086401c)'):
        assert needle in s, needle
    syms = {v['symbol'] for v in BY['wtl_loadphysicalblock_atxp']['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.lakeHeights' in syms


def test_artifact_contract():
    assert DATA['batch'].startswith('Physical-block load-path batch (E16)')
    assert 'outside this body' in DATA['claim']
    assert '0x00864050' in DATA['claim']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['schema'] == 1
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    # the nine out-of-body rows (data-island false branches) are recorded, not dropped
    d = BY['wtl_loadphysicalblock_atxp']['disjoint_branch_rows']
    assert len(d) == 9, d
    assert d[0] == {'address': '0x0085f474', 'destination': '0x00923e38', 'mnemonic': 'bllo'}, d[0]


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_fetch_and_unpack()
    test_generation()
    test_artifact_contract()
    print('block load contract: OK')
