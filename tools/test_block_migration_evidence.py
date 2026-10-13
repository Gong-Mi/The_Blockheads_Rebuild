#!/usr/bin/env python3
"""Contract test for the physical-block version-upgrade batch (E15).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the cumulative version ladder (gates at 3/5/7, no write-back of the
version byte), stage A's guard chain + two-sided 0.55..0.85 flint band + the
treasure/troll placement, stage B's 0x3a beach-band writes, stage C's mirrored
tin band with the 0x6a/0x6b byte3 writes, and the single recorded out-of-body
branch row.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCK_MIGRATION.md').read_text()
DATA = json.loads((NATIVE / 'block_migration.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_updatephysicalblocktol']

IMPS = ['0x008650b0']

WORDS = [1311]

COUNTS = {
    'wtl_updatephysicalblocktol': (13, 2, 0, 10, 29, 81),
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
    assert sum(WORDS) == 1311
    for needle in ('1311', 'cumulative version ladder', 'createTreasureChestOrTrollAtTile',
                   'bestStartPosition', '0x3a', '0x6a', 'no writer of offset 13',
                   '0.85 - 0.3'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_version_ladder():
    s = BY['wtl_updatephysicalblocktol']['semantics']
    for needle in ("the whole listing contains no store to offset 13 of the record",
                   'gate two runs (cmp 5, bge 0x00865bbc at 0x00865698)',
                   'whose bge at 0x00865bc8 jumps straight to the epilogue at 0x00866474'):
        assert needle in s, needle


def test_stage_writes():
    s = BY['wtl_updatephysicalblocktol']['semantics']
    for needle in ('byte2 = 1 (strb 0x008655a0)', 'byte1 = 1 (strb 0x008655b4)',
                   'byte0 = 2 (strb 0x008655c8)',
                   '0.55 synthesised as 0.85-0.3 at 0x00865568',
                   'loadTroll:0 loadTreasure:1',
                   'writes 0x3a into tile byte0 (strb 0x00865b78) and byte1 (strb 0x00865b80)',
                   'stores byte3 = 0x6a (strb 0x0086622c)',
                   'stores byte3 = 0x6b when 0.1 < noise6 < 0.15'):
        assert needle in s, needle
    syms = {v['symbol'] for v in BY['wtl_updatephysicalblocktol']['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction' in syms


def test_artifact_contract():
    assert DATA['batch'].startswith('Physical-block version-upgrade batch (E15)')
    assert 'outside this body' in DATA['claim']
    assert 'the caller that bumps the version byte' in DATA['claim']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['schema'] == 1
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    # the one branch row that leaves the body is recorded, not dropped
    d = BY['wtl_updatephysicalblocktol']['disjoint_branch_rows']
    assert d == [{'address': '0x00866254', 'destination': '0xfe92ac18', 'mnemonic': 'bllo'}], d


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_version_ladder()
    test_stage_writes()
    test_artifact_contract()
    print('block migration contract: OK')
