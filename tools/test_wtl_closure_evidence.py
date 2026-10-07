#!/usr/bin/env python3
"""Contract test for the WorldTileLoader closure batch (E18).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics of the 16-body closure set: dealloc (15 objc_msgSend(release)
dispatches, six __wrap_free C-buffer frees, objc_msgSendSuper2(super, dealloc)),
.cxx_construct (no-op) and fourteen accessors (atomic getters with dmb ish, two
objc_copyStruct struct getters, one plain ldrsb getter, one barrier-bracketed
char setter, two float getters via vmov r0, s0).
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WTL_CLOSURE.md').read_text()
DATA = json.loads((NATIVE / 'wtl_closure.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = [
    'wtl_dealloc', 'wtl_cxx_construct', 'wtl_distanceorderedfoodtyp', 'wtl_randomseed',
    'wtl_beststartposition', 'wtl_treedensitynoisefuncti', 'wtl_seasonoffsetnoisefunct',
    'wtl_treepositions', 'wtl_npcpositions', 'wtl_plantpositions', 'wtl_highestpoint',
    'wtl_needstoexit', 'wtl_setneedstoexit_', 'wtl_xfrequencymultiplier',
    'wtl_yheightdivider', 'wtl_lightblockdatabase',
]

IMPS = [
    '0x00854770', '0x00868fd8', '0x00865074', '0x00868c40', '0x00868c7c', '0x00868cdc',
    '0x00868d20', '0x00868d64', '0x00868da8', '0x00868dec', '0x00868e30', '0x00868e90',
    '0x00868ecc', '0x00868f10', '0x00868f4c', '0x00868f94',
]

COUNTS = {
    'wtl_dealloc': (2, 2, 1, 21, 22, 0),
    'wtl_cxx_construct': (0, 0, 0, 0, 0, 0),
    'wtl_distanceorderedfoodtyp': (0, 0, 0, 1, 0, 0),
    'wtl_randomseed': (0, 0, 0, 1, 0, 0),
    'wtl_beststartposition': (0, 0, 0, 1, 1, 0),
    'wtl_treedensitynoisefuncti': (0, 0, 0, 5, 0, 0),
    'wtl_seasonoffsetnoisefunct': (0, 0, 0, 4, 0, 0),
    'wtl_treepositions': (0, 0, 0, 3, 0, 0),
    'wtl_npcpositions': (0, 0, 0, 2, 0, 0),
    'wtl_plantpositions': (0, 0, 0, 1, 0, 0),
    'wtl_highestpoint': (0, 0, 0, 1, 1, 0),
    'wtl_needstoexit': (0, 0, 0, 1, 0, 0),
    'wtl_setneedstoexit_': (0, 0, 0, 1, 0, 0),
    'wtl_xfrequencymultiplier': (0, 0, 0, 1, 0, 0),
    'wtl_yheightdivider': (0, 0, 0, 2, 0, 0),
    'wtl_lightblockdatabase': (0, 0, 0, 1, 0, 0),
}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 736
    for needle in ('16 bodies', 'dealloc', '__wrap_free', 'objc_msgSendSuper2', 'release',
                   'no-op', 'dmb ish', 'objc_copyStruct', 'lightBlockDatabaseEnvironment',
                   'setNeedsToExit'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_dealloc():
    s = BY['wtl_dealloc']['semantics']
    for needle in ('blockDirectory', 'heightNoiseFunctionA', 'gemNoiseFunction',
                   'treePositions', 'npcPositions', 'plantPositions', 'dirtHeights',
                   'rockHeights', 'lakeHeights', 'raw C buffers'):
        assert needle in s, needle
    syms = {v['symbol'] for v in BY['wtl_dealloc']['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.blockDirectory' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment' in syms


def test_accessors():
    s = BY['wtl_randomseed']['semantics']
    assert 'dmb ish' in s and 'randomSeed' in s
    s = BY['wtl_beststartposition']['semantics']
    assert 'objc_copyStruct' in s and 'atomic 1' in s
    s = BY['wtl_needstoexit']['semantics']
    assert 'ldrsb' in s and 'no memory barrier' in s
    s = BY['wtl_setneedstoexit_']['semantics']
    assert 'barrier-after-store' in s
    s = BY['wtl_yheightdivider']['semantics']
    assert 'vmov r0, s0' in s
    s = BY['wtl_cxx_construct']['semantics']
    assert 'no-op stub' in s
