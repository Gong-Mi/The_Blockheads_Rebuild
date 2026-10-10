#!/usr/bin/env python3
"""Contract test for the WorldTileLoader world-constructor batch (E17).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics of the largest body in the binary: the size normalisation to 0x200,
the three height arrays (rockHeights/dirtHeights/lakeHeights), the Documents-
path block-storage resolution, the saved-state pass with the 0x7fffffff
sentinel and the ==32 gate, the noise construction groups, the spawn streak
search, the -1 retry sentinel, the per-column tree/plant candidate pass with
the distance bids, the bestStartPosition search, the statistics NSLog, the
quickSort of the bid table into distanceOrderedFoodTypes and the final
registration dispatch with the stack-guard epilogue.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'WTL_INITWITHWORLD.md').read_text()
DATA = json.loads((NATIVE / 'wtl_initwithworld.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_initwithworld_randomse']

IMPS = ['0x00849728']

WORDS = [10857]

COUNTS = {
    'wtl_initwithworld_randomse': (54, 22, 8, 83, 393, 543),
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
    assert sum(WORDS) == 10857
    for needle in ('10857', 'world constructor', 'bestStartPosition', 'quarter-column',
                   'rockHeights', 'distanceOrderedFoodTypes', 'seasonOffsetNoiseFunction',
                   '0x7fffffff', '0x200', 'compressBlocks'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_constructor_pipeline():
    s = BY['wtl_initwithworld_randomse']['semantics']
    for needle in ('normalised to 0x200',
                   'rockHeights, dirtHeights and lakeHeights',
                   'NSSearchPathForDirectoriesInDomains(0xe, 1, 1)',
                   'The pair is turned into the vertical scale',
                   'the srand48-style seeder',
                   'seed-retry loop',
                   '0x2710',
                   'quickSort(float*, 0x1f, unsigned int*)',
                   'distanceOrderedFoodTypes',
                   '__stack_chk_fail'):
        assert needle in s, needle


def test_candidate_pass():
    s = BY['wtl_initwithworld_randomse']['semantics']
    for needle in ('growthVigorForTreeTypeAtPos(TreeType, (idx, maxAB), world)',
                   'growthVigorForPlantTypeAtPos',
                   'lrand48',
                   'the bestStartPosition selection',
                   '0x00853f28',
                   '0x0084ed20',
                   '0x008516dc'):
        assert needle in s, needle
    syms = {v['symbol'] for v in BY['wtl_initwithworld_randomse']['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.rockHeights' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.distanceOrderedFoodTypes' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.seasonOffsetNoiseFunction' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.xFrequencyMultiplier' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider' in syms


def test_retry_and_sentinels():
    s = BY['wtl_initwithworld_randomse']['semantics']
    for needle in ('0x7fffffff', 'cmp r0, 0x20', '0x0084d000', '0x0085328c', '0x7d0'):
        assert needle in s, needle

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_constructor_pipeline()
    test_candidate_pass()
    test_retry_and_sentinels()
    print('test_wtl_initwithworld_evidence: OK')
