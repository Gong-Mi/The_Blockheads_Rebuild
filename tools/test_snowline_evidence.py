#!/usr/bin/env python3
"""Contract test for the snow surface + ice melt line (E118)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'SNOWLINE.md').read_text()
DATA = json.loads((NATIVE / 'snowline.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['sl_00', 'sl_01', 'sl_02', 'sl_03', 'sl_04', 'sl_05', 'sl_06', 'sl_07', 'sl_08', 'sl_09', 'sl_10', 'sl_11', 'sl_12', 'sl_13', 'sl_14', 'sl_15', 'sl_16', 'sl_17', 'sl_18', 'sl_19', 'sl_20', 'sl_21', 'sl_22', 'sl_23', 'sl_24']
IMPS = ['0x00d918d8', '0x00d8d9b8', '0x00d8d5e0', '0x00d8d89c', '0x00d8da7c', '0x00d8d5c4', '0x00d8d4b8', '0x00d8dab8', '0x00d8db28', '0x00d8e530', '0x00d8fb80', '0x00d903b8', '0x00d90a4c', '0x00d90e84', '0x00d911d8', '0x00d913d4', '0x00d91588', '0x00d919a0', '0x00d919e8', '0x00834210', '0x00835b60', '0x006cbbe0', '0x006cdccc', '0x008e1bf0', '0x008e6608']
COUNTS = {'sl_00': (2, 2, 1, 0, 2, 1), 'sl_01': (2, 2, 1, 1, 2, 0), 'sl_02': (5, 0, 1, 3, 9, 2), 'sl_03': (2, 2, 1, 0, 2, 2), 'sl_04': (0, 0, 0, 1, 0, 0), 'sl_05': (0, 0, 0, 0, 0, 0), 'sl_06': (2, 2, 1, 2, 3, 0), 'sl_07': (1, 1, 1, 0, 1, 0), 'sl_08': (6, 1, 0, 5, 16, 30), 'sl_09': (16, 2, 1, 10, 62, 65), 'sl_10': (3, 0, 1, 4, 25, 22), 'sl_11': (3, 1, 0, 4, 13, 40), 'sl_12': (2, 1, 0, 3, 9, 21), 'sl_13': (3, 1, 0, 4, 6, 17), 'sl_14': (2, 1, 0, 3, 4, 4), 'sl_15': (2, 1, 0, 2, 6, 7), 'sl_16': (2, 1, 0, 3, 5, 18), 'sl_17': (0, 0, 0, 1, 0, 0), 'sl_18': (0, 0, 0, 1, 0, 0), 'sl_19': (3, 0, 0, 6, 6, 14), 'sl_20': (6, 1, 0, 6, 10, 7), 'sl_21': (3, 0, 0, 6, 17, 43), 'sl_22': (6, 1, 0, 6, 10, 7), 'sl_23': (0, 0, 0, 1, 1, 11), 'sl_24': (2, 1, 0, 0, 2, 1)}
WORDS = [50, 49, 175, 71, 15, 7, 63, 28, 642, 1428, 526, 421, 270, 198, 127, 109, 212, 18, 19, 202, 272, 439, 272, 202, 51]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 5866
    for needle in ('5866', 'iceMeltTimer', 'fillTile:atPos:withType:', 'snowChangedAtMacroPos',
                   'partialContent', '255.0', '0x423', '0xf4', '0x422', 'rainRandomTimer',
                   'addParticleAtPos', 'spreadGrass', 'updateGroundFrozen', '0x64'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_snowline():
    s = BY['sl_20']['semantics']
    assert '0xf4' in s and 'iceMeltTimer' in s and 'fillTile' in s
    s = BY['sl_12']['semantics']
    assert 'snowChangedAtMacroPos' in s and '0x1b/0x1c' in s
    s = BY['sl_13']['semantics']
    assert '255.0' in s
    s = BY['sl_22']['semantics']
    assert 'Stairs' in s
    symbols = {v['symbol'] for e in DATA['classes'] for v in e['ivars'].values()}
    assert 'OBJC_IVAR_$_SnowSurfaceBlock.temperature' in symbols
    assert 'OBJC_IVAR_$_SnowSurfaceBlock.partialContent' in symbols
    assert 'OBJC_IVAR_$_Column.iceMeltTimer' in symbols
    assert 'OBJC_IVAR_$_Stairs.iceMeltTimer' in symbols


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_snowline()
    print('test_snowline_evidence: OK')
