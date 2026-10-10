#!/usr/bin/env python3
"""Contract test for the terrain generation batch (E12).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the material fractions (and the sandstone sentinel), the desert /
beach / desert-or-beach / floating-island-cave predicates, the block-id choice
and flint bands in fillDirtTile:, the recursive dirt and water flow-out bodies,
the ore/gem stamping path and the spawn-column search.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TERRAIN_GENERATION.md').read_text()
DATA = json.loads((NATIVE / 'terrain_generation.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_limestonefractionforx_', 'wtl_sandstonefractionforx_',
         'wtl_isfloatingislandcavefo', 'wtl_sandfractionforpos_hig',
         'wtl_sandfractionforpos_hei', 'wtl_isdesertforpos_height_',
         'wtl_isbeachforpos_height_', 'wtl_isdesertorbeachforpos_',
         'wtl_filldirttile_worldpos_', 'wtl_recursivelyflowoutwate',
         'wtl_recursivelyflowoutdirt', 'wtl_placegemsincaveforphys',
         'wtl_findbeststartposition']

IMPS = ['0x00857684', '0x008578b8', '0x00858320', '0x0085a84c', '0x0085ab18',
        '0x0085b0d0', '0x0085b190', '0x0085b480', '0x0085b5b0', '0x0085c214',
        '0x0085c518', '0x0085ce60', '0x00864188']

WORDS = [141, 93, 209, 179, 366, 48, 188, 76, 793, 193, 594, 1556, 955]

COUNTS = {
    'wtl_limestonefractionforx_': (2, 1, 0, 3, 2, 2),
    'wtl_sandstonefractionforx_': (1, 0, 0, 2, 2, 5),
    'wtl_isfloatingislandcavefo': (3, 2, 0, 4, 6, 7),
    'wtl_sandfractionforpos_hig': (2, 0, 0, 3, 5, 11),
    'wtl_sandfractionforpos_hei': (3, 2, 0, 2, 13, 15),
    'wtl_isdesertforpos_height_': (1, 0, 0, 0, 1, 0),
    'wtl_isbeachforpos_height_': (2, 1, 0, 2, 4, 7),
    'wtl_isdesertorbeachforpos_': (2, 0, 0, 0, 2, 1),
    'wtl_filldirttile_worldpos_': (6, 2, 0, 5, 19, 51),
    'wtl_recursivelyflowoutwate': (1, 0, 0, 1, 9, 9),
    'wtl_recursivelyflowoutdirt': (3, 0, 0, 1, 28, 34),
    'wtl_placegemsincaveforphys': (10, 5, 0, 8, 33, 125),
    'wtl_findbeststartposition': (4, 2, 0, 4, 50, 50),
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
    assert sum(WORDS) == 5391
    for needle in ('5391', 'customRules', 'lrand48()', '0.3', '0.45', '0x5f5e0ff',
                   'worldWidthMacro', 'getX:Y:octaves:', 'tile[3]', 'byte0xb',
                   '(x, y+1)', 'never visited', '(-1, -1)'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))
    assert sum(COUNTS[n][0] for n in NAMES) == 40
    assert sum(COUNTS[n][1] for n in NAMES) == 15
    assert sum(COUNTS[n][2] for n in NAMES) == 0
    assert sum(COUNTS[n][3] for n in NAMES) == 35
    assert sum(COUNTS[n][4] for n in NAMES) == 174
    assert sum(COUNTS[n][5] for n in NAMES) == 317


def test_fractions():
    ls = BY['wtl_limestonefractionforx_']
    for needle in ('1024.0', '39599.0', '32.0f * self->yHeightDivider@244', 'min((faultOffset / 1024.0f) * 2.0f, 1.0f)'):
        assert needle in ls['semantics'], needle
    syms = {v['symbol'] for v in ls['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction' in syms
    assert 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider' in syms
    ss = BY['wtl_sandstonefractionforx_']
    assert '0.45' in ss['semantics'] and '-1.0f' in ss['semantics']
    assert 'isDesertForPos:pos height:minHeight' in ss['semantics']
    hi = BY['wtl_sandfractionforpos_hig']
    assert '0.0f' in hi['semantics'] and 'worldWidthMacro * 32' in hi['semantics']
    hh = BY['wtl_sandfractionforpos_hei']
    for needle in ('MAX(512', 'octaves:(highRes ? 11 : 4)', '0x0085adf0', '__wrap_fmodf'):
        assert needle in hh['semantics'], needle
    assert 'clamp_float' in hh['semantics']


def test_predicates():
    d = BY['wtl_isdesertforpos_height_']
    assert '> 0.3)' in d['semantics'] and '0x0085b180' in d['semantics']
    assert len(d['ivars']) == 0
    db = BY['wtl_isdesertorbeachforpos_']
    assert 'isBeachForPos:pos height:height] ? YES' in db['semantics']
    assert '0x0085b598' in db['semantics'] and 'two different pool copies' in db['semantics']
    b = BY['wtl_isbeachforpos_height_']
    for needle in ('1008 - H', '1040 - H', 'octaves:11', '1024 - 16 * noise - H'):
        assert needle in b['semantics'], needle
    cav = BY['wtl_isfloatingislandcavefo']
    for needle in ('|noiseA + 0.5 * noiseB| < 0.2', 'caveNoiseFunctionA@52', 'caveNoiseFunctionB@56', 'byte +12'):
        assert needle in cav['semantics'], needle


def test_fill_and_flow():
    f = BY['wtl_filldirttile_worldpos_']
    for needle in ('{6, 7, 8, 27, 28, 58}', 'tile[0] and tile[1]', 'tile[3] = 1',
                   'customRules byte 15', 'flintDensityNoiseFunction@36',
                   'block 58', 'becomes 27'):
        assert needle in f['semantics'], needle
    w = BY['wtl_recursivelyflowoutwate']
    assert 'byte0 == 2' in w['semantics'] and 'byte4 = 0xff' in w['semantics']
    assert 'self-recursive objc_msgSend at 0x0085c31c' in w['semantics']
    dd = BY['wtl_recursivelyflowoutdirt']
    for needle in ('0x5f5e0ff', 'f1 > 0.7', 'f1 > 0.9', 'lrand48()', 'dead spill'):
        assert needle in dd['semantics'], needle


def test_gems_and_spawn():
    g = BY['wtl_placegemsincaveforphys']
    assert g['verified_words'] == 1556 and len(g['branches']) == 125
    for needle in ('worldY-1', 'expertMode', '0.11 / 0.22', '0x5e, 0x91, 0x90',
                   'byte 0x11', '{0x3a, 0x38, 0x36, 0x34, 0x3c}', 'gemNoiseFunction@60'):
        assert needle in g['semantics'], needle
    assert 'byte0 = 16' in g['semantics']
    s = BY['wtl_findbeststartposition']
    assert s['verified_words'] == 955 and len(s['calls']) == 50 == len(s['branches'])
    for needle in ('[2W,14W] U [18W,30W]', 'ground < 512', '(-10.0f, 40.0f)', '(-5.0f, 25.0f)',
                   'customRules] byte +3 == 2', 'min(256, W/2)', '(-1,-1)'):
        assert needle in s['semantics'], needle
    assert 'baseTemperatureForWorldPos' in s['semantics']


def test_artifact_contract():
    assert DATA['batch'].startswith('Terrain generation batch (E12)')
    assert 'outside these bodies' in DATA['claim']
    assert 'customRules' in DATA['claim'] and 'name tables' in DATA['claim']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['schema'] == 1
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    assert all(BY[n]['disjoint_branch_rows'] == [] for n in NAMES)


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_fractions()
    test_predicates()
    test_fill_and_flow()
    test_gems_and_spawn()
    test_artifact_contract()
    print('terrain generation contract: OK')
