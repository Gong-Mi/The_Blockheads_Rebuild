#!/usr/bin/env python3
"""Contract test for the crop smalls sweep (E91)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CROP_SMALLS.md').read_text()
DATA = json.loads((NATIVE / 'crop_smalls.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cl_objecttype', 'cl_emitslight', 'cl_lightfactor', 'cl_lightcolor', 'cl_maxagebase', 'cl_seeditem', 'cl_mintemp', 'cl_floweringseason', 'cl_candie', 'cl_planttype', 'cl_soiltype', 'cl_renderimage', 'wh_objecttype', 'wh_maxagebase', 'wh_seeditem', 'wh_mintemp', 'wh_floweringseason', 'wh_candie', 'wh_planttype', 'wh_soiltype', 'wh_renderimage', 'wh_npcspawn', 'tm_objecttype', 'tm_maxagebase', 'tm_seeditem', 'tm_mintemp', 'tm_floweringseason', 'tm_candie', 'tm_planttype', 'tm_soiltype', 'tm_renderimage', 'cr_objecttype', 'cr_maxagebase', 'cr_seeditem', 'cr_foodremove', 'cr_mintemp', 'cr_floweringseason', 'cr_candie', 'cr_planttype', 'cr_soiltype', 'cr_renderimage', 'cr_npcspawn', 'fx_objecttype', 'fx_maxagebase', 'fx_seeditem', 'fx_folliageitem', 'fx_mintemp', 'fx_floweringseason', 'fx_candie', 'fx_planttype', 'fx_soiltype', 'fx_renderimage', 'sf_objecttype', 'sf_emitslight', 'sf_lightfactor', 'sf_lightcolor', 'sf_maxagebase', 'sf_seeditem', 'sf_mintemp', 'sf_floweringseason', 'sf_candie', 'sf_planttype', 'sf_soiltype', 'sf_renderimage', 'co_objecttype', 'co_maxagebase', 'co_seeditem', 'co_mintemp', 'co_floweringseason', 'co_candie', 'co_planttype', 'co_soiltype', 'co_renderimage']
IMPS = ['0x006b9ec0', '0x006b9edc', '0x006b9ef8', '0x006b9fb4', '0x006ba168', '0x006ba198', '0x006ba1b4', '0x006ba1d0', '0x006ba21c', '0x006ba24c', '0x006ba268', '0x006ba2dc', '0x006d13d4', '0x006d13f0', '0x006d1420', '0x006d143c', '0x006d1458', '0x006d14a4', '0x006d14d4', '0x006d14f0', '0x006d158c', '0x006d15e8', '0x006ffba0', '0x006ffbbc', '0x006ffbec', '0x006ffc08', '0x006ffc24', '0x006ffc70', '0x006ffca0', '0x006ffcbc', '0x006ffd30', '0x007418e0', '0x007418fc', '0x0074192c', '0x00741948', '0x00741978', '0x00741994', '0x007419e0', '0x00741a10', '0x00741a2c', '0x00741ac8', '0x00741b24', '0x00770ca8', '0x00770cc4', '0x00770cf4', '0x00770d10', '0x00770d2c', '0x00770d48', '0x00770d94', '0x00770db4', '0x00770dd0', '0x00770ea8', '0x009bc33c', '0x009bc358', '0x009bc394', '0x009bc450', '0x009bc5a4', '0x009bc5d4', '0x009bc5f0', '0x009bc60c', '0x009bc658', '0x009bc688', '0x009bc6a4', '0x009bc740', '0x00b501e0', '0x00b501fc', '0x00b5022c', '0x00b50248', '0x00b50264', '0x00b502b0', '0x00b502e0', '0x00b502fc', '0x00b50398']
COUNTS = {'cl_objecttype': (0, 0, 0, 0, 0, 0), 'cl_emitslight': (0, 0, 0, 0, 0, 0), 'cl_lightfactor': (1, 0, 0, 2, 1, 0), 'cl_lightcolor': (1, 1, 0, 0, 2, 4), 'cl_maxagebase': (0, 0, 0, 0, 0, 0), 'cl_seeditem': (0, 0, 0, 0, 0, 0), 'cl_mintemp': (0, 0, 0, 0, 0, 0), 'cl_floweringseason': (0, 0, 0, 0, 0, 1), 'cl_candie': (0, 0, 0, 0, 0, 0), 'cl_planttype': (0, 0, 0, 0, 0, 0), 'cl_soiltype': (0, 0, 0, 0, 0, 3), 'cl_renderimage': (0, 0, 0, 1, 0, 2), 'wh_objecttype': (0, 0, 0, 0, 0, 0), 'wh_maxagebase': (0, 0, 0, 0, 0, 0), 'wh_seeditem': (0, 0, 0, 0, 0, 0), 'wh_mintemp': (0, 0, 0, 0, 0, 0), 'wh_floweringseason': (0, 0, 0, 0, 0, 1), 'wh_candie': (0, 0, 0, 0, 0, 0), 'wh_planttype': (0, 0, 0, 0, 0, 0), 'wh_soiltype': (0, 0, 0, 0, 0, 5), 'wh_renderimage': (0, 0, 0, 1, 0, 2), 'wh_npcspawn': (0, 0, 0, 0, 0, 0), 'tm_objecttype': (0, 0, 0, 0, 0, 0), 'tm_maxagebase': (0, 0, 0, 0, 0, 0), 'tm_seeditem': (0, 0, 0, 0, 0, 0), 'tm_mintemp': (0, 0, 0, 0, 0, 0), 'tm_floweringseason': (0, 0, 0, 0, 0, 1), 'tm_candie': (0, 0, 0, 0, 0, 0), 'tm_planttype': (0, 0, 0, 0, 0, 0), 'tm_soiltype': (0, 0, 0, 0, 0, 3), 'tm_renderimage': (0, 0, 0, 1, 0, 2), 'cr_objecttype': (0, 0, 0, 0, 0, 0), 'cr_maxagebase': (0, 0, 0, 0, 0, 0), 'cr_seeditem': (0, 0, 0, 0, 0, 0), 'cr_foodremove': (0, 0, 0, 0, 0, 0), 'cr_mintemp': (0, 0, 0, 0, 0, 0), 'cr_floweringseason': (0, 0, 0, 0, 0, 1), 'cr_candie': (0, 0, 0, 0, 0, 0), 'cr_planttype': (0, 0, 0, 0, 0, 0), 'cr_soiltype': (0, 0, 0, 0, 0, 5), 'cr_renderimage': (0, 0, 0, 1, 0, 2), 'cr_npcspawn': (0, 0, 0, 0, 0, 0), 'fx_objecttype': (0, 0, 0, 0, 0, 0), 'fx_maxagebase': (0, 0, 0, 0, 0, 0), 'fx_seeditem': (0, 0, 0, 0, 0, 0), 'fx_folliageitem': (0, 0, 0, 0, 0, 0), 'fx_mintemp': (0, 0, 0, 0, 0, 0), 'fx_floweringseason': (0, 0, 0, 0, 0, 1), 'fx_candie': (0, 0, 0, 0, 0, 0), 'fx_planttype': (0, 0, 0, 0, 0, 0), 'fx_soiltype': (0, 0, 0, 0, 0, 8), 'fx_renderimage': (0, 0, 0, 1, 0, 2), 'sf_objecttype': (0, 0, 0, 1, 0, 0), 'sf_emitslight': (0, 0, 0, 1, 0, 0), 'sf_lightfactor': (1, 0, 0, 2, 1, 0), 'sf_lightcolor': (1, 1, 0, 0, 2, 2), 'sf_maxagebase': (0, 0, 0, 0, 0, 0), 'sf_seeditem': (0, 0, 0, 0, 0, 0), 'sf_mintemp': (0, 0, 0, 0, 0, 0), 'sf_floweringseason': (0, 0, 0, 0, 0, 1), 'sf_candie': (0, 0, 0, 0, 0, 0), 'sf_planttype': (0, 0, 0, 0, 0, 0), 'sf_soiltype': (0, 0, 0, 0, 0, 5), 'sf_renderimage': (0, 0, 0, 1, 0, 2), 'co_objecttype': (0, 0, 0, 0, 0, 0), 'co_maxagebase': (0, 0, 0, 0, 0, 0), 'co_seeditem': (0, 0, 0, 0, 0, 0), 'co_mintemp': (0, 0, 0, 0, 0, 0), 'co_floweringseason': (0, 0, 0, 0, 0, 1), 'co_candie': (0, 0, 0, 0, 0, 0), 'co_planttype': (0, 0, 0, 0, 0, 0), 'co_soiltype': (0, 0, 0, 0, 0, 5), 'co_renderimage': (0, 0, 0, 1, 0, 2)}
WORDS = [14, 7, 47, 109, 12, 14, 7, 19, 12, 7, 29, 23, 7, 12, 14, 7, 19, 12, 7, 39, 23, 7, 7, 12, 14, 7, 19, 12, 7, 29, 23, 7, 12, 7, 12, 7, 19, 12, 7, 39, 23, 7, 7, 12, 21, 14, 7, 19, 8, 7, 54, 23, 22, 15, 47, 85, 12, 14, 7, 19, 12, 7, 39, 23, 7, 12, 14, 7, 19, 12, 7, 39, 23]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1343
    for needle in ('1343', '0x1c20', '0x3840', '0x708', '0x13c', 'seed/item'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_table():
    s = BY['cr_objecttype']['semantics']
    assert '0x1b' in s
    s = BY['fx_maxagebase']['semantics']
    assert '0x3840' in s
    s = BY['tm_seeditem']['semantics']
    assert '0x13c' in s
    s = BY['cl_lightcolor']['semantics']
    assert '0xff/0x4b' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_table()
    print('test_cropsmalls_evidence: OK')
