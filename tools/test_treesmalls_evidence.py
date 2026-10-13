#!/usr/bin/env python3
"""Contract test for the fruit-tree smalls sweep (E85)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TREE_SMALLS.md').read_text()
DATA = json.loads((NATIVE / 'tree_smalls.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cf_objecttype', 'cf_fruititem', 'cf_fruitseason', 'cf_getsavedict', 'cf_makedead', 'cf_treetype', 'cf_kindself', 'lt_objecttype', 'lt_fruititem', 'lt_fruitseason', 'lt_getsavedict', 'lt_makedead', 'lt_treetype', 'lt_kindself', 'at_availfood', 'at_setavailfood', 'at_fruititem', 'at_fruitseason', 'at_objecttype', 'at_makedead', 'at_treetype', 'at_kindself', 'ot_objecttype', 'ot_fruititem', 'ot_fruitseason', 'ot_getsavedict', 'ot_makedead', 'ot_treetype', 'ot_kindself', 'cn_objecttype', 'cn_fruititem', 'cn_fruitseason', 'cn_getsavedict', 'cn_makedead', 'cn_kindself', 'cn_treetype', 'cn_soiltype', 'ct_objecttype', 'ct_fruititem', 'ct_fruitseason', 'ct_makedead', 'ct_kindself', 'ct_treetype', 'ct_soiltype', 'ct_availfood', 'ct_setavailfood', 'pt_objecttype', 'pt_fruititem', 'pt_fallen', 'pt_makedead', 'pt_treetype', 'pt_kindself', 'ch_objecttype', 'ch_fruititem', 'ch_fruitseason', 'ch_getsavedict', 'ch_makedead', 'ch_treetype', 'ch_kindself', 'mg_objecttype', 'mg_fruititem', 'mg_fruitseason', 'mg_getsavedict', 'mg_makedead', 'mg_treetype', 'mg_kindself', 'mp_objecttype', 'mp_fruititem', 'mp_fruitseason', 'mp_getsavedict', 'mp_makedead', 'mp_treetype', 'mp_kindself']
IMPS = ['0x007de158', '0x007de174', '0x007de190', '0x007dec20', '0x007e0c24', '0x007e1368', '0x007e1384', '0x00809210', '0x0080922c', '0x00809248', '0x00809d34', '0x0080c3a8', '0x0080c410', '0x0080c42c', '0x009bc8fc', '0x009bc93c', '0x009bca08', '0x009bca24', '0x009bca54', '0x009bf588', '0x009bff14', '0x009bff30', '0x00a95bd8', '0x00a95bf4', '0x00a95c10', '0x00a966fc', '0x00a98d70', '0x00a98dd8', '0x00a98df4', '0x00a98ff0', '0x00a9900c', '0x00a99028', '0x00a99ab4', '0x00a9b268', '0x00a9b2d0', '0x00a9b36c', '0x00a9b388', '0x00b527e4', '0x00b52800', '0x00b5281c', '0x00b5561c', '0x00b55650', '0x00b556a4', '0x00b556c0', '0x00b5575c', '0x00b557a4', '0x00b64378', '0x00b64394', '0x00b643b0', '0x00b66f40', '0x00b67a18', '0x00b67a34', '0x00d0d604', '0x00d0d620', '0x00d0d63c', '0x00d0e024', '0x00d0fd4c', '0x00d1048c', '0x00d104a8', '0x00d4aad0', '0x00d4aaec', '0x00d4ab08', '0x00d4b5ec', '0x00d4da38', '0x00d4daa0', '0x00d4dabc', '0x00db5668', '0x00db5684', '0x00db56a0', '0x00db60ac', '0x00db8010', '0x00db879c', '0x00db87b8']
COUNTS = {'cf_objecttype': (0, 0, 0, 0, 0, 0), 'cf_fruititem': (0, 0, 0, 0, 0, 0), 'cf_fruitseason': (0, 0, 0, 0, 0, 0), 'cf_getsavedict': (1, 1, 1, 0, 1, 0), 'cf_makedead': (0, 0, 0, 0, 0, 5), 'cf_treetype': (0, 0, 0, 0, 0, 0), 'cf_kindself': (0, 0, 0, 0, 0, 4), 'lt_objecttype': (0, 0, 0, 0, 0, 0), 'lt_fruititem': (0, 0, 0, 0, 0, 0), 'lt_fruitseason': (0, 0, 0, 0, 0, 0), 'lt_getsavedict': (1, 1, 1, 0, 1, 0), 'lt_makedead': (0, 0, 0, 0, 0, 5), 'lt_treetype': (0, 0, 0, 0, 0, 0), 'lt_kindself': (0, 0, 0, 0, 0, 4), 'at_availfood': (0, 0, 0, 1, 0, 0), 'at_setavailfood': (2, 0, 0, 3, 2, 0), 'at_fruititem': (0, 0, 0, 0, 0, 0), 'at_fruitseason': (0, 0, 0, 0, 0, 0), 'at_objecttype': (0, 0, 0, 0, 0, 0), 'at_makedead': (0, 0, 0, 0, 0, 5), 'at_treetype': (0, 0, 0, 0, 0, 0), 'at_kindself': (0, 0, 0, 0, 0, 4), 'ot_objecttype': (0, 0, 0, 0, 0, 0), 'ot_fruititem': (0, 0, 0, 0, 0, 0), 'ot_fruitseason': (0, 0, 0, 0, 0, 0), 'ot_getsavedict': (1, 1, 1, 0, 1, 0), 'ot_makedead': (0, 0, 0, 0, 0, 5), 'ot_treetype': (0, 0, 0, 0, 0, 0), 'ot_kindself': (0, 0, 0, 0, 0, 4), 'cn_objecttype': (0, 0, 0, 0, 0, 0), 'cn_fruititem': (0, 0, 0, 0, 0, 0), 'cn_fruitseason': (0, 0, 0, 0, 0, 3), 'cn_getsavedict': (1, 1, 1, 0, 1, 0), 'cn_makedead': (0, 0, 0, 0, 0, 5), 'cn_kindself': (0, 0, 0, 0, 0, 4), 'cn_treetype': (0, 0, 0, 0, 0, 0), 'cn_soiltype': (0, 0, 0, 0, 0, 5), 'ct_objecttype': (0, 0, 0, 0, 0, 0), 'ct_fruititem': (0, 0, 0, 0, 0, 0), 'ct_fruitseason': (0, 0, 0, 0, 0, 0), 'ct_makedead': (0, 0, 0, 0, 0, 1), 'ct_kindself': (0, 0, 0, 0, 0, 1), 'ct_treetype': (0, 0, 0, 0, 0, 0), 'ct_soiltype': (0, 0, 0, 0, 0, 5), 'ct_availfood': (0, 0, 0, 2, 0, 0), 'ct_setavailfood': (0, 0, 0, 1, 0, 0), 'pt_objecttype': (0, 0, 0, 0, 0, 0), 'pt_fruititem': (0, 0, 0, 0, 0, 0), 'pt_fallen': (0, 0, 0, 0, 0, 0), 'pt_makedead': (0, 0, 0, 0, 0, 5), 'pt_treetype': (0, 0, 0, 0, 0, 0), 'pt_kindself': (0, 0, 0, 0, 0, 4), 'ch_objecttype': (0, 0, 0, 0, 0, 0), 'ch_fruititem': (0, 0, 0, 0, 0, 0), 'ch_fruitseason': (0, 0, 0, 0, 0, 0), 'ch_getsavedict': (1, 1, 1, 0, 1, 0), 'ch_makedead': (0, 0, 0, 0, 0, 5), 'ch_treetype': (0, 0, 0, 0, 0, 0), 'ch_kindself': (0, 0, 0, 0, 0, 4), 'mg_objecttype': (0, 0, 0, 0, 0, 0), 'mg_fruititem': (0, 0, 0, 0, 0, 0), 'mg_fruitseason': (0, 0, 0, 0, 0, 0), 'mg_getsavedict': (1, 1, 1, 0, 1, 0), 'mg_makedead': (0, 0, 0, 0, 0, 5), 'mg_treetype': (0, 0, 0, 0, 0, 0), 'mg_kindself': (0, 0, 0, 0, 0, 4), 'mp_objecttype': (0, 0, 0, 0, 0, 0), 'mp_fruititem': (0, 0, 0, 0, 0, 0), 'mp_fruitseason': (0, 0, 0, 0, 0, 0), 'mp_getsavedict': (1, 1, 1, 0, 1, 0), 'mp_makedead': (0, 0, 0, 0, 0, 5), 'mp_treetype': (0, 0, 0, 0, 0, 0), 'mp_kindself': (0, 0, 0, 0, 0, 4)}
WORDS = [14, 7, 12, 32, 26, 7, 39, 14, 7, 12, 31, 26, 7, 39, 16, 51, 7, 12, 7, 26, 7, 39, 14, 7, 12, 31, 26, 7, 39, 14, 7, 30, 31, 26, 39, 7, 39, 14, 7, 13, 13, 21, 7, 39, 37, 19, 22, 15, 8, 26, 7, 39, 14, 7, 13, 31, 26, 7, 39, 14, 7, 12, 31, 26, 7, 39, 14, 7, 12, 31, 26, 7, 39]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 1463
    for needle in ('1463', '0x15', '0x1b/0x1c', 'dmb ish', '0x3a', 'treeType'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_pins():
    s = BY['at_fruititem']['semantics']
    assert '0x15' in s
    s = BY['at_makedead']['semantics']
    assert '0x1b' in s and '0x1c' in s
    s = BY['ct_availfood']['semantics']
    assert 'dmb ish' in s
    s = BY['cn_soiltype']['semantics']
    assert '0x30' in s
    s = BY['pt_fallen']['semantics']
    assert 'returns **0**' in s


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_pins()
    print('test_treesmalls_evidence: OK')
