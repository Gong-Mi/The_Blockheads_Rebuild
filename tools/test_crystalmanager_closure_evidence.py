#!/usr/bin/env python3
"""Contract test for the CrystalManager closure batch (E10).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the lazy singleton, the ivar family the trade portal fingerprints
(crystalCount@8 / amountString@12 / countWatcher@16 / needsSave@20), the flag
pair, the atomic accessor pair, modify:modifyString:, and the iCloud identity
pair whose rejoin id is the MD5 of the iCloud id plus the literal "rejoin".
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'CRYSTALMANAGER_CLOSURE.md').read_text()
DATA = json.loads((NATIVE / 'crystalmanager_closure.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['cm_instance', 'cm_init', 'cm_amount', 'cm_commitsaveifneeded', 'cm_save',
         'cm_modify_modifystring_', 'cm_icloudid', 'cm_icloudserverrejoinid',
         'cm_countwatcher', 'cm_setcountwatcher_', 'cm_needssave', 'cm_amountstring']

IMPS = ['0x009f3b14', '0x009f3bdc', '0x009f452c', '0x009f4568', '0x009f4f34', '0x009f4f74',
        '0x009f526c', '0x009f5e78', '0x009f5f24', '0x009f5f68', '0x009f5fac', '0x009f5fe8']

WORDS = [50, 90, 15, 68, 16, 190, 767, 43, 17, 17, 15, 17]

# selector / import / classref / ivar / calls / branches, measured per body
COUNTS = {
    'cm_instance': (2, 1, 1, 0, 2, 1), 'cm_init': (3, 2, 2, 1, 4, 2),
    'cm_amount': (0, 0, 0, 1, 0, 0), 'cm_commitsaveifneeded': (1, 2, 0, 2, 1, 1),
    'cm_save': (0, 0, 0, 1, 0, 0), 'cm_modify_modifystring_': (6, 3, 1, 3, 8, 1),
    'cm_icloudid': (24, 15, 8, 0, 46, 27), 'cm_icloudserverrejoinid': (3, 2, 0, 0, 3, 0),
    'cm_countwatcher': (0, 0, 0, 1, 0, 0), 'cm_setcountwatcher_': (0, 0, 0, 1, 0, 0),
    'cm_needssave': (0, 0, 0, 1, 0, 0), 'cm_amountstring': (0, 0, 0, 1, 0, 0),
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
    assert sum(WORDS) == 1305
    for needle in ('1305', 'crystalCount', 'amountString', 'countWatcher', 'needsSave',
                   'rejoin', 'singleton', 'dmb ish', 'modify:modifyString:'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))
    assert sum(COUNTS[n][4] for n in NAMES) == 64
    assert sum(COUNTS[n][5] for n in NAMES) == 32
    assert sum(COUNTS[n][3] for n in NAMES) == 12


def test_ivar_family():
    # the ivars the trade portal fingerprints, all confirmed through their own cells
    assert BY['cm_amount']['ivars']['0x009f4560'] == {
        'offset': 8, 'slot': '0x0105e760', 'symbol': 'OBJC_IVAR_$_CrystalManager.crystalCount'}
    assert BY['cm_amountstring']['ivars']['0x009f6024'] == {
        'offset': 12, 'slot': '0x0105e75c', 'symbol': 'OBJC_IVAR_$_CrystalManager.amountString'}
    for n, cell in (('cm_save', '0x009f4f6c'), ('cm_needssave', '0x009f5fe0')):
        assert BY[n]['ivars'][cell]['symbol'] == 'OBJC_IVAR_$_CrystalManager.needsSave', n
        assert BY[n]['ivars'][cell]['offset'] == 20, n
    for n, cell in (('cm_countwatcher', '0x009f5f60'), ('cm_setcountwatcher_', '0x009f5fa4')):
        assert BY[n]['ivars'][cell]['symbol'] == 'OBJC_IVAR_$_CrystalManager.countWatcher', n
        assert BY[n]['ivars'][cell]['offset'] == 16, n


def test_singleton_and_flags():
    inst = BY['cm_instance']
    assert inst['selectors']['0x009f3bd0']['selector'] == 'alloc'
    assert inst['selectors']['0x009f3bcc']['selector'] == 'init'
    assert inst['selectors']['0x009f3bd4']['class'] == 'OBJC_CLASS_$_CrystalManager'
    assert 'singleton' in inst['semantics']
    assert '0x01064984' in inst['semantics']
    assert 'needsSave@20 to 1' in BY['cm_save']['semantics']
    assert 'ldrsb' in BY['cm_needssave']['semantics']
    assert 'dmb ish' in BY['cm_countwatcher']['semantics']
    assert 'dmb ish' in BY['cm_setcountwatcher_']['semantics']
    assert 'dmb ish' in BY['cm_amountstring']['semantics']


def test_icloud_pair():
    rj = BY['cm_icloudserverrejoinid']
    assert rj['selectors']['0x009f5f1c']['selector'] == 'iCloudID'
    assert rj['selectors']['0x009f5f18']['selector'] == 'stringByAppendingString:'
    assert rj['selectors']['0x009f5f10']['selector'] == 'stringFromMD5'
    assert rj['selectors']['0x009f5f14']['import'] == '__CFConstantStringClassReference'
    for needle in ('rejoin', 'stringFromMD5', 'iCloudID', '0x00f5be3d'):
        assert needle in rj['semantics'], needle
    ic = BY['cm_icloudid']
    assert ic['verified_words'] == 767
    assert len(ic['selectors']) == 47


def test_boundaries_and_hashes():
    assert '2236 bytes of non-method code' in BY['cm_commitsaveifneeded']['boundary']
    assert 'trimmed at the next IMP 0x009f5f68' in BY['cm_countwatcher']['boundary']
    assert '364 bytes of non-method code' in BY['cm_amountstring']['boundary']
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    assert all(BY[n]['disjoint_branch_rows'] == [] for n in NAMES)
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']
    assert DATA['schema'] == 1


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_ivar_family()
    test_singleton_and_flags()
    test_icloud_pair()
    test_boundaries_and_hashes()
    print('crystal manager closure contract: OK')
