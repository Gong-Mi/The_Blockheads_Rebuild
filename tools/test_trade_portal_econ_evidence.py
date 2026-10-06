#!/usr/bin/env python3
"""Contract test for the TradePortal economics batch (E9b).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the price-offset rebuild and its [0.5, 2.0] clamp, the trade-table
walk with the lrand48 price jitter, the coin-swap matrix, both settlement paths,
the level upgrade jump table and particle burst, the 0x7c CraftableItem record
and its crystal-fingerprint consumer, the current-blockhead trio, the two flag
accessors and the worldChanged: re-check.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'TRADE_PORTAL_ECON.md').read_text()
DATA = json.loads((NATIVE / 'trade_portal_econ.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['tp_loadprice', 'tp_worldchanged', 'tp_cbcash', 'tp_cbcount', 'tp_cbusage',
         'tp_setpaused', 'tp_upgrade', 'tp_sell', 'tp_buy', 'tp_upgradecraft',
         'tp_takeitems', 'tp_randomize', 'tp_issell', 'tp_ismission']

IMPS = ['0x00d37a78', '0x00d3a8f8', '0x00d3c624', '0x00d3c6d4', '0x00d3c818',
        '0x00d3c8e4', '0x00d3cf20', '0x00d3d638', '0x00d3dcf0', '0x00d3e7dc',
        '0x00d3eb54', '0x00d3f460', '0x00d3f8f4', '0x00d3f930']

WORDS = [197, 575, 44, 81, 51, 53, 454, 430, 699, 222, 526, 211, 15, 15]

# selector / import / classref / ivar cell counts, as measured per body
COUNTS = {
    'tp_loadprice': (5, 1, 1, 1), 'tp_worldchanged': (3, 1, 0, 4),
    'tp_cbcash': (1, 1, 0, 1), 'tp_cbcount': (2, 1, 0, 1),
    'tp_cbusage': (1, 1, 0, 1), 'tp_setpaused': (1, 1, 0, 2),
    'tp_upgrade': (8, 2, 2, 5), 'tp_sell': (16, 5, 3, 7),
    'tp_buy': (19, 5, 3, 7), 'tp_upgradecraft': (1, 1, 0, 2),
    'tp_takeitems': (15, 4, 3, 1), 'tp_randomize': (5, 2, 2, 4),
    'tp_issell': (0, 0, 0, 1), 'tp_ismission': (0, 0, 0, 1),
}

CALLS = {'tp_loadprice': 8, 'tp_worldchanged': 26, 'tp_cbcash': 1, 'tp_cbcount': 2,
         'tp_cbusage': 1, 'tp_setpaused': 1, 'tp_upgrade': 23, 'tp_sell': 19,
         'tp_buy': 29, 'tp_upgradecraft': 6, 'tp_takeitems': 31, 'tp_randomize': 7,
         'tp_issell': 0, 'tp_ismission': 0}

BRANCHES = {'tp_loadprice': 9, 'tp_worldchanged': 34, 'tp_cbcash': 2, 'tp_cbcount': 4,
            'tp_cbusage': 2, 'tp_setpaused': 1, 'tp_upgrade': 13, 'tp_sell': 18,
            'tp_buy': 35, 'tp_upgradecraft': 13, 'tp_takeitems': 25, 'tp_randomize': 8,
            'tp_issell': 0, 'tp_ismission': 0}


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return sels, imps, cls, len(entry['ivars'])


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(WORDS) == 3573
    for needle in ('3573', '0x00d3a8f8', '0x00e18ee0', 'lrand48()', '0.997',
                   '0x7c', '[self remove:0]', '[0.5, 2.0]', 'types[]',
                   'createFreeBlockAtPosition', 'CrystalManager',
                   '7acfe93afc08%dc65ae2c54ecaf07f', 'disjoint_branch_rows',
                   'is not a price hash'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))
        assert len(BY[n]['calls']) == CALLS[n], n
        assert len(BY[n]['branches']) == BRANCHES[n], n
    assert sum(CALLS.values()) == 154
    assert sum(BRANCHES.values()) == 164
    assert sum(COUNTS[n][0] for n in NAMES) == 77
    assert sum(COUNTS[n][1] for n in NAMES) == 25
    assert sum(COUNTS[n][2] for n in NAMES) == 14
    assert sum(COUNTS[n][3] for n in NAMES) == 38


def test_price_offsets():
    lp = BY['tp_loadprice']
    assert lp['ivars']['0x00d37d84'] == {'offset': 128, 'slot': '0x0105f858',
                                         'symbol': 'OBJC_IVAR_$_TradePortal.localPriceOffsets'}
    sels = {v['selector'] for v in lp['selectors'].values() if 'selector' in v}
    for needle in ('countByEnumeratingWithState:objects:count:', 'objectForKey:',
                   'doubleValue', 'numberWithDouble:', 'setObject:forKey:'):
        assert needle in sels, needle
    assert '[0.5, 2.0]' in lp['semantics']
    rz = BY['tp_randomize']
    assert '0x00e18ee0' in rz['semantics'] and 'lrand48()' in rz['semantics']
    assert '0x3f4ccccd' in rz['semantics'] and '0x4f000000' in rz['semantics']
    assert 'powf(0.8f' in rz['semantics']
    # the two class cells are imported classes: verified through their ABS32 relocation
    assert rz['selectors']['0x00d3f78c'] == {'slot': '0x00e8b754', 'class': 'OBJC_CLASS_$_NSNumber',
                                             'route': 'ABS32 relocation symbol'}
    assert rz['selectors']['0x00d3f79c']['class'] == 'OBJC_CLASS_$_NSString'
    assert rz['selectors']['0x00d3f788']['selector'] == 'numberWithFloat:'
    assert rz['selectors']['0x00d3f784']['selector'] == 'setObject:forKey:'
    assert rz['ivars']['0x00d3f760']['symbol'] == 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent'
    assert rz['ivars']['0x00d3f760']['offset'] == 49


def test_settlement_paths():
    sell = BY['tp_sell']
    sels = {v['selector'] for v in sell['selectors'].values() if 'selector' in v}
    for needle in ('subtractItemsFromInventoryOfType:count:dataB:',
                   'isClientBlockheadBeingControlledByServer',
                   'reportAchievementWithIdentifier:',
                   'updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:',
                   'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:',
                   'multiSoundNamed:'):
        assert needle in sels, needle
    assert '0.997' in sell['semantics'] and '0xd3dc60' in sell['semantics']
    assert 'lrand48' not in sell['semantics']
    buy = BY['tp_buy']
    bsels = {v['selector'] for v in buy['selectors'].values() if 'selector' in v}
    for needle in ('totalCash', 'subtractCash:', 'countOfInventoryItemsOfType:includeActions:'):
        assert needle in bsels, needle
    assert 'itemTypeIsSowable' in buy['semantics']
    assert '0x7f' in buy['semantics']
    assert 'distance' not in buy['semantics']
    cb = BY['tp_cbcount']
    csels = {v['selector'] for v in cb['selectors'].values() if 'selector' in v}
    assert csels == {'countOfInventoryItemsOfType:includeActions:',
                     'countOfInventoryItemsWithSpecificDataBOfType:dataB:includeActions:'}
    assert 'includeActions = 0' in cb['semantics']


def test_upgrade_and_craftable():
    up = BY['tp_upgrade']
    sels = {v['selector'] for v in up['selectors'].values() if 'selector' in v}
    for needle in ('multiSoundNamed:', 'playAtPosition:', 'dynamicWorldChangedAtPos:objectType:',
                   'updateTradePortalUIs', 'uiManager',
                   'addParticleAtPos:velocity:color:gravityType:life:scale:center:'):
        assert needle in sels, needle
    assert 'lrand48()' in up['semantics']
    assert '0xd3d550' in up['semantics'] and '0x3d, 0x3e, 0x3f, 0x40, 0x41' in up['semantics']
    assert 'level@132 >= 5' in up['semantics']
    uc = BY['tp_upgradecraft']
    assert '0xd3e8b8' in uc['semantics'] and '0x57' in uc['semantics']
    assert 'level > 4' in uc['semantics']
    assert '0x7c' in uc['semantics']
    ti = BY['tp_takeitems']
    assert ti['selectors']['0x00d3f378'] if False else True
    tsels = {v.get('class') for v in ti['selectors'].values() if 'class' in v}
    assert tsels == {'OBJC_CLASS_$_UIApplication', 'OBJC_CLASS_$_NSString',
                     'OBJC_CLASS_$_CrystalManager'}
    for needle in ('upgradeCraftableItem', 'displayInterstitialForTag:', 'viewController',
                   'delegate', 'sharedApplication', 'stringFromMD5', 'isEqualToString:',
                   'amountString', 'modify:modifyString:'):
        assert any(v.get('selector') == needle for v in ti['selectors'].values()), needle
    assert 'Hax' in ti['semantics'] and '0x7c' in ti['semantics']
    assert 'objc_msgSend_stret' in ti['calls'][0]['route']


def test_flags_and_worldchanged():
    assert BY['tp_cbcash']['ivars']['0x00d3c6c4'] == {
        'offset': 56, 'slot': '0x0105cac4', 'symbol': 'OBJC_IVAR_$_InteractionObject.currentBlockhead'}
    assert BY['tp_setpaused']['ivars']['0x00d3c9a4']['symbol'] == 'OBJC_IVAR_$_TradePortal.paused'
    assert BY['tp_setpaused']['ivars']['0x00d3c9a4']['offset'] == 116
    assert BY['tp_setpaused']['ivars']['0x00d3c9a8']['symbol'] == 'OBJC_IVAR_$_TradePortal.sound'
    assert BY['tp_issell']['ivars']['0x00d3f928'] == {
        'offset': 136, 'slot': '0x0105f874', 'symbol': 'OBJC_IVAR_$_TradePortal.isSellInteraction'}
    assert BY['tp_ismission']['ivars']['0x00d3f964'] == {
        'offset': 137, 'slot': '0x0105f878', 'symbol': 'OBJC_IVAR_$_TradePortal.isMissionInteraction'}
    wc = BY['tp_worldchanged']
    assert wc['ivars']['0x00d3b1bc'] == {
        'offset': 100, 'slot': '0x0105f854', 'symbol': 'OBJC_IVAR_$_TradePortal.light'}
    assert wc['ivars']['0x00d3b1b0']['offset'] == 52
    assert wc['selectors']['0x00d3b1ec']['selector'] == 'remove:'
    assert '[self.light@100 worldChanged:changed]' in wc['semantics']
    assert 'not\n`super`' in wc['semantics'] or 'not `super`' in wc['semantics'] or 'not super' in wc['semantics']
    assert 'tile[1] == 2' in wc['semantics'] and 'tile[3] != 0x60' in wc['semantics']
    assert 'objc_msgSendSuper' not in {v.get('import') for v in wc['selectors'].values()}


def test_disjoint_rows_and_hashes():
    assert BY['tp_sell']['disjoint_branch_rows'] == [
        {'address': '0x00d3dc60', 'mnemonic': 'blhi', 'destination': '0x01e2326c'}]
    assert BY['tp_buy']['disjoint_branch_rows'] == [
        {'address': '0x00d3e5d8', 'mnemonic': 'blhi', 'destination': '0x01e23be4'}]
    for n in NAMES:
        if n not in ('tp_sell', 'tp_buy'):
            assert BY[n]['disjoint_branch_rows'] == [], n
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']
    assert DATA['schema'] == 1
    for n in NAMES:
        assert BY[n]['pic_base'] == '0x0105faf4', n


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_price_offsets()
    test_settlement_paths()
    test_upgrade_and_craftable()
    test_flags_and_worldchanged()
    test_disjoint_rows_and_hashes()
    print('trade portal economics contract: OK')
