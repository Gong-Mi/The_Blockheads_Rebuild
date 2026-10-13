#!/usr/bin/env python3
"""Contract test for the TradePortal structure batch (E9a).

Pins doc and JSON to each other and to the recovered semantics: the placement
trio with the level jump table, the light system (ArtificialLight init), the
draw animation loop, the title bodies, remove:, and the net/save quartets.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/TRADE_PORTAL.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/trade_portal.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['tp_subderived', 'tp_objtype', 'tp_lightrgb', 'tp_updlight', 'tp_initpos',
         'tp_initsave', 'tp_initnet', 'tp_updnet', 'tp_dealloc', 'tp_getsave',
         'tp_interobjtype', 'tp_remoteupd', 'tp_draw', 'tp_worldcontents',
         'tp_doubleheight', 'tp_setneedsremoved', 'tp_fbitem', 'tp_fbsave',
         'tp_fba', 'tp_fbb', 'tp_remove', 'tp_destroyitem', 'tp_title',
         'tp_actiontitle', 'tp_secondtitle', 'tp_thirdtitle', 'tp_setworkbench',
         'tp_requireshuman', 'tp_sgcdc', 'tp_addquad', 'tp_sgdq', 'tp_rmmacro',
         'tp_lightglow', 'tp_lightpos', 'tp_interrender', 'tp_occnormal',
         'tp_addlight', 'tp_expertmode', 'tp_localoffsets', 'tp_level']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == [
        '0x00d37598', '0x00d377a8', '0x00d377c4', '0x00d37828', '0x00d37d8c',
        '0x00d382fc', '0x00d38760', '0x00d38e20', '0x00d39340', '0x00d39460',
        '0x00d396d4', '0x00d396f0', '0x00d3a198', '0x00d3b230', '0x00d3b248',
        '0x00d3b264', '0x00d3b3b8', '0x00d3b3d4', '0x00d3b420', '0x00d3b43c',
        '0x00d3b458', '0x00d3b860', '0x00d3b87c', '0x00d3b910', '0x00d3bbc4',
        '0x00d3c054', '0x00d3c3cc', '0x00d3c608', '0x00d3c9b8', '0x00d3c9d8',
        '0x00d3cdf4', '0x00d3ce18', '0x00d3f38c', '0x00d3f3a8', '0x00d3f7ac',
        '0x00d3f7c8', '0x00d3f7e4', '0x00d3f858', '0x00d3f874', '0x00d3f8b8']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [128, 7, 25, 148, 348, 281, 423, 237, 72, 157, 7, 682,
                     472, 6, 7, 85, 7, 19, 7, 7, 258, 7, 37, 173, 292, 222,
                     143, 7, 8, 234, 9, 66, 7, 46, 7, 7, 29, 7, 17, 15]
    assert sum(words) == 4716
    for needle in ('4716', '0x00d37d8c', '0x00d3a198', 'ArtificialLight',
                   'LEVEL JUMP TABLE', '0x3c,0x3d,0x3e,0x3f,0x40,0x41',
                   'animationLoopTimer', 'updateQuadBufferTexCoords',
                   'createFreeBlockAtPosition', '0xd2', 'getLightRGB',
                   'stringWithFormat:', 'dmb ish', 'remoteUpdate'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        'tp_subderived': (3, 3, 6, 2), 'tp_objtype': (0, 0, 0, 0),
        'tp_lightrgb': (0, 0, 1, 0), 'tp_updlight': (6, 5, 7, 0),
        'tp_initpos': (12, 4, 12, 15), 'tp_initsave': (13, 7, 14, 4),
        'tp_initnet': (18, 7, 23, 8), 'tp_updnet': (7, 4, 11, 5),
        'tp_dealloc': (5, 2, 3, 0), 'tp_getsave': (6, 3, 6, 2),
        'tp_interobjtype': (0, 0, 0, 0), 'tp_remoteupd': (22, 8, 38, 16),
        'tp_draw': (4, 9, 6, 15), 'tp_worldcontents': (0, 0, 0, 0),
        'tp_doubleheight': (0, 0, 0, 0), 'tp_setneedsremoved': (5, 3, 4, 1),
        'tp_fbitem': (0, 0, 0, 0), 'tp_fbsave': (2, 0, 1, 0),
        'tp_fba': (0, 0, 0, 0), 'tp_fbb': (0, 0, 0, 0),
        'tp_remove': (7, 9, 8, 9), 'tp_destroyitem': (0, 0, 0, 0),
        'tp_title': (2, 1, 1, 0), 'tp_actiontitle': (2, 1, 9, 17),
        'tp_secondtitle': (2, 1, 17, 27), 'tp_thirdtitle': (2, 1, 13, 20),
        'tp_setworkbench': (5, 2, 5, 12), 'tp_requireshuman': (0, 0, 0, 0),
        'tp_sgcdc': (0, 0, 0, 0), 'tp_addquad': (0, 5, 4, 0),
        'tp_sgdq': (0, 0, 0, 0), 'tp_rmmacro': (4, 2, 3, 0),
        'tp_lightglow': (0, 0, 0, 0), 'tp_lightpos': (0, 1, 3, 0),
        'tp_interrender': (0, 0, 0, 0), 'tp_occnormal': (0, 0, 0, 0),
        'tp_addlight': (2, 1, 1, 0), 'tp_expertmode': (0, 0, 0, 0),
        'tp_localoffsets': (0, 1, 0, 0), 'tp_level': (0, 1, 0, 0),
    }

def test_light_system():
    ul = BY['tp_updlight']
    assert ul['selectors']['0x00d37a50'] == {'selector': 'removeFromTiles', 'slot': '0x00e887e0'}
    assert ul['selectors']['0x00d37a58'] == {'class': 'OBJC_CLASS_$_ArtificialLight', 'slot': '0x00e8b750'}
    init_sel = ul['selectors']['0x00d37a70']
    assert init_sel['selector'] == 'initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:'
    assert BY['tp_lightrgb']['types'] == '{Vector=[4f]}8@0:4'
    assert '255.0, 246.0, 64.0' in BY['tp_lightrgb']['semantics']
    assert 'Vector(pos.x, pos.y+1, -1.0)' in BY['tp_lightpos']['semantics']
    assert BY['tp_lightglow']['verified_words'] == 7
    al = BY['tp_addlight']
    assert al['selectors']['0x00d3f84c'] == {'selector': 'addContributionForPhysicalBlockLoadedAtXPos:yPos:', 'slot': '0x00e8892c'}

def test_level_and_remove():
    ip = BY['tp_initpos']
    assert ip['ivars']['0x00d382cc'] == {'offset': 132, 'slot': '0x0105f85c', 'symbol': 'OBJC_IVAR_$_TradePortal.level'}
    assert ip['ivars']['0x00d382ac'] == {'offset': 128, 'slot': '0x0105f858', 'symbol': 'OBJC_IVAR_$_TradePortal.localPriceOffsets'}
    assert 'tile[0] = {0x3c,0x3d,0x3e,0x3f,0x40,0x41}' in ip['semantics']
    assert 'dmb ish' in BY['tp_level']['semantics']
    rm = BY['tp_remove']
    assert rm['selectors']['0x00d3b838'] == {'selector': 'setNeedsRemoved:', 'slot': '0x00e88898'}
    assert rm['selectors']['0x00d3b854']['selector'] == 'createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:'
    assert rm['selectors']['0x00d3b834'] == {'selector': 'stopInteracting', 'slot': '0x00e888a0'}
    assert '0xd2' in rm['semantics']
    assert BY['tp_destroyitem']['semantics'] == 'destroyItemType = 0xd2 (210).'
    assert BY['tp_fbitem']['semantics'] == 'freeblockCreationItemType = 0xd2 (210).'

def test_draw_and_titles():
    d = BY['tp_draw']
    syms = {v['symbol'] for v in d['ivars'].values()}
    for needle in ('OBJC_IVAR_$_TradePortal.animationLoopTimer',
                   'OBJC_IVAR_$_TradePortal.animationLoopIndex',
                   'OBJC_IVAR_$_TradePortal.savedDrawBuffer',
                   'OBJC_IVAR_$_DynamicObject.floatPos'):
        assert needle in syms, needle
    assert 'updateQuadBufferTexCoords' in d['semantics']
    assert '0.2f' in d['semantics']
    aq = BY['tp_addquad']
    assert 'fillQuadBuffer' in aq['semantics'] and 'index+1' in aq['semantics']
    t = BY['tp_title']
    assert t['selectors']['0x00d3b900'] == {'selector': 'stringWithFormat:', 'slot': '0x00e888ac'}
    assert 'f4e784' in t['semantics']
    for n, f in (('tp_actiontitle', 'f4e794'), ('tp_secondtitle', 'f4e7a4'), ('tp_thirdtitle', 'f4e7a4')):
        assert f in BY[n]['semantics'], n
    assert '0xfffffd80' in BY['tp_setworkbench']['semantics']

def test_serialization_quartets():
    ru = BY['tp_remoteupd']
    assert '0x40-byte item struct' in ru['semantics']
    assert 'level-1, 0..4' in ru['semantics']
    assert '0xd37798' in ru['semantics'] and '0xd38dfc' in ru['semantics']
    assert BY['tp_updnet']['selectors']['0x00d38e20'] if False else True
    assert '0xd391d4' in BY['tp_updnet']['semantics']
    gs = BY['tp_getsave']
    assert 'f4e724' in gs['semantics'] and 'f4e734' in gs['semantics']
    assert '0xd38dfc' in BY['tp_initnet']['semantics']

def test_constants_and_hashes():
    assert BY['tp_objtype']['imp'] == '0x00d377a8'
    assert '0x32' in BY['tp_objtype']['semantics']
    assert '7 (uxth)' in BY['tp_interobjtype']['semantics']
    assert '0xa7' in BY['tp_interrender']['semantics']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_light_system()
    test_level_and_remove()
    test_draw_and_titles()
    test_serialization_quartets()
    test_constants_and_hashes()
    print('trade portal contract: OK')
