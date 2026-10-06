#!/usr/bin/env python3
"""Contract test for the electricity consumers/producers closure batch.

Pins doc and JSON to each other and to the recovered semantics: the Workbench
electric API (conducts/generates/requires/usesStores type whitelists, the
subtract + steam-regeneration loop), the solar-panel light formulas, the
DynamicWorld power-search forwarder into the WirePathCreator engine, and the
ParticleEmitter electricity-particle segment allocator.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/POWER_WORKBENCH.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/power_workbench.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wb_fullsun', 'wb_solarpanel', 'wb_avail', 'wb_conducts',
         'wb_subtract', 'wb_generates', 'wb_usesstores', 'wb_requires',
         'dw_findsub', 'pe_add', 'pe_doadd']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == [
        '0x00aee208', '0x00aee508', '0x00b01284', '0x00b012c0',
        '0x00b0137c', '0x00b01c24', '0x00b01cac', '0x00b0b7d0',
        '0x008fdee8', '0x00d8753c', '0x00d876b0']
    assert [BY[n]['boundary_end'] for n in NAMES] == [
        '0x00aee4e0', '0x00aee9d0', '0x00b012c0', '0x00b0137c',
        '0x00b01744', '0x00b01cac', '0x00b01ec0', '0x00b0b868',
        '0x008fdf6c', '0x00d876b0', '0x00d87b04']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [182, 306, 15, 47, 242, 34, 133, 38, 33, 93, 277]
    assert sum(words) == 1400
    for needle in ('1400', '0xb0137c', '0xb01cac', '0xaee208',
                   '0xd876b0', '0xae3574'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        'wb_fullsun': (2, 2, 5, 10),
        'wb_solarpanel': (5, 2, 8, 13),
        'wb_avail': (0, 1, 0, 0),
        'wb_conducts': (3, 0, 2, 1),
        'wb_subtract': (4, 7, 5, 10),
        'wb_generates': (0, 1, 0, 1),
        'wb_usesstores': (0, 1, 0, 10),
        'wb_requires': (3, 0, 3, 0),
        'dw_findsub': (2, 1, 1, 0),
        'pe_add': (2, 2, 9, 5),
        'pe_doadd': (4, 5, 9, 8),
    }

def test_workbench_type_whitelists():
    assert BY['wb_generates']['ivars']['0x00b01ca4'] == {
        'slot': '0x0105ec14', 'symbol': 'OBJC_IVAR_$_Workbench.type', 'offset': 120}
    assert BY['wb_usesstores']['ivars']['0x00b01eb8']['offset'] == 120
    s = BY['wb_generates']['semantics']
    assert '== 0xf || type == 0x14' in s
    s2 = BY['wb_usesstores']['semantics']
    for t in ('0xf', '0x14', '0x15', '0x11', '0x10', '0x1b', '0x12', '0x13', '0x1a', '0x1d', '0x1e'):
        assert t in s2, t

def test_conducts_and_requires():
    cond = BY['wb_conducts']
    assert cond['selectors']['0x00b01370'] == {'slot': '0x00e86164', 'selector': 'isStorageDevice'}
    assert cond['selectors']['0x00b01374'] == {'slot': '0x00e86168', 'selector': 'generatesElectricity'}
    req = BY['wb_requires']
    assert req['selectors']['0x00b0b860'] == {'slot': '0x00e86184', 'selector': 'type'}
    assert req['selectors']['0x00b0b85c'] == {'slot': '0x00e86188', 'selector': 'level'}
    callees = {c['route']: c['callee'] for c in req['calls'] if c['callee']}
    assert callees['bl 0xae3574'] == '0x00ae3574'

def test_subtract_and_steam_loop():
    sub = BY['wb_subtract']
    assert sub['ivars']['0x00b01710'] == {
        'slot': '0x0105ec44', 'symbol': 'OBJC_IVAR_$_Workbench.availableElectricity', 'offset': 222}
    assert sub['ivars']['0x00b0172c']['offset'] == 120    # type
    assert sub['ivars']['0x00b01730']['offset'] == 212    # fuelFraction
    assert sub['ivars']['0x00b01734']['offset'] == 280    # particleCreateTimerSteamEngine
    assert sub['ivars']['0x00b01718']['offset'] == 49     # updateNeedsToBeSent
    assert sub['selectors']['0x00b01728'] == {
        'slot': '0x00e85fcc', 'selector': 'dynamicWorldChangedAtPos:objectType:'}
    assert sub['selectors']['0x00b0173c'] == {'slot': '0x00e860a0', 'selector': 'updateHasFuel'}
    s = sub['semantics']
    for needle in ('0.000583', '0x3a18d478', '0.1f', '0x3dcccccd',
                   'available < 100', '4.0f', 'flag byte'):
        assert needle in s, needle

def test_solar_panel_light():
    fs = BY['wb_fullsun']
    assert fs['selectors']['0x00aee4f0'] == {'slot': '0x00e85f08', 'selector': 'macroTiles'}
    assert fs['ivars']['0x00aee4e8']['offset'] == 4    # DynamicObject.world
    assert fs['ivars']['0x00aee4f4']['offset'] == 16   # DynamicObject.pos
    callees = {c['route']: c['callee'] for c in fs['calls'] if c['callee']}
    assert callees['bl sym.tileAtWorldPosition_int__int__MacroTile__World_'] == '0x00a16e68'
    assert callees['bl sym.tileIsAirOrSnow_Tile_'] == '0x00a12760'
    assert callees['bl sym.tileIsTree_Tile_'] == '0x00a13214'
    assert callees['bl sym.imp.__wrap_powf'] == '0x001c3f98'
    sp_ = BY['wb_solarpanel']
    assert sp_['selectors']['0x00aeea00'] == {
        'slot': '0x00e86094', 'selector': 'getDayNightFractionForX:atWorldTime:'}
    assert sp_['selectors']['0x00aeea04'] == {'slot': '0x00e85f54', 'selector': 'worldTime'}
    assert sp_['selectors']['0x00aeea0c'] == {
        'slot': '0x00e86098', 'selector': 'getWeatherFractionForPos:'}
    for needle in ('powf', '255.0', '2000.0', '1e-4', '0x3f1a36e2eb1c432d',
                   '0.23f', '0.2', 'sum16(tile+0xe', '/= 2'):
        assert needle in DOC, needle

def test_forwarder_and_emitter():
    dw = BY['dw_findsub']
    assert dw['selectors']['0x008fdf60'] == {
        'slot': '0x00e83220', 'selector': 'findAndSubtractAllPowerUpTo:forUser:'}
    assert dw['ivars']['0x008fdf64'] == {
        'slot': '0x0105e020', 'symbol': 'OBJC_IVAR_$_DynamicWorld.wirePathCreator', 'offset': 9496}
    add = BY['pe_add']
    assert add['selectors']['0x00d8769c'] == {
        'slot': '0x00e88cfc', 'selector': 'sendNetDataForElectricityParticlePathIfRequired:size:ignoreClient:'}
    assert add['selectors']['0x00d876a4'] == {
        'slot': '0x00e88d00', 'selector': 'doAddElectricityParticleWithPath:size:'}
    assert add['ivars']['0x00d87694']['offset'] == 4     # ParticleEmitter.world
    assert add['ivars']['0x00d876a0']['offset'] == 96    # stopAllParticles
    do = BY['pe_doadd']
    assert do['ivars']['0x00d87adc']['offset'] == 52     # electrictyFreeIndices
    assert do['ivars']['0x00d87ae0']['offset'] == 48     # electrictyParticles
    assert do['ivars']['0x00d87ae8']['offset'] == 56     # electrictyTakenIndices
    assert do['ivars']['0x00d87af4']['offset'] == 100    # worldWidthMacro
    assert do['selectors']['0x00d87ad8'] == {'slot': '0x00e88d04', 'selector': 'firstIndex'}
    assert do['selectors']['0x00d87aec'] == {'slot': '0x00e88d08', 'selector': 'removeIndex:'}
    callees = {c['route']: c['callee'] for c in do['calls'] if c['callee']}
    assert callees['bl sym.makeIntpair_int__int_'] == '0x004b49fc'
    assert callees['bl method.Vector.Vector_float__float__float_'] == '0x004b52ac'
    assert callees['bl sym.imp.__modsi3'] == '0x001c3020'
    for needle in ('makeIntpair', 'worldWidthMacro@100', '40', '0.03f', '-1.47f',
                   '50.0/size', 'NSNotFound', 'electrictyFreeIndices@52'):
        assert needle in DOC, needle

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']
    assert 'outside' in DOC

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_workbench_type_whitelists()
    test_conducts_and_requires()
    test_subtract_and_steam_loop()
    test_solar_panel_light()
    test_forwarder_and_emitter()
    test_hashes_and_claim()
    print('power workbench contract: OK')
