#!/usr/bin/env python3
"""Contract test for the ElevatorMotor closure batch.

Pins doc and JSON to each other and to the recovered semantics: the elevator
power contract (15-unit charge loop via findAndSubtractAllPowerUpTo), rail
minY/maxY re-scan + atomic accessors, serialization quartets, static-geometry
trio, and the freeblock foreword pair.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/ELEVATOR_MOTOR.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/elevator_motor.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['m_subderived', 'm_objtype', 'm_initpos', 'm_initsave', 'm_initnet',
         'm_getsave', 'm_dealloc', 'm_updnet', 'm_creationnet', 'm_remoteupd',
         'm_update', 'm_draw', 'm_fbitem', 'm_fbsave', 'm_fba', 'm_fbb',
         'm_worldchanged', 'm_sgcdc', 'm_addcube', 'm_rmmacro', 'm_isstorage',
         'm_occnormal', 'm_miny', 'm_setminy', 'm_maxy', 'm_setmaxy']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == [
        '0x006ffeec', '0x006fff94', '0x006fffb0', '0x0070046c', '0x007007d4',
        '0x00700b5c', '0x00700ed8', '0x00700f9c', '0x00700ff0', '0x007014d8',
        '0x007017a0', '0x00701a1c', '0x00701c44', '0x00701c80', '0x00701ccc',
        '0x00701ce8', '0x00701d04', '0x00702334', '0x00702354', '0x007026d4',
        '0x007027dc', '0x007029a8', '0x007029c4', '0x00702a00', '0x00702a44',
        '0x00702a80']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [42, 7, 303, 218, 217, 223, 49, 21, 223, 178, 159, 138,
                     15, 19, 7, 7, 396, 8, 195, 66, 7, 7, 15, 17, 15, 17]
    assert sum(words) == 2569
    for needle in ('2569', '0x006ffeec', '0x007017a0', 'findAndSubtractAllPowerUpTo:forUser:',
                   'dmb ish', '0x67', 'macroTiles', 'texture 584', '0xbfc00000',
                   'fillBuffer:fromIndex:matrix:', 'creationNetDataForClient:',
                   'getSaveDict', 'availableElectricity', 'timeUntilNextPowerCheck',
                   'OBJC_CLASS_$_DrawCube', 'worldChanged:'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        'm_subderived': (1, 2, 2, 0), 'm_objtype': (0, 0, 0, 0),
        'm_initpos': (6, 6, 8, 20), 'm_initsave': (9, 5, 12, 2),
        'm_initnet': (11, 5, 10, 3), 'm_getsave': (7, 5, 10, 1),
        'm_dealloc': (5, 1, 2, 0), 'm_updnet': (2, 0, 1, 0),
        'm_creationnet': (7, 6, 9, 3), 'm_remoteupd': (7, 7, 4, 6),
        'm_update': (4, 6, 3, 7), 'm_draw': (0, 0, 0, 0),
        'm_fbitem': (0, 1, 0, 0), 'm_fbsave': (2, 0, 1, 0),
        'm_fba': (0, 0, 0, 0), 'm_fbb': (0, 0, 0, 0),
        'm_worldchanged': (0, 6, 4, 40), 'm_sgcdc': (0, 0, 0, 0),
        'm_addcube': (2, 2, 3, 0), 'm_rmmacro': (4, 2, 3, 0),
        'm_isstorage': (0, 0, 0, 0), 'm_occnormal': (0, 0, 0, 0),
        'm_miny': (0, 1, 0, 0), 'm_setminy': (0, 1, 0, 0),
        'm_maxy': (0, 1, 0, 0), 'm_setmaxy': (0, 1, 0, 0),
    }

def test_power_contract():
    up = BY['m_update']
    assert up['selectors']['0x007019fc'] == {'selector': 'findAndSubtractAllPowerUpTo:forUser:', 'slot': '0x00e804bc'}
    assert up['ivars']['0x007019f0'] == {'offset': 60, 'slot': '0x0105d310', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.availableElectricity'}
    assert up['ivars']['0x007019f4'] == {'offset': 72, 'slot': '0x0105d318', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.timeUntilNextPowerCheck'}
    assert up['ivars']['0x00701a04'] == {'offset': 49, 'slot': '0x0105c3cc', 'symbol': 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent'}
    sem = up['semantics']
    for needle in ('5.0f', '0xf - availableElectricity', 'findAndSubtractAllPowerUpTo',
                   'dynamicWorldChangedAtPos:objectType:'):
        assert needle in sem, needle
    ru = BY['m_remoteupd']
    assert ru['selectors']['0x00701770'] == {'selector': 'getBytes:length:', 'slot': '0x00e80470'}
    assert ru['selectors']['0x00701764'] == {'class': 'OBJC_CLASS_$_ElevatorMotor', 'slot': '0x00e8bce8'}

def test_rail_and_accessors():
    ip = BY['m_initpos']
    assert ip['ivars']['0x00700440'] == {'offset': 68, 'slot': '0x0105d304', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.maxY'}
    assert ip['ivars']['0x00700444'] == {'offset': 64, 'slot': '0x0105d308', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.minY'}
    assert ip['ivars']['0x00700448']['symbol'] == 'OBJC_IVAR_$_ElevatorMotor.itemType'
    assert 'tile[3] == 0x67' in ip['semantics']
    wc = BY['m_worldchanged']
    assert wc['branches'][0]['mnemonic'] is not None
    assert wc['ivars']['0x00702320'] == {'offset': 64, 'slot': '0x0105d308', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.minY'}
    assert wc['ivars']['0x0070232c'] == {'offset': 68, 'slot': '0x0105d304', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.maxY'}
    assert 'shrink' in wc['semantics']
    for n in ('m_miny', 'm_setminy', 'm_maxy', 'm_setmaxy'):
        assert 'dmb ish' in BY[n]['semantics'], n
    assert BY['m_setmaxy']['ivars']['0x00702abc'] == {'offset': 68, 'slot': '0x0105d304', 'symbol': 'OBJC_IVAR_$_ElevatorMotor.maxY'}
    assert BY['m_objtype']['types'] == 'i8@0:4'
    assert '0x37' in BY['m_objtype']['semantics']
    assert '= 0' in BY['m_isstorage']['semantics']
    assert '= 1' in BY['m_occnormal']['semantics']

def test_serialization_and_static_geometry():
    assert BY['m_updnet']['selectors']['0x00700fe8'] == {'selector': 'creationNetDataForClient:', 'slot': '0x00e80498'}
    assert BY['m_fbsave']['selectors']['0x00701cc4'] == {'selector': 'getSaveDict', 'slot': '0x00e80480'}
    assert BY['m_fbsave']['selectors']['0x00701cc0'] == {'import': 'objc_msgSend', 'slot': '0x0105b7a0'}
    sub = BY['m_subderived']
    assert sub['selectors']['0x006fff90'] == {'selector': 'macroTiles', 'slot': '0x00e8044c'}
    assert 'reloadDrawBlockDynamicObjectStaticGeometryForTile' in sub['semantics']
    rm = BY['m_rmmacro']
    assert rm['selectors']['0x007027c0'] == {'selector': 'removeFromMacroBlock', 'slot': '0x00e804c4'}
    assert 'objc_msgSendSuper2' in rm['semantics']
    ac = BY['m_addcube']
    assert ac['selectors']['0x00702654'] == {'class': 'OBJC_CLASS_$_DrawCube', 'slot': '0x00e8a4a8'}
    assert ac['selectors']['0x0070265c']['selector'].startswith('fillBuffer:fromIndex:matrix:')
    assert '0x248' in ac['semantics'] and '-1.5f' in ac['semantics']
    assert '0x702660' in ac['semantics']

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_power_contract()
    test_rail_and_accessors()
    test_serialization_and_static_geometry()
    test_hashes_and_claim()
    print('elevator motor contract: OK')
