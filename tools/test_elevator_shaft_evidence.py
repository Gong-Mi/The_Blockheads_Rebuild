#!/usr/bin/env python3
"""Contract test for the ElevatorShaft closure batch.

Pins doc and JSON to each other and to the recovered semantics: the door
contract (solidTile/opening/paintColor), rail motor tracking
(elevatorMotorForShaftAtPos -> lastKnownMotorPos), the draw pipeline
(animation phase, fillQuadBufferColored, 2 quads / 3 cubes, textures 583 /
115), the serialization quartets, and the copyStruct accessor.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/ELEVATOR_SHAFT.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/elevator_shaft.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['s_subderived', 's_objtype', 's_initpos', 's_initsave', 's_initnet',
         's_getsave', 's_updnet', 's_creationnet', 's_remoteupd', 's_dealloc',
         's_draw', 's_worldchanged', 's_sgdq', 's_addquad', 's_sgcdc',
         's_fbitem', 's_fbsave', 's_fba', 's_fbb', 's_addcube', 's_open',
         's_rmmacro', 's_paint', 's_ispaint', 's_occnormal', 's_lastmotor']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == [
        '0x00cacc58', '0x00cacf38', '0x00cacf54', '0x00cad2cc', '0x00cad624',
        '0x00cad998', '0x00cadd14', '0x00cadd68', '0x00cae218', '0x00cae414',
        '0x00cae4d8', '0x00caf680', '0x00cafb50', '0x00cafbb8', '0x00cb0394',
        '0x00cb03f0', '0x00cb042c', '0x00cb0478', '0x00cb0494', '0x00cb04b0',
        '0x00cb1138', '0x00cb1178', '0x00cb12f4', '0x00cb150c', '0x00cb1528',
        '0x00cb1544']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [184, 7, 222, 214, 212, 223, 21, 209, 127, 49, 714, 308,
                     26, 503, 23, 15, 19, 7, 7, 802, 16, 95, 134, 7, 7, 24]
    assert sum(words) == 4175
    for needle in ('4175', '0x00cacc58', '0x00cae4d8', 'elevatorMotorForShaftAtPos:',
                   'solidTile@86', 'opening@68', 'paintColor@84',
                   'lastKnownMotorPos@60', 'fillQuadBufferColored', 'texture 115',
                   'abs(4*f - 1)', 'objc_copyStruct', '0x38'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        's_subderived': (3, 5, 10, 3), 's_objtype': (0, 0, 0, 0),
        's_initpos': (7, 5, 8, 6), 's_initsave': (9, 4, 12, 2),
        's_initnet': (11, 4, 10, 3), 's_getsave': (7, 4, 10, 1),
        's_updnet': (2, 0, 1, 0), 's_creationnet': (7, 5, 9, 3),
        's_remoteupd': (2, 4, 7, 0), 's_dealloc': (5, 1, 2, 0),
        's_draw': (0, 7, 9, 10), 's_worldchanged': (3, 7, 9, 13),
        's_sgdq': (0, 1, 0, 2), 's_addquad': (0, 7, 9, 3),
        's_sgcdc': (0, 1, 0, 2), 's_fbitem': (0, 1, 0, 0),
        's_fbsave': (2, 0, 1, 0), 's_fba': (0, 0, 0, 0), 's_fbb': (0, 0, 0, 0),
        's_addcube': (2, 4, 11, 4), 's_open': (0, 1, 0, 0),
        's_rmmacro': (4, 2, 5, 0), 's_paint': (3, 6, 6, 1),
        's_ispaint': (0, 0, 0, 0), 's_occnormal': (0, 0, 0, 0),
        's_lastmotor': (0, 1, 1, 0),
    }

def test_door_contract():
    assert BY['s_open']['ivars']['0x00cb1170'] == {
        'offset': 68, 'slot': '0x0105f4a4', 'symbol': 'OBJC_IVAR_$_ElevatorShaft.opening'}
    assert BY['s_sgdq']['ivars']['0x00cafbb0'] == {
        'offset': 86, 'slot': '0x0105f498', 'symbol': 'OBJC_IVAR_$_ElevatorShaft.solidTile'}
    assert BY['s_sgcdc']['ivars']['0x00cb03e8']['offset'] == 86
    assert '0 : 2' in BY['s_sgdq']['semantics']
    assert '0 : 3' in BY['s_sgcdc']['semantics']
    p = BY['s_paint']
    assert p['ivars']['0x00cb14e0'] == {
        'offset': 84, 'slot': '0x0105f4a0', 'symbol': 'OBJC_IVAR_$_ElevatorShaft.paintColor'}
    assert p['ivars']['0x00cb14f4']['symbol'] == 'OBJC_IVAR_$_DynamicObject.updateNeedsToBeSent'
    sem = p['semantics']
    for needle in ('paint field', '!isNet', 'updateNeedsToBeSent', 'reload'):
        assert needle in sem, needle

def test_rail_tracking():
    sub = BY['s_subderived']
    assert sub['selectors']['0x00cacf28'] == {'selector': 'elevatorMotorForShaftAtPos:', 'slot': '0x00e87bd4'}
    assert sub['selectors']['0x00cacf1c'] == {'selector': 'macroTiles', 'slot': '0x00e87bd0'}
    assert 'lastKnownMotorPos@60' in sub['semantics']
    wc = BY['s_worldchanged']
    assert wc['selectors']['0x00cafb2c'] == {'selector': 'elevatorMotorForShaftAtPos:', 'slot': '0x00e87bd4'}
    assert 'tileIsSolid' in wc['semantics'] and 'shrink' not in wc['semantics']
    lm = BY['s_lastmotor']
    assert lm['ivars']['0x00cb159c'] == {
        'offset': 60, 'slot': '0x0105f494', 'symbol': 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos'}
    assert lm['pic_base'] == '0x0105faf4'
    assert 'objc_copyStruct' in lm['semantics']

def test_draw_pipeline():
    d = BY['s_draw']
    assert 'fillQuadBufferColored' in d['semantics']
    assert 'abs(4*field@9b4 - 1)' in d['semantics'] or 'abs(4*' in d['semantics']
    aq = BY['s_addquad']
    assert 'texture 583' in aq['semantics'] or 'tex 583' in aq['semantics']
    assert 'index+2' in aq['semantics']
    ac = BY['s_addcube']
    assert ac['selectors']['0x00cb1130']['selector'].startswith('fillBuffer:fromIndex:matrix:')
    assert ac['selectors']['0x00cb1130']['selector'].endswith(':paintColor:')
    assert ac['selectors']['0x00cb1128'] == {'class': 'OBJC_CLASS_$_DrawCube', 'slot': '0x00e8b5c4'}
    for needle in ('0x73', '583', 'index+3', '0.95f'):
        assert needle in ac['semantics'], needle

def test_serialization_quartets():
    assert BY['s_updnet']['selectors']['0x00cadd60'] == {'selector': 'creationNetDataForClient:', 'slot': '0x00e87c1c'}
    assert BY['s_fbsave']['selectors']['0x00cb0470'] == {'selector': 'getSaveDict', 'slot': '0x00e87c0c'}
    ru = BY['s_remoteupd']
    assert ru['selectors']['0x00cae404'] == {'selector': 'getBytes:length:', 'slot': '0x00e87bfc'}
    assert 'tileIsSolid' in ru['semantics']
    cn = BY['s_creationnet']
    for cell, sym in (('0x00cae090', 'OBJC_IVAR_$_ElevatorShaft.lastKnownMotorPos'),
                      ('0x00cae08c', 'OBJC_IVAR_$_ElevatorShaft.solidTile'),
                      ('0x00cae088', 'OBJC_IVAR_$_ElevatorShaft.paintColor')):
        assert cn['ivars'][cell]['symbol'] == sym
    assert '0xcae0ac' in cn['semantics']
    assert '0xcad974' in BY['s_initnet']['semantics']

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_door_contract()
    test_rail_tracking()
    test_draw_pipeline()
    test_serialization_quartets()
    test_hashes_and_claim()
    print('elevator shaft contract: OK')
