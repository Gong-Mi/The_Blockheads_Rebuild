#!/usr/bin/env python3
"""Contract test for the electricity net-sync pair + wire forwarding + WirePathCreator lifecycle batch.

Pins doc and JSON to each other and to the recovered semantics: the
particle-path broadcast/pack/unpack round trip (gzipDeflate/gzipInflate,
opcode-carrying 8-byte header, packed {x,y} pairs), the wire tag 0x26
forwarding trio, the initial-wire-objects macro-tile net data assembly, and
the WirePathCreator 512-slot property array lifecycle.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = (ROOT / 'reconstruction/reverse-v3/native/POWER_SYNC.md').read_text()
DATA = json.loads((ROOT / 'reconstruction/reverse-v3/native/power_sync.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['world_sendelecpath', 'world_elecpathrecv', 'dw_initialwirenets',
         'dw_addwire', 'dw_wireatpos', 'dw_removewire', 'wpc_init', 'wpc_dealloc']

def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    imps = [BY[n]['imp'] for n in NAMES]
    assert imps == ['0x005ca058', '0x005ca9c4', '0x008b5300', '0x008eb9c0',
                    '0x008eba64', '0x008ebad4', '0x00db1e90', '0x00db1f84']
    ends = [BY[n]['boundary_end'] for n in NAMES]
    assert ends == ['0x005ca9c4', '0x005caef8', '0x008b5e54', '0x008eba64',
                    '0x008ebad4', '0x008ebb88', '0x00db1f84', '0x00db20b4']
    words = [BY[n]['verified_words'] for n in NAMES]
    assert words == [603, 333, 725, 41, 28, 45, 61, 76]
    assert sum(words) == 1912
    for needle in ('1912', '0x005ca058', '0x005ca9c4', '0x005caef8',
                   '0x008b5300', '0x008eb9c0', '0x00db1e90', '0x00db1f84'):
        assert needle in DOC, needle

def test_anchor_counts():
    counts = {n: (len(BY[n]['selectors']), len(BY[n]['ivars']),
                  len(BY[n]['calls']), len(BY[n]['branches'])) for n in NAMES}
    assert counts == {
        'world_sendelecpath': (15, 3, 24, 23),
        'world_elecpathrecv': (9, 1, 19, 22),
        'dw_initialwirenets': (20, 2, 43, 20),
        'dw_addwire': (1, 0, 1, 0),
        'dw_wireatpos': (1, 0, 1, 0),
        'dw_removewire': (3, 0, 2, 0),
        'wpc_init': (3, 2, 2, 2),
        'wpc_dealloc': (5, 3, 4, 0),
    }

def test_net_sync_pair():
    send = BY['world_sendelecpath']
    assert send['selectors']['0x005ca970'] == {'slot': '0x00e7de28', 'selector': 'array'}
    assert send['selectors']['0x005ca9a4'] == {'slot': '0x00e7ddf0', 'selector': 'appendBytes:length:'}
    assert send['selectors']['0x005ca96c'] == {'slot': '0x0105b7a0', 'import': 'objc_msgSend'}
    assert send['ivars']['0x005ca964'] == {'slot': '0x0105c784', 'symbol': 'OBJC_IVAR_$_World.client', 'offset': 960}
    assert send['ivars']['0x005ca968'] == {'slot': '0x0105c74c', 'symbol': 'OBJC_IVAR_$_World.server', 'offset': 964}
    assert send['ivars']['0x005ca97c'] == {'slot': '0x0105c77c', 'symbol': 'OBJC_IVAR_$_World.serverClients', 'offset': 956}
    recv = BY['world_elecpathrecv']
    assert recv['selectors']['0x005caee0'] == {'slot': '0x00e7e78c', 'selector': 'doAddElectricityParticleWithPath:size:'}
    assert recv['selectors']['0x005caed4'] == {'slot': '0x00e8a04c', 'class': 'OBJC_CLASS_$_ParticleEmitter'}
    callees = {c['route']: c['callee'] for c in recv['calls'] if c['callee']}
    assert callees['bl sym.imp._Unwind_Resume'] == '0x001c29c0'
    assert callees['bl sym.imp.__wrap_malloc'] == '0x001c2e58'
    assert any(c['callee'] == '0x005db5b4' for c in recv['calls']
               if c['route'].endswith('__push_back_slow_path_ElectrictyParticlePathIndex_const__ElectrictyParticlePathIndex_const_'))
    for needle in ('gzipDeflate', 'sendNetworkData:toPeers:reliable:',
                   'sendDataToServer:reliable:', 'gzipInflate',
                   'subdataWithRange:', 'doAddElectricityParticleWithPath:size:',
                   '0x5db5b4', '0x5cb054', 'length == 8'):
        assert needle in DOC, needle

def test_wire_forwarding_trio():
    addw = BY['dw_addwire']
    assert addw['selectors']['0x008eba5c'] == {
        'slot': '0x00e83118',
        'selector': 'addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:'}
    assert '0x26' in DOC
    watp = BY['dw_wireatpos']
    assert watp['selectors']['0x008ebacc'] == {'slot': '0x00e830e4', 'selector': 'objectOfType:atPos:'}
    rmw = BY['dw_removewire']
    assert rmw['selectors']['0x008ebb78'] == {'slot': '0x00e830f4', 'selector': 'removeStandardObject:'}
    dw = BY['dw_initialwirenets']
    assert dw['selectors']['0x008b5e20'] == {'slot': '0x00e82e18', 'selector': 'creationNetDataForClient:'}
    assert dw['selectors']['0x008b5e38'] == {'slot': '0x00e82e24', 'selector': 'wireDynamicObject:'}
    assert dw['selectors']['0x008b5e1c'] == {'slot': '0x00e8a9d4', 'class': 'OBJC_CLASS_$_Blockhead'}
    assert dw['ivars']['0x008b5de0']['offset'] == 4     # DynamicWorld.world
    assert dw['ivars']['0x008b5e10']['offset'] == 24    # DynamicWorld.serverClients
    callees = {c['route']: c['callee'] for c in dw['calls'] if c['callee']}
    assert callees['bl sym.tileAtWorldPositionLoaded_int__int__World_'] == '0x00a12f24'
    assert callees['bl sym.imp.__modsi3'] == '0x001c3020'
    assert callees['bl sym.imp.__aeabi_idiv'] == '0x001c3728'
    for needle in ('wireDynamicObject:', 'creationNetDataForClient:',
                   'updateNetDataForClient:', 'macroTiles', '0x26'):
        assert needle in DOC, needle

def test_wirepathcreator_lifecycle():
    winit = BY['wpc_init']
    assert winit['selectors']['0x00db1f70'] == {'slot': '0x00e88f0c', 'selector': 'init'}
    assert winit['ivars']['0x00db1f7c'] == {'slot': '0x0105fadc', 'symbol': 'OBJC_IVAR_$_WirePathCreator.world', 'offset': 4}
    assert winit['ivars']['0x00db1f78'] == {'slot': '0x0105fad8', 'symbol': 'OBJC_IVAR_$_WirePathCreator.derivedTilePropertiesArray', 'offset': 20}
    callees = {c['route']: c['callee'] for c in winit['calls'] if c['callee']}
    assert callees['bl sym.imp.__wrap_malloc'] == '0x001c2e58'
    wde = BY['wpc_dealloc']
    assert wde['selectors']['0x00db20a0'] == {'slot': '0x00e88f10', 'selector': 'release'}
    assert wde['ivars']['0x00db20a4']['symbol'] == 'OBJC_IVAR_$_WirePathCreator.closedList'
    assert wde['ivars']['0x00db20a8']['symbol'] == 'OBJC_IVAR_$_WirePathCreator.openList'
    assert wde['ivars']['0x00db20ac']['symbol'] == 'OBJC_IVAR_$_WirePathCreator.derivedTilePropertiesArray'
    for needle in ('0x1800', '512', 'objc_msgSendSuper2', 'derivedTilePropertiesArray@20',
                   'openList@8', 'closedList@12'):
        assert needle in DOC, needle

def test_hashes_and_claim():
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert 'outside these bodies' in DATA['claim']
    assert 'transport consumers' in DOC

if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_net_sync_pair()
    test_wire_forwarding_trio()
    test_wirepathcreator_lifecycle()
    test_hashes_and_claim()
    print('power sync contract: OK')
