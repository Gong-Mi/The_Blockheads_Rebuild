#!/usr/bin/env python3
"""Contract test for the physical-block save/sync batch (E14).

Pins the JSON artifact and the prose doc to each other and to the recovered
semantics: the 65541-byte gzip input (tile pointer + byte13 + the offset-24 word,
incremented in place after the copy), the NSException path on a nil gzipDeflate,
the per-client light-block piggyback and receipt dictionary, the database persist
under an MD5-derived key, the client-sync broadcast with its reliable semantics,
and the sendDynamicObjects-gated dynamic-object passes.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'BLOCK_SAVE_SYNC.md').read_text()
DATA = json.loads((NATIVE / 'block_save_sync.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['wtl_savephysicalblock_macr', 'wtl_sendblocktoclientwitho']

IMPS = ['0x00859a84', '0x00858664']

WORDS = [882, 1197]

COUNTS = {
    'wtl_savephysicalblock_macr': (21, 9, 6, 2, 47, 21),
    'wtl_sendblocktoclientwitho': (25, 12, 6, 2, 65, 29),
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
    assert sum(WORDS) == 2079
    for needle in ('2079', '65541', '0x10000', 'physicalBlock+8',
                   'sendDynamicObjects', 'macroIndex', 'reliable:1', 'stringFromMD5',
                   'loadLightBlockForClientLightBlockIndex'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))
    assert sum(COUNTS[n][0] for n in NAMES) == 46
    assert sum(COUNTS[n][1] for n in NAMES) == 21
    assert sum(COUNTS[n][2] for n in NAMES) == 12
    assert sum(COUNTS[n][3] for n in NAMES) == 4
    assert sum(COUNTS[n][4] for n in NAMES) == 112
    assert sum(COUNTS[n][5] for n in NAMES) == 50


def test_writer():
    s = BY['wtl_savephysicalblock_macr']['semantics']
    for needle in ("it gzips the block's tile image plus two scalar fields into the "
                   "block database",
                   '65536+1+4 = 65541 bytes total',
                   "sourcing the 'C' byte at offset 13 (add r3, r3, 0xd at 0x00859b98)",
                   'when it returns nil the method raises [NSException raise:',
                   'It then increments the int at physicalBlock+24 in place '
                   '(ldr 0x00859cf4, add 0x00859cf8, str 0x00859cfc)',
                   'the sendReliably: byte spilled to [fp,-0x35] at 0x00859b2c is never read',
                   'persists the compressed payload [self->blockDatabase setData:payload '
                   'forKey:key2]',
                   'reliable:1 constant is the movw r1,1 at 0x0085a640'):
        assert needle in s, needle
    syms = {v['symbol'] for v in BY['wtl_savephysicalblock_macr']['ivars'].values()}
    assert 'OBJC_IVAR_$_WorldTileLoader.blockDatabase' in syms


def test_sender():
    s = BY['wtl_sendblocktoclientwitho']['semantics']
    for needle in ('Two nil guards short-circuit to the flag copy at 0x859868',
                   'the u32 at block+0x18 is incremented right afterwards '
                   '(0x00858860-0x0085886c)',
                   'sendDynamicObjects gates only the dynamic-object fetch',
                   'initialDynamicObjectsNetDataForMacroTileIndex:macroIndex '
                   'wireForClient:sendToClient',
                   'dataWithBytes:&(char)7 length:1',
                   'tags entries with byte 8',
                   'reliable controls only this message',
                   'Nothing is written to lightBlockDatabase in this body.'):
        assert needle in s, needle
    # the writer's constant reliable is not the sender's behaviour: the sender
    # passes its own byte for the block message and hardcodes 1 for the dynamic
    # packets - a swap must fail here.
    assert 'ldrb of [fp,-0x3e] at 0x0085902c' in s
    assert '0x008593b8, 0x008593e8; reliable hardcoded 1, not the argument' in s


def test_artifact_contract():
    assert DATA['batch'].startswith('Physical-block save/sync batch (E14)')
    assert 'outside these bodies' in DATA['claim']
    assert 'setData:forKey:' in DATA['claim']
    assert DATA['elf_sha256'] == '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
    assert DATA['schema'] == 1
    assert all(BY[n]['pic_base'] == '0x0105faf4' for n in NAMES)
    assert all(BY[n]['disjoint_branch_rows'] == [] for n in NAMES)


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_writer()
    test_sender()
    test_artifact_contract()
    print('block save sync contract: OK')
