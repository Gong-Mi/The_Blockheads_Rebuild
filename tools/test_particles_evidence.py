#!/usr/bin/env python3
"""Contract test for the ParticleEmitter class (E73)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
DOC = (NATIVE / 'PARTICLES.md').read_text()
DATA = json.loads((NATIVE / 'particles.json').read_text())
BY = {m['name']: m for m in DATA['classes']}

NAMES = ['pe_init', 'pe_instance', 'pe_reset', 'pe_setworld', 'pe_setworldwidth', 'pe_worldwidth',
         'pe_setstopall', 'pe_stopall', 'pe_addparticle', 'pe_addparticle_center',
         'pe_addparticle_goal', 'pe_addbonus', 'pe_addelectricity', 'pe_doelectricity', 'pe_render']

IMPS = ['0x00d85f98', '0x00d85ecc', '0x00d86e30', '0x00d86dec', '0x00d8ccf8', '0x00d8ccbc',
        '0x00d8cc78', '0x00d8cc3c', '0x00d87034', '0x00d87268', '0x00d87b8c', '0x00d88284',
        '0x00d8753c', '0x00d876b0', '0x00d88670']

COUNTS = {
    'pe_init': (10, 13, 7, 17, 56, 8),
    'pe_instance': (2, 1, 1, 0, 2, 1),
    'pe_reset': (2, 1, 0, 5, 5, 6),
    'pe_setworld': (0, 0, 0, 1, 0, 0),
    'pe_setworldwidth': (0, 0, 0, 1, 0, 0),
    'pe_worldwidth': (0, 0, 0, 1, 0, 0),
    'pe_setstopall': (0, 0, 0, 1, 0, 0),
    'pe_stopall': (0, 0, 0, 1, 0, 0),
    'pe_addparticle': (1, 0, 0, 0, 1, 0),
    'pe_addparticle_center': (1, 0, 0, 0, 1, 0),
    'pe_addparticle_goal': (4, 1, 0, 9, 12, 10),
    'pe_addbonus': (3, 1, 0, 9, 7, 7),
    'pe_addelectricity': (2, 0, 0, 2, 9, 5),
    'pe_doelectricity': (3, 1, 0, 5, 9, 8),
    'pe_render': (22, 3, 0, 25, 186, 106),
}

WORDS = [913, 51, 129, 17, 17, 15, 17, 15, 141, 181, 446, 251, 93, 277, 4099]


def kinds(entry):
    sels = sum(1 for v in entry['selectors'].values() if 'selector' in v)
    imps = sum(1 for v in entry['selectors'].values() if 'import' in v)
    cls = sum(1 for v in entry['selectors'].values() if 'class' in v)
    return (sels, imps, cls, len(entry['ivars']), len(entry['calls']), len(entry['branches']))


def test_bodies():
    assert [m['name'] for m in DATA['classes']] == NAMES
    assert [BY[n]['imp'] for n in NAMES] == IMPS
    assert [BY[n]['verified_words'] for n in NAMES] == WORDS
    assert sum(BY[n]['verified_words'] for n in NAMES) == 6662
    for needle in ('6662', 'ElectrictyParticlePathIndex', '0x7fffffff', 'dmb ish',
                   'closestPointOnLineToPoint', '16384, 4', '2048'):
        assert needle in DOC, needle


def test_anchor_counts():
    for n in NAMES:
        assert kinds(BY[n]) == COUNTS[n], (n, kinds(BY[n]))


def test_arc():
    s = BY['pe_addelectricity']['semantics']
    for needle in ('Electricty', 'vector', '_Unwind_Resume'):
        assert needle in s, needle
    s = BY['pe_doelectricity']['semantics']
    for needle in ('0x32', '40-byte', '::assign', '0x7fffffff'):
        assert needle in s, needle
    s = BY['pe_render']['semantics']
    for needle in ('closestPointOnLineToPoint', 'glDrawArrays', 'tileIsAir', '0.99f'):
        assert needle in s, needle


def test_pool_and_atomics():
    s = BY['pe_init']['semantics']
    for needle in ('16384, 4', '2048', '0x800'):
        assert needle in s, needle
    for n in ('pe_setworldwidth', 'pe_setstopall'):
        assert 'dmb ish' in BY[n]['semantics'], n
    s = BY['pe_addparticle_goal']['semantics']
    for needle in ('ffffff50', '0x7fffffff', 'vcvt.f32.s32'):
        assert needle in s, needle


if __name__ == '__main__':
    test_bodies()
    test_anchor_counts()
    test_arc()
    test_pool_and_atomics()
    print('test_particles_evidence: OK')
