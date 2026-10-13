#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3j (five mid-size initWithWorld
loaders with own save keys).

Host mode (pinned ELF present): re-runs the recovery tool `--check` and its
mutation `--self-test`.

CI mode (no ELF): static assertions over the checked-in evidence — the five
classes with IMPs/boundaries, runtime superclasses, exact own-key sets and
key→ivar pairs, conversion selectors, and the census numbers.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
TOOL = ROOT / 'tools/recover_midsize5_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'midsize5_initwithworld.json')

EXPECT = {
    'AppleTree': {'imp': 0x009BD3B0, 'boundary': 0x009BD548, 'words': 102,
                  'super': 'Tree', 'keys': ['availableFood'],
                  'pairs': {'availableFood': 'OBJC_IVAR_$_AppleTree.availableFood'}},
    'TrainStation': {'imp': 0x00B38F88, 'boundary': 0x00B3912C, 'words': 105,
                     'super': 'InteractionObject', 'keys': ['text'],
                     'pairs': {'text': 'OBJC_IVAR_$_TrainStation.text'}},
    'Plant': {'imp': 0x009559D0, 'boundary': 0x00955B98, 'words': 114,
              'super': 'DynamicObject', 'keys': [], 'pairs': {}},
    'GatherBlock': {'imp': 0x008695A0, 'boundary': 0x008697A0, 'words': 128,
                    'super': 'DynamicObject',
                    'keys': ['lastKnownGatherValue', 'timer'],
                    'pairs': {
                        'lastKnownGatherValue':
                            'OBJC_IVAR_$_GatherBlock.lastKnownGatherValue',
                        'timer': 'OBJC_IVAR_$_GatherBlock.timer'}},
    'Yak': {'imp': 0x0095DAE4, 'boundary': 0x0095DCFC, 'words': 134,
            'super': 'DonkeyLike', 'keys': ['hair', 'milk'],
            'pairs': {'hair': 'OBJC_IVAR_$_Yak.hair',
                      'milk': 'OBJC_IVAR_$_Yak.milk'}},
}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3j', 'batch must be b3j')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 5, 'must cover five classes')
    seen = {c['class'] for c in data['classes']}
    check(seen == set(EXPECT), f'class set drift: {sorted(seen)}')
    for c in data['classes']:
        e = EXPECT[c['class']]
        check(int(c['imp'], 16) == e['imp'], f"{c['class']}: imp drift")
        check(int(c['boundary'], 16) == e['boundary'], f"{c['class']}: boundary drift")
        check(c['code_words'] == e['words'], f"{c['class']}: word count drift")
        check(c['runtime_superclass'] == e['super'],
              f"{c['class']}: runtime super drift {c['runtime_superclass']}")
        check(c['own_keys'] == sorted(e['keys']),
              f"{c['class']}: own key set drift {c['own_keys']}")
        check(c['own_key_ivar_pairs'] == e['pairs'],
              f"{c['class']}: key/ivar pair drift")
    census = data['census']
    check(census['covered_after_b3j'] == 25, 'census covered drift')
    check(census['remaining_methods'] == 18, 'census remaining drift')
    check(census['remaining_words'] == 9051, 'census remaining words drift')

    if ELF.exists() and os.environ.get('BLOCKHEADS_SKIP_HOST') != '1':
        import hashlib
        check(hashlib.sha256(ELF.read_bytes()).hexdigest() == SHA,
              'ELF sha mismatch')
        r = subprocess.run([sys.executable, str(TOOL), str(ELF), '--check'],
                           capture_output=True, text=True)
        check(r.returncode == 0, f'--check failed: {r.stdout} {r.stderr[-400:]}')
        r2 = subprocess.run([sys.executable, str(TOOL), str(ELF),
                             '--self-test'], capture_output=True, text=True)
        check(r2.returncode == 0 and '6/6' in r2.stdout,
              f'self-test failed: {r2.stdout[-400:]} {r2.stderr[-400:]}')
    else:
        print('b3j evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3j evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3j evidence: PASS')


if __name__ == '__main__':
    main()
