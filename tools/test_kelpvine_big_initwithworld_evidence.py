#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3m-1 (KelpPlant/VinePlant big
loaders).

Host mode (pinned ELF present): re-runs the recovery tool `--check` and its
mutation `--self-test`.

CI mode (no ELF): static assertions over the checked-in evidence.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
TOOL = ROOT / 'tools/recover_kelpvine_big_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'kelpvine_big_initwithworld.json')

EXPECT = {
    'KelpPlant': (0x00815BE8, 606, 'Plant',
                  ['availableFood', 'growthTimer',
                   'numberOfOccupiedTilesAbove', 'saveTime']),
    'VinePlant': (0x004F68A0, 681, 'Plant',
                  ['availableFood', 'growthTimer',
                   'numberOfOccupiedTilesBelow', 'saveTime']),
}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3m1', 'batch must be b3m1')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 2, 'must cover two classes')
    seen = {c['class'] for c in data['classes']}
    check(seen == set(EXPECT), f'class set drift: {sorted(seen)}')
    for c in data['classes']:
        imp, words, sup, keys = EXPECT[c['class']]
        check(int(c['imp'], 16) == imp, f"{c['class']}: imp drift")
        check(c['code_words'] == words, f"{c['class']}: word count drift")
        check(c['runtime_superclass'] == sup, f"{c['class']}: super drift")
        check(c['own_keys'] == keys, f"{c['class']}: own key set drift")
        check('treeDensityNoiseFunction:seasonOffsetNoiseFunction:'
              in c['selector'], f"{c['class']}: long variant drift")
    census = data['census']
    check(census['covered_after_b3m1'] == 57, 'census covered drift')
    check(census['remaining_methods'] == 3, 'census remaining drift')
    check(census['remaining_words'] == 3494, 'census remaining words drift')

    if ELF.exists() and os.environ.get('BLOCKHEADS_SKIP_HOST') != '1':
        import hashlib
        check(hashlib.sha256(ELF.read_bytes()).hexdigest() == SHA,
              'ELF sha mismatch')
        r = subprocess.run([sys.executable, str(TOOL), str(ELF), '--check'],
                           capture_output=True, text=True)
        check(r.returncode == 0, f'--check failed: {r.stdout} {r.stderr[-400:]}')
        r2 = subprocess.run([sys.executable, str(TOOL), str(ELF),
                             '--self-test'], capture_output=True, text=True)
        check(r2.returncode == 0 and '4/4' in r2.stdout,
              f'self-test failed: {r2.stdout[-400:]} {r2.stderr[-400:]}')
    else:
        print('b3m1 evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3m1 evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3m1 evidence: PASS')


if __name__ == '__main__':
    main()
