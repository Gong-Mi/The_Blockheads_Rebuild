#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3i (nine tree-family long-variant
forwarders).

Host mode (pinned ELF present): re-runs the recovery tool `--check` and its
mutation `--self-test`, and asserts the JSON claims.

CI mode (no ELF): static assertions over the checked-in evidence — the nine
classes with their IMPs/boundaries, the shared-body sha256, the Tree runtime
superclass, the census numbers, and the empty own-keys/own-ivars sets.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
TOOL = ROOT / 'tools/recover_treefamily9_long_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'treefamily9_long_initwithworld.json')

CLASSES = {
    'CactusTree': 0x00B533BC, 'CherryTree': 0x00D0DF2C,
    'CoconutTree': 0x00A99948, 'CoffeeTree': 0x007DEB28,
    'GemTree': 0x00529134, 'LimeTree': 0x00809C3C,
    'MangoTree': 0x00D4B4F4, 'MapleTree': 0x00DB5FB4,
    'OrangeTree': 0x00A96604,
}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3i', 'batch must be b3i')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 9, 'must cover nine classes')
    seen = {c['class'] for c in data['classes']}
    check(seen == set(CLASSES), f'class set drift: {sorted(seen)}')
    body_hashes = set()
    for c in data['classes']:
        imp = int(c['imp'], 16)
        check(imp == CLASSES[c['class']], f"{c['class']}: imp drift")
        check(c['code_words'] == 62, f"{c['class']}: word count drift")
        check(c['runtime_superclass'] == 'Tree',
              f"{c['class']}: runtime super drift")
        check(c['super_call_word_index'] == 42,
              f"{c['class']}: super call index drift")
        check(c['own_keys'] == [] and c['own_ivars'] == [],
              f"{c['class']}: must read no key and write no ivar")
        check('treeDensityNoiseFunction:seasonOffsetNoiseFunction:'
              in c['selector'], f"{c['class']}: selector drift")
        body_hashes.add(c['shared_body_sha256'])
    check(len(body_hashes) == 1, 'the nine bodies must share one sha256')
    census = data['census']
    check(census['covered_after_b3i'] == 20, 'census covered drift')
    check(census['remaining_methods'] == 23, 'census remaining drift')
    check(census['remaining_words'] == 9634, 'census remaining words drift')

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
        print('b3i evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3i evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3i evidence: PASS')


if __name__ == '__main__':
    main()
