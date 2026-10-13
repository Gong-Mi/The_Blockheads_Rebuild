#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3l (fifteen upper-mid-tier
initWithWorld loaders incl. the chain nodes).

Host mode (pinned ELF present): re-runs the recovery tool `--check` and
its mutation `--self-test`.

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
TOOL = ROOT / 'tools/recover_uppermid15_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'uppermid15_initwithworld.json')

EXPECT = {
    'ElevatorShaft': (0x00CAD2CC, 214, 'DynamicObject', 5),
    'GlowBlock': (0x00CA8920, 214, 'DynamicObject', 2),
    'ElevatorMotor': (0x0070046C, 218, 'DynamicObject', 5),
    'TradingPost': (0x005E5718, 223, 'InteractionObject', 4),
    'FireObject': (0x00674AF4, 259, 'DynamicObject', 6),
    'DynamicObject': (0x00839F7C, 273, None, 4),
    'NormalPlant': (0x00A66614, 281, 'Plant', 2),
    'TradePortal': (0x00D382FC, 281, 'InteractionObject', 3),
    'Torch': (0x004B5D38, 318, 'DynamicObject', 6),
    'InteractionObject': (0x005F4634, 352, 'DynamicObject', 6),
    'OwnershipSign': (0x00A34B18, 352, 'Sign', 4),
    'Painting': (0x00AA81E8, 358, 'DynamicObject', 5),
    'TrainCar': (0x00A3892C, 363, 'DynamicObject', 6),
    'DropBear': (0x0079D538, 404, 'NPC', 9),
    'CaveTroll': (0x00D538CC, 408, 'NPC', 4),
}

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3l', 'batch must be b3l')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 15, 'must cover fifteen classes')
    seen = {c['class'] for c in data['classes']}
    check(seen == set(EXPECT), f'class set drift: {sorted(seen)}')
    total_keys = 0
    for c in data['classes']:
        imp, words, sup, keys = EXPECT[c['class']]
        check(int(c['imp'], 16) == imp, f"{c['class']}: imp drift")
        check(c['code_words'] == words, f"{c['class']}: word count drift")
        check(c['runtime_superclass'] == sup,
              f"{c['class']}: runtime super drift")
        check(len(c['own_keys']) == keys,
              f"{c['class']}: own key count drift {c['own_keys']}")
        total_keys += len(c['own_keys'])
    check(total_keys == 71, f'total key reads must be 71, got {total_keys}')
    census = data['census']
    check(census['front_methods'] == 60, 'census front methods drift')
    check(census['front_words'] == 13820, 'census front words drift')
    check(census['covered_after_b3l'] == 55, 'census covered drift')
    check(census['remaining_methods'] == 5, 'census remaining drift')
    check(census['remaining_words'] == 4781, 'census remaining words drift')

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
        print('b3l evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3l evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3l evidence: PASS')


if __name__ == '__main__':
    main()
