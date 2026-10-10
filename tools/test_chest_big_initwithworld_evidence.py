#!/usr/bin/env python3
"""Dual-mode evidence guard for batch b3m-2 (the Chest loader).

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
TOOL = ROOT / 'tools/recover_chest_big_initwithworld.py'
JSON_PATH = (ROOT / 'reconstruction/reverse-v3/native/'
             'chest_big_initwithworld.json')

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    data = json.loads(JSON_PATH.read_text())
    check(data['batch'] == 'b3m2', 'batch must be b3m2')
    check(data['elf_sha256'] == SHA, 'elf sha drift')
    check(len(data['classes']) == 1, 'must cover one class')
    c = data['classes'][0]
    check(c['class'] == 'Chest', 'class drift')
    check(int(c['imp'], 16) == 0x00CB627C, 'imp drift')
    check(c['code_words'] == 760, 'word count drift')
    check(c['runtime_superclass'] == 'InteractionObject', 'super drift')
    check(c['own_keys'] == ['chestType', 'safeClientID', 'saveItemSlots',
                            'shelfItemDataBs_%d', 'shelfRenderItems_%d'],
          f'own key set drift {c["own_keys"]}')
    cap = c['capacity_helper']
    check(cap['imp'] == '0x00cb623c', 'capacity helper imp drift')
    check(cap['code_words'] == 16, 'capacity helper size drift')
    check(cap['rule'] == 'numberOfSlots = (chestType == 2 || chestType == 5) '
          '? 4 : 16', 'capacity rule drift')
    check(c['literal_cells']['stack_chk_guard_got'] is not None,
          'stack canary GOT missing')
    census = data['census']
    check(census['covered_after_b3m2'] == 58, 'census covered drift')
    check(census['remaining_methods'] == 2, 'census remaining drift')
    check(census['remaining_words'] == 2734, 'census remaining words drift')

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
        print('b3m2 evidence: static contract only '
              '(no pinned ELF or no Unicorn on this host)')

    if failures:
        print('b3m2 evidence: FAIL')
        for f in failures:
            print(f'  - {f}')
        raise SystemExit(1)
    print('b3m2 evidence: PASS')


if __name__ == '__main__':
    main()
