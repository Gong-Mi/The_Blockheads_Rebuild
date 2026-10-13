#!/usr/bin/env python3
"""Hash-gated roundtrip test for batch-b3e CrystalManager load evidence.

Host (pinned ELF present): recovery tool `--check` + `--self-test`.
CI (ELF absent): static content assertions + listing word count.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
OUT = NATIVE / 'crystalmanager_loadfromsave.json'
RECOVER = ROOT / 'tools/recover_crystalmanager_loadfromsave.py'
LISTING = NATIVE / 'disasm_crystalmanager_loadfromsave.txt'
SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'


def main():
    if ELF.exists():
        for args, label in ((['--check'], 'stale crystalmanager_loadfromsave.json'),
                            (['--self-test'], 'b3e negative controls failed')):
            r = subprocess.run([sys.executable, str(RECOVER), str(ELF)] + args,
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(r.stdout + r.stderr)
                raise SystemExit(label)
            print(r.stdout.strip())

    d = json.loads(OUT.read_text())
    assert d['elf_sha256'] == SHA and d['batch'] == 'b3e'
    assert d['class'] == 'CrystalManager'
    assert (d['imp'], d['boundary'], d['code_words']) == \
        ('0x009f3d44', '0x009f452c', 506)
    assert d['selector'] == 'loadFromSave'
    assert d['super_call'] is None

    kc = d['keychain_path']
    assert kc['class'] == 'OBJC_CLASS_$_SFHFKeychainUtils'
    assert kc['selector'] == 'getPasswordForUsername:andServiceName:error:'
    assert kc['call_site'] == '0x009f3da4'
    assert kc['username_and_service_key'] == \
        'com.majicjungle.blockheads.crystalcount'
    assert kc['error_out_param'] == 'fp-0x28'
    assert set(kc['writes']) == {'crystalCount@8', 'amountString@12'}
    assert 'intValue' in kc['writes']['crystalCount@8']
    assert 'stringFromMD5' in kc['writes']['amountString@12']
    assert '7acfe93afc08%dc65ae2c54ecaf07f' in kc['writes']['amountString@12']

    fp = d['file_path']
    assert 'NSSearchPathForDirectoriesInDomains(14,1,1)' in fp['search_paths']
    assert '0x001c3f20' in fp['search_paths']
    assert 'game/4bbf9ea9f3e11dd7afcb0f22ccb635d2' in fp['string_file']
    assert 'encoding:4' in fp['string_file']
    assert 'gzipInflate' in fp['data_file']
    assert fp['parser_thunk'].startswith('0x009f4508')
    assert '0x009f602c' in fp['parser_thunk']
    assert 'loadSaveIDB' in fp['tamper_gate']
    assert 'isEqualToString' in fp['tamper_gate']
    assert '>> 2' in fp['writes']['crystalCount@8']
    assert 'not symbolically evaluated' in fp['not_decoded']

    assert d['stored_scale']['file'] == 4 and d['stored_scale']['keychain'] == 1
    assert d['constants'] == {'search_path_directory': 14,
                              'search_path_domain_mask': 1,
                              'expand_tilde': 1, 'file_encoding_utf8': 4}
    assert d['ivar_offsets'] == {'amountString': 12, 'crystalCount': 8}
    assert len(d['pool_keys']) == 7
    assert 'loadSaveIDB' in d['pool_keys']
    kinds = {v['class']: v['kind'] for v in d['classref_cells'].values()}
    assert kinds['OBJC_CLASS_$_SFHFKeychainUtils'] == 'relative_pointer'
    assert kinds['OBJC_CLASS_$_NSString'] == 'abs32_zero_slot'
    assert kinds['OBJC_CLASS_$_UIDevice'] == 'relative_pointer'
    assert len(d['selrefs']) == 15
    assert 'gzipInflate' in d['selrefs']

    t = LISTING.read_text()
    n = len(re.findall(r'^\s+0x[0-9a-f]{8}\s+[0-9a-f]{8}\s', t, re.MULTILINE))
    assert n == 506, n
    assert '# -[CrystalManager loadFromSave]' in t

    print('b3e evidence: PASS')


if __name__ == '__main__':
    main()
