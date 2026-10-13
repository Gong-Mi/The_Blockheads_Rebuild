#!/usr/bin/env python3
"""CI-safe evidence guard for the Tree loader stage-1 ARM differential (b4d).

Host, when the pinned ELF and Unicorn are present: runs the differential and
asserts it matched. Without them (CI): asserts the recovered C++ module, its
CTest registration, the CMake/workflow registrations, the shared case table,
and that the b3a decode (scalar chain offsets/widths, 12-byte fruit records,
isStaticTree gate sites, write-only saveTime) is still the frozen one.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'tree_load_save_dict.h').read_text()
    source = (RECOVERED / 'tree_load_save_dict.cpp').read_text()
    contract = (ROOT / 'tools/test_tree_load_save_dict.cpp').read_text()
    harness = (ROOT / 'tools/test_tree_loadsave_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    decode = json.loads((NATIVE / 'tree_loadsavedictvalues.json').read_text())

    assert '0x004c2df0' in header and 'STAGE 1' in header
    assert 'ALWAYS-ON' in header
    assert 'height' in source and 'age' in source
    assert '0x00a12f24' in header and 'tileIsKindOfSelf' in header
    assert 'tree_load_save_dict_stage1' in source

    # Shared case table (C++ vs harness), column by column on the shared inputs.
    contract_raw = re.sub(r'\s+', ' ', re.search(
        r'const std::vector<Case> cases = \{(.*?)\};', contract, re.DOTALL).group(1))
    contract_raw = re.sub(r'(\d)f\b', r'\1', contract_raw)
    contract_raw = contract_raw.replace('{', '(').replace('}', ')')
    contract_raw = contract_raw.replace('INT32_MAX', '2147483647') \
                               .replace('INT32_MIN', '-2147483648')
    contract_cases = eval('[' + contract_raw + ']', {'__builtins__': {}}, {})
    harness_cases = eval('[' + re.sub(
        r'\s+', ' ', re.search(r'CASES = \[(.*?)\n\]', harness, re.DOTALL).group(1)) + ']',
        {'__builtins__': {}}, {})
    assert len(contract_cases) == len(harness_cases) == 5
    assert [c[0] for c in contract_cases] == \
        [h['treeSeasonOffset'] for h in harness_cases]
    assert [c[4] for c in contract_cases] == [h['height'] for h in harness_cases]
    assert [c[5] for c in contract_cases] == [h['age'] for h in harness_cases]
    assert [h['dead'] for h in harness_cases] == [c[1] for c in contract_cases]

    assert 'tree_load_save_dict.cpp' in cmake
    assert 'recovered_tree_load_save_dict_stage1' in cmake
    assert 'test_tree_loadsave_arm_evidence.py' in workflow

    # The b3a decode this stage implements must still be the frozen one.
    chains = {c['key']: (c['ivar_offset'], c['store_kind'])
              for c in decode['chains']}
    assert chains == {'treeSeasonOffset': (84, 'word_store'),
                      'dead': (104, 'byte_store'),
                      'timeDied': (112, 'double_store'),
                      'removeCheckCount': (120, 'float_store')}, chains
    assert decode['treeFruit']['record_stride'] == 0xc
    assert set(decode['treeFruit']['fruit_keys']) == {'pos.x', 'pos.y',
                                                      'hasCreatedFreeBlockThisSeason'}
    assert decode['isStaticTree_gate']['bne'] == '0x004c3570'
    assert decode['saveTime_read_back'] is False
    assert 'saveTime' not in decode['pool_keys']

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/tree-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_tree_loadsave_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('Tree stage-1 ARM differential failed')
        report = json.loads((out / 'tree-loadsave-arm-result.json').read_text())
        assert report['match'] is True and report['stage'] == 1
        assert report['cases'] == 5, report['cases']
        # The executed key order is the corrected always-on set.
        assert report['rows'][0]['keys_requested'] == sorted(
            ['treeSeasonOffset', 'dead', 'timeDied', 'removeCheckCount',
             'treeFruit', 'height', 'age']), report['rows'][0]['keys_requested']
        assert report['rows'][0]['enumerate_calls'] >= 1
        print(f"b4d ARM differential: stage {report['stage']}, "
              f"{report['cases']} cases matched")
    else:
        print('b4d evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4d evidence: PASS')


if __name__ == '__main__':
    main()
