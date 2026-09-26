#!/usr/bin/env python3
"""CI-safe evidence guard for the NPC loadValuesFromSaveDict: ARM
differential (batch b4f).

Host, when both the pinned ELF and Unicorn are present: runs the full ARM
differential and asserts it matched. Without them (CI): asserts the
structural artifacts — the recovered C++ module, its CTest contract, the
differential's case list, the CMake/CTest registration, the workflow
registration of this guard, and the b3n decode JSON the module claims to
implement.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
CASES = ['all_present_old_nil', 'all_present_old_set', 'missing_fullness',
         'missing_laycooldown', 'missing_breed', 'missing_currentblockhead',
         'missing_tamecounts', 'missing_tamedclientid_name', 'truncations',
         'float_edges']


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'npc_load_values_from_save_dict.h').read_text()
    source = (RECOVERED / 'npc_load_values_from_save_dict.cpp').read_text()
    contract = (ROOT / 'tools/test_npc_load_values.cpp').read_text()
    harness = (ROOT / 'tools/test_npc_loadvalues_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    decode = json.loads((NATIVE / 'npc_loadvalues_keys.json').read_text())

    # The module documents what it implements and where the decode lives.
    assert '0x00643b20' in header and 'b3n' in header and 'b4f' in header
    assert 'loadValuesFromSaveDict:' in header
    assert 'kNpcLoadDictCopyToken' in header
    # Trace-code names moved to the single-source generated header (b4f fix).
    assert 'generated/trace_codes.h' in header
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('ObjectForKeyFullness', 'ObjectForKeyLayCooldownTimer',
                    'ObjectForKeyBreed', 'ObjectForKeyCurrentBlockheadIndex',
                    'DictionaryWithDictionary'):
        assert snippet in generated, snippet
    # The four group gates plus the -1 default store are in the contract body.
    for snippet in ('present[static_cast<int>(Key::Fullness)]',
                    'present[static_cast<int>(Key::LayCooldownTimer)]',
                    'present[static_cast<int>(Key::Breed)]',
                    'present[static_cast<int>(Key::CurrentBlockheadIndex)]',
                    'store_word(image, 136, 0xffffffffu)'):
        assert snippet in source, snippet
    assert 'store_halfword(image, 54' in source
    assert 'store_halfword(image, 96' in source
    assert 'store_halfword(image, 98' in source

    # The contract test pins the same facts the harness executes.
    for snippet in ('0x3F8CCCCD', '4464', '0x5678', '0xFFFFFFFF',
                    'kNpcLoadDictCopyToken', 'has 37 calls'):
        assert snippet in contract, snippet

    # Harness and guard agree on the case list.
    for name in CASES:
        assert f"'{name}'" in harness, name
    assert 'COPY_TOKEN = 0x00D1C700' in harness
    # Trace codes: single source of truth, no drift possible.
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'trace_codes_gen' in harness  # single-source trace codes (b4f fix)

    # Registration in both places.
    assert 'npc_load_values_from_save_dict.cpp' in cmake
    assert 'recovered_npc_load_values' in cmake
    assert 'test_npc_loadvalues_arm_evidence.py' in workflow

    # The decode this module implements must still be the frozen one.
    assert decode['method'] == 'NPC -[loadValuesFromSaveDict:]'
    assert decode['imp'] == '0x00643b20'
    assert decode['pairing_count'] == 15
    offsets = {p['key']: p['ivar_offset'] for p in decode['pairings']}
    assert offsets['fullness'] == 68 and offsets['damage'] == 54
    assert offsets['breed'] == 96 and offsets['name'] == 92
    assert offsets['tameCountsByClientID'] == 104
    assert offsets['currentBlockheadIndex'] == 136
    assert decode['dictionary_copy_site'] == '0x006442d4'
    assert len(decode['guard_probes']) == 4

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/npc-loadvalues-arm-differential'
        r = subprocess.run([sys.executable,
                            str(ROOT / 'tools/test_npc_loadvalues_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('ARM differential failed')
        report = json.loads((out / 'npc-loadvalues-arm-result.json').read_text())
        assert report['match'] is True
        assert report['cases'] == len(CASES), report['cases']
        assert report['boundary'].startswith('Unicorn execution')
        print(f"b4f ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4f evidence: static contract only (no pinned ELF or no '
              'Unicorn on this host)')

    print('b4f evidence: PASS')


if __name__ == '__main__':
    main()
