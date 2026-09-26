#!/usr/bin/env python3
"""CI-safe evidence guard for the Plant loader ARM differential (batch b4b).

Host, when both the pinned ELF and Unicorn are present: runs the full ARM
differential and asserts it matched. Without them (CI): asserts the recovered
C++ module, its CTest contract, the shared case list between contract and
harness, the CMake/CTest and workflow registrations, and that the decode the
module implements is still the b3b one (field offsets and store widths).
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
    header = (RECOVERED / 'plant_load_save_dict.h').read_text()
    source = (RECOVERED / 'plant_load_save_dict.cpp').read_text()
    contract = (ROOT / 'tools/test_plant_load_save_dict.cpp').read_text()
    harness = (ROOT / 'tools/test_plant_loadsave_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    decode = json.loads((NATIVE / 'treefamily_loadsavedictvalues.json').read_text())

    # Module documents the decode it implements.
    assert '0x009554a0' in header and 'b3b' in header
    assert '0x004c0b70' in header and '1800.0' in header
    assert 'plant_gene_clamp' in source and '1800.0' in source
    assert 'truncate16' in source

    # Shared case list between the CTest contract and the ARM harness. The C++
    # side needs its literals normalised (`0.0f` -> `0.0`, no trailing comma).
    contract_raw = re.sub(r'\s+', ' ', re.search(
        r'const std::vector<Case> cases = \{(.*?)\};', contract,
        re.DOTALL).group(1))
    contract_raw = re.sub(r'(\d)f\b', r'\1', contract_raw)
    contract_raw = contract_raw.replace('{', '(').replace('}', ')')
    contract_cases = eval('[' + contract_raw + ']', {'__builtins__': {}}, {})
    harness_cases = eval('[' + re.sub(
        r'\s+', ' ',
        re.search(r'CASES = \[(.*?)\n\]', harness, re.DOTALL).group(1)) + ']',
        {'__builtins__': {}}, {})
    assert len(contract_cases) == len(harness_cases) == 10, (
        len(contract_cases), len(harness_cases))
    assert [c[0] for c in contract_cases] == \
        [h['seasonOffset'] for h in harness_cases], 'seasonOffset column'
    assert [c[2] for c in contract_cases] == \
        [h['gatherProgress'] for h in harness_cases], 'gatherProgress column'
    assert [(c[8], c[9]) for c in contract_cases] == \
        [(h['saveTime'], h['worldTime']) for h in harness_cases], 'clock column'
    assert [c[6] for c in contract_cases] == \
        [h['maxAgeGene'] for h in harness_cases], 'gene column'

    # Registrations.
    assert 'plant_load_save_dict.cpp' in cmake
    assert 'recovered_plant_load_save_dict' in cmake
    assert 'test_plant_loadsave_arm_evidence.py' in workflow

    # The decode this module implements must still be the frozen b3b one.
    plant = next(c for c in decode['classes'] if c['class'] == 'Plant')
    widths = {c['key']: (c['ivar_offset'], c['store_kind'])
              for c in plant['keys']}
    assert widths['seasonOffset'] == (68, 'word_store'), widths
    assert widths['age'] == (72, 'float_store'), widths
    assert widths['gatherProgress'] == (80, 'word_store'), widths
    assert widths['hasFloweredThisSeason'] == (84, 'byte_store'), widths
    assert widths['flowering'] == (85, 'byte_store'), widths
    assert widths['frozen'] == (76, 'byte_store'), widths
    assert widths['maxAgeGene'] == (54, 'halfword_store'), widths
    assert widths['growthRateGene'] == (56, 'halfword_store'), widths
    assert plant['save_time_read_back'] is True
    assert plant['gene_clamp']['bounds'] == [1, 255]
    assert plant['gene_clamp']['helper'] == '0x004c0b70'
    assert plant['save_time_reset']['threshold_double'] == 1800.0

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/plant-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_plant_loadsave_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('Plant ARM differential failed')
        report = json.loads((out / 'plant-loadsave-arm-result.json').read_text())
        assert report['match'] is True
        assert report['cases'] == 10, report['cases']
        print(f"b4b ARM differential: {report['cases']} cases matched "
              f"(original 332-word ARM vs recovered C++ O0/O2)")
    else:
        print('b4b evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4b evidence: PASS')


if __name__ == '__main__':
    main()
