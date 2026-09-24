#!/usr/bin/env python3
"""CI-safe evidence guard for FreightCar initWithWorld:... ARM differential (batch b4h).

Host, when both the pinned ELF and Unicorn are present: runs the differential
and asserts all cases match bit-exactly against -O0 and -O2.
Without them (CI): asserts the recovered C++ contract, CTest registration,
CMake/workflow registrations, trace code drift check, and that the b3n decode
of FreightCar is still the frozen one.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RECOVERED = ROOT / 'reconstruction/recovered'
ELF = Path.home() / 'blockheads-work/extracted/lib/armeabi-v7a/libApplication.so'
IMP = '0x00a403e8'


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'freight_car_init.h').read_text()
    source = (RECOVERED / 'freight_car_init.cpp').read_text()
    contract = (ROOT / 'tools/test_freight_car_init.cpp').read_text()
    harness = (ROOT / 'tools/test_freight_car_init_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    listing = (NATIVE / 'disasm_freightcar_initwithworld.txt').read_text()
    hooks = json.loads((NATIVE / 'hooks6_persistence_closeout.json').read_text())

    # Contract header documents IMP and batch
    assert '0x00a403e8' in header and 'b4h' in header
    assert 'initWithWorld:dynamicWorld:saveDict:chestSaveDict:cache:' in header
    assert 'generated/trace_codes.h' in header

    # Trace codes single source of truth
    generated = (RECOVERED / 'generated/trace_codes.h').read_text()
    for snippet in ('MsgSendSuper', 'ChestAlloc', 'ChestInitWithWorld',
                    'ChestSetProxyObjectOwner', 'ChestSetFloatPosAndUpdatePosition'):
        assert snippet in generated, snippet

    # Trace codes: single source of truth check
    gen = subprocess.run([sys.executable,
                          str(ROOT / 'tools/gen_trace_codes.py'), '--check'],
                         capture_output=True, text=True)
    assert gen.returncode == 0, gen.stdout + gen.stderr
    assert 'trace_codes_gen' in harness

    # Contract source stores chest at 220 and sets owner + position
    assert 'store_word(result.image, 220, in.chest_init_token)' in source
    assert 'ChestSetProxyObjectOwner' in source
    assert 'ChestSetFloatPosAndUpdatePosition' in source

    # Contract test asserts cases
    assert 'happy_path' in harness
    assert 'nil_super' in harness
    assert 'recovered_freight_car_init' in cmake
    assert 'test_freight_car_init_arm_evidence.py' in workflow

    # The b3n decode for FreightCar must still match
    fc_entry = next((c for c in hooks['classes'] if c['class'] == 'FreightCar'), None)
    assert fc_entry is not None, 'FreightCar missing from hooks6'
    assert fc_entry['imp'] == IMP
    assert fc_entry['code_words'] == 134
    assert fc_entry['runtime_superclass'] == 'TrainCar'

    assert '0x00a403e8' in listing
    assert '0x00a40600' in listing

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/freight-car-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_freight_car_init_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('FreightCar ARM differential failed')
        report = json.loads((out / 'freight_car_init_arm_result.json').read_text())
        assert report['match'] is True
        assert report['cases'] >= 5
        print(f"b4h ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4h evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4h evidence: PASS')


if __name__ == '__main__':
    main()
