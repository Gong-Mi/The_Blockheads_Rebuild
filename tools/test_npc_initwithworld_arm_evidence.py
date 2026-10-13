#!/usr/bin/env python3
"""CI-safe evidence guard for the NPC loader ARM differential (batch b4a).

Host, when both the pinned ELF and Unicorn are present: runs the full ARM
differential and asserts it matched. Without them (CI): asserts the structural
artifacts — the recovered C++ module, its CTest contract, the differential's
case list matching the contract test's list, the CMake/CTest registration, the
workflow registration of this guard, and the b3g decode JSON that the module
claims to implement.
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
CASES = [0, 1, 2, 3, 1024, 1048576, 1 << 23, 123456789, 1073741823,
         1 << 30, 2147483646, 2147483647, -1, -2147483648]


def have_unicorn():
    try:
        import unicorn  # noqa: F401
        return True
    except Exception:
        return False


def main():
    header = (RECOVERED / 'npc_init_with_world.h').read_text()
    source = (RECOVERED / 'npc_init_with_world.cpp').read_text()
    contract = (ROOT / 'tools/test_npc_init_with_world.cpp').read_text()
    harness = (ROOT / 'tools/test_npc_initwithworld_arm.py').read_text()
    cmake = (RECOVERED / 'CMakeLists.txt').read_text()
    workflow = (ROOT / '.github/workflows/method-save.yml').read_text()
    decode = json.loads((NATIVE / 'npc_initwithworld.json').read_text())

    # The module documents what it implements and where the decode lives.
    assert 'randomHarmFromHungerTimer@144' in header
    assert '0x00644b24' in header and 'b3g' in header
    assert 'npc_hunger_timer_seed' in source and '2147483648.0f' in source
    assert 'vcvt.f32.s32' in source and 'vdiv' in source and 'vmul' in source \
        and 'vadd' in source
    assert 'NpcInitCall::SuperInit' in source

    # The contract test and the ARM differential must exercise the same inputs.
    contract_values = re.search(r'values = \{([^}]*)\}', contract)
    assert contract_values, 'contract value list missing'
    contract_cases = eval('[' + re.sub(r'\s+', ' ', contract_values.group(1)) + ']',
                          {'__builtins__': {}}, {})
    harness_cases = eval('[' + re.sub(
        r'\s+', ' ', re.search(r'CASES = \[([^\]]*)\]', harness).group(1)) + ']',
        {'__builtins__': {}}, {})
    assert contract_cases == CASES, contract_cases
    assert harness_cases == CASES, harness_cases

    # Registration in both places.
    assert 'npc_init_with_world.cpp' in cmake
    assert 'recovered_npc_init_with_world' in cmake
    assert 'test_npc_initwithworld_arm_evidence.py' in workflow

    # The decode this module implements must still be the frozen one.
    assert decode['batch'] == 'b3g'
    seed = decode['hunger_timer_seed']
    assert 'lrand48' in seed['formula'] and seed['ivar_offset'] == 144
    assert seed['determinism'].startswith('NON-deterministic')
    assert decode['lrand48_chain']['import'] == 'lrand48'
    assert decode['lrand48_chain']['wrapper'] == '0x006445d8'

    if ELF.exists() and have_unicorn():
        out = ROOT / 'scratch/npc-arm-differential'
        r = subprocess.run([sys.executable, str(ROOT / 'tools/test_npc_initwithworld_arm.py'),
                            str(ELF), '--output-dir', str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout + r.stderr)
            raise SystemExit('ARM differential failed')
        report = json.loads((out / 'npc-initwithworld-arm-result.json').read_text())
        assert report['match'] is True
        assert report['cases'] == len(CASES) + 1, report['cases']
        assert report['boundary'].startswith('Unicorn execution')
        print(f"b4a ARM differential: {report['cases']} cases matched "
              f"(original ARM vs recovered C++ O0/O2)")
    else:
        print('b4a evidence: static contract only (no pinned ELF or no Unicorn '
              'on this host)')

    print('b4a evidence: PASS')


if __name__ == '__main__':
    main()
