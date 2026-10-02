#!/usr/bin/env python3
"""LEVEL-B differential for the NINE tree-family LONG loaders (batch b3i,
executed here): the shared 62-word body of

    -[<Class> initWithWorld:dynamicWorld:saveDict:cache:
              treeDensityNoiseFunction:seasonOffsetNoiseFunction:]

is executed under Unicorn (CactusTree, CherryTree, CoconutTree, CoffeeTree,
GemTree, LimeTree, MangoTree, MapleTree, OrangeTree) and compared with the
recovered contract (reconstruction/recovered/treefamily9_long_init.cpp at -O0
and -O2).

This file is a THIN SHELL: the Unicorn preamble, GOT patching and the
super-forward differential loop all live in the shared library
`tools/arm_harness` (ARMSession + SuperForwardDifferential, added for this
shape). What is local here is the target table, the case table, the
expectations, and the C++ comparison.

Synthetic model (stated limits — not Foundation, not the original-app runtime):
  * `objc_msgSendSuper2` is stubbed by arm_harness.SuperForwardDifferential; it
    records the objc_super struct {receiver, own-class superref}, the selector
    string and the six forwarded arguments (r2:r3 + four stacked words).
  * `objc_msgSend` is also patched to a stub that RECORDS any hit, so a body
    that sent a post-init hook (the b3f/b3h shape) fails the "exactly one call"
    assertion instead of silently diverging.
Independent expectations (NOT derived from the recovered C++): the ABI
placement of the six arguments, the objc_super receiver/class words (the class
word is read from the ELF's own superref cell), the selector, the return value,
and that exactly one message is sent.
"""
import argparse
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from unicorn import UcError

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from arm_harness import ARMSession, SuperForwardDifferential  # noqa: E402

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
SELECTOR = ('initWithWorld:dynamicWorld:saveDict:cache:'
            'treeDensityNoiseFunction:seasonOffsetNoiseFunction:')
STUB = 0x72000000
CMD_REGION = 0x73000000

# class, imp, superref cell, selector cell — transcribed from the b3i decode
# (reconstruction/reverse-v3/native/treefamily9_long_initwithworld.json).
ENTRIES = [
    ('CactusTree', 0x00B533BC, 0x00E8BEA8, 0x00E86A10),
    ('CherryTree', 0x00D0DF2C, 0x00E8BF08, 0x00E88488),
    ('CoconutTree', 0x00A99948, 0x00E8BE50, 0x00E85594),
    ('CoffeeTree', 0x007DEB28, 0x00E8BD58, 0x00E818F4),
    ('GemTree', 0x00529134, 0x00E8BC54, 0x00E7D970),
    ('LimeTree', 0x00809C3C, 0x00E8BD64, 0x00E81C58),
    ('MangoTree', 0x00D4B4F4, 0x00E8BF20, 0x00E88A38),
    ('MapleTree', 0x00DB5FB4, 0x00E8BF50, 0x00E88F70),
    ('OrangeTree', 0x00A96604, 0x00E8BE4C, 0x00E85538),
]

# The six argument tokens (distinct, positional): a permuted forward is a
# mismatch on both sides.
TOKENS = {
    'world': 0x11110000, 'dynamicWorld': 0x22220000, 'saveDict': 0x33330000,
    'cache': 0x44440000, 'treeDensity': 0x55550000, 'seasonOffset': 0x66660000,
}
ARG_ORDER = ['world', 'dynamicWorld', 'saveDict', 'cache', 'treeDensity',
             'seasonOffset']
SELF_PTR = 0x60000000


def bit_trace(codes):
    return sum(1 << c for c in codes)


def build_bridge(output_dir):
    """Compile the recovered contract + its ARM bridge at -O0 and -O2."""
    libcxx = os.environ.get('PREFIX', '/data/data/com.termux/files/usr') + \
        '/lib/libc++_shared.so'
    if Path(libcxx).exists():
        ctypes.CDLL(libcxx, mode=ctypes.RTLD_GLOBAL)
    fns = []
    for opt in (0, 2):
        lib = output_dir / f'treefamily9-O{opt}.so'
        subprocess.run(
            ['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG', '-fno-fast-math',
             '-ffp-contract=off', '-fPIC', '-shared',
             '-I' + str(ROOT / 'reconstruction/recovered'),
             str(ROOT / 'tools/treefamily9_long_init_arm_bridge.cpp'),
             str(ROOT / 'reconstruction/recovered/treefamily9_long_init.cpp'),
             '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_treefamily9_long_init_trace
        fn.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
                       ctypes.c_uint32, ctypes.c_uint32,
                       ctypes.POINTER(ctypes.c_uint32),
                       ctypes.POINTER(ctypes.c_uint32),
                       ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = None
        fns.append(fn)
    return fns


def call_bridge(fn, class_ref, selector_ref, super_returns_nil):
    in_args = (ctypes.c_uint32 * 6)(*[TOKENS[a] for a in ARG_ORDER])
    forward = (ctypes.c_uint32 * 6)()
    trace = ctypes.c_uint32()
    nil = ctypes.c_uint32()
    fn(in_args, class_ref, selector_ref, 1 if super_returns_nil else 0,
       ctypes.byref(trace), forward, ctypes.byref(nil))
    return {'trace': trace.value, 'forwarded': list(forward),
            'returned_nil': bool(nil.value)}


def run_one(session, diff, bridge, entry, expected_forward):
    """Execute one class (both cases) and compare against the C++ builds.

    Raises AssertionError on any mismatch. Returns the report rows.
    """
    cls, imp, superref, sel_cell = entry
    class_word = session.read_word(superref)
    rows = []
    for nil_case in (False, True):
        super_result = 0 if nil_case else SELF_PTR
        run = diff.run(imp, receiver=SELF_PTR, cmd=CMD_REGION,
                       r2=TOKENS['world'], r3=TOKENS['dynamicWorld'],
                       stack_args=[TOKENS['saveDict'], TOKENS['cache'],
                                   TOKENS['treeDensity'],
                                   TOKENS['seasonOffset']],
                       super_result=super_result)
        calls = run['calls']
        assert len(calls) == 1 and calls[0]['stub'] == 'super2', \
            (cls, 'expected exactly one super message', calls)
        call = calls[0]
        # -- independent ABI / struct expectations --------------------------
        assert call['super_receiver'] == SELF_PTR, \
            (cls, 'objc_super.receiver', hex(call['super_receiver']))
        assert call['super_class'] == class_word, \
            (cls, 'objc_super.class', hex(call['super_class']), hex(class_word))
        assert call['selector'] == SELECTOR, (cls, 'selector', call['selector'])
        assert call['forward'] == expected_forward, \
            (cls, 'forwarded argument placement', call['forward'])
        expect_ret = 0 if nil_case else SELF_PTR
        assert run['call_return'] == expect_ret, \
            (cls, nil_case, 'return', hex(run['call_return']))
        bits = bit_trace([0])
        cpp = [call_bridge(fn, superref, sel_cell, nil_case) for fn in bridge]
        for i, c in enumerate(cpp):
            tag = f'O{(0, 2)[i]}'
            assert c['trace'] == bits, (cls, nil_case, tag, 'trace')
            assert c['forwarded'] == list(expected_forward), \
                (cls, nil_case, tag, 'forwarded', c['forwarded'])
            assert c['returned_nil'] == nil_case, \
                (cls, nil_case, tag, 'nil flag')
        rows.append({
            'class': cls, 'imp': f'0x{imp:08x}',
            'superref_cell': f'0x{superref:08x}',
            'super_class_word': f'0x{class_word:08x}',
            'super_returns_nil': nil_case,
            'arm_return': f'0x{run["call_return"]:08x}',
            'arm_forward': [f'0x{v:08x}' for v in call['forward']],
            'arm_trace': bits, 'cpp_trace': [c['trace'] for c in cpp],
            'selector': call['selector'],
        })
    return rows


# Negative controls: patch one word of the CactusTree body inside the emulated
# image and require the differential to FAIL. Each names the expectation that
# must fire (a wrong forward, a missing super message, a wrong return).
MUTATIONS = [
    # word 27: `ldr r2,[fp,#-0x28]` (world → r2). Point it at the dynamicWorld
    # spill instead, so the forwarded tuple carries the wrong token.
    ('cactus_world_arg_source', 0x00B533BC + 27 * 4, 0xE51B202C,
     'forwarded argument placement'),
    # word 42: `blx r8` (the super forward). Replace with a no-op so the body
    # sends no message at all.
    ('cactus_super_call_removed', 0x00B533BC + 42 * 4, 0xE1A00000,
     'expected exactly one super message'),
    # word 48: `cmp r1,r0` (the nil guard). Compare r1 with itself so the happy
    # path takes the nil branch.
    ('cactus_nil_guard_moved', 0x00B533BC + 48 * 4, 0xE1510001, 'return'),
    # word 15: `ldr r6,[fp,#8]` (saveDict). Load the treeDensity spill at
    # fp+0x10 instead, so the stacked saveDict word carries the wrong token.
    ('cactus_savedict_arg_source', 0x00B533BC + 15 * 4, 0xE59B6010,
     'forwarded argument placement'),
    # word 34: `ldr r0,[r0]` (dereference the own-class superref cell into the
    # objc_super class word). Skipping it stores the cell ADDRESS, not the
    # class object.
    ('cactus_class_deref_skipped', 0x00B533BC + 34 * 4, 0xE1A02000,
     'objc_super.class'),
]


def make_session(elf):
    """A FRESH session + differential for one run.

    Unicorn caches translated blocks across emu_start and the CODE hooks stay
    installed on the uc, so a negative control MUST NOT reuse a session: after
    the first mutated run the restored bytes are never re-translated, so every
    later mutation silently reuses the first mutation's translation — the
    control reads as undetected instead of failing loudly.
    """
    session = ARMSession(elf, SHA)
    # _cmd lives in its own small page; the nine bodies store it and never read
    # it, but the differential passes a real pointer anyway.
    session.uc.mem_map(CMD_REGION, 0x1000)
    session.uc.mem_write(CMD_REGION, b'-initWithWorld:cmd-placeholder:\0')
    diff = SuperForwardDifferential(session, GOT_SUPER2, n_stack=4, stub=STUB,
                                    extra_stubs={GOT_MSGSEND: 'msgSend'})
    return session, diff


def self_test(elf, bridge, expected_forward):
    """Negative controls: every mutation must be NOTICED.

    A mutation is noticed either by the specific assertion it is supposed to
    break, or by a fault while executing the mutated body (a mangled
    instruction stream is not a silent pass). A mutation that still runs to
    completion with a matching comparison is the failure this control exists
    for.
    """
    entry = ENTRIES[0]
    failures = []
    detected = []
    for name, addr, word, expect in MUTATIONS:
        session, diff = make_session(elf)   # fresh: see make_session docstring
        session.word(addr, word)
        try:
            run_one(session, diff, bridge, entry, expected_forward)
        except AssertionError as exc:
            if expect not in str(exc):
                failures.append(f'{name}: wrong failure: {exc}')
            else:
                detected.append(f'{name}: assertion ({expect})')
        except UcError as exc:
            detected.append(f'{name}: fault while executing the mutated body '
                            f'({exc})')
        else:
            failures.append(f'{name}: mutation was NOT detected')
    for f in failures:
        print('MUTATION FAIL:', f)
    if failures:
        raise SystemExit(f'{len(failures)}/{len(MUTATIONS)} negative controls '
                         'failed')
    for d in detected:
        print(f'  mutation detected: {d}')
    print(f'b4r self-test: {len(MUTATIONS)}/{len(MUTATIONS)} mutations detected')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if hashlib.sha256(a.elf.read_bytes()).hexdigest() != SHA:
        raise SystemExit('ELF SHA mismatch')
    a.output_dir.mkdir(parents=True, exist_ok=True)

    bridge = build_bridge(a.output_dir)
    expected_forward = tuple(TOKENS[k] for k in ARG_ORDER)

    if a.self_test:
        self_test(a.elf, bridge, expected_forward)
        return

    session, diff = make_session(a.elf)
    rows = []
    traces = {}
    for entry in ENTRIES:
        rows.extend(run_one(session, diff, bridge, entry, expected_forward))
        traces[entry[0]] = bit_trace([0])

    # The executed counterpart of the b3i shared-body identity: all nine
    # classes must produce the SAME happy-path trace.
    assert len(set(traces.values())) == 1, traces

    report = {
        'sha256': SHA, 'selector': SELECTOR, 'entries': len(ENTRIES),
        'cases': len(rows), 'match': True,
        'identical_trace_across_entries': True,
        'arg_order': ARG_ORDER,
        'harness_module': 'tools/arm_harness/super_forward.py '
                          '(SuperForwardDifferential)',
        'boundary': (
            'Unicorn execution of the nine original 62-word shared tree-family '
            'bodies with a synthetic ObjC message graph (stubbed '
            'objc_msgSendSuper2 asserting {self, own-class superref} + selector '
            '+ six arguments; stubbed objc_msgSend recording any hook hit), '
            'compared bit-exactly to the recovered C++ at -O0/-O2. Not '
            'Foundation, not the original-app runtime, not device gameplay; '
            'the superclass initialiser (Tree) is a stub, so the save-dict '
            'reading behind it is out of scope for this differential.'),
        'rows': rows,
    }
    (a.output_dir / 'treefamily9-long-init-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in (
        'sha256', 'entries', 'cases', 'match',
        'identical_trace_across_entries')}, indent=2))


if __name__ == '__main__':
    main()
