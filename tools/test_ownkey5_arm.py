#!/usr/bin/env python3
"""Thin Level-B differential harness for the b3j "forward-then-read own key"
family (batch ownkey5): AppleTree / TrainStation / Plant / GatherBlock / Yak.

Five original ARM32 `initWithWorld:...` loaders share one executed shape
(objc_msgSendSuper2 forward -> nil guard -> per-class own steps -> return self).
The whole Unicorn preamble, the super/msgSend receiver-trace stubs and the
ivar-store hooks live in tools/arm_harness/ownkey.py; this file is only the
per-method table: target IMP, selectors, key sets, store points and the case
list, plus expectations computed independently of the recovered C++.

Every method's ARM run (original instructions, real CFString keys, real clamp
of the message order) is compared bit-for-bit against the recovered shared
engine + thin descriptor built at -O0 and -O2:
  - the full 32-bit ivar image at each decoded store offset,
  - the (code, arg) message trace (single-source trace codes),
  - the returned receiver (self, or nil on the nil-super path).
"""
import argparse
import ctypes
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_harness import ARMSession, FixtureGraph          # noqa: E402
from arm_harness.ownkey import OwnKeyRunner, f32          # noqa: E402
from trace_codes_gen import OWNKEY5_INIT_CODES as C       # noqa: E402

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
LONG = ('initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:'
        'seasonOffsetNoiseFunction:')
SHORT = 'initWithWorld:dynamicWorld:saveDict:cache:'

SELF = 0x60000000
WORLD = 0x51110001
DYN = 0x51110002
SAVE = 0x51110003
CACHE = 0x51110004
DENSITY = 0x51110005
SEASON = 0x51110006

DESCRIPTORS = {
    'AppleTree': {
        'name': 'AppleTree', 'imp': 0x009BD3B0, 'selector': LONG,
        'super_selector': LONG, 'forward_long': True,
        'superref_slot': 0x00E8BDEC, 'image_size': 160,
        'key_reads': [{'key': 'availableFood', 'conv': 'floatValue'}],
        'stores': [(0x009BD50C, 'r0', 136)], 'preload_ivars': {},
    },
    'TrainStation': {
        'name': 'TrainStation', 'imp': 0x00B38F88, 'selector': SHORT,
        'super_selector': SHORT, 'forward_long': False,
        'superref_slot': 0x00E8BE8C, 'image_size': 160,
        'key_reads': [{'key': 'text', 'conv': 'retain'}],
        'stores': [(0x00B390D8, 'r1', 128)], 'preload_ivars': {},
    },
    'Plant': {
        'name': 'Plant', 'imp': 0x009559D0, 'selector': LONG,
        'super_selector': SHORT, 'forward_long': False,
        'superref_slot': 0x00E8BDC4, 'image_size': 96,
        'key_reads': [],
        'stores': [(0x00955AB0, 'r1', 60), (0x00955AC8, 'r1', 64)],
        'preload_ivars': {8: 'dyn_ivar', 16: 'pos_x', 20: 'pos_y'},
    },
    'GatherBlock': {
        'name': 'GatherBlock', 'imp': 0x008695A0, 'selector': SHORT,
        'super_selector': SHORT, 'forward_long': False,
        'superref_slot': 0x00E8BD94, 'image_size': 96,
        # EXECUTED CORRECTION of the b3j static decode: the two key chains were
        # paired the other way round. The ARM reads `timer` FIRST and puts it
        # through floatValue + a vcvt.u32.f32 / vcvt.f32.u32 round trip into
        # timer's own ivar @56, then reads `lastKnownGatherValue` with intValue
        # into @60. Confirmed against the ivar symbol table
        # (OBJC_IVAR_$_GatherBlock.timer = 56, .lastKnownGatherValue = 60) and
        # the executed selector sequence
        # (objectForKey:timer -> floatValue -> store@56, then
        #  objectForKey:lastKnownGatherValue -> intValue -> store@60).
        'key_reads': [{'key': 'timer', 'conv': 'floatValue'},
                      {'key': 'lastKnownGatherValue', 'conv': 'intValue'}],
        'stores': [(0x0086971C, 'r0', 56), (0x00869758, 'r1', 60)],
        'preload_ivars': {},
    },
    'Yak': {
        'name': 'Yak', 'imp': 0x0095DAE4, 'selector': SHORT,
        'super_selector': SHORT, 'forward_long': False,
        'superref_slot': 0x00E8BDCC, 'image_size': 1160,
        # EXECUTED CORRECTION of the b3j static decode: the read ORDER is
        # milk first (-> @1136, milk's own ivar) then hair (-> @1140), not
        # hair first. Confirmed by the executed selector sequence
        # (objectForKey:milk -> floatValue -> store@1136, then
        #  objectForKey:hair -> floatValue -> store@1140) and the ivar symbol
        # table (OBJC_IVAR_$_Yak.milk = 1136, .hair = 1140).
        'key_reads': [{'key': 'milk', 'conv': 'floatValue'},
                      {'key': 'hair', 'conv': 'floatValue'}],
        'stores': [(0x0095DC60, 'r0', 1136), (0x0095DCA0, 'r0', 1140)],
        'preload_ivars': {},
    },
}


def case(**kw):
    base = dict(self=SELF, world=WORLD, dyn=DYN, save=SAVE, cache=CACHE,
                density=DENSITY, season=SEASON, super_nil=0, dyn_ivar=0x5A5A0001,
                pos_x=0x00000011, pos_y=0x00000022, otype=0x00000033, kv=[])
    base.update(kw)
    return base


NAN = 0x7FC00000
CASES = {
    'AppleTree': [
        case(name='happy', kv=[f32(1.5)]),
        case(name='positive_zero', kv=[0x00000000]),
        case(name='negative_zero', kv=[0x80000000]),
        case(name='plus_inf', kv=[0x7F800000]),
        case(name='nan', kv=[NAN]),
        case(name='subnormal', kv=[0x00000001]),
        case(name='large_finite', kv=[f32(65504.0)]),
        case(name='negative', kv=[f32(-3.25)]),
        case(name='nil_super', super_nil=1, kv=[f32(7.0)]),
        case(name='distinct_tokens', world=0xA1, dyn=0xA2, save=0xA3, cache=0xA4,
             density=0xA5, season=0xA6, kv=[f32(2.25)]),
    ],
    'TrainStation': [
        case(name='happy', kv=[0xC0FFEE01]),
        case(name='zero_token', kv=[0x00000000]),
        case(name='all_ones', kv=[0xFFFFFFFF]),
        case(name='low_token', kv=[0x00000007]),
        case(name='nil_super', super_nil=1, kv=[0xC0FFEE01]),
        case(name='distinct_tokens', world=0xB1, dyn=0xB2, save=0xB3, cache=0xB4,
             kv=[0x0BADF00D]),
    ],
    'Plant': [
        case(name='happy', density=0x11110001, season=0x11110002),
        case(name='distinct_args', density=0x22220001, season=0x22220002,
             dyn_ivar=0x22220003, pos_x=0x22220004, pos_y=0x22220005,
             otype=0x22220006),
        case(name='zero_args', density=0, season=0, dyn_ivar=0, pos_x=0,
             pos_y=0, otype=0),
        case(name='negative_otype', otype=0xFFFFFFFF, pos_x=0xDEADBEEF),
        case(name='nil_super', super_nil=1, density=0x33330001,
             season=0x33330002),
        case(name='nil_dyn_ivar', dyn_ivar=0x00000000),
    ],
    'GatherBlock': [
        case(name='happy', kv=[f32(12.5), 0x00000064]),
        case(name='fraction_truncated', kv=[f32(3.999), 7]),
        case(name='negative_float_zero', kv=[f32(-2.5), 0xFFFFFFFF]),
        case(name='nan_float', kv=[NAN, 0x80000000]),
        case(name='huge_float_saturate', kv=[f32(1e30), 0x7FFFFFFF]),
        case(name='zero', kv=[0x00000000, 0x00000000]),
        case(name='int_min', kv=[f32(1.0), 0x80000000]),
        case(name='nil_super', super_nil=1, kv=[f32(9.0), 42]),
    ],
    'Yak': [
        case(name='happy', kv=[f32(5.5), f32(2.25)]),
        case(name='zero', kv=[0x00000000, 0x80000000]),
        case(name='same_values', kv=[f32(1.0), f32(1.0)]),
        case(name='nan_and_inf', kv=[NAN, 0x7F800000]),
        case(name='subnormal', kv=[0x00000001, 0x00000002]),
        case(name='nil_super', super_nil=1, kv=[f32(1.0), f32(2.0)]),
        case(name='distinct_tokens', world=0xD1, dyn=0xD2, save=0xD3, cache=0xD4,
             kv=[f32(-0.5), f32(1024.0)]),
    ],
}


def f32_of(bits):
    return struct.unpack('<f', struct.pack('<I', bits & 0xFFFFFFFF))[0]


def float_through_uint32(bits):
    """ARM VCVT.U32.F32 (round toward zero: NaN/negative -> 0, >= 2^32 ->
    0xFFFFFFFF) then VCVT.F32.U32. Independent of the recovered C++."""
    value = f32_of(bits)
    if value != value or value < 0.0:
        converted = 0
    elif value >= 4294967296.0:
        converted = 0xFFFFFFFF
    else:
        converted = int(value)
    return f32(float(converted))


def expect_ivars(name, c):
    """Independent expectations: the exact ivar value each ARM store must land
    (returns {offset: 32-bit bits})."""
    if c['super_nil']:
        return {}
    if name == 'AppleTree':
        return {136: c['kv'][0] & 0xFFFFFFFF}
    if name == 'TrainStation':
        return {128: c['kv'][0] & 0xFFFFFFFF}
    if name == 'Plant':
        return {60: c['density'], 64: c['season']}
    if name == 'GatherBlock':
        # timer -> floatValue + vcvt round trip -> @56;
        # lastKnownGatherValue -> intValue -> @60 (executed correction).
        return {56: float_through_uint32(c['kv'][0]),
                60: c['kv'][1] & 0xFFFFFFFF}
    if name == 'Yak':
        # executed correction: milk -> floatValue -> @1136 first, then
        # hair -> floatValue -> @1140, then updateTextures
        return {1136: c['kv'][0] & 0xFFFFFFFF, 1140: c['kv'][1] & 0xFFFFFFFF}
    raise AssertionError(name)


def expect_trace(name, c):
    if c['super_nil']:
        return [(C['MsgSendSuper'], 6 if name == 'AppleTree' else 4)]
    if name == 'AppleTree':
        return [(C['MsgSendSuper'], 6), (C['ObjectForKey'], 0),
                (C['FloatValue'], c['kv'][0] & 0xFFFFFFFF),
                (C['StoreIvar'], 136)]
    if name == 'TrainStation':
        return [(C['MsgSendSuper'], 4), (C['ObjectForKey'], 0),
                (C['Retain'], c['kv'][0] & 0xFFFFFFFF), (C['StoreIvar'], 128),
                (C['InitSubDerivedItems'], 0)]
    if name == 'Plant':
        return [(C['MsgSendSuper'], 4), (C['StoreIvar'], 60),
                (C['StoreIvar'], 64), (C['LoadSaveDictValues'], 0),
                (C['ObjectType'], c['otype']),
                (C['DynamicWorldChangedAtPos'], c['pos_x'])]
    if name == 'GatherBlock':
        # executed correction: timer -> floatValue (+vcvt round trip) -> @56
        # first, then lastKnownGatherValue -> intValue -> @60
        return [(C['MsgSendSuper'], 4), (C['ObjectForKey'], 0),
                (C['FloatValue'], c['kv'][0] & 0xFFFFFFFF), (C['StoreIvar'], 56),
                (C['ObjectForKey'], 1), (C['IntValue'], c['kv'][1] & 0xFFFFFFFF),
                (C['StoreIvar'], 60)]
    if name == 'Yak':
        # executed correction: milk -> @1136 first, then hair -> @1140
        return [(C['MsgSendSuper'], 4), (C['ObjectForKey'], 0),
                (C['FloatValue'], c['kv'][0] & 0xFFFFFFFF), (C['StoreIvar'], 1136),
                (C['ObjectForKey'], 1), (C['FloatValue'], c['kv'][1] & 0xFFFFFFFF),
                (C['StoreIvar'], 1140), (C['UpdateTextures'], 0)]
    raise AssertionError(name)


class RecoveredIn(ctypes.Structure):
    _fields_ = [('self_token', ctypes.c_uint32), ('world_token', ctypes.c_uint32),
                ('dynamic_world_token', ctypes.c_uint32),
                ('save_dict_token', ctypes.c_uint32),
                ('cache_token', ctypes.c_uint32),
                ('tree_density_token', ctypes.c_uint32),
                ('season_offset_token', ctypes.c_uint32),
                ('super_returns_nil', ctypes.c_uint32),
                ('ivar_dynamic_world', ctypes.c_uint32),
                ('ivar_pos_x', ctypes.c_uint32), ('ivar_pos_y', ctypes.c_uint32),
                ('object_type', ctypes.c_uint32)]


def build_bridges(repo, out_dir):
    fns = []
    for opt in (0, 2):
        lib = out_dir / f'ownkey5-O{opt}.so'
        subprocess.run(
            ['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG', '-fno-fast-math',
             '-ffp-contract=off', '-fPIC', '-shared',
             '-I' + str(repo / 'reconstruction/recovered'),
             str(repo / 'tools/ownkey5_init_arm_bridge.cpp'),
             str(repo / 'reconstruction/recovered/ownkey5_init.cpp'),
             str(repo / 'reconstruction/recovered/ownkey_loader.cpp'),
             '-o', str(lib)], check=True)
        libcxx = Path('/data/data/com.termux/files/usr/lib/libc++_shared.so')
        if libcxx.exists():
            ctypes.CDLL(str(libcxx), mode=ctypes.RTLD_GLOBAL)
        dll = ctypes.CDLL(str(lib))
        fn = dll.recovered_ownkey5_run
        fn.argtypes = [ctypes.c_int, ctypes.POINTER(RecoveredIn),
                       ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
                       ctypes.POINTER(ctypes.c_uint32),
                       ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint32,
                       ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                       ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = ctypes.c_uint32
        fns.append(fn)
    return fns


def run_cpp(fn, which, c, image_size, presets=()):
    inb = RecoveredIn(
        self_token=c['self'], world_token=c['world'],
        dynamic_world_token=c['dyn'], save_dict_token=c['save'],
        cache_token=c['cache'], tree_density_token=c['density'],
        season_offset_token=c['season'], super_returns_nil=c['super_nil'],
        ivar_dynamic_world=c['dyn_ivar'], ivar_pos_x=c['pos_x'],
        ivar_pos_y=c['pos_y'], object_type=c['otype'])
    kv = (ctypes.c_uint32 * max(1, len(c['kv'])))(*c['kv']) if c['kv'] \
        else (ctypes.c_uint32 * 1)()
    # Pre-existing ivar state, declared by the SAME descriptor the ARM side
    # uses, so both runners start from an identical image.
    presets = list(presets)
    po = (ctypes.c_uint32 * max(1, len(presets)))(*[o for o, _ in presets]) \
        if presets else (ctypes.c_uint32 * 1)()
    pv = (ctypes.c_uint32 * max(1, len(presets)))(*[v for _, v in presets]) \
        if presets else (ctypes.c_uint32 * 1)()
    image = ctypes.create_string_buffer(image_size)
    tb = ctypes.create_string_buffer(16 * 8)
    returned = ctypes.c_uint32(0)
    n = fn(which, ctypes.byref(inb), kv, len(c['kv']), po, pv, len(presets),
           image, image_size, tb, 16, ctypes.byref(returned))
    trace = []
    for i in range(n):
        rec = tb.raw[i * 8:(i + 1) * 8]
        trace.append((rec[0], struct.unpack('<I', rec[4:8])[0]))
    return returned.value, image.raw, trace


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    repo = Path(__file__).resolve().parents[1]
    fns = build_bridges(repo, a.output_dir)

    order = ['AppleTree', 'TrainStation', 'Plant', 'GatherBlock', 'Yak']
    rows = []
    total = 0
    status = {}
    failures = []
    for which, name in enumerate(order):
        desc = DESCRIPTORS[name]
        # A FRESH session per method. Unicorn caches translated blocks and the
        # per-runner CODE hooks accumulate on a shared uc, so a second runner
        # would fire the FIRST runner's super/send stubs (asserting a stale
        # own_class and receiver) against a different method body.
        session = ARMSession(a.elf, SHA)
        graph = FixtureGraph(session.uc)
        runner = OwnKeyRunner(session, graph, desc)
        print(f'--- {name}: own_class=0x{runner.own_class:08x}', flush=True)
        method_cases = 0
        method_failures = []
        # FAILURE DOMAINS ARE SEPARATE: one method's mismatch must not abort the
        # batch, or the methods that already matched lose their report too.
        for c in CASES[name]:
            try:
                returned, arm_image, arm_trace = runner.run_case(c)
                expected_ret = 0 if c['super_nil'] else c['self']
                assert returned == expected_ret, (name, c['name'], 'ret',
                                                  hex(returned))
                # independent expectations (no dependence on the recovered C++).
                exp_trace = expect_trace(name, c)
                assert arm_trace == exp_trace, (name, c['name'], 'trace',
                                                arm_trace, exp_trace)
                for off in expect_ivars(name, c):
                    got = struct.unpack('<I', arm_image[off:off + 4])[0]
                    want = expect_ivars(name, c)[off]
                    assert got == want, (name, c['name'], 'ivar', off, hex(got),
                                         hex(want))
                if c['super_nil']:
                    # The nil guard must leave the instance EXACTLY at its
                    # pre-state: an untouched method must not write anything,
                    # and the pre-existing ivars (declared in the descriptor)
                    # stay.
                    pre = bytearray(desc['image_size'])
                    for off, key in desc.get('preload_ivars', {}).items():
                        struct.pack_into('<I', pre, off, c[key])
                    assert arm_image == bytes(pre), \
                        (name, 'nil-super image must stay at the pre-state')
                # differential vs recovered C++ at -O0 and -O2.
                for opt, fn in zip((0, 2), fns):
                    cret, cimage, ctrace = run_cpp(
                        fn, which, c, desc['image_size'],
                        presets=[(off, c[key]) for off, key
                                 in desc.get('preload_ivars', {}).items()])
                    assert cret == returned, (name, c['name'], f'-O{opt}', 'ret')
                    assert cimage == arm_image, (name, c['name'], f'-O{opt}',
                                                 'image')
                    assert ctrace == arm_trace, (name, c['name'], f'-O{opt}',
                                                 'trace', ctrace, arm_trace)
            except Exception as exc:                      # noqa: BLE001
                method_failures.append(f"{c['name']}: "
                                       f'{type(exc).__name__}: {exc}')
                continue
            rows.append({'class': name, 'case': c['name'],
                         'trace_len': len(arm_trace)})
            method_cases += 1
            total += 1
        if method_failures:
            status[name] = 'FAILED'
            failures.append((name, method_failures))
            print(f'    {name}: {method_cases}/{len(CASES[name])} cases '
                  f'matched, {len(method_failures)} failed', flush=True)
            for f in method_failures:
                print(f'      {f}', flush=True)
        else:
            status[name] = 'MATCHED'
            print(f'    {name}: {method_cases}/{len(CASES[name])} cases '
                  'matched', flush=True)

    report = {
        'sha256': SHA, 'batch': 'ownkey5', 'methods': order,
        'cases': total, 'match': not failures,
        'per_method': {n: len(CASES[n]) for n in order},
        'per_method_status': status,
        'per_method_failures': {n: f for n, f in failures},
        'boundary': (
            'Unicorn execution of the five original ARM32 bodies (AppleTree '
            '102w long, TrainStation 105w, Plant 114w long, GatherBlock 128w, '
            'Yak 134w). The real objc_msgSendSuper2 forward shape, the nil '
            'guard, the own-key reads through the real ELF CFString keys, the '
            'ivar stores and the post-init hooks execute against the original '
            'instructions bit-for-bit and are compared to the recovered shared '
            'engine + thin per-class descriptors at -O0/-O2. Not Foundation, '
            'not the original-app runtime, not device gameplay; the superclass '
            'initialiser, the save dictionary and the hook bodies are stubs.'),
        'rows': rows,
    }
    (a.output_dir / 'ownkey5-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'cases', 'match',
                                             'per_method',
                                             'per_method_status')}, indent=2))
    if failures:
        names = ', '.join(n for n, _ in failures)
        raise SystemExit(f'ownkey5: {len(failures)}/{len(order)} methods '
                         f'NOT matched ({names}); the rest are reported in '
                         f'{a.output_dir}/ownkey5-arm-result.json')


if __name__ == '__main__':
    main()
