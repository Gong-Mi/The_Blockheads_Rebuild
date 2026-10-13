#!/usr/bin/env python3
"""Execute the ORIGINAL ARM `-[Tree growInTimeSinceSaved:]`
(0x004c2568, 546 words, stage 1: nil-tile path) under Unicorn with
synthetic world/dynamicWorld objects and compare the resulting instance
image and message trace against the recovered C++ contract
(reconstruction/recovered/tree_grow_in_time.cpp, built at -O0 and -O2).

Built on tools/arm_harness (batches b4f/b4g patterns consolidated):
  * ARMSession maps the pinned ELF and enables VFP.
  * MsgDispatcher stubs objc_msgSend (GOT slot 0x0105b7a0) on the real
    selector strings; handlers answer isStaticTree / worldTime /
    isGrowingInCompost, script incrementHeight mutations, and record
    updateGrowth:'s adult flag (+ spilled 1.0f at sp+0x44 = the next
    iteration's timeToGrow), sowTreeNearParent:'s [sp] float and
    removeAllOwnedTiles:.
  * WorldAnswers hooks the tile lookup `bl 0xa12f24` (STAGE 1 FIXTURE:
    the tile-record/PRNG block is a stage-2 slice); the per-call check
    asserts the lookup asks for (pos.x, pos.y + current height) — proving
    the body really reads those ivars.
  * Everything else executes for real: the isStaticTree gate, dead checks,
    f64 elapsed math, maxAge comparison, the growth loop (0.005-constant
    growthTime formula, increment/partial branches, spilled timeToGrow),
    compost/death paths and the timeDied f64 store.
Checked per case: the (code, arg) trace, the 120-byte instance image, and
expectations computed independently of the C++ pair (timeDied value,
sowTree adultMaxAge bits, scripted maxHeightReached, boundary branches).
"""
import argparse
import ctypes
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_harness import ARMSession, FixtureGraph, MsgDispatcher, WorldAnswers

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x004C2568
GOT_MSGSEND = 0x0105B7A0
STUB = 0x72000000
IMAGE_SIZE = 120

# Trace codes — derived from the single source of truth
# (reconstruction/reverse-v3/native/trace_schemas.json via
# tools/gen_trace_codes.py); the b4f collision bug was two hand-maintained
# tables drifting apart.
from trace_codes_gen import TREE_GROW_CODES as TG

IS_STATIC_TREE = TG['IsStaticTree']
WORLD_TIME = TG['WorldTime']
INCREMENT_HEIGHT = TG['IncrementHeight']
UPDATE_GROWTH_ADULT = TG['UpdateGrowthAdult']
UPDATE_GROWTH_NO = TG['UpdateGrowthNo']
IS_GROWING_IN_COMPOST = TG['IsGrowingInCompost']
SOW_TREE = TG['SowTreeNearParent']
REMOVE_ALL = TG['RemoveAllOwnedTiles']

BASE = {
    'world_token': 0x51CE0004, 'dynamic_world_token': 0x51CE0005,
    'pos_x': 7, 'pos_y': 11,
    'max_age': 100.0, 'age': 10.0, 'growth_counter': 0.2,
    'growth_rate': 1.0, 'max_height': 10, 'height': 5,
    'max_height_reached': 5, 'dead': 0,
    'world_time': 0.0, 'time_since_saved': 0.0,
}
CASES = [
    {'name': 'static', 'is_static_tree': 1},
    {'name': 'dead_entry', 'dead': 1},
    {'name': 'partial', 'world_time': 50.0, 'time_since_saved': 10.0},
    {'name': 'double_increment', 'max_age': 1000.0, 'growth_counter': 0.9,
     'growth_rate': 10.0, 'height': 3, 'max_height_reached': 3,
     'world_time': 100.0, 'time_since_saved': 0.0},
    {'name': 'scripted_height_exit', 'max_age': 1000.0, 'growth_rate': 10.0,
     'height_after_increment': 10, 'max_height_reached_after_increment': 6,
     'world_time': 100.0, 'time_since_saved': 0.0},
    {'name': 'compost', 'age': 95.0, 'world_time': 200.0,
     'time_since_saved': 110.0, 'is_growing_in_compost': 1},
    {'name': 'death', 'age': 95.0, 'world_time': 200.0,
     'time_since_saved': 110.0},
    {'name': 'nan_worldtime', 'world_time': float('nan'),
     'is_growing_in_compost': 1},
    {'name': 'negative_elapsed', 'world_time': 5.0, 'time_since_saved': 10.0},
    {'name': 'boundary', 'age': 50.0, 'world_time': 60.0,
     'time_since_saved': 10.0, 'is_growing_in_compost': 1},
    {'name': 'tile_sunlight', 'has_tile': 1, 'tile_sun_light': 204,
     'world_time': 100.0, 'time_since_saved': 99.0, 'growth_counter': 0.0,
     'growth_rate': 1.0, 'height': 2, 'max_height': 10},
    {'name': 'tile_artificial_light', 'has_tile': 1, 'tile_sun_light': 0,
     'tile_artificial_light_r': 2048, 'tile_artificial_light_g': 2048,
     'tile_artificial_light_b': 1024,
     'world_time': 100.0, 'time_since_saved': 99.0, 'growth_counter': 0.0,
     'growth_rate': 1.0, 'height': 2, 'max_height': 10},
]


def f32bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    session = ARMSession(a.elf, SHA)
    uc = session.uc
    graph = FixtureGraph(uc)
    self_ptr = graph.base
    dispatcher = MsgDispatcher(uc, STUB)
    tile_lookup = WorldAnswers(uc)
    session.patch_got(GOT_MSGSEND, STUB)

    STUB_IDIV = 0x77000000
    uc.mem_map(STUB_IDIV, 0x1000)
    session.patch_got(0x0106001c, STUB_IDIV)

    def hook_idiv(uc_, addr, sz, data):
        from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_PC, UC_ARM_REG_LR
        n = uc_.reg_read(UC_ARM_REG_R0)
        d = uc_.reg_read(UC_ARM_REG_R1)
        if n & 0x80000000: n -= (1 << 32)
        if d & 0x80000000: d -= (1 << 32)
        res = int(n / d) if d != 0 else 0
        if res < 0: res += (1 << 32)
        uc_.reg_write(UC_ARM_REG_R0, res & 0xffffffff)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, hook_idiv, begin=STUB_IDIV, end=STUB_IDIV + 4)

    TILE_ADDR = 0x78000000
    uc.mem_map(TILE_ADDR, 0x1000)

    def tile_provider(x, y):
        case = state['case']
        if not case.get('has_tile', 0):
            return 0
        uc.mem_write(TILE_ADDR + 7, bytes([case.get('tile_sun_light', 0) & 0xff]))
        uc.mem_write(TILE_ADDR + 14, struct.pack("<H", case.get('tile_artificial_light_r', 0) & 0xffff))
        uc.mem_write(TILE_ADDR + 16, struct.pack("<H", case.get('tile_artificial_light_g', 0) & 0xffff))
        uc.mem_write(TILE_ADDR + 18, struct.pack("<H", case.get('tile_artificial_light_b', 0) & 0xffff))
        return TILE_ADDR

    tile_lookup.tile_provider = tile_provider
    cmd_sel = graph.command_selector('growInTimeSinceSaved:')

    state = {'case': None}

    def check_accessor(x, y):
        case = state['case']
        raw = session.read_word(self_ptr + 60)
        signed = raw - (1 << 32) if raw & 0x80000000 else raw
        assert x == case['pos_x'], ('accessor x', x, case['pos_x'])
        assert y == case['pos_y'] + signed, \
            ('accessor y', y, case['pos_y'], signed)

    @dispatcher.register('isStaticTree')
    def _(ctx):
        ctx.record(IS_STATIC_TREE)
        return state['case'].get('is_static_tree', 0), None

    @dispatcher.register('worldTime')
    def _(ctx):
        assert ctx.recv == state['case']['world_token'], \
            ('worldTime receiver', hex(ctx.recv))
        ctx.record(WORLD_TIME)
        lo, hi = struct.unpack('<II',
                               struct.pack('<d', state['case']['world_time']))
        return lo, hi

    @dispatcher.register('isGrowingInCompost')
    def _(ctx):
        ctx.record(IS_GROWING_IN_COMPOST)
        return state['case'].get('is_growing_in_compost', 0), None

    @dispatcher.register('incrementHeight')
    def _(ctx):
        ctx.record(INCREMENT_HEIGHT)
        case = state['case']
        hai = case.get('height_after_increment', -1)
        mhrai = case.get('max_height_reached_after_increment', -1)
        if hai >= 0:
            graph.word(self_ptr + 60, hai)
        if mhrai >= 0:
            graph.word(self_ptr + 64, mhrai)
        return 0, None

    @dispatcher.register('updateGrowth:')
    def _(ctx):
        adult = ctx.r2 & 0xff
        if adult:
            spill = struct.unpack('<f', ctx.read(ctx.sp + 0x44, 4))[0]
            ctx.record(UPDATE_GROWTH_ADULT, f32bits(spill))
        else:
            ctx.record(UPDATE_GROWTH_NO)
        return 0, None

    @dispatcher.register('sowTreeNearParent:adult:adultMaxAge:')
    def _(ctx):
        case = state['case']
        assert ctx.recv == case['dynamic_world_token'], \
            ('sow receiver', hex(ctx.recv))
        assert ctx.r2 == self_ptr, ('sow tree arg', hex(ctx.r2))
        assert ctx.r3 == 1, 'sow adult = 1'
        ctx.record(SOW_TREE, ctx.stack_word(0))
        return 0, None

    @dispatcher.register('removeAllOwnedTiles:')
    def _(ctx):
        ctx.record(REMOVE_ALL)
        return 0, None

    dispatcher.install()
    tile_lookup.install()
    tile_lookup.on_call = check_accessor

    repo = Path(__file__).resolve().parents[1]
    import os
    libcxx = Path(os.environ.get('PREFIX', '')) / 'lib/libc++_shared.so'
    if libcxx.is_file():
        ctypes.CDLL(str(libcxx), mode=ctypes.RTLD_GLOBAL)
    fns = []
    for opt in (0, 2):
        lib = a.output_dir / f'tree_grow-O{opt}.so'
        subprocess.run(['clang++', '-std=c++17', f'-O{opt}', '-UNDEBUG',
                        '-fno-fast-math', '-ffp-contract=off', '-fPIC',
                        '-shared',
                        '-I' + str(repo / 'reconstruction/recovered'),
                        str(repo / 'tools/tree_grow_in_time_arm_bridge.cpp'),
                        str(repo / 'reconstruction/recovered/tree_grow_in_time.cpp'),
                        '-o', str(lib)], check=True)
        cdll = ctypes.CDLL(str(lib))
        fn = cdll.recovered_tree_grow_run
        fn.argtypes = [ctypes.c_uint8, ctypes.c_uint8, ctypes.c_double,
                       ctypes.c_double, ctypes.c_uint8, ctypes.c_float,
                       ctypes.c_float, ctypes.c_float, ctypes.c_float,
                       ctypes.c_int32, ctypes.c_int32, ctypes.c_int32,
                       ctypes.c_int32, ctypes.c_int32, ctypes.c_uint32,
                       ctypes.c_uint32, ctypes.c_int32, ctypes.c_int32,
                       ctypes.c_uint8, ctypes.c_uint8,
                       ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16,
                       ctypes.c_char_p, ctypes.c_char_p]
        fn.restype = ctypes.c_uint32
        fns.append(fn)

    def word_at(image, off):
        return struct.unpack('<I', image[off:off + 4])[0]

    rows = []
    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        state['case'] = merged
        dispatcher.trace = []
        tile_lookup.calls = []

        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        graph.word(self_ptr + 4, merged['world_token'])
        graph.word(self_ptr + 8, merged['dynamic_world_token'])
        graph.word(self_ptr + 16, merged['pos_x'] & 0xffffffff)
        graph.word(self_ptr + 20, merged['pos_y'] & 0xffffffff)
        graph.word(self_ptr + 60, merged['height'] & 0xffffffff)
        graph.word(self_ptr + 64, merged['max_height_reached'] & 0xffffffff)
        graph.word(self_ptr + 68, f32bits(merged['growth_counter']))
        graph.word(self_ptr + 72, f32bits(merged['growth_rate']))
        graph.word(self_ptr + 88, merged['max_height'] & 0xffffffff)
        graph.word(self_ptr + 92, f32bits(merged['max_age']))
        graph.word(self_ptr + 96, f32bits(merged['age']))
        uc.mem_write(self_ptr + 104, bytes([merged['dead'] & 0xff]))

        lo, hi = struct.unpack('<II',
                               struct.pack('<d', merged['time_since_saved']))
        session.run(IMP, R0=self_ptr, R1=cmd_sel, R2=lo, R3=hi)

        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(dispatcher.trace)

        cpp_images, cpp_traces = [], []
        for fn in fns:
            image_out = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_out = ctypes.create_string_buffer(32 * 8)
            n = fn(merged.get('is_static_tree', 0),
                   merged.get('is_growing_in_compost', 0),
                   merged['world_time'], merged['time_since_saved'],
                   merged['dead'], merged['max_age'], merged['age'],
                   merged['growth_counter'], merged['growth_rate'],
                   merged['max_height'], merged['height'],
                   merged['max_height_reached'], merged['pos_x'],
                   merged['pos_y'], merged['world_token'],
                   merged['dynamic_world_token'],
                   merged.get('height_after_increment', -1),
                   merged.get('max_height_reached_after_increment', -1),
                   merged.get('has_tile', 0),
                   merged.get('tile_sun_light', 0),
                   merged.get('tile_artificial_light_r', 0),
                   merged.get('tile_artificial_light_g', 0),
                   merged.get('tile_artificial_light_b', 0),
                   image_out, trace_out)
            cpp_images.append(image_out.raw)
            cpp_traces.append(
                [(trace_out.raw[i * 8],
                  struct.unpack('<I', trace_out.raw[i * 8 + 4:i * 8 + 8])[0])
                 for i in range(n)])

        for image, trace in zip(cpp_images, cpp_traces):
            assert image == arm_image, (case['name'], 'image mismatch')
            assert trace == arm_trace, (case['name'], 'trace mismatch',
                                        trace, arm_trace)

        # Expectations computed independently of the recovered C++ pair.
        if case['name'] == 'death':
            assert struct.unpack('<d', arm_image[112:120])[0] == 115.0, \
                'timeDied = t + maxAge - age'
            assert (SOW_TREE, f32bits(85.0)) in arm_trace, \
                'adultMaxAge = 85.0f bits'
        if case['name'] == 'scripted_height_exit':
            assert word_at(arm_image, 64) == 10, 'mhr = max(10, 6)'
        if case['name'] == 'double_increment':
            assert sum(1 for c, _ in arm_trace if c == INCREMENT_HEIGHT) == 2
        rows.append({'case': case['name'], 'trace_len': len(arm_trace),
                     'tile_lookups': len(tile_lookup.calls)})

    report = {
        'sha256': SHA, 'class': 'Tree', 'method': 'growInTimeSinceSaved:',
        'entry': f'0x{IMP:08x}', 'stage': 1, 'cases': len(rows), 'match': True,
        'boundary': (
            'Unicorn execution of the original 546-word method (STAGE 1: '
            'tile lookup 0xa12f24 hooked to nil, so the tile-record/PRNG '
            'block is a stage-2 slice) with synthetic world/dynamicWorld '
            'objects. The isStaticTree gate, dead checks, f64 elapsed math, '
            'maxAge comparison, growth loop (0.005-constant growthTime '
            'formula, increment/partial branches, spilled timeToGrow), '
            'compost/death paths and timeDied store execute for real. Not '
            'Foundation, not the original-app runtime, not device gameplay; '
            'incrementHeight mutations are scripted.'),
        'rows': rows,
    }
    (a.output_dir / 'tree-grow-arm-result.json').write_text(
        json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('sha256', 'cases', 'match',
                                             'boundary')}, indent=2))


if __name__ == '__main__':
    main()
