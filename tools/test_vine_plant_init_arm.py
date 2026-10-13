#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of the VinePlant BIG loader (batch b4o)

  -[VinePlant initWithWorld:dynamicWorld:saveDict:cache:
        treeDensityNoiseFunction:seasonOffsetNoiseFunction:]   IMP 0x004F68A0

under Unicorn and compare the 184-byte instance image, the return value, the
tile-consume count and the full (code, arg) trace against the recovered C++
contract at -O0/-O2. Mirror twin of the b4n KelpPlant differential: same
dispatcher, mirrored occupancy axis, plus the light/sun suitability key.
"""
import argparse
import ctypes
import json
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_harness import ARMSession, FixtureGraph, MsgDispatcher
from trace_codes_gen import VINE_INIT_CODES as VC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x004F68A0
IMAGE_SIZE = 184
LONG_SELECTOR = ('initWithWorld:dynamicWorld:saveDict:cache:'
                 'treeDensityNoiseFunction:seasonOffsetNoiseFunction:')

GOT_MSGSEND_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
VENEER_MSGSEND_SLOT = 0x0105FB18
VENEER_LRAND48_SLOT = 0x0105FB10
SUPERREF_SLOT = 0x00E8BC40
VINE_CLASS = 0x00E90558

WORLD_ACCESSOR = 0x00A12F24

STUB_MSG = 0x72000000
STUB_LRAND48 = 0x72001000
STUB_IDIV = 0x72002000
TILE_PAGE = 0x60090000
STACK_OFFSET = 0x8000

BOX_OCCUPIED = 0x5E1A0A01
BOX_GROWTH_TIMER = 0x5E1A0A02
BOX_AVAILABLE_FOOD = 0x5E1A0A03
BOX_SAVE_TIME = 0x5E1A0A04

OFF_WORLD = 4
OFF_DYNAMIC_WORLD = 8
OFF_POS = 16
OFF_AGE = 72
OFF_MAX_AGE = 88
OFF_GROWTH_RATE = 92
OFF_AVAILABLE_FOOD = 100
OFF_GROWTH_TIMER = 176
OFF_OCCUPIED = 180


class BridgeInput(ctypes.Structure):
    _fields_ = [
        ('self_ptr', ctypes.c_uint32),
        ('super_returns_nil', ctypes.c_uint32),
        ('world_argument', ctypes.c_uint32),
        ('dynamic_world_argument', ctypes.c_uint32),
        ('save_dict_token', ctypes.c_uint32),
        ('cache_token', ctypes.c_uint32),
        ('tree_density_argument', ctypes.c_uint32),
        ('season_offset_argument', ctypes.c_uint32),
        ('world_ivar', ctypes.c_uint32),
        ('dynamic_world_ivar', ctypes.c_uint32),
        ('pos_x', ctypes.c_int32),
        ('pos_y', ctypes.c_int32),
        ('occupied_init', ctypes.c_int32),
        ('growth_timer_init', ctypes.c_float),
        ('available_food_init', ctypes.c_float),
        ('age_init', ctypes.c_float),
        ('max_age', ctypes.c_float),
        ('growth_rate', ctypes.c_float),
        ('occupied_box_token', ctypes.c_uint32),
        ('growth_timer_box_token', ctypes.c_uint32),
        ('available_food_box_token', ctypes.c_uint32),
        ('save_time_box_token', ctypes.c_uint32),
        ('occupied_value', ctypes.c_int32),
        ('growth_timer_value', ctypes.c_float),
        ('available_food_value', ctypes.c_float),
        ('save_time_value', ctypes.c_double),
        ('world_time', ctypes.c_double),
        ('lrand48_value', ctypes.c_int64),
        ('is_growing_in_compost', ctypes.c_uint32),
        ('object_type_value', ctypes.c_uint32),
        ('tile_count', ctypes.c_uint32),
        ('tile_present', ctypes.c_uint32 * 64),
        ('tile_byte0', ctypes.c_uint32 * 64),
        ('tile_byte7', ctypes.c_uint32 * 64),
        ('tile_byte11', ctypes.c_uint32 * 64),
        ('tile_half_a', ctypes.c_uint32 * 64),
        ('tile_half_b', ctypes.c_uint32 * 64),
        ('tile_half_c', ctypes.c_uint32 * 64),
    ]


def tile(present=True, byte0=7, byte7=255, byte11=0, a=4, b=8, c=8):
    return {'present': present, 'byte0': byte0, 'byte7': byte7,
            'byte11': byte11, 'a': a, 'b': b, 'c': c}


BASE = {
    'self_ptr': 0x60000000,
    'super_returns_nil': False,
    'world_argument': 0x5E1A0010,
    'dynamic_world_argument': 0x5E1A0020,
    'save_dict_token': 0x60010000,
    'cache_token': 0x5E1A0030,
    'tree_density_argument': 0x5E1A0031,
    'season_offset_argument': 0x5E1A0032,
    'world_ivar': 0x5E1A0004,
    'dynamic_world_ivar': 0x5E1A0008,
    'pos_x': 10,
    'pos_y': -4,
    'occupied_init': 2,
    'growth_timer_init': 1.0,
    'available_food_init': 5.0,
    'age_init': 10.0,
    'max_age': 1000.0,
    'growth_rate': 1.0,
    'occupied_value': 2,
    'growth_timer_value': 1.0,
    'available_food_value': 5.0,
    'save_time_value': 100.0,
    'world_time': 150.0,
    'lrand48_value': 900,
    'is_growing_in_compost': 0,
    'object_type_value': 0x5E1A0041,
    'tiles': [],
}

CASES = [
    {'name': 'super_nil', 'super_returns_nil': True},
    {'name': 'no_growth_timer_low', 'growth_timer_value': 1.0},
    {'name': 'food_refill', 'available_food_value': 0.05, 'lrand48_value': 900},
    {'name': 'food_refill_negative_rand', 'available_food_value': 0.0,
     'lrand48_value': -12345},
    {'name': 'die_of_old_age', 'age_init': 990.0, 'is_growing_in_compost': 0},
    {'name': 'compost_adjust', 'age_init': 990.0, 'is_growing_in_compost': 1,
     'growth_timer_value': 1.0},
    {'name': 'growth_single_tile', 'growth_timer_value': 2000.0,
     'tiles': [tile()]},
    {'name': 'growth_blocked_kind3', 'growth_timer_value': 2000.0,
     'tiles': [tile(byte0=3)]},
    {'name': 'growth_blocked_byte0_31', 'growth_timer_value': 2000.0,
     'tiles': [tile(byte0=31)]},
    {'name': 'growth_blocked_marker', 'growth_timer_value': 2000.0,
     'tiles': [tile(byte11=6)]},
    {'name': 'growth_blocked_too_dark', 'growth_timer_value': 2000.0,
     'tiles': [tile(byte7=0, a=0, b=0, c=0)]},
    {'name': 'growth_light_boundary', 'growth_timer_value': 2000.0,
     'tiles': [tile(byte7=128, a=0, b=0, c=0), tile(byte0=3)]},
    {'name': 'growth_multi_tile', 'growth_timer_value': 100000.0,
     'tiles': [tile(), tile(), tile(), tile()]},
    {'name': 'occupied_limit', 'occupied_value': 15, 'occupied_init': 15,
     'growth_timer_value': 100000.0},
    {'name': 'no_tile_answer', 'growth_timer_value': 2000.0, 'tiles': []},
]


def build_bridge(root, out_dir):
    fns = []
    for opt in (0, 2):
        so_path = out_dir / f'vine_plant_init-O{opt}.so'
        cmd = ['clang++', f'-O{opt}', '-shared', '-fPIC', '-std=c++17',
               '-fno-fast-math', '-ffp-contract=off',
               '-I', str(root / 'reconstruction/recovered'),
               str(root / 'tools/vine_plant_init_arm_bridge.cpp'),
               str(root / 'reconstruction/recovered/vine_plant_init.cpp'),
               '-o', str(so_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        cdll = ctypes.CDLL(str(so_path))
        fn = cdll.recovered_vine_plant_init_run
        fn.argtypes = [ctypes.POINTER(BridgeInput), ctypes.c_char_p,
                       ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32),
                       ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))
    return fns


def low32(value):
    return struct.unpack('<I', struct.pack('<d', value)[:4])[0]


def float_bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--only', default=None)
    ap.add_argument('--debug', action='store_true')
    a = ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    libcpp = Path('/data/data/com.termux/files/usr/lib/libc++_shared.so')
    if libcpp.exists():
        try:
            ctypes.CDLL(str(libcpp), mode=ctypes.RTLD_GLOBAL)
        except Exception:
            pass

    session = ARMSession(a.elf, SHA)
    uc = session.uc
    graph = FixtureGraph(uc)
    uc.mem_map(TILE_PAGE, 0x1000)
    session.patch_got(GOT_MSGSEND_SUPER2, STUB_MSG)
    session.patch_got(GOT_MSGSEND, STUB_MSG)
    session.patch_got(VENEER_MSGSEND_SLOT, STUB_MSG)
    assert session.read_word(SUPERREF_SLOT) == VINE_CLASS, 'VinePlant superref drift'
    cmd_sel = graph.command_selector(LONG_SELECTOR)

    dispatcher = MsgDispatcher(uc, STUB_MSG)
    state = {'case': None, 'tiles_served': 0}

    def case():
        return state['case']

    @dispatcher.register(LONG_SELECTOR)
    def on_super(ctx):
        c = case()
        sup = ctx.recv
        assert ctx.word(sup) == c['self_ptr'], 'super2 receiver'
        assert ctx.word(sup + 4) == VINE_CLASS, 'super2 own class'
        assert ctx.r2 == c['world_argument'] and ctx.r3 == c['dynamic_world_argument']
        assert ctx.stack_word(0) == c['save_dict_token']
        assert ctx.stack_word(4) == c['cache_token']
        assert ctx.stack_word(8) == c['tree_density_argument']
        assert ctx.stack_word(12) == c['season_offset_argument']
        ctx.record(VC['MsgSendSuper'], c['self_ptr'])
        return (0 if c['super_returns_nil'] else c['self_ptr'], None)

    @dispatcher.register('objectForKey:')
    def on_object_for_key(ctx):
        c = case()
        assert ctx.recv == c['save_dict_token'], 'objectForKey: receiver'
        data = struct.unpack('<I', bytes(uc.mem_read(ctx.r2 + 8, 4)))[0]
        key = bytes(uc.mem_read(data, 64)).split(b'\0')[0].decode()
        table = {
            'numberOfOccupiedTilesBelow': (VC['ObjectForKeyOccupiedBelow'], BOX_OCCUPIED),
            'growthTimer': (VC['ObjectForKeyGrowthTimer'], BOX_GROWTH_TIMER),
            'availableFood': (VC['ObjectForKeyAvailableFood'], BOX_AVAILABLE_FOOD),
            'saveTime': (VC['ObjectForKeySaveTime'], BOX_SAVE_TIME),
        }
        assert key in table, f'unexpected key {key!r}'
        code, token = table[key]
        ctx.record(code, token)
        return (token, None)

    @dispatcher.register('intValue')
    def on_int_value(ctx):
        c = case()
        assert ctx.recv == BOX_OCCUPIED, 'intValue receiver'
        value = c['occupied_value'] & 0xffffffff
        ctx.record(VC['IntValueOccupiedBelow'], value)
        return (value, None)

    @dispatcher.register('floatValue')
    def on_float_value(ctx):
        c = case()
        if ctx.recv == BOX_GROWTH_TIMER:
            ctx.record(VC['FloatValueGrowthTimer'], float_bits(c['growth_timer_value']))
            return (float_bits(c['growth_timer_value']), None)
        if ctx.recv == BOX_AVAILABLE_FOOD:
            ctx.record(VC['FloatValueAvailableFood'], float_bits(c['available_food_value']))
            return (float_bits(c['available_food_value']), None)
        raise AssertionError('floatValue on an unexpected box')

    @dispatcher.register('doubleValue')
    def on_double_value(ctx):
        c = case()
        assert ctx.recv == BOX_SAVE_TIME, 'doubleValue receiver'
        ctx.record(VC['DoubleValueSaveTime'], low32(c['save_time_value']))
        half = struct.unpack('<II', struct.pack('<d', c['save_time_value']))
        return (half[0], half[1])

    @dispatcher.register('initSubDerivedItems')
    def on_init_sub_derived(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'initSubDerivedItems receiver'
        ctx.record(VC['InitSubDerivedItems'], 0)
        return (ctx.recv, None)

    @dispatcher.register('isGrowingInCompost')
    def on_is_growing_in_compost(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'isGrowingInCompost receiver'
        flag = 1 if c['is_growing_in_compost'] else 0
        ctx.record(VC['IsGrowingInCompost'], flag)
        return (flag, None)

    @dispatcher.register('dieOfOldAge')
    def on_die_of_old_age(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'dieOfOldAge receiver'
        ctx.record(VC['DieOfOldAge'], 0)
        return (ctx.recv, None)

    @dispatcher.register('worldTime')
    def on_world_time(ctx):
        c = case()
        assert ctx.recv == c['world_ivar'], 'worldTime receiver'
        ctx.record(VC['WorldTime'], low32(c['world_time']))
        half = struct.unpack('<II', struct.pack('<d', c['world_time']))
        return (half[0], half[1])

    @dispatcher.register('objectType')
    def on_object_type(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'objectType receiver'
        ctx.record(VC['ObjectType'], c['object_type_value'])
        return (c['object_type_value'], None)

    @dispatcher.register('worldContentsChangedAtPos:')
    def on_world_contents_changed(ctx):
        c = case()
        assert ctx.recv == c['dynamic_world_ivar'], 'worldContentsChangedAtPos receiver'
        x = ctypes.c_int32(ctx.r2).value
        y = ctypes.c_int32(ctx.r3).value
        assert x == c['pos_x'], ('position x', x)
        ctx.record(VC['WorldContentsChangedAtPos'], y & 0xffffffff)
        return (0, None)

    @dispatcher.register('dynamicWorldChangedAtPos:objectType:')
    def on_dynamic_world_changed(ctx):
        c = case()
        assert ctx.recv == c['dynamic_world_ivar'], 'dynamicWorldChangedAtPos receiver'
        assert ctx.r2 == (c['pos_x'] & 0xffffffff), 'notification pos.x'
        assert ctx.r3 == (c['pos_y'] & 0xffffffff), 'notification pos.y'
        assert ctx.stack_word(0) == c['object_type_value'], 'notification objectType'
        ctx.record(VC['DynamicWorldChangedAtPos'], ctx.stack_word(0))
        return (0, None)

    dispatcher.install()

    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_PC, UC_ARM_REG_LR)

    def hook_world(uc_, address, size, data):
        c = case()
        x = ctypes.c_int32(uc_.reg_read(UC_ARM_REG_R0)).value
        y = ctypes.c_int32(uc_.reg_read(UC_ARM_REG_R1)).value
        world = uc_.reg_read(UC_ARM_REG_R2)
        assert world == c['world_ivar'], 'world accessor receiver'
        assert x == c['pos_x'], ('query x', x)
        index = state['tiles_served']
        answers = c['tiles']
        ptr = 0
        if index < len(answers):
            answer = answers[index]
            if answer['present']:
                ptr = TILE_PAGE + 0x40 * index
                blob = bytearray(0x20)
                blob[0] = answer['byte0'] & 0xff
                blob[7] = answer['byte7'] & 0xff
                blob[11] = answer['byte11'] & 0xff
                struct.pack_into('<HHH', blob, 0x0e, answer['a'] & 0xffff,
                                 answer['b'] & 0xffff, answer['c'] & 0xffff)
                uc_.mem_write(ptr, bytes(blob))
        state['tiles_served'] = index + 1
        dispatcher.trace.append((VC['WorldTileQuery'], y & 0xffffffff))
        uc_.reg_write(UC_ARM_REG_R0, ptr)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    def hook_lrand48(uc_, address, size, data):
        c = case()
        dispatcher.trace.append((VC['Lrand48'], c['lrand48_value'] & 0xffffffff))
        uc_.reg_write(UC_ARM_REG_R0, c['lrand48_value'] & 0xffffffff)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_world, begin=WORLD_ACCESSOR, end=WORLD_ACCESSOR + 4)
    # __aeabi_idiv: the light/sun scan calls it twice (veneer 0x001C3728, slot
    # 0x0106001C). Stubbed with real signed 32-bit division semantics (b4l
    # precedent) — it is a pure function, so no trace entry is emitted.
    uc.mem_map(STUB_IDIV, 0x1000)
    session.patch_got(0x0106001C, STUB_IDIV)

    def hook_idiv(uc_, address, size, data):
        n = uc_.reg_read(UC_ARM_REG_R0)
        d = uc_.reg_read(UC_ARM_REG_R1)
        if n & 0x80000000:
            n -= (1 << 32)
        if d & 0x80000000:
            d -= (1 << 32)
        quotient = int(n / d) if d != 0 else 0
        if quotient < 0:
            quotient += (1 << 32)
        uc_.reg_write(UC_ARM_REG_R0, quotient & 0xffffffff)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_idiv, begin=STUB_IDIV, end=STUB_IDIV + 4)
    uc.mem_map(STUB_LRAND48, 0x1000)
    uc.hook_add(UC_HOOK_CODE, hook_lrand48, begin=STUB_LRAND48, end=STUB_LRAND48 + 4)
    session.patch_got(VENEER_LRAND48_SLOT, STUB_LRAND48)

    root = Path(__file__).resolve().parents[1]
    fns = build_bridge(root, a.output_dir)
    names = {v: k for k, v in VC.items()}

    rows = []
    for case_def in CASES:
        if a.only and case_def['name'] != a.only:
            continue
        merged = dict(BASE)
        merged.update({k: v for k, v in case_def.items() if k != 'name'})
        state['case'] = merged
        state['tiles_served'] = 0
        dispatcher.trace.clear()

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        session.word(self_ptr + OFF_WORLD, merged['world_ivar'])
        session.word(self_ptr + OFF_DYNAMIC_WORLD, merged['dynamic_world_ivar'])
        session.word(self_ptr + OFF_POS, merged['pos_x'] & 0xffffffff)
        session.word(self_ptr + OFF_POS + 4, merged['pos_y'] & 0xffffffff)
        session.word(self_ptr + OFF_OCCUPIED, merged['occupied_init'] & 0xffffffff)
        session.word(self_ptr + OFF_GROWTH_TIMER, float_bits(merged['growth_timer_init']))
        session.word(self_ptr + OFF_AVAILABLE_FOOD, float_bits(merged['available_food_init']))
        session.word(self_ptr + OFF_AGE, float_bits(merged['age_init']))
        session.word(self_ptr + OFF_MAX_AGE, float_bits(merged['max_age']))
        session.word(self_ptr + OFF_GROWTH_RATE, float_bits(merged['growth_rate']))

        stack_top = session.stack + STACK_OFFSET
        uc.mem_write(stack_top, struct.pack('<IIII', merged['save_dict_token'],
                                           merged['cache_token'],
                                           merged['tree_density_argument'],
                                           merged['season_offset_argument']))

        session.run(IMP, sp_offset=STACK_OFFSET, count=4000000,
                    R0=self_ptr, R1=cmd_sel, R2=merged['world_argument'],
                    R3=merged['dynamic_world_argument'])

        arm_ret = uc.reg_read(UC_ARM_REG_R0)
        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(dispatcher.trace)
        expected_ret = 0 if merged['super_returns_nil'] else self_ptr
        assert arm_ret == expected_ret, ('return', hex(arm_ret), hex(expected_ret))
        if a.debug:
            print(f'--- {case_def["name"]} arm trace:')
            for code, arg in arm_trace:
                print(f'    {names.get(code, code):30s} {arg:#x}')
            print('    occupied =', struct.unpack('<i', arm_image[OFF_OCCUPIED:OFF_OCCUPIED + 4])[0],
                  'timer =', struct.unpack('<f', arm_image[OFF_GROWTH_TIMER:OFF_GROWTH_TIMER + 4])[0],
                  'food =', struct.unpack('<f', arm_image[OFF_AVAILABLE_FOOD:OFF_AVAILABLE_FOOD + 4])[0])

        tiles = merged['tiles']
        cfg = BridgeInput()
        cfg.self_ptr = merged['self_ptr']
        cfg.super_returns_nil = 1 if merged['super_returns_nil'] else 0
        cfg.world_argument = merged['world_argument']
        cfg.dynamic_world_argument = merged['dynamic_world_argument']
        cfg.save_dict_token = merged['save_dict_token']
        cfg.cache_token = merged['cache_token']
        cfg.tree_density_argument = merged['tree_density_argument']
        cfg.season_offset_argument = merged['season_offset_argument']
        cfg.world_ivar = merged['world_ivar']
        cfg.dynamic_world_ivar = merged['dynamic_world_ivar']
        cfg.pos_x = merged['pos_x']
        cfg.pos_y = merged['pos_y']
        cfg.occupied_init = merged['occupied_init']
        cfg.growth_timer_init = merged['growth_timer_init']
        cfg.available_food_init = merged['available_food_init']
        cfg.age_init = merged['age_init']
        cfg.max_age = merged['max_age']
        cfg.growth_rate = merged['growth_rate']
        cfg.occupied_box_token = BOX_OCCUPIED
        cfg.growth_timer_box_token = BOX_GROWTH_TIMER
        cfg.available_food_box_token = BOX_AVAILABLE_FOOD
        cfg.save_time_box_token = BOX_SAVE_TIME
        cfg.occupied_value = merged['occupied_value']
        cfg.growth_timer_value = merged['growth_timer_value']
        cfg.available_food_value = merged['available_food_value']
        cfg.save_time_value = merged['save_time_value']
        cfg.world_time = merged['world_time']
        cfg.lrand48_value = merged['lrand48_value']
        cfg.is_growing_in_compost = 1 if merged['is_growing_in_compost'] else 0
        cfg.object_type_value = merged['object_type_value']
        cfg.tile_count = len(tiles)
        for i, answer in enumerate(tiles):
            cfg.tile_present[i] = 1 if answer['present'] else 0
            cfg.tile_byte0[i] = answer['byte0']
            cfg.tile_byte7[i] = answer['byte7']
            cfg.tile_byte11[i] = answer['byte11']
            cfg.tile_half_a[i] = answer['a']
            cfg.tile_half_b[i] = answer['b']
            cfg.tile_half_c[i] = answer['c']

        for opt, fn in fns:
            image_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_buf = ctypes.create_string_buffer(256 * 8)
            ret_out = ctypes.c_uint32(0)
            tiles_out = ctypes.c_uint32(0)
            n = fn(ctypes.byref(cfg), image_buf, trace_buf,
                   ctypes.byref(ret_out), ctypes.byref(tiles_out))
            assert n != 0xFFFFFFFF, 'fixture overflow'
            cpp_image = image_buf.raw[:IMAGE_SIZE]
            cpp_trace = []
            for i in range(n):
                rec = trace_buf.raw[i * 8:(i + 1) * 8]
                cpp_trace.append((rec[0], struct.unpack('<I', rec[4:8])[0]))
            assert arm_image == cpp_image, (
                f'-O{opt} image mismatch in {case_def["name"]}',
                [(hex(i), arm_image[i], cpp_image[i])
                 for i in range(IMAGE_SIZE) if arm_image[i] != cpp_image[i]])
            assert arm_trace == cpp_trace, (
                f'-O{opt} trace mismatch in {case_def["name"]}',
                _first_diff(arm_trace, cpp_trace))
            assert ret_out.value == arm_ret
            assert tiles_out.value == state['tiles_served'], 'tile consume count'

        rows.append({
            'case': case_def['name'],
            'trace_len': len(arm_trace),
            'tile_queries': state['tiles_served'],
            'return': hex(arm_ret),
            'occupied_final': struct.unpack('<i', arm_image[OFF_OCCUPIED:OFF_OCCUPIED + 4])[0],
            'growth_timer_final': struct.unpack('<f', arm_image[OFF_GROWTH_TIMER:OFF_GROWTH_TIMER + 4])[0],
            'age_final': struct.unpack('<f', arm_image[OFF_AGE:OFF_AGE + 4])[0],
        })

    report = {
        'sha256': SHA,
        'class': 'VinePlant',
        'method': LONG_SELECTOR,
        'imp': hex(IMP),
        'code_words': 681,
        'image_size': IMAGE_SIZE,
        'cases': len(rows),
        'match': True,
        'rows': rows,
        'boundary': (
            "Unicorn execution of the original 681-word mirror twin: super2 with all "
            "six arguments, the four keys (numberOfOccupiedTilesBelow/growthTimer/"
            "availableFood/saveTime), initSubDerivedItems before the availableFood "
            "read, the normalised lrand48 dose, the age/compost gate, dieOfOldAge, "
            "and the growth loop with the EXTRA light/sun suitability key (two "
            "__aeabi_idiv calls), the inverted tile-kind gate (kind 3 and byte0 31 "
            "are rejected), marker 0x7C and the 900.0f energy constant. Not "
            "Foundation, not the original-app runtime, no device run."
        )
    }
    (a.output_dir / 'vine_plant_init_arm_result.json').write_text(json.dumps(report, indent=2))
    print(f"vine_plant_init_arm: PASS ({len(rows)} cases)")
    print(json.dumps(report, indent=2))


def _first_diff(a, b):
    for i in range(max(len(a), len(b))):
        left = a[i] if i < len(a) else None
        right = b[i] if i < len(b) else None
        if left != right:
            return {'index': i, 'arm': left, 'cpp': right,
                    'arm_len': len(a), 'cpp_len': len(b)}
    return None


if __name__ == '__main__':
    main()
