#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of the Workbench loader (batch b4q)

  -[Workbench initWithWorld:dynamicWorld:saveDict:cache:]   IMP 0x00AE4ED8

under Unicorn and compare the 324-byte instance image, the return value and
the full (code, arg) trace against the recovered C++ contract at -O0/-O2.
The LAST executed front member (1,390 words) — the crafting centerpiece.

Executed key order (frozen by the run, b4q):
  workbenchType(intValue) selectedIndex(intValue) xScroll(floatValue)
  level(intValue) craftProgressCount(floatValue) hurryTimer(floatValue)
  hurrySeconds(floatValue) hurrying(boolValue) ...

Harness facts:
* super2 (GOT 0x0105B79C) + msgSend (0x0105B7A0) + msgSend_stret (veneer
  0x1C2918 -> GOT 0x105FB6C, the craftableItem struct return) share the
  selector-string stub; for stret r0 = the result buffer, r1 = receiver,
  r2 = selector (ARM32 convention).
* memcpy (veneer 0x1C2894 -> GOT 0x105FB40) copies the craftingItemData v1
  blob; __android_log_print (GOT 0x105FB68) is stubbed as a no-op record.
* memset (0x1C2924 -> 0x105FB70) and objc_enumerationMutation
  (0x1C2E28 -> 0x105FD1C) are stubbed (b4p precedent); 32-bit
  NSFastEnumerationState: state@0, itemsPtr@4, mutationsPtr@8.
* The craftable classrefs carry their class words on disk:
  BlockheadCraftableItemObject 0x00E91228 (type 1),
  PaintingCraftableItemObject 0x00E90E18 (type 2),
  CraftableItemObject 0x00E91CC8 (else); ArtificialLight 0x00E91B10.
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
from trace_codes_gen import WORKBENCH_INIT_CODES as VC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x00AE4ED8
IMAGE_SIZE = 324          # Workbench class_ro_t instance_size
SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'

GOT_MSGSEND_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
GOT_STRET = 0x105FB6C
GOT_MEMCPY = 0x105FB40
GOT_LOGPRINT = 0x105FB68
SUPERREF_SLOT = 0x00E8BE80
WORKBENCH_CLASS = 0x00E91D40

STUB_MSG = 0x72000000
STUB_STRET = 0x72004000
STUB_MEMCPY = 0x72005000
STUB_LOG = 0x72006000
STACK_OFFSET = 0x8000

SAVE_DICT = 0x60010000
CLUSTER_V2 = 0x5E1A0C10
CLUSTER_V1 = 0x5E1A0C20
LIGHT_DICT = 0x5E1A0C30
SLOT_ARRAY = 0x5E1A0C40
FRESH_SLOT = 0x5E1A0C50
BLOCKHEAD_CRAFTABLE_CLASS = 0x00E91228
PAINTING_CRAFTABLE_CLASS = 0x00E90E18
CRAFTABLE_CLASS = 0x00E91CC8
ARTIFICIAL_LIGHT_CLASS = 0x00E91B10

OFF_POS = 16
OFF_CACHE = 32
OFF_IS_IN_USE = 68
OFF_CURRENT_BLOCKHEAD = 56
OFF_CURRENT_FUEL = 108
OFF_SAVED_BH_FUEL = 116
OFF_IS_IN_USE_FUEL = 112
OFF_LIGHT = 100
OFF_SOURCE_ITEMS = 140
OFF_SELECTED_INDEX = 136
OFF_X_SCROLL = 172
OFF_LEVEL = 176
OFF_CRAFT_PROGRESS = 188
OFF_HURRY_TIMER = 192
OFF_HURRY_SECONDS = 196
OFF_HURRYING = 200
OFF_HURRY_COST = 204
OFF_FIRE_SPREAD = 208
OFF_FUEL_FRACTION = 212
OFF_HAS_FUEL = 220
OFF_AVAILABLE_ELEC = 222
OFF_LAST_WORLD_TIME = 256
OFF_TYPE = 120
OFF_COUNT_CREATED = 236
OFF_COUNT_LEFT = 232
OFF_COUNT = 228
OFF_CRAFTING_ITEM = 180

# per-key box tokens (executed fact: the spill-driven call chain)
BOX = {
    'workbenchType': 0x5E1A0C61,
    'selectedIndex': 0x5E1A0C62,
    'xScroll': 0x5E1A0C63,
    'level': 0x5E1A0C64,
    'craftProgressCount': 0x5E1A0C65,
    'hurryTimer': 0x5E1A0C66,
    'hurrySeconds': 0x5E1A0C67,
    'hurrying': 0x5E1A0C68,
    'hurryCost': 0x5E1A0C69,
    'fireSpreadTimer': 0x5E1A0C6A,
    'fuelFraction': 0x5E1A0C6B,
    'hasFuel': 0x5E1A0C6C,
    'lastWorldTime': 0x5E1A0C6D,
    'isInUseFuel': 0x5E1A0C6E,
    'availableElectricity': 0x5E1A0C6F,
    'currentBlockheadIndexFuel': 0x5E1A0C70,
    'countCreated': 0x5E1A0C71,
    'countLeft': 0x5E1A0C72,
    'count': 0x5E1A0C73,
}


def low32(value):
    return struct.unpack('<I', struct.pack('<d', value)[:4])[0]


def float_bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


BASE = {
    'self_ptr': 0x60000000,
    'super_returns_nil': False,
    'world_argument': 0x5E1A0010,
    'dynamic_world_argument': 0x5E1A0020,
    'save_dict_token': SAVE_DICT,
    'cache_token': 0x5E1A0030,
    'world_ivar': 0x5E1A0004,
    'dynamic_world_ivar': 0x5E1A0008,
    'cache_ivar': 0x5E1A0040,
    'pos_x': 12,
    'pos_y': 34,
    'is_in_use_init': 0,
    'workbench_type_value': 3,
    'selected_index_value': 1,
    'x_scroll_value': 2.5,
    'level_value': 2,
    'craft_progress_value': 0.5,
    'hurry_timer_value': 7.0,
    'hurry_seconds_value': 8.0,
    'hurrying_value': 0,
    'hurry_cost_value': 5,
    'fire_spread_value': 9.0,
    'fuel_fraction_value': 0.75,
    'has_fuel_value': 1,
    'last_world_time_value': 123.5,
    'is_in_use_fuel_value': 0,
    'available_elec_value': 42,
    'blockhead_index_fuel_value': -1,     # -1 sentinel -> no re-read
    'is_in_use': 0,
    'crafting_v2_present': False,
    'craftable_object_type': 1,
    'crafting_v1_present': False,
    'crafting_item_nonnil': False,
    'craftable_item_stret_type': 1,
    'count_created_value': 0,
    'count_left_value': 0,
    'count_value': 0,
    'source_slots': [],                   # per-slot list of sub-item types
    'current_blockhead': 0x5E1A0050,
    'current_fuel_blockhead': 0x5E1A0060,
    'light_dict_present': False,
    'light_answer': 0x5E1A0C80,
}


class BridgeInput(ctypes.Structure):
    _fields_ = [
        ('self_ptr', ctypes.c_uint32),
        ('super_returns_nil', ctypes.c_uint32),
        ('world_argument', ctypes.c_uint32),
        ('dynamic_world_argument', ctypes.c_uint32),
        ('save_dict_token', ctypes.c_uint32),
        ('cache_token', ctypes.c_uint32),
        ('world_ivar', ctypes.c_uint32),
        ('dynamic_world_ivar', ctypes.c_uint32),
        ('cache_ivar', ctypes.c_uint32),
        ('pos_x', ctypes.c_int32),
        ('pos_y', ctypes.c_int32),
        ('is_in_use_init', ctypes.c_uint32),
        ('workbench_type_value', ctypes.c_uint32),
        ('selected_index_value', ctypes.c_uint32),
        ('x_scroll_value', ctypes.c_float),
        ('level_value', ctypes.c_uint32),
        ('craft_progress_value', ctypes.c_float),
        ('hurry_timer_value', ctypes.c_float),
        ('hurry_seconds_value', ctypes.c_float),
        ('hurrying_value', ctypes.c_uint32),
        ('hurry_cost_value', ctypes.c_uint32),
        ('fire_spread_value', ctypes.c_float),
        ('fuel_fraction_value', ctypes.c_float),
        ('has_fuel_value', ctypes.c_uint32),
        ('last_world_time_value', ctypes.c_double),
        ('is_in_use_fuel_value', ctypes.c_uint32),
        ('available_elec_value', ctypes.c_uint32),
        ('blockhead_index_fuel_value', ctypes.c_int32),
        ('is_in_use', ctypes.c_uint32),
        ('crafting_v2_present', ctypes.c_uint32),
        ('craftable_object_type', ctypes.c_uint32),
        ('crafting_v1_present', ctypes.c_uint32),
        ('crafting_item_nonnil', ctypes.c_uint32),
        ('craftable_item_stret_type', ctypes.c_uint32),
        ('count_created_value', ctypes.c_uint32),
        ('count_left_value', ctypes.c_uint32),
        ('count_value', ctypes.c_uint32),
        ('slot_count', ctypes.c_uint32),
        ('slot_elem_counts', ctypes.c_uint32 * 16),
        ('sub_types', ctypes.c_uint32 * 64),
        ('sub_type_count', ctypes.c_uint32),
        ('current_blockhead', ctypes.c_uint32),
        ('current_fuel_blockhead', ctypes.c_uint32),
        ('light_dict_present', ctypes.c_uint32),
        ('light_answer', ctypes.c_uint32),
        ('sub_page_base', ctypes.c_uint32),
    ]


CASES = [
    {'name': 'super_nil', 'super_returns_nil': True},
    {'name': 'plain_keys'},
    {'name': 'index_fuel_reread', 'blockhead_index_fuel_value': 7},
    {'name': 'v2_type1', 'is_in_use': 1, 'crafting_v2_present': True,
     'craftable_object_type': 1, 'crafting_item_nonnil': True},
    {'name': 'v2_type2', 'is_in_use': 1, 'crafting_v2_present': True,
     'craftable_object_type': 2, 'crafting_item_nonnil': True},
    {'name': 'v2_type_other', 'is_in_use': 1, 'crafting_v2_present': True,
     'craftable_object_type': 9, 'crafting_item_nonnil': True},
    {'name': 'v1_migration', 'is_in_use': 1, 'crafting_v1_present': True,
     'crafting_item_nonnil': True},
    {'name': 'in_use_no_data', 'is_in_use': 1},
    {'name': 'source_items_walk', 'is_in_use': 1, 'crafting_v2_present': True,
     'craftable_object_type': 1, 'crafting_item_nonnil': True,
     'source_slots': [[7, 11, 9], []], 'count_value': 1},
    {'name': 'fuel_blockhead_wire', 'is_in_use_fuel_value': 1},
    {'name': 'light_dict_restore', 'light_dict_present': True},
]


def build_bridge(root, out_dir):
    fns = []
    for opt in (0, 2):
        so_path = out_dir / f'workbench_init-O{opt}.so'
        cmd = ['clang++', f'-O{opt}', '-shared', '-fPIC', '-std=c++17',
               '-fno-fast-math', '-ffp-contract=off',
               '-I', str(root / 'reconstruction/recovered'),
               str(root / 'tools/workbench_init_arm_bridge.cpp'),
               str(root / 'reconstruction/recovered/workbench_init.cpp'),
               '-o', str(so_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        cdll = ctypes.CDLL(str(so_path))
        fn = cdll.recovered_workbench_init_run
        fn.argtypes = [ctypes.POINTER(BridgeInput), ctypes.c_char_p,
                       ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))
    return fns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--only', default=None)
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--arm-only', action='store_true')
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
    session.patch_got(GOT_MSGSEND_SUPER2, STUB_MSG)
    session.patch_got(GOT_MSGSEND, STUB_MSG)
    session.patch_got(GOT_STRET, STUB_STRET)
    session.patch_got(0x0105FB18, STUB_MSG)       # msgSend veneer
    session.patch_got(GOT_MEMCPY, STUB_MEMCPY)
    session.patch_got(GOT_LOGPRINT, STUB_LOG)
    assert session.read_word(SUPERREF_SLOT) == WORKBENCH_CLASS, 'superref drift'
    cmd_sel = graph.command_selector(SELECTOR)

    # memset + enumerationMutation stubs (b4p addresses)
    session.patch_got(0x0105FB70, 0x72003000)
    session.patch_got(0x0105FD1C, 0x72003008)
    uc.mem_map(0x72003000, 0x1000)
    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3,
                                   UC_ARM_REG_PC, UC_ARM_REG_LR)

    def hook_memset(uc_, address, size, data):
        dst = uc_.reg_read(UC_ARM_REG_R0)
        n = uc_.reg_read(UC_ARM_REG_R1)
        if n:
            uc_.mem_write(dst, b'\x00' * n)
        uc_.reg_write(UC_ARM_REG_R0, dst)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    def hook_enum_mutation(uc_, address, size, data):
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_memset, begin=0x72003000, end=0x72003000 + 4)
    uc.hook_add(UC_HOOK_CODE, hook_enum_mutation, begin=0x72003008,
                end=0x72003008 + 4)

    dispatcher = MsgDispatcher(uc, STUB_MSG)
    state = {'case': None, 'sub_served': {}, 'sub_issued': 0,
             'sub_token_type': {}, 'cur_item_types': {}}

    def case():
        return state['case']

    mut_addr = graph.alloc(0x20)
    graph.word(mut_addr, 0)
    sub_page = graph.alloc(0x800)

    @dispatcher.register(SELECTOR)
    def on_super(ctx):
        c = case()
        sup = ctx.recv
        assert ctx.word(sup) == c['self_ptr'], 'super2 receiver'
        assert ctx.word(sup + 4) == WORKBENCH_CLASS, 'super2 own class'
        assert ctx.r2 == c['world_argument']
        assert ctx.r3 == c['dynamic_world_argument']
        assert ctx.stack_word(0) == c['save_dict_token']
        assert ctx.stack_word(4) == c['cache_token']
        ctx.record(VC['MsgSendSuper'], c['self_ptr'])
        return (0 if c['super_returns_nil'] else c['self_ptr'], None)

    @dispatcher.register('objectForKey:')
    def on_object_for_key(ctx):
        c = case()
        recv = ctx.recv
        data = struct.unpack('<I', bytes(uc.mem_read(ctx.r2 + 8, 4)))[0]
        key = bytes(uc.mem_read(data, 64)).split(b'\0')[0].decode()
        if recv == CLUSTER_V2 and key == 'craftableObjectType':
            ctx.record(VC['ObjectForKeyCraftableObjectType'], 0x5E1A0C74)
            return (0x5E1A0C74, None)
        table = {
            'workbenchType': (VC['ObjectForKeyWorkbenchType'], BOX['workbenchType']),
            'selectedIndex': (VC['ObjectForKeySelectedIndex'], BOX['selectedIndex']),
            'xScroll': (VC['ObjectForKeyXScroll'], BOX['xScroll']),
            'level': (VC['ObjectForKeyLevel'], BOX['level']),
            'craftProgressCount': (VC['ObjectForKeyCraftProgressCount'], BOX['craftProgressCount']),
            'hurryTimer': (VC['ObjectForKeyHurryTimer'], BOX['hurryTimer']),
            'hurrySeconds': (VC['ObjectForKeyHurrySeconds'], BOX['hurrySeconds']),
            'hurrying': (VC['ObjectForKeyHurrying'], BOX['hurrying']),
            'hurryCost': (VC['ObjectForKeyHurryCost'], BOX['hurryCost']),
            'fireSpreadTimer': (VC['ObjectForKeyFireSpreadTimer'], BOX['fireSpreadTimer']),
            'fuelFraction': (VC['ObjectForKeyFuelFraction'], BOX['fuelFraction']),
            'hasFuel': (VC['ObjectForKeyHasFuel'], BOX['hasFuel']),
            'lastWorldTime': (VC['ObjectForKeyLastWorldTime'], BOX['lastWorldTime']),
            'isInUseFuel': (VC['ObjectForKeyIsInUseFuel'], BOX['isInUseFuel']),
            'availableElectricity': (VC['ObjectForKeyAvailableElectricity'], BOX['availableElectricity']),
            'currentBlockheadIndexFuel': (VC['ObjectForKeyBlockheadIndexFuel'], BOX['currentBlockheadIndexFuel']),
            'craftingItemDatav2': (VC['ObjectForKeyCraftingItemDatav2'],
                                   CLUSTER_V2 if c['crafting_v2_present'] else 0),
            'craftingItemData': (VC['ObjectForKeyCraftingItemData'],
                                 CLUSTER_V1 if c['crafting_v1_present'] else 0),
            'lightDict': (VC['ObjectForKeyLightDict'],
                          LIGHT_DICT if c['light_dict_present'] else 0),
            'countCreated': (VC['ObjectForKeyCountCreated'], BOX['countCreated']),
            'countLeft': (VC['ObjectForKeyCountLeft'], BOX['countLeft']),
            'count': (VC['ObjectForKeyCount'], BOX['count']),
        }
        if key.startswith('sourceItems_'):
            idx = int(key.split('_')[1])
            ctx.record(VC['ObjectForKeySourceItemsAt'], idx)
            slots = c['source_slots']
            return (SLOT_ARRAY + idx * 8, None)
        assert key in table, f'unexpected key {key!r} recv={hex(recv)}'
        code, token = table[key]
        ctx.record(code, token)
        return (token, None)

    @dispatcher.register('intValue')
    def on_int_value(ctx):
        c = case()
        recv = ctx.recv
        table = {
            BOX['workbenchType']: (VC['IntValueWorkbenchType'], c['workbench_type_value']),
            BOX['selectedIndex']: (VC['IntValueSelectedIndex'], c['selected_index_value']),
            BOX['level']: (VC['IntValueLevel'], c['level_value']),
            BOX['hurryCost']: (VC['IntValueHurryCost'], c['hurry_cost_value']),
            BOX['hasFuel']: (VC['IntValueHasFuel'], c['has_fuel_value']),
            BOX['availableElectricity']: (VC['IntValueAvailableElectricity'], c['available_elec_value']),
            BOX['currentBlockheadIndexFuel']: (VC['IntValueBlockheadIndexFuel'],
                                               c['blockhead_index_fuel_value'] & 0xffffffff),
            BOX['countCreated']: (VC['IntValueCountCreated'], c['count_created_value']),
            BOX['countLeft']: (VC['IntValueCountLeft'], c['count_left_value']),
            BOX['count']: (VC['IntValueCount'], c['count_value']),
        }
        if recv == 0x5E1A0C74:
            ctx.record(VC['IntValueCraftableObjectType'], c['craftable_object_type'])
            return (c['craftable_object_type'], None)
        assert recv in table, f'intValue on {hex(recv)}'
        code, value = table[recv]
        ctx.record(code, value)
        return (value, None)

    @dispatcher.register('floatValue')
    def on_float_value(ctx):
        c = case()
        recv = ctx.recv
        table = {
            BOX['xScroll']: (VC['FloatValueXScroll'], c['x_scroll_value']),
            BOX['craftProgressCount']: (VC['FloatValueCraftProgressCount'], c['craft_progress_value']),
            BOX['hurryTimer']: (VC['FloatValueHurryTimer'], c['hurry_timer_value']),
            BOX['hurrySeconds']: (VC['FloatValueHurrySeconds'], c['hurry_seconds_value']),
            BOX['fireSpreadTimer']: (VC['FloatValueFireSpreadTimer'], c['fire_spread_value']),
            BOX['fuelFraction']: (VC['FloatValueFuelFraction'], c['fuel_fraction_value']),
        }
        assert recv in table, f'floatValue on {hex(recv)}'
        code, value = table[recv]
        ctx.record(code, float_bits(value))
        return (float_bits(value), None)

    @dispatcher.register('doubleValue')
    def on_double_value(ctx):
        c = case()
        assert ctx.recv == BOX['lastWorldTime'], 'doubleValue receiver'
        ctx.record(VC['DoubleValueLastWorldTime'],
                   low32(c['last_world_time_value']))
        half = struct.unpack('<II', struct.pack('<d', c['last_world_time_value']))
        return (half[0], half[1])

    @dispatcher.register('unsignedIntValue')
    def on_unsigned_int_value(ctx):
        c = case()
        assert ctx.recv == BOX['availableElectricity'], 'unsignedIntValue receiver'
        ctx.record(VC['IntValueAvailableElectricity'], c['available_elec_value'])
        return (c['available_elec_value'], None)

    @dispatcher.register('boolValue')
    def on_bool_value(ctx):
        c = case()
        recv = ctx.recv
        if recv == BOX['hurrying']:
            flag = 1 if c['hurrying_value'] else 0
            ctx.record(VC['IntValueHurrying'], flag)
            return (flag, None)
        if recv == BOX['hasFuel']:
            flag = 1 if c['has_fuel_value'] else 0
            ctx.record(VC['IntValueHasFuel'], flag)
            return (flag, None)
        if recv == BOX['isInUseFuel']:
            flag = 1 if c['is_in_use_fuel_value'] else 0
            ctx.record(VC['BoolValueIsInUseFuel'], flag)
            return (flag, None)
        raise AssertionError(('boolValue receiver', hex(recv)))

    @dispatcher.register('alloc')
    def on_alloc(ctx):
        if ctx.recv == BLOCKHEAD_CRAFTABLE_CLASS:
            ctx.record(VC['CraftableAlloc'], 1)
            return (0x5E1A0C90, None)
        if ctx.recv == PAINTING_CRAFTABLE_CLASS:
            ctx.record(VC['CraftableAlloc'], 2)
            return (0x5E1A0C98, None)
        if ctx.recv == CRAFTABLE_CLASS:
            ctx.record(VC['CraftableAlloc'], 0)
            return (0x5E1A0CA0, None)
        if ctx.recv == ARTIFICIAL_LIGHT_CLASS:
            ctx.record(VC['ArtificialLightAlloc'], 0)
            return (0x5E1A0CA8, None)
        if ctx.recv == 0x00E91CA0:   # InventoryItem classref (b4p constant)
            ctx.record(VC['InventoryAlloc'], 0)
            return (0x5E1A0D00 + state['sub_issued'] * 8, None)
        if ctx.recv == 0:    # the per-slot NSMutableArray classref (reloc slot)
            ctx.record(VC['MutableArrayAllocSlot'], 0)
            return (FRESH_SLOT, None)
        raise AssertionError(f'alloc on {hex(ctx.recv)}')

    @dispatcher.register('initWithSaveDict:')
    def on_init_with_save_dict(ctx):
        c = case()
        ctx.record(VC['CraftableInitWithSaveDict'], ctx.r2)
        return (0x5E1A0CB0 if c['crafting_item_nonnil'] else 0, None)

    @dispatcher.register('initWithCraftableItem:')
    def on_init_with_craftable_item(ctx):
        c = case()
        ctx.record(VC['CraftableInitWithCraftableItem'], ctx.r2)
        return (0x5E1A0CB0 if c['crafting_item_nonnil'] else 0, None)

    @dispatcher.register('bytes')
    def on_bytes(ctx):
        c = case()
        assert ctx.recv == CLUSTER_V1, 'bytes receiver'
        ctx.record(VC['BytesCopy'], 0)
        # the memcpy right after reads 124 bytes from this pointer
        blob = graph.alloc(0x100)
        uc.mem_write(blob, bytes(range(124)))
        return (blob, None)

    @dispatcher.register('initWithWorld:dynamicWorld:saveDict:cache:parentObject:')
    def on_light_init(ctx):
        c = case()
        ctx.record(VC['LightInitWithWorld'], 0)
        return (c['light_answer'], None)

    @dispatcher.register('stringWithFormat:')
    def on_string_with_format(ctx):
        c = case()
        data = struct.unpack('<I', bytes(uc.mem_read(ctx.r2 + 8, 4)))[0]
        fmt = bytes(uc.mem_read(data, 64)).split(b'\0')[0].decode()
        assert fmt == 'sourceItems_%d', f'unexpected format {fmt!r}'
        idx = ctx.r3 & 0xf
        ctx.record(VC['StringWithFormatSourceItems'], idx)
        # the synthesized key must be a CFString the objectForKey: handler
        # can decode through its +8 data pointer
        return (graph.cfstring(f'sourceItems_{idx}'), None)

    @dispatcher.register('countByEnumeratingWithState:objects:count:')
    def on_enumerate(ctx):
        c = case()
        st = ctx.r2
        buf = ctx.r3
        assert SLOT_ARRAY <= ctx.recv < SLOT_ARRAY + 0x100, (
            'enumerate recv', hex(ctx.recv))
        slot_index = (ctx.recv - SLOT_ARRAY) // 8
        slots = c['source_slots']
        subs = slots[slot_index] if slot_index < len(slots) else []
        served = state['sub_served'].get(ctx.recv, 0)
        batch = subs[served:served + 16]
        state['sub_served'][ctx.recv] = served + len(batch)
        ctx.record(VC['CountByEnumeratingSource'], len(batch))
        for i in range(len(batch)):
            token = sub_page + state['sub_issued'] * 8
            state['sub_issued'] += 1
            graph.word(buf + i * 4, token)
            state['sub_token_type'][token] = batch[i]
        graph.word(st + 0, 0)
        graph.word(st + 4, buf)
        graph.word(st + 8, mut_addr)
        return (len(batch), None)

    @dispatcher.register('initWithSaveData:')
    def on_init_with_save_data(ctx):
        assert ctx.r2 in state['sub_token_type'], (
            'initWithSaveData payload', hex(ctx.r2))
        state['cur_item_types'][ctx.recv] = state['sub_token_type'][ctx.r2]
        ctx.record(VC['InventoryInitWithSaveData'], ctx.r2)
        return (ctx.recv, None)

    @dispatcher.register('count')
    def on_count(ctx):
        c = case()
        recv = ctx.recv
        if SLOT_ARRAY <= recv < SLOT_ARRAY + 0x100:
            idx = (recv - SLOT_ARRAY) // 8
            slots = c['source_slots']
            n = len(slots[idx]) if idx < len(slots) else 0
            ctx.record(VC['ObjectForKeySourceItemsAt'], n)
            return (n, None)
        raise AssertionError(('count receiver', hex(recv)))

    @dispatcher.register('autorelease')
    def on_autorelease(ctx):
        ctx.record(VC['InventoryAutorelease'], 0)
        return (ctx.recv, None)

    @dispatcher.register('addObject:')
    def on_add_object(ctx):
        ctx.record(VC['SlotAddObject'], ctx.r2)
        return (0, None)

    @dispatcher.register('setInteractionWorkbench:')
    def on_set_interaction(ctx):
        c = case()
        if ctx.recv == c['current_fuel_blockhead']:
            ctx.record(VC['SetInteractionWorkbenchFuel'], ctx.r2)
        else:
            ctx.record(VC['SetInteractionWorkbenchCraft'], ctx.r2)
        return (0, None)

    @dispatcher.register('release')
    def on_release(ctx):
        c = case()
        ctx.record(VC['ReleaseSlot'], 0)
        return (0, None)

    @dispatcher.register('initSubDerivedItems')
    def on_init_sub_derived(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'initSubDerivedItems receiver'
        ctx.record(VC['InitSubDerivedItems'], 0)
        return (ctx.recv, None)

    @dispatcher.register('macroTiles')
    def on_macro_tiles(ctx):
        c = case()
        assert ctx.recv == c['world_ivar'], 'macroTiles receiver'
        ctx.record(VC['MacroTiles'], 0)
        # the 0xA197B4 consumer walks the array; hand it a zeroed page
        tiles = graph.alloc(0x400)
        uc.mem_write(tiles, b'\x00' * 0x400)
        return (tiles, None)

    @dispatcher.register('worldWidthMacro')
    def on_world_width(ctx):
        c = case()
        assert ctx.recv == c['world_ivar'], 'worldWidthMacro receiver'
        ctx.record(VC['MacroTiles'], 1)
        return (64, None)

    @dispatcher.register('init')
    def on_init(ctx):
        ctx.record(VC['MutableArrayInitSlot'], ctx.recv)
        return (ctx.recv, None)

    if a.debug:
        for _sel, _fn in list(dispatcher.handlers.items()):
            def _wrap(_fn=_fn, _sel=_sel):
                def inner(ctx):
                    print(f'DISPATCH {_sel} recv={hex(ctx.recv)} r2={hex(ctx.r2)}',
                          file=sys.stderr)
                    return _fn(ctx)
                return inner
            dispatcher.handlers[_sel] = _wrap()
    dispatcher.install()

    # memcpy stub (the craftingItemData v1 blob copy): r0=dst, r1=src, r2=len
    uc.mem_map(STUB_MEMCPY, 0x1000)

    def hook_memcpy(uc_, address, size, data):
        c = case()
        dst = uc_.reg_read(UC_ARM_REG_R0)
        src = uc_.reg_read(UC_ARM_REG_R1)
        n = uc_.reg_read(UC_ARM_REG_R2)
        if n:
            uc_.mem_write(dst, bytes(uc_.mem_read(src, n)))
        dispatcher.trace.append((VC['BytesCopy'], n))
        uc_.reg_write(UC_ARM_REG_R0, dst)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_memcpy, begin=STUB_MEMCPY,
                end=STUB_MEMCPY + 4)

    # __android_log_print stub
    uc.mem_map(STUB_LOG, 0x1000)

    def hook_log(uc_, address, size, data):
        dispatcher.trace.append((VC['AndroidLogPrint'], 0))
        uc_.reg_write(UC_ARM_REG_R0, 0)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_log, begin=STUB_LOG, end=STUB_LOG + 4)

    # objc_msgSend_stret: r0 = result buffer, r1 = receiver, r2 = selector
    uc.mem_map(STUB_STRET, 0x1000)

    def hook_stret(uc_, address, size, data):
        c = case()
        sel_ptr = uc_.reg_read(UC_ARM_REG_R2)
        sel = bytes(uc_.mem_read(sel_ptr, 64)).split(b'\0')[0].decode()
        if sel == 'craftableItem':
            # the 124-byte CraftableItem struct (the 0x7c memset at 0xAE5B7C
            # bounds it): +0x00 the type, +0x48 the source-slot count that
            # gates the sourceItems_%d loop.
            out_buf = uc_.reg_read(UC_ARM_REG_R0)
            blob = bytearray(124)
            struct.pack_into('<I', blob, 0x00, c['craftable_item_stret_type'])
            struct.pack_into('<I', blob, 0x48, len(c['source_slots']))
            uc_.mem_write(out_buf, bytes(blob))
            dispatcher.trace.append((VC['CraftableItemStret'],
                                     c['craftable_item_stret_type']))
        else:
            raise AssertionError(('unimplemented stret selector', sel))
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_stret, begin=STUB_STRET, end=STUB_STRET + 4)

    # __aeabi_idiv stub (b4o precedent): the 0xA197B4 helper (the macroTiles
    # consumer / tile-light updater) reaches it via veneer 0x1C3728.
    STUB_IDIV = 0x72002000
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

    # PLT-resolver trap: any call through an UNPATCHED GOT slot lands here
    # (0x1C27C0 -> GOT[2] -> 0x134). Log the caller to identify the import.
    def hook_plt(uc_, address, size, data):
        from unicorn.arm_const import UC_ARM_REG_LR as _LR
        print(f'PLT-RESOLVER hit, caller lr={uc_.reg_read(_LR):#x}',
              file=sys.stderr)
        raise AssertionError('unpatched GOT import')

    uc.hook_add(UC_HOOK_CODE, hook_plt, begin=0x1C27C0, end=0x1C27C0 + 4)

    root = Path(__file__).resolve().parents[1]
    fns = [] if a.arm_only else build_bridge(root, a.output_dir)
    names = {v: k for k, v in VC.items()}

    rows = []
    for case_def in CASES:
        if a.only and case_def['name'] != a.only:
            continue
        merged = dict(BASE)
        merged.update({k: v for k, v in case_def.items() if k != 'name'})
        state['case'] = merged
        state['sub_served'] = {}
        state['sub_issued'] = 0
        state['sub_token_type'] = {}
        state['cur_item_types'] = {}
        dispatcher.trace.clear()

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        # the super's side effect: the isInUse ivar (the gate reads it)
        uc.mem_write(self_ptr + OFF_IS_IN_USE,
                     bytes([1 if merged['is_in_use'] else 0]))
        session.word(self_ptr + 4, merged['world_ivar'])
        session.word(self_ptr + 8, merged['dynamic_world_ivar'])
        session.word(self_ptr + 32, merged['cache_ivar'])
        session.word(self_ptr + OFF_POS, merged['pos_x'] & 0xffffffff)
        session.word(self_ptr + OFF_POS + 4, merged['pos_y'] & 0xffffffff)
        session.word(self_ptr + OFF_CURRENT_BLOCKHEAD, merged['current_blockhead'])
        session.word(self_ptr + OFF_CURRENT_FUEL, merged['current_fuel_blockhead'])


        stack_top = session.stack + STACK_OFFSET
        uc.mem_write(stack_top, struct.pack(
            '<II', merged['save_dict_token'], merged['cache_token']))

        try:
            session.run(IMP, sp_offset=STACK_OFFSET, count=4000000,
                        R0=self_ptr, R1=cmd_sel, R2=merged['world_argument'],
                        R3=merged['dynamic_world_argument'])
        except Exception as exc:
            from unicorn.arm_const import UC_ARM_REG_PC
            print(f'RUN ERROR in {case_def["name"]}: {exc} at pc='
                  f'{uc.reg_read(UC_ARM_REG_PC):#x}', file=sys.stderr)
            raise

        arm_ret = uc.reg_read(UC_ARM_REG_R0)
        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(dispatcher.trace)
        expected_ret = 0 if merged['super_returns_nil'] else self_ptr
        assert arm_ret == expected_ret, ('return', hex(arm_ret), hex(expected_ret))
        if a.debug:
            print(f'--- {case_def["name"]} arm trace:')
            for code, arg in arm_trace:
                print(f'    {names.get(code, code):34s} {arg:#x}')

        if a.arm_only:
            rows.append({'case': case_def['name'],
                         'trace_len': len(arm_trace), 'return': hex(arm_ret)})
            continue

        cfg = BridgeInput()
        for f in ('self_ptr', 'world_argument', 'dynamic_world_argument',
                  'save_dict_token', 'cache_token', 'world_ivar',
                  'dynamic_world_ivar', 'cache_ivar', 'current_blockhead',
                  'current_fuel_blockhead'):
            setattr(cfg, f, merged[f])
        cfg.super_returns_nil = 1 if merged['super_returns_nil'] else 0
        cfg.pos_x = merged['pos_x']
        cfg.pos_y = merged['pos_y']
        # the super's isInUse side effect (the gate reads this ivar)
        cfg.is_in_use_init = 1 if merged['is_in_use'] else 0
        cfg.workbench_type_value = merged['workbench_type_value']
        cfg.selected_index_value = merged['selected_index_value']
        cfg.x_scroll_value = merged['x_scroll_value']
        cfg.level_value = merged['level_value']
        cfg.craft_progress_value = merged['craft_progress_value']
        cfg.hurry_timer_value = merged['hurry_timer_value']
        cfg.hurry_seconds_value = merged['hurry_seconds_value']
        cfg.hurrying_value = merged['hurrying_value']
        cfg.hurry_cost_value = merged['hurry_cost_value']
        cfg.fire_spread_value = merged['fire_spread_value']
        cfg.fuel_fraction_value = merged['fuel_fraction_value']
        cfg.has_fuel_value = merged['has_fuel_value']
        cfg.last_world_time_value = merged['last_world_time_value']
        cfg.is_in_use_fuel_value = merged['is_in_use_fuel_value']
        cfg.available_elec_value = merged['available_elec_value']
        cfg.blockhead_index_fuel_value = merged['blockhead_index_fuel_value']
        cfg.is_in_use = merged['is_in_use']
        cfg.crafting_v2_present = 1 if merged['crafting_v2_present'] else 0
        cfg.craftable_object_type = merged['craftable_object_type']
        cfg.crafting_v1_present = 1 if merged['crafting_v1_present'] else 0
        cfg.crafting_item_nonnil = 1 if merged['crafting_item_nonnil'] else 0
        cfg.craftable_item_stret_type = merged['craftable_item_stret_type']
        cfg.count_created_value = merged['count_created_value']
        cfg.count_left_value = merged['count_left_value']
        cfg.count_value = merged['count_value']
        cfg.slot_count = len(merged['source_slots'])
        flat = []
        counts = []
        for slot in merged['source_slots']:
            counts.append(len(slot))
            flat.extend(slot)
        cfg.sub_type_count = len(flat)
        for i, t in enumerate(flat):
            cfg.sub_types[i] = t
        for i, n in enumerate(counts):
            cfg.slot_elem_counts[i] = n
        cfg.light_dict_present = 1 if merged['light_dict_present'] else 0
        cfg.light_answer = merged['light_answer']
        cfg.sub_page_base = sub_page

        for opt, fn in fns:
            image_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_buf = ctypes.create_string_buffer(1024 * 8)
            ret_out = ctypes.c_uint32(0)
            n = fn(ctypes.byref(cfg), image_buf, trace_buf,
                   ctypes.byref(ret_out))
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

        rows.append({
            'case': case_def['name'],
            'trace_len': len(arm_trace),
            'return': hex(arm_ret),
        })

    report = {
        'sha256': SHA,
        'class': 'Workbench',
        'method': SELECTOR,
        'imp': hex(IMP),
        'code_words': 1390,
        'image_size': IMAGE_SIZE,
        'cases': len(rows),
        'match': True,
        'rows': rows,
        'boundary': (
            "Unicorn execution of the original 1,390-word final front member: "
            "super2 with four arguments, the 18-key scalar walk with the "
            "currentBlockheadIndexFuel -1 sentinel re-read, the craftingItemDatav2"
            "/craftingItemData v1->v2 migration (memcpy blob + "
            "__android_log_print + initWithCraftableItem:), the three "
            "craftable classrefs (type 1/2/else), the sourceItems_%d per-slot "
            "NSFastEnumeration with InventoryItem children (type 11 skipped), "
            "setInteractionWorkbench: wiring (craft + fuel blockhead), the "
            "lightDict ArtificialLight 5-arg init, and initSubDerivedItems. "
            "Not Foundation, not the original-app runtime, no device run."
        )
    }
    (a.output_dir / 'workbench_init_arm_result.json').write_text(json.dumps(report, indent=2))
    print(f"workbench_init_arm: PASS ({len(rows)} cases)")
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
