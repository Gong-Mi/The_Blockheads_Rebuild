#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of Chest -[initWithWorld:dynamicWorld:saveDict:cache:]
(IMP 0x00CB627C, 760 words, batch b4m) under Unicorn and compare the 140-byte
instance image, the return value and the full (code, arg) message trace against
the recovered C++ contract (reconstruction/recovered/chest_init_with_world.cpp,
built at -O0 and -O2).

Synthetic model (all of it stated, none of it Foundation):
  * objc_msgSendSuper2 (GOT slot 0x0105B79C) and objc_msgSend (GOT slot
    0x0105B7A0 + veneer slot 0x0105FB18 via 0x001C281C) are stubbed by ONE
    selector-string dispatcher; the super call asserts the objc_super struct
    (receiver + the OWN class word 0x00E92240) and all four forwarded args.
  * objc_msgSend_stret (veneer 0x001C2918 -> slot 0x0105FB6C) writes the
    64-byte customRules struct (byte 0 = case gate, byte 1.. = 0xAB pattern)
    and asserts the receiver is the self->world ivar.
  * memset (veneer 0x001C2924 -> slot 0x0105FB70) executes real byte fills and
    is traced for BOTH call sites (0x40 customRules fallback, 0x20 per-slot
    enumeration state).
  * objc_enumerationMutation (veneer 0x001C2E28 -> slot 0x0105FD1C) is traced.
  * __stack_chk_guard (JUMP_SLOT 0x0105B7E0) is pointed at a mapped canary
    word; 0x001C28B8 (__stack_chk_fail) must never run.
  * The classref cells 0x00E8B618 (NSMutableArray) / 0x00E8B620 (NSString) have
    zero file words -> patched to synthetic class tokens; 0x00E8B61C already
    holds the real InventoryItem class object 0x00E91CA0.
  * The body addresses the REAL ELF CFString objects for chestType /
    safeClientID / saveItemSlots / the two format strings; the dispatcher
    resolves them through the object's +8 data pointer (b4a lesson 7) and
    stringWithFormat: synthesizes CFString-shaped keys with the same layout.
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
from trace_codes_gen import CHEST_INIT_CODES as CH

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x00CB627C
IMAGE_SIZE = 140

# GOT + veneer slots
GOT_MSGSEND_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
GOT_STACK_CHK_GUARD = 0x0105B7E0
VENEER_MSGSEND_SLOT = 0x0105FB18        # 0x001C281C objc_msgSend
VENEER_MSGSEND_STRET_SLOT = 0x0105FB6C  # 0x001C2918 objc_msgSend_stret
VENEER_MEMSET_SLOT = 0x0105FB70         # 0x001C2924 memset
VENEER_MUTATION_SLOT = 0x0105FD1C       # 0x001C2E28 objc_enumerationMutation

# classref cells
ARRAY_CLASS_SLOT = 0x00E8B618
ITEM_CLASS_SLOT = 0x00E8B61C
STRING_CLASS_SLOT = 0x00E8B620
ARRAY_CLASS = 0x00E91C00
ITEM_CLASS = 0x00E91CA0
STRING_CLASS = 0x00E91D00

# superref cell 0x00E8BEF0 (word 0x00E92240 = the OWN class; msgSendSuper2
# resolves the superclass through chest_class->superclass == InteractionObject)
CHEST_CLASS = 0x00E92240

STUB_MSG = 0x72000000
STUB_MEMSET = 0x72100000
STUB_MUTATION = 0x72200000
STUB_STRET = 0x72300000

ITEMS_PAGE = 0x60080000
GUARD_PAGE = 0x600F0000
GUARD_ADDR = GUARD_PAGE + 0x40
MUTATION_ADDR = GUARD_PAGE + 0x80

CHEST_INVENTORY_ARRAY_TOKEN = 0x5E1C0401
CHEST_SLOT_ARRAY_BASE = 0x5E1C1000
CHEST_SHELF_RENDER_BOX_BASE = 0x5E1C1A00
CHEST_SHELF_ITEM_DATA_BOX_BASE = 0x5E1C1B00

STACK_OFFSET = 0x8000


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
        ('pos_x', ctypes.c_uint32),
        ('pos_y', ctypes.c_uint32),
        ('owner_id_ivar', ctypes.c_uint32),
        ('has_chest_type_key', ctypes.c_uint32),
        ('chest_type_box_token', ctypes.c_uint32),
        ('chest_type_value', ctypes.c_int32),
        ('rules_byte0', ctypes.c_int32),
        ('safe_client_id_token', ctypes.c_uint32),
        ('object_type_value', ctypes.c_uint32),
        ('slots_array_token', ctypes.c_uint32),
        ('slot_count', ctypes.c_uint32),
        ('slot_item_offsets', ctypes.c_uint32 * 64),
        ('slot_item_counts', ctypes.c_uint32 * 64),
        ('item_count', ctypes.c_uint32),
        ('item_tokens', ctypes.c_uint32 * 512),
        ('item_types', ctypes.c_uint32 * 512),
        ('shelf_render_box_tokens', ctypes.c_uint32 * 4),
        ('shelf_render_values', ctypes.c_uint32 * 4),
        ('shelf_item_data_box_tokens', ctypes.c_uint32 * 4),
        ('shelf_item_data_values', ctypes.c_uint32 * 4),
        ('mutate_slot', ctypes.c_int32),
        ('mutate_item', ctypes.c_int32),
    ]


def slot_items(spec):
    """spec: list of (token, type) tuples."""
    return list(spec)


BASE = {
    'self_ptr': 0x60000000,
    'super_returns_nil': False,
    'world_argument': 0x5E1C0010,
    'dynamic_world_argument': 0x5E1C0020,
    'save_dict_token': 0x60010000,
    'cache_token': 0x5E1C0030,
    'world_ivar': 0x5E1C0004,
    'dynamic_world_ivar': 0x5E1C0008,
    'pos_x': 0x11223344,
    'pos_y': 0x55667788,
    'owner_id_ivar': 0,
    'has_chest_type_key': True,
    'chest_type_box_token': 0x5E1C0A01,
    'chest_type_value': 0,
    'rules_byte0': 0,
    'safe_client_id_token': 0x5E1C0C01,
    'object_type_value': 0x5E1C0041,
    'slots_array_token': 0x5E1C0E01,
    'slots': [],
    'shelf_render_box_tokens': [CHEST_SHELF_RENDER_BOX_BASE + i for i in range(4)],
    'shelf_render_values': [0x11, 0x22, 0x33, 0x44],
    'shelf_item_data_box_tokens': [CHEST_SHELF_ITEM_DATA_BOX_BASE + i for i in range(4)],
    'shelf_item_data_values': [0x1, 0x2, 0x3, 0x4],
    'mutate_slot': -1,
    'mutate_item': -1,
}

CASES = [
    {
        # nil super -> nil, no ivar touched, no key read
        'name': 'super_nil',
        'super_returns_nil': True,
        'owner_id_ivar': 0x0BAD0001,
    },
    {
        # four-slot chest (chestType 2), one item per slot, itemType 11 filtered
        'name': 'chest_type_2_full',
        'chest_type_value': 2,
        'slots': [slot_items([(0x8001, 3)]), slot_items([(0x8002, 11)]),
                  slot_items([(0x8003, 7)]), slot_items([(0x8004, 0)])],
    },
    {
        # default capacity 16, every slot empty (terminal enumeration per slot)
        'name': 'chest_type_0_sixteen',
        'chest_type_value': 0,
        'slots': [slot_items([]) for _ in range(16)],
    },
    {
        # fewer saved slots than the capacity -> pad with empty arrays
        'name': 'count_less_than_capacity',
        'chest_type_value': 2,
        'slots': [slot_items([(0x9001, 1)]), slot_items([(0x9002, 2)])],
    },
    {
        # missing saveItemSlots key -> shelf restore loop
        'name': 'slots_key_missing',
        'chest_type_value': 0,
        'slots_array_token': 0,
        'shelf_render_box_tokens': [CHEST_SHELF_RENDER_BOX_BASE, 0,
                                    CHEST_SHELF_RENDER_BOX_BASE + 2, 0],
        'shelf_render_values': [7, 0, 9, 0],
        'shelf_item_data_box_tokens': [CHEST_SHELF_ITEM_DATA_BOX_BASE, 0,
                                       CHEST_SHELF_ITEM_DATA_BOX_BASE + 2, 0],
        # 0x12345 exercises the strh truncation to 0x2345
        'shelf_item_data_values': [0x12345, 0, 0xFFFF, 0],
    },
    {
        # chestType 4 with a zero rules byte: stays 4, inventoryItems nil
        'name': 'chest_type_4_rules_zero',
        'chest_type_value': 4,
        'slots': [slot_items([]) for _ in range(16)],
    },
    {
        # chestType 4 with a non-zero rules byte: zeroed, RE-READ -> 16-slot path
        'name': 'chest_type_4_rules_gate',
        'chest_type_value': 4,
        'rules_byte0': 1,
        'slots': [slot_items([(0x8100, 4)])] + [slot_items([]) for _ in range(15)],
    },
    {
        # nil world -> 0x40 memset fallback, byte 0 stays 0, chestType stays 4
        'name': 'chest_type_4_world_nil',
        'chest_type_value': 4,
        'world_ivar': 0,
        'slots': [slot_items([]) for _ in range(16)],
    },
    {
        # pre-set ownerID skips the safeClientID default
        'name': 'owner_id_present',
        'owner_id_ivar': 0x5E1C0FFF,
        'chest_type_value': 5,
        'slots': [slot_items([]) for _ in range(4)],
    },
    {
        # ownerID nil + mixed item types across a five-slot chest (capacity 4)
        'name': 'mixed_item_types',
        'chest_type_value': 5,
        'slots': [slot_items([(0xA001, 1), (0xA002, 11), (0xA003, 25)]),
                  slot_items([(0xA004, 11)]),
                  slot_items([(0xA005, 0)]),
                  slot_items([])],
    },
    {
        # chestType key missing -> [nil intValue] -> 0 -> 16-slot path
        'name': 'chest_type_key_missing',
        'has_chest_type_key': False,
        'slots': [slot_items([]) for _ in range(16)],
    },
    {
        # 18 saved items in one slot -> batches 16, 2, 0
        'name': 'chunked_slot_items',
        'chest_type_value': 2,
        'slots': [slot_items([(0xB000 + i, i) for i in range(18)]),
                  slot_items([]), slot_items([]), slot_items([])],
    },
    {
        # the fixture bumps the mutation counter while element 1 is built, so
        # elements 2..3 of that batch observe it (per-batch capture resets)
        'name': 'mutation_during_enumeration',
        'chest_type_value': 2,
        'slots': [slot_items([(0xC001, 1), (0xC002, 2), (0xC003, 3), (0xC004, 4)]),
                  slot_items([(0xC005, 5)]), slot_items([]), slot_items([])],
        'mutate_slot': 0,
        'mutate_item': 1,
    },
]


def build_bridge(root, out_dir):
    fns = []
    for opt in (0, 2):
        so_path = out_dir / f'chest_init_with_world-O{opt}.so'
        cmd = [
            'clang++', f'-O{opt}', '-shared', '-fPIC', '-std=c++17',
            '-I', str(root / 'reconstruction/recovered'),
            str(root / 'tools/chest_init_with_world_arm_bridge.cpp'),
            str(root / 'reconstruction/recovered/chest_init_with_world.cpp'),
            '-o', str(so_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        cdll = ctypes.CDLL(str(so_path))
        fn = cdll.recovered_chest_init_run
        fn.argtypes = [ctypes.POINTER(BridgeInput), ctypes.c_char_p,
                       ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))
    return fns


def bridge_input(case, slots, item_offsets, item_counts, item_tokens, item_types):
    cfg = BridgeInput()
    cfg.self_ptr = case['self_ptr']
    cfg.super_returns_nil = 1 if case['super_returns_nil'] else 0
    cfg.world_argument = case['world_argument']
    cfg.dynamic_world_argument = case['dynamic_world_argument']
    cfg.save_dict_token = case['save_dict_token']
    cfg.cache_token = case['cache_token']
    cfg.world_ivar = case['world_ivar']
    cfg.dynamic_world_ivar = case['dynamic_world_ivar']
    cfg.pos_x = case['pos_x']
    cfg.pos_y = case['pos_y']
    cfg.owner_id_ivar = case['owner_id_ivar']
    cfg.has_chest_type_key = 1 if case['has_chest_type_key'] else 0
    cfg.chest_type_box_token = case['chest_type_box_token']
    cfg.chest_type_value = case['chest_type_value']
    cfg.rules_byte0 = case['rules_byte0']
    cfg.safe_client_id_token = case['safe_client_id_token']
    cfg.object_type_value = case['object_type_value']
    cfg.slots_array_token = case['slots_array_token']
    cfg.slot_count = len(slots)
    for i, (off, cnt) in enumerate(zip(item_offsets, item_counts)):
        cfg.slot_item_offsets[i] = off
        cfg.slot_item_counts[i] = cnt
    cfg.item_count = len(item_tokens)
    for i, tok in enumerate(item_tokens):
        cfg.item_tokens[i] = tok
        cfg.item_types[i] = item_types[i]
    for i in range(4):
        cfg.shelf_render_box_tokens[i] = case['shelf_render_box_tokens'][i]
        cfg.shelf_render_values[i] = case['shelf_render_values'][i]
        cfg.shelf_item_data_box_tokens[i] = case['shelf_item_data_box_tokens'][i]
        cfg.shelf_item_data_values[i] = case['shelf_item_data_values'][i]
    cfg.mutate_slot = case['mutate_slot']
    cfg.mutate_item = case['mutate_item']
    return cfg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    ap.add_argument('--output-dir', type=Path, required=True)
    a = ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)

    # Preload libc++_shared.so (Termux: not in the default dlopen namespace).
    libcpp = Path('/data/data/com.termux/files/usr/lib/libc++_shared.so')
    if libcpp.exists():
        try:
            ctypes.CDLL(str(libcpp), mode=ctypes.RTLD_GLOBAL)
        except Exception:
            pass

    session = ARMSession(a.elf, SHA)
    uc = session.uc
    graph = FixtureGraph(uc)

    uc.mem_map(STUB_MEMSET, 0x1000)
    uc.mem_map(STUB_MUTATION, 0x1000)
    uc.mem_map(STUB_STRET, 0x1000)
    uc.mem_map(ITEMS_PAGE, 0x1000)
    uc.mem_map(GUARD_PAGE, 0x1000)

    # Both message paths of the body reach the same dispatcher.
    session.patch_got(GOT_MSGSEND_SUPER2, STUB_MSG)
    session.patch_got(GOT_MSGSEND, STUB_MSG)
    session.patch_got(VENEER_MSGSEND_SLOT, STUB_MSG)
    session.patch_got(VENEER_MSGSEND_STRET_SLOT, STUB_STRET)
    session.patch_got(VENEER_MEMSET_SLOT, STUB_MEMSET)
    session.patch_got(VENEER_MUTATION_SLOT, STUB_MUTATION)
    # __stack_chk_guard: the slot must hold the ADDRESS of the canary word.
    session.word(GOT_STACK_CHK_GUARD, GUARD_ADDR)

    session.word(ARRAY_CLASS_SLOT, ARRAY_CLASS)
    session.word(STRING_CLASS_SLOT, STRING_CLASS)
    assert session.read_word(ITEM_CLASS_SLOT) == ITEM_CLASS, 'InventoryItem classref drift'

    cmd_sel = graph.command_selector('initWithWorld:dynamicWorld:saveDict:cache:')

    dispatcher = MsgDispatcher(uc, STUB_MSG)

    state = {
        'case': None,
        'trace': [],
        'slot_items': [],
        'item_types': {},
        'slot_of_token': {},
        'cur_slot': None,
        'batch_begin': 0,
        'batch_next': 0,
        'sub': 0,
        'array_creations': 0,
        'last_key_family': None,
        'last_shelf_index': None,
    }

    def chest_type_now():
        return struct.unpack('<i', bytes(uc.mem_read(state['case']['self_ptr'] + 108, 4)))[0]

    def expected_capacity():
        return 4 if chest_type_now() in (2, 5) else 16

    def key_object_name(obj):
        data = struct.unpack('<I', bytes(uc.mem_read(obj + 8, 4)))[0]
        return bytes(uc.mem_read(data, 64)).split(b'\0')[0].decode()

    def shelf_index(name, prefix):
        assert name.startswith(prefix), name
        return int(name[len(prefix):])

    real_keys = set()

    @dispatcher.register('initWithWorld:dynamicWorld:saveDict:cache:')
    def on_super(ctx):
        case = state['case']
        sup = ctx.recv
        assert ctx.word(sup) == case['self_ptr'], 'super2 receiver'
        assert ctx.word(sup + 4) == CHEST_CLASS, 'super2 class word (own class)'
        assert ctx.r2 == case['world_argument'], 'super world argument'
        assert ctx.r3 == case['dynamic_world_argument'], 'super dynamicWorld argument'
        assert ctx.stack_word(0) == case['save_dict_token'], 'super saveDict argument'
        assert ctx.stack_word(4) == case['cache_token'], 'super cache argument'
        ctx.record(CH['MsgSendSuper'], case['self_ptr'])
        return (0 if case['super_returns_nil'] else case['self_ptr'], None)

    @dispatcher.register('objectForKey:')
    def on_object_for_key(ctx):
        case = state['case']
        assert ctx.recv == case['save_dict_token'], 'objectForKey: receiver'
        name = key_object_name(ctx.r2)
        real_keys.add(name)
        if name == 'chestType':
            state['last_key_family'] = 'chestType'
            token = case['chest_type_box_token'] if case['has_chest_type_key'] else 0
            ctx.record(CH['ObjectForKeyChestType'], token)
            return (token, None)
        if name == 'safeClientID':
            state['last_key_family'] = 'safeClientID'
            ctx.record(CH['ObjectForKeySafeClientID'], case['safe_client_id_token'])
            return (case['safe_client_id_token'], None)
        if name == 'saveItemSlots':
            state['last_key_family'] = 'saveItemSlots'
            ctx.record(CH['ObjectForKeySaveItemSlots'], case['slots_array_token'])
            return (case['slots_array_token'], None)
        if name.startswith('shelfRenderItems_'):
            idx = shelf_index(name, 'shelfRenderItems_')
            state['last_key_family'] = 'shelfRenderItems'
            state['last_shelf_index'] = idx
            box = case['shelf_render_box_tokens'][idx]
            ctx.record(CH['ObjectForKeyShelfRenderItems'], box)
            return (box, None)
        if name.startswith('shelfItemDataBs_'):
            idx = shelf_index(name, 'shelfItemDataBs_')
            state['last_key_family'] = 'shelfItemDataBs'
            state['last_shelf_index'] = idx
            box = case['shelf_item_data_box_tokens'][idx]
            ctx.record(CH['ObjectForKeyShelfItemDataBs'], box)
            return (box, None)
        raise AssertionError(f'unexpected key {name!r}')

    @dispatcher.register('intValue')
    def on_int_value(ctx):
        case = state['case']
        family = state['last_key_family']
        if family == 'chestType':
            assert ctx.recv in (0, case['chest_type_box_token']), 'chestType box identity'
            value = case['chest_type_value'] if ctx.recv else 0
            ctx.record(CH['IntValueChestType'], value & 0xffffffff)
            return (value & 0xffffffff, None)
        idx = state['last_shelf_index']
        if family == 'shelfRenderItems':
            assert ctx.recv in (0, case['shelf_render_box_tokens'][idx]), 'shelfRenderItems box'
            value = case['shelf_render_values'][idx] if ctx.recv else 0
            ctx.record(CH['IntValueShelfRenderItems'], value & 0xffffffff)
            return (value & 0xffffffff, None)
        if family == 'shelfItemDataBs':
            assert ctx.recv in (0, case['shelf_item_data_box_tokens'][idx]), 'shelfItemDataBs box'
            value = case['shelf_item_data_values'][idx] if ctx.recv else 0
            ctx.record(CH['IntValueShelfItemDataBs'], value & 0xffffffff)
            return (value & 0xffffffff, None)
        raise AssertionError('intValue without a preceding key read')

    @dispatcher.register('retain')
    def on_retain(ctx):
        case = state['case']
        assert ctx.recv == case['safe_client_id_token'], 'retain receiver'
        ctx.record(CH['RetainSafeClientID'], ctx.recv)
        return (ctx.recv, None)

    @dispatcher.register('objectType')
    def on_object_type(ctx):
        case = state['case']
        assert ctx.recv == case['self_ptr'], 'objectType receiver'
        ctx.record(CH['ObjectType'], case['object_type_value'])
        return (case['object_type_value'], None)

    @dispatcher.register('dynamicWorldChangedAtPos:objectType:')
    def on_dynamic_world_changed(ctx):
        case = state['case']
        assert ctx.recv == case['dynamic_world_ivar'], 'dynamicWorld ivar identity'
        assert ctx.r2 == case['pos_x'], 'pos.x argument'
        assert ctx.r3 == case['pos_y'], 'pos.y argument'
        assert ctx.stack_word(0) == case['object_type_value'], 'objectType argument'
        ctx.record(CH['DynamicWorldChangedAtPos'], ctx.stack_word(0))
        return (0, None)

    @dispatcher.register('alloc')
    def on_alloc(ctx):
        case = state['case']
        if ctx.recv == ARRAY_CLASS:
            ctx.record(CH['AllocNSMutableArray'], CHEST_INVENTORY_ARRAY_TOKEN)
            return (CHEST_INVENTORY_ARRAY_TOKEN, None)
        if ctx.recv == ITEM_CLASS:
            items = state['slot_items'][state['cur_slot']]
            g = state['batch_begin'] + state['sub']
            token = items[g][0]
            ctx.record(CH['AllocInventoryItem'], token)
            state['sub'] += 1
            if case['mutate_slot'] == state['cur_slot'] and case['mutate_item'] == g:
                session.word(MUTATION_ADDR, 1)
            return (token, None)
        raise AssertionError(f'alloc receiver {hex(ctx.recv)}')

    @dispatcher.register('array')
    def on_array(ctx):
        assert ctx.recv == ARRAY_CLASS, 'array class receiver'
        token = CHEST_SLOT_ARRAY_BASE + state['array_creations']
        state['array_creations'] += 1
        ctx.record(CH['ArrayNSMutableArray'], token)
        return (token, None)

    @dispatcher.register('initWithCapacity:')
    def on_init_with_capacity(ctx):
        assert ctx.recv == CHEST_INVENTORY_ARRAY_TOKEN, 'initWithCapacity: receiver'
        capacity = ctx.r2
        assert capacity == expected_capacity(), (
            'capacity helper drift', capacity, expected_capacity())
        ctx.record(CH['InitWithCapacity'], capacity)
        return (ctx.recv, None)

    @dispatcher.register('count')
    def on_count(ctx):
        case = state['case']
        assert ctx.recv == case['slots_array_token'], 'count receiver'
        ctx.record(CH['CountSaveItemSlots'], len(state['slot_items']))
        return (len(state['slot_items']), None)

    @dispatcher.register('objectAtIndex:')
    def on_object_at_index(ctx):
        case = state['case']
        assert ctx.recv == case['slots_array_token'], 'objectAtIndex: receiver'
        idx = ctx.r2
        assert idx < len(state['slot_items']), 'slot index out of fixture range'
        state['cur_slot'] = idx
        state['batch_begin'] = 0
        state['batch_next'] = 0
        state['sub'] = 0
        ctx.record(CH['ObjectAtIndex'], idx)
        return (CHEST_SLOT_ARRAY_BASE + idx, None)

    @dispatcher.register('countByEnumeratingWithState:objects:count:')
    def on_enumerate(ctx):
        assert ctx.stack_word(0) == 16, 'enumeration batch size argument'
        slot_token = ctx.recv
        idx = state['slot_of_token'][slot_token]
        assert idx == state['cur_slot'], 'enumeration slot identity'
        items = state['slot_items'][idx]
        start = state['batch_next']
        remaining = len(items) - start
        batch = min(remaining, 16)
        ctx.record(CH['FastEnumeration'], batch)
        if batch:
            for k in range(batch):
                token = items[start + k][0]
                uc.mem_write(ITEMS_PAGE + 4 * k, struct.pack('<I', token))
            uc.mem_write(ctx.r2 + 0, struct.pack('<I', 0))
            uc.mem_write(ctx.r2 + 4, struct.pack('<I', ITEMS_PAGE))
            uc.mem_write(ctx.r2 + 8, struct.pack('<I', MUTATION_ADDR))
            state['batch_begin'] = start
            state['batch_next'] = start + batch
            state['sub'] = 0
        return (batch, None)

    @dispatcher.register('initWithSaveData:')
    def on_init_with_save_data(ctx):
        item_data = ctx.r2
        assert item_data in state['item_types'], 'initWithSaveData: payload identity'
        ctx.record(CH['InitWithSaveData'], item_data)
        return (ctx.recv, None)

    @dispatcher.register('autorelease')
    def on_autorelease(ctx):
        ctx.record(CH['AutoreleaseItem'], ctx.recv)
        return (ctx.recv, None)

    @dispatcher.register('itemType')
    def on_item_type(ctx):
        assert ctx.recv in state['item_types'], 'itemType receiver identity'
        item_type = state['item_types'][ctx.recv]
        ctx.record(CH['ItemType'], item_type)
        return (item_type, None)

    @dispatcher.register('addObject:')
    def on_add_object(ctx):
        obj = ctx.r2
        if ctx.recv == CHEST_INVENTORY_ARRAY_TOKEN:
            assert CHEST_SLOT_ARRAY_BASE <= obj < (
                CHEST_SLOT_ARRAY_BASE + state['array_creations']), \
                'slot array identity'
            ctx.record(CH['AddObjectSlotArray'], obj)
        elif ctx.recv in state['slot_of_token']:
            assert obj in state['item_types'], 'item identity'
            ctx.record(CH['AddObjectItem'], obj)
        else:
            raise AssertionError(f'addObject: receiver {hex(ctx.recv)}')
        return (ctx.recv, None)

    @dispatcher.register('stringWithFormat:')
    def on_string_with_format(ctx):
        fmt = key_object_name(ctx.r2)
        index = ctx.r3
        if fmt == 'shelfRenderItems_%d':
            ctx.record(CH['StringWithFormatShelfRenderItems'], index)
        elif fmt == 'shelfItemDataBs_%d':
            ctx.record(CH['StringWithFormatShelfItemDataBs'], index)
        else:
            raise AssertionError(f'unexpected format {fmt!r}')
        key = fmt.replace('%d', str(index))
        real_keys.add(key)
        return (graph.cfstring(key), None)

    @dispatcher.register('initSubDerivedItems')
    def on_init_sub_derived(ctx):
        assert ctx.recv == state['case']['self_ptr'], 'initSubDerivedItems receiver'
        ctx.record(CH['InitSubDerivedItems'], 0)
        return (ctx.recv, None)

    dispatcher.install()

    def hook_plain(uc_, address, size, data):
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_PC,
                                       UC_ARM_REG_LR)
        if address == STUB_MEMSET:
            dst = uc_.reg_read(UC_ARM_REG_R0)
            val = uc_.reg_read(UC_ARM_REG_R1) & 0xff
            n = uc_.reg_read(UC_ARM_REG_R2)
            uc_.mem_write(dst, bytes([val]) * n)
            code = CH['StateMemset'] if n == 0x20 else CH['CustomRulesMemset']
            dispatcher.trace.append((code, n))
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        if address == STUB_MUTATION:
            dispatcher.trace.append((CH['EnumerationMutation'],
                                     uc_.reg_read(UC_ARM_REG_R0)))
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        if address == STUB_STRET:
            buf = uc_.reg_read(UC_ARM_REG_R0)
            recv = uc_.reg_read(UC_ARM_REG_R1)
            case = state['case']
            assert recv == case['world_ivar'], 'customRules receiver (self->world ivar)'
            assert buf != 0, 'customRules stret buffer'
            payload = bytes([case['rules_byte0'] & 0xff]) + b'\xab' * 63
            uc_.mem_write(buf, payload)
            dispatcher.trace.append((CH['CustomRulesStret'],
                                     case['rules_byte0'] & 0xff))
            uc_.reg_write(UC_ARM_REG_R0, buf)
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))
            return
        raise AssertionError(f'unexpected hook address {hex(address)}')

    from unicorn import UC_HOOK_CODE
    uc.hook_add(UC_HOOK_CODE, hook_plain, begin=STUB_MEMSET, end=STUB_MEMSET + 4)
    uc.hook_add(UC_HOOK_CODE, hook_plain, begin=STUB_MUTATION, end=STUB_MUTATION + 4)
    uc.hook_add(UC_HOOK_CODE, hook_plain, begin=STUB_STRET, end=STUB_STRET + 4)

    root = Path(__file__).resolve().parents[1]
    fns = build_bridge(root, a.output_dir)

    rows = []
    for case in CASES:
        merged = dict(BASE)
        merged.update({k: v for k, v in case.items() if k != 'name'})
        merged['name'] = case['name']
        state['case'] = merged
        dispatcher.trace.clear()
        state['slot_items'] = [list(s) for s in merged['slots']]
        state['item_types'] = {}
        for slot in state['slot_items']:
            for token, item_type in slot:
                assert token not in state['item_types'], 'duplicate item token'
                state['item_types'][token] = item_type
        state['slot_of_token'] = {CHEST_SLOT_ARRAY_BASE + i: i
                                  for i in range(len(state['slot_items']))}
        state['cur_slot'] = None
        state['batch_begin'] = 0
        state['batch_next'] = 0
        state['sub'] = 0
        state['array_creations'] = 0
        state['last_key_family'] = None
        state['last_shelf_index'] = None
        real_keys.clear()

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        session.word(self_ptr + 4, merged['world_ivar'])
        session.word(self_ptr + 8, merged['dynamic_world_ivar'])
        session.word(self_ptr + 16, merged['pos_x'])
        session.word(self_ptr + 20, merged['pos_y'])
        session.word(self_ptr + 36, merged['owner_id_ivar'])
        session.word(MUTATION_ADDR, 0)

        stack_top = session.stack + STACK_OFFSET
        uc.mem_write(stack_top, struct.pack('<II', merged['save_dict_token'],
                                            merged['cache_token']))

        session.run(IMP, sp_offset=STACK_OFFSET,
                    R0=self_ptr, R1=cmd_sel,
                    R2=merged['world_argument'],
                    R3=merged['dynamic_world_argument'])

        from unicorn.arm_const import UC_ARM_REG_R0
        arm_ret = uc.reg_read(UC_ARM_REG_R0)
        arm_image = bytes(uc.mem_read(self_ptr, IMAGE_SIZE))
        arm_trace = list(dispatcher.trace)

        expected_ret = 0 if merged['super_returns_nil'] else self_ptr
        assert arm_ret == expected_ret, ('ARM return value', hex(arm_ret),
                                         hex(expected_ret))

        item_tokens = []
        item_types = []
        item_offsets = []
        item_counts = []
        for slot in state['slot_items']:
            item_offsets.append(len(item_tokens))
            item_counts.append(len(slot))
            for token, item_type in slot:
                item_tokens.append(token)
                item_types.append(item_type)

        cfg = bridge_input(merged, state['slot_items'], item_offsets,
                           item_counts, item_tokens, item_types)

        for opt, fn in fns:
            image_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_buf = ctypes.create_string_buffer(1024 * 8)
            ret_out = ctypes.c_uint32(0)
            n = fn(ctypes.byref(cfg), image_buf, trace_buf, ctypes.byref(ret_out))
            assert n != 0xFFFFFFFF, 'fixture overflow'
            assert n != 0xFFFFFFFE, 'slot table overflow'
            cpp_image = image_buf.raw[:IMAGE_SIZE]
            cpp_trace = []
            for i in range(n):
                rec = trace_buf.raw[i * 8:(i + 1) * 8]
                code = rec[0]
                arg = struct.unpack('<I', rec[4:8])[0]
                cpp_trace.append((code, arg))

            assert arm_image == cpp_image, (
                f'-O{opt} image mismatch in {case["name"]}',
                [(i, arm_image[i], cpp_image[i])
                 for i in range(IMAGE_SIZE) if arm_image[i] != cpp_image[i]])
            assert arm_trace == cpp_trace, (
                f'-O{opt} trace mismatch in {case["name"]}',
                _first_diff(arm_trace, cpp_trace))
            assert ret_out.value == arm_ret, f'-O{opt} return mismatch in {case["name"]}'

        rows.append({
            'case': case['name'],
            'return': hex(arm_ret),
            'trace_len': len(arm_trace),
            'keys': sorted(real_keys),
            'items': len(item_tokens),
            'slots': len(state['slot_items']),
        })

    report = {
        'sha256': SHA,
        'class': 'Chest',
        'method': 'initWithWorld:dynamicWorld:saveDict:cache:',
        'imp': hex(IMP),
        'code_words': 760,
        'cases': len(CASES),
        'match': True,
        'rows': rows,
        'boundary': (
            "Unicorn execution of the original 760-word method: objc_msgSendSuper2 "
            "forwarding (objc_super struct + all four arguments asserted), "
            "chestType intValue store at 108, the 64-byte customRules stret with the "
            "byte-0 gate and the RE-READ of chestType, the safeClientID retain default "
            "at 36, the 0x00CB623C capacity rule (2/5 -> 4 else 16), the "
            "saveItemSlots count-vs-capacity gate, per-slot [NSMutableArray array] + "
            "objectAtIndex: + 16-wide fast enumeration with the mutation check, "
            "[[InventoryItem alloc] initWithSaveData:] construction with the "
            "itemType != 11 filter, the shelfRenderItems_%d / shelfItemDataBs_%d "
            "restore loop with the strh truncation, and [self initSubDerivedItems]. "
            "Not Foundation, not the original-app runtime, no device acceptance."
        )
    }

    (a.output_dir / 'chest_init_with_world_arm_result.json').write_text(
        json.dumps(report, indent=2))
    print(f"chest_init_with_world_arm: PASS ({len(CASES)} cases)")
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
