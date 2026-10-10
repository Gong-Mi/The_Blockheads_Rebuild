#!/usr/bin/env python3
"""Execute the ORIGINAL ARM body of the FreeBlock exact-variant loader (batch b4p)

  -[FreeBlock initWithWorld:dynamicWorld:saveDict:cache:]   IMP 0x00626A68

under Unicorn and compare the 156-byte instance image, the return value, the
tile-consume count and the full (code, arg) trace against the recovered C++
contract at -O0/-O2. The largest front member (1,347 words).

Harness facts:
* super2 (GOT 0x0105B79C) + msgSend (GOT 0x0105B7A0) share the stub; the super
  handler asserts the objc_super struct (receiver + OWN class 0x00E907B0,
  superref slot 0x00E8BC78) and all FOUR forwarded arguments.
* The world accessor 0x00A12F24 is hooked (ground loop queries (pos.x,
  pos.y-1) per iteration, max 16).
* The ground-loop tile-kind helper 0x00A12300 and the position builder
  0x004B49FC and the floatPos identity helper 0x004BDAAC run NATIVELY
  against fixture tile bytes.
* The itemType blacklist helper 0x00627C40 and the liquid-container predicate
  0x005B2AD4 run NATIVELY (both fully inside the mapped ELF); the recovered
  contract carries the probed answer sets as explicit tables.
* NSFastEnumeration is stubbed: countByEnumeratingWithState:objects:count:
  serves up to 16 fixture elements per call; the mutation veneers
  0x1C2924/0x1C2E28 are bypassed (the stub returns complete batches).
* The 64-bit priorityBlockheadUinqueID resolution goes through the real
  0x1C281C veneer (world blockheadWithIDIncludingNet: with r2/r3 = the
  sign-extended 32-bit intValue), then retain, then the ivar store.
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
from trace_codes_gen import FREEBLOCK_INIT_CODES as VC

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
IMP = 0x00626A68
IMAGE_SIZE = 156          # FreeBlock class_ro_t instance_size
SELECTOR = 'initWithWorld:dynamicWorld:saveDict:cache:'

GOT_MSGSEND_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
SUPERREF_SLOT = 0x00E8BC78
FREEBLOCK_CLASS = 0x00E907B0

WORLD_ACCESSOR = 0x00A12F24
POS_BUILDER = 0x004B49FC
FLOATPOS_HELPER = 0x004BDAAC
TILE_KIND_HELPER = 0x00A12300

STUB_MSG = 0x72000000
TILE_PAGE = 0x60090000
STACK_OFFSET = 0x8000

BOX_HOVERS = 0x5E1A0B01
BOX_ITEM_TYPE = 0x5E1A0B02
BOX_DATA_A = 0x5E1A0B03
BOX_DATA_B = 0x5E1A0B04
BOX_BOUNCE_TIMER = 0x5E1A0B05
BOX_FALL_SPEED = 0x5E1A0B06
BOX_CREATION_TIME = 0x5E1A0B07
BOX_FLOAT_POS_VX = 0x5E1A0B08
BOX_FLOAT_POS_VY = 0x5E1A0B09
BOX_PRIORITY_ID = 0x5E1A0B0A
BOX_DYN_SAVE_DICT = 0x5E1A0B0B

SUBITEMS_ARRAY = 0x5E1A0B20
SUBITEMS_ARRAY_2 = 0x5E1A0B21    # alloc-return token (fresh array pre-init)
FRESH_ARRAY = 0x5E1A0B80         # post-init fresh array stored in self->subItems
INVENTORY_CLASS = 0x5E1A0B30
SAVE_DICT_TOKEN = 0x60010000

OFF_WORLD = 4
OFF_DYNAMIC_WORLD = 8
OFF_POS = 16
OFF_UNIQUE_ID = 40
OFF_FLOAT_POS = 24
OFF_UPDATE_NEEDS = 49
OFF_ITEM_TYPE = 56
OFF_DATA_A = 60
OFF_DATA_B = 62
OFF_HOVERS = 64
OFF_BOUNCE_TIMER = 68
OFF_FALL_SPEED = 72
OFF_CREATION_TIME = 80
OFF_PRIORITY_BLOCKHEAD = 136
OFF_DYN_SAVE_DICT = 140
OFF_SUB_ITEMS = 112


def low32(value):
    return struct.unpack('<I', struct.pack('<d', value)[:4])[0]


def float_bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def tile(present=True, byte0=2):
    return {'present': present, 'byte0': byte0}


BASE = {
    'self_ptr': 0x60000000,
    'super_returns_nil': False,
    'world_argument': 0x5E1A0010,
    'dynamic_world_argument': 0x5E1A0020,
    'save_dict_token': SAVE_DICT_TOKEN,
    'cache_token': 0x5E1A0030,
    'world_ivar': 0x5E1A0004,
    'dynamic_world_ivar': 0x5E1A0008,
    'pos_x': 30,
    'pos_y': -5,
    'unique_id': 0,
    'item_type_init': 7,
    'hovers_init': 0,
    'bounce_timer_value': 1.5,
    'fall_speed_value': 20.0,
    'creation_time_value': 10.0,
    'float_vx_value': 3.5,
    'float_vy_value': -1.25,
    'hovers_value': 0,
    'item_type_value': 7,
    'data_a_value': 3,
    'data_b_value': 4,
    'priority_id_value': 0,
    'blockhead_answer': 0x5E1A00B0,
    'sub_items': [],           # list of elements; each element = list of sub-item types
    'world_time': 50.0,
    'object_type_value': 0x5E1A0041,
    'tiles': [],               # ground-loop tile answers
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
        ('pos_x', ctypes.c_int32),
        ('pos_y', ctypes.c_int32),
        ('unique_id', ctypes.c_uint32),
        ('item_type_init', ctypes.c_uint32),
        ('hovers_init', ctypes.c_uint32),
        ('bounce_timer_value', ctypes.c_float),
        ('fall_speed_value', ctypes.c_float),
        ('creation_time_value', ctypes.c_double),
        ('float_vx_value', ctypes.c_float),
        ('float_vy_value', ctypes.c_float),
        ('hovers_value', ctypes.c_uint32),
        ('item_type_value', ctypes.c_uint32),
        ('data_a_value', ctypes.c_uint32),
        ('data_b_value', ctypes.c_uint32),
        ('priority_id_value', ctypes.c_int32),
        ('blockhead_answer', ctypes.c_uint32),
        ('sub_items', ctypes.c_uint32 * 64),      # flattened sub-item types
        ('sub_item_count', ctypes.c_uint32),      # number of flattened types
        ('elem_counts', ctypes.c_uint32 * 16),    # per-element sub-item counts
        ('elem_count', ctypes.c_uint32),          # number of elements
        ('world_time', ctypes.c_double),
        ('object_type_value', ctypes.c_uint32),
        ('tile_count', ctypes.c_uint32),
        ('tile_present', ctypes.c_uint32 * 64),
        ('tile_byte0', ctypes.c_uint32 * 64),
    ]


CASES = [
    {'name': 'super_nil', 'super_returns_nil': True},
    # full key walk, no hovers tail
    {'name': 'plain_keys'},
    # elements are arrays of sub-item types; itemType==11 children are skipped
    {'name': 'subitems_walk',
     'sub_items': [[7], [7, 11], [], [9]], 'hovers_value': 0},
    # priority ID resolution (nonzero) + retain
    {'name': 'priority_resolve', 'priority_id_value': 42},
    # priority ID zero -> no blockheadWithIDIncludingNet:
    {'name': 'priority_zero', 'priority_id_value': 0},
    # hovers != 0 but creationTime fresh -> early return after the gate
    {'name': 'hovers_fresh', 'hovers_value': 1, 'world_time': 100.0,
     'creation_time_value': 10.0},
    # hovers + old creationTime + item in the small helper set (0x5b2ad4) -> end
    {'name': 'hovers_liquid_helper', 'hovers_value': 1, 'world_time': 10000.0,
     'creation_time_value': 10.0, 'item_type_value': 0x3f},
    # hovers + old + inline cmp 0xcd -> end
    {'name': 'hovers_inline_cd', 'hovers_value': 1, 'world_time': 10000.0,
     'creation_time_value': 10.0, 'item_type_value': 0xcd},
    # hovers + old + blacklist 0x627c40 (e.g. 0x91) -> end
    {'name': 'hovers_blacklist', 'hovers_value': 1, 'world_time': 10000.0,
     'creation_time_value': 10.0, 'item_type_value': 0x91},
    # hovers + old + clean type -> floatPos re-anchor + elapsed gate
    #  elapsed = wt - floatPosDouble - 900; make elapsed >= 900 -> skip loop
    {'name': 'hovers_elapsed_big', 'hovers_value': 1, 'world_time': 10000.0,
     'creation_time_value': 10.0, 'item_type_value': 7,
     'float_vx_value': 1.0, 'float_vy_value': 1.0},
    # elapsed < 900 -> ground loop: fall twice, stop on air
    {'name': 'ground_fall_two',
     'hovers_value': 1, 'world_time': 1200.0, 'creation_time_value': 10.0,
     'item_type_value': 7, 'float_vx_value': 100.0, 'float_vy_value': 0.0,
     'tiles': [tile(present=True, byte0=2), tile(present=True, byte0=2),
               tile(present=False)]},
    # ground loop: solid at first query -> 1 step
    {'name': 'ground_fall_one',
     'hovers_value': 1, 'world_time': 1200.0, 'creation_time_value': 10.0,
     'item_type_value': 7, 'float_vx_value': 100.0, 'float_vy_value': 0.0,
     'tiles': [tile(present=True, byte0=2)]},
    # ground loop: tile present but byte0 != 2 -> treat as empty, keep falling
    {'name': 'ground_fall_soft_tile',
     'hovers_value': 1, 'world_time': 1200.0, 'creation_time_value': 10.0,
     'item_type_value': 7, 'float_vx_value': 100.0, 'float_vy_value': 0.0,
     'tiles': [tile(present=True, byte0=0), tile(present=True, byte0=2)]},
    # 16 solid tiles -> the loop cap: 16 falls, no 17th query
    {'name': 'ground_fall_limit',
     'hovers_value': 1, 'world_time': 1200.0, 'creation_time_value': 10.0,
     'item_type_value': 7, 'float_vx_value': 100.0, 'float_vy_value': 0.0,
     'tiles': [tile(present=True, byte0=2)] * 16},
    # 20 solid tiles: still capped at 16 queries / 16 falls
    {'name': 'ground_fall_over_limit',
     'hovers_value': 1, 'world_time': 1200.0, 'creation_time_value': 10.0,
     'item_type_value': 7, 'float_vx_value': 100.0, 'float_vy_value': 0.0,
     'tiles': [tile(present=True, byte0=2)] * 20},
]


def build_bridge(root, out_dir):
    fns = []
    for opt in (0, 2):
        so_path = out_dir / f'freeblock_init-O{opt}.so'
        cmd = ['clang++', f'-O{opt}', '-shared', '-fPIC', '-std=c++17',
               '-fno-fast-math', '-ffp-contract=off',
               '-I', str(root / 'reconstruction/recovered'),
               str(root / 'tools/freeblock_init_arm_bridge.cpp'),
               str(root / 'reconstruction/recovered/freeblock_init.cpp'),
               '-o', str(so_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, res.stderr
        cdll = ctypes.CDLL(str(so_path))
        fn = cdll.recovered_freeblock_init_run
        fn.argtypes = [ctypes.POINTER(BridgeInput), ctypes.c_char_p,
                       ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32),
                       ctypes.POINTER(ctypes.c_uint32)]
        fn.restype = ctypes.c_uint32
        fns.append((opt, fn))
    return fns


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
    # veneer 0x1C281C -> GOT 0x0105FB18 = objc_msgSend; 0x1C2924 -> 0x0105FB70
    # = memset (the NSFastEnumeration state zeroing); 0x1C2E28 -> 0x0105FD1C =
    # objc_enumerationMutation.
    session.patch_got(0x0105FB18, STUB_MSG)
    assert session.read_word(SUPERREF_SLOT) == FREEBLOCK_CLASS, 'superref drift'
    cmd_sel = graph.command_selector(SELECTOR)

    mut_addr = graph.alloc(0x20)
    graph.word(mut_addr, 0)
    elem_page = graph.alloc(0x400)     # element tokens live here
    sub_page = graph.alloc(0x800)      # sub-element payload tokens
    dispatcher = MsgDispatcher(uc, STUB_MSG)
    state = {'case': None, 'tiles_served': 0,
             'elem_served': 0, 'elem_issued': 0, 'elem_token_subs': {},
             'sub_served': {}, 'sub_issued': 0, 'sub_token_type': {},
             'cur_item': None, 'cur_item_types': {}, 'temp_of_elem': {}}

    def case():
        return state['case']

    @dispatcher.register(SELECTOR)
    def on_super(ctx):
        c = case()
        sup = ctx.recv
        assert ctx.word(sup) == c['self_ptr'], 'super2 receiver'
        assert ctx.word(sup + 4) == FREEBLOCK_CLASS, 'super2 own class'
        assert ctx.r2 == c['world_argument']
        assert ctx.r3 == c['dynamic_world_argument']
        assert ctx.stack_word(0) == c['save_dict_token']
        assert ctx.stack_word(4) == c['cache_token']
        ctx.record(VC['MsgSendSuper'], c['self_ptr'])
        return (0 if c['super_returns_nil'] else c['self_ptr'], None)

    @dispatcher.register('objectForKey:')
    def on_object_for_key(ctx):
        c = case()
        assert ctx.recv == c['save_dict_token'], 'objectForKey: receiver'
        data = struct.unpack('<I', bytes(uc.mem_read(ctx.r2 + 8, 4)))[0]
        key = bytes(uc.mem_read(data, 64)).split(b'\0')[0].decode()
        table = {
            'bounceTimer': (VC['ObjectForKeyBounceTimer'], BOX_BOUNCE_TIMER),
            'fallSpeed': (VC['ObjectForKeyFallSpeed'], BOX_FALL_SPEED),
            'creationTime': (VC['ObjectForKeyCreationTime'], BOX_CREATION_TIME),
            'floatPos[VX]': (VC['ObjectForKeyFloatPosVX'], BOX_FLOAT_POS_VX),
            'floatPos[VY]': (VC['ObjectForKeyFloatPosVY'], BOX_FLOAT_POS_VY),
            'hovers': (VC['ObjectForKeyHovers'], BOX_HOVERS),
            'itemType': (VC['ObjectForKeyItemType'], BOX_ITEM_TYPE),
            'dataA': (VC['ObjectForKeyDataA'], BOX_DATA_A),
            'dataB': (VC['ObjectForKeyDataB'], BOX_DATA_B),
            'subItems': (VC['ObjectForKeySubItems'], SUBITEMS_ARRAY),
            'dynamicObjectSaveDict': (VC['ObjectForKeyDynSaveDict'], BOX_DYN_SAVE_DICT),
            'priorityBlockheadUinqueID': (VC['ObjectForKeyPriorityId'], BOX_PRIORITY_ID),
        }
        assert key in table, f'unexpected key {key!r}'
        code, token = table[key]
        ctx.record(code, token)
        return (token, None)

    @dispatcher.register('floatValue')
    def on_float_value(ctx):
        c = case()
        recv = ctx.recv
        table = {
            BOX_BOUNCE_TIMER: (VC['FloatValueBounceTimer'], c['bounce_timer_value']),
            BOX_FALL_SPEED: (VC['FloatValueFallSpeed'], c['fall_speed_value']),
            BOX_FLOAT_POS_VX: (VC['FloatValueFloatPosVX'], c['float_vx_value']),
            BOX_FLOAT_POS_VY: (VC['FloatValueFloatPosVY'], c['float_vy_value']),
        }
        assert recv in table, f'floatValue on {hex(recv)}'
        code, value = table[recv]
        ctx.record(code, float_bits(value))
        return (float_bits(value), None)

    @dispatcher.register('doubleValue')
    def on_double_value(ctx):
        c = case()
        assert ctx.recv == BOX_CREATION_TIME, 'doubleValue receiver'
        ctx.record(VC['DoubleValueCreationTime'], low32(c['creation_time_value']))
        half = struct.unpack('<II', struct.pack('<d', c['creation_time_value']))
        return (half[0], half[1])

    @dispatcher.register('boolValue')
    def on_bool_value(ctx):
        c = case()
        assert ctx.recv == BOX_HOVERS, 'boolValue receiver'
        flag = 1 if c['hovers_value'] else 0
        ctx.record(VC['BoolValueHovers'], flag)
        return (flag, None)

    @dispatcher.register('intValue')
    def on_int_value(ctx):
        c = case()
        recv = ctx.recv
        if recv == BOX_ITEM_TYPE:
            ctx.record(VC['IntValueItemType'], c['item_type_value'])
            return (c['item_type_value'], None)
        if recv == BOX_DATA_A:
            ctx.record(VC['IntValueDataA'], c['data_a_value'])
            return (c['data_a_value'], None)
        if recv == BOX_DATA_B:
            ctx.record(VC['IntValueDataB'], c['data_b_value'])
            return (c['data_b_value'], None)
        if recv == BOX_PRIORITY_ID:
            v = c['priority_id_value'] & 0xffffffff
            ctx.record(VC['IntValuePriorityId'], v)
            return (v, None)
        raise AssertionError(f'intValue on {hex(recv)}')

    @dispatcher.register('retain')
    def on_retain(ctx):
        c = case()
        if ctx.recv == c['blockhead_answer']:
            ctx.record(VC['RetainBlockhead'], 0)
        else:
            raise AssertionError(f'retain on {hex(ctx.recv)}')
        return (ctx.recv, None)

    @dispatcher.register('array')
    def on_array(ctx):
        # NSMutableArray classref slot 0x00E8A1AC is relocation-resolved at
        # load in the original runtime; in the harness it reads 0.
        ctx.record(VC['MutableArrayArray'], 0)
        return (SUBITEMS_ARRAY_2, None)

    @dispatcher.register('init')
    def on_init(ctx):
        # The NSMutableArray creation goes alloc+init (executed fact); the
        # fresh array token is stored into self->subItems by the original.
        if ctx.recv == SUBITEMS_ARRAY_2:
            ctx.record(VC['MutableArrayInit'], ctx.recv)
            return (FRESH_ARRAY, None)
        ctx.record(VC['MutableArrayInit'], ctx.recv)
        return (ctx.recv, None)

    @dispatcher.register('countByEnumeratingWithState:objects:count:')
    def on_enumerate(ctx):
        c = case()
        st = ctx.r2
        buf = ctx.r3
        if ctx.recv == SUBITEMS_ARRAY:
            # outer enumeration over the save-dict subItems elements
            served = state['elem_served']
            remaining = c['sub_items'][served:served + 16]
            state['elem_served'] = served + len(remaining)
            ctx.record(VC['CountByEnumerating'], len(remaining))
            for i in range(len(remaining)):
                token = elem_page + state['elem_issued'] * 8
                state['elem_issued'] += 1
                graph.word(buf + i * 4, token)
                state['elem_token_subs'][token] = list(remaining[i])
            state['cur_elem'] = None
        else:
            # inner enumeration over one element's sub-item payloads
            assert ctx.recv in state['elem_token_subs'], (
                'inner enumerate receiver', hex(ctx.recv))
            subs = state['elem_token_subs'][ctx.recv]
            served = state['sub_served'].get(ctx.recv, 0)
            batch = subs[served:served + 16]
            state['sub_served'][ctx.recv] = served + len(batch)
            ctx.record(VC['CountByEnumerating'], len(batch))
            for i in range(len(batch)):
                token = sub_page + state['sub_issued'] * 8
                state['sub_issued'] += 1
                graph.word(buf + i * 4, token)
                state['sub_token_type'][token] = batch[i]
        # 32-bit NSFastEnumerationState: state@0, itemsPtr@4,
        # mutationsPtr@8, extra@12 (chest precedent).
        graph.word(st + 0, 0)
        graph.word(st + 4, buf)
        graph.word(st + 8, mut_addr)
        return (len(batch) if ctx.recv != SUBITEMS_ARRAY else len(remaining), None)

    @dispatcher.register('alloc')
    def on_alloc(ctx):
        # Two alloc sites: the NSMutableArray classref (slot word 0 on disk,
        # the fresh array) and the InventoryItem classref 0x00E91CA0.
        if ctx.recv == 0x00E91CA0:
            ctx.record(VC['InventoryAlloc'], 0)
            return (0x5E1A0B90 + state['sub_issued'] * 8, None)
        ctx.record(VC['MutableArrayArray'], 0)   # fresh-array alloc
        return (SUBITEMS_ARRAY_2, None)

    @dispatcher.register('initWithSaveData:')
    def on_init_with_save_data(ctx):
        assert ctx.r2 in state['sub_token_type'], (
            'initWithSaveData: payload identity', hex(ctx.r2))
        state['cur_item_types'][ctx.recv] = state['sub_token_type'][ctx.r2]
        ctx.record(VC['InventoryInitWithSaveData'], ctx.r2)
        return (ctx.recv, None)

    @dispatcher.register('autorelease')
    def on_autorelease(ctx):
        ctx.record(VC['InventoryAutorelease'], 0)
        return (ctx.recv, None)

    @dispatcher.register('itemType')
    def on_item_type(ctx):
        item = ctx.recv
        assert item in state['cur_item_types'], ('itemType receiver', hex(item))
        ctx.record(VC['InventoryItemType'], state['cur_item_types'][item])
        return (state['cur_item_types'][item], None)

    @dispatcher.register('addObject:')
    def on_add_object(ctx):
        c = case()
        # Two addObject: sites: [self->subItems addObject:temp] (receiver
        # FRESH_ARRAY, arg = temp token) and [temp addObject:item] (receiver
        # temp token, arg = item token). One code, args keep them distinct.
        ctx.record(VC['SubItemsAddObject'], ctx.r2)
        return (0, None)

    @dispatcher.register('copy')
    def on_copy(ctx):
        c = case()
        assert ctx.recv == BOX_DYN_SAVE_DICT, 'copy receiver'
        ctx.record(VC['DynSaveDictCopy'], 0)
        return (BOX_DYN_SAVE_DICT, None)

    @dispatcher.register('blockheadWithIDIncludingNet:')
    def on_blockhead_with_id(ctx):
        c = case()
        assert ctx.recv == c['dynamic_world_ivar'], (
            'blockheadWithIDIncludingNet receiver', hex(ctx.recv))
        low = ctx.r2
        high = ctx.r3
        expect = c['priority_id_value'] & 0xffffffff
        if expect & 0x80000000:
            expect_high = 0xffffffff
        else:
            expect_high = 0
        assert low == expect and high == expect_high, (
            'blockhead id', hex(low), hex(high), hex(expect))
        ctx.record(VC['BlockheadWithID'], low)
        return (c['blockhead_answer'], None)

    @dispatcher.register('initSubDerivedObjects')
    def on_init_sub_derived(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'initSubDerivedObjects receiver'
        ctx.record(VC['InitSubDerivedObjects'], 0)
        return (ctx.recv, None)

    @dispatcher.register('worldTime')
    def on_world_time(ctx):
        c = case()
        assert ctx.recv == c['world_ivar'], 'worldTime receiver'
        ctx.record(VC['WorldTime'], low32(c['world_time']))
        half = struct.unpack('<II', struct.pack('<d', c['world_time']))
        return (half[0], half[1])

    @dispatcher.register('updatePosition:')
    def on_update_position(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'updatePosition: receiver'
        x = ctypes.c_int32(ctx.r2).value
        y = ctypes.c_int32(ctx.r3).value
        ctx.record(VC['UpdatePosition'],
                   ((y & 0xffff) << 16) | (x & 0xffff))
        # the original SETS self->pos from the argument
        session.word(c['self_ptr'] + OFF_POS, x & 0xffffffff)
        session.word(c['self_ptr'] + OFF_POS + 4, y & 0xffffffff)
        return (0, None)

    @dispatcher.register('objectType')
    def on_object_type(ctx):
        c = case()
        assert ctx.recv == c['self_ptr'], 'objectType receiver'
        ctx.record(VC['ObjectType'], c['object_type_value'])
        return (c['object_type_value'], None)

    @dispatcher.register('dynamicWorldChangedAtPos:objectType:')
    def on_dynamic_world_changed(ctx):
        c = case()
        assert ctx.recv == c['dynamic_world_ivar'], 'dynamicWorldChangedAtPos receiver'
        x = ctypes.c_int32(ctx.r2).value
        y = ctypes.c_int32(ctx.r3).value
        assert ctx.stack_word(0) == c['object_type_value'], 'notification objectType'
        ctx.record(VC['DynamicWorldChangedAtPos'],
                   ((y & 0xffff) << 16) | (x & 0xffff))
        return (0, None)

    dispatcher.install()

    from unicorn import UC_HOOK_CODE
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_PC,
                                   UC_ARM_REG_LR)

    def hook_world(uc_, address, size, data):
        c = case()
        x = ctypes.c_int32(uc_.reg_read(UC_ARM_REG_R0)).value
        y = ctypes.c_int32(uc_.reg_read(UC_ARM_REG_R1)).value
        world = uc_.reg_read(UC_ARM_REG_R2)
        assert world == c['world_ivar'], 'world accessor receiver'
        index = state['tiles_served']
        answers = c['tiles']
        ptr = 0
        if index < len(answers):
            answer = answers[index]
            if answer['present']:
                ptr = TILE_PAGE + 0x40 * (index % 16)
                blob = bytearray(0x20)
                blob[0] = answer['byte0'] & 0xff
                uc_.mem_write(ptr, bytes(blob))
        state['tiles_served'] = index + 1
        dispatcher.trace.append((VC['WorldTileQuery'], y & 0xffffffff))
        uc_.reg_write(UC_ARM_REG_R0, ptr)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    # memset stub (NSFastEnumeration state zeroing via the real call chain).
    STUB_MEMSET = 0x72003000
    uc.mem_map(STUB_MEMSET, 0x1000)
    session.patch_got(0x0105FB70, STUB_MEMSET)
    session.patch_got(0x0105FD1C, STUB_MEMSET + 8)   # enumerationMutation: no-op

    def hook_memset(uc_, address, size, data):
        dst = uc_.reg_read(UC_ARM_REG_R0)
        n = uc_.reg_read(UC_ARM_REG_R1)
        if n:
            uc_.mem_write(dst, b'\x00' * n)
        uc_.reg_write(UC_ARM_REG_R0, dst)
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    def hook_enum_mutation(uc_, address, size, data):
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    uc.hook_add(UC_HOOK_CODE, hook_memset, begin=STUB_MEMSET,
                end=STUB_MEMSET + 4)
    uc.hook_add(UC_HOOK_CODE, hook_enum_mutation, begin=STUB_MEMSET + 8,
                end=STUB_MEMSET + 8 + 4)

    uc.hook_add(UC_HOOK_CODE, hook_world, begin=WORLD_ACCESSOR,
                end=WORLD_ACCESSOR + 4)

    # itemType tracking for the InventoryItem stub: the pending item's type is
    # consumed from the fixture list in enumeration order.
    def note_pending_item(index):
        c = case()
        items = c['sub_items']
        state['pending_item_type'] = items[index] if index < len(items) else 0

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
        state['elem_served'] = 0
        state['elem_issued'] = 0
        state['elem_token_subs'] = {}
        state['sub_served'] = {}
        state['sub_issued'] = 0
        state['sub_token_type'] = {}
        state['cur_item_types'] = {}
        state['temp_of_elem'] = {}
        dispatcher.trace.clear()

        self_ptr = merged['self_ptr']
        uc.mem_write(self_ptr, b'\x00' * IMAGE_SIZE)
        session.word(self_ptr + OFF_WORLD, merged['world_ivar'])
        session.word(self_ptr + OFF_DYNAMIC_WORLD, merged['dynamic_world_ivar'])
        session.word(self_ptr + OFF_POS, merged['pos_x'] & 0xffffffff)
        session.word(self_ptr + OFF_POS + 4, merged['pos_y'] & 0xffffffff)
        session.word(self_ptr + OFF_ITEM_TYPE, merged['item_type_init'] & 0xffffffff)
        session.word(self_ptr + OFF_HOVERS, merged['hovers_init'] & 0xffffffff)
        session.word(self_ptr + OFF_UNIQUE_ID, merged['unique_id'] & 0xffffffff)

        stack_top = session.stack + STACK_OFFSET
        uc.mem_write(stack_top, struct.pack(
            '<II', merged['save_dict_token'], merged['cache_token']))

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
                print(f'    {names.get(code, code):34s} {arg:#x}')
            print('    itemType =', struct.unpack('<I', arm_image[OFF_ITEM_TYPE:OFF_ITEM_TYPE+4])[0],
                  'hovers =', arm_image[OFF_HOVERS])
            print('    floatPos bytes24-31 =', arm_image[24:32].hex())
            print('    creationTime bytes80-87 =', arm_image[80:88].hex())
            print('    updateNeeds@49 =', arm_image[49])

        cfg = BridgeInput()
        cfg.self_ptr = merged['self_ptr']
        cfg.super_returns_nil = 1 if merged['super_returns_nil'] else 0
        cfg.world_argument = merged['world_argument']
        cfg.dynamic_world_argument = merged['dynamic_world_argument']
        cfg.save_dict_token = merged['save_dict_token']
        cfg.cache_token = merged['cache_token']
        cfg.world_ivar = merged['world_ivar']
        cfg.dynamic_world_ivar = merged['dynamic_world_ivar']
        cfg.pos_x = merged['pos_x']
        cfg.pos_y = merged['pos_y']
        cfg.unique_id = merged['unique_id']
        cfg.item_type_init = merged['item_type_init']
        cfg.hovers_init = merged['hovers_init']
        cfg.bounce_timer_value = merged['bounce_timer_value']
        cfg.fall_speed_value = merged['fall_speed_value']
        cfg.creation_time_value = merged['creation_time_value']
        cfg.float_vx_value = merged['float_vx_value']
        cfg.float_vy_value = merged['float_vy_value']
        cfg.hovers_value = merged['hovers_value']
        cfg.item_type_value = merged['item_type_value']
        cfg.data_a_value = merged['data_a_value']
        cfg.data_b_value = merged['data_b_value']
        cfg.priority_id_value = merged['priority_id_value']
        cfg.blockhead_answer = merged['blockhead_answer']
        flat_types = []
        elem_counts = []
        for elem in merged['sub_items']:
            elem_counts.append(len(elem))
            flat_types.extend(elem)
        cfg.sub_item_count = len(flat_types)
        for i, t in enumerate(flat_types):
            cfg.sub_items[i] = t
        cfg.elem_count = len(elem_counts)
        for i, n in enumerate(elem_counts):
            cfg.elem_counts[i] = n
        cfg.world_time = merged['world_time']
        cfg.object_type_value = merged['object_type_value']
        cfg.tile_count = len(merged['tiles'])
        for i, t in enumerate(merged['tiles']):
            cfg.tile_present[i] = 1 if t['present'] else 0
            cfg.tile_byte0[i] = t['byte0']

        for opt, fn in fns:
            image_buf = ctypes.create_string_buffer(IMAGE_SIZE)
            trace_buf = ctypes.create_string_buffer(512 * 8)
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
            'item_type_final': struct.unpack('<I', arm_image[OFF_ITEM_TYPE:OFF_ITEM_TYPE+4])[0],
            'hovers_final': arm_image[OFF_HOVERS],
            'pos_x_final': struct.unpack('<i', arm_image[OFF_POS:OFF_POS+4])[0],
            'pos_y_final': struct.unpack('<i', arm_image[OFF_POS+4:OFF_POS+8])[0],
        })

    report = {
        'sha256': SHA,
        'class': 'FreeBlock',
        'method': SELECTOR,
        'imp': hex(IMP),
        'code_words': 1347,
        'image_size': IMAGE_SIZE,
        'cases': len(rows),
        'match': True,
        'rows': rows,
        'boundary': (
            "Unicorn execution of the original 1,347-word exact-variant loader: "
            "super2 with four arguments, the twelve-key walk (bounceTimer/"
            "fallSpeed/creationTime/floatPos[VX]/floatPos[VY]/hovers/itemType/"
            "dataA/dataB/subItems/dynamicObjectSaveDict/priorityBlockhead-"
            "UinqueID), the NSFastEnumeration subItems loop with InventoryItem "
            "alloc+initWithSaveData: children (itemType==11 skipped), the 64-bit "
            "blockheadWithIDIncludingNet: resolution, initSubDerivedObjects, the "
            "hovers/creationTime>900s gate, the itemType blacklist (inline cmps + "
            "0x627C40 helper + 0x5B2AD4 liquid predicate), the floatPos re-anchor "
            "and the max-16 ground-fall loop with native 0x00A12300/0x004B49FC/"
            "0x004BDAAC helpers. Not Foundation, not the original-app runtime, "
            "no device run."
        )
    }
    (a.output_dir / 'freeblock_init_arm_result.json').write_text(json.dumps(report, indent=2))
    print(f"freeblock_init_arm: PASS ({len(rows)} cases)")
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
