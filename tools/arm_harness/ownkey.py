"""Shared Level-B differential runner for the b3j "forward-then-read" family
(batch ownkey5): AppleTree / TrainStation / Plant / GatherBlock / Yak.

Five original ARM32 `initWithWorld:...` loaders share one executed shape:

    objc_msgSendSuper2 (same-shape forward)
    nil guard -> return nil
    <per-class own steps>          # objectForKey:/conv -> own ivar, or
                                   # long-variant arg stores, or tail hooks
    return self

This module owns the WHOLE Unicorn preamble, the objc_msgSendSuper2 stub, the
objc_msgSend receiver/argument trace stub (the shared objectForKey:/floatValue/
intValue/retain assertion vocabulary), the ivar-store code hooks and the
descriptor schema. A method harness is a thin table (see
tools/test_ownkey5_arm.py). Nothing here is class-specific.

Trace codes come from the single source of truth (trace_schemas.json ->
tools/trace_codes_gen.py), so ARM and C++ cannot drift.
"""
import struct

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                               UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                               UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                               UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_PC,
                               UC_ARM_REG_LR)

REG = {'r0': UC_ARM_REG_R0, 'r1': UC_ARM_REG_R1}
# register-file index -> Unicorn register (for the [Rn, Rm] store form)
_R = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
      UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
      UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
      UC_ARM_REG_R12]

from .loader import ARMSession
from .graph import FixtureGraph
from trace_codes_gen import OWNKEY5_INIT_CODES as C

GOT_SUPER2 = 0x0105B79C
GOT_MSGSEND = 0x0105B7A0
VENEER_MSGSEND_SLOT = 0x0105FB18     # 0x1c281c veneer (Plant dispatches here)

STUB_SUPER = 0x72000000
STUB_SEND = 0x72100000

def _ensure_mapped(uc, addr, size):
    """Map a stub page, tolerating a session that already has it mapped.

    Keying the cache on id(uc) is unsound: with a fresh ARMSession per method
    a freed uc's object id can be reused, and a stale entry would then skip
    the mapping and crash on the first stub hit.
    """
    try:
        uc.mem_map(addr, size)
    except Exception:
        pass

SUPER_STRUCT = 0x60000800            # 8-byte {receiver, class} scratch

CONV_CODE = {
    'intValue': C['IntValue'],
    'floatValue': C['FloatValue'],
    'boolValue': C['BoolValue'],
    'doubleValue': C['DoubleValue'],
    'retain': C['Retain'],
}
HOOK_CODE = {
    'initSubDerivedItems': C['InitSubDerivedItems'],
    'updateTextures': C['UpdateTextures'],
    'loadSaveDictValues:': C['LoadSaveDictValues'],
}


def f32(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


class OwnKeyRunner:
    """Installs the shared stubs for one method descriptor onto a session."""

    def __init__(self, session, graph, descriptor):
        self.session = session
        self.uc = session.uc
        self.graph = graph
        self.d = descriptor
        self.trace = []
        self.state = {'case': None, 'boxes': {}, 'box_key': {}, 'key_index': {}}

        uc = self.uc
        _ensure_mapped(uc, STUB_SUPER, 0x1000)
        _ensure_mapped(uc, STUB_SEND, 0x1000)
        session.patch_got(GOT_SUPER2, STUB_SUPER)
        session.patch_got(GOT_MSGSEND, STUB_SEND)
        session.patch_got(VENEER_MSGSEND_SLOT, STUB_SEND)

        # objc_super struct scratch for the super stub.
        uc.mem_write(SUPER_STRUCT, b'\x00' * 8)

        self.own_class = session.read_word(self.d['superref_slot'])
        for i, kr in enumerate(self.d['key_reads']):
            self.state['key_index'][kr['key']] = i

        # the method's own selector string (used as the r1 entry argument).
        self.sel_region = graph.command_selector(self.d['selector'])
        self.d = dict(self.d, selector_region=self.sel_region)

        uc.hook_add(UC_HOOK_CODE, self._super_hook, begin=STUB_SUPER,
                    end=STUB_SUPER + 4)
        uc.hook_add(UC_HOOK_CODE, self._send_hook, begin=STUB_SEND,
                    end=STUB_SEND + 4)
        for addr, reg, offset in self.d['stores']:
            uc.hook_add(UC_HOOK_CODE,
                        self._make_store_hook(addr, reg, offset),
                        begin=addr, end=addr + 4)

    # -- helpers -----------------------------------------------------------
    def _resolve_key(self, obj):
        """The body passes the real ELF CFString object in r2; resolve the key
        string directly, else through the object's +8 data pointer (b4f)."""
        raw = bytes(self.uc.mem_read(obj, 48)).split(b'\x00')[0].decode(
            'latin-1')
        if raw in self.state['key_index']:
            return raw
        data = self.session.read_word(obj + 8)
        raw = bytes(self.uc.mem_read(data, 48)).split(b'\x00')[0].decode()
        return raw

    def _make_store_hook(self, addr, reg, offset):
        """Assert the store targets `self + offset`.

        Two addressing forms occur in this family (verified against the raw
        words): the base register already holds the address
        (`str r0,[r1]` / `vstr s0,[r0]`, displacement 0) and the
        register-offset form (`str r0,[r1,r2]`, base = self, index = offset).
        Derive the effective address from the instruction's own encoding
        instead of assuming one form.
        """
        word = self.session.read_word(addr)
        register_form = ((word >> 25) & 1) == 1

        def hook(uc_, address, size, data):
            if address != addr:
                return
            if register_form:
                # ARM register-offset form: Rn = bits 19-16, Rm = bits 3-0.
                dest = (self.uc.reg_read(_R[(word >> 16) & 0xF]) +
                        self.uc.reg_read(_R[word & 0xF]))
            else:
                dest = self.uc.reg_read(REG[reg])
            expected = self.state['case']['self'] + offset
            assert dest == expected, ('store dest', hex(dest),
                                      hex(expected))
            self.trace.append((C['StoreIvar'], offset))
        return hook

    # -- stubs -------------------------------------------------------------
    def _super_hook(self, uc_, address, size, data):
        case = self.state['case']
        struct_ptr = uc_.reg_read(UC_ARM_REG_R0)
        recv = self.session.read_word(struct_ptr)
        cls = self.session.read_word(struct_ptr + 4)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 128)).split(b'\x00')[0].decode()
        r2 = uc_.reg_read(UC_ARM_REG_R2)
        r3 = uc_.reg_read(UC_ARM_REG_R3)
        sp = uc_.reg_read(UC_ARM_REG_SP)
        a0 = self.session.read_word(sp)
        a1 = self.session.read_word(sp + 4)
        assert recv == case['self'], ('super receiver', hex(recv))
        assert cls == self.own_class, ('super class', hex(cls),
                                       hex(self.own_class))
        assert sel == self.d['super_selector'], sel
        assert r2 == case['world'], ('super world', hex(r2))
        assert r3 == case['dyn'], ('super dyn', hex(r3))
        assert a0 == case['save'], ('super saveDict', hex(a0))
        assert a1 == case['cache'], ('super cache', hex(a1))
        if self.d['forward_long']:
            a2 = self.session.read_word(sp + 8)
            a3 = self.session.read_word(sp + 12)
            assert a2 == case['density'], ('super density', hex(a2))
            assert a3 == case['season'], ('super season', hex(a3))
        self.trace.append((C['MsgSendSuper'], 6 if self.d['forward_long'] else 4))
        uc_.reg_write(UC_ARM_REG_R0,
                      0 if case['super_nil'] else case['self'])
        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    def _send_hook(self, uc_, address, size, data):
        case = self.state['case']
        recv = uc_.reg_read(UC_ARM_REG_R0)
        sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
        sel = bytes(uc_.mem_read(sel_ptr, 128)).split(b'\x00')[0].decode()
        r2 = uc_.reg_read(UC_ARM_REG_R2)
        r3 = uc_.reg_read(UC_ARM_REG_R3)
        sp = uc_.reg_read(UC_ARM_REG_SP)

        if sel == 'objectForKey:':
            assert recv == case['save'], ('objectForKey recv', hex(recv))
            key = self._resolve_key(r2)
            assert key in self.state['boxes'], ('unknown key', repr(key))
            index = self.state['key_index'][key]
            self.trace.append((C['ObjectForKey'], index))
            uc_.reg_write(UC_ARM_REG_R0, self.state['boxes'][key])
        elif sel in ('intValue', 'floatValue', 'boolValue', 'doubleValue',
                     'retain'):
            key = self.state['box_key'].get(recv)
            assert key is not None, ('conversion receiver', hex(recv), sel)
            bits = case['kv'][self.state['key_index'][key]] & 0xFFFFFFFF
            self.trace.append((CONV_CODE[sel], bits))
            uc_.reg_write(UC_ARM_REG_R0, bits)
        elif sel == 'initSubDerivedItems' or sel == 'updateTextures':
            assert recv == case['self'], (sel, 'receiver', hex(recv))
            self.trace.append((HOOK_CODE[sel], 0))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == 'loadSaveDictValues:':
            assert recv == case['self'], ('loadSaveDictValues recv', hex(recv))
            assert r2 == case['save'], ('loadSaveDictValues arg', hex(r2))
            self.trace.append((C['LoadSaveDictValues'], 0))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        elif sel == 'objectType':
            assert recv == case['self'], ('objectType recv', hex(recv))
            self.trace.append((C['ObjectType'], case['otype']))
            uc_.reg_write(UC_ARM_REG_R0, case['otype'])
        elif sel == 'dynamicWorldChangedAtPos:objectType:':
            assert recv == case['dyn_ivar'], ('notify recv', hex(recv))
            assert r2 == case['pos_x'], ('notify pos.x', hex(r2))
            assert r3 == case['pos_y'], ('notify pos.y', hex(r3))
            assert self.session.read_word(sp) == case['otype'], 'notify otype'
            self.trace.append((C['DynamicWorldChangedAtPos'], case['pos_x']))
            uc_.reg_write(UC_ARM_REG_R0, 0)
        else:
            raise AssertionError(('unexpected msgSend selector', sel))

        uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

    # -- run ---------------------------------------------------------------
    def run_case(self, case):
        """Execute the original ARM body once; return (returned, image, trace)."""
        self.state['case'] = case
        self.state['boxes'] = {}
        self.state['box_key'] = {}
        self.trace = []

        self_ptr = case['self']
        for i, kr in enumerate(self.d['key_reads']):
            box = self.graph.box(kr['key'], i, 0)
            self.state['boxes'][kr['key']] = box
            self.state['box_key'][box] = kr['key']

        self.uc.mem_write(self_ptr, b'\x00' * self.d['image_size'])
        for off, value in self.d.get('preload_ivars', {}).items():
            self.graph.word(self_ptr + off, case[value])

        sp = self.session.stack + 0x8000
        # The INCOMING frame always carries all four stacked arguments for a
        # long-variant method (saveDict, cache, treeDensity, seasonOffset) —
        # the body may swallow any of them into its own ivars. `forward_long`
        # decides only how many of them the super stub asserts, never how many
        # the caller places on the stack.
        args = [case['save'], case['cache'], case['density'], case['season']]
        self.uc.mem_write(sp, struct.pack('<%dI' % len(args), *args))

        self.session.run(self.d['imp'], sp_offset=0x8000, R0=self_ptr,
                         R1=self.d['selector_region'], R2=case['world'],
                         R3=case['dyn'])
        returned = self.uc.reg_read(UC_ARM_REG_R0)
        image = bytes(self.uc.mem_read(self_ptr, self.d['image_size']))
        return returned, image, list(self.trace)


def make_graph(session, descriptor):
    return FixtureGraph(session.uc)
