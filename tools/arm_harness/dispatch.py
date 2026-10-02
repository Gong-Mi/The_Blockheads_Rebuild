"""Selector-string objc_msgSend stub with a handler table.

The original bodies load every selector from their own selref cells, so the
stub receives pointers into the mapped ELF's real selector strings — it
dispatches on those strings directly (no synthesized selector table needed).
Handlers receive the raw registers plus a recorder; each returns the r0
value (and optionally r1 for softfp pairs). Unknown selectors raise instead
of guessing (the b4e lesson: a logging/strict stub beats a permissive one).
"""
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_PC, UC_ARM_REG_LR)


class MsgDispatcher:
    def __init__(self, uc, stub_addr):
        self.uc = uc
        self.stub_addr = stub_addr
        self.handlers = {}
        self.trace = []
        uc.mem_map(stub_addr, 0x1000)

    def register(self, selector):
        def deco(fn):
            self.handlers[selector] = fn
            return fn
        return deco

    def record(self, code, arg=0):
        self.trace.append((code, arg))

    def install(self):
        uc = self.uc

        def hook(uc_, address, size, data):
            recv = uc_.reg_read(UC_ARM_REG_R0)
            sel_ptr = uc_.reg_read(UC_ARM_REG_R1)
            # 256 bytes: the selector strings of the longest front methods
            # (`initWithWorld:dynamicWorld:saveDict:cache:treeDensityNoiseFunction:
            # seasonOffsetNoiseFunction:` is ~99 chars) do not fit in 64.
            sel = bytes(uc_.mem_read(sel_ptr, 256)).split(b'\0')[0].decode()
            fn = self.handlers.get(sel)
            if fn is None:
                raise AssertionError(('unimplemented message',
                                      hex(recv), sel))
            ctx = StubContext(uc_, recv, sel, uc_.reg_read(UC_ARM_REG_R2),
                              uc_.reg_read(UC_ARM_REG_R3),
                              uc_.reg_read(UC_ARM_REG_SP), self)
            r0, r1 = fn(ctx)
            uc_.reg_write(UC_ARM_REG_R0, r0 & 0xffffffff)
            if r1 is not None:
                uc_.reg_write(UC_ARM_REG_R1, r1 & 0xffffffff)
            uc_.reg_write(UC_ARM_REG_PC, uc_.reg_read(UC_ARM_REG_LR))

        uc.hook_add(UC_HOOK_CODE, hook, begin=self.stub_addr,
                    end=self.stub_addr + 4)


class StubContext:
    """Registers + small reads a handler needs; keeps handler signatures
    uniform across harnesses."""

    def __init__(self, uc, recv, selector, r2, r3, sp, dispatcher):
        self.uc = uc
        self.recv = recv
        self.selector = selector
        self.r2 = r2
        self.r3 = r3
        self.sp = sp
        self.dispatcher = dispatcher

    def record(self, code, arg=0):
        self.dispatcher.record(code, arg)

    def read(self, addr, n):
        return bytes(self.uc.mem_read(addr, n))

    def word(self, addr):
        import struct
        return struct.unpack('<I', self.read(addr, 4))[0]

    def stack_word(self, offset):
        return self.word(self.sp + offset)

    def cstring(self, addr, limit=64):
        return self.read(addr, limit).split(b'\0')[0].decode()
