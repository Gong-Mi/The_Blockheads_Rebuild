"""Synthetic instance memory for the executed differentials.

Proven pattern from batches b4f/b4g: the ORIGINAL body addresses the real ELF
CFString objects (its PIC literals point there), so a harness that wants to
attribute objectForKey: calls synthesizes its own CFString objects with the
same {isa, info, data_ptr, len} layout and points the save-dict side at them;
the stub resolves keys through the +8 data pointer. Per-key boxes carry a
key index + payload so conversion stubs can attribute their result.
"""
import struct


class FixtureGraph:
    def __init__(self, uc, base=0x60000000, size=0x10000,
                 cmd_region=0x73000000):
        self.uc = uc
        self.base = base
        uc.mem_map(base, size)
        uc.mem_map(cmd_region, 0x1000)
        self.cmd_region = cmd_region
        self._next = base + 0x2000
        self.boxes = {}
        self.cfstrings = {}
        self.box_by_addr = {}

    def word(self, at, value):
        self.uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def alloc(self, n, align=0x20):
        addr = (self._next + align - 1) & ~(align - 1)
        self._next = addr + max(n, align)
        return addr

    def command_selector(self, name):
        self.uc.mem_write(self.cmd_region, name.encode() + b'\0')
        return self.cmd_region

    def cfstring(self, name, isa=0x11111111):
        """A 16-byte CFString object; the body passes the OBJECT in r2, the
        stub resolves the key through the +8 data pointer (b4a lesson 7)."""
        if name in self.cfstrings:
            return self.cfstrings[name]
        s = self.alloc(0x20)
        obj = self.alloc(0x20)
        self.uc.mem_write(s, name.encode() + b'\0')
        self.word(obj + 0, isa)
        self.word(obj + 4, 0)
        self.word(obj + 8, s)
        self.word(obj + 12, len(name))
        self.cfstrings[name] = obj
        return obj

    def box(self, key, key_index, payload=0):
        """An 8-byte boxed value: {key_index, payload}. Object payloads are
        usually the box's own address (fixed per key)."""
        addr = self.alloc(0x20)
        self.word(addr + 0, key_index)
        self.word(addr + 4, payload & 0xffffffff)
        self.boxes[key] = addr
        self.box_by_addr[addr] = key
        return addr

    def set_box_payload(self, key, payload):
        self.word(self.boxes[key] + 4, payload & 0xffffffff)
