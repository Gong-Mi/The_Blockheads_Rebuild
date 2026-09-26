"""ELF -> Unicorn session for the executed differentials (batches b4*)."""
import hashlib
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC,
                               UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)


class ARMSession:
    """SHA-gated ARM32 ELF mapped into a fresh Unicorn instance.

    The b4x harnesses all repeat the same preamble: verify the pinned SHA,
    iterate PT_LOAD segments, map every touched 4 KiB page, write file bytes,
    enable CP10/CP11 + FPEXC.EN (without which the first VFP instruction
    raises UC_ERR_INSN_INVALID). This class is that preamble.
    """

    def __init__(self, elf_path, sha256, stack=0x70000000, stop=0x71000000):
        raw = elf_path if isinstance(elf_path, bytes) else open(elf_path, 'rb').read()
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise SystemExit('ELF SHA mismatch')
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.reg_write(UC_ARM_REG_C1_C0_2,
                          self.uc.reg_read(UC_ARM_REG_C1_C0_2) | (0xF << 20))
        self.uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        with __import__('io').BytesIO(raw) as f:
            elf = ELFFile(f)
            assert elf['e_machine'] == 'EM_ARM' and elf.elfclass == 32
            self.loads = [(s['p_vaddr'], s['p_memsz'], s.data())
                          for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        pages = set()
        for base, size, _ in self.loads:
            pages.update(range(base & ~4095, (base + size + 4095) & ~4095, 4096))
        for page in sorted(pages):
            self.uc.mem_map(page, 4096)
        for base, _, data in self.loads:
            self.uc.mem_write(base, data)
        self.stack = stack
        self.stop = stop
        self.uc.mem_map(stack, 0x10000)
        self.uc.mem_map(stop, 0x1000)

    def word(self, at, value):
        self.uc.mem_write(at, struct.pack('<I', value & 0xffffffff))

    def read_word(self, at):
        return struct.unpack('<I', bytes(self.uc.mem_read(at, 4)))[0]

    def patch_got(self, slot, stub_addr):
        self.word(slot, stub_addr)

    def run(self, imp, sp_offset=0x8000, count=500000, **regs):
        """Run from imp until LR hits stop. regs: R0/R1/R2/R3 + SP/LR are
        set by the caller through kwargs; SP defaults to stack+sp_offset."""
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_R3)
        table = {'R0': UC_ARM_REG_R0, 'R1': UC_ARM_REG_R1,
                 'R2': UC_ARM_REG_R2, 'R3': UC_ARM_REG_R3}
        for name, reg in table.items():
            if name in regs:
                self.uc.reg_write(reg, regs[name])
        self.uc.reg_write(UC_ARM_REG_SP, self.stack + sp_offset)
        self.uc.reg_write(UC_ARM_REG_LR, self.stop)
        self.uc.emu_start(imp, self.stop, count=count)
        assert self.uc.reg_read(UC_ARM_REG_PC) == self.stop, \
            'method did not return'
