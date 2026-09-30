#!/usr/bin/env python3
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from armv7_semantics import (arm_pc, bfc_result, branch_target, canonical_reg,
                             condition_name, decode_address, decode_bfc,
                             decode_data_op, decode_memory, decode_modified_immediate,
                             decode_shift, operand_value, shift_value, transfer_bfc)


def insn(word, address=0x1000):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    result = list(md.disasm(struct.pack('<I', word), address))
    assert len(result) == 1
    return result[0]


def main():
    assert arm_pc(0x1000) == 0x1008
    assert canonical_reg('r13') == 'sp'
    assert canonical_reg('FP') == 'fp'

    load = insn(0xe5920004)
    mem = decode_memory(load)
    assert mem.mnemonic == 'ldr' and mem.destination == 'r0'
    assert mem.address.base == 'r2' and mem.address.offset == 4
    assert mem.width == 4 and not mem.signed
    imm = decode_modified_immediate(insn(0xe3a00c01), 1)
    assert imm == {'imm8': 1, 'rotate': 24, 'value': 256}

    byte_load = insn(0xe5d13000)
    mem = decode_memory(byte_load)
    assert mem.mnemonic == 'ldrb' and mem.width == 1

    half_store = insn(0xe1c020b0)
    mem = decode_memory(half_store)
    assert mem.mnemonic == 'strh' and mem.destination == 'r2' and mem.width == 2

    bitfield = insn(0xe7c1201f)
    spec = decode_bfc(bitfield)
    assert spec == {'destination': 'r2', 'lsb': 0, 'width': 2}
    assert bfc_result(0xffffffff, 0, 2) == 0xfffffffc
    assert transfer_bfc(0xffffffff, spec) == 0xfffffffc
    assert transfer_bfc(None, spec) is None

    branch = insn(0xea000002)
    assert branch_target(branch) == 0x1010
    assert condition_name(branch) == 'al'
    conditional = insn(0x1a000002)
    assert condition_name(conditional) == 'ne'
    wb = decode_address(insn(0xe5b12004))
    assert wb.base == 'r1' and wb.offset == 4 and wb.add and wb.pre_index and wb.writeback
    down = decode_address(insn(0xe5110004))
    assert down.base == 'r1' and down.offset == 4 and not down.add
    post = decode_address(insn(0xe4910004))
    assert post.base == 'r1' and not post.pre_index and post.writeback and post.add

    shifted = insn(0xe0810213)
    data = decode_data_op(shifted)
    assert not data.set_flags
    adds = decode_data_op(insn(0xe2910001))
    assert adds.mnemonic == 'add' and adds.set_flags
    cmps = decode_data_op(insn(0xe3510001))
    assert cmps.mnemonic == 'cmp' and cmps.destination is None and cmps.set_flags
    movs = decode_data_op(insn(0xe1b02003))
    assert movs.mnemonic == 'mov' and movs.set_flags
    assert data.mnemonic == 'add' and data.destination == 'r0'
    assert data.shift.kind == 'lsl' and data.shift.by_register
    assert data.shift.register == 'r2'
    assert operand_value(shifted, 2) == {'kind': 'register', 'register': 'r3'}
    lsl_imm = insn(0xe1a02103)
    assert decode_shift(lsl_imm.operands[1], lsl_imm).amount == 2
    assert shift_value(0x00000003, decode_shift(lsl_imm.operands[1], lsl_imm)) == 0x0000000c
    rrx = insn(0xe1a02063)
    assert rrx.mnemonic == 'rrx'
    assert shift_value(0x00000002, decode_shift(rrx.operands[1], rrx), carry=1) == 0x80000001
    ror = insn(0xe1a02161)
    assert decode_shift(ror.operands[1], ror).kind == 'ror'
    assert shift_value(0x00000001, decode_shift(ror.operands[1], ror)) == 0x40000000
    print('armv7_semantics: PASS')


if __name__ == '__main__':
    main()
