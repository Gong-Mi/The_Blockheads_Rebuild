#!/usr/bin/env python3
"""Small ARMv7-A/ARM-state semantic layer for reverse-engineering tools.

The decoder remains Capstone-backed for this prototype.  This module keeps the
parts that LLVM's ARM backend models structurally (register decoding, ARM PC
bias, address modes, writeback, condition codes, and BFC) out of op_str
regular expressions.  It is deliberately not a CPU emulator.
"""
from dataclasses import dataclass
from typing import Optional

try:
    from capstone.arm import (ARM_SFT_ASR, ARM_SFT_ASR_REG, ARM_SFT_LSL,
                              ARM_SFT_LSL_REG, ARM_SFT_LSR, ARM_SFT_LSR_REG,
                              ARM_SFT_ROR, ARM_SFT_ROR_REG, ARM_SFT_RRX,
                              ARM_SFT_RRX_REG)
except ImportError:  # pragma: no cover - only for non-Capstone importers
    ARM_SFT_ASR = 1; ARM_SFT_ASR_REG = 6; ARM_SFT_LSL = 2; ARM_SFT_LSL_REG = 7
    ARM_SFT_LSR = 3; ARM_SFT_LSR_REG = 8; ARM_SFT_ROR = 4; ARM_SFT_ROR_REG = 9
    ARM_SFT_RRX = 5; ARM_SFT_RRX_REG = 10

SHIFT_NAMES = {
    ARM_SFT_ASR: "asr", ARM_SFT_ASR_REG: "asr",
    ARM_SFT_LSL: "lsl", ARM_SFT_LSL_REG: "lsl",
    ARM_SFT_LSR: "lsr", ARM_SFT_LSR_REG: "lsr",
    ARM_SFT_ROR: "ror", ARM_SFT_ROR_REG: "ror",
    ARM_SFT_RRX: "rrx", ARM_SFT_RRX_REG: "rrx",
}

@dataclass(frozen=True)
class Shift:
    kind: str
    amount: Optional[int] = None
    register: Optional[str] = None
    by_register: bool = False

@dataclass(frozen=True)
class DataOp:
    mnemonic: str
    destination: str
    left: object
    right: object
    shift: Optional[Shift] = None
    set_flags: bool = False


def decode_shift(operand, insn=None) -> Optional[Shift]:
    if insn is not None and insn.mnemonic.lower() == "rrx":
        return Shift("rrx", amount=1, by_register=False)
    shift = getattr(operand, "shift", None)
    if shift is None or not getattr(shift, "type", 0):
        return None
    kind = SHIFT_NAMES.get(int(shift.type), "unknown")
    value = int(getattr(shift, "value", 0) or 0)
    by_register = kind in {"asr", "lsl", "lsr", "ror"} and int(shift.type) in {
        ARM_SFT_ASR_REG, ARM_SFT_LSL_REG, ARM_SFT_LSR_REG, ARM_SFT_ROR_REG}
    register = None
    if by_register and insn is not None and value:
        register = canonical_reg(insn.reg_name(value))
    return Shift(kind, amount=None if by_register else value,
                 register=register, by_register=by_register)


def decode_shifted_operand(insn, operand_index: int):
    if len(insn.operands) <= operand_index:
        return None
    operand = insn.operands[operand_index]
    return {
        "value": operand_value(insn, operand_index),
        "shift": decode_shift(operand, insn),
    }


def decode_data_op(insn) -> Optional[DataOp]:
    """Decode common ARM data-processing operands from Capstone structures."""
    raw_m = insn.mnemonic.lower()
    flag_suffix = raw_m.endswith("s") and raw_m[:-1] not in {"asr"}
    m = raw_m[:-1] if flag_suffix else raw_m
    names = {"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
             "orr", "bic", "mov", "mvn", "cmp", "cmn", "tst", "teq",
             "lsl", "lsr", "asr", "ror", "rrx"}
    if m not in names or not insn.operands:
        return None
    dst_i = 0 if m not in {"cmp", "cmn", "tst", "teq"} else None
    if dst_i is not None and insn.operands[dst_i].type != 1:
        return None
    start = 1 if dst_i is not None else 0
    if len(insn.operands) <= start:
        return None
    left = insn.operands[start]
    right = insn.operands[start + 1] if len(insn.operands) > start + 1 else None
    destination = _reg_name(insn, insn.operands[dst_i].reg) if dst_i is not None else None
    shift = decode_shift(right, insn) if right is not None else None
    return DataOp(m, destination, left, right, shift,
                  set_flags=flag_suffix or m in {"cmp", "cmn", "tst", "teq"} )


def decode_modified_immediate(insn, operand_index: int):
    """Decode ARM data-processing immediate encoding (imm8 rotated right)."""
    if len(insn.operands) <= operand_index or insn.operands[operand_index].type != 2:
        return None
    word = int.from_bytes(bytes(insn.bytes[:4]), "little")
    imm8 = word & 0xff
    rotate = ((word >> 8) & 0xf) * 2
    value = ((imm8 >> rotate) | (imm8 << (32 - rotate))) & 0xffffffff if rotate else imm8
    return {"imm8": imm8, "rotate": rotate, "value": value}


def operand_value(insn, operand_index: int):
    """Return a structural immediate/register description for a data operand."""
    if len(insn.operands) <= operand_index:
        return None
    op = insn.operands[operand_index]
    if op.type == 1:
        return {"kind": "register", "register": _reg_name(insn, op.reg)}
    if op.type == 2:
        raw = decode_modified_immediate(insn, operand_index)
        return {"kind": "immediate", "value": int(op.imm) & 0xffffffff,
                "encoding": raw}
    return {"kind": "other", "type": int(op.type)}


def shift_value(value: int, shift: Shift, carry: int = 0) -> int:
    value &= 0xffffffff
    if shift is None:
        return value
    amount = int(shift.amount or 0)
    if shift.kind == "lsl":
        return 0 if amount >= 32 else (value << amount) & 0xffffffff
    if shift.kind == "lsr":
        return 0 if amount >= 32 else value >> amount
    if shift.kind == "asr":
        signed = value if value < 0x80000000 else value - 0x100000000
        if amount >= 32:
            return 0xffffffff if signed < 0 else 0
        return (signed >> amount) & 0xffffffff
    if shift.kind == "ror":
        amount %= 32
        return value if amount == 0 else ((value >> amount) | (value << (32 - amount))) & 0xffffffff
    if shift.kind == "rrx":
        return ((carry & 1) << 31) | (value >> 1)
    raise ValueError("unsupported ARM shift: " + shift.kind)

REGISTERS = {**{f"r{i}": f"r{i}" for i in range(13)},
             "r13": "sp", "r14": "lr", "r15": "pc",
             "sp": "sp", "lr": "lr", "pc": "pc", "fp": "fp", "ip": "ip"}

# Capstone's ARM_CC_* enum is not the raw four-bit ARM condition field:
# INVALID=0, EQ=1, NE=2, ... AL=15. Keep this adapter explicit.
COND_CODES = {
    0: "unknown", 1: "eq", 2: "ne", 3: "hs", 4: "lo", 5: "mi", 6: "pl", 7: "vs",
    8: "vc", 9: "hi", 10: "ls", 11: "ge", 12: "lt", 13: "gt", 14: "le", 15: "al",
}

@dataclass(frozen=True)
class Address:
    base: str
    offset: int = 0
    index: Optional[str] = None
    index_shift: int = 0
    add: bool = True
    pre_index: bool = True
    writeback: bool = False

@dataclass(frozen=True)
class MemoryOp:
    mnemonic: str
    destination: str
    address: Address
    width: int
    signed: bool = False


def canonical_reg(name: str) -> str:
    return REGISTERS.get(name.lower(), name.lower())


def arm_pc(address: int) -> int:
    """Architectural PC value for an ARM-state instruction."""
    return (address + 8) & 0xffffffff


def condition_name(insn) -> str:
    return COND_CODES.get(int(getattr(insn, "cc", 14)), "unknown")


def _reg_name(insn, reg_id: int) -> str:
    return canonical_reg(insn.reg_name(reg_id))


def decode_address(insn, operand_index: int = 1) -> Optional[Address]:
    """Decode a Capstone ARM memory operand without parsing its text form."""
    if len(insn.operands) <= operand_index:
        return None
    operand = insn.operands[operand_index]
    if operand.type != 3:  # ARM_OP_MEM
        return None
    mem = operand.mem
    base = _reg_name(insn, mem.base) if mem.base else "none"
    index = _reg_name(insn, mem.index) if mem.index else None
    # Capstone's ARM operand object does not expose P/U/W consistently across
    # versions (notably for post-indexed LDR). Read these architectural bits
    # from the instruction word, like LLVM's ARM addressing-mode decoder does.
    word = int.from_bytes(bytes(insn.bytes[:4]), "little")
    pre_index = bool(word & (1 << 24))
    add = bool(word & (1 << 23))
    writeback = bool(word & (1 << 21)) or not pre_index
    shift = int(getattr(mem, "lshift", 0) or 0)
    return Address(base=base, offset=abs(int(mem.disp)), index=index,
                   index_shift=shift, add=add, pre_index=pre_index,
                   writeback=writeback)


def decode_memory(insn, operand_index: int = 1) -> Optional[MemoryOp]:
    m = insn.mnemonic.lower()
    widths = {"ldr": 4, "str": 4, "ldrb": 1, "strb": 1,
              "ldrh": 2, "strh": 2, "ldrsb": 1, "ldrsh": 2,
              "ldrd": 8, "strd": 8}
    if m not in widths or len(insn.operands) <= operand_index:
        return None
    dst = insn.operands[0]
    if dst.type != 1:
        return None
    return MemoryOp(m, _reg_name(insn, dst.reg), decode_address(insn, operand_index),
                    widths[m], m in {"ldrsb", "ldrsh"})


def branch_target(insn) -> Optional[int]:
    if insn.mnemonic.lower() not in {"b", "bl", "blx"} and not insn.mnemonic.lower().startswith("b"):
        return None
    if not insn.operands or insn.operands[0].type != 2:
        return None
    return int(insn.operands[0].imm) & 0xffffffff


def bfc_result(source: int, lsb: int, width: int) -> int:
    """ARM BFC: clear WIDTH bits beginning at LSB in the destination."""
    if width <= 0 or lsb < 0 or lsb + width > 32:
        raise ValueError("invalid ARM BFC bitfield")
    mask = ((1 << width) - 1) << lsb
    return source & (~mask & 0xffffffff)


def decode_bfc(insn):
    if insn.mnemonic.lower() != "bfc" or len(insn.operands) != 3:
        return None
    if any(o.type != 2 for o in insn.operands[1:]):
        return None
    dst = insn.operands[0]
    if dst.type != 1:
        return None
    return {"destination": _reg_name(insn, dst.reg),
            "lsb": int(insn.operands[1].imm),
            "width": int(insn.operands[2].imm)}


def transfer_bfc(value: Optional[int], spec) -> Optional[int]:
    return None if value is None else bfc_result(value, spec["lsb"], spec["width"])
