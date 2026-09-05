#!/usr/bin/env python3
"""Bounded ARM32 constant propagation for Objective-C dispatch candidates.

Tracks call target and r1 independently. CFG joins retain only equal values;
unsupported instructions invalidate state. This is not receiver/argument recovery
or runtime verification. ELF relocations identify imported call targets.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import re
import subprocess
from collections import deque
from pathlib import Path

ORIGINAL_SHA256 = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
ALIASES = {'ip': 'r12', 'sl': 'r10', 'fp': 'r11', 'lr': 'r14', 'sp': 'r13', 'pc': 'r15'}
REG = re.compile(r'^(?:r(?:1[0-5]|[0-9])|ip|sl|fp|lr|sp|pc)$')
CONDITIONS = ('eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le')


def reg(s):
    return ALIASES.get(s, s)


class ELFMemory:
    def __init__(self, path):
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != ORIGINAL_SHA256:
            raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
        self.data = data
        elf = ELFFile(io.BytesIO(data))
        if elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_ARM':
            raise ValueError('expected little-endian ELF32 ARM')
        self.segments = [(s['p_vaddr'], s['p_offset'], s['p_filesz'])
                         for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.imports = {}
        self.unsupported_relocations = set()
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symbols = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                address = rel['r_offset']
                kind = rel['r_info_type']
                if kind in (21, 22) and rel['r_info_sym']:
                    self.imports[address] = symbols.get_symbol(rel['r_info_sym']).name
                elif kind != 23:  # R_ARM_RELATIVE: file addend is module-relative VA
                    self.unsupported_relocations.add(address)
        self.selectors = {}
        for section in elf.iter_sections():
            if '__objc_selrefs' not in section.name:
                continue
            for address in range(section['sh_addr'], section['sh_addr'] + section['sh_size'], 4):
                pointer = self.word(address)
                if pointer is None:
                    continue
                offset = self.offset(pointer, 1)
                if offset is None:
                    continue
                end = data.find(b'\0', offset, offset + 512)
                if end >= 0:
                    self.selectors[pointer] = data[offset:end].decode('utf-8', 'strict')

    def offset(self, address, size):
        for va, offset, length in self.segments:
            if va <= address and address + size <= va + length:
                return offset + address - va
        return None

    def word(self, address):
        if address in getattr(self, 'unsupported_relocations', set()):
            return None
        offset = self.offset(address, 4)
        return None if offset is None else int.from_bytes(self.data[offset:offset+4], 'little')


def load_pdfj(elf, imp):
    raw = subprocess.check_output([
        'r2', '-q', '-e', 'scr.color=false', '-e', 'bin.relocs.apply=true',
        '-e', 'asm.arch=arm', '-e', 'asm.bits=32',
        '-c', f'af @ 0x{imp:x}; pdfj @ 0x{imp:x}; q', str(elf)], text=True)
    return json.loads(raw)


def parse_ops(pdfj):
    return sorted((op for op in pdfj.get('ops', []) if isinstance(op, dict) and 'addr' in op),
                  key=lambda op: op['addr'])


def instruction(op):
    text = op.get('disasm', '').split(';')[0].strip()
    parts = text.split(None, 1)
    if not parts:
        return '', ''
    return parts[0], parts[1] if len(parts) == 2 else ''


def value(token, state, pc):
    token = token.strip().lstrip('#')
    if REG.fullmatch(token):
        return pc if reg(token) == 'r15' else state.get(reg(token))
    try:
        return int(token, 0)
    except ValueError:
        return None


def location(text, state, pc):
    m = re.fullmatch(r'\[([^\]]+)\]', text.strip())
    if not m:
        return None
    parts = [p.strip() for p in m[1].split(',')]
    if len(parts) not in (1, 2):
        return None
    offset = value(parts[1], state, pc) if len(parts) == 2 else 0
    if not isinstance(offset, int):
        return None
    if reg(parts[0]) in ('r11', 'r13'):
        return ('stack', reg(parts[0]), offset)
    base = value(parts[0], state, pc)
    return (base + offset) & 0xffffffff if isinstance(base, int) else None


def transfer(op, incoming, memory):
    state = dict(incoming)
    mnemonic, operands = instruction(op)
    args = [p.strip() for p in operands.split(',', 1)]
    pc = op['addr'] + 8
    if mnemonic in ('bl', 'blx'):
        for name in ('r0', 'r1', 'r2', 'r3', 'r12', 'r14'):
            state.pop(name, None)
        return state
    if mnemonic == 'b' or mnemonic in {'b' + c for c in CONDITIONS} or mnemonic in ('cmp', 'cmn', 'tst', 'teq', 'nop'):
        return state
    if mnemonic == 'push':
        # Stack-relative slots change, but fp-relative locals remain stable.
        return {k: v for k, v in state.items() if not (isinstance(k, tuple) and k[1] == 'r13')}
    if len(args) == 2 and mnemonic in ('str', 'ldr'):
        if '!' in operands or '],' in operands:
            return {}  # writeback/post-indexed addressing is not modelled
        destination = reg(args[0])
        address = location(args[1], state, pc)
        if mnemonic == 'str':
            if isinstance(address, tuple):
                state.pop(address, None)
                if destination in state:
                    state[address] = state[destination]
            else:
                # Unknown stores may alias saved locals. Do not retain stack facts.
                state = {k: v for k, v in state.items() if isinstance(k, str)}
            return state
        state.pop(destination, None)
        loaded = None
        if isinstance(address, tuple):
            loaded = incoming.get(address)
        elif isinstance(address, int):
            loaded = ('symbol', memory.imports[address]) if address in memory.imports else memory.word(address)
        if loaded is not None:
            state[destination] = loaded
        return state
    if len(args) == 2 and mnemonic in ('mov', 'movw', 'add', 'sub'):
        destination = reg(args[0])
        parts = [p.strip() for p in args[1].split(',')]
        result = None
        if mnemonic in ('mov', 'movw') and len(parts) == 1:
            result = value(parts[0], incoming, pc)
        elif mnemonic in ('add', 'sub') and len(parts) == 2:
            a, b = (value(p, incoming, pc) for p in parts)
            if isinstance(a, int) and isinstance(b, int):
                result = (a + b if mnemonic == 'add' else a - b) & 0xffffffff
        state.pop(destination, None)
        if destination in ('r11', 'r13'):
            state = {k: v for k, v in state.items() if not (isinstance(k, tuple) and k[1] == destination)}
        if result is not None:
            state[destination] = result
        return state
    # Known single-destination instructions can invalidate only that result.
    single_writes = {'eor', 'orr', 'and', 'bic', 'mvn', 'movt', 'lsl', 'lsr', 'asr',
                     'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'mul', 'rsb'}
    predicated_writes = {base + cond for base in ('mov', 'movw', 'add', 'sub', 'ldr')
                         for cond in CONDITIONS}
    if mnemonic in single_writes | predicated_writes and args and REG.fullmatch(args[0]):
        destination = reg(args[0])
        state.pop(destination, None)
        if destination in ('r11', 'r13'):
            state = {k: v for k, v in state.items() if not isinstance(k, tuple)}
        return state
    # Unknown opcode, multi-register load, etc.: fail closed.
    return {}


def analyze_ops(ops, memory):
    ops = sorted(ops, key=lambda op: op['addr'])
    if not ops:
        return []
    by_address = {op['addr']: i for i, op in enumerate(ops)}
    states = {0: {}}
    queue = deque([0])
    while queue:
        i = queue.popleft()
        op = ops[i]
        mnemonic, operands = instruction(op)
        outgoing = transfer(op, states[i], memory)
        successors = []
        if mnemonic == 'b' or mnemonic in {'b' + c for c in CONDITIONS}:
            target = value(operands, {}, op['addr'] + 8)
            if target in by_address:
                successors.append(by_address[target])
            if mnemonic != 'b' and i + 1 < len(ops):
                successors.append(i + 1)
        elif mnemonic == 'bx' or (mnemonic == 'pop' and ('pc' in operands or 'r15' in operands)):
            pass
        elif i + 1 < len(ops) and ops[i+1]['addr'] == op['addr'] + 4:
            successors.append(i+1)
        for successor in successors:
            old = states.get(successor)
            merged = outgoing if old is None else {k: v for k, v in old.items() if k in outgoing and outgoing[k] == v}
            if old is None or merged != old:
                states[successor] = dict(merged)
                queue.append(successor)
    rows = []
    for i, op in enumerate(ops):
        mnemonic, operands = instruction(op)
        if mnemonic != 'blx' or not REG.fullmatch(operands):
            continue
        state = states.get(i, {})
        target = state.get(reg(operands))
        symbol = target[1] if isinstance(target, tuple) and target[0] == 'symbol' else ''
        selector = state.get('r1')
        name = memory.selectors.get(selector, '') if isinstance(selector, int) and symbol == 'objc_msgSend' else ''
        rows.append({'call_address': f"0x{op['addr']:08x}", 'target_register': operands,
                     'target_symbol': symbol, 'selector_status': 'candidate' if name else 'unknown',
                     'selector_address': f'0x{selector:08x}' if name else '',
                     'selector_name': name, 'receiver_status': 'unknown', 'argument_status': 'unknown'})
    return rows


def analyze(elf, imp):
    memory = ELFMemory(elf)
    return analyze_ops(parse_ops(load_pdfj(elf, imp)), memory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', type=Path)
    parser.add_argument('--imp', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = analyze(args.elf, int(args.imp, 16))
    if not rows:
        raise SystemExit('no blx sites found')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
    print(f"blx-sites={len(rows)} selector-candidates={sum(r['selector_status'] == 'candidate' for r in rows)}")


if __name__ == '__main__':
    main()
