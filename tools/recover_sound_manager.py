#!/usr/bin/env python3
"""Hash-pinned MJSoundManager singleton/listener complete-method evidence."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from recover_world_view_contracts import SHA, require

ROOT = Path(__file__).resolve().parents[1]
METHODS = [('instance', 0xb88858, 0xb88924, 0xb8893c),
           ('setListenerPosition:zoom:', 0xb89e98, 0xb89f60, 0xb89f68),
           ('listenerPos', 0xb89f68, 0xb89fa8, 0xb89fb0)]

def recover(path):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == SHA, 'ELF SHA mismatch')
    with path.open('rb') as f:
        elf = ELFFile(f)
        segs = [(s['p_vaddr'], s.data(), s['p_memsz']) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        syms = {s.name: s['st_value'] for sec in elf.iter_sections() if sec['sh_type'] == 'SHT_DYNSYM' for s in sec.iter_symbols()}
        rel = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
                tab = elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    rel[r['r_offset']] = (r['r_info_type'], tab.get_symbol(r['r_info_sym']).name)
    def read(a, n):
        for base, data, memsz in segs:
            if base <= a and a+n <= base+memsz:
                offset = a-base
                return data[offset:offset+n].ljust(n, b'\0')
        raise ValueError(hex(a))
    def word(a): return struct.unpack('<I', read(a, 4))[0]
    def string(a):
        b = bytearray()
        while read(a, 1) != b'\0': b += read(a, 1); a += 1
        return b.decode()
    base = (0xb88868+8+word(0xb88938)) & 0xffffffff
    require(base == 0x105faf4, 'PIC base')
    slot = (base+word(0xb88924)) & 0xffffffff
    require(slot == 0x1065e94 and word(slot) == 0 and slot not in rel, 'singleton storage')
    require(rel[(base+word(0xb88928)) & 0xffffffff] == (21, 'objc_msgSend'), 'instance dispatch import')
    selectors = []
    for literal, expected in [(0xb88930, 'alloc'), (0xb8892c, 'initWithMasterVolume:')]:
        ref = (base+word(literal)) & 0xffffffff
        require(rel[ref] == (23, '') and string(word(ref)) == expected, 'selector')
        selectors.append({'literal': hex(literal), 'ref': hex(ref), 'selector': expected})
    classref = (base+word(0xb88934)) & 0xffffffff
    require(rel[classref] == (23, '') and word(classref) == syms['OBJC_CLASS_$_MJSoundManager'], 'classref')
    listener_base = (0xb89ea8+8+word(0xb89f64)) & 0xffffffff
    require(listener_base == base, 'listener PIC base')
    ivar_slot = (base+word(0xb89f60)) & 0xffffffff
    ivar = word(ivar_slot)
    names = [name for name, a in syms.items() if a == ivar and name.startswith('OBJC_IVAR_$_MJSoundManager.')]
    require(len(names) == 1 and rel[ivar_slot] == (23, ''), 'listener ivar')
    require(word(0xb89f28) == 0xeeb30a04 and word(0xb888a0) == 0xeeb70a00, '20.0f/1.0f VFP immediate')
    # Standard ARM PLT veneer, decode rotated immediates.
    def imm(w):
        v, rot = w & 255, ((w >> 8) & 15)*2
        return ((v >> rot) | (v << (32-rot))) & 0xffffffff if rot else v
    a, b, c = [word(0x1c443c+i*4) for i in range(3)]
    require(a & 0xfffff000 == 0xe28fc000 and b & 0xfffff000 == 0xe28cc000 and c & 0xfffff000 == 0xe5bcf000, 'PLT format')
    al_slot = (0x1c443c+8+imm(a)+imm(b)+(c & 4095)) & 0xffffffff
    require(rel[al_slot][1] == 'alListener3f', 'AL import')
    helper = bytes.fromhex('04d04de200008de500009de504d08de21eff2fe1')
    require(read(0x4bdaac, 20) == helper, 'Vector2 identity helper')
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    records, lines = [], []
    for name, start, end, pool_end in METHODS:
        insns = list(md.disasm(read(start, end-start), start))
        require(len(insns)*4 == end-start, 'instruction coverage')
        calls = [{'address': hex(i.address), 'opcode': i.mnemonic, 'target': i.op_str} for i in insns if i.mnemonic in ('bl', 'blx')]
        branches = [{'address': hex(i.address), 'opcode': i.mnemonic, 'target': i.op_str} for i in insns if i.mnemonic.startswith('b') and i.mnemonic not in ('bl', 'blx', 'bx')]
        records.append(dict(selector=name, implementation=f'0x{start:08x}', code_end=hex(end), pool_end=hex(pool_end), instruction_count=len(insns), region_sha256=hashlib.sha256(read(start,pool_end-start)).hexdigest(), calls=calls, branches=branches))
        lines.append(f'\n{name} 0x{start:08x}:')
        lines.extend(f'{i.address:08x}: {word(i.address):08x}  {i.mnemonic} {i.op_str}' for i in insns)
        lines.extend(f'{a:08x}: {word(a):08x}  .word (pool)' for a in range(end,pool_end,4))
    require([len(r['calls']) for r in records] == [2,3,0], 'complete call counts')
    require([len(r['branches']) for r in records] == [1,0,0], 'complete branch counts')
    result = dict(schema=1, elf_sha256=SHA, methods=records, singleton_slot=hex(slot), singleton_initial_value=0, singleton_classref=hex(classref), selectors=selectors, listener_ivar=dict(symbol=names[0], offset=hex(word(ivar)), slot=hex(ivar_slot)), al_import_slot=hex(al_slot), al_parameter=0x1004, listener_z_multiplier=20.0, initial_master_volume=1.0, runtime_verified=False, integrated_into_game=False)
    return json.dumps(result, indent=2)+'\n', '\n'.join(lines)+'\n'

def main():
    p=argparse.ArgumentParser(); p.add_argument('--elf',type=Path,required=True); p.add_argument('--check',action='store_true'); args=p.parse_args()
    text, disasm = recover(args.elf)
    for name, data in [('sound_manager.json',text), ('disasm_sound_manager.txt',disasm)]:
        out=ROOT/'reconstruction/reverse-v3/native'/name
        if args.check: require(out.read_text()==data,'stale '+name)
        else: out.write_text(data)
    d=json.loads(text)
    print(json.dumps({'methods':len(d['methods']), 'instructions':sum(r['instruction_count'] for r in d['methods']), 'calls':sum(len(r['calls']) for r in d['methods']), 'branches':sum(len(r['branches']) for r in d['methods']), 'listener_ivar':d['listener_ivar']}))
if __name__=='__main__': main()
