#!/usr/bin/env python3
"""Hash-gated World getter evidence; requires pyelftools and capstone.
No device access. --check compares regenerated outputs without writing them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
# Fixed ARM words include complete function bodies and their literal pools.
BYTE_GETTER = ('e24dd008 e59f202c e08f2002 e59f3020 e7932002 '
               'e58d0004 e58d1000 e59d0004 e5921000 e0800001 '
               'e1d000d0 e28dd008 e12fff1e')
SPECS = [
 ('translation', 0x5536a4, 0x5536e4,
  'e24dd008 e59f3038 e08f3003 e59fc02c e79c3003 e58d1004 e58d2000 '
  'e59d1004 e5932000 e0811002 e5912000 e5802000 e5911004 e5801004 '
  'e28dd008 e12fff1e ffffcc20 00b0c440',
  0x5536ac, 0x5536e8, 0x5536e4, 0x105c714, 0xf328d4, 0x270, 'accurateTranslation'),
 ('isSimulating', 0x56783c, 0x567870, BYTE_GETTER + ' ffffce48 00af82a8',
  0x567844, 0x567874, 0x567870, 0x105c93c, 0xf32afc, 0xc44, 'isSimulating'),
 ('takingPhoto', 0x5c4030, 0x5c40a4,
  'e92d4c10 e28db008 e24dd010 e59f206c e08f2002 e3003000 e59fc054 '
  'e79cc002 e59fe050 e08ee002 e59f404c e7942002 e58d000c e58d1008 '
  'e59d000c e5921000 e0800001 e5900000 e59e1000 e58d3004 e12fff3c '
  'e59d1004 e1500001 e3000000 13a00001 e2000001 e6af0070 e24bd008 '
  'e8bd8c10 ffffbcac ffe1ebd0 ffffcc80 00a9baac',
  0x5c4040, 0x5c40b0, 0x5c40ac, 0x105c774, 0xf32934, 0xf0, 'uiManager'),
 ('worldWidthMacro', 0x5d9824, 0x5d9858,
  'e24dd008 e58d0004 e58d1000 e59d0004 e59f101c e59f201c e08f2002 '
  'e7911002 e5911000 e7900001 f57ff05b e28dd008 e12fff1e ffffcc34 00a862b0',
  0x5d983c, 0x5d985c, 0x5d9858, 0x105c728, 0xf328e4, 0xc, 'worldWidthMacro'),
 ('translatingToGoal', 0x5d9be8, 0x5d9c1c, BYTE_GETTER + ' ffffce94 00a85efc',
  0x5d9bf0, 0x5d9c20, 0x5d9c1c, 0x105c988, 0xf32b48, 0x280, 'translatingToGoal'),
 ('loadComplete', 0x5d9c68, 0x5d9c9c, BYTE_GETTER + ' ffffcdd4 00a85e7c',
  0x5d9c70, 0x5d9ca0, 0x5d9c9c, 0x105c8c8, 0xf32a84, 0x8c, 'loadComplete'),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def recover(path, methods_path):
    require(hashlib.sha256(path.read_bytes()).hexdigest() == SHA, 'original ELF SHA mismatch')
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        segments = [(s['p_vaddr'], s.data()) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        symbols = {s.name: s['st_value'] for sec in elf.iter_sections()
                   if sec['sh_type'] == 'SHT_DYNSYM' for s in sec.iter_symbols()}
        relocs = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
                symtab = elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    relocs[r['r_offset']] = (r['r_info_type'], symtab.get_symbol(r['r_info_sym']).name)
    def read(a, n):
        for base, data in segments:
            if base <= a and a+n <= base+len(data):
                return data[a-base:a-base+n]
        raise ValueError(f'unmapped address {a:#x}')
    def word(a):
        return struct.unpack('<I', read(a, 4))[0]
    rows = [line.split('\t') for line in methods_path.read_text().splitlines()]
    methods = {r[3]: (int(r[0], 16), r[4]) for r in rows
               if len(r) >= 5 and r[1:3] == ['World', 'instance']}
    records, text = [], []
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for name, start, end, expected, pc, literal, index, slot, symbol_va, offset, field in SPECS:
        words = [int(w, 16) for w in expected.split()]
        raw = b''.join(struct.pack('<I', w) for w in words)
        require(read(start, len(raw)) == raw, f'fixed words mismatch: {name}')
        require(methods[name][0] == start, f'World IMP mismatch: {name}')
        base = (pc + 8 + word(literal)) & 0xffffffff
        require((base + word(index)) & 0xffffffff == slot, 'PIC ivar slot mismatch')
        require(relocs[slot] == (23, ''), 'expected R_ARM_RELATIVE ivar slot')
        require(word(slot) == symbol_va, 'ivar pointer mismatch')
        symbol = 'OBJC_IVAR_$_World.' + field
        require(symbols[symbol] == symbol_va and word(symbol_va) == offset, 'ivar symbol/offset mismatch')
        insns = list(md.disasm(read(start, end-start), start))
        require(len(insns)*4 == end-start and insns[-1].address+4 == end, 'instruction coverage mismatch')
        records.append(dict(selector=name, implementation=f'0x{start:08x}', types=methods[name][1],
                            code_end_exclusive=hex(end), stage='implemented', complete_method=True,
                            instruction_count=len(insns), fixed_words=[f'{w:08x}' for w in words],
                            field=dict(name=field, symbol=symbol, symbol_va=hex(symbol_va),
                                       original_offset=hex(offset), pic_base=hex(base),
                                       got_slot=hex(slot), relocation='R_ARM_RELATIVE'),
                            runtime_verified=False))
        text.append(f'\n-[World {name}] 0x{start:08x} code end {end:#x}')
        text.extend(f'{i.address:08x}: {word(i.address):08x}  {i.mnemonic} {i.op_str}' for i in insns)
        text.extend(f'{a:08x}: {word(a):08x}  .word (literal)' for a in range(end, start+len(raw), 4))
    # takingPhoto: target/selector/receiver proved independently, not by method name.
    require(relocs[0x105b7a0] == (21, 'objc_msgSend'), 'objc_msgSend target relocation mismatch')
    require(word(0x105b7a0) == 0, 'unexpected imported target addend')
    require((0x105faf4 + word(0x5c40a4)) & 0xffffffff == 0x105b7a0, 'call target PIC mismatch')
    require((0x105faf4 + word(0x5c40a8)) & 0xffffffff == 0xe7e6c4, 'selector PIC mismatch')
    require(relocs[0xe7e6c4] == (23, '') and word(0xe7e6c4) == 0xed3824, 'selector relocation mismatch')
    require(read(0xed3824, 9) == b'cameraUI\0', 'selector string mismatch')
    records[2]['dispatch'] = dict(callsite='0x005c4080', target='objc_msgSend',
                                  target_slot='0x0105b7a0', selector='cameraUI',
                                  selector_ref='0x00e7e6c4', selector_string='0x00ed3824',
                                  receiver='self.uiManager', result='returned object != nil')
    setter_start, setter_end = 0x5531d0, 0x5536a4
    require(methods['setTranslation:'][0] == setter_start, 'setter World IMP mismatch')
    setter_data = read(setter_start, setter_end-setter_start)
    setter_sha = 'a587b51ed92d57877723438e5518d8a149f84c1df11468b61b0b8a380279a9e1'
    require(hashlib.sha256(setter_data).hexdigest() == setter_sha, 'setter region mismatch')
    text.append('\n-[World setTranslation:] 0x005531d0 NOT IMPLEMENTED; code end 0x55365c')
    insns = list(md.disasm(read(setter_start, 0x55365c-setter_start), setter_start))
    require(len(insns)*4 == 0x55365c-setter_start, 'setter disassembly coverage mismatch')
    text.extend(f'{i.address:08x}: {word(i.address):08x}  {i.mnemonic} {i.op_str}' for i in insns)
    text.extend(f'{a:08x}: {word(a):08x}  .word (pool/padding)' for a in range(0x55365c, setter_end, 4))
    pending = dict(selector='setTranslation:', implementation='0x005531d0',
                   stage='refs', complete_method=False, implemented=False,
                   region_end_exclusive=hex(setter_end), region_sha256=setter_sha,
                   reason='Contains wrapping, second-vector quantization and outgoing ObjC effects; not a plain assignment.')
    result = dict(schema=1, elf_sha256=SHA, evidence='A: static original ELF',
                  complete_method_count=len(records), methods=records, pending=[pending],
                  runtime_verified=False, integrated_into_game=False)
    require(len(records) == 6 and len({r['implementation'] for r in records}) == 6, 'method total mismatch')
    return {'world_view_contracts.json': json.dumps(result, ensure_ascii=False, indent=2)+'\n',
            'disasm_world_view_contracts.txt': '\n'.join(text).lstrip()+'\n'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument('--methods', type=Path, default=root/'reconstruction/reverse-v3/native/libApplication_objc_methods.tsv')
    parser.add_argument('--out-dir', type=Path, default=root/'reconstruction/reverse-v3/native')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs = recover(args.elf, args.methods)
    for name, contents in outputs.items():
        target = args.out_dir/name
        if args.check:
            require(target.read_text() == contents, f'stale artifact: {target}')
        else:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            target.write_text(contents)
    print('PASS: six complete World methods; fixed words/PIC/ivar/selector verified; setTranslation pending; artifacts ' + ('match' if args.check else 'generated'))


if __name__ == '__main__':
    main()
