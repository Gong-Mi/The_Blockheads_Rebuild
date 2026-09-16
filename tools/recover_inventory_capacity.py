#!/usr/bin/env python3
"""Hash-gated bounded ARM evidence; no execution or generic decompilation claim."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED_SHA256 = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
RANGES = {
    'canPickUpItemOfType:subItems:': [(0xc5d748, 0xc5d7ac)],
    'canPickUpItemOfType:subItems:dataA:dataB:': [
        (0xc5d7b8, 0xc5e4d8), (0xc5e4f0, 0xc5e8cc),
        (0xc5e8d0, 0xc5e978), (0xc5e97c, 0xc5e990)],
    'subItemCapacityAtC5EAA8': [(0xc5eaa8, 0xc5ec34)],
    'itemTypeIsValidInventoryItem': [(0xc5e9ac, 0xc5ea20)],
    'itemTypeIsLiquid': [(0xc5ea20, 0xc5ea38)],
    'itemTypeIsMoney': [(0xc5ea38, 0xc5ea90)],
    'itemTypeCarriesLiquids': [(0xc5ea90, 0xc5eaa8)],
    'itemTypeIsStackable': [(0x4ea3cc, 0x4ea4c0)],
    'itemTypeSubItemsCanBeModifiedWhileCarried': [(0x4eb960, 0x4eb9a4)],
    'itemTypeIsValidFillItem': [(0x580cdc, 0x580e5c)],
    'itemTypeCanBeColored': [(0x4d6128, 0x4d6220)],
}
POOLS = [(0xc5d7ac, 0xc5d7b8), (0xc5e4d8, 0xc5e4f0),
         (0xc5e8cc, 0xc5e8d0), (0xc5e978, 0xc5e97c), (0xc5e990, 0xc5e9ac)]

def gate(blob):
    actual = hashlib.sha256(blob).hexdigest()
    if actual != EXPECTED_SHA256:
        raise ValueError(f'ELF SHA-256 mismatch: {actual}; expected {EXPECTED_SHA256}')

def validate_words(rows, start, end):
    if [r['address'] for r in rows] != list(range(start, end, 4)):
        raise ValueError('missing, duplicate, or non-contiguous ARM word')
    if any(len(bytes.fromhex(r['bytes'])) != 4 for r in rows):
        raise ValueError('not an ARM32 instruction word')

def self_test():
    for wrong in (b'', b'\x7fELF', EXPECTED_SHA256.encode(), b'not-original'):
        try: gate(wrong)
        except ValueError: pass
        else: raise AssertionError('bad image accepted')
    rows = [{'address': 4, 'bytes': '00000000'}, {'address': 8, 'bytes': '01000000'}]
    validate_words(rows, 4, 12)
    for wrong in (rows[:1], rows[::-1], rows + rows[:1],
                  [{'address': 4, 'bytes': '00'}, rows[1]]):
        try: validate_words(wrong, 4, 12)
        except ValueError: pass
        else: raise AssertionError('bad instruction fixture accepted')
    print('inventory capacity evidence fixtures: positive coverage + 8 negative fixtures PASS')

def recover(path, out):
    blob = Path(path).read_bytes()
    gate(blob) # MUST precede imports/parsing/fixed addresses
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    import io
    elf = ELFFile(io.BytesIO(blob))
    if elf['e_machine'] != 'EM_ARM' or not elf.little_endian or elf.elfclass != 32:
        raise ValueError('not ELF32 little-endian ARM')
    def read(va, n):
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va and va+n <= seg['p_vaddr']+seg['p_filesz']:
                off = seg['p_offset'] + va-seg['p_vaddr']
                return blob[off:off+n]
        raise ValueError(f'unmapped VA {va:#x}')
    def word(va): return struct.unpack('<I', read(va, 4))[0]
    def cstr(va): return read(va, 180).split(b'\0')[0].decode('utf8')
    symbols, rels = {}, {}
    for sec in elf.iter_sections():
        if sec['sh_type'] in ('SHT_DYNSYM', 'SHT_SYMTAB'):
            for s in sec.iter_symbols():
                if s.name and s['st_value']: symbols.setdefault(s['st_value'], []).append(s.name)
        if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
            syms = elf.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                rels[r['r_offset']] = {'type': r['r_info_type'],
                    'symbol': syms.get_symbol(r['r_info_sym']).name}
    pic = (0xc5d7d0 + word(0xc5e4d8)) & 0xffffffff
    assert pic == (0xc5d760 + word(0xc5d7b4)) & 0xffffffff
    pool_rows = []
    selectors = {'worldUIDragging', 'objectAtIndex:', 'count', 'itemType', 'dataB',
                 'subItems', 'countByEnumeratingWithState:objects:count:',
                 'canPickUpItemOfType:subItems:dataA:dataB:'}
    observed = set()
    for lo, hi in POOLS:
        for va in range(lo, hi, 4):
            value = word(va)
            target = (pic + value) & 0xffffffff
            row = {'address': hex(va), 'word': hex(value), 'pic_plus_word': hex(target)}
            if target in rels:
                row['relocation'] = rels[target]
                pointee = word(target)
                row['pointee'] = hex(pointee)
                if pointee:
                    names = symbols.get(pointee)
                    if names:
                        row['symbol'] = names
                        row['ivar_offset'] = word(pointee)
                    else:
                        text = cstr(pointee)
                        row['selector'] = text
                        assert text in selectors, (hex(va), text)
                        observed.add(text)
            pool_rows.append(row)
    assert observed == selectors
    # PLT literal arithmetic is decoded from instruction bits (not rendered #imm).
    def rotated_imm(w):
        v, rot = w & 255, ((w >> 8) & 15) * 2
        return ((v >> rot) | (v << ((32-rot) % 32))) & 0xffffffff
    imports = []
    for va, expected in [(0x1c2924, 'memset'), (0x1c2e28, 'objc_enumerationMutation')]:
        slot = (va+8+rotated_imm(word(va))+rotated_imm(word(va+4))+(word(va+8)&0xfff)) & 0xffffffff
        rel = rels[slot]
        assert rel['symbol'] == expected, (hex(va), rel)
        imports.append({'plt': hex(va), 'slot': hex(slot), 'relocation': rel,
                        'bytes': read(va,12).hex()})
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    methods = []
    for name, ranges in RANGES.items():
        instructions = []
        for start, end in ranges:
            rows = [{'address': i.address, 'bytes': i.bytes.hex(),
                     'mnemonic': i.mnemonic, 'operands': i.op_str}
                    for i in cs.disasm(read(start,end-start),start)]
            validate_words(rows,start,end)
            instructions.extend(rows)
        methods.append({'name': name, 'entry': hex(ranges[0][0]),
                        'ranges': [[hex(a),hex(b)] for a,b in ranges],
                        'instruction_count': len(instructions),
                        'range_sha256': [hashlib.sha256(read(a,b-a)).hexdigest() for a,b in ranges],
                        'instructions': instructions})
    table = NATIVE / 'libApplication_objc_methods.tsv'
    lines = [line for line in table.read_text().splitlines()
             if line.startswith(('0x00c5d748\t','0x00c5d7b8\t'))]
    assert len(lines) == 2 and all('\ti' in line for line in lines)
    result = {'schema': 1, 'original_sha256': EXPECTED_SHA256,
              'method_table_anchors': lines, 'pic_base': hex(pic),
              'classification': {'invalid_or_dragging': 0, 'fit': 1, 'exhausted': -1},
              'outer_indexes': {'first':1,'exclusive_end':8},
              'enumeration_buffer_capacity': 16,
              'source': ['reconstruction/recovered/inventory_capacity.h',
                         'reconstruction/recovered/inventory_capacity.cpp'],
              'semantic_status': 'complete bounded method/control-flow recovery with explicit dynamic runtime dependencies; not original-runtime differential validation',
              'dynamic_dependencies': ['world/inventoryItems receiver ivars',
                  'Foundation/Item Objective-C dispatch', 'fast enumeration + mutation callback',
                  'wrapper override dispatch'],
              'helper_implementation_owner': 'inventory_rules.h/.cpp except subItemCapacityAtC5EAA8',
              'pool_references': pool_rows, 'plt_imports': imports, 'functions': methods}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(f'wrote {out}: {len(methods)} bounded functions; {sum(x["instruction_count"] for x in methods)} ARM words')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf')
    p.add_argument('--output', default=str(NATIVE/'inventory_capacity_evidence.json'))
    p.add_argument('--self-test', action='store_true')
    a = p.parse_args()
    if a.self_test: self_test()
    if a.elf: recover(a.elf, a.output)
    elif not a.self_test: p.error('--elf or --self-test required')
if __name__ == '__main__': main()
