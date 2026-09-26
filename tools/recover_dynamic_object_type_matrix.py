#!/usr/bin/env python3
"""Hash-gated full enum-to-class matrix recovery from classForDynamicObjectType."""
import argparse, hashlib, json, struct
from pathlib import Path
from elftools.elf.elffile import ELFFile

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
FUNC_ADDR = 0x00B597BC
JUMP_TABLE = 0x00B597FC
TABLE_ENTRIES = 66
BASE_PC = 0x00B597F8
BASE_PIC = 0x0105FAF4

def s(v): return v - (1 << 32) if v & 0x80000000 else v

def get_class_name(raw, segs, class_ptr):
 def word(a):
  for va, po, sz in segs:
   if va <= a and a + 4 <= va + sz:
    return struct.unpack_from('<I', raw, po + a - va)[0]
  return None
 ro = word(class_ptr + 16)
 if not ro: return None
 name_ptr = word(ro + 16)
 if not name_ptr: return None
 for va, po, sz in segs:
  if va <= name_ptr < va + sz:
   s_bytes = raw[po + name_ptr - va : po + name_ptr - va + 64]
   if b'\0' in s_bytes:
    return s_bytes[:s_bytes.find(b'\0')].decode('utf-8', 'replace')
 return None

def recover(path):
 raw = path.read_bytes()
 if hashlib.sha256(raw).hexdigest() != SHA:
  raise ValueError('ELF SHA mismatch')
 with path.open('rb') as f:
  elf = ELFFile(f)
  segs = [(s['p_vaddr'], s['p_offset'], s['p_filesz']) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']

 def word(a):
  for va, po, sz in segs:
   if va <= a and a + 4 <= va + sz:
    return struct.unpack_from('<I', raw, po + a - va)[0]
  return None

 matrix = []
 for type_id in range(1, 65):
  rel_off = word(JUMP_TABLE + type_id * 4)
  target = BASE_PC + rel_off
  found_class = None
  for pc in range(target, target + 48, 4):
   instr = word(pc)
   if (instr & 0xfffff000) == 0xe59f3000:
    imm = instr & 0xfff
    lit_w = word(pc + 8 + imm)
    slot = (BASE_PIC + s(lit_w)) & 0xffffffff
    slot_w = word(slot)
    if slot_w:
     found_class = get_class_name(raw, segs, slot_w)
     if found_class: break
  if not found_class:
   raise ValueError(f'failed to decode class for type {type_id}')
  matrix.append({'type_id': type_id, 'class_name': found_class, 'jump_target': f'0x{target:08x}'})

 return {
  'schema': 1,
  'elf_sha256': SHA,
  'function': '_Z25classForDynamicObjectTypei',
  'function_address': f'0x{FUNC_ADDR:08x}',
  'jump_table_address': f'0x{JUMP_TABLE:08x}',
  'total_types': len(matrix),
  'types': matrix,
  'claim': 'full 1..64 DynamicObjectType enum-to-class matrix verified against native classForDynamicObjectType jump table'
 }

def main():
 ap = argparse.ArgumentParser()
 ap.add_argument('elf', type=Path)
 ap.add_argument('--check', action='store_true')
 ap.add_argument('--output', type=Path, default=Path('reconstruction/reverse-v3/native/dynamicobject_type_matrix.json'))
 a = ap.parse_args()
 r = recover(a.elf)
 text = json.dumps(r, indent=2, sort_keys=True) + '\n'
 if a.check:
  if a.output.read_text() != text: raise SystemExit('stale dynamicobject_type_matrix.json')
 else:
  a.output.write_text(text)
 print(f"dynamicobject-type-matrix: types={len(r['types'])} PASS")

if __name__ == '__main__': main()
