"""Recover exact server Tile member metadata; not Android ABI equivalence."""
import argparse,hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
sha=hashlib.sha256(a.elf.read_bytes()).hexdigest()
if sha!='b1534f723ac524e1ed283e1cad01bb8cdfb6caf03c98642e25730266f0cfd5ea':raise SystemExit('wrong original server ELF')
with a.elf.open('rb') as f:
 dw=ELFFile(f).get_dwarf_info();die=dw.get_DIE_from_refaddr(0x41129)
 assert die.tag=='DW_TAG_structure_type' and die.attributes['DW_AT_name'].value==b'Tile'
 rows=[]
 for c in die.iter_children():
  if c.tag!='DW_TAG_member':continue
  attrs=c.attributes;t=c.get_DIE_from_attribute('DW_AT_type');chain=[]
  while t is not None:
   chain.append({'tag':t.tag,'name':t.attributes['DW_AT_name'].value.decode() if 'DW_AT_name' in t.attributes else None,'bytes':t.attributes['DW_AT_byte_size'].value if 'DW_AT_byte_size' in t.attributes else None})
   t=t.get_DIE_from_attribute('DW_AT_type') if 'DW_AT_type' in t.attributes else None
  rows.append({'name':attrs['DW_AT_name'].value.decode(),'offset':attrs['DW_AT_data_member_location'].value,'types':chain})
 result={'sha256':sha,'die':'0x41129','scope':'Linux server 1.7.1; Android 1.7.6 names require cross-check','bytes':die.attributes['DW_AT_byte_size'].value,'members':rows}
 assert result['bytes']==64 and len(rows)==26
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2));print('PASS: 26 members, Tile size 64, original ELF hash verified')
