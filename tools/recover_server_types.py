"""Hash-pinned server DWARF types. Never infer Android layout from x86 pointers."""
import argparse,hashlib,json
from collections import defaultdict
from pathlib import Path
from elftools.elf.elffile import ELFFile
SHA='b1534f723ac524e1ed283e1cad01bb8cdfb6caf03c98642e25730266f0cfd5ea'
class DefinitionConflict(ValueError):pass

def merge_definitions(name,definitions):
 first=definitions[0][0]
 for value,source in definitions:
  if value!=first:raise DefinitionConflict('conflicting definitions: '+name)
 return {**first,'sources':[source for value,source in definitions]}

def type_description(die,seen=None):
 if die is None:return None
 seen=set() if seen is None else set(seen)
 a=die.attributes;r={'tag':die.tag}
 for key,label in [('DW_AT_name','name'),('DW_AT_byte_size','bytes'),('DW_AT_encoding','encoding')]:
  if key in a:
   v=a[key].value;r[label]=v.decode() if isinstance(v,bytes) else v
 if die.offset in seen:return r
 seen.add(die.offset)
 if 'DW_AT_type' in a:r['target']=type_description(die.get_DIE_from_attribute('DW_AT_type'),seen)
 if die.tag=='DW_TAG_array_type':
  ranges=[]
  for child in die.iter_children():
   if child.tag!='DW_TAG_subrange_type':continue
   ca=child.attributes;lo=ca['DW_AT_lower_bound'].value if 'DW_AT_lower_bound' in ca else 0
   row={'lower':lo}
   if 'DW_AT_count' in ca:row['count']=ca['DW_AT_count'].value
   elif 'DW_AT_upper_bound' in ca:row['count']=ca['DW_AT_upper_bound'].value-lo+1
   ranges.append(row)
  r['subranges']=ranges
 return r

def recover(path):
 if hashlib.sha256(Path(path).read_bytes()).hexdigest()!=SHA:raise ValueError('SHA-256 mismatch')
 structs=defaultdict(list);enums=defaultdict(list)
 with Path(path).open('rb') as stream:
  dw=ELFFile(stream).get_dwarf_info()
  for cu in dw.iter_CUs():
   for d in cu.iter_DIEs():
    a=d.attributes
    if 'DW_AT_name' not in a or 'DW_AT_declaration' in a:continue
    name=a['DW_AT_name'].value.decode();source={'die_offset':d.offset,'cu_offset':cu.cu_offset}
    if d.tag=='DW_TAG_structure_type' and name in ('Tile','PhysicalBlock'):
     members=[]
     for c in d.iter_children():
      if c.tag!='DW_TAG_member':continue
      ca=c.attributes;members.append({'name':ca['DW_AT_name'].value.decode(),'offset':ca['DW_AT_data_member_location'].value,'type':type_description(c.get_DIE_from_attribute('DW_AT_type'))})
     structs[name].append(({'bytes':a['DW_AT_byte_size'].value,'members':members},source))
    elif d.tag=='DW_TAG_enumeration_type' and name:
     values=[{'name':c.attributes['DW_AT_name'].value.decode(),'value':c.attributes['DW_AT_const_value'].value} for c in d.iter_children() if c.tag=='DW_TAG_enumerator']
     enums[name].append(({'bytes':a['DW_AT_byte_size'].value,'values':values},source))
 structures={n:merge_definitions(n,v) for n,v in sorted(structs.items())};enumerations={n:merge_definitions(n,v) for n,v in sorted(enums.items())}
 return {'sha256':SHA,'scope':'Linux server 1.7.1 DWARF; no Android ABI equivalence claim','structures':structures,'enums':enumerations,'conflicts':[],'counts':{'definitions_merged':sum(len(v) for v in list(structs.values())+list(enums.values())),'structures':len(structures),'enums':len(enumerations)}}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('output',type=Path);a=p.parse_args();r=recover(a.elf);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(r,indent=2));print(r['counts'])
