#!/usr/bin/env python3
"""Pin four inventory-add IMPs; extract calls, branches, PIC selectors and ivars.
The disassembly manifest is an audit aid, not an automatic semantic proof.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
ROOT = Path(__file__).resolve().parents[1]
METHODS = [(0xc5f904, 0xc5f960, 'addItemToInventory:'),
           (0xc5f960, 0xc5f9d8, 'addItemToInventory:flash:'),
           (0xc5f9d8, 0xc5fa6c, 'addItemToInventory:flash:disableWarpCheck:'),
           (0xc5fa6c, 0xc61c00, 'addItemToInventory:flash:disableWarpCheck:forceSlotIndex:')]
POOLS = [(0xc5f954,0xc5f960),(0xc5f9cc,0xc5f9d8),(0xc5fa60,0xc5fa6c),
         (0xc60a50,0xc60a74),(0xc60c9c,0xc60cb4),(0xc60fb4,0xc60fd0),
         (0xc6168c,0xc61694),(0xc61bb8,0xc61c00)]

def require(x, message):
    if not x: raise ValueError(message)

def recover(path):
    blob = path.read_bytes()
    require(hashlib.sha256(blob).hexdigest() == SHA, 'ELF SHA mismatch')
    with path.open('rb') as f:
        elf = ELFFile(f)
        require(elf.elfclass == 32 and elf.little_endian, 'ARM32 LE required')
        segs = [(s['p_vaddr'],s.data()) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
        symbols = {s.name:s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols()}
        rels = {}
        for sec in elf.iter_sections():
            if sec['sh_type'] in ('SHT_REL','SHT_RELA'):
                tab = elf.get_section(sec['sh_link'])
                for r in sec.iter_relocations():
                    rels[r['r_offset']] = (r['r_info_type'], tab.get_symbol(r['r_info_sym']).name)
    def read(a,n):
        for base,data in segs:
            if base <= a and a+n <= base+len(data): return data[a-base:a-base+n]
        raise ValueError('not file-backed '+hex(a))
    def word(a): return struct.unpack('<I',read(a,4))[0]
    def string(a):
        out=bytearray()
        for _ in range(1024):
            b=read(a,1); a+=1
            if b==b'\0': return out.decode()
            out+=b
        raise ValueError('unterminated string')
    base=(0xc5fa7c+8+word(0xc60a50)) & 0xffffffff
    require(base==0x105faf4,'PIC base')
    selector_literals = {0xc5f958:'addItemToInventory:flash:',0xc5f9d0:'addItemToInventory:flash:disableWarpCheck:',0xc5fa64:'addItemToInventory:flash:disableWarpCheck:forceSlotIndex:',0xc60a58:'itemType',0xc60a60:'reportAchievementWithIdentifier:',0xc60a70:'addItemToFoundList:',0xc60c9c:'count',0xc60ca0:'objectAtIndex:',0xc60ca8:'dataB',0xc60cac:'dataA',0xc60cb0:'insertObject:atIndex:',0xc60fb4:'addObject:',0xc60fbc:'flashInventoryAtIndex:subIndex:forBlockhead:color:',0xc60fc0:'uiManager',0xc60fc4:'checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB:',0xc60fc8:'countByEnumeratingWithState:objects:count:',0xc60fcc:'subItems',0xc61bf8:'removeAllObjects',0xc61bfc:'addObjectsFromArray:'}
    selectors=[]
    for literal,expected in selector_literals.items():
        ref=(base+word(literal))&0xffffffff
        require(rels.get(ref)==(23,''),'selector relocation '+hex(ref))
        actual=string(word(ref)); require(actual==expected,'selector mismatch '+hex(literal))
        selectors.append(dict(literal=hex(literal),ref=hex(ref),selector=actual))
    require(rels[(base+word(0xc60a54))&0xffffffff]==(21,'objc_msgSend'),'dispatch import')
    ivars=[]
    for lit in [0xc60a64,0xc60a6c,0xc60ca4,0xc60fb8,0xc6168c]:
        slot=(base+word(lit))&0xffffffff
        symbol_addr=word(slot)
        names=[n for n,a in symbols.items() if a==symbol_addr and n.startswith('OBJC_IVAR_$_')]
        require(len(names)==1 and rels.get(slot)==(23,''),'ivar resolution '+hex(lit))
        ivars.append(dict(literal=hex(lit),slot=hex(slot),symbol=names[0],offset=hex(word(symbol_addr))))
    strings=[]
    for literal,expected in [(0xc60a5c,'grp.titanium'),(0xc60a68,'grp.mj.platinum')]:
        obj=(base+word(literal))&0xffffffff
        payload=string(word(obj+8)); require(payload==expected,'CFString payload')
        strings.append(dict(literal=hex(literal),object=hex(obj),payload=payload))
    # Decisive anchors independent of textual disassembler aliases.
    anchors={0xc5f918:0xe300c000,0xc5f974:0xe300e000,0xc5f9f0:0xe3e04000,
             0xc5fc70:0xe3500008,0xc5fd40:0xe3500063,0xc613c8:0xe0810000,
             0xc613cc:0xe3500063,0xc61ba4:0xe3e00000,0xc61bac:0xe51b0020}
    for a,w in anchors.items(): require(word(a)==w,'anchor '+hex(a))
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM); records=[]; lines=[]
    for start,end,name in METHODS:
        calls=[]; branches=[]; count=0; pool_count=0
        lines.append(f'\n# {name} [{start:#x}, {end:#x})')
        for a in range(start,end,4):
            if any(p<=a<q for p,q in POOLS):
                pool_count+=1; lines.append(f'{a:08x}: {word(a):08x} .word (literal pool)'); continue
            ins=list(md.disasm(read(a,4),a)); require(len(ins)==1,'decode '+hex(a))
            i=ins[0]; count+=1
            lines.append(f'{a:08x}: {word(a):08x} {i.mnemonic} {i.op_str}')
            if i.mnemonic in ('bl','blx'):
                calls.append(dict(address=hex(a),opcode=i.mnemonic,target=i.op_str))
            elif i.mnemonic.startswith('b') and i.mnemonic!='bic':
                branches.append(dict(address=hex(a),opcode=i.mnemonic,target=i.op_str))
        require((count+pool_count)*4==end-start,'word coverage')
        records.append(dict(selector=name,start=hex(start),end=hex(end),region_sha256=hashlib.sha256(read(start,end-start)).hexdigest(),instruction_count=count,pool_word_count=pool_count,calls=calls,branches=branches))
    helper_names={hex(a):[n for n,v in symbols.items() if v==a] for a in [0xc5eaa8]}
    result=dict(schema=1,elf_sha256=SHA,methods=records,selectors=selectors,ivars=ivars,cfstrings=strings,helper_symbols=helper_names,anchors={hex(k):hex(v) for k,v in anchors.items()},runtime_verified=False,integrated_into_game=False,semantics_status='hand-reviewed full body; external runtime/helper contracts required')
    return json.dumps(result,indent=2)+'\n','\n'.join(lines)+'\n'

def main():
    p=argparse.ArgumentParser(); p.add_argument('--elf',type=Path,required=True);p.add_argument('--check',action='store_true');a=p.parse_args()
    manifest,disasm=recover(a.elf)
    out=ROOT/'reconstruction/reverse-v3/native'
    for name,data in [('inventory_add.json',manifest),('disasm_inventory_add.txt',disasm)]:
        target=out/name
        if a.check: require(target.read_text()==data,'stale '+name)
        else: target.write_text(data)
    d=json.loads(manifest)
    print(json.dumps(dict(methods=len(d['methods']),instructions=sum(x['instruction_count'] for x in d['methods']),calls=sum(len(x['calls']) for x in d['methods']),ivars=d['ivars'],helper_symbols=d['helper_symbols'])))
if __name__=='__main__':main()
