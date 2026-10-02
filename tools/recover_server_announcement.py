"""Verify bounded announcement-builder evidence, not entire BHServer callback."""
import argparse,hashlib,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=argparse.ArgumentParser();p.add_argument('elf',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
sha=hashlib.sha256(a.elf.read_bytes()).hexdigest()
assert sha=='b1534f723ac524e1ed283e1cad01bb8cdfb6caf03c98642e25730266f0cfd5ea'
with a.elf.open('rb') as f:
 e=ELFFile(f)
 def read(va,n):f.seek(next(e.address_offsets(va)));return f.read(n)
 def text(va):return read(va,256).split(b'\0')[0].decode()
 base=0xbe7658
 expected={0xbd0:'dataWithBytes:length:',0xc80:'appendBytes:length:',0xe0:'dictionary',0x630:'ownerName',0x7f0:'setObject:forKey:',0x860:'sendNetworkData:toPeers:reliable:'}
 selectors={hex(offset):text(struct.unpack('<Q',read(base+offset,8))[0]) for offset in expected}
 assert all(selectors[hex(k)]==v for k,v in expected.items())
 cs=Cs(CS_ARCH_X86,CS_MODE_64)
 stores=[]
 for va,operand in [(0x57199c,'byte ptr [rbp - 0x29], 0x23'),(0x571a0e,'byte ptr [rbp - 0x39], 0x26')]:
  ins=next(cs.disasm(read(va,15),va));assert ins.mnemonic=='mov' and ins.op_str==operand
  stores.append({'address':hex(va),'bytes':bytes(ins.bytes).hex(),'instruction':ins.mnemonic+' '+ins.op_str})
 constants={}
 for va,name in [(0xbe5260,'ownerName'),(0xbe51a0,'worldID')]:
  constants[hex(va)]=text(struct.unpack('<Q',read(va+8,8))[0]);assert constants[hex(va)]==name
 result={'sha256':sha,'owner':'_i_BHServer__match_player_didChangeState_','owner_address':'0x5717f0','scope':'header stores and selector/constant identities; not complete callback semantics','header_stores':stores,'selector_base':hex(base),'selectors':selectors,'constants':constants,'local_branch':'state==1 path after non-nil player and superclass callback; containsObject gate','wire_observation':'ENet app payload starts 23 26, then XML plist with worldID; optional ownerName source path also present'}
a.output.write_text(json.dumps(result,indent=2));print('PASS bounded server announcement evidence')
