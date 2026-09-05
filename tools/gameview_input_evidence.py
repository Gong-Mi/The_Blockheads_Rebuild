#!/usr/bin/env python3
"""Hash-gated input-method evidence; no runtime execution claim."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('elf',type=Path)
parser.add_argument('--check',action='store_true')
parser.add_argument('--output-dir',type=Path,default=ROOT/'reconstruction/reverse-v3/native')
args=parser.parse_args()
p=args.elf; raw=p.read_bytes()
def emit(name,text):
 out=args.output_dir/name
 if args.check:
  assert out.read_text()==text, 'stale '+name
 else:
  out.parent.mkdir(parents=True,exist_ok=True); out.write_text(text)
assert hashlib.sha256(raw).hexdigest()=='733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
with p.open('rb') as f:
 e=ELFFile(f); seg=[(s['p_vaddr'],s.data()) for s in e.iter_segments() if s['p_type']=='PT_LOAD']; syms={s['st_value']:s.name for sec in e.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols()}; rel={}
 for sec in e.iter_sections():
  if sec['sh_type'] in ('SHT_REL','SHT_RELA'):
   tab=e.get_section(sec['sh_link'])
   for r in sec.iter_relocations(): rel[r['r_offset']]=tab.get_symbol(r['r_info_sym']).name or 'R_ARM_RELATIVE'
 ex=e.get_section_by_name('.ARM.exidx'); exdata=ex.data(); exbase=ex['sh_addr']
def read(a,n):
 for b,d in seg:
  if b<=a and a+n<=b+len(d): return d[a-b:a-b+n]
 raise ValueError(hex(a))
def word(a): return struct.unpack('<I',read(a,4))[0]
def string(a):
 try: return read(a,160).split(b'\0')[0].decode()
 except Exception: return ''
base=(0x92d1dc+word(0x92de58))&0xffffffff
assert base==0x105faf4
fields=[]
for a in range(0x92dddc,0x92de5c,4):
 slot=(base+word(a))&0xffffffff
 try:
  v=word(slot); fields.append(dict(literal=hex(a),slot=hex(slot),value=hex(v),symbol=syms.get(v,''),string=string(v),relocation=rel.get(slot,''),offset=hex(word(v)) if syms.get(v,'').startswith('OBJC_IVAR') else None))
 except ValueError: pass
bounds=[]
for i in range(0,len(exdata),8):
 v=struct.unpack_from('<I',exdata,i)[0]&0x7fffffff
 if v&0x40000000:v-=0x80000000
 a=(exbase+i+v)&0xffffffff
 if 0x92d100<=a<=0x92df00 or 0x940f00<=a<=0x941020: bounds.append(hex(a))
methods=[]; md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
for name,start,end,pool in [('pinchGesture',0x92d1c4,0x92dddc,0x92de5c),('pinchZoomToScale',0x940f24,0x940f84,0x940f90),('shouldAllowDoubleTap',0x940f90,0x940fe8,0x940ff0)]:
 ins=[]
 for a in range(start,end,4):
  if name=='pinchGesture' and a in (0x92d4a0,0x92d998):continue
  x=list(md.disasm(read(a,4),a)); assert len(x)==1
  ins.append(x[0])
 methods.append(dict(name=name,start=hex(start),code_end=hex(end),pool_end=hex(pool),sha256=hashlib.sha256(read(start,pool-start)).hexdigest(),calls=[dict(address=hex(i.address),opcode=i.mnemonic,target=i.op_str,review='pending') for i in ins if i.mnemonic in ('bl','blx')],branches=[dict(address=hex(i.address),opcode=i.mnemonic,target=i.op_str,review='pending') for i in ins if i.mnemonic.startswith('b') and i.mnemonic not in ('bl','blx','bic')]))
 emit('gameview_input_'+name+'.asm',subprocess.check_output(['gobjdump','-d',f'--start-address={hex(start)}',f'--stop-address={hex(pool)}',str(p)],text=True))
rows=[r for r in (ROOT/'reconstruction/reverse-v3/native/libApplication_objc_methods.tsv').read_text().splitlines() if any(x in r for x in ('0x0092d1c4','0x00940f24','0x00940f90','0x0092de5c'))]
# Independently resolve the two small methods' PIC bases and exported ivars.
small=[]
for addpc,pool,literals in [(0x940f38,0x940f8c,[(0x940f84,'hasPinchVelocity'),(0x940f88,'pinchZooming')]),(0x940fa0,0x940fec,[(0x940fe8,'pinchScale')])]:
 b=(addpc+word(pool))&0xffffffff; assert b==base
 for literal,name in literals:
  slot=(b+word(literal))&0xffffffff; v=word(slot)
  assert syms[v]=='OBJC_IVAR_$_GameView.'+name and rel[slot]=='R_ARM_RELATIVE'
  small.append(dict(literal=hex(literal),slot=hex(slot),symbol=syms[v],offset=hex(word(v))))
assert all(hex(x) in bounds for x in (0x92d1c4,0x92de5c,0x940f24,0x940f90,0x940ff0))
assert len(rows)==4
# VFPExpandImm independent of disassembler text (imm8 from instruction bits).
def expand(w,double):
 v=((w>>16)&15)*16+(w&15); ebits=11 if double else 8; fbits=52 if double else 23
 b=(v>>6)&1; exponent=((1-b)<<(ebits-1))|(((1<<(ebits-3))-1)*b<<2)|((v>>4)&3)
 bits=((v>>7)<<(ebits+fbits))|(exponent<<fbits)|((v&15)<<(fbits-4))
 return struct.unpack('<d' if double else '<f',bits.to_bytes(8 if double else 4,'little'))[0]
assert expand(word(0x940fa0),True)==3.0
for a,value in [(0x92d800,.125),(0x92d804,.5),(0x92d95c,.125),(0x92d960,.5)]: assert expand(word(a),False)==value
assert expand(word(0x92da54),True)==.5
assert struct.unpack('<f',read(0x92d998,4))[0]==40960.0
assert struct.unpack('<f',read(0x92de20,4))[0]==-100.0 and struct.unpack('<f',read(0x92de24,4))[0]==100.0
assert word(0x92d4a0)==0 and word(0x92dc2c)==0xe30c2ccd and word(0x92dc30)==0xe3432ccc
# Every ObjC call has a separately hand-reviewed selector/receiver path.
objc={0x92d25c:('loadComplete','fresh self.world'),0x92d2bc:('uiManager','fresh self.world'),0x92d2cc:('currentTouchIsInAnyButtons','previous uiManager result'),0x92d318:('isSimulating','fresh self.world'),0x92d364:('allowsPanning','fresh self.world'),0x92d3c4:('setTranslatingToGoal:','fresh self.world; r2=0'),0x92d454:('startPinchOrPan','fresh self.world'),0x92d7fc:('takingPhoto','fresh self.world; fp-128 preserves scale'),0x92d8a0:('pinchScaleChanged','self; BEFORE pinching=true'),0x92d958:('takingPhoto','fresh self.world; fp-152 preserves scale'),0x92da08:('pinchScaleChanged','self; BEFORE cap and velocity gate'),0x92dd88:('updateTranslation:','self; r2/r3 copy pinchOffset plus conditional translationOffset')}
helpers={0x4d0480:'Vector2 constructor: lane stores',0x4bdaac:'Vector2 float pointer: identity',0x4d0368:'multiply: independent f32 lanes',0x4d03c0:'divide: independent f32 lanes, no reciprocal',0x4d04b4:'subtract: independent f32 lanes',0x4d0418:'add: independent f32 lanes',0x1c4214:'isnanf: velocity classification',0x1c4220:'__isfinitef: velocity classification'}
branch_meanings={0x92d268:'return if !loadComplete',0x92d2d8:'return if UI buttons',0x92d324:'return if simulating',0x92d370:'return if !allowsPanning',0x92d3d0:'state != 1',0x92d3f4:'scrolling skips start and translationOffset zero',0x92d720:'scale <= cap OR unordered skips cap',0x92d828:'saved scale >= floor OR unordered retains saved scale',0x92d8c8:'state != 2',0x92d984:'saved scale >= floor OR unordered retains saved scale',0x92da50:'scale > cap skips velocity write',0x92da7c:'scale < .5 skips velocity write (unordered passes)',0x92daa0:'NaN velocity skips write',0x92dabc:'velocity <= -100 OR unordered skips write',0x92dad8:'velocity >= 100 OR unordered skips write',0x92dafc:'finite velocity selects write',0x92db6c:'scale <= cap OR unordered selects offset recomputation',0x92dd0c:'!scrolling skips translationOffset addition',0x92dd98:'state == 3 clears pinching',0x92dda4:'state != 4 skips pinching clear'}
for c in methods[0]['calls']:
 a=int(c['address'],16)
 if a in objc:
  selector,receiver=objc[a]; assert selector in [x['string'] for x in fields]
  c.update(selector=selector,receiver=receiver,review='hand-reviewed PIC/register/spill route')
 else: c.update(binding=helpers[int(c['target'][1:],16)],review='complete numerical helper or explicit imported classification')
for b in methods[0]['branches']:
 a=int(b['address'],16)
 if b['opcode']=='b': meaning='unconditional join to '+b['target']
 else: meaning=branch_meanings[a]
 b.update(meaning=meaning,review='implemented')
assert len(methods[0]['calls'])==28 and len(methods[0]['branches'])==30
assert {int(b['address'],16) for b in methods[0]['branches'] if b['opcode']!='b'}==set(branch_meanings)
for m in methods:
 m.update(stage='implemented',call_count=len(m['calls']),branch_count=len(m['branches']))
 if m['name']=='shouldAllowDoubleTap':
  m['branches'][0]['review']='BX LR return; MOVGT implements ordered >3.0'
# Preserve complete directly used numerical bodies (symbol boundaries).
helper_regions=[(0x4bdaac,0x4bdac0),(0x4d0368,0x4d051c)]
# Decode ARM PLT veneers through relocation, not objdump labels.
def imm(w):
 v=w&255; rot=((w>>8)&15)*2
 return ((v>>rot)|(v<<(32-rot)))&0xffffffff if rot else v
for plt,name in [(0x1c281c,'objc_msgSend'),(0x1c4214,'isnanf'),(0x1c4220,'__isfinitef')]:
 a,b,c=[word(plt+4*k) for k in range(3)]
 assert a&0xfffff000==0xe28fc000 and b&0xfffff000==0xe28cc000 and c&0xfffff000==0xe5bcf000
 slot=(plt+8+imm(a)+imm(b)+(c&4095))&0xffffffff
 assert rel[slot]==name
assert read(0x4bdaac,20)==bytes.fromhex('04d04de200008de500009de504d08de21eff2fe1')
assert word(0x4d0518)==0xe8bd8800
helper_evidence=[]
for start,end in helper_regions:
 helper_evidence.append(dict(start=hex(start),end=hex(end),sha256=hashlib.sha256(read(start,end-start)).hexdigest()))
emit('gameview_input_helpers.asm',''.join(subprocess.check_output(['gobjdump','-d',f'--start-address={hex(a)}',f'--stop-address={hex(b)}',str(p)],text=True) for a,b in helper_regions))
result=dict(elf_sha256=hashlib.sha256(raw).hexdigest(),pic_base=hex(base),exidx_boundaries=bounds,objc_rows=rows,gesture_literal_chains=fields,small_method_fields=small,methods=methods,helper_regions=helper_evidence,complete_batch=True,game_integrated=False,original_runtime_differential=False,source='reconstruction/recovered/gameview_input.cpp',external_boundaries=['GameViewInputRuntime mandatory UI/World/self dispatch methods','FrameWorld loadComplete/isSimulating/takingPhoto','FrameRuntime pinchScaleChanged default recovered projection','platform isnanf/isfinitef classification; FP exception flags not modeled'])
emit('gameview_input_evidence.json',json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(methods=len(methods),gesture_calls=methods[0]['call_count'],gesture_branches=methods[0]['branch_count'],hash_verified=True,check=args.check)))
