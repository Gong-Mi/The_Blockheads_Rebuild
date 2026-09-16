"""Characterize production decoder with ALL records of a stopped server save.
Requires lmdb. Never opens a live environment: caller must stop the server.
Original payloads stay outside git. Reports are complete, not sampled.
"""
import argparse,gzip,hashlib,json,subprocess,tempfile
from pathlib import Path
import lmdb
p=argparse.ArgumentParser();p.add_argument('world_db',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
repo=Path(__file__).resolve().parents[1];results=[]
e=lmdb.open(str(a.world_db),readonly=True,lock=False,max_dbs=8)
db=e.open_db(b'blocks',create=False)
with e.begin(db=db) as t: records=list(t.cursor())
e.close()
if not records:raise SystemExit('FAIL: no physical block records')
with tempfile.TemporaryDirectory(prefix='bh-client-') as tmp:
 root=Path(tmp)
 for opt in ['-O0','-O2']:
  exe=root/'decode';subprocess.run(['clang++','-std=c++17',opt,'-I'+str(repo/'app/src/main/cpp'),str(repo/'tools/decode_original_block.cpp'),str(repo/'app/src/main/cpp/original_save_format.cpp'),'-lz','-o',str(exe)],check=True)
  for key,value in records:
   raw=gzip.decompress(value)
   if len(raw)!=65541:raise AssertionError(('unexpected source size',key,len(raw)))
   inp=root/'in.gz';out=root/'out.bin';inp.write_bytes(value)
   subprocess.run([str(exe),str(inp),str(out)],check=True)
   if out.read_bytes()!=raw:raise AssertionError(('byte mismatch',key))
   rejects={}
   damaged=bytearray(value);damaged[-8]^=1
   for label,bad in [('empty',b''),('truncated',value[:-1]),('crc',bytes(damaged)),('short-payload',gzip.compress(raw[:-1])),('long-payload',gzip.compress(raw+b'\0'))]:
    inp.write_bytes(bad);r=subprocess.run([str(exe),str(inp),str(out)],capture_output=True)
    if r.returncode!=4:raise AssertionError((key,label,r.returncode))
    rejects[label]=True
   results.append({'optimization':opt,'key_hex':key.hex(),'gzip_sha256':hashlib.sha256(value).hexdigest(),'raw_sha256':hashlib.sha256(raw).hexdigest(),'byte_equal':True,'rejected':rejects})
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps({'records':len(records),'results':results},indent=2))
print(f'PASS: {len(records)} real records, O0/O2, full byte equality and five invalid inputs per record; {a.report}')
