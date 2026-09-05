"""Uncompressed default vs compressed negative control on synthetic loopback."""
from pathlib import Path
import subprocess,tempfile,re,plistlib,select
root=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as t:
 b=Path(t)
 for name in ['enet_loopback_fixture','probe_local_server']:
  subprocess.run(['cc','-Wall','-Wextra','-Werror',str(root/(name+'.c')),'-lenet','-o',str(b/name)],check=True)
 server=subprocess.Popen([str(b/'enet_loopback_fixture')],stdout=subprocess.PIPE,text=True)
 try:
  if not select.select([server.stdout],[],[],5)[0]:raise RuntimeError('server startup timeout')
  line=server.stdout.readline();assert line.startswith('READY '),line;port=line.split()[1]
  negative=subprocess.run([str(b/'probe_local_server'),port,'compression'],capture_output=True,text=True,timeout=8)
  assert negative.returncode==4,negative
  positive=subprocess.run([str(b/'probe_local_server'),port],capture_output=True,text=True,timeout=8)
  assert positive.returncode==0,positive
  match=re.search(r'packet_bytes=(\d+) hex=([0-9a-f]+)',positive.stdout);assert match,positive.stdout
  raw=bytes.fromhex(match[2]);assert len(raw)==int(match[1]);assert raw[:2]==b'\x23\x26'
  assert plistlib.loads(raw[2:])['worldID']=='synthetic-fixture'
  print('PASS synthetic ENet: compressed rejected; default CONNECT+payload received')
 finally:
  server.terminate();server.wait(timeout=5)
