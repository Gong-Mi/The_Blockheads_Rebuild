"""Synthetic full-record assembly test against the compiled client decoder."""
import gzip,json,plistlib,sys,tempfile,unittest
from pathlib import Path
import lmdb
from export_server_world import export_world
from assemble_server_snapshot import assemble
DECODER=Path(sys.argv.pop(1)).resolve()
class AssemblyTest(unittest.TestCase):
 def test_all_domains_and_unknown_record_survive(self):
  with tempfile.TemporaryDirectory() as t:
   b=Path(t);source=b/'source';source.mkdir()
   e=lmdb.open(str(source/'world_db'),max_dbs=8)
   raw=bytes(range(256))*256+b'\x01\x78\x56\x34\x12'
   domains={b'blocks':{b'0_0':gzip.compress(raw)},b'main':{b'worldv2':plistlib.dumps({'seed':7,'binary':b'\x00\xff'})},b'dw':{b'0_0/1':plistlib.dumps({'dynamicObjects':[{'uniqueID':42}]})},b'unknown':{b'\xff':b'opaque-value'}}
   for name,records in domains.items():
    db=e.open_db(name)
    with e.begin(write=True,db=db) as txn:
     for k,v in records.items():txn.put(k,v)
   e.close();export_world(source,b/'archive');result=assemble(b/'archive',DECODER,b/'snapshot')
   groups={bytes.fromhex(g['database_hex']):g for g in result['groups']}
   self.assertEqual(set(groups),set(domains))
   self.assertEqual(sum(len(g['records']) for g in groups.values()),4)
   record=groups[b'blocks']['records'][0];self.assertEqual((b/'snapshot'/record['decoded_file']).read_bytes(),raw)
   self.assertEqual(groups[b'main']['records'][0]['plist']['binary'],{'binary_hex':'00ff'})
   self.assertEqual(groups[b'dw']['records'][0]['plist']['dynamicObjects'][0]['uniqueID'],42)
   self.assertTrue(groups[b'unknown']['records'][0]['opaque'])
   with self.assertRaises(FileExistsError):assemble(b/'archive',DECODER,b/'snapshot')
if __name__=='__main__':unittest.main()
