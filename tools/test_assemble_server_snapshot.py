"""Synthetic full-record assembly test against the compiled client decoder."""
import gzip,json,plistlib,subprocess,sys,tempfile,unittest
from pathlib import Path
import lmdb
from export_server_world import export_world
from assemble_server_snapshot import assemble
DECODER=Path(sys.argv.pop(1)).resolve()
LOADER = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 and Path(sys.argv[1]).is_file() else None
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
   self.assertEqual(record['coordinate'],{'x':0,'y':0})
   index=(b/'snapshot'/'blocks'/'index.tsv').read_text().splitlines()
   self.assertEqual(index[0],'key_hex\tx\ty\tfile\traw_sha256\tbytes')
   self.assertIn('\t0\t0\tblocks/0_0.raw\t',index[1])
   self.assertEqual(groups[b'main']['records'][0]['plist']['binary'],{'binary_hex':'00ff'})
   dynamic=groups[b'dw']['records'][0]
   self.assertEqual(dynamic['plist']['dynamicObjects'][0]['uniqueID'],42)
   self.assertEqual(dynamic['coordinate'],{'x':0,'y':0})
   self.assertTrue(dynamic['decoded_file'].startswith('dynamic/'))
   dynamic_index=(b/'snapshot'/'dynamic'/'index.tsv').read_text().splitlines()
   self.assertEqual(dynamic_index[0],'key_hex\tx\ty\tfile\traw_sha256\tbytes')
   self.assertIn('\t0\t0\tdynamic/',dynamic_index[1])
   self.assertTrue(groups[b'unknown']['records'][0]['opaque'])
   if LOADER and LOADER.exists():
    r = subprocess.run([str(LOADER), str(b / 'snapshot'), '0', '0'], capture_output=True, text=True, check=True)
    self.assertIn('OK blockCount=1', r.stdout)
    self.assertIn('tile0_type=0', r.stdout)
    self.assertIn('field13=1', r.stdout)
    # Tampering with raw block payload must cause loader to reject with checksum mismatch
    raw_file = b / 'snapshot/blocks/0_0.raw'
    corrupt = bytearray(raw_file.read_bytes())
    corrupt[0] ^= 1
    raw_file.write_bytes(corrupt)
    r_bad = subprocess.run([str(LOADER), str(b / 'snapshot')], capture_output=True, text=True)
    self.assertEqual(r_bad.returncode, 2)
    self.assertIn('LOAD_FAILED: checksum mismatch', r_bad.stderr)
   with self.assertRaises(FileExistsError):assemble(b/'archive',DECODER,b/'snapshot')
 def test_coordinate_key_is_required_and_duplicate_coordinates_rejected(self):
  with tempfile.TemporaryDirectory() as t:
   b=Path(t);source=b/'source';source.mkdir();e=lmdb.open(str(source/'world_db'),max_dbs=8)
   db=e.open_db(b'blocks')
   raw=bytes(range(256))*256+b'\x01\x78\x56\x34\x12'
   with e.begin(write=True,db=db) as txn:
    txn.put(b'not-a-coordinate',gzip.compress(raw))
   e.close();export_world(source,b/'archive')
   with self.assertRaises(ValueError):assemble(b/'archive',DECODER,b/'bad-key')

   source=b/'source2';source.mkdir();e=lmdb.open(str(source/'world_db'),max_dbs=8);db=e.open_db(b'blocks')
   with e.begin(write=True,db=db) as txn:
    txn.put(b'0_0',gzip.compress(raw));txn.put(b'00_0',gzip.compress(raw))
   e.close();export_world(source,b/'archive2')
   with self.assertRaises(ValueError):assemble(b/'archive2',DECODER,b/'duplicate')
if __name__=='__main__':unittest.main()
