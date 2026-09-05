import tempfile,unittest,json
from pathlib import Path
import lmdb
from export_server_world import export_world,verify_archive,restore_world
class ArchiveTest(unittest.TestCase):
 def test_preserve_binary_keys_empty_database_unknown_files_and_detect_corruption(self):
  with tempfile.TemporaryDirectory() as temp:
   base=Path(temp);source=base/'source';source.mkdir();(source/'opaque').write_bytes(b'\x00\xffunknown')
   env=lmdb.open(str(source/'world_db'),max_dbs=4)
   db=env.open_db(b'blocks');env.open_db(b'empty')
   with env.begin(write=True,db=db) as t:t.put(b'\x00\xff',b'payload')
   env.close();dest=base/'archive';m=export_world(source,dest)
   dbs={bytes.fromhex(d['name_hex']):d for d in m['environments'][0]['databases']}
   self.assertEqual(dbs[b'empty']['records'],[])
   row=dbs[b'blocks']['records'][0];self.assertEqual(bytes.fromhex(row['key_hex']),b'\x00\xff')
   self.assertEqual((dest/'blobs'/row['sha256']).read_bytes(),b'payload')
   restored=base/'restored';restore_world(dest,restored)
   for file in source.rglob('*'):
    if file.is_file():self.assertEqual(file.read_bytes(),(restored/file.relative_to(source)).read_bytes())
   with self.assertRaises(FileExistsError):restore_world(dest,restored)
   with self.assertRaises(FileExistsError):export_world(source,dest)
   with self.assertRaises(ValueError):export_world(source,source/'nested')
   (dest/'blobs'/row['sha256']).write_bytes(b'bad')
   with self.assertRaises(ValueError):verify_archive(dest)
 def test_unsafe_paths_rejected_before_output_creation(self):
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);source=base/'src';source.mkdir();(source/'file').write_bytes(b'x')
   archive=base/'archive';m=export_world(source,archive)
   for bad in ['../escape','/absolute']:
    m['files'][0]['path']=bad;(archive/'manifest.json').write_text(json.dumps(m))
    with self.assertRaises(ValueError):restore_world(archive,base/'restored')
    self.assertFalse((base/'restored').exists())
if __name__=='__main__':unittest.main()
