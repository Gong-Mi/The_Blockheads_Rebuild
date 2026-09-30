"""Lossless offline record archive, NOT a replacement game save format.
Caller must stop the server. Original keys/values are never normalized.
"""
import argparse,hashlib,json
from pathlib import Path
import lmdb

def digest(data):return hashlib.sha256(data).hexdigest()
def export_world(source,destination):
 source=Path(source).resolve();destination=Path(destination).resolve()
 if destination==source or source in destination.parents:raise ValueError('output must be outside save')
 destination.mkdir(parents=True,exist_ok=False)
 blobdir=destination/'blobs';blobdir.mkdir()
 def store(data):
  sha=digest(data);path=blobdir/sha
  if not path.exists():path.write_bytes(data)
  return {'sha256':sha,'bytes':len(data)}
 manifest={'schema':1,'scope':'offline lossless archive, not gameplay integration','files':[],'environments':[]}
 for path in sorted(source.rglob('*')):
  if path.is_symlink():raise ValueError('symlink in source')
  if path.is_file():manifest['files'].append({'path':str(path.relative_to(source)),**store(path.read_bytes())})
 for path in sorted(source.rglob('data.mdb')):
  env=lmdb.open(str(path.parent),readonly=True,lock=False,max_dbs=128)
  try:
   with env.begin() as txn: names=[key for key,value in txn.cursor()]
   databases=[]
   for name in names:
    db=env.open_db(name,create=False)
    with env.begin(db=db) as txn:
     rows=[{'key_hex':key.hex(),**store(value)} for key,value in txn.cursor()]
    databases.append({'name_hex':name.hex(),'records':rows})
   manifest['environments'].append({'path':str(path.parent.relative_to(source)),'databases':databases})
  finally:env.close()
 (destination/'manifest.json').write_text(json.dumps(manifest,indent=2))
 verify_archive(destination)
 return manifest

def verify_archive(destination):
 destination=Path(destination);m=json.loads((destination/'manifest.json').read_text())
 entries=list(m['files'])
 for e in m['environments']:
  for db in e['databases']:entries.extend(db['records'])
 for item in entries:
  sha=item['sha256']
  if len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha):raise ValueError('invalid hash')
  data=(destination/'blobs'/sha).read_bytes()
  if len(data)!=item['bytes'] or digest(data)!=sha:raise ValueError('blob verification failed')
 return m

def restore_world(archive,destination):
 archive=Path(archive);destination=Path(destination).resolve();m=verify_archive(archive)
 # Validate every path before creating output; archives may be untrusted.
 for item in m['files']:
  rel=Path(item['path'])
  if rel.is_absolute() or '..' in rel.parts or not rel.parts:raise ValueError('unsafe archive path')
 destination.mkdir(parents=True,exist_ok=False)
 for item in m['files']:
  out=destination/item['path'];out.parent.mkdir(parents=True,exist_ok=True)
  out.write_bytes((archive/'blobs'/item['sha256']).read_bytes())
  if digest(out.read_bytes())!=item['sha256']:raise ValueError('restore hash mismatch')
 return m

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('destination');a=p.parse_args()
 m=export_world(a.source,a.destination)
 print(json.dumps({'files':len(m['files']),'environments':len(m['environments']),'records':sum(len(d['records']) for e in m['environments'] for d in e['databases'])}))
