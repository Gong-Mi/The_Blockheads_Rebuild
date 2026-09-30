"""Assemble offline original records with production block decoder.
Output is an inspection snapshot, not a replacement game world/renderer.
"""
import argparse,gzip,json,plistlib,subprocess
from pathlib import Path
from export_server_world import verify_archive

def describe(value):
 if isinstance(value,dict):return {str(k):describe(v) for k,v in value.items()}
 if isinstance(value,(list,tuple)):return [describe(v) for v in value]
 if isinstance(value,bytes):return {'binary_hex':value.hex()}
 if hasattr(value,'isoformat'):return {'date':value.isoformat()}
 return value

def assemble(archive,decoder,destination):
 archive=Path(archive);destination=Path(destination);m=verify_archive(archive)
 destination.mkdir(parents=True,exist_ok=False);(destination/'blocks').mkdir();groups=[]
 for env in m['environments']:
  for db in env['databases']:
   rows=[]
   for record in db['records']:
    path=archive/'blobs'/record['sha256'];raw=path.read_bytes();row=dict(record)
    if env['path']=='world_db' and bytes.fromhex(db['name_hex'])==b'blocks':
     target=destination/'blocks'/(record['key_hex']+'.raw')
     subprocess.run([str(decoder),str(path),str(target)],check=True)
     if target.read_bytes()!=gzip.decompress(raw):raise ValueError('client byte mismatch')
     row['decoded_file']=str(target.relative_to(destination))
    else:
     decoded=gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') else raw
     try:row['plist']=describe(plistlib.loads(decoded))
     except (ValueError,plistlib.InvalidFileException):row['opaque']=True
    rows.append(row)
   groups.append({'environment':env['path'],'database_hex':db['name_hex'],'records':rows})
 result={'scope':'offline inspection; no runtime object construction','groups':groups,'original_files':m['files']}
 (destination/'snapshot.json').write_text(json.dumps(result,indent=2));return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('decoder',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()
 r=assemble(a.archive,a.decoder,a.destination)
 print(json.dumps({'groups':len(r['groups']),'records':sum(len(g['records']) for g in r['groups'])}))
