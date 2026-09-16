"""Assemble offline original records with production block decoder.
Output is an inspection snapshot, not a replacement game world/renderer.
"""
import argparse,gzip,hashlib,json,plistlib,re,subprocess
from pathlib import Path
from export_server_world import verify_archive

BLOCK_KEY = re.compile(r'^(-?\d+)_(-?\d+)$')


def parse_block_coordinate(key):
 try:
  text=key.decode('ascii')
 except UnicodeDecodeError as exc:
  raise ValueError('physical block key is not ASCII coordinate text') from exc
 match=BLOCK_KEY.fullmatch(text)
 if not match:raise ValueError(f'invalid physical block coordinate key: {key.hex()}')
 return {'x':int(match.group(1)),'y':int(match.group(2))}

def describe(value):
 if isinstance(value,dict):return {str(k):describe(v) for k,v in value.items()}
 if isinstance(value,(list,tuple)):return [describe(v) for v in value]
 if isinstance(value,bytes):return {'binary_hex':value.hex()}
 if hasattr(value,'isoformat'):return {'date':value.isoformat()}
 return value

def assemble(archive,decoder,destination):
 archive=Path(archive);destination=Path(destination);m=verify_archive(archive)
 destination.mkdir(parents=True,exist_ok=False);(destination/'blocks').mkdir();groups=[]
 index=['key_hex\tx\ty\tfile\traw_sha256\tbytes']
 coordinates=set()
 for env in m['environments']:
  for db in env['databases']:
   rows=[]
   for record in db['records']:
    path=archive/'blobs'/record['sha256'];raw=path.read_bytes();row=dict(record)
    if env['path']=='world_db' and bytes.fromhex(db['name_hex'])==b'blocks':
     coordinate=parse_block_coordinate(bytes.fromhex(record['key_hex']))
     coord_key=(coordinate['x'],coordinate['y'])
     if coord_key in coordinates:raise ValueError(f'duplicate physical block coordinate: {coord_key}')
     coordinates.add(coord_key)
     target=destination/'blocks'/(f"{coordinate['x']}_{coordinate['y']}.raw")
     subprocess.run([str(decoder),str(path),str(target)],check=True)
     if target.read_bytes()!=gzip.decompress(raw):raise ValueError('client byte mismatch')
     row['decoded_file']=str(target.relative_to(destination))
     row['coordinate']=coordinate
     index.append('\t'.join([record['key_hex'],str(coordinate['x']),str(coordinate['y']),
                               str(row['decoded_file']),hashlib.sha256(target.read_bytes()).hexdigest(),
                               str(target.stat().st_size)]))
    else:
     decoded=gzip.decompress(raw) if raw.startswith(b'\x1f\x8b') else raw
     try:row['plist']=describe(plistlib.loads(decoded))
     except (ValueError,plistlib.InvalidFileException):row['opaque']=True
    rows.append(row)
   groups.append({'environment':env['path'],'database_hex':db['name_hex'],'records':rows})
 result={'scope':'offline inspection; no runtime object construction','groups':groups,'original_files':m['files']}
 (destination/'blocks'/'index.tsv').write_text('\n'.join(index)+'\n')
 (destination/'snapshot.json').write_text(json.dumps(result,indent=2));return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('decoder',type=Path);p.add_argument('destination',type=Path);a=p.parse_args()
 r=assemble(a.archive,a.decoder,a.destination)
 print(json.dumps({'groups':len(r['groups']),'records':sum(len(g['records']) for g in r['groups'])}))
