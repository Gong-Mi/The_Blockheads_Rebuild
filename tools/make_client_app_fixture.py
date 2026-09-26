#!/usr/bin/env python3
"""Build a synthetic assembled-snapshot directory for the client app skeleton.

The layout matches what tools/assemble_server_snapshot.py writes (blocks/index.tsv
+ decoded 65,541-byte PhysicalBlock payloads, dynamic/index.tsv + payloads), so
the skeleton can be exercised without the original server archive. Payload
plists are real XML plists (plistlib), i.e. the same serialization the dw
domain uses.

Usage:
  python3 tools/make_client_app_fixture.py <destination>

Nothing here claims to be original data: it is a labelled fixture whose dynamic
entries cover the identified / unidentified / out-of-range / opaque record
shapes the loader must report on.
"""
import argparse
import hashlib
import plistlib
import sys
from pathlib import Path

BLOCK_PAYLOAD_SIZE = 65541  # bh176::kPhysicalBlockPayloadSize


def write_block(root: Path, x: int, y: int, tile_type: int) -> str:
    payload = bytearray(BLOCK_PAYLOAD_SIZE)
    payload[0] = tile_type
    name = f"{x}_{y}.raw"
    (root / 'blocks' / name).write_bytes(bytes(payload))
    return name


def dynamic_index_row(key: str, x: int, y: int, name: str, data: bytes) -> str:
    return '\t'.join([
        key.encode().hex(), str(x), str(y), f"dynamic/{name}",
        hashlib.sha256(data).hexdigest(), str(len(data)),
    ])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('destination', type=Path)
    args = ap.parse_args()
    root = args.destination
    if root.exists():
        raise SystemExit(f'{root} already exists')
    (root / 'blocks').mkdir(parents=True)
    (root / 'dynamic').mkdir(parents=True)

    rows = ['key_hex\tx\ty\tfile\traw_sha256\tbytes']
    for i, (x, y, tile_type) in enumerate([(0, 0, 17), (1, 0, 29), (-1, -1, 3)]):
        name = write_block(root, x, y, tile_type)
        rows.append('\t'.join([
            f'{x}_{y}'.encode().hex(), str(x), str(y), f'blocks/{name}',
            'fixture-no-sha-check', str(BLOCK_PAYLOAD_SIZE),
        ]))
    (root / 'blocks' / 'index.tsv').write_text('\n'.join(rows) + '\n')

    dynamic_rows = ['key_hex\tx\ty\tfile\traw_sha256\tbytes']

    def add_record(key: str, x: int, y: int, name: str, data: bytes) -> None:
        (root / 'dynamic' / name).write_bytes(data)
        dynamic_rows.append(dynamic_index_row(key, x, y, name, data))

    # one AppleTree (type 1) and one FreeBlock (type 14) with the decoded base
    # loader keys, plus an Oxygen-like shared-objectType NPC (13, Dodo)
    add_record('0_0/1', 0, 0, 'record0.plist', plistlib.dumps({'dynamicObjects': [
        {'uniqueID': 42, 'pos_x': 3, 'pos_y': -7, 'floatPos': [1.5, 2.5], 'objectType': 1},
        {'uniqueID': 77, 'pos_x': 10, 'pos_y': 11, 'objectType': 14},
        {'uniqueID': 78, 'pos_x': 12, 'pos_y': 13, 'objectType': 13},
    ]}))
    # an entry with a missing type key, one with an out-of-range type, and one
    # that uses the assembly metadata override key
    add_record('1_0/1', 1, 0, 'record1.plist', plistlib.dumps({'dynamicObjects': [
        {'uniqueID': 5},
        {'uniqueID': 6, 'objectType': 65},
        {'uniqueID': 7, 'dynamicObjectType': 24, 'pos_x': 1, 'pos_y': 2},
    ]}))
    # a plist without a dynamicObjects array and a non-plist payload
    add_record('2_0/1', 2, 0, 'record2.plist',
               plistlib.dumps({'seed': 7, 'note': 'not a dynamic object record'}))
    add_record('3_0/1', 3, 0, 'record3.bin', b'\x00\x01\x02not-a-plist')

    (root / 'dynamic' / 'index.tsv').write_text('\n'.join(dynamic_rows) + '\n')
    print(f'wrote fixture snapshot: {root}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
