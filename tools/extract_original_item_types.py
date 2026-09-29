#!/usr/bin/env python3
"""Join numeric client evidence, third-party labels and server171 DWARF symbols.

imageTypeForItemType feeds TileMap (32x32), NOT the Items (32x16) sprite atlas.
All names retain their provenance. Source hashes establish reproducibility, not
Android semantic equivalence. No GPU VoxelType numbers are used as TileType.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import plistlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
OUTPUT = NATIVE / 'original_item_types.tsv'
SOURCES = {
    NATIVE / 'reference_itemtype_enum.txt': '77bf858c6a91cd5af8a62357e036654b066304728af8c7add8c9ae97db933436',
    NATIVE / 'server171_itemtype_enum.txt': '2d0d9cc89b76b84692429f88ddf59bf4b6abfbff51cd9dfd9555bdd00f308b11',
    NATIVE / 'original_item_image_map.tsv': 'd41d3959b1ccf7784c532b7fdb81bd55b0a543156973dcbfd1ac0710e3adf6fe',
    NATIVE / 'original_tile_item_map.tsv': '078076f6c69681869288b8e0952b4787eb696afcb029b6ace2a1ce801e477b42',
    ROOT / 'assets/defaultPrices': 'e7df00e94537f8c51559a8d2a8c1f1b3dd566b09bc38a7240f2acd67f0a344c5',
}
FIELDS = ['item_type', 'item_type_hex', 'reference_name', 'server171_symbol',
          'tile_image_a0', 'tile_col_a0', 'tile_row_a0',
          'tile_image_a1', 'tile_col_a1', 'tile_row_a1',
          'atlas_domain', 'price', 'old_price', 'sources']


def load_enum(path):
    values, names = {}, set()
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = re.fullmatch(r'(\w+) = (\d+)', line)
        if not match:
            raise ValueError(f'invalid enum row: {path}: {line}')
        name, value = match[1], int(match[2])
        if value in values or name in names:
            raise ValueError(f'duplicate enum: {path}: {line}')
        values[value] = name
        names.add(name)
    return values


def render_tsv(fields, rows):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=fields, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def build_table():
    for path, expected in SOURCES.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'source changed; review original evidence before accepting: {path}')
    names = load_enum(NATIVE / 'reference_itemtype_enum.txt')
    server = load_enum(NATIVE / 'server171_itemtype_enum.txt')
    sentinels = {344: 'ITEM_SPRITE_ITEM_COUNT', 1106: 'ITEM_MAX'}
    if {i: name for i, name in server.items() if i not in names} != sentinels:
        raise ValueError('unexpected server/client-reference domain difference')
    if set(names) != set(range(344)) | set(range(1024, 1106)):
        raise ValueError('incomplete reference domain')
    image_rows = list(csv.DictReader(io.StringIO((NATIVE / 'original_item_image_map.tsv').read_text()), delimiter='\t'))
    images = {int(row['item_type']): row for row in image_rows}
    if len(images) != len(image_rows) or set(images) != {58, 168, 174} | set(range(1024, 1106)):
        raise ValueError('duplicate/missing image switch entries')
    prices = plistlib.loads((ROOT / 'assets/defaultPrices').read_bytes())
    if len(prices) != 266 or not {int(k) for k in prices} <= names.keys():
        raise ValueError('unexpected price domain')
    for k, entry in prices.items():
        if str(entry['id']) != k:
            raise ValueError('price key/id mismatch')
    sources = {i: ['reference-label', 'server171-dwarf-symbol'] for i in names}
    for row in csv.DictReader(io.StringIO((NATIVE / 'original_tile_item_map.tsv').read_text()), delimiter='\t'):
        if row['resolution'] != 'direct':
            continue
        item_type = int(row['item_type'])
        if item_type not in names:
            raise ValueError('direct tile target outside reference domain')
        # Keep the original numeric TileType; never a GUI project's VoxelType.
        sources[item_type].append('client-tile-type:' + row['tile_type'])
        if row['image_dataA0'] and item_type in images:
            for field in ('image_dataA0', 'col_dataA0', 'row_dataA0'):
                if row[field] != images[item_type][field]:
                    raise ValueError(f'tile/image numeric contradiction: {item_type}/{field}')
    rows = []
    for i, name in sorted(names.items()):
        row = dict(item_type=str(i), item_type_hex=f'0x{i:03X}', reference_name=name,
                   server171_symbol=server[i], atlas_domain='TileMap:32x32',
                   price='', old_price='')
        for variant in (0, 1):
            image = int(images[i][f'image_dataA{variant}']) if i in images else 32
            col, line = image % 32, image // 32
            if not 0 <= image < 1024:
                raise ValueError('TileMap image outside atlas')
            if i in images and (int(images[i][f'col_dataA{variant}']), int(images[i][f'row_dataA{variant}'])) != (col, line):
                raise ValueError('image/cell contradiction')
            row.update({f'tile_image_a{variant}': str(image), f'tile_col_a{variant}': str(col), f'tile_row_a{variant}': str(line)})
        sources[i].append('client-tile-image@' + images[i]['case_target'] if i in images
                          else 'client-tile-image-default@0x004d769c')
        if str(i) in prices:
            row.update(price=prices[str(i)]['price'], old_price=prices[str(i)]['old_price'])
            sources[i].append('client-defaultPrices-id')
        row['sources'] = ';'.join(sources[i])
        rows.append(row)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify committed output without writing')
    args = parser.parse_args(argv)
    try:
        text = render_tsv(FIELDS, build_table())
        if args.check:
            if OUTPUT.read_text() != text:
                raise ValueError('original_item_types.tsv needs regeneration')
        else:
            OUTPUT.write_text(text)
    except (ValueError, OSError) as error:
        print('item-types: FAIL', error)
        return 1
    print('item-types: PASS (426 reference rows; server171 symbols; client TileMap numeric evidence)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
