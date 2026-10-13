#!/usr/bin/env python3
"""Histogram the tile-record fields over real save data.

The static side says which offsets the drawing path reads; this says what those
offsets actually hold in a world. Input is the offline server-world archive
(`manifest.json` + `blobs/`), whose `blocks` database holds one gzip blob per chunk:
each decompresses to 256 x 64 bytes of tile records plus the 5 trailing PhysicalBlock
bytes the header describes.

Usage:
  python3 tools/histogram_save_tile_fields.py <server-world-archive> [--tsv OUT] [--json OUT] [--check]
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

TILE = 64
FIELDS = (0, 1, 3, 5, 6, 7, 8, 12)
INT16_WINDOWS = (5, 6, 7, 8)


def blocks_records(archive: Path) -> tuple[list[dict], str]:
    manifest = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    records = []
    for env in manifest["environments"]:
        for db in env["databases"]:
            if bytes.fromhex(db["name_hex"]).decode("latin1") != "blocks":
                continue
            records.extend(db["records"])
    return records, hashlib.sha256(
        (archive / "manifest.json").read_bytes()).hexdigest()


def tiles(archive: Path, records: list[dict]):
    for record in records:
        raw = gzip.decompress((archive / "blobs" / record["sha256"]).read_bytes())
        for offset in range(0, len(raw) - (TILE - 1), TILE):
            yield raw[offset:offset + TILE], raw


def build(archive: Path) -> dict:
    records, manifest_sha = blocks_records(archive)
    histograms: dict[int, collections.Counter] = {f: collections.Counter() for f in FIELDS}
    int16: dict[int, collections.Counter] = {w: collections.Counter() for w in INT16_WINDOWS}
    samples = 0
    decompressed_sizes: set[int] = set()
    nonzero8_states: collections.Counter = collections.Counter()
    for tile, raw in tiles(archive, records):
        decompressed_sizes.add(len(raw))
        samples += 1
        for field in FIELDS:
            histograms[field][tile[field]] += 1
        for window in INT16_WINDOWS:
            int16[window][struct.unpack_from("<h", tile, window)[0]] += 1
        if tile[8]:
            nonzero8_states[(tile[0], tile[1], tile[3], tile[7])] += 1

    return {
        "schema": 1,
        "archive_manifest_sha256": manifest_sha,
        "claim": ("field value domains of the 64-byte tile record measured on real save "
                  "data (offline server-world archive); what the drawing path reads, and "
                  "what the world actually stores, are different questions"),
        "counts": {
            "blocks_records": len(records),
            "tiles": samples,
            "decompressed_sizes": sorted(decompressed_sizes),
            "tiles_per_record": (sorted(decompressed_sizes)[0] - 5) // TILE
            if decompressed_sizes else 0,
        },
        "fields": {
            str(field): {
                "distinct": len(histograms[field]),
                "zero": histograms[field].get(0, 0),
                "top": [[value, count] for value, count in histograms[field].most_common(8)],
            }
            for field in FIELDS
        },
        "int16_windows": {
            str(window): {
                "distinct_nonzero": len([v for v in int16[window] if v]),
                "small_nonzero": len([v for v in int16[window] if v and -2000 <= v <= 2000]),
                "samples": sorted([v for v in int16[window] if v and -2000 <= v <= 2000])[:8],
            }
            for window in INT16_WINDOWS
        },
        "nonzero_offset8_states": [
            {"type": key[0], "back_wall": key[1], "contents": key[2],
             "temperature_scale_byte": key[3], "tiles": count}
            for key, count in nonzero8_states.most_common(10)
        ],
    }


def render_tsv(record: dict) -> str:
    lines = ["field\tdistinct\tzero\ttop_values"]
    for field, entry in record["fields"].items():
        top = ",".join(f"{v}:{c}" for v, c in entry["top"])
        lines.append(f"raw[{field}]\t{entry['distinct']}\t{entry['zero']}\t{top}")
    for window, entry in record["int16_windows"].items():
        lines.append(f"int16@raw[{window}]\t{entry['distinct_nonzero']}\t-\t"
                     f"small_nonzero={entry['small_nonzero']}")
    for state in record["nonzero_offset8_states"]:
        lines.append(f"offset8!=0\ttype={state['type']}\tbackWall={state['back_wall']}\t"
                     f"contents={state['contents']} scale={state['temperature_scale_byte']} "
                     f"tiles={state['tiles']}")
    return "\n".join(lines) + "\n"


def main() -> int:
    native = Path("reconstruction/reverse-v3/native")
    ap = argparse.ArgumentParser()
    ap.add_argument("archive", type=Path)
    ap.add_argument("--tsv", type=Path, default=native / "tile_record_save_data.tsv")
    ap.add_argument("--json", type=Path, default=native / "tile_record_save_data.json")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not (args.archive / "manifest.json").exists():
        print(f"skip: no manifest under {args.archive}")
        return 0
    record = build(args.archive)
    tsv = render_tsv(record)
    payload = json.dumps(record, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.tsv, tsv), (args.json, payload)):
            if not path.exists():
                print(f"CHECK FAILED: {path} is missing", file=sys.stderr)
                status = 1
            elif path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} is stale", file=sys.stderr)
                status = 1
        if status == 0:
            print(f"check ok: {record['counts']}")
        return status
    args.tsv.parent.mkdir(parents=True, exist_ok=True)
    args.tsv.write_text(tsv, encoding="utf-8")
    args.json.write_text(payload, encoding="utf-8")
    print(f"wrote {args.tsv.name} + {args.json.name}: {record['counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
