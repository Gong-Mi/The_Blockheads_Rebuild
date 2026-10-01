#!/usr/bin/env python3
"""Extract the sound registry: the `grp.*` multi-sound keys and the audio file names.

Where this comes from. The string literals of this build are merged into one cstring blob;
`{u32 length, u32 pointer}` descriptors point into it (the same descriptor shape the audio
coverage work already recorded). Reading the blob in order gives, interleaved:

    dig.wav  grp.lime  grp.mine  grp.basalt  place.wav  grp.decorator  razor.wav
    grp.baby_shark  grp.campfire  ...  craftWorkbench.wav  sword.wav  punch.wav  ...

Two token classes come out of that: `grp.<name>` keys (the MJMultiSound group registry, the
keys `externalMultiSoundWithKey:` / `multiSoundWithSounds:` take) and audio file names.

What this proves and what it does not:
  * PROVES: these tokens exist as literals in the binary, they are bounded by a descriptor
    (length/pointer), and they are laid out in that order.
  * DOES NOT PROVE: which files a `grp.*` group contains. Blob adjacency is emission order
    (the compiler's concatenation of the string literals), which is a strong hint about
    source order and nothing more. Group membership needs the code that passes the key to
    the sound API, and the literal-to-code channel is still unresolved for this build
    (cstring literals are not referenced by absolute address - see AUDIO_CALL_SITES).

Usage:
  python3 tools/extract_sound_group_keys.py [--elf PATH] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
NATIVE = Path("reconstruction/reverse-v3/native")
AUDIO_ASSETS_TSV = NATIVE / "audio_asset_coverage.tsv"
AUDIO_EXT = (".wav", ".mp3", ".caf", ".aif", ".aiff")
GROUP_PREFIX = "grp."
# descriptor shape seen in this build: {u32 length, u32 pointer}, pointer into __cstring
MAX_BLOB = 1 << 20


def sections(elf: bytes) -> list[dict]:
    shoff = struct.unpack_from("<I", elf, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", elf, 46)
    out = []
    for i in range(shnum):
        f = struct.unpack_from("<10I", elf, shoff + i * shentsize)
        out.append({"index": i, "nameoff": f[0], "type": f[1], "addr": f[3],
                    "off": f[4], "size": f[5]})
    shstr = next(s["off"] for s in out if s["index"] == shstrndx)
    for sec in out:
        end = elf.index(b"\0", shstr + sec["nameoff"])
        sec["name"] = elf[shstr + sec["nameoff"]:end].decode("latin1")
    return out


def section_of(secs: list[dict], va: int) -> dict | None:
    return next((s for s in secs if s["off"] <= va < s["off"] + s["size"]), None)


def shipped_names() -> set[str]:
    names: set[str] = set()
    if not AUDIO_ASSETS_TSV.exists():
        return names
    with AUDIO_ASSETS_TSV.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            for key in ("name", "file", "asset", "path"):
                val = (row.get(key) or "").strip()
                if val.lower().endswith(AUDIO_EXT):
                    names.add(val.rsplit("/", 1)[-1])
    return names


def find_descriptors(elf: bytes, secs: list[dict]) -> list[dict]:
    """Every {u32 len, u32 ptr} whose ptr lands in a cstring section and whose run holds
    NUL-terminated tokens. length is treated as the byte length of the referenced run."""
    descs = []
    for off in range(0, len(elf) - 8, 4):
        length, ptr = struct.unpack_from("<II", elf, off)
        if not 8 <= length <= MAX_BLOB or not 0 < ptr < len(elf):
            continue
        sec = section_of(secs, ptr)
        if sec is None or "cstring" not in sec["name"]:
            continue
        end = ptr + length
        if end > len(elf):
            continue
        blob = elf[ptr:end]
        if b"\0" not in blob:
            continue
        tokens = blob.split(b"\0")
        printable = [t for t in tokens if t and all(32 <= c < 127 for c in t)]
        if len(printable) < 4:
            continue
        descs.append({"descriptor_va": off, "length": length, "pointer": ptr,
                      "token_count": len(printable), "tokens": printable})
    return descs


def classify(descs: list[dict], shipped: set[str]) -> dict:
    keys: dict[str, dict] = {}
    audio: dict[str, dict] = {}
    other_unseen: list[str] = []
    for d in descs:
        for idx, raw in enumerate(d["tokens"]):
            token = raw.decode("latin1")
            nxt = d["tokens"][idx + 1].decode("latin1") if idx + 1 < len(d["tokens"]) else None
            if token.startswith(GROUP_PREFIX) and len(token) > len(GROUP_PREFIX):
                keys.setdefault(token, {"descriptor_va": f"0x{d['descriptor_va']:x}",
                                        "next_token": nxt})
            elif token.lower().endswith(AUDIO_EXT):
                audio.setdefault(token, {"descriptor_va": f"0x{d['descriptor_va']:x}",
                                         "shipped": token in shipped})
    return {"group_keys": keys, "audio_names": audio, "other_unseen": other_unseen}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    ap.add_argument("--json", type=Path, default=NATIVE / "sound_group_keys.json")
    ap.add_argument("--tsv", type=Path, default=NATIVE / "sound_group_keys.tsv")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not args.elf.exists():
        print(f"skip: no ELF at {args.elf}")
        return 0
    elf = args.elf.read_bytes()
    secs = sections(elf)
    shipped = shipped_names()
    descs = find_descriptors(elf, secs)
    cls = classify(descs, shipped)
    keys, audio = cls["group_keys"], cls["audio_names"]
    # A short key that is a strict prefix of another key is a fragment, not a registry
    # entry: this build's string blob holds literal pieces used in key construction
    # (grp.magn / grp.magnet, grp.baby_ / grp.baby_shark). Classify mechanically rather
    # than eyeballing, so the count moves if the data moves.
    key_names = list(keys)
    fragments = {k: sorted(n for n in key_names if n != k and n.startswith(k))
                 for k in key_names}
    fragments = {k: v for k, v in fragments.items() if v}
    complete = [k for k in key_names if k not in fragments]
    payload = {
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "group_key_complete_count": len(complete),
        "group_key_fragment_count": len(fragments),
        "group_key_fragments": fragments,
        "format_string_audio_names": sorted(k for k in audio if "%" in k),
        "descriptor_count": len(descs),
        "group_key_count": len(keys),
        "group_key_prefix_caveat": ("being a strict prefix of another key is a mechanical "
                                    "fact, not proof of being a fragment: grp.ruby is a "
                                    "prefix of grp.ruby_chandelier and still looks like a "
                                    "real tier key. Only grp.magn / grp.baby_ style entries "
                                    "that cannot stand alone are fragments."),
        "audio_name_count": len(audio),
        "audio_name_shipped_count": sum(1 for v in audio.values() if v["shipped"]),
        "audio_names_not_shipped": sorted(k for k, v in audio.items() if not v["shipped"]),
        "group_keys": dict(sorted(keys.items())),
        "audio_names": dict(sorted(audio.items())),
        "boundary": ("tokens are literals in a descriptor-bounded cstring run; blob order is "
                     "emission order, not group membership. Membership needs the call site, "
                     "which the literal channel does not currently provide."),
    }
    rows = ["kind\ttoken\tdescriptor_va\textra"]
    for k, v in sorted(keys.items()):
        rows.append(f"group_key\t{k}\t{v['descriptor_va']}\tnext={v['next_token']}")
    for k, v in sorted(audio.items()):
        rows.append(f"audio_name\t{k}\t{v['descriptor_va']}\tshipped={v['shipped']}")
    tsv = "\n".join(rows) + "\n"
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        status = 0
        for path, expected in ((args.json, text), (args.tsv, tsv)):
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                print(f"CHECK FAILED: {path} missing or stale", file=sys.stderr)
                status = 1
        if status == 0:
            print("check ok: sound group keys")
        return status
    args.json.write_text(text, encoding="utf-8")
    args.tsv.write_text(tsv, encoding="utf-8")
    print(f"wrote {args.json.name} + {args.tsv.name}: {len(descs)} descriptors, "
          f"{len(keys)} grp.* keys, {len(audio)} audio names "
          f"({payload['audio_name_shipped_count']} shipped, "
          f"{len(payload['audio_names_not_shipped'])} not in the shipped set)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
