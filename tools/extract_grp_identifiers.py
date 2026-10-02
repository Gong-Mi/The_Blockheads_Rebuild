#!/usr/bin/env python3
"""Extract the `grp.*` identifiers from the binary, and cross-check them against the shipped
achievement list.

CORRECTION to how this started. This tool was written as "the sound registry", on the
assumption that `grp.*` names MJMultiSound groups. The shipped asset
`assets/GKAchievements.plist` disproves that assumption: every one of its 91 top-level keys
is a `grp.*` identifier whose value is `{googleIdentifier: <Play Games achievement id>}`, and
the binary carries the matching machinery (`GKAchievements`, `reportAchievement` x16,
`achievement*` x24, `googleIdentifier` x4). So these are the game's achievement identifiers.
Whether any of them *also* names a multi-sound group is not established, and this artifact
does not claim it.

What is extracted here, with that correction applied:
  * the `grp.*` literals in the merged cstring blob, with the descriptor that bounds them;
  * the audio file-name literals sharing that blob (facts about the string layout);
  * the achievement cross-check: which identifiers the shipped plist defines, their
    `googleIdentifier` values, and the set difference in both directions.

Boundary: blob adjacency is emission order, not semantics. Group membership (which files a
sound group contains) is NOT established by anything in this file.

Usage:
  python3 tools/extract_grp_identifiers.py [--elf PATH] [--plist PATH] [--check]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import plistlib
import re
import struct
import sys
from pathlib import Path

DEFAULT_ELF = Path.home() / "blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
NATIVE = Path("reconstruction/reverse-v3/native")
DEFAULT_PLIST = Path.home() / "blockheads-work/extracted/assets/GKAchievements.plist"
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
    ap.add_argument("--json", type=Path, default=NATIVE / "grp_identifiers.json")
    ap.add_argument("--tsv", type=Path, default=NATIVE / "grp_identifiers.tsv")
    ap.add_argument("--plist", type=Path, default=DEFAULT_PLIST,
                    help="shipped achievement list used for the cross-check")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not args.elf.exists():
        print(f"skip: no ELF at {args.elf}")
        return 0
    elf = args.elf.read_bytes()
    secs = sections(elf)
    shipped = shipped_names()
    plist_keys = {}
    if args.plist.exists():
        plist_keys = plistlib.loads(args.plist.read_bytes())
    descs = find_descriptors(elf, secs)
    cls = classify(descs, shipped)
    keys, audio = cls["group_keys"], cls["audio_names"]
    # Classification is evidence-based, not heuristic. The shipped plist is the authority
    # for what these identifiers are; a literal that is not in it is either a fragment used
    # in key construction or a near-miss spelling. Near-misses are flagged by edit distance
    # so a typo like grp.amethyst_pickax (the plist has ..._pickaxe) cannot hide.
    key_names = list(keys)
    plist_names = set(plist_keys) if plist_keys else set()
    identifiers = sorted(plist_names & set(key_names))
    binary_only = sorted(set(key_names) - plist_names)

    def near(n: str) -> list[str]:
        """plist identifiers within edit distance 2 of n (cheap Levenshtein)."""
        import difflib
        return difflib.get_close_matches(n, identifiers, n=2, cutoff=0.9)

    near_misses = {n: near(n) for n in binary_only if near(n)}

    crosscheck: dict = {"plist_path": str(args.plist), "available": False}
    if plist_keys:
        raw = args.plist.read_bytes()
        crosscheck = {
            "plist_path": str(args.plist),
            "available": True,
            "plist_sha256": hashlib.sha256(raw).hexdigest(),
            "entry_count": len(plist_keys),
            "kind": "play-games achievement identifiers" if all(
                isinstance(v, dict) and "googleIdentifier" in v for v in plist_keys.values())
                else "unrecognised shape",
            "google_identifiers": {k: v.get("googleIdentifier")
                                   for k, v in plist_keys.items()},
            "in_plist_not_in_binary": sorted(set(plist_keys) - set(key_names)),
            "in_binary_not_in_plist": binary_only,
            "binary_only_near_misses": near_misses,
        }

    payload = {
        "elf_sha256": hashlib.sha256(elf).hexdigest(),
        "what_these_are": ("achievement identifiers per the shipped GKAchievements.plist; "
                           "NOT established as sound-group keys (see the header note)"),
        "achievement_crosscheck": crosscheck,
        "achievement_identifier_count": len(identifiers),
        "achievement_identifiers": identifiers,
        "binary_only_literal_count": len(binary_only),
        "binary_only_literals": binary_only,
        "binary_only_near_misses": near_misses,
        "format_string_audio_names": sorted(k for k in audio if "%" in k),
        "descriptor_count": len(descs),
        "group_key_count": len(keys),
        "classification_basis": ("identifiers = literals that the shipped achievement plist "
                                 "also defines; binary_only = literals it does not, which are "
                                 "fragments of other keys or near-miss spellings. This replaces "
                                 "an earlier prefix-count heuristic, which the cross-check shows "
                                 "was too eager (grp.ruby is a real identifier)."),
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
            print("check ok: grp identifiers")
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
