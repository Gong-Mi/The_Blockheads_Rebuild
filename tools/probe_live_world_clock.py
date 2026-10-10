#!/usr/bin/env python3
"""Measure the live original's world clock against the pinned build (root, read-only).

What it establishes, with the build bound by sha256 before anything is read:

  * `World.worldTime` is a double ivar whose offset is resolved at runtime through the
    `__objc_ivar` cell that `OBJC_IVAR_$_World.worldTime` also denotes (decoded from
    class_ro_t, not guessed);
  * the rate at which it advances per second of REAL time, measured against
    `World.lastUpdateTime` (an NSDate-reference wall clock that this same probe
    verifies advances 1.000/s);
  * the state of `World.fastForward`, because the update path scales time by 20.0f
    only under that flag -- a rate measured without recording the flag is not
    interpretable.

Passive only: /proc/<pid>/maps + pread(/proc/<pid>/mem). No injection, no ptrace, no
screenshot, no interaction with the app. Nothing is written unless --json is passed.

Exit codes: 0 ok, 1 no such process, 2 BUILD MISMATCH, 3 World instance not found.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

PKG = "com.noodlecake.blockheads"
RW_FILE_OFF = 0x00E32000                      # this family: rw segment file offset == p_vaddr
NON_INSTANCE_HINTS = ("stack", "/lib", "libApplication", ".so", "apk", "dex", "oat",
                      "art", "ttf", "font", "jar", "odex", "vdex", "idmap", "dmabuf",
                      "gralloc")
CLOCK_FIELDS = ("worldTime", "lastUpdateTime", "fastForward", "timeOfDayFraction")
NON_INT = {"@", "#", ":"}


# --------------------------------------------------------------------------- pure
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_u32(blob: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(blob):
        raise ValueError(f"read_u32 out of range: {off:#x}")
    return struct.unpack_from("<I", blob, off)[0]


def read_cstr(blob: bytes, off: int, limit: int = 4096) -> str:
    """NUL-terminated ASCII string at `off`.

    `limit` must be generous: ObjC type encodings for structs are long
    (`{CustomRules="customRulesEnabled"C"seedType"c...}`, 504 bytes in this build),
    and a too-small window turns a valid entry into a hard failure.
    """
    if not 0 <= off < len(blob):
        raise ValueError(f"read_cstr out of range: {off:#x}")
    end = blob.find(b"\0", off, min(off + limit, len(blob)))
    if end < 0:
        raise ValueError(f"unterminated cstring at {off:#x}")
    return blob[off:end].decode("ascii", "replace")


def decode_ivar_list(blob: bytes, ivars_va: int) -> list[dict]:
    """Decode a 32-bit ld64 ivar_list_t: [entsize][count][ {offset*,name*,type*,size*} ].

    The `offset` member is a POINTER to a 4-byte cell that holds the runtime offset --
    the same cell OBJC_IVAR_$_Class.ivar denotes. A degenerate entsize is rejected
    rather than followed, so a bad pointer cannot silently return an empty list.
    """
    entsize = read_u32(blob, ivars_va)
    count = read_u32(blob, ivars_va + 4)
    if entsize < 16 or entsize % 4 or count > 4096:
        raise ValueError(f"implausible ivar_list header: entsize={entsize} count={count}")
    out = []
    p = ivars_va + 8
    for _ in range(count):
        out.append({
            "offset_ptr": read_u32(blob, p),
            "name": read_cstr(blob, read_u32(blob, p + 4)),
            "encoding": read_cstr(blob, read_u32(blob, p + 8)),
            "size": read_u32(blob, p + 12),
        })
        p += entsize
    if not out:
        raise ValueError("ivar_list decoded to zero entries")
    return out


def slope(xs: list[float], ys: list[float]) -> float:
    """Least-squares slope of ys over xs; requires >= 2 distinct samples."""
    n = len(xs)
    if n < 2 or len(ys) != n:
        raise ValueError("slope needs >= 2 paired samples")
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        raise ValueError("slope: all x identical")
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


def binding_verdict(running_sha: str, pinned_sha: str) -> str:
    return "ok" if running_sha == pinned_sha else "BUILD MISMATCH"


def find_pid(pkg: str) -> int | None:
    """PID of the target, robust to `pidof` limits.

    `pidof` matches the truncated /proc/<pid>/comm (15 chars) and, unprivileged,
    cannot see another UID's process at all - which silently returned "not running"
    for a target that was very much alive. Fall back to scanning /proc/*/cmdline.
    """
    try:
        out = subprocess.run(["pidof", pkg], capture_output=True, text=True, timeout=10)
        for tok in out.stdout.split():
            if tok.isdigit():
                return int(tok)
    except (OSError, subprocess.SubprocessError):
        pass
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmd = (entry / "cmdline").read_bytes().split(b"\0")[0].decode()
        except OSError:
            continue
        if cmd == pkg:
            return int(entry.name)
    return None


def derive_save_dir(pid: int) -> str | None:
    """The loaded world's save dir name, from /proc/<pid>/fd (…/saves/<name>/world_db/lock.mdb).

    Deriving it beats accepting it on the command line: the path contains a space
    ("Application Support"), which shell quoting silently splits into a wrong name -
    - and a wrong saveID then rejects every valid instance candidate.
    """
    try:
        fds = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        return None
    for e in fds:
        try:
            target = os.readlink(e)
        except OSError:
            continue
        if target.endswith("/world_db/lock.mdb") and "/saves/" in target:
            return target.split("/saves/", 1)[1].split("/", 1)[0]
    return None


# --------------------------------------------------------------------------- live
class Probe:
    def __init__(self, pid: int, elf_path: str) -> None:
        self.pid = pid
        self.blob = Path(elf_path).read_bytes()
        from elftools.elf.elffile import ELFFile
        self.elf = ELFFile(open(elf_path, "rb"))
        self.sections = {s.name: (s["sh_addr"], s["sh_size"]) for s in self.elf.iter_sections()}
        self.maps = []
        with open(f"/proc/{pid}/maps") as fh:
            for line in fh:
                parts = line.split()
                a, b = parts[0].split("-")
                self.maps.append((int(a, 16), int(b, 16), parts[1], int(parts[2], 16),
                                  " ".join(parts[5:])))
        self.rw = self._map(RW_FILE_OFF, "rw-p")
        self.mem = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        self._parse_classes()

    def _map(self, off: int, perm: str):
        for m in self.maps:
            if m[3] == off and m[2] == perm and "libApplication.so" in m[4]:
                return m
        raise SystemExit("libApplication.so segment not mapped as expected")

    def sec(self, part: str):
        for n, v in self.sections.items():
            if part in n:
                return v
        raise KeyError(part)

    def _parse_classes(self) -> None:
        cl_va, cl_sz = self.sec("__objc_classlist")
        data_va, data_sz = self.sec("__objc_data")
        const_va, const_sz = self.sec("__objc_const")
        name_va, name_sz = self.sec("__objc_classname")
        self.class_obj = {}
        self.class_ro = {}
        for i in range(cl_sz // 4):
            r = read_u32(self.blob, cl_va + 4 * i)
            if not (data_va <= r < data_va + data_sz):
                continue
            for k in range(10):
                w = read_u32(self.blob, r + 4 * k)
                if const_va <= w < const_va + const_sz:
                    self.class_ro[r] = w
                    for ni in range(16):
                        wp = read_u32(self.blob, w + 4 * ni)
                        if name_va <= wp < name_va + name_sz:
                            self.class_obj[read_cstr(self.blob, wp)] = r
                            break
                    break
        self.ivar_sym = {}
        for s in self.elf.get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_") and s["st_value"]:
                self.ivar_sym[s.name[len("OBJC_IVAR_$_"):]] = s["st_value"]

    # --- live reads
    def rd(self, addr: int, n: int) -> bytes:
        try:
            return os.pread(self.mem, n, addr)
        except OSError:
            return b""

    def rdw(self, addr: int):
        b = self.rd(addr, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else None

    def cell(self, sym_va: int):
        return self.rdw(self.rw[0] + (sym_va - RW_FILE_OFF))

    def live_class(self, cls: str):
        r = self.class_obj.get(cls)
        return None if r is None else self.rw[0] + (r - RW_FILE_OFF)

    def region_of(self, a: int):
        for m in self.maps:
            if m[0] <= a < m[1]:
                return m
        return None

    def is_instance_ptr(self, a: int) -> bool:
        if a == 0 or a >= 0x100000000 or a % 4:
            return False
        m = self.region_of(a)
        return bool(m) and m[2] == "rw-p" and not any(h in m[4] for h in NON_INSTANCE_HINTS)

    def ivars(self, cls: str) -> list[dict]:
        ro = self.class_ro.get(self.class_obj[cls])
        if ro is None:
            raise SystemExit(f"no class_ro_t for {cls}")
        ivars_va = read_u32(self.blob, ro + 4 * 7)
        if not ivars_va:
            raise SystemExit(f"{cls} has no ivar list")
        return decode_ivar_list(self.blob, ivars_va)


def decode(p: Probe, base: int, iv: dict, off: int):
    enc = iv["encoding"]
    a = base + off
    if enc == "d":
        b = p.rd(a, 8)
        return struct.unpack("<d", b)[0] if len(b) == 8 else None
    if enc == "f":
        b = p.rd(a, 4)
        return struct.unpack("<f", b)[0] if len(b) == 4 else None
    if enc in ("i", "I"):
        return p.rdw(a)
    if enc in ("c", "C", "B"):
        b = p.rd(a, 1)
        return b[0] if b else None
    if enc in ("q", "Q"):
        b = p.rd(a, 8)
        return struct.unpack("<q", b)[0] if len(b) == 8 else None
    if enc in ("s", "S"):
        b = p.rd(a, 2)
        return struct.unpack("<h", b)[0] if len(b) == 2 else None
    return None


def find_world(p: Probe, save_dir: str | None):
    """World instance, signature-checked: header class + dynamicWorld hop + backref
    (+ saveID string equal to the on-disk save dir when one is supplied)."""
    wc, dc = p.live_class("World"), p.live_class("DynamicWorld")
    if wc is None or dc is None:
        raise SystemExit("World/DynamicWorld class objects not resolvable in this build")
    dw_off = p.cell(p.ivar_sym["World.dynamicWorld"])
    back_off = p.cell(p.ivar_sym["DynamicWorld.world"])
    sid_off = p.cell(p.ivar_sym["World.saveID"])
    if dw_off is None or back_off is None:
        raise SystemExit("ivar offset cells unreadable (wrong build?)")

    def ok(w: int) -> bool:
        if not p.is_instance_ptr(w) or p.rdw(w) != wc:
            return False
        dw = p.rdw(w + dw_off)
        if not dw or not p.is_instance_ptr(dw) or p.rdw(dw) != dc:
            return False
        if p.rdw(dw + back_off) != w:
            return False
        if save_dir:
            sid = p.rdw(w + sid_off) if sid_off else None
            if not sid or save_dir.encode() not in p.rd(sid, 128):
                return False
        return True

    needle = struct.pack("<I", wc)
    for m in p.maps:
        if "stack_and_tls" not in m[4]:
            continue
        lo = max(m[0], m[1] - (1 << 20))
        buf = p.rd(lo, m[1] - lo)
        i = 0
        while True:
            i = buf.find(needle, i)
            if i < 0:
                break
            w = lo + i
            i += 4
            if ok(w):
                return w, {"found_via": f"stack {m[4]}", "world_class": hex(wc)}
    for m in p.maps:
        if m[2] != "rw-p" or m[0] >= 0x100000000:
            continue
        if any(h in m[4] for h in NON_INSTANCE_HINTS):
            continue
        pos = m[0]
        while pos < m[1]:
            buf = p.rd(pos, min(1 << 22, m[1] - pos))
            if not buf:
                break
            i = 0
            while True:
                i = buf.find(needle, i)
                if i < 0:
                    break
                w = pos + i
                i += 4
                if ok(w):
                    return w, {"found_via": f"heap scan {m[4]!r}", "world_class": hex(wc)}
            pos += len(buf)
    return None, {"found_via": None, "world_class": hex(wc)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default=os.environ.get("BH_ELF"),
                    help="pinned libApplication.so for the running build (or $BH_ELF)")
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--save-dir-name", default=None,
                    help="on-disk save dir name, to cross-check World.saveID")
    ap.add_argument("--seconds", type=float, default=30.0)
    ap.add_argument("--period", type=float, default=1.0)
    ap.add_argument("--json", default=None,
                    help="write the report here; omitted means stdout only (no default "
                         "path on purpose: a probe must never overwrite an artifact)")
    args = ap.parse_args()
    if not args.elf:
        ap.error("--elf (or $BH_ELF) is required")

    pid = args.pid or find_pid(PKG)
    if not pid:
        print(json.dumps({"pkg": PKG, "error": "target is not running (no /proc entry with "
                                                "this cmdline)"}, indent=1))
        return 1
    running_lib = None
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            if "libApplication.so" in line and line.split()[1] == "r-xp":
                running_lib = line.split()[-1]
                break
    if running_lib is None:
        print(json.dumps({"pid": pid, "error": "no libApplication.so mapped"}), file=sys.stderr)
        return 1

    rep = {"schema": 1, "pid": pid, "pkg": PKG, "captured": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "pinned_elf": args.elf, "running_lib": running_lib}
    rep["running_sha256"] = sha256_file(running_lib)
    rep["pinned_sha256"] = sha256_file(args.elf)
    rep["build_binding"] = binding_verdict(rep["running_sha256"], rep["pinned_sha256"])
    if rep["build_binding"] != "ok":
        print(json.dumps(rep, indent=1))
        return 2

    p = Probe(pid, args.elf)
    save_dir = args.save_dir_name or derive_save_dir(pid)
    rep["save_dir_name"] = save_dir
    world, how = find_world(p, save_dir)
    rep["instance_discovery"] = how
    if world is None:
        print(json.dumps(rep, indent=1))
        return 3
    rep["world"] = hex(world)

    table = {iv["name"]: iv for iv in p.ivars("World")}
    fields = {}
    rep["clock_field_layout"] = {}
    for name in CLOCK_FIELDS:
        iv = table.get(name)
        if iv is None:
            continue
        off_live = p.cell(iv["offset_ptr"])
        fields[name] = dict(iv, offset=off_live if off_live is not None else
                            read_u32(p.blob, iv["offset_ptr"]))
        rep["clock_field_layout"][name] = {
            "encoding": iv["encoding"],
            "offset_ptr": hex(iv["offset_ptr"]),
            "offset": fields[name]["offset"],
            "symbol_denotes_same_cell": p.ivar_sym.get(f"World.{name}") == iv["offset_ptr"],
        }

    rows = []
    t0 = time.time()
    while True:
        now = time.time()
        rows.append({"t": round(now - t0, 4),
                     **{n: decode(p, world, iv, iv["offset"]) for n, iv in fields.items()}})
        if now - t0 >= args.seconds:
            break
        time.sleep(args.period)
    rep["samples"] = rows

    real = [r["lastUpdateTime"] for r in rows]
    game = [r["worldTime"] for r in rows]
    rep["real_seconds_per_second"] = slope(rows and [r["t"] for r in rows], real)
    rep["worldTime_per_real_second"] = slope([r["t"] for r in rows], game)
    rep["worldTime_per_lastUpdateTime_width"] = (game[-1] - game[0]) / (real[-1] - real[0])
    rep["fastForward_states_seen"] = sorted({r.get("fastForward") for r in rows})
    rep["timeOfDayFraction_span"] = [min(r["timeOfDayFraction"] for r in rows),
                                     max(r["timeOfDayFraction"] for r in rows)]
    if len(rep["fastForward_states_seen"]) > 1:
        rep["warning"] = ("fastForward changed during the window - the rate above is a "
                          "blend; re-run until the flag is stable")
    rep["interpretation"] = ("worldTime advances worldTime_per_real_second units per real "
                             "second while fastForward holds; a 900-unit day therefore "
                             "lasts 900 / that rate real seconds")
    text = json.dumps(rep, indent=1)
    if args.json:
        Path(args.json).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
