#!/usr/bin/env python3
"""Live worldTime clock probe against the pinned 1.7.5 build (sha256 d09418e9...).

Passive, read-only: /proc/<pid>/maps + pread on /proc/<pid>/mem. No injection,
no screenshots, no interaction. Discovers the World instance from thread-stack
anchors (per references/live-memory-object-graph-walk.md), decodes World's ivar
table (name + ObjC type encoding + offset cell) straight from the pinned ELF,
then samples the clock fields over a wall-clock interval.

Output: JSON on stdout (and to --out when given).
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

from elftools.elf.elffile import ELFFile

PKG = "com.noodlecake.blockheads"
RW_FILE_OFF = 0x00E32000
SAVE_DIR = "a8124d2b4dea3347ddef22a1550a78c6"

DEFAULT_ELF = os.environ.get(
    "BH_ELF",
    "/data/data/com.termux/files/home/blockheads-work/live175/libApplication-175.so")

NON_INSTANCE_REGION_HINTS = (
    "stack", "/lib", "libApplication", ".so", "apk", "dex", "oat", "art", "ttf",
    "font", "jar", "odex", "vdex", "idmap", "dmabuf", "gralloc",
)


def sha256_path(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Probe:
    def __init__(self, pid: int, elf_path: str) -> None:
        self.pid = pid
        self.elf_path = elf_path
        self.blob = Path(elf_path).read_bytes()
        self.elf = ELFFile(open(elf_path, "rb"))
        self.sections = {s.name: (s["sh_addr"], s["sh_size"]) for s in self.elf.iter_sections()}
        self.maps = []
        with open(f"/proc/{pid}/maps") as fh:
            for line in fh:
                parts = line.split()
                a, b = parts[0].split("-")
                self.maps.append((int(a, 16), int(b, 16), parts[1], int(parts[2], 16),
                                  " ".join(parts[5:])))
        self.rw = next(m for m in self.maps
                       if m[3] == RW_FILE_OFF and "libApplication.so" in m[4] and m[2] == "rw-p")
        self.rx = next(m for m in self.maps
                       if m[3] == 0 and "libApplication.so" in m[4] and m[2] == "r-xp")
        self.mem = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        self._parse_elf()

    # ---- ELF side -------------------------------------------------------
    def sec(self, part: str):
        for n, v in self.sections.items():
            if part in n:
                return v
        raise KeyError(part)

    def u32_file(self, off: int) -> int:
        return struct.unpack_from("<I", self.blob, off)[0]

    def cstr(self, va: int, limit: int = 128) -> str:
        z = self.blob.find(b"\0", va, va + limit)
        return self.blob[va:z].decode("ascii", "replace")

    def _parse_elf(self) -> None:
        cl_va, cl_sz = self.sec("__objc_classlist")
        data_va, data_sz = self.sec("__objc_data")
        const_va, const_sz = self.sec("__objc_const")
        name_va, name_sz = self.sec("__objc_classname")

        self.class_obj_by_name: dict[str, int] = {}
        for i in range(cl_sz // 4):
            r = self.u32_file(cl_va + 4 * i)
            if not (data_va <= r < data_va + data_sz):
                continue
            for w in [self.u32_file(r + 4 * k) for k in range(10)]:
                if const_va <= w < const_va + const_sz:
                    for ni in range(16):
                        wp = self.u32_file(w + 4 * ni)
                        if name_va <= wp < name_va + name_sz:
                            self.class_obj_by_name[self.cstr(wp)] = r
                            break
                    break

        self.ivar_sym: dict[str, int] = {}
        for s in self.elf.get_section_by_name(".dynsym").iter_symbols():
            if s.name.startswith("OBJC_IVAR_$_") and s["st_value"]:
                self.ivar_sym[s.name[len("OBJC_IVAR_$_"):]] = s["st_value"]

    def ivar_table(self, cls: str):
        """[(name, encoding, offset_cell_va, size)] straight from class_ro_t."""
        r = self.class_obj_by_name[cls]
        const_va, const_sz = self.sec("__objc_const")
        ro = None
        for k in range(10):
            w = self.u32_file(r + 4 * k)
            if const_va <= w < const_va + const_sz:
                ro = w
                break
        if ro is None:
            return []
        words = [self.u32_file(ro + 4 * k) for k in range(10)]
        inst_start, inst_size, ivars_va = words[1], words[2], words[7]
        entries = []
        entsize_hdr = None
        if ivars_va:
            entsize = self.u32_file(ivars_va)
            entsize_hdr = entsize
            count = self.u32_file(ivars_va + 4)
            p = ivars_va + 8
            for _ in range(count):
                # 32-bit ld64 ivar_t: [ offset* | name* | type* | size* ] — the offset
                # field is a POINTER to the cell that OBJC_IVAR_$_Class.ivar also denotes.
                off_ptr = self.u32_file(p)
                name_p = self.u32_file(p + 4)
                type_p = self.u32_file(p + 8)
                size_p = self.u32_file(p + 12)
                nm = self.cstr(name_p) if name_p else "?"
                ty = self.cstr(type_p) if type_p else "?"
                sz = self.u32_file(size_p) if size_p else 0
                entries.append({"name": nm, "encoding": ty, "offset_ptr": off_ptr,
                                "size": sz})
                p += entsize
        return entries, inst_start, inst_size, entsize_hdr

    # ---- live side ------------------------------------------------------
    def rdw(self, addr: int):
        try:
            b = os.pread(self.mem, 4, addr)
        except OSError:
            return None
        return struct.unpack("<I", b)[0] if len(b) == 4 else None

    def rdi(self, addr: int):
        b = self.rds(addr, 4)
        return struct.unpack("<i", b)[0] if len(b) == 4 else None

    def rds(self, addr: int, n: int) -> bytes:
        try:
            return os.pread(self.mem, n, addr)
        except OSError:
            return b""

    def cell(self, sym_va: int):
        """Live value of an __objc_ivar offset cell."""
        return self.rdw(self.rw[0] + (sym_va - RW_FILE_OFF))

    def file_cell(self, sym_va: int):
        return struct.unpack_from("<i", self.blob, sym_va)[0]

    def live_class(self, cls: str):
        """Live address of the class object = the pointer instances store in their isa."""
        r = self.class_obj_by_name.get(cls)
        if r is None:
            return None
        return self.rw[0] + (r - RW_FILE_OFF)

    def classlist_reloc(self, cls: str):
        """What the relocated __objc_classlist cell itself holds (cross-check)."""
        r = self.class_obj_by_name.get(cls)
        if r is None:
            return None
        cl_va, cl_sz = self.sec("__objc_classlist")
        for i in range(cl_sz // 4):
            if self.u32_file(cl_va + 4 * i) == r:
                return self.rdw(self.rw[0] + (cl_va + 4 * i - RW_FILE_OFF))
        return None

    def region_of(self, a: int):
        for m in self.maps:
            if m[0] <= a < m[1]:
                return m
        return None

    def is_instance_ptr(self, a: int) -> bool:
        if a == 0 or a >= 0x100000000 or a % 4:
            return False
        m = self.region_of(a)
        if m is None or m[2] != "rw-p":
            return False
        if any(h in m[4] for h in NON_INSTANCE_REGION_HINTS):
            return False
        return True


def _validate_world(p: Probe, w: int, world_cls: int, dw_cls: int,
                    dw_off, back_off, saveid_off):
    """Strong signature: header is the World class, both hops close, saveID matches."""
    if not p.is_instance_ptr(w) or p.rdw(w) != world_cls:
        return None, "not a World-headed object"
    dw = p.rdw(w + dw_off) if dw_off else None
    if not dw or not p.is_instance_ptr(dw):
        return None, "dynamicWorld not an instance pointer"
    if p.rdw(dw) != dw_cls:
        return None, "dynamicWorld header != DynamicWorld class"
    back = p.rdw(dw + back_off) if back_off else None
    if back != w:
        return None, "DynamicWorld.world backref mismatch"
    sid = p.rdw(w + saveid_off) if saveid_off else None
    if not sid or not p.is_instance_ptr(sid):
        return None, "saveID not an instance pointer"
    if SAVE_DIR.encode() not in p.rds(sid, 96):
        return None, "saveID string != on-disk save dir"
    return {"world": hex(w), "dynamicWorld": hex(dw)}, None


def find_world(p: Probe):
    world_cls = p.live_class("World")
    dw_cls = p.live_class("DynamicWorld")
    if not world_cls or not dw_cls:
        return None, {"error": "class pointers unresolved"}
    dw_off = p.cell(p.ivar_sym["World.dynamicWorld"])
    back_off = p.cell(p.ivar_sym["DynamicWorld.world"])
    saveid_off = p.cell(p.ivar_sym["World.saveID"])

    info = {"world_class": hex(world_cls), "dw_class": hex(dw_cls),
            "classlist_reloc_world": (hex(p.classlist_reloc("World"))
                                      if p.classlist_reloc("World") else None),
            "world_dynamicWorld_off": dw_off, "dw_world_off": back_off,
            "world_saveID_off": saveid_off,
            "stack_words_scanned": 0, "stack_candidates": [],
            "heap_hits": 0, "heap_rejections": {}, "heap_verified": []}

    # ---- 1. thread-stack anchors (preferred per the walk reference) ----
    for m in p.maps:
        if "stack_and_tls" not in m[4]:
            continue
        lo = max(m[0], m[1] - (1 << 20))
        buf = p.rds(lo, m[1] - lo)
        info["stack_words_scanned"] += len(buf) // 4
        needle = struct.pack("<I", world_cls)
        start = 0
        while True:
            i = buf.find(needle, start)
            if i < 0:
                break
            start = i + 4
            w = struct.unpack_from("<I", buf, lo + i)[0]
            v, why = _validate_world(p, w, world_cls, dw_cls, dw_off, back_off, saveid_off)
            rec = {"addr": hex(w), "stack": m[4]}
            if v is None:
                rec["rejected"] = why
            else:
                rec.update(v)
            info["stack_candidates"].append(rec)
            if v is not None:
                return w, info

    # ---- 2. heap scan for the class-pointer word (validated) ----
    needle = struct.pack("<I", world_cls)
    CHUNK = 1 << 22
    for m in p.maps:
        if m[2] != "rw-p" or m[0] >= 0x100000000:
            continue
        if any(h in m[4] for h in NON_INSTANCE_REGION_HINTS):
            continue
        pos = m[0]
        while pos < m[1]:
            n = min(CHUNK, m[1] - pos)
            buf = p.rds(pos, n)
            if not buf:
                break
            start = 0
            while True:
                i = buf.find(needle, start)
                if i < 0:
                    break
                start = i + 4
                w = pos + i
                info["heap_hits"] += 1
                v, why = _validate_world(p, w, world_cls, dw_cls, dw_off, back_off, saveid_off)
                if v is None:
                    info["heap_rejections"][why] = info["heap_rejections"].get(why, 0) + 1
                    continue
                rec = {"addr": hex(w), "region": m[4]}
                rec.update(v)
                info["heap_verified"].append(rec)
            pos += len(buf)
        if info["heap_verified"]:
            return int(info["heap_verified"][0]["addr"], 16), info
    return None, info


def decode(p: Probe, base: int, iv: dict):
    off, enc, sz = iv["offset"], iv["encoding"], iv["size"]
    a = base + off
    if enc == "d":
        b = p.rds(a, 8)
        return struct.unpack("<d", b)[0] if len(b) == 8 else None
    if enc == "f":
        b = p.rds(a, 4)
        return struct.unpack("<f", b)[0] if len(b) == 4 else None
    if enc in ("i", "I"):
        return p.rdw(a)
    if enc in ("q", "Q"):
        b = p.rds(a, 8)
        return struct.unpack("<q", b)[0] if len(b) == 8 else None
    if enc in ("c", "C", "B"):
        b = p.rds(a, 1)
        return b[0] if b else None
    if enc in ("s", "S"):
        b = p.rds(a, 2)
        return struct.unpack("<h", b)[0] if len(b) == 2 else None
    if enc.startswith("@"):
        v = p.rdw(a)
        return hex(v) if v else None
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default=DEFAULT_ELF)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--out")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--period", type=float, default=2.0)
    args = ap.parse_args()

    pid = args.pid or int(subprocess.check_output(["pidof", PKG]).decode().split()[0])
    running_lib = None
    with open(f"/proc/{pid}/maps") as fh:
        for line in fh:
            if "libApplication.so" in line and line.split()[1] == "r-xp":
                running_lib = line.split()[-1]
                break
    rep: dict = {"pid": pid, "pkg": PKG, "elf": args.elf,
                 "running_lib": running_lib, "captured": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    if running_lib is None:
        print(json.dumps({**rep, "error": "no libApplication.so mapped"}))
        return 1
    live_sha = sha256_path(running_lib)
    pinned_sha = sha256_path(args.elf)
    rep["running_sha256"] = live_sha
    rep["pinned_sha256"] = pinned_sha
    if live_sha != pinned_sha:
        rep["error"] = "BUILD MISMATCH - refusing to measure"
        print(json.dumps(rep, indent=1))
        return 2

    p = Probe(pid, args.elf)
    rep["rw_base"] = hex(p.rw[0])
    rep["rx_base"] = hex(p.rx[0])
    rep["classes_resolved"] = len(p.class_obj_by_name)
    rep["ivar_symbols"] = len(p.ivar_sym)

    table, inst_start, inst_size, entsize_hdr = p.ivar_table("World")
    rep["World_instanceStart"] = inst_start
    rep["World_instanceSize"] = inst_size
    rep["World_ivar_list_entsize"] = entsize_hdr
    rep["World_ivar_count"] = len(table)

    world, info = find_world(p)
    rep["world_discovery"] = info
    if world is None:
        print(json.dumps(rep, indent=1))
        return 3
    rep["world"] = hex(world)

    iv_by_name = {iv["name"]: iv for iv in table}
    wanted = ("worldTime", "timeOfDayFraction", "lastUpdateTime", "randomSeed",
              "saveID", "creationDate", "totalTimeToSimulate", "timeLeftToSimulate",
              "dynamicWorld", "saveCounter", "saveCount", "isHeadingTowardsMIdday",
              "weatherFraction", "dayColor", "doubleTimeUnlocked",
              "simulationTimeOffsetRatio", "worldTimeAtLastSave")
    fields = {}
    rep["field_layout"] = {}
    for k in wanted:
        iv = iv_by_name.get(k)
        if iv is None:
            continue
        sym = p.ivar_sym.get(f"World.{k}")
        off_ptr = iv["offset_ptr"]
        off_file = struct.unpack_from("<i", p.blob, off_ptr)[0]
        off_live = p.cell(off_ptr)
        iv = dict(iv, offset=off_live if off_live is not None else off_file)
        fields[k] = iv
        rep["field_layout"][k] = {
            "encoding": iv["encoding"],
            "size": iv["size"],
            "offset_ptr": hex(off_ptr),
            "offset_from_cell_file": off_file,
            "offset_from_cell_live": off_live,
            "cell_read_stable": off_file == off_live,
            "symbol_denotes_same_cell": (sym == off_ptr) if sym else None,
        }
    rep["fields_missing"] = [k for k in wanted if k not in fields]
    rep["world_field_sample"] = {k: decode(p, world, v) for k, v in fields.items()}

    # ---- time series ----------------------------------------------------
    series = []
    t0 = time.time()
    mono0 = time.monotonic()
    while True:
        wall = time.time()
        row = {"t_wall": round(wall - t0, 3), "monotonic": round(time.monotonic() - mono0, 3)}
        for k, v in fields.items():
            if k in ("worldTime", "timeOfDayFraction", "lastUpdateTime",
                     "totalTimeToSimulate", "timeLeftToSimulate", "saveCounter",
                     "weatherFraction"):
                row[k] = decode(p, world, v)
        series.append(row)
        if wall - t0 >= args.seconds:
            break
        time.sleep(args.period)
    rep["series"] = series

    if len(series) >= 2:
        a, b = series[0], series[-1]
        dt = b["t_wall"] - a["t_wall"]
        rep["deltas"] = {}
        for k in ("worldTime", "timeOfDayFraction", "lastUpdateTime"):
            if a.get(k) is not None and b.get(k) is not None:
                rep["deltas"][k] = round(b[k] - a[k], 6)
        rep["deltas"]["wall_seconds"] = round(dt, 3)
        if a.get("worldTime") is not None:
            rep["deltas"]["worldTime_per_wall_second"] = round(
                (b["worldTime"] - a["worldTime"]) / dt, 9)
            rep["deltas"]["fmod_worldTime_over_900"] = round(b["worldTime"] / 900.0 % 1.0, 9)
            if b.get("timeOfDayFraction") is not None:
                rep["deltas"]["timeOfDayFraction_minus_fmod"] = round(
                    b["timeOfDayFraction"] - (b["worldTime"] / 900.0 % 1.0), 9)

    text = json.dumps(rep, indent=1)
    if args.out:
        Path(args.out).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
