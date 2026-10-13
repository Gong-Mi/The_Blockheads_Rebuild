#!/usr/bin/env python3
"""Contract test for tools/gen_sound_preload_list.py.

The generator is deterministic and its refusals are load-bearing (they stop a header being emitted
from inputs that lost rows), so both are pinned here on synthetic inputs:

  * deterministic, sorted output;
  * refuses when the method names no sounds at all (a changed method name must not silently emit an
    empty list that a consumer would compile happily);
  * refuses when any name lacks a shipped sha256;
  * --check fails on a stale or missing header, and passes on the freshly generated one.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import gen_sound_preload_list as g  # noqa: E402


def write_inputs(tmp: Path) -> tuple[Path, Path]:
    wiring = tmp / "wiring.json"
    coverage = tmp / "coverage.json"
    wiring.write_text(json.dumps({
        "elf_sha256": "deadbeef", "rows": [
            {"name": "b.wav", "methods": [g.METHOD], "replacement_referenced": True,
             "sites": [{"pool_word_at": "0x1"}]},
            {"name": "a.wav", "methods": [g.METHOD], "replacement_referenced": False,
             "sites": [{"pool_word_at": "0x2"}]},
            {"name": "x.wav", "methods": ["Other -[thing]"], "replacement_referenced": False},
        ]}))
    coverage.write_text(json.dumps({"rows": [
        {"name": "a.wav", "sha256": "a" * 64}, {"name": "b.wav", "sha256": "b" * 64},
        {"name": "x.wav", "sha256": "c" * 64}]}))
    return wiring, coverage


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        wiring, coverage = write_inputs(tmp)
        rows, meta = g.build(wiring, coverage)
        assert [r["name"] for r in rows] == ["a.wav", "b.wav"], rows
        assert meta["count"] == 2 and meta["shipped"] == 2 and meta["with_sha256"] == 2, meta
        assert meta["already_referenced_by_replacement"] == 1, meta
        assert meta["method"] == g.METHOD == "World -[incrementalLoad]"

        text = g.render(rows, meta)
        assert "kOriginalLoadTimeSoundCount = 2" in text, text
        assert text.index('"a.wav"') < text.index('"b.wav"'), "rows must be sorted"
        assert "Membership only" in text, "the boundary note must survive rendering"
        assert '"a" * 64' not in text and "a" * 64 in text

        out = tmp / "out.h"
        r = subprocess.run([sys.executable, str(ROOT / "tools/gen_sound_preload_list.py"),
                            "--wiring", str(wiring), "--coverage", str(coverage), "--out", str(out)],
                           capture_output=True, text=True)
        assert r.returncode == 0 and out.is_file(), (r.returncode, r.stderr)
        r = subprocess.run([sys.executable, str(ROOT / "tools/gen_sound_preload_list.py"),
                            "--wiring", str(wiring), "--coverage", str(coverage), "--out", str(out),
                            "--check"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        out.write_text(out.read_text() + "\n// hand edit\n")
        r = subprocess.run([sys.executable, str(ROOT / "tools/gen_sound_preload_list.py"),
                            "--wiring", str(wiring), "--coverage", str(coverage), "--out", str(out),
                            "--check"], capture_output=True, text=True)
        assert r.returncode == 1, "a hand-edited generated header must fail --check"
        r = subprocess.run([sys.executable, str(ROOT / "tools/gen_sound_preload_list.py"),
                            "--wiring", str(wiring), "--coverage", str(coverage),
                            "--out", str(tmp / "missing.h"), "--check"], capture_output=True, text=True)
        assert r.returncode == 1, "a missing header must fail --check"

        # negative control: the method naming nothing must be refused outright
        empty = tmp / "empty.json"
        empty.write_text(json.dumps({"rows": [{"name": "x.wav", "methods": ["Other -[thing]"]}]}))
        r = subprocess.run([sys.executable, str(ROOT / "tools/gen_sound_preload_list.py"),
                            "--wiring", str(empty), "--coverage", str(coverage),
                            "--out", str(tmp / "empty.h")], capture_output=True, text=True)
        assert r.returncode == 1 and "REFUSING" in (r.stderr + r.stdout), (r.returncode, r.stderr)

        # negative control: a name without a shipped sha256 must be refused
        partial = tmp / "partial.json"
        partial.write_text(json.dumps({"rows": [
            {"name": "a.wav", "methods": [g.METHOD]}, {"name": "ghost.wav", "methods": [g.METHOD]}]}))
        r = subprocess.run([sys.executable, str(ROOT / "tools/gen_sound_preload_list.py"),
                            "--wiring", str(partial), "--coverage", str(coverage),
                            "--out", str(tmp / "partial.h")], capture_output=True, text=True)
        assert r.returncode == 1 and "REFUSING" in (r.stderr + r.stdout), (r.returncode, r.stderr)

    real_wiring = ROOT / "reconstruction/reverse-v3/native/audio_wiring_map.json"
    real_cov = ROOT / "reconstruction/reverse-v3/native/audio_asset_coverage.json"
    if real_wiring.is_file() and real_cov.is_file():
        rows, meta = g.build(real_wiring, real_cov)
        assert meta["count"] == 32 and meta["with_sha256"] == 32, meta
        print(f"synthetic controls verified; real inputs give {meta['count']} names, all with sha256")
    else:
        print("synthetic controls verified (real artifacts absent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
