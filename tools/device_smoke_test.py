#!/usr/bin/env python3
"""Repeatable on-device smoke test for the rebuild APK.

This is intentionally a smoke test, not a gameplay-equivalence test. It
proves installation/launch/native initialization and captures evidence for a
later visual review.
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path


def run(*args, check=True):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(args)}\n{p.stdout}")
    return p.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", type=Path)
    ap.add_argument("--install", action="store_true",
                    help="install --replace before launch")
    ap.add_argument("--out-dir", type=Path, default=Path("reconstruction/device-smoke"))
    ap.add_argument("--wait", type=float, default=3.0)
    ap.add_argument("--package", default="com.noodlecake.blockheads.rebuild")
    ap.add_argument("--activity", default=".MainMenuActivity")
    args = ap.parse_args()

    if args.install and not args.apk:
        ap.error("--install requires --apk")
    run("adb", "get-state")
    if args.install:
        run("adb", "install", "-r", str(args.apk))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    run("adb", "logcat", "-c", check=False)
    component = f"{args.package}/{args.activity}"
    run("adb", "shell", "am", "force-stop", args.package, check=False)
    run("adb", "shell", "am", "start", "-n", component)
    time.sleep(args.wait)

    pid = run("adb", "shell", "pidof", args.package, check=False)
    logs = run("adb", "logcat", "-d", "-v", "threadtime", check=False)
    (args.out_dir / "logcat.txt").write_text(logs + "\n", encoding="utf-8")
    with (args.out_dir / "screen.png").open("wb") as f:
        p = subprocess.run(("adb", "exec-out", "screencap", "-p"), stdout=f)
    if p.returncode:
        raise RuntimeError("screencap failed")

    if not pid:
        print(f"device-smoke: FAIL process not found; evidence={args.out_dir}")
        return 1
    print(f"device-smoke: PASS pid={pid} component={component} evidence={args.out_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as exc:
        print(f"device-smoke: FAIL {exc}", file=sys.stderr)
        raise SystemExit(1)
