#!/usr/bin/env python3
"""Contract test for the live frame stack captured from the official process.

The artifact is a build-bound recapture (libApplication sha256 recorded) whose
frames are verified twice before inclusion: a bl/blx instruction must end
exactly at the address (ARM and Thumb modes both tried), and the enclosing
function start — nearest A32 push-with-lr prologue — must exactly match a
method-table imp for Objective-C credit (otherwise the frame is recorded as an
unnamed function by its raw start). No process access is required in CI.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "live_frame_stack.json"

BUILD_SHA256 = "d09418e9c0865902054a71358dcff3264d47f7b24ede58667cb5ea0e6f269b96"

REQUIRED_FRAMES = [
    ("UIApplication", "run"),
    ("World", "render:cameraZ:projectionMatrix:pinchScale:"),
    ("UIManager", "render:projectionMatrix:cameraZ:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:pinchScale:mapAlpha:"),
    ("WorldUI", "render:translation:pinchScale:paused:"),
    ("SleepProgressUI", "render:translation:pinchScale:"),
    ("Tutorial", "render:translation:pinchScale:"),
    ("MJButton", "renderFrame:projectionMatrix:"),
    ("MJTextView", "renderFrame:projectionMatrix:"),
    ("MJView", "renderFrame:projectionMatrix:"),
    ("BitmapString", "renderWithProjectionMatrix:modelViewMatrix:"),
    ("Blockhead", "drawForButtonProjectionMatrix:modelViewMatrix:"),
    ("NoiseFunction", "getX:Y:octaves:"),
]


def main() -> int:
    assert JSON_PATH.exists(), f"missing {JSON_PATH}"
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    assert data["thread_name"] == "UIKitMain", data["thread_name"]
    assert data["root_driver"] == "World render:cameraZ:projectionMatrix:pinchScale:"
    assert data["build_libApplication_sha256"] == BUILD_SHA256, data["build_libApplication_sha256"]

    # the declared count must match the recorded data
    assert data["frame_count"] == len(data["frames"]), (
        f"frame_count {data['frame_count']} != len(frames) {len(data['frames'])}"
    )
    assert len(data["frames"]) >= 15, "implausibly small frame list"

    # every listed frame carries its call-site evidence and a resolved function start
    for frame in data["frames"]:
        assert frame["callsite_insn"], f"frame without call-site evidence: {frame}"
        assert frame["fn_start"], f"frame without fn_start: {frame}"
        if frame["attribution"] == "objc-method":
            assert isinstance(frame["offset"], int) and frame["offset"] >= 0, frame
        else:
            assert frame["attribution"] == "unnamed-function", frame
        assert frame["stack_addr"].startswith("0x") and frame["return_addr"].startswith("0x"), frame

    credited = [(f["class"], f["selector"]) for f in data["frames"]
                if f["attribution"] == "objc-method"]
    for pair in REQUIRED_FRAMES:
        assert pair in credited, f"missing credited frame {pair}"

    non_calls = [w for w in data["stack_words"] if not w["callsite"]]
    assert non_calls, "the stack-word table should retain the non-call words as negatives"

    print(f"live-frame-stack: PASS ({len(data['frames'])} verified frames; build-bound)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
