#!/usr/bin/env python3
"""Contract test for the live frame stack captured from the official process.

Verifies the live frame hierarchy and structural roles pinned from UIKitMain
execution on Android without requiring process access in CI.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "reconstruction/reverse-v3/native"
JSON_PATH = NATIVE / "live_frame_stack.json"

REQUIRED_ROLES = {
    "world_master_render": ("World", "render:cameraZ:projectionMatrix:pinchScale:"),
    "ui_master_render": ("UIManager", "render:projectionMatrix:cameraZ:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:pinchScale:mapAlpha:"),
    "world_hud_render": ("WorldUI", "render:translation:pinchScale:paused:"),
    "entity_animal_draw": ("DonkeyLike", "draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:"),
    "bone_matrix_calculation": ("DonkeyLike", "setupMatrices:dt:"),
    "character_portrait_preview": ("Blockhead", "drawForButtonProjectionMatrix:modelViewMatrix:"),
}


def main() -> int:
    assert JSON_PATH.exists(), f"missing {JSON_PATH}"
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    assert data["thread_name"] == "UIKitMain", data["thread_name"]
    assert data["root_driver"] == "World render:cameraZ:projectionMatrix:pinchScale:"

    # the declared count must match the recorded data, and the capture must carry its
    # provenance explicitly (build-unbound is recorded, not silently glossed)
    assert data["frame_count"] == len(data["frames"]), (
        f"frame_count {data['frame_count']} != len(frames) {len(data['frames'])}"
    )
    prov = data["provenance"]
    assert prov["build"] == "unrecorded", prov
    assert "build-unbound" in prov["note"], prov

    frames_by_role = {f["role"]: (f["class"], f["selector"]) for f in data["frames"]}
    for role, (cls, sel) in REQUIRED_ROLES.items():
        assert role in frames_by_role, f"missing role {role}"
        assert frames_by_role[role] == (cls, sel), f"role {role}: got {frames_by_role[role]}, expected {(cls, sel)}"

    print(f"live-frame-stack: PASS ({len(data['frames'])} frames; count consistent; build unbound)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
