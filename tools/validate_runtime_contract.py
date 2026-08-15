#!/usr/bin/env python3
"""Static lifecycle/persistence contracts for the Android rebuild.

These checks are deliberately narrow: they prevent regressions that can pass
Gradle and APK packaging while leaving the device with an empty world or a
stale loading overlay.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
GAME_ACTIVITY = ROOT / "app/src/main/java/com/noodlecake/blockheads/rebuild/GameActivity.java"
ENGINE = ROOT / "app/src/main/cpp/game_engine.cpp"
PERSISTENCE = ROOT / "app/src/main/cpp/persistence_manager.h"


def fail(message: str) -> None:
    print(f"runtime-contract: FAIL {message}")
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


game = GAME_ACTIVITY.read_text(encoding="utf-8")
engine = ENGINE.read_text(encoding="utf-8")
persistence = PERSISTENCE.read_text(encoding="utf-8")

# initNative belongs after the GameView/layout exists. A duplicate call causes
# world loading and persistence side effects twice on one Activity creation.
require(game.count("initNative(getExternalFilesDir(null).getAbsolutePath());") == 1,
        "GameActivity must call initNative exactly once")
require(game.index("setContentView(layout);") < game.index(
    "initNative(getExternalFilesDir(null).getAbsolutePath());"),
        "initNative must run after GameActivity has installed its content view")

# A loaded save contains tiles, not the runtime vertex cache consumed by GL.
# The loader must schedule/rebuild each loaded chunk before returning success.
load_start = persistence.index("static bool loadWorld")
load_end = persistence.index("static void", load_start) if "static void" in persistence[load_start:] else len(persistence)
load_body = persistence[load_start:load_end]
require("world->chunks.push_back(chunk);" in load_body,
        "save loader no longer appends loaded chunks")
require("world->processChunkAsync(chunk);" in load_body,
        "loaded chunks are not rebuilt into renderer mesh caches")

# The native init path must publish a non-loading state to the Java overlay.
init_start = engine.index("Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative")
init_end = engine.index("extern \"C\" JNIEXPORT", init_start + 20)
init_body = engine[init_start:init_end]
require("Native Init Complete" in init_body,
        "native init has no completion marker")
require("updateDebugInfo" in init_body and '"Ready"' in init_body,
        "GameActivity loading overlay is never transitioned to Ready")

# MainMenuActivity and GameActivity own distinct GLSurfaceView/EGL contexts.
# GL object names from one context cannot be reused in the next Activity.  Every
# surface creation must therefore replace and initialize the native renderer;
# merely checking that g_renderer is non-null leaves stale programs/textures/VBOs.
helper_start = engine.index("void onSurfaceCreatedInternal")
helper_end = engine.index("extern \"C\" JNIEXPORT", helper_start)
helper_body = engine[helper_start:helper_end]
require("delete g_renderer;" in helper_body and "g_renderer = new WorldRenderer();" in helper_body,
        "surface creation must replace renderer resources for the current EGL context")
require("if (!g_renderer)" not in helper_body and "skipping re-init" not in helper_body,
        "surface creation still permits stale cross-context GL resources")

surface_start = engine.index("Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative")
surface_end = engine.index("extern \"C\" JNIEXPORT", surface_start + 20)
surface_body = engine[surface_start:surface_end]
require("menuMode = false" in surface_body,
        "GameActivity surface does not explicitly leave menu mode")

print("runtime-contract: PASS")
