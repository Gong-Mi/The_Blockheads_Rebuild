#!/usr/bin/env python3
"""Static regression checks for the v2 GLES asset/render contract."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
RENDERER = (ROOT / "app/src/main/cpp/world_renderer.cpp").read_text()
WORLD = (ROOT / "app/src/main/cpp/game_world.cpp").read_text()
BLOCK = (ROOT / "app/src/main/assets/Block.vsh").read_text()
ITEM = (ROOT / "app/src/main/assets/Item.fsh").read_text()

errors = []
def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)

require("Item.vsh" in RENDERER and "Item.fsh" in RENDERER,
        "renderer must compile the original Item shader pair")
require("itemProgram" in RENDERER and "normal_texture" in RENDERER,
        "drop-item path must bind the Item program and normal texture")
require("glGenerateMipmap" not in RENDERER,
        "renderer must not unconditionally generate mipmaps for NPOT assets")
require("(type - 1) % 32" not in RENDERER and "(item.type - 1) % 32" not in RENDERER,
        "numeric IDs must not be used as guessed atlas coordinates")
require("ItemManager::getInstance().getDef(item.type)" in RENDERER,
        "drop items must resolve through the item definition table")
require("outTexIndex.x" in BLOCK and "/ 255.0" in BLOCK,
        "block shader atlas-index contract must remain explicit")
require("texture2D(texture, outTexCoord.xy)" in ITEM,
        "item shader must consume normalized UVs directly")
require("queueCV.wait_for" in WORLD and "std::chrono::milliseconds(50)" in WORLD,
        "world worker must wake on a timer when the chunk queue is idle")
require("queueCV.wait(lock, [this]" not in WORLD,
        "world worker must not block simulation indefinitely on an empty queue")
require("selectionBox40.png" in (ROOT / "app/src/main/java/com/noodlecake/blockheads/rebuild/GameActivity.java").read_text(),
        "hotbar must use the APK's case-sensitive selectionBox40.png name")
for name in ("Item.vsh", "Item.fsh", "Items.png", "ItemNormals.png", "yakLegs.png", "selectionBox40.png"):
    require((ROOT / "app/src/main/assets" / name).exists(), f"missing runtime asset: {name}")

if errors:
    print("render-contract: FAIL")
    for error in errors:
        print(f"- {error}")
    raise SystemExit(1)
print("render-contract: PASS")
