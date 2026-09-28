#!/usr/bin/env python3
"""CI-safe guard for the specials executed differential
(tools/test_specials_arm.py + tools/specials_arm_bridge.cpp).

CI mode (no ELF): asserts the module/bridge surfaces the differential pinned
(SteamTrain's own body has no hook; OwnershipSign's default-15 radii, the
[1,30] clamp and the ID-gated object block), the harness table and the CMake
registration. Host mode (--elf <pinned ELF>, needs Unicorn): runs the
differential itself and requires all modelled cases to match.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"


def require(path: Path, needles) -> None:
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{path.name} misses: {needle}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", type=Path)
    a = ap.parse_args()

    # the module carries the ARM-attested OwnershipSign facts
    require(ROOT / "reconstruction/recovered/ownershipsign_full.h", [
        "kOwnershipDefaultRadius = 15",
        "kOwnershipRadiusMin = 1",
        "kOwnershipRadiusMax = 30",
        "ownershipClampRadius",
    ])
    require(ROOT / "reconstruction/recovered/ownershipsign_full.cpp", [
        "state.has_land_owner_name =",
        "id_present &&",
        "EXECUTED differential",
    ])
    # the bridge pins the modelled classes and their semantics
    require(ROOT / "tools/specials_arm_bridge.cpp", [
        "{42, kSteamTrain, 4, nullptr, \"\", false, 0, 0, 0}",
        "{60, kOwnershipSign, 4, nullptr, \"updateText\", true, 15, 1, 30}",
        "{52, kPainting, 5, \"initSubDerivedItems\", \"initSubDerivedItems\", false, 0, 0, 0}",
        "{25, kDropBear, 9, \"loadDerivedStuff\",",
        "dies of old age",
        "0x4479A000",
        "{39, kCaveTroll, 4, \"initSubDerivedStuffStuff\",",
        "0x1C2894",
        "0x4BE068",
        "movw lr, #0xf",
        "resolveOwnerName",
        "playerIsBanned",
    ])
    require(ROOT / "reconstruction/recovered/painting_full.cpp", [
        "EXECUTED differential",
        "playerIsBannedWithID:",
    ])
    require(ROOT / "reconstruction/recovered/npc_full.cpp", [
        "EXECUTED differential",
        "RETURNS NIL (dies of old age)",
        "memcpy veneer",
    ])
    require(ROOT / "tools/test_specials_arm.py", [
        "VENEER_MEMCPY = 0x1C2894",
        "worldWidthMacro",
        "plt_names",
        "0x00A93C64",  # ArtificialLight (dump-attested reads)
        "('Tree', 1, 0x004C2568",   # the tree growth machine entry
        "--static-tree",
        "--r2r3-double",            # the saveTime double wiring
        "--seed",
        "--fake-tile",              # the synthetic tile world
        "__aeabi_idiv",
    ])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_tree_growintimesincesaved.txt",
            ["growInTimeSinceSaved"])
    require(ROOT / "tools/test_specials_arm.py", [
        "('UIManager', 0, 0x00AD7748",  # the input-front router entry
    ])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_uimanager_starttouch.txt",
            ["startTouch:tapCount:index:"])
    require(ROOT / "reconstruction/reverse-v3/native/INPUT_FRONT.md",
            ["tcUI@32", "currentTouchIsInAnyButtons@154"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_dpad_touch.txt",
            ["touchIsInViewAtAll:",
             "OBJC_IVAR_$_DPad.rightSide (slot 0x0105d31c) = 160",
             "OBJC_IVAR_$_DPad.windowInfo (slot 0x0105d340) = 112"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_craftui_touch.txt",
            ["OBJC_IVAR_$_CraftUI.scrollingButtons (slot 0x0105ef50) = 148",
             "OBJC_IVAR_$_CraftUI.craftButton (slot 0x0105ef6c) = 208"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_craftui_starttouch.txt",
            ["CraftUI.scrollingButtons (slot 0x0105ef50) = 148",
             "CraftUI.countSlider (slot 0x0105ef9c) = 164"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_mjview_touch.txt",
            ["OBJC_IVAR_$_MJView.subviews (slot 0x0105cda8) = 44",
             "countByEnumeratingWithState:objects:count:"])
    require(ROOT / "reconstruction/reverse-v3/native/INPUT_FRONT.md",
            ["the MJ toolkit", "three-layer picture"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_gameuiview_all.txt",
            ["OBJC_IVAR_$_GameUIView.displayed (slot 0x0105dee0) = 4",
             "OBJC_IVAR_$_GameUIView.resourcesLoaded (slot 0x0105c494) = 16"])
    require(ROOT / "reconstruction/recovered/artificial_light_full.h", [
        "READ ORDER is ARM-attested",
        "maxRed",
        "downlight_forces_direction",
        "diameter",
    ])
    require(ROOT / "tools/specials_arm_bridge.cpp", [
        "{21, kArtificialLight, 9, \"addToTiles\", \"isClient,addToTiles\",",
        "0x0002468A",
    ])
    # Painting's pinned structure (MODEL: 52) + the harness's five entries
    require(ROOT / "tools/test_specials_arm.py", [
        ELF_SHA,
        "0x00D18834",  # SteamTrain
        "0x00A34B18",  # OwnershipSign
        "0x00AA81E8",  # Painting
        "0x0079D538",  # DropBear
        "0x00D538CC",  # CaveTroll
    ])
    # CMake registration
    require(ROOT / "reconstruction/recovered/CMakeLists.txt",
            ["specials_arm_evidence"])

    if a.elf is not None:
        out = ROOT / "build-specials-evidence"
        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools/test_specials_arm.py"),
             str(a.elf), "--output-dir", str(out)],
            capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            return 1
        print("specials-arm: PASS (differential executed, modelled cases match)")
        return 0

    print("specials-arm: PASS (constants; run with --elf to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
