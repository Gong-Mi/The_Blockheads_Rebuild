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
        "('UIManager', 72, 0x00AD7748",  # the input-front router entry
        "('MJControl', 70, 0x009F6894",  # the UI front's first differential class
        "('MJView', 71, 0x006614A8",     # the view gates
        "recovered_ui_seq", "UI_CASES",
        # the router's block-chain fixture surface: per-receiver answers
        # ('ret1'), the uiViews enumeration batch ('views'/'enum_recv') and
        # the fixture switch that feeds them
        "ui_fixture", "enum_recv",
        "startTouch:tapCount:paused:index:']}}",  # case 16's paused answer
        "touchIsInViewAtAll:']}}",                # case 14/18's in-view answer
        "hidePauseUI@148 set: the pauseUI block returns 1, no call",
        # the CraftUI panel: the five entries + the order proof
        "('CraftUIRect', 73, 0x00B80EB4",
        "('CraftUIInUI', 74, 0x00B81030",
        "('CraftUIPress', 75, 0x00B81248",
        "('CraftUIMove', 76, 0x00B8146C",
        "('CraftUIEnd', 77, 0x00B81608",
        "expect_recv", "CHILD_SB, CHILD_CB, CHILD_CS",
        "CHILD_CB, CHILD_CS, CHILD_SB",
        # the DPad panel: the forward + the rotated hit test, with the
        # platform-libm sinf/cosf stand-in
        "('DPadInUI', 78, 0x0070561C",
        "('DPadRect', 79, 0x0070567C",
        "def dpad_frame(rs, wx8, wy, w10, w14, w1c):",
        "elif name in ('sinf', 'cosf'):",
        # the BlockheadUI panel: the rect + the gated children OR
        "('BlockheadUIRect', 80, 0x006FD188",
        "('BlockheadUIInUI', 81, 0x006FD314",
        "('BlockheadUIPress', 82, 0x006FD69C",
        "('BlockheadUIMove', 83, 0x006FDA2C",
        "('BlockheadUIEnd', 84, 0x006FDCA8",
        "def blockhead_frame(wx, wy, ox, oy):",
        "def bh_seeds(sd):",
        "gate: no sleep/med",
        # the constant-verdict panels + the shared seeds helper
        "('MapUIRect', 85, 0x009CB460",
        "('MainMenuUIInUI', 96, 0x00A09D70",
        "def cv_seeds(off):",
        "the constant-verdict fixture",
        # the WorkbenchProgressBarUI panel
        "('WPBarUIRect', 97, 0x00734850",
        "def wpb_seeds(wx, wy, ox, oy):",
        # the CameraUI panel
        "('CameraUIRect', 102, 0x009D6054",
        "def cam_seeds():",
        # the PetUI panel
        "('PetUIRect', 107, 0x0080F9E0",
        "def pet_seeds(wx, wy, ox, oy):",
        # the WearUI panel
        "('WearUIRect', 112, 0x0088A7EC",
        "def wear_seeds(w=200.0, h=100.0",
        # the RegenerateUI panel
        "('RegenerateUIRect', 117, 0x009D2E94",
        "def regen_seeds():",
        # the TradingPostBuyUI panel
        "('TPBuyUIRect', 122, 0x00713EB4",
        "def tpb_seeds(closed=0):",
        # the SoundOptionsUI panel
        "('SoundOptionsUIRect', 127, 0x00AE122C",
        "def snd_seeds():",
        # the InventoryFullUI panel
        "('InventoryFullUIRect', 132, 0x00CAC4C4",
        "def inv_seeds():",
        # the FreeOfferUI panel
        "('FreeOfferUIRect', 137, 0x00DAFF70",
        "def fof_seeds():",
        # the AddCreditUI panel
        "('AddCreditUIRect', 142, 0x00D3533C",
        "def ac_seeds(in_progress=0):",
        # the ControlOptionsUI panel
        "('ControlOptionsUIRect', 147, 0x006DA870",
        "def co_seeds():",
        # the HungerUI panel
        "('HungerUIRect', 152, 0x0063D524",
        "def hgr_seeds(wx=0.0, wy=0.0, ox=0.0, oy=0.0):",
        # the JetPackUI panel
        "('JetPackUIRect', 157, 0x00B58D54",
        "def jpk_seeds(wx=0.0, wy=0.0, ox=0.0, oy=0.0):",
        # the SleepProgressUI panel
        "('SleepProgressUIRect', 162, 0x00B36E90",
        "def slp_seeds(wx=0.0, wy=0.0, ox=0.0, oy=0.0, med=0):",
        # the AddFuelUI panel
        "('AddFuelUIRect', 167, 0x009B784C",
        "def afu_seeds(wx=0.0, wy=0.0, ox=0.0, oy=0.0):",
        # the PaintMixUI panel
        "('PaintMixUIRect', 172, 0x006723E8",
        "def pmm_seeds(wx=0.0, wy=0.0, ox=0.0, oy=0.0):",
        # PauseUI's second batch
        "('PauseUIInUI2', 177, 0x009E8EF0",
        "def pau_seeds(opt=0, share=0, disabled=0):",
        # ShareUI's second batch
        "('ShareUIPress2', 181, 0x009C3344",
        "def su_seeds():",
        # OptionsUI's second batch
        "('OptionsUIPress2', 184, 0x008478C8",
        "def opt_seeds(case):",
        # MainMenuUI's press batch
        "('MainMenuUIPress2', 187, 0x00A09DF0",
        "def mm_seeds(case):",
    ])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_uimanager_starttouch.txt",
            ["startTouch:tapCount:index:"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_pauseui_touch2.txt",
            ["PauseUI -[touch family 2]", "implementation: 0x009e8ef0",
             "boundary: 0x009e9b10"])
    require(ROOT / "reconstruction/reverse-v3/native/INPUT_FRONT.md",
            ["tcUI@32", "currentTouchIsInAnyButtons@154", "hidePauseUI@148",
             "run_ui_router", "19 cases", "children's OR ONLY",
             "CB, CS, SB", "rotated-diamond hit test", "0xBF490FDB",
             "stopButtonDisplayed@76"])
    require(ROOT / "reconstruction/recovered/ui_touch_router.h",
            ["run_ui_router", "RouterInputs", "RouterTrace",
             "current_touch_is_in_any_buttons", "hide_pause_ui",
             "craftui_touch_is_in_view_at_all", "craftui_move_touch",
             "dpad_touch_is_in_view_at_all", "DPadFrame",
             "blockheadui_touch_is_in_view_at_all", "BlockheadChildren",
             "blockheadui_start_touch", "blockheadui_move_touch",
             "blockheadui_end_touch", "kMapUiRect", "kMainMenuUiInUi",
             "wbpbarui_touch_is_in_view_at_all",
             "kWorkbenchProgressBarInUi", "cameraui_touch_is_in_ui",
             "cameraui_end_touch", "petui_touch_is_in_view_at_all",
             "petui_end_touch", "wearui_touch_is_in_view_at_all",
             "wearui_end_touch", "regenerateui_touch_is_in_view_at_all",
             "regenerateui_end_touch",
             "tpbuyui_touch_is_in_view_at_all", "tpbuyui_end_touch",
             "soundoptionsui_start_touch", "soundoptionsui_end_touch",
             "inventoryfullui_touch_is_in_view_at_all",
             "kInventoryFullUiInUi", "freeofferui_start_touch",
             "freeofferui_move_touch", "freeofferui_end_touch",
             "addcredit_ui_start_touch", "addcredit_ui_end_touch",
             "kAddCreditUiInUi", "controloptionsui_start_touch",
             "controloptionsui_end_touch", "kControlOptionsUiInUi",
             "hungerui_touch_is_in_view_at_all", "hungerui_end_touch",
             "jetpackui_touch_is_in_view_at_all", "jetpackui_end_touch",
             "sleepprogressui_touch_is_in_view_at_all",
             "sleepprogressui_end_touch", "addfuelui_touch_is_in_view_at_all",
             "addfuelui_end_touch", "paintmixui_touch_is_in_view_at_all",
             "paintmixui_end_touch", "pauseui_touch_is_in_ui",
             "pauseui_end_touch", "shareui_start_touch",
             "shareui_end_touch", "optionsui_start_touch",
             "optionsui_end_touch", "mainmenuui_start_touch"])
    require(ROOT / "reconstruction/recovered/ui_touch_router.cpp",
            ["startTouch:tapCount:paused:index:", "import(memset)",
             "touchIsInViewAtAll:", "x > -130.0f && x < 130.0f",
             "0xBF490FDBu", "y > -144.0f && y < 142.0f",
             "blockhead_move_end_chain"])
    require(ROOT / "tools/test_ui_touch_router.cpp",
            ["block chain x19", "touchIsInViewAtAll:", "craftui x16",
             "dpad x11", "blockhead x28", "const x17", "wpbar x11",
             "camera x10", "pet x13", "wear x14", "regen x14",
             "tpbuy x18", "sound x7", "invfull x12", "freeoffer x9",
             "addcredit x10", "ctrlopts x7", "hunger x13",
             "jetpack x15", "sleepprog x19", "addfuel x15",
             "paintmix x19", "pauseui2 x16", "shareui2 x3",
             "optionsui2 x12", "mainmenu x10"])
    # the constant-verdict listings
    require(ROOT / "reconstruction/reverse-v3/native/disasm_mapui_touch.txt",
            ["MapUI -[touch family]", "implementation: 0x009cb460"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_mainmenuui_rect.txt",
            ["OBJC_IVAR_$_MainMenuUI.windowInfo (slot 0x0105e770) = 128"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_dpad_touch.txt",
            ["touchIsInViewAtAll:",
             "OBJC_IVAR_$_DPad.rightSide (slot 0x0105d31c) = 160",
             "OBJC_IVAR_$_DPad.windowInfo (slot 0x0105d340) = 112"])
    # the BlockheadUI batch's first evidence artifacts (the decode front
    # that follows the DPad one)
    require(ROOT / "reconstruction/reverse-v3/native/disasm_blockheadui_touch.txt",
            ["BlockheadUI -[touch block]",
             "implementation: 0x006fd188",
             "boundary: 0x006fd69c"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_blockheadui_starttouch.txt",
            ["implementation: 0x006fd69c",
             "boundary: 0x006fda2c"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_blockheadui_moveend.txt",
            ["implementation: 0x006fda2c",
             "boundary: 0x006fdf24"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_craftui_touch.txt",
            ["OBJC_IVAR_$_CraftUI.scrollingButtons (slot 0x0105ef50) = 148",
             "OBJC_IVAR_$_CraftUI.craftButton (slot 0x0105ef6c) = 208"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_craftui_starttouch.txt",
            ["CraftUI.scrollingButtons (slot 0x0105ef50) = 148",
             "CraftUI.countSlider (slot 0x0105ef9c) = 164"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_tableviewui_touch.txt",
            ["OBJC_IVAR_$_TableViewUI.extraControlWasTouched (slot 0x0105d274) = 98"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_scrollingbuttons_touch.txt",
            ["OBJC_IVAR_$_ScrollingButtons.xScroll (slot 0x0105d5e8) = 104"])
    require(ROOT / "reconstruction/reverse-v3/native/disasm_mjview_touch.txt",
            ["OBJC_IVAR_$_MJView.subviews (slot 0x0105cda8) = 44",
             "countByEnumeratingWithState:objects:count:"])
    require(ROOT / "reconstruction/reverse-v3/native/INPUT_FRONT.md",
            ["the MJ toolkit", "three-layer picture"])
    require(ROOT / "tools/specials_arm_bridge.cpp",
            ["recovered_ui_seq", "recovered_ui_ret", "ui_control.h",
             "ui_touch_router.h", "run_ui_router", "ui_router_case",
             "ui_router_seeds", "ui_router_seeds(out, case_id)",
             "craftui_trace", "craftui_seeds", "craftui_child",
             "dpad_point_for", "dpad_seeds", "dpad_touch_is_in_view_at_all",
             "blockhead_seeds", "blockhead_children_for", "blockhead_sd",
             "constant_panel_seeds", "constant_panel_ret",
             "wpb_seeds_for", "cam_child", "cam_seeds_for",
             "pet_child", "pet_seeds_for", "wear_child", "wear_seeds_for",
             "regen_child", "regen_point", "tpb_child", "tpb_seeds_for",
             "snd_seeds_for", "inv_seeds_for", "inv_point",
             "fof_seeds_for", "fof_buys", "ac_seeds_for",
             "ac_in_progress", "co_seeds_for", "hgr_seeds_for",
             "hgr_child", "jpk_seeds_for", "jpk_child", "slp_seeds_for",
             "slp_child", "slp_med", "afu_seeds_for", "afu_hit_index",
             "pmm_seeds_for", "pmm_child", "pmm_level", "pau_seeds_for",
             "pau_opt", "pau_share_c", "su_seeds_for", "opt_seeds_for",
             "opt_child", "mm_seeds_for", "mm_selection"])
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
        # the run's own report pins the case totals: 35 modelled + 335 UI
        # rows (router 19 + CraftUI 16 + DPad 11 + BlockheadUI 28 +
        # const 17 + WPBar 11 + Camera 10 + Pet 13 + Wear 14 + Regen 14 +
        # TPBuy 18 + Sound 7 + InvFull 12 + FreeOffer 9 + AddCredit 10 +
        # CtrlOpts 7 + Hunger 13 + JetPack 15 + SleepProg 19 + AddFuel 15
        # + PaintMix 19 + PauseUI2 16 + ShareUI2 3 + OptionsUI2 12
        # + MainMenu 10 + MJControl 3 + MJView 4)
        import json
        report = json.loads((out / "specials-arm-result.json").read_text())
        assert report["cases"] == 380, report["cases"]
        assert report["match"] is True
        ui_rows = [r for r in report["rows"] if r["class"] == "UIManager"]
        assert len(ui_rows) == 19, len(ui_rows)
        assert {f'0x{r["arm_return"][-1]}' for r in ui_rows
                if r["case"] in (7, 8, 10, 11, 13, 16, 17)} == {'0x1'}
        craftui_rows = [r for r in report["rows"]
                        if r["class"].startswith("CraftUI")]
        assert len(craftui_rows) == 16, len(craftui_rows)
        dpad_rows = [r for r in report["rows"]
                     if r["class"].startswith("DPad")]
        assert len(dpad_rows) == 11, len(dpad_rows)
        blockhead_rows = [r for r in report["rows"]
                          if r["class"].startswith("BlockheadUI")]
        assert len(blockhead_rows) == 28, len(blockhead_rows)
        const_rows = [r for r in report["rows"]
                      if r["class"].startswith(("MapUI", "OptionsUI",
                                                "ShareUI", "PauseUI",
                                                "MainMenuUI"))
                      and not r["class"].endswith("2")]
        assert len(const_rows) == 17, len(const_rows)
        # the const-1 panels must answer 1 for the far point too
        # (MapUIRect's far case is the const-0 control)
        far = {r["class"]: r["arm_return"] for r in const_rows
               if r["case"] == 1 and r["class"] != "MapUIRect"}
        assert far and all(v == '0x00000001' for v in far.values()), far
        wpbar_rows = [r for r in report["rows"]
                      if r["class"].startswith("WPBarUI")]
        assert len(wpbar_rows) == 11, len(wpbar_rows)
        cam_rows = [r for r in report["rows"]
                    if r["class"].startswith("CameraUI")]
        assert len(cam_rows) == 10, len(cam_rows)
        pet_rows = [r for r in report["rows"]
                    if r["class"].startswith("PetUI")]
        assert len(pet_rows) == 13, len(pet_rows)
        wear_rows = [r for r in report["rows"]
                     if r["class"].startswith("WearUI")]
        assert len(wear_rows) == 14, len(wear_rows)
        regen_rows = [r for r in report["rows"]
                      if r["class"].startswith("RegenerateUI")]
        assert len(regen_rows) == 14, len(regen_rows)
        tpb_rows = [r for r in report["rows"]
                    if r["class"].startswith("TPBuyUI")]
        assert len(tpb_rows) == 18, len(tpb_rows)
        snd_rows = [r for r in report["rows"]
                    if r["class"].startswith("SoundOptionsUI")]
        assert len(snd_rows) == 7, len(snd_rows)
        inv_rows = [r for r in report["rows"]
                    if r["class"].startswith("InventoryFullUI")]
        assert len(inv_rows) == 12, len(inv_rows)
        fof_rows = [r for r in report["rows"]
                    if r["class"].startswith("FreeOfferUI")]
        assert len(fof_rows) == 9, len(fof_rows)
        ac_rows = [r for r in report["rows"]
                   if r["class"].startswith("AddCreditUI")]
        assert len(ac_rows) == 10, len(ac_rows)
        co_rows = [r for r in report["rows"]
                   if r["class"].startswith("ControlOptionsUI")]
        assert len(co_rows) == 7, len(co_rows)
        hgr_rows = [r for r in report["rows"]
                    if r["class"].startswith("HungerUI")]
        assert len(hgr_rows) == 13, len(hgr_rows)
        jpk_rows = [r for r in report["rows"]
                    if r["class"].startswith("JetPackUI")]
        assert len(jpk_rows) == 15, len(jpk_rows)
        slp_rows = [r for r in report["rows"]
                    if r["class"].startswith("SleepProgressUI")]
        assert len(slp_rows) == 19, len(slp_rows)
        afu_rows = [r for r in report["rows"]
                    if r["class"].startswith("AddFuelUI")]
        assert len(afu_rows) == 15, len(afu_rows)
        pmm_rows = [r for r in report["rows"]
                    if r["class"].startswith("PaintMixUI")]
        assert len(pmm_rows) == 19, len(pmm_rows)
        pau2_rows = [r for r in report["rows"]
                     if r["class"] in ("PauseUIInUI2", "PauseUIPress2",
                                       "PauseUIMove2", "PauseUIEnd2")]
        assert len(pau2_rows) == 16, len(pau2_rows)
        su2_rows = [r for r in report["rows"]
                    if r["class"] in ("ShareUIPress2", "ShareUIMove2",
                                      "ShareUIEnd2")]
        assert len(su2_rows) == 3, len(su2_rows)
        opt2_rows = [r for r in report["rows"]
                     if r["class"] in ("OptionsUIPress2", "OptionsUIMove2",
                                       "OptionsUIEnd2")]
        assert len(opt2_rows) == 12, len(opt2_rows)
        mm_rows = [r for r in report["rows"]
                   if r["class"] == "MainMenuUIPress2"]
        assert len(mm_rows) == 10, len(mm_rows)
        print("specials-arm: PASS (differential executed, modelled cases "
              "match; router 19/19, craftui 16/16, dpad 11/11, "
              "blockhead 28/28, const 17/17, wpbar 11/11, camera 10/10, "
              "pet 13/13, wear 14/14, regen 14/14, tpbuy 18/18, "
              "sound 7/7, invfull 12/12, freeoffer 9/9, "
              "addcredit 10/10, ctrlopts 7/7, hunger 13/13, "
              "jetpack 15/15, sleepprog 19/19, addfuel 15/15, paintmix 19/19, "
              "pauseui2 16/16, shareui2 3/3, optionsui2 12/12, mainmenu 10/10)")
        return 0

    print("specials-arm: PASS (constants; run with --elf to execute)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
