#!/usr/bin/env python3
"""Validate checked-in reverse-v3 evidence without requiring the copyrighted APK."""

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction" / "reverse-v3" / "native"


def _normalise(s: str) -> str:
    """Strip markdown emphasis/backticks and collapse whitespace before comparing a needle.

    A phrase that reads as one sentence in review can be split across two lines in the file, or carry
    `*emphasis*` / `**bold**` / backticks inside it. Three separate times an author-side formatting
    difference like that failed the gate on a *correct* document, which teaches the wrong lesson:
    rewrite the check, not the prose. Matching is therefore on normalised text.
    """
    return re.sub(r"\s+", " ", re.sub(r"[`*_]", "", s)).strip()


def require(path: Path, needles: list[str]) -> None:
    if not path.is_file():
        raise SystemExit(f"missing evidence file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    hay = _normalise(text)
    missing = [needle for needle in needles if _normalise(needle) not in hay]
    if missing:
        raise SystemExit(
            f"{path.relative_to(ROOT)} is missing required evidence: {missing}"
        )


def main() -> None:
    # a local build cannot see a file that was never committed; git can (see the guard's docstring)
    subprocess.run([sys.executable, str(ROOT / "tools/check_cmake_sources_tracked.py")], check=True)


    methods = NATIVE / "libApplication_objc_methods.tsv"
    lines = methods.read_text(encoding="utf-8").splitlines()
    if lines[0] != "implementation\tclass\tkind\tselector\ttypes":
        raise SystemExit("Objective-C method map header changed")
    if len(lines) != 10479:
        raise SystemExit(f"Objective-C method map count changed: {len(lines) - 1}")

    require(
        methods,
        [
            "0x00555a84\tWorld\tinstance\tsaveAll\t",
            "0x00557c40\tWorld\tinstance\tloadGame\t",
            "0x0055b698\tWorld\tinstance\tinitializeDatabases\t",
            "0x00859a84\tWorldTileLoader\tinstance\tsavePhysicalBlock:",
            "0x008b29bc\tDynamicWorld\tinstance\tsaveGameWithWorldData:",
            "0x00aa51b8\tDatabaseConvertor\tinstance\tconvertWorld\t",
        ],
    )
    require(
        methods,
        [
            "0x0092c148\tGameView\tinstance\tmoveTouch:\tv16@0:4{CGPoint=ff}8",
            "0x005b3278\tWorld\tinstance\tmoveTouch:index:\tv20@0:4{CGPoint=ff}8i16",
            "0x00ad8048\tUIManager\tinstance\tmoveTouch:index:\tv20@0:4{CGPoint=ff}8i16",
            "0x0092c3f4\tGameView\tinstance\tendTouch:\tv16@0:4{CGPoint=ff}8",
            "0x005b3430\tWorld\tinstance\tendTouch:index:\tv20@0:4{CGPoint=ff}8i16",
            "0x005b3308\tWorld\tinstance\tdoEndTouch:wasCancelled:index:\tv24@0:4{CGPoint=ff}8c16i20",
            "0x0092cdd8\tGameView\tinstance\tendSecondaryTouch:\tv16@0:4{CGPoint=ff}8",
            "0x0092cfa0\tGameView\tinstance\tcancelSecondaryTouch:\tv16@0:4{CGPoint=ff}8",
        ],
    )
    require(
        NATIVE / "gameview_endtouch.json",
        [
            '"batch": "GameView endTouch: -> World endTouch:index: -> doEndTouch:wasCancelled:index: forwarding"',
            '"verified_interval_words": 145',
            '"verified_interval_words": 33',
            '"apk_integration": false',
            '"original_runtime_differential": false',
        ],
    )
    require(
        NATIVE / "disasm_gameview_endtouch.txt",
        ["# GameView -[endTouch:]", "# implementation: 0x0092c3f4", "# ARM.exidx end: 0x0092c638"],
    )
    require(
        NATIVE / "disasm_world_endtouch_index.txt",
        ["# World -[endTouch:index:]", "# implementation: 0x005b3430", "# ARM.exidx end: 0x005b34b4"],
    )
    require(
        NATIVE / "GAMEVIEW_ENDTOUCH.md",
        ["0x0092c4a4", "0x0092c5d4", "0x005b34a0", "does not call these recovered methods"],
    )
    require(
        NATIVE / "gameview_canceltouch_batch.json",
        [
            '"batch": "GameView cancelTouch: -> World cancelTouch:index: -> doEndTouch:wasCancelled:1 (tail-merge of the World forwarding pair)"',
            '"verified_interval_words": 153',
            '"verified_interval_words": 33',
            '"world_forwarding_pair_tail_merge": true',
            '"apk_integration": false',
            '"original_runtime_differential": false',
        ],
    )
    require(
        NATIVE / "disasm_world_canceltouch_index.txt",
        ["# World -[cancelTouch:index:]", "# implementation: 0x005b33ac", "# ARM.exidx end: 0x005b3430"],
    )
    require(
        NATIVE / "GAMEVIEW_CANCELTOUCH_BATCH.md",
        ["0x005b33ac", "wasCancelled", "Tail-merge", "0x92c6e8"],
    )
    require(
        NATIVE / "gameview_secondarytouch.json",
        [
            '"batch": "GameView secondary end/cancel pair (mirror of the primary pair: secondaryTouchStarted gate, index literal 1, secondary tail clear)"',
            '"verified_interval_words": 114',
            '"verified_interval_words": 122',
            '"index: primary forwards literal 0, secondary forwards literal 1"',
            '"apk_integration": false',
            '"original_runtime_differential": false',
        ],
    )
    require(
        NATIVE / "disasm_gameview_endsecondarytouch.txt",
        ["# GameView -[endSecondaryTouch:]", "# implementation: 0x0092cdd8", "# ARM.exidx end: 0x0092cfa0"],
    )
    require(
        NATIVE / "disasm_gameview_cancelsecondarytouch.txt",
        ["# GameView -[cancelSecondaryTouch:]", "# implementation: 0x0092cfa0", "# ARM.exidx end: 0x0092d188"],
    )
    require(
        NATIVE / "GAMEVIEW_SECONDARYTOUCH.md",
        ["secondaryTouchStarted", "0x0092cdd8", "0x0092cfa0", "secondary forwards 1"],
    )
    require(
        NATIVE / "gameview_movetouch.json",
        [
            '"batch": "GameView moveTouch: -> World moveTouch:index: forwarding tail"',
            '"verified_interval_words": 171',
            '"verified_interval_words": 36',
            '"apk_integration": false',
            '"original_runtime_differential": false',
        ],
    )
    require(
        NATIVE / "disasm_gameview_movetouch.txt",
        ["# GameView -[moveTouch:]", "# implementation: 0x0092c148", "# ARM.exidx end: 0x0092c3f4"],
    )
    require(
        NATIVE / "disasm_world_movetouch.txt",
        ["# World -[moveTouch:index:]", "# implementation: 0x005b3278", "# ARM.exidx end: 0x005b3308"],
    )
    require(
        NATIVE / "GAMEVIEW_MOVETOUCH.md",
        ["0x0092c1f8", "0x0092c304", "0x005b32f0", "does not call these recovered methods"],
    )
    require(
        NATIVE / "refs_world_lifecycle.tsv",
        [
            "%@/saves/%@/worldv2",
            "%@/saves/%@/world_db/",
            "initWithPath:maxDatabases:maxMapSizeInMB:",
            "initWithWorld:worldDatabase:dynamicObjectDatabase:blockDatabase:",
        ],
    )
    require(
        NATIVE / "refs_persistence.tsv",
        [
            "dynamicObjectIDCount",
            "%@_worldv2",
            "%@_blockheads",
            "%@_blockhead_%lld_inventory",
            "gzipDeflate",
            "compressedBlock",
            "physicalBlock",
        ],
    )
    require(
        NATIVE / "refs_tile_storage.tsv",
        [
            "%d_%d_compressedBlock",
            "gzipInflate",
            "dataForKey:",
            "setData:forKey:",
        ],
    )
    require(
        NATIVE / "disasm_world_lifecycle.txt",
        [
            "# World -[saveAll]",
            "# World -[loadGame]",
            "# World -[initializeDatabases]",
            "# ARM.exidx end:",
        ],
    )
    require(
        NATIVE / "disasm_persistence.txt",
        [
            "# DynamicWorld -[saveGameWithWorldData:signOwnershipData:]",
            "# DatabaseConvertor -[convertWorld]",
        ],
    )
    require(
        NATIVE / "disasm_tile_storage.txt",
        [
            "# WorldTileLoader -[savePhysicalBlock:macroTile:sendToClients:server:sendReliably:]",
            "# WorldTileLoader -[loadPhysicalBlock:atXPos:yPos:createIfNotCreated:]",
        ],
    )
    require(
        ROOT / "app/src/main/cpp/original_save_format.h",
        [
            "kOriginalTileSize = 64",
            "kTileBytesPerPhysicalBlock",
            "physicalBlockField13",
            "physicalBlockField24",
        ],
    )
    require(
        ROOT / "app/src/main/cpp/original_save_format.cpp",
        [
            "exactly 65541 bytes",
            "inflateInit2(&stream, MAX_WBITS + 16)",
        ],
    )
    require(
        NATIVE / "STATIC_RENDER_CONTRACT.md",
        [
            "723 files",
            "32×32 atlas",
            "BlockTransparent",
            "lightmap UV",
            "Evidence levels",
        ],
    )
    require(
        NATIVE / "disasm_draw_frame.txt",
        [
            "# EvolutionViewController -[drawFrame]",
            "# implementation: 0x00781a44",
            "# ARM.exidx end: 0x00781eb0",
        ],
    )
    require(
        NATIVE / "refs_draw_frame.tsv",
        [
            "implementation\tclass\tmethod\treference_kind\treference_address\tvalue",
            "0x00781a44\tEvolutionViewController\tdrawFrame\tselector",
            "initOpenGL",
            "preUpdate:",
            "update:accurateDT:",
            "render:",
            "presentFramebuffer",
        ],
    )
    require(
        NATIVE / "disasm_dynamic_world_update.txt",
        [
            "# DynamicWorld -[update:accurateDT:isSimulation:]",
            "# implementation: 0x008cbf40",
            "# ARM.exidx end:",
        ],
    )
    require(
        NATIVE / "refs_dynamic_world_update.tsv",
        [
            "0x008cbf40\tDynamicWorld\tupdate:accurateDT:isSimulation:\tselector",
            "removeObject:",
            "addObject:",
            "updateNetObjects",
            "updateRain:dt:",
            "worldChanged:",
        ],
    )
    require(
        NATIVE / "GAMEVIEW_INIT.md",
        [
            "0x0091c780",
            "0x0091d9cc",
            "1171",
            "0x0105faf4",
            "initWithPath:maxDatabases:maxMapSizeInMB:",
            "reconnectWithAuthenticationDelegate:",
            "totalGamePlayTimePassed",
        ],
    )
    require(
        NATIVE / "disasm_gameview_init.txt",
        [
            "# GameView -[init]",
            "# implementation: 0x0091c780",
            "# ARM.exidx end: 0x0091d9cc",
        ],
    )
    require(
        NATIVE / "gameview_init.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"blx_sites\": 60",
            "\"selector_resolved_calls\": 21",
            "NSSearchPathForDirectoriesInDomains",
            "__wrap_exit",
        ],
    )
    require(
        NATIVE / "WORLD_STARTTOUCH.md",
        [
            "0x005b31b8",
            "0x005b3278",
            "OBJC_IVAR_$_World.pauseIdleTimer",
            "OBJC_IVAR_$_World.uiManager",
            "startTouch:tapCount:index:",
            "sxtb",
        ],
    )
    require(
        NATIVE / "disasm_world_starttouch.txt",
        [
            "# World -[startTouch:tapCount:index:]",
            "# implementation: 0x005b31b8",
            "# ARM.exidx end: 0x005b3278",
        ],
    )
    require(
        NATIVE / "world_starttouch.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 48",
            "\"branch_count\": 0",
            "\"msgsend_stub\": \"0x001c281c\"",
            "OBJC_IVAR_$_World.pauseIdleTimer",
        ],
    )
    require(
        NATIVE / "GAMEVIEW_TOUCHISINUI.md",
        [
            "0x0092bc54",
            "0x0092be2c",
            "118",
            "0x0105faf4",
            "R_ARM_JUMP_SLOT  objc_msgSend",
            "loadComplete",
            "isSimulating",
        ],
    )
    require(
        NATIVE / "disasm_gameview_touchisinui.txt",
        [
            "# GameView -[touchIsInUI:]",
            "# implementation: 0x0092bc54",
            "# ARM.exidx end: 0x0092be2c",
        ],
    )
    require(
        NATIVE / "gameview_touchisinui.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"msgsend_stub\": \"0x001c281c\"",
            "\"verified_words\": 118",
            "OBJC_IVAR_$_GameView.mainMenuUI",
        ],
    )
    require(
        NATIVE / "GAMEVIEW_CANCELTOUCH.md",
        [
            "0x0092c638",
            "0x0092c89c",
            "153",
            "0x0105faf4",
            "cancelTouch:index:",
            "startTouchHasntMoved",
            "endTouch:",
        ],
    )
    require(
        NATIVE / "disasm_gameview_canceltouch.txt",
        [
            "# GameView -[cancelTouch:]",
            "# implementation: 0x0092c638",
            "# ARM.exidx end: 0x0092c89c",
        ],
    )
    require(
        NATIVE / "gameview_canceltouch.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"msgsend_stub\": \"0x001c281c\"",
            "\"verified_words\": 153",
            "OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI",
        ],
    )
    require(
        NATIVE / "WORLDTILELOADER_REFINETERRAINCOUNT.md",
        [
            "0x00854c18",
            "0x00854c54",
            "15 words",
            "0x0105faf4",
            "OBJC_IVAR_$_WorldTileLoader.refineTerrainCount",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_refineterraincount.txt",
        [
            "# WorldTileLoader -[refineTerrainCount]",
            "# implementation: 0x00854c18",
            "# ARM.exidx end: 0x00854c54",
        ],
    )
    require(
        NATIVE / "worldtileloader_refineterraincount.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 15",
            "OBJC_IVAR_$_WorldTileLoader.refineTerrainCount",
        ],
    )
    require(
        NATIVE / "WORLDTILELOADER_FAULTOFFSET.md",
        [
            "0x00856d18",
            "0x00857188",
            "284 words",
            "worldWidthMacro",
            "getX:Y:octaves:",
            "heightNoiseFunctionB",
            "faultNoiseFunction",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_faultoffset.txt",
        [
            "# WorldTileLoader -[faultOffsetForX:y:]",
            "# implementation: 0x00856d18",
            "# ARM.exidx end: 0x00857188",
        ],
    )
    require(
        NATIVE / "worldtileloader_faultoffset.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 284",
            "OBJC_IVAR_$_WorldTileLoader.faultNoiseFunction",
            "OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB",
            "__wrap_powf",
        ],
    )
    require(
        NATIVE / "WORLDTILELOADER_ISCAVE.md",
        [
            "0x00857f48",
            "0x00858320",
            "246 words",
            "customRules",
            "caveNoiseFunctionA",
            "caveNoiseFunctionB",
            "yHeightDivider",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_iscave.txt",
        [
            "# WorldTileLoader -[isCaveForX:y:faultOffset:]",
            "# implementation: 0x00857f48",
            "# ARM.exidx end: 0x00858320",
        ],
    )
    require(
        NATIVE / "worldtileloader_iscave.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 246",
            "OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionA",
            "OBJC_IVAR_$_WorldTileLoader.caveNoiseFunctionB",
            "objc_msgSend_stret",
        ],
    )
    require(
        NATIVE / "WORLDTILELOADER_REFINETERRAIN.md",
        [
            "0x00854c54",
            "0x00855ad0",
            "927 words",
            "refineTerrainCount",
            "hasRefinedTerrain",
            "isCaveForX:y:faultOffset:",
            "recursivelyFlowOutWaterFromTile:atPos:",
            "NSAutoreleasePool",
        ],
    )
    require(
        NATIVE / "WORLDTILELOADER_GETROCKDIRT.md",
        [
            "0x00857188",
            "0x00857340",
            "110 words",
            "worldWidthMacro",
            "rockHeights",
            "dirtHeights",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_getrockdirt.txt",
        [
            "# WorldTileLoader -[getRockAndDirtHeightforX:rockHeight:dirtHeight:]",
            "# implementation: 0x00857188",
            "# ARM.exidx end: 0x00857340",
        ],
    )
    require(
        NATIVE / "worldtileloader_getrockdirt.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 110",
            "OBJC_IVAR_$_WorldTileLoader.rockHeights",
            "OBJC_IVAR_$_WorldTileLoader.dirtHeights",
        ],
    )
    require(
        NATIVE / "WORLDTILELOADER_COLUMN_HEIGHTS.md",
        [
            "0x00857a2c",
            "0x00857bf8",
            "0x00857dc8",
            "0x00857340",
            "return i + (flag != 0 ? 1 : 0)",
            "lakeHeights",
            "heightNoiseFunctionA",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_unmodifiedgroundlevel.txt",
        [
            "# WorldTileLoader -[unmodifiedGroundLevelForX:]",
            "# implementation: 0x00857a2c",
            "# ARM.exidx end: 0x00857bf8",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_maxofrockanddirt.txt",
        [
            "# WorldTileLoader -[maxOfRockAndDirtHeightForX:]",
            "# implementation: 0x00857bf8",
            "# ARM.exidx end: 0x00857dc8",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_lakeheight.txt",
        [
            "# WorldTileLoader -[lakeHeightForX:]",
            "# implementation: 0x00857dc8",
            "# ARM.exidx end: 0x00857f48",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_getcloudheight.txt",
        [
            "# WorldTileLoader -[getCloudHeightForX:]",
            "# implementation: 0x00857340",
            "# ARM.exidx end: 0x00857684",
        ],
    )
    require(
        NATIVE / "worldtileloader_column_heights.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 209",
            "0x3fc99999a0000000",
            "OBJC_IVAR_$_WorldTileLoader.heightNoiseFunctionB",
            "OBJC_IVAR_$_WorldTileLoader.lakeHeights",
            "getX:Y:octaves:",
        ],
    )
    require(
        NATIVE / "WORLDHELPER_SUNLIGHT.md",
        [
            "0x00a1b7d4",
            "0x00a1c680",
            "0x00a1ca64",
            "recursivelyRemoveAllSunLightWithList:",
            "containsIndex:",
            "_Z25worldIndexAtWorldPositioniiP5World",
            "minx:x-32 maxX:x+32",
        ],
    )
    require(
        NATIVE / "disasm_worldhelper_updatesunlight.txt",
        [
            "# WorldHelper +[updateSunLightForTile:atPos:world:]",
            "# implementation: 0x00a1b7d4",
            "# ARM.exidx end: 0x00a1bd10",
        ],
    )
    require(
        NATIVE / "disasm_worldhelper_updatesunlightremoved.txt",
        [
            "# WorldHelper +[updateSunLightRemovedForTile:atPos:world:]",
            "# implementation: 0x00a1c680",
            "# ARM.exidx end: 0x00a1ca64",
        ],
    )
    require(
        NATIVE / "worldhelper_sunlight.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 335",
            "OBJC_CLASS_$_NSMutableIndexSet",
            "recursivelyUpdateSunLightWithList:openIndices:world:",
            "0x00a156a8",
        ],
    )
    require(
        NATIVE / "WORLDHELPER_RECURSIVE_REMOVE.md",
        [
            "0x00a1bd10",
            "0x00a1c680",
            "604",
            "objectAtIndex:0",
            "level monotonicity",
            "minx",
            "0x00a18f68",
        ],
    )
    require(
        NATIVE / "disasm_worldhelper_recursiveremovesunlight.txt",
        [
            "# WorldHelper +[recursivelyRemoveAllSunLightWithList:openIndices:lightWasRemovedList:removeIndices:world:minx:maxX:]",
            "# implementation: 0x00a1bd10",
            "# ARM.exidx end: 0x00a1c680",
        ],
    )
    require(
        NATIVE / "worldhelper_recursiveremove.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 604",
            "OBJC_CLASS_$_NSNumber",
            "recalculateDrawBlockLightingForTile",
            "0x00a156a8",
        ],
    )
    require(
        NATIVE / "WORLDHELPER_RECURSIVE_UPDATE.md",
        [
            "0x00a19c0c",
            "0x00a1b7d4",
            "1778",
            "(+1,+1)",
            "torch kind `0x4b`",
            "createTreasureChestOrTroll",
            "0x00a18f68",
        ],
    )
    require(
        NATIVE / "disasm_worldhelper_recursiveupdatesunlight.txt",
        [
            "# WorldHelper +[recursivelyUpdateSunLightWithList:openIndices:world:]",
            "# implementation: 0x00a19c0c",
            "# ARM.exidx end: 0x00a1b7d4",
        ],
    )
    require(
        NATIVE / "worldhelper_recursiveupdate.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 1778",
            "saveSunlightChangedAtPos:",
            "addTorchAtPos:ofType:dataA:dataB:saveDict:placedByClient:",
            "0x00a15518",
        ],
    )
    require(
        NATIVE / "WORLDHELPER_RECALCULATE_LIGHTING.md",
        [
            "0x00a1ca64",
            "0x00a1d730",
            "819",
            "d2 >= 0x1e4",
            "0x422",
            "exploreLightChangedAtMacroPos",
            "updateSunLightForTile",
        ],
    )
    require(
        NATIVE / "disasm_worldhelper_recalculatelighting.txt",
        [
            "# WorldHelper +[recalculateLightingForPhysicalBlockIfNeeded:world:clientLightBlockIndex:forBlockhead:]",
            "# implementation: 0x00a1ca64",
            "# ARM.exidx end: 0x00a1d730",
        ],
    )
    require(
        NATIVE / "worldhelper_recalculatelighting.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 819",
            "getDayNightFractionForX:atWorldTime:",
            "currentTemperatureForTileAtWorldPos",
            "0x00a15404",
        ],
    )
    require(
        NATIVE / "ARTIFICIALLIGHT_TILES.md",
        [
            "0x00a92238",
            "0x00a93160",
            "0x00a93198",
            "0x00a93728",
            "970",
            "addedGrid",
            "0xdfff",
            "recursivelyUpdateLightWithList",
            "loadTroll",
        ],
    )
    require(
        NATIVE / "disasm_artificiallight_addtotiles.txt",
        [
            "# ArtificialLight -[addToTiles]",
            "# implementation: 0x00a92238",
            "# ARM.exidx end: 0x00a93160",
        ],
    )
    require(
        NATIVE / "disasm_artificiallight_removefromtiles.txt",
        [
            "# ArtificialLight -[removeFromTiles]",
            "# implementation: 0x00a93198",
            "# ARM.exidx end: 0x00a93728",
        ],
    )
    require(
        NATIVE / "artificiallight_tiles.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 970",
            "\"verified_words\": 356",
            "contributionGridOrigin",
            "0x00a14824",
            "tileRequiresGlowBlock",
        ],
    )
    require(
        NATIVE / "ARTIFICIALLIGHT_BLOCKLOAD.md",
        [
            "0x00a95248",
            "0x00a958bc",
            "413",
            "x-cylindrical",
            "removeFromTiles",
            "addToTiles",
            "0xe85518",
        ],
    )
    require(
        NATIVE / "disasm_artificiallight_addcontribution.txt",
        [
            "# ArtificialLight -[addContributionForPhysicalBlockLoadedAtXPos:yPos:]",
            "# implementation: 0x00a95248",
            "# ARM.exidx end: 0x00a958bc",
        ],
    )
    require(
        NATIVE / "artificiallight_blockload.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 413",
            "@selector(removeFromTiles)",
            "objc_msgSend function",
            "memset(self.contributionGrid",
        ],
    )
    require(
        NATIVE / "ARTIFICIALLIGHT_RECURSIVE_UPDATE.md",
        [
            "0x00a8f22c",
            "0x00a91d30",
            "2753",
            "max(r*5/6, 5)",
            "max(r*7/6, 7)",
            "lightDirection",
            "pop_front",
        ],
    )
    require(
        NATIVE / "disasm_artificiallight_recursiveupdate.txt",
        [
            "# ArtificialLight -[recursivelyUpdateLightWithList:]",
            "# implementation: 0x00a8f22c",
            "# ARM.exidx end: 0x00a91d30",
        ],
    )
    require(
        NATIVE / "artificiallight_recursiveupdate.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 2753",
            "lightDirection",
            "0x00a15518",
            "pop_front",
        ],
    )
    require(
        NATIVE / "LIGHT_EMITTERS.md",
        [
            "1301",
            "0x00a93bbc",
            "0x004be0d4",
            "253, 150, 55",
            "connectionType",
            "Torch.itemType",
        ],
    )
    require(
        NATIVE / "lightemitters.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 803",
            "\"verified_words\": 261",
            "@selector(lightColor)",
            "Torch.connectionType",
        ],
    )
    for _emit_file, _emit_imp in (
        ("disasm_artificiallight_lightcolor.txt", "# implementation: 0x00a93bbc"),
        ("disasm_fireobject_getlightrgb.txt", "# implementation: 0x006746a4"),
        ("disasm_glowblock_getlightrgb.txt", "# implementation: 0x00ca8334"),
        ("disasm_glowblock_lightpos.txt", "# implementation: 0x00ca955c"),
        ("disasm_glowblock_glowquadcount.txt", "# implementation: 0x00ca9500"),
        ("disasm_torch_getlightrgb.txt", "# implementation: 0x004b4e98"),
        ("disasm_torch_glowquadcount.txt", "# implementation: 0x004bed90"),
        ("disasm_torch_isdownlight.txt", "# implementation: 0x004bedec"),
        ("disasm_torch_isuplight.txt", "# implementation: 0x004bee3c"),
        ("disasm_torch_lightpos.txt", "# implementation: 0x004be0d4"),
    ):
        require(NATIVE / _emit_file, [_emit_imp])
    require(
        NATIVE / "POWER_CORE.md",
        [
            "1010",
            "0x0094f000",
            "0x00db20b4",
            "usesStoresConductsOrProducesElectricity",
            "currentConfiguration@60",
            "0x1ff",
        ],
    )
    require(
        NATIVE / "power_core.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 808",
            "\"verified_words\": 94",
            "usesStoresConductsOrProducesElectricity",
            "derivedTilePropertiesArray",
        ],
    )
    for _pow_file, _pow_imp in (
        ("disasm_wire_updatewireconfiguration.txt", "# implementation: 0x0094f000"),
        ("disasm_wirepathcreator_tilederivedproperties.txt", "# implementation: 0x00db20b4"),
        ("disasm_elevatormotor_hasrequiredpower.txt", "# implementation: 0x007027f8"),
        ("disasm_elevatormotor_usepower.txt", "# implementation: 0x00702848"),
    ):
        require(NATIVE / _pow_file, [_pow_imp])
    require(
        NATIVE / "POWER_FIND.md",
        [
            "2769",
            "0x00db2690",
            "0x00db51d4",
            "subtractElectricty:",
            "addElectricityParticleWithPath:size:",
            "openList@8",
        ],
    )
    require(
        NATIVE / "power_find.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 2769",
            "availableElectricity",
            "subtractElectricty:",
            "OBJC_CLASS_$_ParticleEmitter",
        ],
    )
    require(
        NATIVE / "disasm_wirepathcreator_findandsubtractpower.txt",
        [
            "# implementation: 0x00db2690",
            "# ARM.exidx end: 0x00db51d4",
        ],
    )
    require(
        NATIVE / "POWER_SYNC.md",
        [
            "1912",
            "0x005ca058",
            "0x005caef8",
            "sendNetDataForElectricityParticlePathIfRequired",
            "doAddElectricityParticleWithPath:size:",
            "0x1800",
        ],
    )
    require(
        NATIVE / "power_sync.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 603",
            "\"verified_words\": 725",
            "gzipDeflate",
            "doAddElectricityParticleWithPath:size:",
            "addStandardObjectAtPos:objectType:itemType:saveDict:placedByClient:",
        ],
    )
    for _ps_file, _ps_imp, _ps_end in (
        ("disasm_world_sendelectricitynetdata.txt", "# implementation: 0x005ca058", "# ARM.exidx end: 0x005ca9c4"),
        ("disasm_world_electricitypathrecv.txt", "# implementation: 0x005ca9c4", "# ARM.exidx end: 0x005caef8"),
        ("disasm_dynamicworld_initialwirenets.txt", "# implementation: 0x008b5300", "# ARM.exidx end: 0x008b5e54"),
        ("disasm_dynamicworld_addwireatpos.txt", "# implementation: 0x008eb9c0", "# ARM.exidx end: 0x008eba64"),
        ("disasm_dynamicworld_wireatpos.txt", "# implementation: 0x008eba64", "# ARM.exidx end: 0x008ebad4"),
        ("disasm_dynamicworld_removewireatpos.txt", "# implementation: 0x008ebad4", "# ARM.exidx end: 0x008ebb88"),
        ("disasm_wirepathcreator_init.txt", "# implementation: 0x00db1e90", "# ARM.exidx end: 0x00db1f84"),
        ("disasm_wirepathcreator_dealloc.txt", "# implementation: 0x00db1f84", "# ARM.exidx end: 0x00db20b4"),
    ):
        require(NATIVE / _ps_file, [_ps_imp, _ps_end])
    require(
        NATIVE / "POWER_WORKBENCH.md",
        [
            "1400",
            "0xb0137c",
            "0xb01cac",
            "subtractElectricty:",
            "doAddElectricityParticleWithPath:size:",
            "availableElectricity@222",
        ],
    )
    require(
        NATIVE / "power_workbench.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 182",
            "\"verified_words\": 242",
            "subtractElectricty:",
            "makeIntpair",
            "getDayNightFractionForX:atWorldTime:",
        ],
    )
    for _wb_file, _wb_imp, _wb_end in (
        ("disasm_workbench_combinedlightfullsun.txt", "# implementation: 0x00aee208", "# ARM.exidx end: 0x00aee508"),
        ("disasm_workbench_combinedlightsolarpanel.txt", "# implementation: 0x00aee508", "# ARM.exidx end: 0x00aeea18"),
        ("disasm_workbench_availableelectricity.txt", "# implementation: 0x00b01284", "# ARM.exidx end: 0x00b012c0"),
        ("disasm_workbench_conductselectricity.txt", "# implementation: 0x00b012c0", "# ARM.exidx end: 0x00b0137c"),
        ("disasm_workbench_subtractelectricty.txt", "# implementation: 0x00b0137c", "# ARM.exidx end: 0x00b01750"),
        ("disasm_workbench_generateselectricity.txt", "# implementation: 0x00b01c24", "# ARM.exidx end: 0x00b01ec0"),
        ("disasm_workbench_usesstoresconductsorproduces.txt", "# implementation: 0x00b01cac", "# ARM.exidx end: 0x00b01ec0"),
        ("disasm_workbench_requireselectricty.txt", "# implementation: 0x00b0b7d0", "# ARM.exidx end: 0x00b0bca4"),
        ("disasm_dynamicworld_findandsubtractpower.txt", "# implementation: 0x008fdee8", "# ARM.exidx end: 0x008fdf6c"),
        ("disasm_particleemitter_addelectricityparticle.txt", "# implementation: 0x00d8753c", "# ARM.exidx end: 0x00d876b0"),
        ("disasm_particleemitter_doaddelectricityparticle.txt", "# implementation: 0x00d876b0", "# ARM.exidx end: 0x00d87b04"),
    ):
        require(NATIVE / _wb_file, [_wb_imp, _wb_end])
    require(
        NATIVE / "WIRE_CLOSURE.md",
        [
            "2104",
            "0x0094fca0",
            "worldChanged:",
            "updateWireConfiguration",
            "createFreeBlockAtPosition:",
            "0x60",
        ],
    )
    require(
        NATIVE / "wire_closure.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 720",
            "\"verified_words\": 42",
            "gzipDeflate",
            "createFreeBlockAtPosition:",
            "worldWidthMacro",
        ],
    )
    for _wc_file, _wc_imp, _wc_end in (
        ("disasm_wire_initsubderiveditems.txt", "# implementation: 0x0094fca0", "# ARM.exidx end: 0x0094fd48"),
        ("disasm_wire_objecttype.txt", "# implementation: 0x0094fd48", "# ARM.exidx end: 0x0094fd64"),
        ("disasm_wire_initwithworld_position.txt", "# implementation: 0x0094fd64", "# ARM.exidx end: 0x0095002c"),
        ("disasm_wire_initwithworld_savedict.txt", "# implementation: 0x0095002c", "# ARM.exidx end: 0x0095034c"),
        ("disasm_wire_initwithworld_netdata.txt", "# implementation: 0x0095034c", "# ARM.exidx end: 0x00950688"),
        ("disasm_wire_dealloc.txt", "# implementation: 0x009506ac", "# ARM.exidx end: 0x00950770"),
        ("disasm_wire_getsavedict_closure.txt", "# implementation: 0x00950770", "# ARM.exidx end: 0x00950a64"),
        ("disasm_wire_updatenetdata.txt", "# implementation: 0x00950a64", "# ARM.exidx end: 0x00950ab8"),
        ("disasm_wire_creationnetdata.txt", "# implementation: 0x00950ab8", "# ARM.exidx end: 0x00950dbc"),
        ("disasm_wire_remoteupdate.txt", "# implementation: 0x00950f28", "# ARM.exidx end: 0x009510f8"),
        ("disasm_wire_freeblockcreationitemtype.txt", "# implementation: 0x00951320", "# ARM.exidx end: 0x009513b0"),
        ("disasm_wire_freeblockcreationsavedict.txt", "# implementation: 0x0095135c", "# ARM.exidx end: 0x009513b0"),
        ("disasm_wire_freeblockcreationdataa.txt", "# implementation: 0x00951378", "# ARM.exidx end: 0x009513b0"),
        ("disasm_wire_freeblockcreationdatab.txt", "# implementation: 0x00951394", "# ARM.exidx end: 0x009513b0"),
        ("disasm_wire_worldchanged.txt", "# implementation: 0x009513b0", "# ARM.exidx end: 0x00951ef0"),
        ("disasm_wire_removefrommacroblock.txt", "# implementation: 0x00954a2c", "# ARM.exidx end: 0x00954c74"),
        ("disasm_wire_occupiesforegroundcontents.txt", "# implementation: 0x00954b34", "# ARM.exidx end: 0x00954c74"),
        ("disasm_wire_occupiesnormalcontents.txt", "# implementation: 0x00954bd4", "# ARM.exidx end: 0x00954c74"),
    ):
        require(NATIVE / _wc_file, [_wc_imp, _wc_end])
    require(
        NATIVE / "WIRE_RENDER.md",
        [
            "2861",
            "0x00952770",
            "fillBuffer:",
            "staticGeometryDrawCubeCount",
            "floatPos@24",
            "0x70",
        ],
    )
    require(
        NATIVE / "wire_render.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 2194",
            "\"verified_words\": 138",
            "fillBuffer:fromIndex:matrix:",
            "texCoordsForImageIndex",
            "OBJC_CLASS_$_DrawCube",
        ],
    )
    for _wr_file, _wr_imp, _wr_end in (
        ("disasm_wire_draw.txt", "# implementation: 0x009510f8", "# ARM.exidx end: 0x00951320"),
        ("disasm_wire_staticgeometrydrawcubecount.txt", "# implementation: 0x00951f2c", "# ARM.exidx end: 0x00952770"),
        ("disasm_wire_adddrawcubedata.txt", "# implementation: 0x00952770", "# ARM.exidx end: 0x009549b8"),
    ):
        require(NATIVE / _wr_file, [_wr_imp, _wr_end])
    require(
        NATIVE / "CAMERA_UI.md",
        [
            "3024",
            "0x009d414c",
            "0x005c3278",
            "NoodlePermissionGranter",
            "shaderNamed:attributes:uniforms:",
            "dmb ish",
        ],
    )
    require(
        NATIVE / "camera_ui.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 1080",
            "\"verified_words\": 354",
            "showCameraUI",
            "doCameraScreenshot",
            "UIImageWriteToSavedPhotosAlbum",
        ],
    )
    for _cu_file, _cu_imp, _cu_end in (
        ("disasm_cameraui_initwithworld.txt", "# implementation: 0x009d414c", "# ARM.exidx end: 0x009d522c"),
        ("disasm_cameraui_dealloc.txt", "# implementation: 0x009d53d0", "# ARM.exidx end: 0x009d54d0"),
        ("disasm_cameraui_windowinfochanged.txt", "# implementation: 0x009d54d0", "# ARM.exidx end: 0x009d5c24"),
        ("disasm_cameraui_render.txt", "# implementation: 0x009d5c24", "# ARM.exidx end: 0x009d6054"),
        ("disasm_cameraui_touchisinviewatall.txt", "# implementation: 0x009d6054", "# ARM.exidx end: 0x009d60d4"),
        ("disasm_cameraui_touchisinui.txt", "# implementation: 0x009d60d4", "# ARM.exidx end: 0x009d620c"),
        ("disasm_cameraui_starttouch.txt", "# implementation: 0x009d620c", "# ARM.exidx end: 0x009d6398"),
        ("disasm_cameraui_movetouch.txt", "# implementation: 0x009d6398", "# ARM.exidx end: 0x009d65a8"),
        ("disasm_cameraui_endtouch.txt", "# implementation: 0x009d64a0", "# ARM.exidx end: 0x009d65a8"),
        ("disasm_cameraui_cancelbutton.txt", "# implementation: 0x009d65a8", "# ARM.exidx end: 0x009d6610"),
        ("disasm_cameraui_takephotobutton.txt", "# implementation: 0x009d6610", "# ARM.exidx end: 0x009d6678"),
        ("disasm_uimanager_showcameraui.txt", "# implementation: 0x00adc97c", "# ARM.exidx end: 0x00adc9ec"),
        ("disasm_uimanager_dismisscameraui.txt", "# implementation: 0x00ade3f0", "# ARM.exidx end: 0x00ade42c"),
        ("disasm_uimanager_setdismisscameraui.txt", "# implementation: 0x00ade42c", "# ARM.exidx end: 0x00ade608"),
        ("disasm_world_docamerascreenshot.txt", "# implementation: 0x005c3278", "# ARM.exidx end: 0x005c3800"),
        ("disasm_world_startusingcamera.txt", "# implementation: 0x005c3d24", "# ARM.exidx end: 0x005c3e10"),
        ("disasm_world_takephotobuttontapped.txt", "# implementation: 0x005c3e10", "# ARM.exidx end: 0x005c3ebc"),
        ("disasm_world_canceltakephotobuttontapped.txt", "# implementation: 0x005c3ebc", "# ARM.exidx end: 0x005c4030"),
        ("disasm_world_takingphoto.txt", "# implementation: 0x005c4030", "# ARM.exidx end: 0x005c40b4"),
        ("disasm_world_sharephotofinished.txt", "# implementation: 0x005c40b4", "# ARM.exidx end: 0x005c4228"),
        ("disasm_world_hasjusttakenphoto.txt", "# implementation: 0x005da600", "# ARM.exidx end: 0x005da63c"),
    ):
        require(NATIVE / _cu_file, [_cu_imp, _cu_end])
    require(
        NATIVE / "ELEVATOR_MOTOR.md",
        [
            "2569",
            "0x006ffeec",
            "findAndSubtractAllPowerUpTo:forUser:",
            "dmb ish",
            "macroTiles",
            "fillBuffer:fromIndex:matrix:",
            "texture 584",
        ],
    )
    require(
        NATIVE / "elevator_motor.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 396",
            "\"verified_words\": 303",
            "availableElectricity",
            "timeUntilNextPowerCheck",
            "findAndSubtractAllPowerUpTo:forUser:",
            "fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ",
        ],
    )
    for _em_file, _em_imp, _em_end in (
        ("disasm_elevatormotor_initsubderiveditems.txt", "# implementation: 0x006ffeec", "# ARM.exidx end: 0x006fff94"),
        ("disasm_elevatormotor_objecttype.txt", "# implementation: 0x006fff94", "# ARM.exidx end: 0x006fffb0"),
        ("disasm_elevatormotor_initwithworld_position.txt", "# implementation: 0x006fffb0", "# ARM.exidx end: 0x0070046c"),
        ("disasm_elevatormotor_initwithworld_savedict.txt", "# implementation: 0x0070046c", "# ARM.exidx end: 0x007007d4"),
        ("disasm_elevatormotor_initwithworld_netdata.txt", "# implementation: 0x007007d4", "# ARM.exidx end: 0x00700b38"),
        ("disasm_elevatormotor_getsavedict_closure.txt", "# implementation: 0x00700b5c", "# ARM.exidx end: 0x00700ed8"),
        ("disasm_elevatormotor_dealloc.txt", "# implementation: 0x00700ed8", "# ARM.exidx end: 0x00700f9c"),
        ("disasm_elevatormotor_updatenetdata.txt", "# implementation: 0x00700f9c", "# ARM.exidx end: 0x00700ff0"),
        ("disasm_elevatormotor_creationnetdata.txt", "# implementation: 0x00700ff0", "# ARM.exidx end: 0x0070136c"),
        ("disasm_elevatormotor_remoteupdate.txt", "# implementation: 0x007014d8", "# ARM.exidx end: 0x007017a0"),
        ("disasm_elevatormotor_update.txt", "# implementation: 0x007017a0", "# ARM.exidx end: 0x00701a1c"),
        ("disasm_elevatormotor_draw.txt", "# implementation: 0x00701a1c", "# ARM.exidx end: 0x00701c44"),
        ("disasm_elevatormotor_freeblockcreationitemtype.txt", "# implementation: 0x00701c44", "# ARM.exidx end: 0x00701c80"),
        ("disasm_elevatormotor_freeblockcreationsavedict.txt", "# implementation: 0x00701c80", "# ARM.exidx end: 0x00701ccc"),
        ("disasm_elevatormotor_freeblockcreationdataa.txt", "# implementation: 0x00701ccc", "# ARM.exidx end: 0x00701d04"),
        ("disasm_elevatormotor_freeblockcreationdatab.txt", "# implementation: 0x00701ce8", "# ARM.exidx end: 0x00701d04"),
        ("disasm_elevatormotor_worldchanged.txt", "# implementation: 0x00701d04", "# ARM.exidx end: 0x00702334"),
        ("disasm_elevatormotor_staticgeometrydrawcubecount.txt", "# implementation: 0x00702334", "# ARM.exidx end: 0x00702354"),
        ("disasm_elevatormotor_adddrawcubedata.txt", "# implementation: 0x00702354", "# ARM.exidx end: 0x00702660"),
        ("disasm_elevatormotor_removefrommacroblock.txt", "# implementation: 0x007026d4", "# ARM.exidx end: 0x007027dc"),
        ("disasm_elevatormotor_isstoragedevice.txt", "# implementation: 0x007027dc", "# ARM.exidx end: 0x00702848"),
        ("disasm_elevatormotor_occupiesnormalcontents.txt", "# implementation: 0x007029a8", "# ARM.exidx end: 0x00702a00"),
        ("disasm_elevatormotor_miny.txt", "# implementation: 0x007029c4", "# ARM.exidx end: 0x00702a00"),
        ("disasm_elevatormotor_setminy.txt", "# implementation: 0x00702a00", "# ARM.exidx end: 0x00702a44"),
        ("disasm_elevatormotor_maxy.txt", "# implementation: 0x00702a44", "# ARM.exidx end: 0x00702a80"),
        ("disasm_elevatormotor_setmaxy.txt", "# implementation: 0x00702a80", "# ARM.exidx end: 0x00702ac4"),
    ):
        require(NATIVE / _em_file, [_em_imp, _em_end])
    require(
        NATIVE / "ELEVATOR_SHAFT.md",
        [
            "4175",
            "0x00cacc58",
            "elevatorMotorForShaftAtPos:",
            "solidTile@86",
            "opening@68",
            "paintColor@84",
            "lastKnownMotorPos@60",
            "fillQuadBufferColored",
            "objc_copyStruct",
        ],
    )
    require(
        NATIVE / "elevator_shaft.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 714",
            "\"verified_words\": 802",
            "elevatorMotorForShaftAtPos:",
            "lastKnownMotorPos",
            "fillBuffer:fromIndex:matrix:width:height:depth:centerX:centerY:centerZ",
        ],
    )
    for _es_file, _es_imp, _es_end in (
        ("disasm_elevatorshaft_initsubderiveditems.txt", "# implementation: 0x00cacc58", "# ARM.exidx end: 0x00cacf38"),
        ("disasm_elevatorshaft_objecttype.txt", "# implementation: 0x00cacf38", "# ARM.exidx end: 0x00cacf54"),
        ("disasm_elevatorshaft_initwithworld_atposition.txt", "# implementation: 0x00cacf54", "# ARM.exidx end: 0x00cad2cc"),
        ("disasm_elevatorshaft_initwithworld_savedict_closure.txt", "# implementation: 0x00cad2cc", "# ARM.exidx end: 0x00cad624"),
        ("disasm_elevatorshaft_initwithworld_netdata.txt", "# implementation: 0x00cad624", "# ARM.exidx end: 0x00cad974"),
        ("disasm_elevatorshaft_getsavedict_closure.txt", "# implementation: 0x00cad998", "# ARM.exidx end: 0x00cadd14"),
        ("disasm_elevatorshaft_updatenetdata.txt", "# implementation: 0x00cadd14", "# ARM.exidx end: 0x00cadd68"),
        ("disasm_elevatorshaft_creationnetdata.txt", "# implementation: 0x00cadd68", "# ARM.exidx end: 0x00cae0ac"),
        ("disasm_elevatorshaft_remoteupdate.txt", "# implementation: 0x00cae218", "# ARM.exidx end: 0x00cae414"),
        ("disasm_elevatorshaft_dealloc.txt", "# implementation: 0x00cae414", "# ARM.exidx end: 0x00cae4d8"),
        ("disasm_elevatorshaft_draw.txt", "# implementation: 0x00cae4d8", "# ARM.exidx end: 0x00caf000"),
        ("disasm_elevatorshaft_worldchanged.txt", "# implementation: 0x00caf680", "# ARM.exidx end: 0x00cafb50"),
        ("disasm_elevatorshaft_staticgeometrydrawquadcount.txt", "# implementation: 0x00cafb50", "# ARM.exidx end: 0x00cafbb8"),
        ("disasm_elevatorshaft_adddrawquaddata.txt", "# implementation: 0x00cafbb8", "# ARM.exidx end: 0x00cb0394"),
        ("disasm_elevatorshaft_staticgeometrydrawcubecount.txt", "# implementation: 0x00cb0394", "# ARM.exidx end: 0x00cb03f0"),
        ("disasm_elevatorshaft_freeblockcreationitemtype.txt", "# implementation: 0x00cb03f0", "# ARM.exidx end: 0x00cb042c"),
        ("disasm_elevatorshaft_freeblockcreationsavedict.txt", "# implementation: 0x00cb042c", "# ARM.exidx end: 0x00cb0478"),
        ("disasm_elevatorshaft_freeblockcreationdataa.txt", "# implementation: 0x00cb0478", "# ARM.exidx end: 0x00cb04b0"),
        ("disasm_elevatorshaft_freeblockcreationdatab.txt", "# implementation: 0x00cb0494", "# ARM.exidx end: 0x00cb04b0"),
        ("disasm_elevatorshaft_adddrawcubedata.txt", "# implementation: 0x00cb04b0", "# ARM.exidx end: 0x00cb1138"),
        ("disasm_elevatorshaft_open.txt", "# implementation: 0x00cb1138", "# ARM.exidx end: 0x00cb1178"),
        ("disasm_elevatorshaft_removefrommacroblock.txt", "# implementation: 0x00cb1178", "# ARM.exidx end: 0x00cb12f4"),
        ("disasm_elevatorshaft_paint.txt", "# implementation: 0x00cb12f4", "# ARM.exidx end: 0x00cb150c"),
        ("disasm_elevatorshaft_ispaintable.txt", "# implementation: 0x00cb150c", "# ARM.exidx end: 0x00cb1544"),
        ("disasm_elevatorshaft_occupiesnormalcontents.txt", "# implementation: 0x00cb1528", "# ARM.exidx end: 0x00cb1544"),
        ("disasm_elevatorshaft_lastknownmotorpos.txt", "# implementation: 0x00cb1544", "# ARM.exidx end: 0x00cb15a4"),
    ):
        require(NATIVE / _es_file, [_es_imp, _es_end])
    require(
        NATIVE / "TRADE_PORTAL.md",
        [
            "4716",
            "0x00d37d8c",
            "ArtificialLight",
            "LEVEL JUMP TABLE",
            "createFreeBlockAtPosition",
            "updateQuadBufferTexCoords",
            "stringWithFormat:",
        ],
    )
    require(
        NATIVE / "trade_portal.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 682",
            "\"verified_words\": 472",
            "ArtificialLight",
            "initWithWorld:dynamicWorld:atPosition:cache:parentObject:colorR:colorG:colorB:heat:radius:lightDirection:",
            "createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:",
        ],
    )
    for _tp_file, _tp_imp, _tp_end in (
        ("disasm_tradeportal_initsubderiveditems.txt", "# implementation: 0x00d37598", "# ARM.exidx end: 0x00d37798"),
        ("disasm_tradeportal_objecttype.txt", "# implementation: 0x00d377a8", "# ARM.exidx end: 0x00d377c4"),
        ("disasm_tradeportal_getlightrgb.txt", "# implementation: 0x00d377c4", "# ARM.exidx end: 0x00d37828"),
        ("disasm_tradeportal_updateportallight.txt", "# implementation: 0x00d37828", "# ARM.exidx end: 0x00d37a78"),
        ("disasm_tradeportal_initwithworld_atposition.txt", "# implementation: 0x00d37d8c", "# ARM.exidx end: 0x00d382fc"),
        ("disasm_tradeportal_initwithworld_savedict.txt", "# implementation: 0x00d382fc", "# ARM.exidx end: 0x00d38760"),
        ("disasm_tradeportal_initwithworld_netdata.txt", "# implementation: 0x00d38760", "# ARM.exidx end: 0x00d38dfc"),
        ("disasm_tradeportal_updatenetdata.txt", "# implementation: 0x00d38e20", "# ARM.exidx end: 0x00d391d4"),
        ("disasm_tradeportal_dealloc.txt", "# implementation: 0x00d39340", "# ARM.exidx end: 0x00d39460"),
        ("disasm_tradeportal_getsavedict_closure.txt", "# implementation: 0x00d39460", "# ARM.exidx end: 0x00d396d4"),
        ("disasm_tradeportal_interactionobjecttype.txt", "# implementation: 0x00d396d4", "# ARM.exidx end: 0x00d396f0"),
        ("disasm_tradeportal_remoteupdate.txt", "# implementation: 0x00d396f0", "# ARM.exidx end: 0x00d3a198"),
        ("disasm_tradeportal_draw.txt", "# implementation: 0x00d3a198", "# ARM.exidx end: 0x00d3a8f8"),
        ("disasm_tradeportal_worldcontentschanged.txt", "# implementation: 0x00d3b230", "# ARM.exidx end: 0x00d3b248"),
        ("disasm_tradeportal_isdoubleheight.txt", "# implementation: 0x00d3b248", "# ARM.exidx end: 0x00d3b264"),
        ("disasm_tradeportal_setneedsremoved.txt", "# implementation: 0x00d3b264", "# ARM.exidx end: 0x00d3b3b8"),
        ("disasm_tradeportal_freeblockcreationitemtype.txt", "# implementation: 0x00d3b3b8", "# ARM.exidx end: 0x00d3b3d4"),
        ("disasm_tradeportal_freeblockcreationsavedict.txt", "# implementation: 0x00d3b3d4", "# ARM.exidx end: 0x00d3b420"),
        ("disasm_tradeportal_freeblockcreationdataa.txt", "# implementation: 0x00d3b420", "# ARM.exidx end: 0x00d3b458"),
        ("disasm_tradeportal_freeblockcreationdatab.txt", "# implementation: 0x00d3b43c", "# ARM.exidx end: 0x00d3b458"),
        ("disasm_tradeportal_remove.txt", "# implementation: 0x00d3b458", "# ARM.exidx end: 0x00d3b860"),
        ("disasm_tradeportal_destroyitemtype.txt", "# implementation: 0x00d3b860", "# ARM.exidx end: 0x00d3b87c"),
        ("disasm_tradeportal_title.txt", "# implementation: 0x00d3b87c", "# ARM.exidx end: 0x00d3b910"),
        ("disasm_tradeportal_actiontitle.txt", "# implementation: 0x00d3b910", "# ARM.exidx end: 0x00d3bbc4"),
        ("disasm_tradeportal_secondoptiontitle.txt", "# implementation: 0x00d3bbc4", "# ARM.exidx end: 0x00d3c054"),
        ("disasm_tradeportal_thirdoptiontitle.txt", "# implementation: 0x00d3c054", "# ARM.exidx end: 0x00d3c3cc"),
        ("disasm_tradeportal_setworkbenchchoiceuioption.txt", "# implementation: 0x00d3c3cc", "# ARM.exidx end: 0x00d3c608"),
        ("disasm_tradeportal_requireshumaninteraction.txt", "# implementation: 0x00d3c608", "# ARM.exidx end: 0x00d3c624"),
        ("disasm_tradeportal_staticgeometrydrawcubecount.txt", "# implementation: 0x00d3c9b8", "# ARM.exidx end: 0x00d3c9d8"),
        ("disasm_tradeportal_adddrawquaddata.txt", "# implementation: 0x00d3c9d8", "# ARM.exidx end: 0x00d3cd80"),
        ("disasm_tradeportal_staticgeometrydrawquadcount.txt", "# implementation: 0x00d3cdf4", "# ARM.exidx end: 0x00d3ce18"),
        ("disasm_tradeportal_removefrommacroblock.txt", "# implementation: 0x00d3ce18", "# ARM.exidx end: 0x00d3cf20"),
        ("disasm_tradeportal_lightglowquadcount.txt", "# implementation: 0x00d3f38c", "# ARM.exidx end: 0x00d3f3a8"),
        ("disasm_tradeportal_lightpos.txt", "# implementation: 0x00d3f3a8", "# ARM.exidx end: 0x00d3f460"),
        ("disasm_tradeportal_interactionrenderitemtype.txt", "# implementation: 0x00d3f7ac", "# ARM.exidx end: 0x00d3f7e4"),
        ("disasm_tradeportal_occupiesnormalcontents.txt", "# implementation: 0x00d3f7c8", "# ARM.exidx end: 0x00d3f7e4"),
        ("disasm_tradeportal_addartificiallightcontribution.txt", "# implementation: 0x00d3f7e4", "# ARM.exidx end: 0x00d3f858"),
        ("disasm_tradeportal_canbeusedinexpertmode.txt", "# implementation: 0x00d3f858", "# ARM.exidx end: 0x00d3f874"),
        ("disasm_tradeportal_localpriceoffsets.txt", "# implementation: 0x00d3f874", "# ARM.exidx end: 0x00d3f8b8"),
        ("disasm_tradeportal_level.txt", "# implementation: 0x00d3f8b8", "# ARM.exidx end: 0x00d3f96c"),
    ):
        require(NATIVE / _tp_file, [_tp_imp, _tp_end])
    require(
        NATIVE / "TRADE_PORTAL_ECON.md",
        [
            "3573",
            "0x00e18ee0",
            "lrand48()",
            "0.997",
            "0x7c",
            "[self remove:0]",
            "[0.5, 2.0]",
            "is not a price hash",
        ],
    )
    require(
        NATIVE / "trade_portal_econ.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 699',
            '"verified_words": 575',
            "createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:",
            "displayInterstitialForTag:",
            "OBJC_CLASS_$_CrystalManager",
            "OBJC_IVAR_$_TradePortal.isMissionInteraction",
            '"disjoint_branch_rows"',
        ],
    )
    for _tpe_file, _tpe_imp, _tpe_end in (
        ("disasm_tradeportal_loadpriceoffsets_closure.txt", "# implementation: 0x00d37a78", "# ARM.exidx end: 0x00d37d8c"),
        ("disasm_tradeportal_worldchanged.txt", "# implementation: 0x00d3a8f8", "# ARM.exidx end: 0x00d3b1f4"),
        ("disasm_tradeportal_currentblockheadcash.txt", "# implementation: 0x00d3c624", "# ARM.exidx end: 0x00d3c6d4"),
        ("disasm_tradeportal_currentblockheadcountofinventoryitemsoftype.txt", "# implementation: 0x00d3c6d4", "# ARM.exidx end: 0x00d3c818"),
        ("disasm_tradeportal_currentblockheadusagemultiplierforfirstitemoftype.txt", "# implementation: 0x00d3c818", "# ARM.exidx end: 0x00d3c8e4"),
        ("disasm_tradeportal_setpaused.txt", "# implementation: 0x00d3c8e4", "# ARM.exidx end: 0x00d3c9b8"),
        ("disasm_tradeportal_upgradetonextlevel.txt", "# implementation: 0x00d3cf20", "# ARM.exidx end: 0x00d3d638"),
        ("disasm_tradeportal_sellitem.txt", "# implementation: 0x00d3d638", "# ARM.exidx end: 0x00d3dcf0"),
        ("disasm_tradeportal_buyitem.txt", "# implementation: 0x00d3dcf0", "# ARM.exidx end: 0x00d3e7dc"),
        ("disasm_tradeportal_upgradecraftableitem.txt", "# implementation: 0x00d3e7dc", "# ARM.exidx end: 0x00d3eb54"),
        ("disasm_tradeportal_takeitemsfromblockhead.txt", "# implementation: 0x00d3eb54", "# ARM.exidx end: 0x00d3f38c"),
        ("disasm_tradeportal_randomizelocaloffsets.txt", "# implementation: 0x00d3f460", "# ARM.exidx end: 0x00d3f7ac"),
        ("disasm_tradeportal_issellinteraction.txt", "# implementation: 0x00d3f8f4", "# ARM.exidx end: 0x00d3f96c"),
        ("disasm_tradeportal_ismissioninteraction.txt", "# implementation: 0x00d3f930", "# ARM.exidx end: 0x00d3f96c"),
    ):
        require(NATIVE / _tpe_file, [_tpe_imp, _tpe_end])
    require(
        NATIVE / "CRYSTALMANAGER_CLOSURE.md",
        [
            "1305",
            "crystalCount",
            "amountString",
            "countWatcher",
            "needsSave",
            "rejoin",
            "singleton",
        ],
    )
    require(
        NATIVE / "crystalmanager_closure.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 767',
            '"verified_words": 190',
            "OBJC_IVAR_$_CrystalManager.crystalCount",
            "OBJC_IVAR_$_CrystalManager.amountString",
            "OBJC_IVAR_$_CrystalManager.countWatcher",
            "OBJC_IVAR_$_CrystalManager.needsSave",
            "__CFConstantStringClassReference",
        ],
    )
    for _cm_file, _cm_imp, _cm_end in (
        ("disasm_crystalmanager_instance.txt", "# implementation: 0x009f3b14", "# ARM.exidx end: 0x009f3bdc"),
        ("disasm_crystalmanager_init.txt", "# implementation: 0x009f3bdc", "# ARM.exidx end: 0x009f3d44"),
        ("disasm_crystalmanager_amount.txt", "# implementation: 0x009f452c", "# ARM.exidx end: 0x009f4568"),
        ("disasm_crystalmanager_commitsaveifneeded.txt", "# implementation: 0x009f4568", "# ARM.exidx end: 0x009f4678"),
        ("disasm_crystalmanager_save.txt", "# implementation: 0x009f4f34", "# ARM.exidx end: 0x009f4f74"),
        ("disasm_crystalmanager_modify_modifystring_.txt", "# implementation: 0x009f4f74", "# ARM.exidx end: 0x009f526c"),
        ("disasm_crystalmanager_icloudid.txt", "# implementation: 0x009f526c", "# ARM.exidx end: 0x009f5e68"),
        ("disasm_crystalmanager_icloudserverrejoinid.txt", "# implementation: 0x009f5e78", "# ARM.exidx end: 0x009f5f24"),
        ("disasm_crystalmanager_countwatcher.txt", "# implementation: 0x009f5f24", "# ARM.exidx end: 0x009f5fac"),
        ("disasm_crystalmanager_setcountwatcher_.txt", "# implementation: 0x009f5f68", "# ARM.exidx end: 0x009f5fac"),
        ("disasm_crystalmanager_needssave.txt", "# implementation: 0x009f5fac", "# ARM.exidx end: 0x009f5fe8"),
        ("disasm_crystalmanager_amountstring.txt", "# implementation: 0x009f5fe8", "# ARM.exidx end: 0x009f602c"),
    ):
        require(NATIVE / _cm_file, [_cm_imp, _cm_end])
    require(
        NATIVE / "PORTAL_CHEST_MANAGER.md",
        [
            "3820",
            "portalChestTransaction",
            "saveItemSlots",
            "customRules",
            "std::set<int>",
            "NSApplicationSupportDirectory",
        ],
    )
    require(
        NATIVE / "portalchest_closure.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 786',
            '"verified_words": 742',
            "OBJC_IVAR_$_PortalChestManager.pendingTransactionIsResend",
            "OBJC_IVAR_$_PortalChestManager.transactionIdentifierCount",
            "OBJC_IVAR_$_PortalChestManager.pendingSaveData",
            "moveInventoryItemsFromArray:toIndex:count:movedItems:assignedIndexes:",
            "sendDataToServer:reliable:",
        ],
    )
    for _pcm_file, _pcm_imp, _pcm_end in (
        ("disasm_portalchestmanager_initwithworld_.txt", "# implementation: 0x00957db4", "# ARM.exidx end: 0x0095894c"),
        ("disasm_portalchestmanager_dealloc.txt", "# implementation: 0x00958970", "# ARM.exidx end: 0x00958a34"),
        ("disasm_portalchestmanager_savewithmainthreadblock_.txt", "# implementation: 0x00958a34", "# ARM.exidx end: 0x0095926c"),
        ("disasm_portalchestmanager_saveanypendingdatatodisk.txt", "# implementation: 0x009593d8", "# ARM.exidx end: 0x009595a4"),
        ("disasm_portalchestmanager_savetransactionwithfailurecreation_ite.txt", "# implementation: 0x009595a4", "# ARM.exidx end: 0x00959f68"),
        ("disasm_portalchestmanager_takeincominginventoryitemsfromarray_to.txt", "# implementation: 0x00959f68", "# ARM.exidx end: 0x0095a038"),
        ("disasm_portalchestmanager_moveinventoryitemswithinchestfromarray.txt", "# implementation: 0x0095a038", "# ARM.exidx end: 0x0095a108"),
        ("disasm_portalchestmanager_portalchestserverackreceivedwithsucces.txt", "# implementation: 0x0095a108", "# ARM.exidx end: 0x0095a934"),
        ("disasm_portalchestmanager_portalchestinventoryitems.txt", "# implementation: 0x0095a934", "# ARM.exidx end: 0x0095a9bc"),
        ("disasm_portalchestmanager_takeincominginventoryitemsfromarray_to_a9bc.txt", "# implementation: 0x0095a9bc", "# ARM.exidx end: 0x0095aba4"),
        ("disasm_portalchestmanager_itemsremovedtoinventory_andordropped_.txt", "# implementation: 0x0095aba4", "# ARM.exidx end: 0x0095ad94"),
        ("disasm_portalchestmanager_moveinventoryitemswithinchestfromarray_ad94.txt", "# implementation: 0x0095ad94", "# ARM.exidx end: 0x0095ae70"),
        ("disasm_portalchestmanager_moveinventoryitemsfromarray_toindex_co.txt", "# implementation: 0x0095ae70", "# ARM.exidx end: 0x0095bab8"),
        ("disasm_portalchestmanager_haspendingtransaction.txt", "# implementation: 0x0095bab8", "# ARM.exidx end: 0x0095baf4"),
    ):
        require(NATIVE / _pcm_file, [_pcm_imp, _pcm_end])
    require(
        NATIVE / "TERRAIN_GENERATION.md",
        [
            "5391",
            "worldWidthMacro",
            "customRules",
            "lrand48()",
            "0x5f5e0ff",
            "getX:Y:octaves:",
        ],
    )
    require(
        NATIVE / "terrain_generation.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '\"verified_words\": 1556',
            '\"verified_words\": 955',
            "OBJC_IVAR_$_WorldTileLoader.rockTypeNoiseFunction",
            "OBJC_IVAR_$_WorldTileLoader.sandNoiseFunction",
            "OBJC_IVAR_$_WorldTileLoader.gemNoiseFunction",
            "OBJC_IVAR_$_WorldTileLoader.yHeightDivider",
            "fillDirtTile:worldPos:worldDirtHeight:parentType:",
        ],
    )
    for _tg_file, _tg_imp, _tg_end in (
        ("disasm_worldtileloader_limestonefractionforx_y_faultoffset_.txt", "# implementation: 0x00857684", "# ARM.exidx end: 0x008578b8"),
        ("disasm_worldtileloader_sandstonefractionforx_y_faultoffset_lime.txt", "# implementation: 0x008578b8", "# ARM.exidx end: 0x00857a2c"),
        ("disasm_worldtileloader_isfloatingislandcaveforx_y_.txt", "# implementation: 0x00858320", "# ARM.exidx end: 0x00858664"),
        ("disasm_worldtileloader_sandfractionforpos_highres_.txt", "# implementation: 0x0085a84c", "# ARM.exidx end: 0x0085ab18"),
        ("disasm_worldtileloader_sandfractionforpos_height_highres_.txt", "# implementation: 0x0085ab18", "# ARM.exidx end: 0x0085b0d0"),
        ("disasm_worldtileloader_isdesertforpos_height_.txt", "# implementation: 0x0085b0d0", "# ARM.exidx end: 0x0085b190"),
        ("disasm_worldtileloader_isbeachforpos_height_.txt", "# implementation: 0x0085b190", "# ARM.exidx end: 0x0085b480"),
        ("disasm_worldtileloader_isdesertorbeachforpos_height_.txt", "# implementation: 0x0085b480", "# ARM.exidx end: 0x0085b5b0"),
        ("disasm_worldtileloader_filldirttile_worldpos_worlddirtheight_pa.txt", "# implementation: 0x0085b5b0", "# ARM.exidx end: 0x0085c214"),
        ("disasm_worldtileloader_recursivelyflowoutwaterfromtile_atpos_.txt", "# implementation: 0x0085c214", "# ARM.exidx end: 0x0085c518"),
        ("disasm_worldtileloader_recursivelyflowoutdirtfromtile_atpos_.txt", "# implementation: 0x0085c518", "# ARM.exidx end: 0x0085ce60"),
        ("disasm_worldtileloader_placegemsincaveforphysicalblock_tileinde.txt", "# implementation: 0x0085ce60", "# ARM.exidx end: 0x0085e6b0"),
        ("disasm_worldtileloader_findbeststartposition.txt", "# implementation: 0x00864188", "# ARM.exidx end: 0x00865074"),
    ):
        require(NATIVE / _tg_file, [_tg_imp, _tg_end])

    require(
        NATIVE / "LIGHTBLOCK_PERSISTENCE.md",
        [
            "2260",
            "lightBlockDatabaseEnvironment@248",
            "macroPosForMacroIndex",
            "playerLightBlocks",
            "flags[32]@0xA0",
            "finishBulkTransaction",
        ],
    )
    require(
        NATIVE / "lightblock_persistence.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '\"verified_words\": 632',
            '\"verified_words\": 26',
            "OBJC_IVAR_$_WorldTileLoader.lightBlockDatabase",
            "OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment",
            "sendLightBlockToClientWithoutSavingForBlock:pos:sendToClient:server:",
            "startBulkTransaction",
        ],
    )
    for _lb_file, _lb_imp, _lb_end in (
        ("disasm_worldtileloader_unarchivelightblocksforclient_.txt", "# implementation: 0x0086652c", "# ARM.exidx end: 0x00866f0c"),
        ("disasm_worldtileloader_archivelightblocksforclient_.txt", "# implementation: 0x00866f30", "# ARM.exidx end: 0x00867650"),
        ("disasm_worldtileloader_loadlightblockforclientlightblockindex_c.txt", "# implementation: 0x00867a58", "# ARM.exidx end: 0x008681e4"),
        ("disasm_worldtileloader_sendlightblocktoclientwithoutsavingforbl.txt", "# implementation: 0x008681e4", "# ARM.exidx end: 0x00868700"),
        ("disasm_worldtileloader_savelightblockforclientlightblockindex_c.txt", "# implementation: 0x00868700", "# ARM.exidx end: 0x00868b70"),
        ("disasm_worldtileloader_startbulklightblocktransaction.txt", "# implementation: 0x00868b70", "# ARM.exidx end: 0x00868c40"),
        ("disasm_worldtileloader_finishbulklightblocktransaction.txt", "# implementation: 0x00868bd8", "# ARM.exidx end: 0x00868c40"),    ):
        require(NATIVE / _lb_file, [_lb_imp, _lb_end])
    require(
        NATIVE / "BLOCK_SAVE_SYNC.md",
        [
            "2079",
            "65541",
            "physicalBlock+8",
            "sendDynamicObjects",
            "macroIndex",
            "initialDynamicObjectsNetDataForMacroTileIndex:macroIndex",
        ],
    )
    require(
        NATIVE / "block_save_sync.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 882',
            '"verified_words": 1197',
            "OBJC_IVAR_$_WorldTileLoader.blockDatabase",
            "loadLightBlockForClientLightBlockIndex:clientID:intoPhysicalBlock:",
            "initialDynamicObjectsNetDataForMacroTileIndex:wireForClient:",
            "sendNetworkData:toPeers:reliable:",
        ],
    )
    for _bs_file, _bs_imp, _bs_end in (
        ("disasm_worldtileloader_savephysicalblock_macrotile_sendtoclient.txt", "# implementation: 0x00859a84", "# ARM.exidx end: 0x0085a84c"),
        ("disasm_worldtileloader_sendblocktoclientwithoutsavingforblock_p.txt", "# implementation: 0x00858664", "# ARM.exidx end: 0x00859918"),
    ):
        require(NATIVE / _bs_file, [_bs_imp, _bs_end])
    require(
        NATIVE / "BLOCK_MIGRATION.md",
        [
            "1311",
            "cumulative version ladder",
            "createTreasureChestOrTrollAtTile",
            "bestStartPosition",
            "no writer of offset 13",
        ],
    )
    require(
        NATIVE / "block_migration.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1311',
            "OBJC_IVAR_$_WorldTileLoader.bestStartPosition",
            "OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction",
            "createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:",
        ],
    )
    for _bm_file, _bm_imp, _bm_end in (
        ("disasm_worldtileloader_updatephysicalblocktolatestversion_.txt", "# implementation: 0x008650b0", "# ARM.exidx end: 0x0086652c"),
    ):
        require(NATIVE / _bm_file, [_bm_imp, _bm_end])
    require(
        NATIVE / "BLOCK_LOAD.md",
        [
            "5736",
            "block-load orchestrator",
            "bestStartPosition",
            "quarter-column",
            "0x5e",
            "0x10001",
        ],
    )
    require(
        NATIVE / "block_load.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 5736',
            "OBJC_IVAR_$_WorldTileLoader.bestStartPosition",
            "OBJC_IVAR_$_WorldTileLoader.lakeHeights",
            "placeGemsInCaveForPhysicalBlock:tileIndex:worldX:worldY:floatingIslandType:",
        ],
    )
    for _bl_file, _bl_imp, _bl_end in (
        ("disasm_worldtileloader_loadphysicalblock_atxpos_ypos_createifno.txt", "# implementation: 0x0085e6b0", "# ARM.exidx end: 0x00864050"),
    ):
        require(NATIVE / _bl_file, [_bl_imp, _bl_end])
    require(
        NATIVE / "WTL_INITWITHWORLD.md",
        [
            "10857",
            "world constructor",
            "bestStartPosition",
            "quarter-column",
            "rockHeights",
            "distanceOrderedFoodTypes",
        ],
    )
    require(
        NATIVE / "wtl_initwithworld.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 10857',
            "OBJC_IVAR_$_WorldTileLoader.bestStartPosition",
            "OBJC_IVAR_$_WorldTileLoader.distanceOrderedFoodTypes",
            "growthVigorForTreeTypeAtPos",
        ],
    )
    for _iw_file, _iw_imp, _iw_end in (
        ("disasm_worldtileloader_initwithworld_randomseed_isnewworld_save.txt", "# implementation: 0x00849728", "# ARM.exidx end: 0x008540cc"),
    ):
        require(NATIVE / _iw_file, [_iw_imp, _iw_end])
    require(
        NATIVE / "WTL_CLOSURE.md",
        [
            "16 bodies",
            "dealloc",
            "__wrap_free",
            "objc_msgSendSuper2",
            "objc_copyStruct",
            "dmb ish",
        ],
    )
    require(
        NATIVE / "wtl_closure.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 298',
            "OBJC_IVAR_$_WorldTileLoader.blockDirectory",
            "OBJC_IVAR_$_WorldTileLoader.lightBlockDatabaseEnvironment",
            "objc_copyStruct",
        ],
    )
    for _wc_file, _wc_imp, _wc_end in (
        ("disasm_worldtileloader_dealloc.txt", "# implementation: 0x00854770", "# ARM.exidx end: 0x00854c18"),
        ("disasm_worldtileloader_cxx_construct.txt", "# implementation: 0x00868fd8", "# ARM.exidx end: 0x00868ff0"),
        ("disasm_worldtileloader_distanceorderedfoodtypes.txt", "# implementation: 0x00865074", "# ARM.exidx end: 0x008650b0"),
        ("disasm_worldtileloader_randomseed.txt", "# implementation: 0x00868c40", "# ARM.exidx end: 0x00868c7c"),
        ("disasm_worldtileloader_beststartposition.txt", "# implementation: 0x00868c7c", "# ARM.exidx end: 0x00868cdc"),
        ("disasm_worldtileloader_treedensitynoisefunction.txt", "# implementation: 0x00868cdc", "# ARM.exidx end: 0x00868e30"),
        ("disasm_worldtileloader_seasonoffsetnoisefunction.txt", "# implementation: 0x00868d20", "# ARM.exidx end: 0x00868e30"),
        ("disasm_worldtileloader_treepositions.txt", "# implementation: 0x00868d64", "# ARM.exidx end: 0x00868e30"),
        ("disasm_worldtileloader_npcpositions.txt", "# implementation: 0x00868da8", "# ARM.exidx end: 0x00868e30"),
        ("disasm_worldtileloader_plantpositions.txt", "# implementation: 0x00868dec", "# ARM.exidx end: 0x00868e30"),
        ("disasm_worldtileloader_highestpoint.txt", "# implementation: 0x00868e30", "# ARM.exidx end: 0x00868e90"),
        ("disasm_worldtileloader_needstoexit.txt", "# implementation: 0x00868e90", "# ARM.exidx end: 0x00868ecc"),
        ("disasm_worldtileloader_setneedstoexit_.txt", "# implementation: 0x00868ecc", "# ARM.exidx end: 0x00868f10"),
        ("disasm_worldtileloader_xfrequencymultiplier.txt", "# implementation: 0x00868f10", "# ARM.exidx end: 0x00868f4c"),
        ("disasm_worldtileloader_yheightdivider.txt", "# implementation: 0x00868f4c", "# ARM.exidx end: 0x00868fd8"),
        ("disasm_worldtileloader_lightblockdatabase.txt", "# implementation: 0x00868f94", "# ARM.exidx end: 0x00868fd8"),
    ):
        require(NATIVE / _wc_file, [_wc_imp, _wc_end])
    require(
        NATIVE / "DYN_OBJECT_LOAD.md",
        [
            "11207",
            "dynamic-object",
            "version ladder",
            "tree-promise",
            "gzipInflate",
            "conversionThread",
        ],
    )
    require(
        NATIVE / "dyn_load.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 6196',
            "OBJC_IVAR_$_DynamicWorld.currentlyLoadingMacroBlocks",
            "OBJC_IVAR_$_DynamicWorld.dynamicObjects",
            "currentlyAddingObjectIDs",
        ],
    )
    for _dl_file, _dl_imp, _dl_end in (
        ("disasm_worldtileloader_loaddynamicobjectsformacrotile_includesu.txt", "# implementation: 0x008bd9b8", "# ARM.exidx end: 0x008c3a88"),
        ("disasm_worldtileloader_loaddynamicobjects_repositionblockheadlo.txt", "# implementation: 0x008aedac", "# ARM.exidx end: 0x008b1db0"),
        ("disasm_worldtileloader_loaddynamicobjectsoftype_fromdata_physic.txt", "# implementation: 0x008baa54", "# ARM.exidx end: 0x008bc89c"),
    ):
        require(NATIVE / _dl_file, [_dl_imp, _dl_end])
    require(
        NATIVE / "DYN_OBJECT_LEAVES.md",
        [
            "5479",
            "Tree factory",
            "occupancy scan",
            "GemTree",
            "conversionThread",
            "rarity ladder",
        ],
    )
    require(
        NATIVE / "dyn_leaf.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1447',
            "OBJC_CLASS_$_AppleTree",
            "OBJC_CLASS_$_TomatoPlant",
            "currentlyAddingGlowBlocks",
        ],
    )
    for _lf_file, _lf_imp, _lf_end in (
        ("disasm_worldtileloader_conversionthread_.txt", "# implementation: 0x008ae5b8", "# ARM.exidx end: 0x008aedac"),
        ("disasm_worldtileloader_loadtreeatposition_type_maxheight_growth.txt", "# implementation: 0x008e4e44", "# ARM.exidx end: 0x008e6250"),
        ("disasm_worldtileloader_loadplantatposition_type_maxagegene_grow.txt", "# implementation: 0x008e69e8", "# ARM.exidx end: 0x008e7608"),
        ("disasm_worldtileloader_loadnpcatposition_type_savedict_isadult_.txt", "# implementation: 0x008e66d4", "# ARM.exidx end: 0x008e69e8"),
        ("disasm_worldtileloader_loadsnowsurfaceblockatpos_loadsnow_.txt", "# implementation: 0x008e6608", "# ARM.exidx end: 0x008e66d4"),
        ("disasm_worldtileloader_loadsurfaceblockatpos_.txt", "# implementation: 0x008e6594", "# ARM.exidx end: 0x008e6608"),
        ("disasm_worldtileloader_loadglowblockifneededatpos_tile_.txt", "# implementation: 0x008f4f88", "# ARM.exidx end: 0x008f5530"),
        ("disasm_worldtileloader_addtorchatpos_oftype_dataa_datab_savedic.txt", "# implementation: 0x008e8320", "# ARM.exidx end: 0x008e86b4"),
        ("disasm_worldtileloader_createtreasurechestortrollattile_atpos_l.txt", "# implementation: 0x008e909c", "# ARM.exidx end: 0x008ea738"),
        ("disasm_worldtileloader_loadnewblockheadatpos_craftableitemobjec.txt", "# implementation: 0x008f5b70", "# ARM.exidx end: 0x008f64c0"),
    ):
        require(NATIVE / _lf_file, [_lf_imp, _lf_end])
    require(
        NATIVE / "NET_SYNC.md",
        [
            "10076",
            "dirty-macro-tile",
            "65-slot",
            "FreeBlock",
            "remoteCreationDataUpdate:",
            "setNeedsRemoved: 1",
            "macroPosForWorldPos",
            "sendDataToServer:",
            "blockheadWillBeUnloaded:",
            "liveServerClientBlockheadInventories",
            "initForReadingWithData:",
        ],
    )
    require(
        NATIVE / "net_sync.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 3313',
            "OBJC_IVAR_$_DynamicWorld.worldDatabase",
            "OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions",
            "remoteCreationDataUpdate:",
        ],
    )
    for _ns_file, _ns_imp, _ns_end in (
        ("disasm_worldtileloader_saveandsendonlyblocksthatneedtobesent.txt", "# implementation: 0x008b49f8", "# ARM.exidx end: 0x008b5300"),
        ("disasm_worldtileloader_updatenetobjects.txt", "# implementation: 0x008c4c20", "# ARM.exidx end: 0x008c7fe4"),
        ("disasm_worldtileloader_sendnetdataifneededforobject_iscreation_.txt", "# implementation: 0x008c7fe4", "# ARM.exidx end: 0x008c9740"),
        ("disasm_worldtileloader_loadanyblockheadsfordisconnectedclients.txt", "# implementation: 0x008c9cac", "# ARM.exidx end: 0x008cbc8c"),
        ("disasm_worldtileloader_clientblockheadinventoryrecievedforplaye.txt", "# implementation: 0x008fb288", "# ARM.exidx end: 0x008fbe90"),
        ("disasm_worldtileloader_loadclientblockheadsdataforplayerid_.txt", "# implementation: 0x008fbe90", "# ARM.exidx end: 0x008fdbf0"),
    ):
        require(NATIVE / _ns_file, [_ns_imp, _ns_end])
    require(
        NATIVE / "WORLD_SAVE.md",
        [
            "7058",
            "five-container dirty sweep",
            "macroTileAtMacroPostion",
            "savePhysicalBlockForMacroTile:",
            "5000",
            "worldIndexAtWorldPos",
            "objectTypeCanBeLoadedOnlyWhenClientOwnerOnline",
            "blockheadWillBeUnloaded:",
            "makeIntpair",
            "NSKeyedArchiver",
        ],
    )
    require(
        NATIVE / "world_save.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 2063',
            "OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions",
            "savePhysicalBlockForMacroTile:sendReliably:dontSend:onlySaveIfClientsNeedIt:",
            "macroIndexAtMacroPosition",
        ],
    )
    for _ws_file, _ws_imp, _ws_end in (
        ("disasm_worldtileloader_savegamewithworlddata_signownershipdata_.txt", "# implementation: 0x008b29bc", "# ARM.exidx end: 0x008b49f8"),
        ("disasm_worldtileloader_saveblockheads.txt", "# implementation: 0x008b6f0c", "# ARM.exidx end: 0x008b84c8"),
        ("disasm_worldtileloader_savedynamicobjectsformacrotile_objecttyp.txt", "# implementation: 0x008b933c", "# ARM.exidx end: 0x008ba904"),
        ("disasm_worldtileloader_removedynamicobjectsformacrotile_.txt", "# implementation: 0x008b5e54", "# ARM.exidx end: 0x008b68ac"),
        ("disasm_worldtileloader_worldchangedatpos_sendreliably_.txt", "# implementation: 0x008df7a4", "# ARM.exidx end: 0x008e046c"),
        ("disasm_worldtileloader_clientconnected_.txt", "# implementation: 0x008f7428", "# ARM.exidx end: 0x008f7f90"),
    ):
        require(NATIVE / _ws_file, [_ws_imp, _ws_end])
    require(
        NATIVE / "WORLD_UPDATE.md",
        [
            "6053",
            "0x00E49A64",
            "0x00E4AA3C",
            "0x00E4AA60",
            "reloadDrawBlockWaterForTile",
            "tileIsAirWaterOrSnow",
            "0x67 / 0x68",
            "std::__tree_next",
        ],
    )
    require(
        NATIVE / "world_update.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1292',
            "OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions",
            "checkAndRestorePoleItems:",
            "elevatorMotorForShaftAtPos:",
        ],
    )
    for _wu_file, _wu_imp, _wu_end in (
        ("disasm_worldtileloader_lightchangedatmacropos_sendreliably_send.txt", "# implementation: 0x008e1f18", "# ARM.exidx end: 0x008e2bac"),
        ("disasm_worldtileloader_waterchangedatpos_fullblock_.txt", "# implementation: 0x008e0ad0", "# ARM.exidx end: 0x008e1390"),
        ("disasm_worldtileloader_sowtreenearparent_adult_adultmaxage_.txt", "# implementation: 0x008e2dc8", "# ARM.exidx end: 0x008e37c0"),
        ("disasm_worldtileloader_sowplantnearparent_.txt", "# implementation: 0x008e3edc", "# ARM.exidx end: 0x008e49c8"),
        ("disasm_worldtileloader_gettreelifefractionforpos_.txt", "# implementation: 0x008f9b70", "# ARM.exidx end: 0x008fad90"),
        ("disasm_worldtileloader_checkandrestorepoleitems_.txt", "# implementation: 0x009039e8", "# ARM.exidx end: 0x00904e18"),
        ("disasm_worldtileloader_elevatormotorforshaftatpos_.txt", "# implementation: 0x008ebf40", "# ARM.exidx end: 0x008ecd4c"),
    ):
        require(NATIVE / _wu_file, [_wu_imp, _wu_end])
    require(
        NATIVE / "OBJECT_LIFE.md",
        [
            "6108",
            "0x00E4AA0C",
            "0x00E4AA90",
            "blockheadWillBeUnloaded:",
            "objectTypeHasStaticPosition",
            "itemTypeFromTileIsForegorund",
            "tileIsWorkbench",
            "vcvt.f32.f64",
            "__tree insert_unique",
        ],
    )
    require(
        NATIVE / "object_life.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1116',
            "OBJC_IVAR_$_DynamicWorld.blockheads",
            "doRepairForTileAtPos:",
            "createFreeBlockAtPosition:ofType:dataA:dataB:subItems:dynamicObjectSaveDict:hovers:playSound:priorityBlockhead:",
        ],
    )
    for _ol_file, _ol_imp, _ol_end in (
        ("disasm_worldtileloader_dealloc_dynamicworld.txt", "# implementation: 0x008ad320", "# ARM.exidx end: 0x008ae490"),
        ("disasm_worldtileloader_remoteremove_forobjectsoftype_fromclient.txt", "# implementation: 0x008c420c", "# ARM.exidx end: 0x008c4b74"),
        ("disasm_worldtileloader_dorepairfortileatpos_.txt", "# implementation: 0x00905dd0", "# ARM.exidx end: 0x009067e0"),
        ("disasm_worldtileloader_blockheadatpos_.txt", "# implementation: 0x008f45a4", "# ARM.exidx end: 0x008f4f88"),
        ("disasm_worldtileloader_blockheadoccupiestileatpos_ignoreblockhe.txt", "# implementation: 0x008f3b80", "# ARM.exidx end: 0x008f45a4"),
        ("disasm_worldtileloader_interactionobjectatpos_.txt", "# implementation: 0x008f0550", "# ARM.exidx end: 0x008f1048"),
        ("disasm_worldtileloader_clientdisconnected_simulate_.txt", "# implementation: 0x008f85a0", "# ARM.exidx end: 0x008f8fcc"),
        ("disasm_worldtileloader_createfreeblockatposition_forforegroundcontents_fortile_prio.txt", "# implementation: 0x008de880", "# ARM.exidx end: 0x008df004"),
        ("disasm_worldtileloader_createfreeblockatposition_oftype_dataa_datab_subitems_dynami.txt", "# implementation: 0x008ddc78", "# ARM.exidx end: 0x008de650"),
    ):
        require(NATIVE / _ol_file, [_ol_imp, _ol_end])
    require(
        NATIVE / "DRAW_RELOAD.md",
        [
            "5368",
            "0x00E4AA1C",
            "0x00E18134",
            "__wrap_glEnable",
            "__wrap_free",
            "__wrap_malloc",
            "__wrap_exit",
            "ffe23540",
        ],
    )
    require(
        NATIVE / "draw_reload.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1642',
            "OBJC_IVAR_$_DynamicWorld.dynamicObjects",
            "reloadDynamicObjectStaticGemometryForMacroTile:",
            "drawBlockheadBoxes:projectionMatrix:modelViewMatrix:",
        ],
    )
    for _dr_file, _dr_imp, _dr_end in (
        ("disasm_worldtileloader_drawinfrontofblocksobjects_projectionmat.txt", "# implementation: 0x008d2db8", "# ARM.exidx end: 0x008d4760"),
        ("disasm_worldtileloader_drawnames_projectionmatrix_modelviewmatr.txt", "# implementation: 0x008dc6b4", "# ARM.exidx end: 0x008ddc78"),
        ("disasm_worldtileloader_reloaddynamicobjectquadsformacrotile_.txt", "# implementation: 0x008ff8bc", "# ARM.exidx end: 0x009007c0"),
        ("disasm_worldtileloader_reloaddynamicobjectstaticcylindersformacrotile_.txt", "# implementation: 0x008fec40", "# ARM.exidx end: 0x008ff3dc"),
        ("disasm_worldtileloader_reloaddynamicobjectstaticgemometryformacrotile_.txt", "# implementation: 0x008fe4a4", "# ARM.exidx end: 0x008fec40"),
        ("disasm_worldtileloader_drawblockheadboxes_projectionmatrix_mode.txt", "# implementation: 0x008dc07c", "# ARM.exidx end: 0x008dc6b4"),
    ):
        require(NATIVE / _dr_file, [_dr_imp, _dr_end])
    require(
        NATIVE / "WORLD_MUTATE.md",
        [
            "2673",
            "ffffe5c4",
            "classForInteractionObjectType",
            "recalculateDrawBlockLightingForTile",
            "0x62",
            "tileIsSolid",
        ],
    )
    require(
        NATIVE / "world_mutate.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 532',
            "OBJC_IVAR_$_DynamicWorld.worldChangedMacroPositions",
            "placeTrainCarAtPos:ofType:saveDict:placedByClient:",
            "removeDynamicObjectsBelongingToClient:",
        ],
    )
    for _mu_file, _mu_imp, _mu_end in (
        ("disasm_worldtileloader_worldcontentschangedatpos_.txt", "# implementation: 0x008e046c", "# ARM.exidx end: 0x008e0ad0"),
        ("disasm_worldtileloader_interactionobjectplacedatposition_withit.txt", "# implementation: 0x008e7a60", "# ARM.exidx end: 0x008e7ec4"),
        ("disasm_worldtileloader_removestandardobject_.txt", "# implementation: 0x008e88fc", "# ARM.exidx end: 0x008e8fe8"),
        ("disasm_worldtileloader_removedooratpos_.txt", "# implementation: 0x008edc38", "# ARM.exidx end: 0x008ee1f0"),
        ("disasm_worldtileloader_createclientfreeblockswithdata_.txt", "# implementation: 0x008d0c90", "# ARM.exidx end: 0x008d11a8"),
        ("disasm_worldtileloader_removedynamicobjectsbelongingtoclient_.txt", "# implementation: 0x00904e18", "# ARM.exidx end: 0x00905308"),
        ("disasm_worldtileloader_placetraincaratpos_oftype_savedict_place.txt", "# implementation: 0x008ee700", "# ARM.exidx end: 0x008eef50"),
    ):
        require(NATIVE / _mu_file, [_mu_imp, _mu_end])
    require(
        NATIVE / "BREED_NPC.md",
        [
            "2961",
            "0x00E4AA3C",
            "0x00E4AA1C",
            "0x00E4AA0C",
            "0x00E4AA90",
            "cylindrical wrap-distance",
            "0xfff34184",
            "256-iteration",
        ],
    )
    require(
        NATIVE / "breed_npc.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 574',
            "OBJC_IVAR_$_DynamicWorld.client",
            "teleportBlockhead:toWorkbench:",
            "npcCloseEnoughToBreedWithNPC:",
        ],
    )
    for _br_file, _br_imp, _br_end in (
        ("disasm_worldtileloader_npccloseenoughtobreedwithnpc_.txt", "# implementation: 0x008f3288", "# ARM.exidx end: 0x008f3b80"),
        ("disasm_worldtileloader_findbreedingplantnearplant_.txt", "# implementation: 0x008e37c0", "# ARM.exidx end: 0x008e3ea0"),
        ("disasm_worldtileloader_getplantatpos_.txt", "# implementation: 0x008ef6f8", "# ARM.exidx end: 0x008efe3c"),
        ("disasm_worldtileloader_toomanynpcstospawnmorenearpos_.txt", "# implementation: 0x008f2bb4", "# ARM.exidx end: 0x008f3288"),
        ("disasm_worldtileloader_setpaused_.txt", "# implementation: 0x008f9580", "# ARM.exidx end: 0x008f9b70"),
        ("disasm_worldtileloader_saveblockheadinventory_.txt", "# implementation: 0x008b8634", "# ARM.exidx end: 0x008b8b80"),
        ("disasm_worldtileloader_teleportblockhead_toworkbench_.txt", "# implementation: 0x008f5658", "# ARM.exidx end: 0x008f5b70"),
    ):
        require(NATIVE / _br_file, [_br_imp, _br_end])
    require(
        NATIVE / "CLIENT_SESSION.md",
        [
            "3047",
            "512",
            "0x00E4AA1C",
            "0x00E18104",
            "NSSearchPathForDirectoriesInDomains",
            "ffe23600",
        ],
    )
    require(
        NATIVE / "client_session.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 648',
            "OBJC_IVAR_$_DynamicWorld.server",
            "sendLightblocksToClients",
            "clientPickupRequest:count:clientID:blockheadRequesterUniqueID:",
        ],
    )
    for _se_file, _se_imp, _se_end in (
        ("disasm_worldtileloader_initwithworld_worldtileloader_clienttile.txt", "# implementation: 0x008ac884", "# ARM.exidx end: 0x008ad2a4"),
        ("disasm_worldtileloader_checkforharmabledynamicobjectundertap_ig.txt", "# implementation: 0x008f1acc", "# ARM.exidx end: 0x008f23f4"),
        ("disasm_worldtileloader_clientblockheadwithid_fromclient_request.txt", "# implementation: 0x00905308", "# ARM.exidx end: 0x00905b2c"),
        ("disasm_worldtileloader_sendlightblockstoclients.txt", "# implementation: 0x008b1dd4", "# ARM.exidx end: 0x008b254c"),
        ("disasm_worldtileloader_clientpickuprequest_count_clientid_block.txt", "# implementation: 0x008f6954", "# ARM.exidx end: 0x008f7000"),
        ("disasm_worldtileloader_sendchestinventoryforchest_toclientownin.txt", "# implementation: 0x00901b58", "# ARM.exidx end: 0x00902164"),
    ):
        require(NATIVE / _se_file, [_se_imp, _se_end])
    require(
        NATIVE / "RELOAD_TAIL.md",
        [
            "2280",
            "0x1c4",
            "0x30c",
            "0x180",
            "0x514",
            "ffe23784",
            "ffe237c0",
            "objectTypeMayHaveArtificalLight",
        ],
    )
    require(
        NATIVE / "reload_tail.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 339',
            "OBJC_IVAR_$_DynamicWorld.freeBlocksByPosition",
            "reloadDodoEggQuadsForMacroTile:",
            "freeBlocksAtPos:",
        ],
    )
    for _rt_file, _rt_imp, _rt_end in (
        ("disasm_worldtileloader_reloadlightglowquadsformacrotile_.txt", "# implementation: 0x00900ca0", "# ARM.exidx end: 0x00901180"),
        ("disasm_worldtileloader_reloaddynamicobjectitemquadsformacrotile_.txt", "# implementation: 0x009007c0", "# ARM.exidx end: 0x00900ca0"),
        ("disasm_worldtileloader_reloaddodoeggquadsformacrotile_.txt", "# implementation: 0x008ff3dc", "# ARM.exidx end: 0x008ff8bc"),
        ("disasm_worldtileloader_cxx_destruct_dynamicworld.txt", "# implementation: 0x00906ccc", "# ARM.exidx end: 0x00907218"),
        ("disasm_worldtileloader_addartificiallightcontributionforphysica.txt", "# implementation: 0x00903014", "# ARM.exidx end: 0x00903420"),
        ("disasm_worldtileloader_hasdynamicobjectstosaveinmacropos_.txt", "# implementation: 0x008c98a0", "# ARM.exidx end: 0x008c9cac"),
        ("disasm_worldtileloader_blockheadwillbeunloaded_.txt", "# implementation: 0x00901180", "# ARM.exidx end: 0x00901560"),
        ("disasm_worldtileloader_freeblocksatpos_.txt", "# implementation: 0x008f16bc", "# ARM.exidx end: 0x008f1a78"),
    ):
        require(NATIVE / _rt_file, [_rt_imp, _rt_end])
    require(
        NATIVE / "PLACEMENT.md",
        [
            "1808",
            "treeTypeForSeedItemType",
            "classForDynamicObjectType",
            "ffffe578",
            "0xaa",
            "ffffe558",
        ],
    )
    require(
        NATIVE / "placement.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 278',
            "OBJC_IVAR_$_DynamicWorld.dynamicObjectsByWorldPosIndex",
            "poleItemTaken:",
            "workbenchPlacedAtPosition:ofType:saveDict:placedByClient:clientName:",
        ],
    )
    for _pl_file, _pl_imp, _pl_end in (
        ("disasm_worldtileloader_sowtreeorplantatposition_itemtype_maxhei.txt", "# implementation: 0x008e49c8", "# ARM.exidx end: 0x008e4b2c"),
        ("disasm_worldtileloader_workbenchplacedatposition_oftype_savedic.txt", "# implementation: 0x008e7608", "# ARM.exidx end: 0x008e7a60"),
        ("disasm_worldtileloader_dynamicworldchangedatpos_objecttype_.txt", "# implementation: 0x008e1390", "# ARM.exidx end: 0x008e17ac"),
        ("disasm_worldtileloader_createbackgroundcontentfreeblockatpositi.txt", "# implementation: 0x008df3c4", "# ARM.exidx end: 0x008df7a4"),
        ("disasm_worldtileloader_addrailatpos_oftype_ownedbystation_.txt", "# implementation: 0x008ecea4", "# ARM.exidx end: 0x008ed254"),
        ("disasm_worldtileloader_addstandardobjectatpos_objecttype_itemty.txt", "# implementation: 0x008eb0c0", "# ARM.exidx end: 0x008eb468"),
        ("disasm_worldtileloader_addpaintingatpos_oftype_savedict_placedb.txt", "# implementation: 0x008eac68", "# ARM.exidx end: 0x008eb00c"),
        ("disasm_worldtileloader_poleitemtaken_.txt", "# implementation: 0x0090365c", "# ARM.exidx end: 0x009039e8"),
    ):
        require(NATIVE / _pl_file, [_pl_imp, _pl_end])
    require(
        NATIVE / "LOAD_SESSION.md",
        [
            "1671",
            "netBlockheads",
            "serverClients",
            "dynamicObjects",
            "objectTypeHasStaticPosition",
            "classForDynamicObjectType",
        ],
    )
    require(
        NATIVE / "load_session.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 294',
            "OBJC_IVAR_$_DynamicWorld.dynamicObjects",
            "ridableObjectWithID:",
            "exploreLightChangedAtMacroPos:clientLightBlockIndex:",
        ],
    )
    for _ls_file, _ls_imp, _ls_end in (
        ("disasm_worldtileloader_stopallblockheadactionsforclientduetokic.txt", "# implementation: 0x008f8108", "# ARM.exidx end: 0x008f85a0"),
        ("disasm_worldtileloader_newfoundlistrecievedfromclient_list_.txt", "# implementation: 0x008fad90", "# ARM.exidx end: 0x008fb168"),
        ("disasm_worldtileloader_appenddebuglog_.txt", "# implementation: 0x00902b2c", "# ARM.exidx end: 0x00902f00"),
        ("disasm_worldtileloader_explorelightchangedatmacropos_clientligh.txt", "# implementation: 0x008e17ac", "# ARM.exidx end: 0x008e1b68"),
        ("disasm_worldtileloader_loadlocalinventorydataforchest_.txt", "# implementation: 0x008b8fc4", "# ARM.exidx end: 0x008b933c"),
        ("disasm_worldtileloader_ridableobjectwithid_.txt", "# implementation: 0x008f8fcc", "# ARM.exidx end: 0x008f932c"),
        ("disasm_worldtileloader_loadstandarddynamicobjectoftype_atpos_.txt", "# implementation: 0x008e6250", "# ARM.exidx end: 0x008e6594"),
    ):
        require(NATIVE / _ls_file, [_ls_imp, _ls_end])
    require(
        NATIVE / "REMOTE_RECEIVE.md",
        [
            "1197",
            "0x00E4AA1C",
            "ffffe588",
            "ffffe544",
            "remoteCreationDataUpdate",
            "chestInventoryDataRecievedFromServer",
        ],
    )
    require(
        NATIVE / "remote_receive.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 205',
            "npcExistsAtPos:ignoreNPC:",
            "freeblockPositionChanged:oldPos:",
        ],
    )
    for _rr_file, _rr_imp, _rr_end in (
        ("disasm_worldtileloader_remotecreationdataupdate_forobjectsoftyp.txt", "# implementation: 0x008c3e64", "# ARM.exidx end: 0x008c3fa0"),
        ("disasm_worldtileloader_remoteupdate_forobjectsoftype_fromclient.txt", "# implementation: 0x008c3fa0", "# ARM.exidx end: 0x008c420c"),
        ("disasm_worldtileloader_snowchangedatmacropos_.txt", "# implementation: 0x008e1bf0", "# ARM.exidx end: 0x008e1f18"),
        ("disasm_worldtileloader_npcexistsatpos_ignorenpc_.txt", "# implementation: 0x008f28a4", "# ARM.exidx end: 0x008f2bb4"),
        ("disasm_worldtileloader_freeblockpositionchanged_oldpos_.txt", "# implementation: 0x00906998", "# ARM.exidx end: 0x00906ccc"),
        ("disasm_worldtileloader_requestpaintingdataforpainting_.txt", "# implementation: 0x00901560", "# ARM.exidx end: 0x009016c0"),
        ("disasm_worldtileloader_paintingdatarecievedfromserver_.txt", "# implementation: 0x009019a8", "# ARM.exidx end: 0x00901b58"),
        ("disasm_worldtileloader_chestinventorydatarecievedfromserver_.txt", "# implementation: 0x00902164", "# ARM.exidx end: 0x009023f4"),
    ):
        require(NATIVE / _rr_file, [_rr_imp, _rr_end])
    require(
        NATIVE / "USERS_BANS.md",
        [
            "1013",
            "0x270",
            "ffffe51c",
            "ffffe4f8",
            "ffffe5ac",
            "remotePickupRequestReply",
            "loadDebugChestAtPos",
        ],
    )
    require(
        NATIVE / "users_bans.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 175',
            "blockheadWithUniqueID:",
            "getOwnerNameForObjectOwnerID:",
        ],
    )
    for _ub_file, _ub_imp, _ub_end in (
        ("disasm_worldtileloader_usermutechanged_.txt", "# implementation: 0x009023f4", "# ARM.exidx end: 0x009025e4"),
        ("disasm_worldtileloader_userbanchanged_isbanned_.txt", "# implementation: 0x009025e4", "# ARM.exidx end: 0x0090280c"),
        ("disasm_worldtileloader_playerisbannedwithid_.txt", "# implementation: 0x0090280c", "# ARM.exidx end: 0x009028c8"),
        ("disasm_worldtileloader_playerschanged.txt", "# implementation: 0x009028c8", "# ARM.exidx end: 0x00902ac0"),
        ("disasm_worldtileloader_getownernameforobjectownerid_.txt", "# implementation: 0x00902ac0", "# ARM.exidx end: 0x00902b2c"),
        ("disasm_worldtileloader_iscontrollingblockheadsforclientplayer_.txt", "# implementation: 0x008fdbf0", "# ARM.exidx end: 0x008fdeac"),
        ("disasm_worldtileloader_remotepickuprequestreply_.txt", "# implementation: 0x008f722c", "# ARM.exidx end: 0x008f7428"),
        ("disasm_worldtileloader_blockheadwithuniqueid_.txt", "# implementation: 0x008f7000", "# ARM.exidx end: 0x008f722c"),
        ("disasm_worldtileloader_loaddebugchestatpos_chest_.txt", "# implementation: 0x009067e0", "# ARM.exidx end: 0x00906998"),
    ):
        require(NATIVE / _ub_file, [_ub_imp, _ub_end])
    require(
        NATIVE / "QUERY_ACCESS.md",
        [
            "1133",
            "0x00E4AA1C",
            "0x00E4AA0C",
            "0x1d4",
            "pathUsers",
            "hasLightsToAdd",
        ],
    )
    require(
        NATIVE / "query_access.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 334',
            "npcWithID:",
            "localAndDisconnectedClientBlockheads",
        ],
    )
    for _qa_file, _qa_imp, _qa_end in (
        ("disasm_worldtileloader_npcwithid_.txt", "# implementation: 0x008f23f4", "# ARM.exidx end: 0x008f2630"),
        ("disasm_worldtileloader_harmabledynamicobjectwithid_.txt", "# implementation: 0x008f2630", "# ARM.exidx end: 0x008f28a4"),
        ("disasm_worldtileloader_blockheadwithidincludingnet_.txt", "# implementation: 0x008f932c", "# ARM.exidx end: 0x008f956c"),
        ("disasm_worldtileloader_localanddisconnectedclientblockheads.txt", "# implementation: 0x008f67f8", "# ARM.exidx end: 0x008f6954"),
        ("disasm_worldtileloader_localnetid.txt", "# implementation: 0x008f6568", "# ARM.exidx end: 0x008f6698"),
        ("disasm_worldtileloader_pathusers.txt", "# implementation: 0x008fdf6c", "# ARM.exidx end: 0x008fe4a4"),
        ("disasm_worldtileloader_railorstationnamechanged.txt", "# implementation: 0x008fe280", "# ARM.exidx end: 0x008fe4a4"),
        ("disasm_worldtileloader_haslightstoadd.txt", "# implementation: 0x009034b8", "# ARM.exidx end: 0x00903594"),
    ):
        require(NATIVE / _qa_file, [_qa_imp, _qa_end])
    require(
        NATIVE / "BLOCK_LOAD_ACCESS.md",
        [
            "605",
            "objectTypeIsInteractionObject",
            "0x8b1db0",
            "0x1a",
            "ffffe518",
            "ffffe51c",
        ],
    )
    require(
        NATIVE / "block_load_access.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 169',
            "removeObjectDueToRepair:",
            "connectionToServerLost",
        ],
    )
    for _bl_file, _bl_imp, _bl_end in (
        ("disasm_worldtileloader_removeobjectduetorepair_.txt", "# implementation: 0x00905b2c", "# ARM.exidx end: 0x00905dd0"),
        ("disasm_worldtileloader_clientblockheadsrecievedforplayerid_data.txt", "# implementation: 0x008fb168", "# ARM.exidx end: 0x008fb288"),
        ("disasm_worldtileloader_portalisbeingremovedatpos_.txt", "# implementation: 0x00902f3c", "# ARM.exidx end: 0x00903014"),
        ("disasm_worldtileloader_loadedcountofobjectsoftype_.txt", "# implementation: 0x00903594", "# ARM.exidx end: 0x0090365c"),
        ("disasm_worldtileloader_loadgatherblockatpos_.txt", "# implementation: 0x008f5530", "# ARM.exidx end: 0x008f55e8"),
        ("disasm_worldtileloader_isclient.txt", "# implementation: 0x008f64c0", "# ARM.exidx end: 0x008f6568"),
        ("disasm_worldtileloader_netblockheads.txt", "# implementation: 0x008f676c", "# ARM.exidx end: 0x008f67f8"),
        ("disasm_worldtileloader_gatherblockatpos_.txt", "# implementation: 0x008f55e8", "# ARM.exidx end: 0x008f5658"),
        ("disasm_worldtileloader_isserver.txt", "# implementation: 0x008f6514", "# ARM.exidx end: 0x008f6568"),
        ("disasm_worldtileloader_allblockheadsincludingnet.txt", "# implementation: 0x008f6698", "# ARM.exidx end: 0x008f676c"),
        ("disasm_worldtileloader_portalpositions.txt", "# implementation: 0x008fdeac", "# ARM.exidx end: 0x008fdee8"),
        ("disasm_worldtileloader_blockheads.txt", "# implementation: 0x00902f00", "# ARM.exidx end: 0x00902f3c"),
        ("disasm_worldtileloader_connectiontoserverlost.txt", "# implementation: 0x008f956c", "# ARM.exidx end: 0x008f9580"),
    ):
        require(NATIVE / _bl_file, [_bl_imp, _bl_end])
    require(
        NATIVE / "ACCESSOR_A.md",
        [
            "711",
            "0x11 (17)",
            "0x1e (30)",
            "0x34 (52)",
            "tileIsPlant",
            "0x270",
        ],
    )
    require(
        NATIVE / "accessor_a.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 160',
            "placeFireAtPosition:",
            "paintingWithID:",
        ],
    )
    for _a1_file, _a1_imp, _a1_end in (
        ("disasm_worldtileloader_placefireatposition_.txt", "# implementation: 0x008e80e4", "# ARM.exidx end: 0x008e8320"),
        ("disasm_worldtileloader_objectoftype_atpos_.txt", "# implementation: 0x008e86b4", "# ARM.exidx end: 0x008e888c"),
        ("disasm_worldtileloader_torchatpos_.txt", "# implementation: 0x008e888c", "# ARM.exidx end: 0x008e88fc"),
        ("disasm_worldtileloader_removetorchatpos_.txt", "# implementation: 0x008e8fe8", "# ARM.exidx end: 0x008e909c"),
        ("disasm_worldtileloader_eggatpos_.txt", "# implementation: 0x008ea738", "# ARM.exidx end: 0x008ea7a8"),
        ("disasm_worldtileloader_addeggatpos_savedict_.txt", "# implementation: 0x008ea7a8", "# ARM.exidx end: 0x008eaa28"),
        ("disasm_worldtileloader_removeeggatpos_.txt", "# implementation: 0x008eaa28", "# ARM.exidx end: 0x008eaadc"),
        ("disasm_worldtileloader_paintingwithid_.txt", "# implementation: 0x008eaadc", "# ARM.exidx end: 0x008eabf8"),
        ("disasm_worldtileloader_paintingatpos_.txt", "# implementation: 0x008eabf8", "# ARM.exidx end: 0x008eac68"),
        ("disasm_worldtileloader_removepaintingatpos_.txt", "# implementation: 0x008eb00c", "# ARM.exidx end: 0x008eb0c0"),
    ):
        require(NATIVE / _a1_file, [_a1_imp, _a1_end])
    require(
        NATIVE / "ACCESSOR_B.md",
        [
            "456",
            "0x13 (19)",
            "0x35 (53)",
            "0x36 (54)",
            "0x38 (56)",
            "ffe23624",
        ],
    )
    require(
        NATIVE / "accessor_b.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 41',
            "elevatorShaftAtPos:",
            "removeElevatorShaftAtPos:",
        ],
    )
    for _a2_file, _a2_imp, _a2_end in (
        ("disasm_worldtileloader_ladderatpos_.txt", "# implementation: 0x008eb468", "# ARM.exidx end: 0x008eb4d8"),
        ("disasm_worldtileloader_addladderatpos_oftype_savedict_placedbyc.txt", "# implementation: 0x008eb4d8", "# ARM.exidx end: 0x008eb57c"),
        ("disasm_worldtileloader_removeladderatpos_.txt", "# implementation: 0x008eb57c", "# ARM.exidx end: 0x008eb630"),
        ("disasm_worldtileloader_columnatpos_.txt", "# implementation: 0x008eb630", "# ARM.exidx end: 0x008eb6a0"),
        ("disasm_worldtileloader_addcolumnatpos_oftype_savedict_placedbyc.txt", "# implementation: 0x008eb6a0", "# ARM.exidx end: 0x008eb744"),
        ("disasm_worldtileloader_removecolumnatpos_.txt", "# implementation: 0x008eb744", "# ARM.exidx end: 0x008eb7f8"),
        ("disasm_worldtileloader_stairsatpos_.txt", "# implementation: 0x008eb7f8", "# ARM.exidx end: 0x008eb868"),
        ("disasm_worldtileloader_addstairsatpos_oftype_savedict_placedbyc.txt", "# implementation: 0x008eb868", "# ARM.exidx end: 0x008eb90c"),
        ("disasm_worldtileloader_removestairsatpos_.txt", "# implementation: 0x008eb90c", "# ARM.exidx end: 0x008eb9c0"),
        ("disasm_worldtileloader_elevatorshaftatpos_.txt", "# implementation: 0x008ebb88", "# ARM.exidx end: 0x008ebbf8"),
        ("disasm_worldtileloader_addelevatorshaftatpos_oftype_savedict_pl.txt", "# implementation: 0x008ebbf8", "# ARM.exidx end: 0x008ebc9c"),
        ("disasm_worldtileloader_removeelevatorshaftatpos_.txt", "# implementation: 0x008ebc9c", "# ARM.exidx end: 0x008ebd50"),
    ):
        require(NATIVE / _a2_file, [_a2_imp, _a2_end])
    require(
        NATIVE / "ACCESSOR_C.md",
        [
            "1307",
            "0x1f (31)",
            "0x14 (20)",
            "0x180",
            "0x00E4AA0C",
            "ffe23664",
        ],
    )
    require(
        NATIVE / "accessor_c.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 149',
            "addDoorAtPos:ofType:saveDict:placedByClient:",
            "boatWithID:",
        ],
    )
    for _a3_file, _a3_imp, _a3_end in (
        ("disasm_worldtileloader_windowatpos_.txt", "# implementation: 0x008ed3a4", "# ARM.exidx end: 0x008ed414"),
        ("disasm_worldtileloader_addwindowatpos_oftype_savedict_placedbyc.txt", "# implementation: 0x008ed414", "# ARM.exidx end: 0x008ed4b8"),
        ("disasm_worldtileloader_removewindowatpos_.txt", "# implementation: 0x008ed4b8", "# ARM.exidx end: 0x008ed56c"),
        ("disasm_worldtileloader_adddooratpos_oftype_savedict_placedbycli.txt", "# implementation: 0x008ed56c", "# ARM.exidx end: 0x008ed7c0"),
        ("disasm_worldtileloader_dooratpos_.txt", "# implementation: 0x008ed7c0", "# ARM.exidx end: 0x008ed950"),
        ("disasm_worldtileloader_doorcanbeusedbypathuser_atpos_.txt", "# implementation: 0x008ed950", "# ARM.exidx end: 0x008edb58"),
        ("disasm_worldtileloader_doorisopenatpos_.txt", "# implementation: 0x008edb58", "# ARM.exidx end: 0x008edc38"),
        ("disasm_worldtileloader_setdooratpos_toopen_direction_.txt", "# implementation: 0x008ef3c8", "# ARM.exidx end: 0x008ef488"),
        ("disasm_worldtileloader_posofdoorsotherblockatpos_.txt", "# implementation: 0x008ef488", "# ARM.exidx end: 0x008ef618"),
        ("disasm_worldtileloader_placeboatinwateratpos_savedict_placedbyc.txt", "# implementation: 0x008ee1f0", "# ARM.exidx end: 0x008ee3e8"),
        ("disasm_worldtileloader_checkforboatundertap_.txt", "# implementation: 0x008ee3e8", "# ARM.exidx end: 0x008ee5e4"),
        ("disasm_worldtileloader_boatwithid_.txt", "# implementation: 0x008ee5e4", "# ARM.exidx end: 0x008ee700"),
        ("disasm_worldtileloader_checkfortraincarundertap_.txt", "# implementation: 0x008eef50", "# ARM.exidx end: 0x008ef18c"),
        ("disasm_worldtileloader_traincarwithid_.txt", "# implementation: 0x008ef18c", "# ARM.exidx end: 0x008ef3c8"),
    ):
        require(NATIVE / _a3_file, [_a3_imp, _a3_end])
    require(
        NATIVE / "WORKBENCH_INTERACTION.md",
        [
            "887",
            "0x2d (45)",
            "0x00E4AA90",
            "0x21c",
            "ffffe588",
            "ffffe560",
        ],
    )
    require(
        NATIVE / "workbench_interaction.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 238',
            "workbenchAtPos:",
            "getNextDynamicObjectID",
        ],
    )
    for _wb_file, _wb_imp, _wb_end in (
        ("disasm_worldtileloader_workbenchatpos_.txt", "# implementation: 0x008efe3c", "# ARM.exidx end: 0x008f0090"),
        ("disasm_worldtileloader_workbenchhasbeencrafted.txt", "# implementation: 0x008f015c", "# ARM.exidx end: 0x008f0198"),
        ("disasm_worldtileloader_assigncraftprogressuitoloadedworkbenches.txt", "# implementation: 0x008f0198", "# ARM.exidx end: 0x008f0550"),
        ("disasm_worldtileloader_interactionobjectwithid_.txt", "# implementation: 0x008f1048", "# ARM.exidx end: 0x008f1284"),
        ("disasm_worldtileloader_interactionobjecttypeforobjectatpos_.txt", "# implementation: 0x008f1284", "# ARM.exidx end: 0x008f1354"),
        ("disasm_worldtileloader_removeworkbenchatpos_removeblockhead_.txt", "# implementation: 0x008f1354", "# ARM.exidx end: 0x008f145c"),
        ("disasm_worldtileloader_removeinteractionobjectatpos_removeblock.txt", "# implementation: 0x008f145c", "# ARM.exidx end: 0x008f1564"),
        ("disasm_worldtileloader_freeblocksexistatpos_.txt", "# implementation: 0x008f1564", "# ARM.exidx end: 0x008f16bc"),
        ("disasm_worldtileloader_getnextdynamicobjectid.txt", "# implementation: 0x008f1a78", "# ARM.exidx end: 0x008f1acc"),
        ("disasm_worldtileloader_portal.txt", "# implementation: 0x008f0090", "# ARM.exidx end: 0x008f015c"),
    ):
        require(NATIVE / _wb_file, [_wb_imp, _wb_end])
    require(
        NATIVE / "SAVE_REMOTE_SIM.md",
        [
            "1297",
            "0x2e (46)",
            "0xe (14",
            "objectTypeCanBeLoadedOnlyWhenClientOwnerOnline",
            "0xfff33ef4",
            "8.0",
        ],
    )
    require(
        NATIVE / "save_remote_sim.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 284',
            "saveDynamicObjects",
            "setServer:serverClients:",
        ],
    )
    for _sc_file, _sc_imp, _sc_end in (
        ("disasm_worldtileloader_savedynamicobjects.txt", "# implementation: 0x008b254c", "# ARM.exidx end: 0x008b29bc"),
        ("disasm_worldtileloader_remotecreate_forobjectsoftype_clientid_.txt", "# implementation: 0x008c3c08", "# ARM.exidx end: 0x008c3e64"),
        ("disasm_worldtileloader_loadclientowneddynamicobjectsforclient_p.txt", "# implementation: 0x008bd6bc", "# ARM.exidx end: 0x008bd9b8"),
        ("disasm_worldtileloader_finishsimulating.txt", "# implementation: 0x008cbc8c", "# ARM.exidx end: 0x008cbf40"),
        ("disasm_worldtileloader_removesavedinventoryforchest_.txt", "# implementation: 0x008b8dc0", "# ARM.exidx end: 0x008b8fc4"),
        ("disasm_worldtileloader_saferemovefromdynamicobjectdatabase_.txt", "# implementation: 0x008b8c58", "# ARM.exidx end: 0x008b8dc0"),
        ("disasm_worldtileloader_mainthreadremovedirfromconversionlist_.txt", "# implementation: 0x008ae490", "# ARM.exidx end: 0x008ae5b8"),
        ("disasm_worldtileloader_removeportalfromlistatpos_.txt", "# implementation: 0x008b8b80", "# ARM.exidx end: 0x008b8c58"),
        ("disasm_worldtileloader_simulate_.txt", "# implementation: 0x008c9740", "# ARM.exidx end: 0x008c98a0"),
        ("disasm_worldtileloader_update_accuratedt_.txt", "# implementation: 0x008c9810", "# ARM.exidx end: 0x008c98a0"),
        ("disasm_worldtileloader_setserver_serverclients_.txt", "# implementation: 0x008ad2b4", "# ARM.exidx end: 0x008ad320"),
    ):
        require(NATIVE / _sc_file, [_sc_imp, _sc_end])
    require(
        NATIVE / "DRAW_PASS.md",
        [
            "2344",
            "ffe23538",
            "ffe23534",
            "0xa8",
            "0x00E4AA1C",
            "map<int, int>",
        ],
    )
    require(
        NATIVE / "draw_pass.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1395',
            "preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:",
            "drawFreeBlocks:projectionMatrix:",
        ],
    )
    for _dp_file, _dp_imp, _dp_end in (
        ("disasm_worldtileloader_predrawupdate_cameraminxworld_cameramaxx.txt", "# implementation: 0x008d11a8", "# ARM.exidx end: 0x008d17ec"),
        ("disasm_worldtileloader_drawopaqueobjects_projectionmatrix_model.txt", "# implementation: 0x008d17ec", "# ARM.exidx end: 0x008d2db8"),
        ("disasm_worldtileloader_drawfreeblocks_projectionmatrix_modelvie.txt", "# implementation: 0x008d4760", "# ARM.exidx end: 0x008d4ff0"),
    ):
        require(NATIVE / _dp_file, [_dp_imp, _dp_end])
    require(
        NATIVE / "FINAL_SMALLS.md",
        [
            "380",
            "ffffe55c",
            "ffffe5a4",
            "0xa8",
            "ffe23580",
            "0xfff34074",
        ],
    )
    require(
        NATIVE / "final_smalls.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 140',
            "playTimeCrystalReceivedSoundAtPos:",
            "activeBlockheadIndex",
        ],
    )
    for _fs_file, _fs_imp, _fs_end in (
        ("disasm_worldtileloader_playtimecrystalreceivedsoundatpos_.txt", "# implementation: 0x008de650", "# ARM.exidx end: 0x008de880"),
        ("disasm_worldtileloader_freeblockwithuniqueid_.txt", "# implementation: 0x008df2a8", "# ARM.exidx end: 0x008df3c4"),
        ("disasm_worldtileloader_lightchangedatmacropos_sendreliably_.txt", "# implementation: 0x008e1b68", "# ARM.exidx end: 0x008e1bf0"),
        ("disasm_worldtileloader_activeblockhead.txt", "# implementation: 0x008e2bac", "# ARM.exidx end: 0x008e2cbc"),
        ("disasm_worldtileloader_activeblockheadindex.txt", "# implementation: 0x008e2cbc", "# ARM.exidx end: 0x008e2cf8"),
        ("disasm_worldtileloader_selectedblockheadchanged_.txt", "# implementation: 0x008e2cf8", "# ARM.exidx end: 0x008e2dc8"),
    ):
        require(NATIVE / _fs_file, [_fs_imp, _fs_end])
    require(
        NATIVE / "LAST_SMALLS.md",
        [
            "536",
            "0x37 (55)",
            "0x28 (40)",
            "0x00E4AA64",
            "ffe23640",
            "ffe23648",
        ],
    )
    require(
        NATIVE / "last_smalls.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 186',
            "openElevatorAtPos:",
            "treeAtPos:",
        ],
    )
    for _ls2_file, _ls2_imp, _ls2_end in (
        ("disasm_worldtileloader_openelevatoratpos_.txt", "# implementation: 0x008ebd50", "# ARM.exidx end: 0x008ebed0"),
        ("disasm_worldtileloader_elevatormotoratpos_.txt", "# implementation: 0x008ebed0", "# ARM.exidx end: 0x008ebf40"),
        ("disasm_worldtileloader_addelevatormotoratpos_oftype_savedict_pl.txt", "# implementation: 0x008ecd4c", "# ARM.exidx end: 0x008ecdf0"),
        ("disasm_worldtileloader_removeelevatormotoratpos_.txt", "# implementation: 0x008ecdf0", "# ARM.exidx end: 0x008ecea4"),
        ("disasm_worldtileloader_getrailatpos_.txt", "# implementation: 0x008ed254", "# ARM.exidx end: 0x008ed2c4"),
        ("disasm_worldtileloader_removerailatpos_.txt", "# implementation: 0x008ed2c4", "# ARM.exidx end: 0x008ed3a4"),
        ("disasm_worldtileloader_treeatpos_.txt", "# implementation: 0x008ef618", "# ARM.exidx end: 0x008ef6f8"),
        ("disasm_worldtileloader_sendpaintingdataforpaintingwithid_toclie.txt", "# implementation: 0x009016c0", "# ARM.exidx end: 0x009019a8"),
    ):
        require(NATIVE / _ls2_file, [_ls2_imp, _ls2_end])
    require(
        NATIVE / "WORLD_NET.md",
        [
            "8016",
            "2312",
            "0xc350",
            "0x7fffffff",
            "0x3e7",
        ],
    )
    require(
        NATIVE / "world_net.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 2312',
            "summaryNetDataForAdmin:",
            "peersInterestedInMacroIndex:",
        ],
    )
    for _wn_file, _wn_imp, _wn_end in (
        ("disasm_worldtileloader_wn_00.txt", "implementation: 0x005536ec", "ARM.exidx end: 0x0055468c"),
        ("disasm_worldtileloader_wn_01.txt", "implementation: 0x005547f8", "ARM.exidx end: 0x00554cfc"),
        ("disasm_worldtileloader_wn_02.txt", "implementation: 0x00554cfc", "ARM.exidx end: 0x00554f04"),
        ("disasm_worldtileloader_wn_03.txt", "implementation: 0x00554f04", "ARM.exidx end: 0x0055555c"),
        ("disasm_worldtileloader_wn_04.txt", "implementation: 0x0055555c", "ARM.exidx end: 0x00555a84"),
        ("disasm_worldtileloader_wn_05.txt", "implementation: 0x00557bd4", "ARM.exidx end: 0x00557c40"),
        ("disasm_worldtileloader_wn_06.txt", "implementation: 0x0056b674", "ARM.exidx end: 0x0056da94"),
        ("disasm_worldtileloader_wn_07.txt", "implementation: 0x0056dbd8", "ARM.exidx end: 0x0056dc8c"),
        ("disasm_worldtileloader_wn_08.txt", "implementation: 0x0056dc8c", "ARM.exidx end: 0x0056dd38"),
        ("disasm_worldtileloader_wn_09.txt", "implementation: 0x005b9e10", "ARM.exidx end: 0x005ba014"),
        ("disasm_worldtileloader_wn_10.txt", "implementation: 0x005ba014", "ARM.exidx end: 0x005bb634"),
        ("disasm_worldtileloader_wn_11.txt", "implementation: 0x005bfcb0", "ARM.exidx end: 0x005c01a4"),
        ("disasm_worldtileloader_wn_12.txt", "implementation: 0x005c01a4", "ARM.exidx end: 0x005c0570"),
        ("disasm_worldtileloader_wn_13.txt", "implementation: 0x005c0570", "ARM.exidx end: 0x005c0698"),
        ("disasm_worldtileloader_wn_14.txt", "implementation: 0x005c0698", "ARM.exidx end: 0x005c07c0"),
        ("disasm_worldtileloader_wn_15.txt", "implementation: 0x005c07c0", "ARM.exidx end: 0x005c0b4c"),
        ("disasm_worldtileloader_wn_16.txt", "implementation: 0x005c0b4c", "ARM.exidx end: 0x005c0f54"),
        ("disasm_worldtileloader_wn_17.txt", "implementation: 0x005c0f54", "ARM.exidx end: 0x005c1298"),
        ("disasm_worldtileloader_wn_18.txt", "implementation: 0x005c1298", "ARM.exidx end: 0x005c15dc"),
        ("disasm_worldtileloader_wn_19.txt", "implementation: 0x005c15dc", "ARM.exidx end: 0x005c1920"),
        ("disasm_worldtileloader_wn_20.txt", "implementation: 0x005c1920", "ARM.exidx end: 0x005c19b4"),
    ):
        require(NATIVE / _wn_file, [_wn_imp, _wn_end])
    require(
        NATIVE / "WORLD_RENDER.md",
        [
            "33840",
            "29808",
            "glVertexAttribPointer",
            "pushDepthMaskState",
            "0xbe2",
        ],
    )
    require(
        NATIVE / "world_render.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 29808',
            "exportCurrentFrame",
            "doPortalScreenshot",
        ],
    )
    for _wd_file, _wd_imp, _wd_end in (
        ("disasm_worldtileloader_wd_00.txt", "implementation: 0x0058c7f8", "ARM.exidx end: 0x005a99b8"),
        ("disasm_worldtileloader_wd_01.txt", "implementation: 0x005aa5c8", "ARM.exidx end: 0x005ab1ac"),
        ("disasm_worldtileloader_wd_02.txt", "implementation: 0x005ab5bc", "ARM.exidx end: 0x005ac12c"),
        ("disasm_worldtileloader_wd_03.txt", "implementation: 0x005b3e78", "ARM.exidx end: 0x005b3fb0"),
        ("disasm_worldtileloader_wd_04.txt", "implementation: 0x005b3fb0", "ARM.exidx end: 0x005b4304"),
        ("disasm_worldtileloader_wd_05.txt", "implementation: 0x005b466c", "ARM.exidx end: 0x005b4a00"),
        ("disasm_worldtileloader_wd_06.txt", "implementation: 0x005b6698", "ARM.exidx end: 0x005b6820"),
        ("disasm_worldtileloader_wd_07.txt", "implementation: 0x005b6820", "ARM.exidx end: 0x005b6fa8"),
        ("disasm_worldtileloader_wd_08.txt", "implementation: 0x005c29c0", "ARM.exidx end: 0x005c3278"),
        ("disasm_worldtileloader_wd_09.txt", "implementation: 0x005c3800", "ARM.exidx end: 0x005c3d24"),
        ("disasm_worldtileloader_wd_10.txt", "implementation: 0x005c5ce0", "ARM.exidx end: 0x005c5fa8"),
        ("disasm_worldtileloader_wd_11.txt", "implementation: 0x005c5fa8", "ARM.exidx end: 0x005c60ac"),
        ("disasm_worldtileloader_wd_12.txt", "implementation: 0x005c6414", "ARM.exidx end: 0x005c6898"),
        ("disasm_worldtileloader_wd_13.txt", "implementation: 0x005d5534", "ARM.exidx end: 0x005d5584"),
    ):
        require(NATIVE / _wd_file, [_wd_imp, _wd_end])
    require(
        NATIVE / "WORLD_SIMULATION.md",
        [
            "22239",
            "7369",
            "glDeleteTextures",
            "itemTypeIsSowable",
            "0x15180",
        ],
    )
    require(
        NATIVE / "world_simulation.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 7369',
            "continueSimulate",
            "addSimulationEventOfType:",
        ],
    )
    for _ws_file, _ws_imp, _ws_end in (
        ("disasm_worldtileloader_ws_00.txt", "implementation: 0x00564c64", "ARM.exidx end: 0x00564f2c"),
        ("disasm_worldtileloader_ws_01.txt", "implementation: 0x00564f2c", "ARM.exidx end: 0x005650d8"),
        ("disasm_worldtileloader_ws_02.txt", "implementation: 0x005650d8", "ARM.exidx end: 0x00566948"),
        ("disasm_worldtileloader_ws_03.txt", "implementation: 0x00566e64", "ARM.exidx end: 0x0056783c"),
        ("disasm_worldtileloader_ws_04.txt", "implementation: 0x00567878", "ARM.exidx end: 0x0056871c"),
        ("disasm_worldtileloader_ws_05.txt", "implementation: 0x0056884c", "ARM.exidx end: 0x0056b278"),
        ("disasm_worldtileloader_ws_06.txt", "implementation: 0x0056b278", "ARM.exidx end: 0x0056b674"),
        ("disasm_worldtileloader_ws_07.txt", "implementation: 0x0056dd38", "ARM.exidx end: 0x0056dd78"),
        ("disasm_worldtileloader_ws_08.txt", "implementation: 0x0056dd78", "ARM.exidx end: 0x0057509c"),
        ("disasm_worldtileloader_ws_09.txt", "implementation: 0x00583c50", "ARM.exidx end: 0x0058b764"),
        ("disasm_worldtileloader_ws_10.txt", "implementation: 0x005ac1a4", "ARM.exidx end: 0x005ac350"),
        ("disasm_worldtileloader_ws_11.txt", "implementation: 0x005c78c4", "ARM.exidx end: 0x005c8094"),
    ):
        require(NATIVE / _ws_file, [_ws_imp, _ws_end])
    require(
        NATIVE / "WORLD_MUTATION.md",
        [
            "15099",
            "4785",
            "polarToRectangular",
            "linearInterpolate",
            "0x1f4",
        ],
    )
    require(
        NATIVE / "world_mutation.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 4785',
            "paintTile:",
            "waterMovedFrom:",
        ],
    )
    for _wm_file, _wm_imp, _wm_end in (
        ("disasm_worldtileloader_wm_00.txt", "implementation: 0x005751f8", "ARM.exidx end: 0x0057598c"),
        ("disasm_worldtileloader_wm_01.txt", "implementation: 0x005759bc", "ARM.exidx end: 0x00575ac8"),
        ("disasm_worldtileloader_wm_02.txt", "implementation: 0x00575ac8", "ARM.exidx end: 0x00575d44"),
        ("disasm_worldtileloader_wm_03.txt", "implementation: 0x00575d44", "ARM.exidx end: 0x00576120"),
        ("disasm_worldtileloader_wm_04.txt", "implementation: 0x005762c8", "ARM.exidx end: 0x00576518"),
        ("disasm_worldtileloader_wm_05.txt", "implementation: 0x00576518", "ARM.exidx end: 0x00576878"),
        ("disasm_worldtileloader_wm_06.txt", "implementation: 0x00578430", "ARM.exidx end: 0x00578a20"),
        ("disasm_worldtileloader_wm_07.txt", "implementation: 0x00578a20", "ARM.exidx end: 0x00578c94"),
        ("disasm_worldtileloader_wm_08.txt", "implementation: 0x00578c94", "ARM.exidx end: 0x00579074"),
        ("disasm_worldtileloader_wm_09.txt", "implementation: 0x00579d58", "ARM.exidx end: 0x0057a30c"),
        ("disasm_worldtileloader_wm_10.txt", "implementation: 0x0057b700", "ARM.exidx end: 0x0057bd18"),
        ("disasm_worldtileloader_wm_11.txt", "implementation: 0x0057bd70", "ARM.exidx end: 0x0057bf90"),
        ("disasm_worldtileloader_wm_12.txt", "implementation: 0x0057bf90", "ARM.exidx end: 0x0057c034"),
        ("disasm_worldtileloader_wm_13.txt", "implementation: 0x00580f88", "ARM.exidx end: 0x0058122c"),
        ("disasm_worldtileloader_wm_14.txt", "implementation: 0x0058122c", "ARM.exidx end: 0x0058198c"),
        ("disasm_worldtileloader_wm_15.txt", "implementation: 0x00581a38", "ARM.exidx end: 0x00582364"),
        ("disasm_worldtileloader_wm_16.txt", "implementation: 0x00582364", "ARM.exidx end: 0x00582408"),
        ("disasm_worldtileloader_wm_17.txt", "implementation: 0x00582408", "ARM.exidx end: 0x00582488"),
        ("disasm_worldtileloader_wm_18.txt", "implementation: 0x00582488", "ARM.exidx end: 0x00582a14"),
        ("disasm_worldtileloader_wm_19.txt", "implementation: 0x00582a50", "ARM.exidx end: 0x00582ad8"),
        ("disasm_worldtileloader_wm_20.txt", "implementation: 0x00582ad8", "ARM.exidx end: 0x00582e00"),
        ("disasm_worldtileloader_wm_21.txt", "implementation: 0x00583578", "ARM.exidx end: 0x00583c50"),
        ("disasm_worldtileloader_wm_22.txt", "implementation: 0x0058c350", "ARM.exidx end: 0x0058c408"),
        ("disasm_worldtileloader_wm_23.txt", "implementation: 0x0058c408", "ARM.exidx end: 0x0058c558"),
        ("disasm_worldtileloader_wm_24.txt", "implementation: 0x0058c558", "ARM.exidx end: 0x0058c6b8"),
        ("disasm_worldtileloader_wm_25.txt", "implementation: 0x0058c6b8", "ARM.exidx end: 0x0058c7f8"),
        ("disasm_worldtileloader_wm_26.txt", "implementation: 0x005b3b70", "ARM.exidx end: 0x005b3e78"),
        ("disasm_worldtileloader_wm_27.txt", "implementation: 0x005c1ddc", "ARM.exidx end: 0x005c2790"),
        ("disasm_worldtileloader_wm_28.txt", "implementation: 0x005d6fc8", "ARM.exidx end: 0x005d70b4"),
        ("disasm_worldtileloader_wm_52.txt", "implementation: 0x00576120", "ARM.exidx end: 0x005761e0"),
        ("disasm_worldtileloader_wm_51.txt", "implementation: 0x005761e0", "ARM.exidx end: 0x005762c8"),
        ("disasm_worldtileloader_wm_50.txt", "implementation: 0x00576878", "ARM.exidx end: 0x00578430"),
        ("disasm_worldtileloader_wm_55.txt", "implementation: 0x00579074", "ARM.exidx end: 0x00579a48"),
        ("disasm_worldtileloader_wm_53.txt", "implementation: 0x0057a30c", "ARM.exidx end: 0x0057b5e4"),
        ("disasm_worldtileloader_wm_56.txt", "implementation: 0x0057c034", "ARM.exidx end: 0x0057c11c"),
        ("disasm_worldtileloader_wm_54.txt", "implementation: 0x0057c11c", "ARM.exidx end: 0x00580be0"),
    ):
        require(NATIVE / _wm_file, [_wm_imp, _wm_end])
    require(
        NATIVE / "TRAIN_CAR.md",
        [
            "7219",
            "setRightCar",
            "setEngineCar",
            "connectsToOtherCars",
            "0xbf00",
        ],
    )
    require(
        NATIVE / "train_car.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1753',
            "leftWheelPos",
            "rightWheelPos",
        ],
    )
    for _tc_file, _tc_imp, _tc_end in (
        ("disasm_worldtileloader_tc_00.txt", "implementation: 0x00a37550", "ARM.exidx end: 0x00a385f8"),
        ("disasm_worldtileloader_tc_01.txt", "implementation: 0x00a385f8", "ARM.exidx end: 0x00a38614"),
        ("disasm_worldtileloader_tc_02.txt", "implementation: 0x00a38614", "ARM.exidx end: 0x00a3892c"),
        ("disasm_worldtileloader_tc_03.txt", "implementation: 0x00a38ed8", "ARM.exidx end: 0x00a390cc"),
        ("disasm_worldtileloader_tc_04.txt", "implementation: 0x00a390cc", "ARM.exidx end: 0x00a394b0"),
        ("disasm_worldtileloader_tc_05.txt", "implementation: 0x00a39d64", "ARM.exidx end: 0x00a39db0"),
        ("disasm_worldtileloader_tc_06.txt", "implementation: 0x00a39db0", "ARM.exidx end: 0x00a3a26c"),
        ("disasm_worldtileloader_tc_07.txt", "implementation: 0x00a3a26c", "ARM.exidx end: 0x00a3a3a0"),
        ("disasm_worldtileloader_tc_08.txt", "implementation: 0x00a3a34c", "ARM.exidx end: 0x00a3a3a0"),
        ("disasm_worldtileloader_tc_09.txt", "implementation: 0x00a3a3a0", "ARM.exidx end: 0x00a3a5d8"),
        ("disasm_worldtileloader_tc_10.txt", "implementation: 0x00a3a5d8", "ARM.exidx end: 0x00a3c13c"),
        ("disasm_worldtileloader_tc_11.txt", "implementation: 0x00a3c13c", "ARM.exidx end: 0x00a3c264"),
        ("disasm_worldtileloader_tc_12.txt", "implementation: 0x00a3c264", "ARM.exidx end: 0x00a3c488"),
        ("disasm_worldtileloader_tc_13.txt", "implementation: 0x00a3c488", "ARM.exidx end: 0x00a3ca44"),
        ("disasm_worldtileloader_tc_14.txt", "implementation: 0x00a3ca44", "ARM.exidx end: 0x00a3cc6c"),
        ("disasm_worldtileloader_tc_15.txt", "implementation: 0x00a3cc6c", "ARM.exidx end: 0x00a3cc88"),
        ("disasm_worldtileloader_tc_16.txt", "implementation: 0x00a3cc88", "ARM.exidx end: 0x00a3cd78"),
        ("disasm_worldtileloader_tc_17.txt", "implementation: 0x00a3cd00", "ARM.exidx end: 0x00a3cd78"),
        ("disasm_worldtileloader_tc_18.txt", "implementation: 0x00a3cd28", "ARM.exidx end: 0x00a3cd78"),
        ("disasm_worldtileloader_tc_19.txt", "implementation: 0x00a3cd78", "ARM.exidx end: 0x00a3cd94"),
        ("disasm_worldtileloader_tc_20.txt", "implementation: 0x00a3cd94", "ARM.exidx end: 0x00a3cdb0"),
        ("disasm_worldtileloader_tc_21.txt", "implementation: 0x00a3cdb0", "ARM.exidx end: 0x00a3d384"),
        ("disasm_worldtileloader_tc_22.txt", "implementation: 0x00a3d384", "ARM.exidx end: 0x00a3d5ec"),
        ("disasm_worldtileloader_tc_23.txt", "implementation: 0x00a3d5ec", "ARM.exidx end: 0x00a3d600"),
        ("disasm_worldtileloader_tc_24.txt", "implementation: 0x00a3d600", "ARM.exidx end: 0x00a3d630"),
        ("disasm_worldtileloader_tc_25.txt", "implementation: 0x00a3d630", "ARM.exidx end: 0x00a3d6bc"),
        ("disasm_worldtileloader_tc_26.txt", "implementation: 0x00a3d6bc", "ARM.exidx end: 0x00a3db70"),
        ("disasm_worldtileloader_tc_27.txt", "implementation: 0x00a3db70", "ARM.exidx end: 0x00a3dbbc"),
        ("disasm_worldtileloader_tc_28.txt", "implementation: 0x00a3dba0", "ARM.exidx end: 0x00a3dbbc"),
        ("disasm_worldtileloader_tc_29.txt", "implementation: 0x00a3dbbc", "ARM.exidx end: 0x00a3dc08"),
        ("disasm_worldtileloader_tc_30.txt", "implementation: 0x00a3dc08", "ARM.exidx end: 0x00a3dff8"),
        ("disasm_worldtileloader_tc_31.txt", "implementation: 0x00a3dff8", "ARM.exidx end: 0x00a3e180"),
        ("disasm_worldtileloader_tc_32.txt", "implementation: 0x00a3e180", "ARM.exidx end: 0x00a3e1b8"),
        ("disasm_worldtileloader_tc_33.txt", "implementation: 0x00a3e19c", "ARM.exidx end: 0x00a3e1b8"),
        ("disasm_worldtileloader_tc_34.txt", "implementation: 0x00a3e1b8", "ARM.exidx end: 0x00a3e210"),
        ("disasm_worldtileloader_tc_35.txt", "implementation: 0x00a3e1e4", "ARM.exidx end: 0x00a3e210"),
        ("disasm_worldtileloader_tc_36.txt", "implementation: 0x00a3e210", "ARM.exidx end: 0x00a3e248"),
        ("disasm_worldtileloader_tc_37.txt", "implementation: 0x00a3e22c", "ARM.exidx end: 0x00a3e248"),
        ("disasm_worldtileloader_tc_38.txt", "implementation: 0x00a3e248", "ARM.exidx end: 0x00a3e260"),
        ("disasm_worldtileloader_tc_39.txt", "implementation: 0x00a3e260", "ARM.exidx end: 0x00a3e30c"),
        ("disasm_worldtileloader_tc_40.txt", "implementation: 0x00a3e27c", "ARM.exidx end: 0x00a3e30c"),
        ("disasm_worldtileloader_tc_41.txt", "implementation: 0x00a3e2c4", "ARM.exidx end: 0x00a3e30c"),
        ("disasm_worldtileloader_tc_42.txt", "implementation: 0x00a3e30c", "ARM.exidx end: 0x00a3e454"),
        ("disasm_worldtileloader_tc_43.txt", "implementation: 0x00a3e454", "ARM.exidx end: 0x00a3e59c"),
        ("disasm_worldtileloader_tc_44.txt", "implementation: 0x00a3e59c", "ARM.exidx end: 0x00a3e614"),
        ("disasm_worldtileloader_tc_45.txt", "implementation: 0x00a3e5d8", "ARM.exidx end: 0x00a3e614"),
        ("disasm_worldtileloader_tc_46.txt", "implementation: 0x00a3e614", "ARM.exidx end: 0x00a3e6a4"),
        ("disasm_worldtileloader_tc_47.txt", "implementation: 0x00a3e6a4", "ARM.exidx end: 0x00a3eb0c"),
        ("disasm_worldtileloader_tc_48.txt", "implementation: 0x00a3eb0c", "ARM.exidx end: 0x00a3eb58"),
        ("disasm_worldtileloader_tc_49.txt", "implementation: 0x00a3eb28", "ARM.exidx end: 0x00a3eb58"),
        ("disasm_worldtileloader_tc_50.txt", "implementation: 0x00a3eb44", "ARM.exidx end: 0x00a3eb58"),
        ("disasm_worldtileloader_tc_51.txt", "implementation: 0x00a3eb58", "ARM.exidx end: 0x00a3ecac"),
        ("disasm_worldtileloader_tc_52.txt", "implementation: 0x00a3ecac", "ARM.exidx end: 0x00a3ed50"),
        ("disasm_worldtileloader_tc_53.txt", "implementation: 0x00a3ed50", "ARM.exidx end: 0x00a3ef44"),
        ("disasm_worldtileloader_tc_54.txt", "implementation: 0x00a3ef44", "ARM.exidx end: 0x00a3ef7c"),
        ("disasm_worldtileloader_tc_55.txt", "implementation: 0x00a3ef60", "ARM.exidx end: 0x00a3ef7c"),
        ("disasm_worldtileloader_tc_56.txt", "implementation: 0x00a3ef7c", "ARM.exidx end: 0x00a3f16c"),
    ):
        require(NATIVE / _tc_file, [_tc_imp, _tc_end])
    require(
        NATIVE / "YAK.md",
        [
            "8563",
            "0x13f",
            "0x143",
            "powf",
            "lrand48",
        ],
    )
    require(
        NATIVE / "yak.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 3592',
            "milkByBlockhead:",
            "shaveByBlockhead:",
        ],
    )
    for _yk_file, _yk_imp, _yk_end in (
        ("disasm_worldtileloader_y_00.txt", "implementation: 0x0095c7c4", "ARM.exidx end: 0x0095c7e0"),
        ("disasm_worldtileloader_y_01.txt", "implementation: 0x0095c7e0", "ARM.exidx end: 0x0095c874"),
        ("disasm_worldtileloader_y_02.txt", "implementation: 0x0095c810", "ARM.exidx end: 0x0095c874"),
        ("disasm_worldtileloader_y_03.txt", "implementation: 0x0095c844", "ARM.exidx end: 0x0095c874"),
        ("disasm_worldtileloader_y_04.txt", "implementation: 0x0095c874", "ARM.exidx end: 0x0095c914"),
        ("disasm_worldtileloader_y_05.txt", "implementation: 0x0095c890", "ARM.exidx end: 0x0095c914"),
        ("disasm_worldtileloader_y_06.txt", "implementation: 0x0095c8c0", "ARM.exidx end: 0x0095c914"),
        ("disasm_worldtileloader_y_07.txt", "implementation: 0x0095c8dc", "ARM.exidx end: 0x0095c914"),
        ("disasm_worldtileloader_y_08.txt", "implementation: 0x0095c8f8", "ARM.exidx end: 0x0095c914"),
        ("disasm_worldtileloader_y_09.txt", "implementation: 0x0095c914", "ARM.exidx end: 0x0095c9c0"),
        ("disasm_worldtileloader_y_10.txt", "implementation: 0x0095c9c0", "ARM.exidx end: 0x0095cba8"),
        ("disasm_worldtileloader_y_11.txt", "implementation: 0x0095cba8", "ARM.exidx end: 0x0095d640"),
        ("disasm_worldtileloader_y_12.txt", "implementation: 0x0095d640", "ARM.exidx end: 0x0095d65c"),
        ("disasm_worldtileloader_y_13.txt", "implementation: 0x0095d65c", "ARM.exidx end: 0x0095d868"),
        ("disasm_worldtileloader_y_14.txt", "implementation: 0x0095d868", "ARM.exidx end: 0x0095dae4"),
        ("disasm_worldtileloader_y_15.txt", "implementation: 0x0095dcfc", "ARM.exidx end: 0x0095dee4"),
        ("disasm_worldtileloader_y_16.txt", "implementation: 0x0095e0a8", "ARM.exidx end: 0x0095e270"),
        ("disasm_worldtileloader_y_17.txt", "implementation: 0x0095e270", "ARM.exidx end: 0x0095e47c"),
        ("disasm_worldtileloader_y_18.txt", "implementation: 0x0095e47c", "ARM.exidx end: 0x0095e568"),
        ("disasm_worldtileloader_y_19.txt", "implementation: 0x0095e568", "ARM.exidx end: 0x0095e6a0"),
        ("disasm_worldtileloader_y_20.txt", "implementation: 0x0095e6a0", "ARM.exidx end: 0x0095e834"),
        ("disasm_worldtileloader_y_21.txt", "implementation: 0x0095e834", "ARM.exidx end: 0x0095e99c"),
        ("disasm_worldtileloader_y_22.txt", "implementation: 0x0095e99c", "ARM.exidx end: 0x0095e9b8"),
        ("disasm_worldtileloader_y_23.txt", "implementation: 0x0095e9b8", "ARM.exidx end: 0x009621d8"),
        ("disasm_worldtileloader_y_24.txt", "implementation: 0x00963040", "ARM.exidx end: 0x00965290"),
        ("disasm_worldtileloader_y_25.txt", "implementation: 0x00965850", "ARM.exidx end: 0x009658b4"),
        ("disasm_worldtileloader_y_26.txt", "implementation: 0x009658b4", "ARM.exidx end: 0x0096596c"),
        ("disasm_worldtileloader_y_27.txt", "implementation: 0x0096596c", "ARM.exidx end: 0x00965c1c"),
        ("disasm_worldtileloader_y_28.txt", "implementation: 0x00965c1c", "ARM.exidx end: 0x00965cd4"),
        ("disasm_worldtileloader_y_29.txt", "implementation: 0x00965cd4", "ARM.exidx end: 0x00965fb0"),
        ("disasm_worldtileloader_y_30.txt", "implementation: 0x00965fb0", "ARM.exidx end: 0x00966388"),
        ("disasm_worldtileloader_y_31.txt", "implementation: 0x00966388", "ARM.exidx end: 0x009663bc"),
        ("disasm_worldtileloader_y_32.txt", "implementation: 0x009663a4", "ARM.exidx end: 0x009663bc"),
    ):
        require(NATIVE / _yk_file, [_yk_imp, _yk_end])
    require(
        NATIVE / "DONKEYLIKE.md",
        [
            "18480",
            "tileIsAirWaterOrSnow",
            "tileContainsGate",
            "0x1518",
            "cosf",
        ],
    )
    require(
        NATIVE / "donkeylike.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 7982',
            "doDonkeyLikeRemoteUpdate:",
            "cantBeCapturedTipStringForBlockhead:withItemType:",
        ],
    )
    for _dl_file, _dl_imp, _dl_end in (
        ("disasm_worldtileloader_dl_00.txt", "implementation: 0x00ab0710", "ARM.exidx end: 0x00ab0aa8"),
        ("disasm_worldtileloader_dl_01.txt", "implementation: 0x00ab0aa8", "ARM.exidx end: 0x00ab0ac4"),
        ("disasm_worldtileloader_dl_02.txt", "implementation: 0x00ab0ac4", "ARM.exidx end: 0x00ab0c3c"),
        ("disasm_worldtileloader_dl_03.txt", "implementation: 0x00ab0d64", "ARM.exidx end: 0x00ab0eb0"),
        ("disasm_worldtileloader_dl_04.txt", "implementation: 0x00ab0eb0", "ARM.exidx end: 0x00ab1008"),
        ("disasm_worldtileloader_dl_05.txt", "implementation: 0x00ab1008", "ARM.exidx end: 0x00ab11cc"),
        ("disasm_worldtileloader_dl_06.txt", "implementation: 0x00ab11cc", "ARM.exidx end: 0x00ab12f0"),
        ("disasm_worldtileloader_dl_07.txt", "implementation: 0x00ab12f0", "ARM.exidx end: 0x00ab13dc"),
        ("disasm_worldtileloader_dl_08.txt", "implementation: 0x00ab13dc", "ARM.exidx end: 0x00ab13f8"),
        ("disasm_worldtileloader_dl_09.txt", "implementation: 0x00ab13f8", "ARM.exidx end: 0x00ab14c4"),
        ("disasm_worldtileloader_dl_10.txt", "implementation: 0x00ab14c4", "ARM.exidx end: 0x00ab1cdc"),
        ("disasm_worldtileloader_dl_11.txt", "implementation: 0x00ab1d18", "ARM.exidx end: 0x00ab1e84"),
        ("disasm_worldtileloader_dl_12.txt", "implementation: 0x00ab1e84", "ARM.exidx end: 0x00ab1fc4"),
        ("disasm_worldtileloader_dl_13.txt", "implementation: 0x00ab1fc4", "ARM.exidx end: 0x00ab2130"),
        ("disasm_worldtileloader_dl_14.txt", "implementation: 0x00ab2130", "ARM.exidx end: 0x00ab9de8"),
        ("disasm_worldtileloader_dl_15.txt", "implementation: 0x00abc508", "ARM.exidx end: 0x00ac2748"),
        ("disasm_worldtileloader_dl_16.txt", "implementation: 0x00ac2ef0", "ARM.exidx end: 0x00ac2f10"),
        ("disasm_worldtileloader_dl_17.txt", "implementation: 0x00ac2f10", "ARM.exidx end: 0x00ac35ec"),
        ("disasm_worldtileloader_dl_18.txt", "implementation: 0x00ac35ec", "ARM.exidx end: 0x00ac381c"),
        ("disasm_worldtileloader_dl_19.txt", "implementation: 0x00ac381c", "ARM.exidx end: 0x00ac398c"),
        ("disasm_worldtileloader_dl_20.txt", "implementation: 0x00ac398c", "ARM.exidx end: 0x00ac4260"),
        ("disasm_worldtileloader_dl_21.txt", "implementation: 0x00ac4260", "ARM.exidx end: 0x00ac43d4"),
        ("disasm_worldtileloader_dl_22.txt", "implementation: 0x00ac42e0", "ARM.exidx end: 0x00ac43d4"),
        ("disasm_worldtileloader_dl_23.txt", "implementation: 0x00ac43d4", "ARM.exidx end: 0x00ac457c"),
        ("disasm_worldtileloader_dl_24.txt", "implementation: 0x00ac457c", "ARM.exidx end: 0x00ac45a8"),
        ("disasm_worldtileloader_dl_25.txt", "implementation: 0x00ac45a8", "ARM.exidx end: 0x00ac46e4"),
        ("disasm_worldtileloader_dl_26.txt", "implementation: 0x00ac46e4", "ARM.exidx end: 0x00ac47dc"),
        ("disasm_worldtileloader_dl_27.txt", "implementation: 0x00ac47dc", "ARM.exidx end: 0x00ac4858"),
        ("disasm_worldtileloader_dl_28.txt", "implementation: 0x00ac4858", "ARM.exidx end: 0x00ac489c"),
        ("disasm_worldtileloader_dl_29.txt", "implementation: 0x00ac489c", "ARM.exidx end: 0x00ac48d0"),
        ("disasm_worldtileloader_dl_30.txt", "implementation: 0x00ac48d0", "ARM.exidx end: 0x00ac4a84"),
        ("disasm_worldtileloader_dl_31.txt", "implementation: 0x00ac4a84", "ARM.exidx end: 0x00ac4a9c"),
        ("disasm_worldtileloader_dl_32.txt", "implementation: 0x00ac4a9c", "ARM.exidx end: 0x00ac4ab8"),
        ("disasm_worldtileloader_dl_33.txt", "implementation: 0x00ac4ab8", "ARM.exidx end: 0x00ac4ba8"),
        ("disasm_worldtileloader_dl_34.txt", "implementation: 0x00ac4ba8", "ARM.exidx end: 0x00ac4be0"),
        ("disasm_worldtileloader_dl_35.txt", "implementation: 0x00ac4bc4", "ARM.exidx end: 0x00ac4be0"),
        ("disasm_worldtileloader_dl_36.txt", "implementation: 0x00ac4be0", "ARM.exidx end: 0x00ac4cd8"),
        ("disasm_worldtileloader_dl_37.txt", "implementation: 0x00ac4cd8", "ARM.exidx end: 0x00ac4f84"),
        ("disasm_worldtileloader_dl_38.txt", "implementation: 0x00ac4f84", "ARM.exidx end: 0x00ac4ff4"),
        ("disasm_worldtileloader_dl_39.txt", "implementation: 0x00ac4fa0", "ARM.exidx end: 0x00ac4ff4"),
        ("disasm_worldtileloader_dl_40.txt", "implementation: 0x00ac4fbc", "ARM.exidx end: 0x00ac4ff4"),
        ("disasm_worldtileloader_dl_41.txt", "implementation: 0x00ac4fd8", "ARM.exidx end: 0x00ac4ff4"),
        ("disasm_worldtileloader_dl_42.txt", "implementation: 0x00ac4ff4", "ARM.exidx end: 0x00ac50d8"),
        ("disasm_worldtileloader_dl_43.txt", "implementation: 0x00ac50d8", "ARM.exidx end: 0x00ac5240"),
        ("disasm_worldtileloader_dl_44.txt", "implementation: 0x00ac5240", "ARM.exidx end: 0x00ac525c"),
        ("disasm_worldtileloader_dl_45.txt", "implementation: 0x00ac525c", "ARM.exidx end: 0x00ac5644"),
    ):
        require(NATIVE / _dl_file, [_dl_imp, _dl_end])
    require(
        NATIVE / "DONKEY.md",
        [
            "15785",
            "sinf",
            "glUniformMatrix4fv",
            "nameForDonkeyBreed",
            "0xde1",
        ],
    )
    require(
        NATIVE / "donkey.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 7321',
            "setupMatrices:dt:",
            "generateBreedForChild",
        ],
    )
    for _dk_file, _dk_imp, _dk_end in (
        ("disasm_worldtileloader_d_npctype.txt", "implementation: 0x006ba498", "ARM.exidx end: 0x006ba4b4"),
        ("disasm_worldtileloader_d_maxage.txt", "implementation: 0x006ba4b4", "ARM.exidx end: 0x006ba518"),
        ("disasm_worldtileloader_d_minfullness.txt", "implementation: 0x006ba4e4", "ARM.exidx end: 0x006ba518"),
        ("disasm_worldtileloader_d_foodplanttype.txt", "implementation: 0x006ba518", "ARM.exidx end: 0x006ba570"),
        ("disasm_worldtileloader_d_speciesname.txt", "implementation: 0x006ba570", "ARM.exidx end: 0x006ba5e0"),
        ("disasm_worldtileloader_d_fooditemtype.txt", "implementation: 0x006ba5e0", "ARM.exidx end: 0x006ba6ac"),
        ("disasm_worldtileloader_d_captureditemtype.txt", "implementation: 0x006ba638", "ARM.exidx end: 0x006ba6ac"),
        ("disasm_worldtileloader_d_capturerequireditemtype.txt", "implementation: 0x006ba690", "ARM.exidx end: 0x006ba6ac"),
        ("disasm_worldtileloader_d_getnamesarray.txt", "implementation: 0x006ba6ac", "ARM.exidx end: 0x006ba71c"),
        ("disasm_worldtileloader_d_getnamesarraycount.txt", "implementation: 0x006ba71c", "ARM.exidx end: 0x006ba790"),
        ("disasm_worldtileloader_d_creationdatastructsize.txt", "implementation: 0x006ba774", "ARM.exidx end: 0x006ba790"),
        ("disasm_worldtileloader_d_loadderivedstuff.txt", "implementation: 0x006ba790", "ARM.exidx end: 0x006bc3ac"),
        ("disasm_worldtileloader_d_dealloc.txt", "implementation: 0x006bc680", "ARM.exidx end: 0x006bc8f4"),
        ("disasm_worldtileloader_d_maxhealth.txt", "implementation: 0x006bc8f4", "ARM.exidx end: 0x006bc9b0"),
        ("disasm_worldtileloader_d_flies.txt", "implementation: 0x006bc910", "ARM.exidx end: 0x006bc9b0"),
        ("disasm_worldtileloader_d_canjumpmultipletileswhilefly.txt", "implementation: 0x006bc960", "ARM.exidx end: 0x006bc9b0"),
        ("disasm_worldtileloader_d_galloping.txt", "implementation: 0x006bc9b0", "ARM.exidx end: 0x006bca88"),
        ("disasm_worldtileloader_d_maxvelocity.txt", "implementation: 0x006bca88", "ARM.exidx end: 0x006bcad8"),
        ("disasm_worldtileloader_d_setupmatrices_dt_.txt", "implementation: 0x006bcad8", "ARM.exidx end: 0x006c3d3c"),
        ("disasm_worldtileloader_d_drawsubclassstuff_projection.txt", "implementation: 0x006c4ba4", "ARM.exidx end: 0x006c9fe0"),
        ("disasm_worldtileloader_d_createitemdropsfordeath.txt", "implementation: 0x006ca8a0", "ARM.exidx end: 0x006caf24"),
        ("disasm_worldtileloader_d_generatebreedforchild.txt", "implementation: 0x006cad1c", "ARM.exidx end: 0x006caf24"),
        ("disasm_worldtileloader_d_breedstring.txt", "implementation: 0x006caedc", "ARM.exidx end: 0x006caf24"),
        ("disasm_worldtileloader_d_blockheadcanride_usingitem_.txt", "implementation: 0x006cb018", "ARM.exidx end: 0x006cb1f4"),
        ("disasm_worldtileloader_d_cxx_construct.txt", "implementation: 0x006cb1f4", "ARM.exidx end: 0x006cb20c"),
    ):
        require(NATIVE / _dk_file, [_dk_imp, _dk_end])
    require(
        NATIVE / "GEM_TREE.md",
        [
            "4471",
            "0x6e,0x71,0x74",
            "0x57,0x56,0x4c",
            "worldIndexAtWorldPosition",
            "recursively",
        ],
    )
    require(
        NATIVE / "gem_tree.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1640',
            "bushContentsType",
            "trunkBushContentsType",
        ],
    )
    for _g_file, _g_imp, _g_end in (
        ("disasm_worldtileloader_g_objecttype.txt", "implementation: 0x005275b4", "ARM.exidx end: 0x005275d0"),
        ("disasm_worldtileloader_g_fruititem.txt", "implementation: 0x005275d0", "ARM.exidx end: 0x00527620"),
        ("disasm_worldtileloader_g_fruitseason.txt", "implementation: 0x00527620", "ARM.exidx end: 0x0052772c"),
        ("disasm_worldtileloader_g_shouldfall.txt", "implementation: 0x0052772c", "ARM.exidx end: 0x00527748"),
        ("disasm_worldtileloader_g_ctor.txt", "implementation: 0x00527748", "ARM.exidx end: 0x005290e8"),
        ("disasm_worldtileloader_g_growth.txt", "implementation: 0x00529578", "ARM.exidx end: 0x00529590"),
        ("disasm_worldtileloader_g_bushcontents.txt", "implementation: 0x00529590", "ARM.exidx end: 0x005297b8"),
        ("disasm_worldtileloader_g_trunkcontents.txt", "implementation: 0x00529648", "ARM.exidx end: 0x005297b8"),
        ("disasm_worldtileloader_g_trunkbushcontents.txt", "implementation: 0x00529700", "ARM.exidx end: 0x005297b8"),
        ("disasm_worldtileloader_g_makedead.txt", "implementation: 0x005297b8", "ARM.exidx end: 0x005298e0"),
        ("disasm_worldtileloader_g_update.txt", "implementation: 0x005298e0", "ARM.exidx end: 0x0052a078"),
        ("disasm_worldtileloader_g_worldchanged.txt", "implementation: 0x0052a078", "ARM.exidx end: 0x0052b6e8"),
        ("disasm_worldtileloader_g_recursivetiles.txt", "implementation: 0x0052b750", "ARM.exidx end: 0x0052bae4"),
        ("disasm_worldtileloader_g_treetype.txt", "implementation: 0x0052bae4", "ARM.exidx end: 0x0052bb20"),
        ("disasm_worldtileloader_g_gemitem.txt", "implementation: 0x0052bb20", "ARM.exidx end: 0x0052bbdc"),
        ("disasm_worldtileloader_g_kindself.txt", "implementation: 0x0052bbdc", "ARM.exidx end: 0x0052be44"),
        ("disasm_worldtileloader_g_isstatic.txt", "implementation: 0x0052be44", "ARM.exidx end: 0x0052be60"),
    ):
        require(NATIVE / _g_file, [_g_imp, _g_end])
    require(
        NATIVE / "TULIP_PLANT.md",
        [
            "5691",
            "0xffff",
            "glUniform4f",
            "clamp_float",
            "0x1c2",
        ],
    )
    require(
        NATIVE / "tulip_plant.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1465',
            "colorGenesVariation",
            "mixGenesVariation",
        ],
    )
    for _tl_file, _tl_imp, _tl_end in (
        ("disasm_worldtileloader_tl_objecttype.txt", "implementation: 0x0099f950", "ARM.exidx end: 0x0099f96c"),
        ("disasm_worldtileloader_tl_initsubderived.txt", "implementation: 0x0099f96c", "ARM.exidx end: 0x009a0710"),
        ("disasm_worldtileloader_tl_ctor.txt", "implementation: 0x009a09f8", "ARM.exidx end: 0x009a1368"),
        ("disasm_worldtileloader_tl_ctorsave.txt", "implementation: 0x009a1368", "ARM.exidx end: 0x009a1684"),
        ("disasm_worldtileloader_tl_ctornet.txt", "implementation: 0x009a1684", "ARM.exidx end: 0x009a1854"),
        ("disasm_worldtileloader_tl_creationdata.txt", "implementation: 0x009a1b58", "ARM.exidx end: 0x009a1d20"),
        ("disasm_worldtileloader_tl_setflowering.txt", "implementation: 0x009a1c24", "ARM.exidx end: 0x009a1d20"),
        ("disasm_worldtileloader_tl_update.txt", "implementation: 0x009a1d20", "ARM.exidx end: 0x009a2b00"),
        ("disasm_worldtileloader_tl_draw.txt", "implementation: 0x009a2b00", "ARM.exidx end: 0x009a41e4"),
        ("disasm_worldtileloader_tl_kindself.txt", "implementation: 0x009a498c", "ARM.exidx end: 0x009a49c0"),
        ("disasm_worldtileloader_tl_planttype.txt", "implementation: 0x009a49c0", "ARM.exidx end: 0x009a49dc"),
        ("disasm_worldtileloader_tl_soiltype.txt", "implementation: 0x009a49dc", "ARM.exidx end: 0x009a4a78"),
        ("disasm_worldtileloader_tl_harvested.txt", "implementation: 0x009a4a78", "ARM.exidx end: 0x009a4f1c"),
        ("disasm_worldtileloader_tl_tilesabove.txt", "implementation: 0x009a4f1c", "ARM.exidx end: 0x009a4f90"),
        ("disasm_worldtileloader_tl_droppeditem.txt", "implementation: 0x009a4f74", "ARM.exidx end: 0x009a4f90"),
        ("disasm_worldtileloader_tl_staticquadcount.txt", "implementation: 0x009a4f90", "ARM.exidx end: 0x009a4fb8"),
        ("disasm_worldtileloader_tl_adddrawquad.txt", "implementation: 0x009a4fb8", "ARM.exidx end: 0x009a5354"),
        ("disasm_worldtileloader_tl_rmmacro.txt", "implementation: 0x009a53c8", "ARM.exidx end: 0x009a54d0"),
        ("disasm_worldtileloader_tl_canbreed.txt", "implementation: 0x009a54d0", "ARM.exidx end: 0x009a557c"),
        ("disasm_worldtileloader_tl_mixgenes.txt", "implementation: 0x009a557c", "ARM.exidx end: 0x009a5770"),
        ("disasm_worldtileloader_tl_colorgenevar.txt", "implementation: 0x009a5770", "ARM.exidx end: 0x009a5c50"),
        ("disasm_worldtileloader_tl_availfood.txt", "implementation: 0x009a5d24", "ARM.exidx end: 0x009a5db8"),
        ("disasm_worldtileloader_tl_setavailfood.txt", "implementation: 0x009a5d6c", "ARM.exidx end: 0x009a5db8"),
        ("disasm_worldtileloader_tl_colorgene.txt", "implementation: 0x009a5db8", "ARM.exidx end: 0x009a5df4"),
        ("disasm_worldtileloader_tl_setcolorgene.txt", "implementation: 0x009a5df4", "ARM.exidx end: 0x009a5e3c"),
        ("disasm_worldtileloader_tl_cxxconstruct.txt", "implementation: 0x009a5e3c", "ARM.exidx end: 0x009a5fb4"),
    ):
        require(NATIVE / _tl_file, [_tl_imp, _tl_end])
    require(
        NATIVE / "KELP_PLANT.md",
        [
            "5280",
            "sinf",
            "updateArbitraryQuadV",
            "macroTileAtMacroPostion",
            "tileIsWater",
        ],
    )
    require(
        NATIVE / "kelp_plant.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 918',
            "dieOfOldAge",
            "addDrawQuadData:fromIndex:forMacroPos:",
        ],
    )
    for _kp_file, _kp_imp, _kp_end in (
        ("disasm_worldtileloader_k_objecttype.txt", "implementation: 0x00814a54", "ARM.exidx end: 0x00814a70"),
        ("disasm_worldtileloader_k_initsubderived.txt", "implementation: 0x00814a70", "ARM.exidx end: 0x00814f44"),
        ("disasm_worldtileloader_k_ctor.txt", "implementation: 0x00814f54", "ARM.exidx end: 0x00815be8"),
        ("disasm_worldtileloader_k_ctornet.txt", "implementation: 0x00816560", "ARM.exidx end: 0x008166e0"),
        ("disasm_worldtileloader_k_creationdata.txt", "implementation: 0x00816960", "ARM.exidx end: 0x008169ec"),
        ("disasm_worldtileloader_k_dealloc.txt", "implementation: 0x008169ec", "ARM.exidx end: 0x00816a58"),
        ("disasm_worldtileloader_k_remoteupdate.txt", "implementation: 0x00816a58", "ARM.exidx end: 0x00816e34"),
        ("disasm_worldtileloader_k_update.txt", "implementation: 0x00816e34", "ARM.exidx end: 0x00817c8c"),
        ("disasm_worldtileloader_k_dieofoldage.txt", "implementation: 0x00817c8c", "ARM.exidx end: 0x00818150"),
        ("disasm_worldtileloader_k_draw.txt", "implementation: 0x00818150", "ARM.exidx end: 0x00818cec"),
        ("disasm_worldtileloader_k_kindself.txt", "implementation: 0x00818d9c", "ARM.exidx end: 0x00818dd0"),
        ("disasm_worldtileloader_k_planttype.txt", "implementation: 0x00818dd0", "ARM.exidx end: 0x00818dec"),
        ("disasm_worldtileloader_k_soiltype.txt", "implementation: 0x00818dec", "ARM.exidx end: 0x00818e74"),
        ("disasm_worldtileloader_k_gatherprogress.txt", "implementation: 0x00818e74", "ARM.exidx end: 0x00818f7c"),
        ("disasm_worldtileloader_k_harvested.txt", "implementation: 0x00818f7c", "ARM.exidx end: 0x00819858"),
        ("disasm_worldtileloader_k_setgather.txt", "implementation: 0x00819858", "ARM.exidx end: 0x008199ac"),
        ("disasm_worldtileloader_k_tilesabove.txt", "implementation: 0x008199ac", "ARM.exidx end: 0x00819a04"),
        ("disasm_worldtileloader_k_droppeditem.txt", "implementation: 0x008199e8", "ARM.exidx end: 0x00819a04"),
        ("disasm_worldtileloader_k_staticquadcount.txt", "implementation: 0x00819a04", "ARM.exidx end: 0x00819cd8"),
        ("disasm_worldtileloader_k_adddrawquad.txt", "implementation: 0x00819cd8", "ARM.exidx end: 0x0081a6f0"),
        ("disasm_worldtileloader_k_rmmacro.txt", "implementation: 0x0081a6f0", "ARM.exidx end: 0x0081a890"),
        ("disasm_worldtileloader_k_availfood.txt", "implementation: 0x0081a890", "ARM.exidx end: 0x0081a924"),
        ("disasm_worldtileloader_k_setavailfood.txt", "implementation: 0x0081a8d8", "ARM.exidx end: 0x0081a924"),
    ):
        require(NATIVE / _kp_file, [_kp_imp, _kp_end])
    require(
        NATIVE / "VINE_PLANT.md",
        [
            "4102",
            "currentTemperatureForTileAt",
            "tileIsWater",
            "fillArbitraryQuadBuffer",
            "macroPosForWorldPos",
        ],
    )
    require(
        NATIVE / "vine_plant.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 758',
            "dieOfOldAge",
            "staticGeometryForegroundDrawQuadCountForMacroPos:",
        ],
    )
    for _vp_file, _vp_imp, _vp_end in (
        ("disasm_worldtileloader_v_objecttype.txt", "implementation: 0x004f58ec", "ARM.exidx end: 0x004f5908"),
        ("disasm_worldtileloader_v_initsubderived.txt", "implementation: 0x004f5908", "ARM.exidx end: 0x004f5cb4"),
        ("disasm_worldtileloader_v_ctor.txt", "implementation: 0x004f5cb4", "ARM.exidx end: 0x004f688c"),
        ("disasm_worldtileloader_v_ctornet.txt", "implementation: 0x004f7344", "ARM.exidx end: 0x004f74c4"),
        ("disasm_worldtileloader_v_remoteupdate.txt", "implementation: 0x004f7744", "ARM.exidx end: 0x004f7b20"),
        ("disasm_worldtileloader_v_dealloc.txt", "implementation: 0x004f7b20", "ARM.exidx end: 0x004f7b8c"),
        ("disasm_worldtileloader_v_creationdata.txt", "implementation: 0x004f7b8c", "ARM.exidx end: 0x004f7cf0"),
        ("disasm_worldtileloader_v_compost.txt", "implementation: 0x004f7c18", "ARM.exidx end: 0x004f7cf0"),
        ("disasm_worldtileloader_v_update.txt", "implementation: 0x004f7cf0", "ARM.exidx end: 0x004f86a8"),
        ("disasm_worldtileloader_v_dieofoldage.txt", "implementation: 0x004f86a8", "ARM.exidx end: 0x004f8a6c"),
        ("disasm_worldtileloader_v_kindself.txt", "implementation: 0x004f8a6c", "ARM.exidx end: 0x004f8aa0"),
        ("disasm_worldtileloader_v_planttype.txt", "implementation: 0x004f8aa0", "ARM.exidx end: 0x004f8abc"),
        ("disasm_worldtileloader_v_soiltype.txt", "implementation: 0x004f8abc", "ARM.exidx end: 0x004f8b58"),
        ("disasm_worldtileloader_v_gatherprogress.txt", "implementation: 0x004f8b58", "ARM.exidx end: 0x004f8c64"),
        ("disasm_worldtileloader_v_harvested.txt", "implementation: 0x004f8c64", "ARM.exidx end: 0x004f956c"),
        ("disasm_worldtileloader_v_setgather.txt", "implementation: 0x004f956c", "ARM.exidx end: 0x004f96c0"),
        ("disasm_worldtileloader_v_tilesbelow.txt", "implementation: 0x004f96c0", "ARM.exidx end: 0x004f96fc"),
        ("disasm_worldtileloader_v_setneedsremoved.txt", "implementation: 0x004f96fc", "ARM.exidx end: 0x004f9788"),
        ("disasm_worldtileloader_v_droppeditem.txt", "implementation: 0x004f9788", "ARM.exidx end: 0x004f97a4"),
        ("disasm_worldtileloader_v_fgquadcount.txt", "implementation: 0x004f97a4", "ARM.exidx end: 0x004f9a78"),
        ("disasm_worldtileloader_v_addfgquad.txt", "implementation: 0x004f9a78", "ARM.exidx end: 0x004fa2e8"),
        ("disasm_worldtileloader_v_rmmacro.txt", "implementation: 0x004fa3d4", "ARM.exidx end: 0x004fa570"),
        ("disasm_worldtileloader_v_availfood.txt", "implementation: 0x004fa570", "ARM.exidx end: 0x004fa604"),
        ("disasm_worldtileloader_v_setavailfood.txt", "implementation: 0x004fa5b8", "ARM.exidx end: 0x004fa604"),
    ):
        require(NATIVE / _vp_file, [_vp_imp, _vp_end])
    require(
        NATIVE / "CROP_SMALLS.md",
        [
            "1343",
            "0x1c20",
            "0x3840",
            "0x708",
            "seed/item",
        ],
    )
    require(
        NATIVE / "crop_smalls.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 109',
            "foodToRemoveWhenSpawningNPC",
            "renderImageType",
        ],
    )
    for _cs_file, _cs_imp, _cs_end in (
        ("disasm_worldtileloader_cl_objecttype.txt", "implementation: 0x006b9ec0", "ARM.exidx end: 0x006b9ef8"),
        ("disasm_worldtileloader_cl_emitslight.txt", "implementation: 0x006b9edc", "ARM.exidx end: 0x006b9ef8"),
        ("disasm_worldtileloader_cl_lightfactor.txt", "implementation: 0x006b9ef8", "ARM.exidx end: 0x006b9fb4"),
        ("disasm_worldtileloader_cl_lightcolor.txt", "implementation: 0x006b9fb4", "ARM.exidx end: 0x006ba168"),
        ("disasm_worldtileloader_cl_maxagebase.txt", "implementation: 0x006ba168", "ARM.exidx end: 0x006ba198"),
        ("disasm_worldtileloader_cl_seeditem.txt", "implementation: 0x006ba198", "ARM.exidx end: 0x006ba1d0"),
        ("disasm_worldtileloader_cl_mintemp.txt", "implementation: 0x006ba1b4", "ARM.exidx end: 0x006ba1d0"),
        ("disasm_worldtileloader_cl_floweringseason.txt", "implementation: 0x006ba1d0", "ARM.exidx end: 0x006ba21c"),
        ("disasm_worldtileloader_cl_candie.txt", "implementation: 0x006ba21c", "ARM.exidx end: 0x006ba24c"),
        ("disasm_worldtileloader_cl_planttype.txt", "implementation: 0x006ba24c", "ARM.exidx end: 0x006ba268"),
        ("disasm_worldtileloader_cl_soiltype.txt", "implementation: 0x006ba268", "ARM.exidx end: 0x006ba2dc"),
        ("disasm_worldtileloader_cl_renderimage.txt", "implementation: 0x006ba2dc", "ARM.exidx end: 0x006ba338"),
        ("disasm_worldtileloader_wh_objecttype.txt", "implementation: 0x006d13d4", "ARM.exidx end: 0x006d13f0"),
        ("disasm_worldtileloader_wh_maxagebase.txt", "implementation: 0x006d13f0", "ARM.exidx end: 0x006d1420"),
        ("disasm_worldtileloader_wh_seeditem.txt", "implementation: 0x006d1420", "ARM.exidx end: 0x006d1458"),
        ("disasm_worldtileloader_wh_mintemp.txt", "implementation: 0x006d143c", "ARM.exidx end: 0x006d1458"),
        ("disasm_worldtileloader_wh_floweringseason.txt", "implementation: 0x006d1458", "ARM.exidx end: 0x006d14a4"),
        ("disasm_worldtileloader_wh_candie.txt", "implementation: 0x006d14a4", "ARM.exidx end: 0x006d14d4"),
        ("disasm_worldtileloader_wh_planttype.txt", "implementation: 0x006d14d4", "ARM.exidx end: 0x006d14f0"),
        ("disasm_worldtileloader_wh_soiltype.txt", "implementation: 0x006d14f0", "ARM.exidx end: 0x006d158c"),
        ("disasm_worldtileloader_wh_renderimage.txt", "implementation: 0x006d158c", "ARM.exidx end: 0x006d15e8"),
        ("disasm_worldtileloader_wh_npcspawn.txt", "implementation: 0x006d15e8", "ARM.exidx end: 0x006d1604"),
        ("disasm_worldtileloader_tm_objecttype.txt", "implementation: 0x006ffba0", "ARM.exidx end: 0x006ffbbc"),
        ("disasm_worldtileloader_tm_maxagebase.txt", "implementation: 0x006ffbbc", "ARM.exidx end: 0x006ffbec"),
        ("disasm_worldtileloader_tm_seeditem.txt", "implementation: 0x006ffbec", "ARM.exidx end: 0x006ffc24"),
        ("disasm_worldtileloader_tm_mintemp.txt", "implementation: 0x006ffc08", "ARM.exidx end: 0x006ffc24"),
        ("disasm_worldtileloader_tm_floweringseason.txt", "implementation: 0x006ffc24", "ARM.exidx end: 0x006ffc70"),
        ("disasm_worldtileloader_tm_candie.txt", "implementation: 0x006ffc70", "ARM.exidx end: 0x006ffca0"),
        ("disasm_worldtileloader_tm_planttype.txt", "implementation: 0x006ffca0", "ARM.exidx end: 0x006ffcbc"),
        ("disasm_worldtileloader_tm_soiltype.txt", "implementation: 0x006ffcbc", "ARM.exidx end: 0x006ffd30"),
        ("disasm_worldtileloader_tm_renderimage.txt", "implementation: 0x006ffd30", "ARM.exidx end: 0x006ffd8c"),
        ("disasm_worldtileloader_cr_objecttype.txt", "implementation: 0x007418e0", "ARM.exidx end: 0x007418fc"),
        ("disasm_worldtileloader_cr_maxagebase.txt", "implementation: 0x007418fc", "ARM.exidx end: 0x0074192c"),
        ("disasm_worldtileloader_cr_seeditem.txt", "implementation: 0x0074192c", "ARM.exidx end: 0x00741948"),
        ("disasm_worldtileloader_cr_foodremove.txt", "implementation: 0x00741948", "ARM.exidx end: 0x00741978"),
        ("disasm_worldtileloader_cr_mintemp.txt", "implementation: 0x00741978", "ARM.exidx end: 0x00741994"),
        ("disasm_worldtileloader_cr_floweringseason.txt", "implementation: 0x00741994", "ARM.exidx end: 0x007419e0"),
        ("disasm_worldtileloader_cr_candie.txt", "implementation: 0x007419e0", "ARM.exidx end: 0x00741a10"),
        ("disasm_worldtileloader_cr_planttype.txt", "implementation: 0x00741a10", "ARM.exidx end: 0x00741a2c"),
        ("disasm_worldtileloader_cr_soiltype.txt", "implementation: 0x00741a2c", "ARM.exidx end: 0x00741ac8"),
        ("disasm_worldtileloader_cr_renderimage.txt", "implementation: 0x00741ac8", "ARM.exidx end: 0x00741b24"),
        ("disasm_worldtileloader_cr_npcspawn.txt", "implementation: 0x00741b24", "ARM.exidx end: 0x00741b40"),
        ("disasm_worldtileloader_fx_objecttype.txt", "implementation: 0x00770ca8", "ARM.exidx end: 0x00770cc4"),
        ("disasm_worldtileloader_fx_maxagebase.txt", "implementation: 0x00770cc4", "ARM.exidx end: 0x00770cf4"),
        ("disasm_worldtileloader_fx_seeditem.txt", "implementation: 0x00770cf4", "ARM.exidx end: 0x00770d48"),
        ("disasm_worldtileloader_fx_folliageitem.txt", "implementation: 0x00770d10", "ARM.exidx end: 0x00770d48"),
        ("disasm_worldtileloader_fx_mintemp.txt", "implementation: 0x00770d2c", "ARM.exidx end: 0x00770d48"),
        ("disasm_worldtileloader_fx_floweringseason.txt", "implementation: 0x00770d48", "ARM.exidx end: 0x00770d94"),
        ("disasm_worldtileloader_fx_candie.txt", "implementation: 0x00770d94", "ARM.exidx end: 0x00770db4"),
        ("disasm_worldtileloader_fx_planttype.txt", "implementation: 0x00770db4", "ARM.exidx end: 0x00770dd0"),
        ("disasm_worldtileloader_fx_soiltype.txt", "implementation: 0x00770dd0", "ARM.exidx end: 0x00770ea8"),
        ("disasm_worldtileloader_fx_renderimage.txt", "implementation: 0x00770ea8", "ARM.exidx end: 0x00770f04"),
        ("disasm_worldtileloader_sf_objecttype.txt", "implementation: 0x009bc33c", "ARM.exidx end: 0x009bc394"),
        ("disasm_worldtileloader_sf_emitslight.txt", "implementation: 0x009bc358", "ARM.exidx end: 0x009bc394"),
        ("disasm_worldtileloader_sf_lightfactor.txt", "implementation: 0x009bc394", "ARM.exidx end: 0x009bc450"),
        ("disasm_worldtileloader_sf_lightcolor.txt", "implementation: 0x009bc450", "ARM.exidx end: 0x009bc5a4"),
        ("disasm_worldtileloader_sf_maxagebase.txt", "implementation: 0x009bc5a4", "ARM.exidx end: 0x009bc5d4"),
        ("disasm_worldtileloader_sf_seeditem.txt", "implementation: 0x009bc5d4", "ARM.exidx end: 0x009bc60c"),
        ("disasm_worldtileloader_sf_mintemp.txt", "implementation: 0x009bc5f0", "ARM.exidx end: 0x009bc60c"),
        ("disasm_worldtileloader_sf_floweringseason.txt", "implementation: 0x009bc60c", "ARM.exidx end: 0x009bc658"),
        ("disasm_worldtileloader_sf_candie.txt", "implementation: 0x009bc658", "ARM.exidx end: 0x009bc688"),
        ("disasm_worldtileloader_sf_planttype.txt", "implementation: 0x009bc688", "ARM.exidx end: 0x009bc6a4"),
        ("disasm_worldtileloader_sf_soiltype.txt", "implementation: 0x009bc6a4", "ARM.exidx end: 0x009bc740"),
        ("disasm_worldtileloader_sf_renderimage.txt", "implementation: 0x009bc740", "ARM.exidx end: 0x009bc79c"),
        ("disasm_worldtileloader_co_objecttype.txt", "implementation: 0x00b501e0", "ARM.exidx end: 0x00b501fc"),
        ("disasm_worldtileloader_co_maxagebase.txt", "implementation: 0x00b501fc", "ARM.exidx end: 0x00b5022c"),
        ("disasm_worldtileloader_co_seeditem.txt", "implementation: 0x00b5022c", "ARM.exidx end: 0x00b50264"),
        ("disasm_worldtileloader_co_mintemp.txt", "implementation: 0x00b50248", "ARM.exidx end: 0x00b50264"),
        ("disasm_worldtileloader_co_floweringseason.txt", "implementation: 0x00b50264", "ARM.exidx end: 0x00b502b0"),
        ("disasm_worldtileloader_co_candie.txt", "implementation: 0x00b502b0", "ARM.exidx end: 0x00b502e0"),
        ("disasm_worldtileloader_co_planttype.txt", "implementation: 0x00b502e0", "ARM.exidx end: 0x00b502fc"),
        ("disasm_worldtileloader_co_soiltype.txt", "implementation: 0x00b502fc", "ARM.exidx end: 0x00b50398"),
        ("disasm_worldtileloader_co_renderimage.txt", "implementation: 0x00b50398", "ARM.exidx end: 0x00b503f4"),
    ):
        require(NATIVE / _cs_file, [_cs_imp, _cs_end])
    require(
        NATIVE / "NORMAL_PLANT.md",
        [
            "5090",
            "growthVigorForPlantTypeAtPos",
            "reloadDrawBlockDynamicObjectQuad",
            "emitsLight",
            "0x384",
        ],
    )
    require(
        NATIVE / "normal_plant.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1736',
            "tileHarvested:removeBlockhead:correctToolMultiplier:",
            "addLightGlowQuadData:fromIndex:",
        ],
    )
    for _np_file, _np_imp, _np_end in (
        ("disasm_worldtileloader_np_objecttype.txt", "implementation: 0x00a6532c", "ARM.exidx end: 0x00a65348"),
        ("disasm_worldtileloader_np_maxagebase.txt", "implementation: 0x00a65348", "ARM.exidx end: 0x00a65378"),
        ("disasm_worldtileloader_np_contentstype.txt", "implementation: 0x00a65378", "ARM.exidx end: 0x00a653d8"),
        ("disasm_worldtileloader_np_flowercontents.txt", "implementation: 0x00a654f4", "ARM.exidx end: 0x00a65554"),
        ("disasm_worldtileloader_np_mintemp.txt", "implementation: 0x00a65554", "ARM.exidx end: 0x00a655c4"),
        ("disasm_worldtileloader_np_seeditem.txt", "implementation: 0x00a65570", "ARM.exidx end: 0x00a655c4"),
        ("disasm_worldtileloader_np_folliageitem.txt", "implementation: 0x00a6558c", "ARM.exidx end: 0x00a655c4"),
        ("disasm_worldtileloader_np_renderimage.txt", "implementation: 0x00a655a8", "ARM.exidx end: 0x00a655c4"),
        ("disasm_worldtileloader_np_foodremove.txt", "implementation: 0x00a655c4", "ARM.exidx end: 0x00a655f4"),
        ("disasm_worldtileloader_np_floweringseason.txt", "implementation: 0x00a655f4", "ARM.exidx end: 0x00a65634"),
        ("disasm_worldtileloader_np_candie.txt", "implementation: 0x00a65614", "ARM.exidx end: 0x00a65634"),
        ("disasm_worldtileloader_np_npcspawn.txt", "implementation: 0x00a65634", "ARM.exidx end: 0x00a6566c"),
        ("disasm_worldtileloader_np_emitslight.txt", "implementation: 0x00a65650", "ARM.exidx end: 0x00a6566c"),
        ("disasm_worldtileloader_np_lightfactor.txt", "implementation: 0x00a6566c", "ARM.exidx end: 0x00a65698"),
        ("disasm_worldtileloader_np_lightcolor.txt", "implementation: 0x00a65698", "ARM.exidx end: 0x00a659a0"),
        ("disasm_worldtileloader_np_initsubderived.txt", "implementation: 0x00a656e4", "ARM.exidx end: 0x00a659a0"),
        ("disasm_worldtileloader_np_ctor.txt", "implementation: 0x00a659a0", "ARM.exidx end: 0x00a66604"),
        ("disasm_worldtileloader_np_ctorsave.txt", "implementation: 0x00a66614", "ARM.exidx end: 0x00a66a78"),
        ("disasm_worldtileloader_np_ctornet.txt", "implementation: 0x00a66a78", "ARM.exidx end: 0x00a66b94"),
        ("disasm_worldtileloader_np_dealloc.txt", "implementation: 0x00a66b94", "ARM.exidx end: 0x00a66c7c"),
        ("disasm_worldtileloader_np_setneedsremoved.txt", "implementation: 0x00a66c7c", "ARM.exidx end: 0x00a66e14"),
        ("disasm_worldtileloader_np_setflowering.txt", "implementation: 0x00a67034", "ARM.exidx end: 0x00a672d0"),
        ("disasm_worldtileloader_np_remoteupdate.txt", "implementation: 0x00a672d0", "ARM.exidx end: 0x00a67414"),
        ("disasm_worldtileloader_np_glowquadcount.txt", "implementation: 0x00a67414", "ARM.exidx end: 0x00a674cc"),
        ("disasm_worldtileloader_np_addglowquad.txt", "implementation: 0x00a674cc", "ARM.exidx end: 0x00a675a0"),
        ("disasm_worldtileloader_np_update.txt", "implementation: 0x00a675a0", "ARM.exidx end: 0x00a690c0"),
        ("disasm_worldtileloader_np_kindself.txt", "implementation: 0x00a690c0", "ARM.exidx end: 0x00a691a0"),
        ("disasm_worldtileloader_np_harvested.txt", "implementation: 0x00a691a0", "ARM.exidx end: 0x00a69888"),
        ("disasm_worldtileloader_np_tilesabove.txt", "implementation: 0x00a69888", "ARM.exidx end: 0x00a698e0"),
        ("disasm_worldtileloader_np_droppeditem.txt", "implementation: 0x00a698e0", "ARM.exidx end: 0x00a699d8"),
        ("disasm_worldtileloader_np_staticquadcount.txt", "implementation: 0x00a699d8", "ARM.exidx end: 0x00a69a00"),
        ("disasm_worldtileloader_np_adddrawquad.txt", "implementation: 0x00a69a00", "ARM.exidx end: 0x00a69eec"),
        ("disasm_worldtileloader_np_rmmacro.txt", "implementation: 0x00a69f60", "ARM.exidx end: 0x00a6a180"),
        ("disasm_worldtileloader_np_addartistlight.txt", "implementation: 0x00a6a180", "ARM.exidx end: 0x00a6a1f4"),
        ("disasm_worldtileloader_np_availfood.txt", "implementation: 0x00a6a1f4", "ARM.exidx end: 0x00a6a288"),
        ("disasm_worldtileloader_np_setavailfood.txt", "implementation: 0x00a6a23c", "ARM.exidx end: 0x00a6a288"),
    ):
        require(NATIVE / _np_file, [_np_imp, _np_end])
    require(
        NATIVE / "TREE_BASE.md",
        [
            "4378",
            "baseGrowthRateForTreeType",
            "__wrap_calloc",
            "tileIsTreeTrunk",
            "0x4c0bc4",
        ],
    )
    require(
        NATIVE / "tree_base.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 334',
            "checkIfDeadTilesNeedRemoved",
            "updateAllOwnedTilesToNewIDSize",
        ],
    )
    for _tb_file, _tb_imp, _tb_end in (
        ("disasm_worldtileloader_tr_rmmacro.txt", "implementation: 0x004c0320", "ARM.exidx end: 0x004c03d4"),
        ("disasm_worldtileloader_tr_initstatic.txt", "implementation: 0x004c03d4", "ARM.exidx end: 0x004c0638"),
        ("disasm_worldtileloader_tr_ctor.txt", "implementation: 0x004c0638", "ARM.exidx end: 0x004c0b70"),
        ("disasm_worldtileloader_tr_compost.txt", "implementation: 0x004c1f84", "ARM.exidx end: 0x004c205c"),
        ("disasm_worldtileloader_tr_fruititem.txt", "implementation: 0x004c205c", "ARM.exidx end: 0x004c2094"),
        ("disasm_worldtileloader_tr_shouldfall.txt", "implementation: 0x004c2078", "ARM.exidx end: 0x004c2094"),
        ("disasm_worldtileloader_tr_fruitseason.txt", "implementation: 0x004c2094", "ARM.exidx end: 0x004c20b4"),
        ("disasm_worldtileloader_tr_fallenfruits.txt", "implementation: 0x004c20b4", "ARM.exidx end: 0x004c2568"),
        ("disasm_worldtileloader_tr_ctorsave.txt", "implementation: 0x004c39a0", "ARM.exidx end: 0x004c3be8"),
        ("disasm_worldtileloader_tr_dealloc.txt", "implementation: 0x004c3be8", "ARM.exidx end: 0x004c3cac"),
        ("disasm_worldtileloader_tr_worldchanged.txt", "implementation: 0x004c4974", "ARM.exidx end: 0x004c5730"),
        ("disasm_worldtileloader_tr_incheight.txt", "implementation: 0x004c576c", "ARM.exidx end: 0x004c57b0"),
        ("disasm_worldtileloader_tr_update.txt", "implementation: 0x004c57b0", "ARM.exidx end: 0x004c6898"),
        ("disasm_worldtileloader_tr_growth.txt", "implementation: 0x004c6898", "ARM.exidx end: 0x004c68e8"),
        ("disasm_worldtileloader_tr_kindself.txt", "implementation: 0x004c68b0", "ARM.exidx end: 0x004c68e8"),
        ("disasm_worldtileloader_tr_makedead.txt", "implementation: 0x004c68d0", "ARM.exidx end: 0x004c68e8"),
        ("disasm_worldtileloader_tr_killtiles.txt", "implementation: 0x004c68e8", "ARM.exidx end: 0x004c6b50"),
        ("disasm_worldtileloader_tr_checkdead.txt", "implementation: 0x004c6b50", "ARM.exidx end: 0x004c7008"),
        ("disasm_worldtileloader_tr_killabove.txt", "implementation: 0x004c7008", "ARM.exidx end: 0x004c7354"),
        ("disasm_worldtileloader_tr_removeall.txt", "implementation: 0x004c7354", "ARM.exidx end: 0x004c76d8"),
        ("disasm_worldtileloader_tr_updateidsize.txt", "implementation: 0x004c76d8", "ARM.exidx end: 0x004c78dc"),
        ("disasm_worldtileloader_tr_soiltype.txt", "implementation: 0x004c78dc", "ARM.exidx end: 0x004c7978"),
        ("disasm_worldtileloader_tr_treetype.txt", "implementation: 0x004c7978", "ARM.exidx end: 0x004c7994"),
        ("disasm_worldtileloader_tr_maxheightgene.txt", "implementation: 0x004c7994", "ARM.exidx end: 0x004c7af4"),
        ("disasm_worldtileloader_tr_growthgene.txt", "implementation: 0x004c7a44", "ARM.exidx end: 0x004c7af4"),
        ("disasm_worldtileloader_tr_height.txt", "implementation: 0x004c7af4", "ARM.exidx end: 0x004c7b68"),
        ("disasm_worldtileloader_tr_isstatic.txt", "implementation: 0x004c7b30", "ARM.exidx end: 0x004c7b68"),
        ("disasm_worldtileloader_tr_occupiesnormal.txt", "implementation: 0x004c7b4c", "ARM.exidx end: 0x004c7b68"),
    ):
        require(NATIVE / _tb_file, [_tb_imp, _tb_end])
    require(
        NATIVE / "PLANT_BASE.md",
        [
            "2168",
            "tileIsPlant",
            "lrand48",
            "ffffcad4",
            "tileIsAirWaterOrSnow",
        ],
    )
    require(
        NATIVE / "plant_base.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 372',
            "removePlantWithoutCreatingFreeblocks",
            "maxAgeGeneVariation",
        ],
    )
    for _pb_file, _pb_imp, _pb_end in (
        ("disasm_worldtileloader_p_rmmacro.txt", "implementation: 0x00954f40", "ARM.exidx end: 0x00954fec"),
        ("disasm_worldtileloader_p_ctor.txt", "implementation: 0x00954fec", "ARM.exidx end: 0x009554a0"),
        ("disasm_worldtileloader_p_ctornet.txt", "implementation: 0x00955b98", "ARM.exidx end: 0x00955d10"),
        ("disasm_worldtileloader_p_dealloc.txt", "implementation: 0x00955d10", "ARM.exidx end: 0x00955d7c"),
        ("disasm_worldtileloader_p_updatenet.txt", "implementation: 0x0095649c", "ARM.exidx end: 0x009564f0"),
        ("disasm_worldtileloader_p_creationdata.txt", "implementation: 0x009564f0", "ARM.exidx end: 0x00956608"),
        ("disasm_worldtileloader_p_creationdata2.txt", "implementation: 0x00956608", "ARM.exidx end: 0x009566e8"),
        ("disasm_worldtileloader_p_remoteupdate.txt", "implementation: 0x009566e8", "ARM.exidx end: 0x00956808"),
        ("disasm_worldtileloader_p_setflowering.txt", "implementation: 0x00956808", "ARM.exidx end: 0x0095684c"),
        ("disasm_worldtileloader_p_worldchanged.txt", "implementation: 0x0095684c", "ARM.exidx end: 0x00956e1c"),
        ("disasm_worldtileloader_p_compost.txt", "implementation: 0x00956e1c", "ARM.exidx end: 0x00956ef8"),
        ("disasm_worldtileloader_p_update.txt", "implementation: 0x00956ef8", "ARM.exidx end: 0x00957304"),
        ("disasm_worldtileloader_p_soiltype.txt", "implementation: 0x00957304", "ARM.exidx end: 0x009573a0"),
        ("disasm_worldtileloader_p_planttype.txt", "implementation: 0x009573a0", "ARM.exidx end: 0x009573bc"),
        ("disasm_worldtileloader_p_gatherprogress.txt", "implementation: 0x009573bc", "ARM.exidx end: 0x00957404"),
        ("disasm_worldtileloader_p_harvested.txt", "implementation: 0x00957404", "ARM.exidx end: 0x00957474"),
        ("disasm_worldtileloader_p_setgather.txt", "implementation: 0x00957474", "ARM.exidx end: 0x009574c8"),
        ("disasm_worldtileloader_p_removeplant.txt", "implementation: 0x009574c8", "ARM.exidx end: 0x0095773c"),
        ("disasm_worldtileloader_p_maxagegene.txt", "implementation: 0x009575cc", "ARM.exidx end: 0x0095773c"),
        ("disasm_worldtileloader_p_growthgene.txt", "implementation: 0x0095768c", "ARM.exidx end: 0x0095773c"),
        ("disasm_worldtileloader_p_isflowering.txt", "implementation: 0x0095773c", "ARM.exidx end: 0x00957794"),
        ("disasm_worldtileloader_p_droppeditem.txt", "implementation: 0x00957778", "ARM.exidx end: 0x00957794"),
        ("disasm_worldtileloader_p_kindself.txt", "implementation: 0x00957794", "ARM.exidx end: 0x009577b4"),
        ("disasm_worldtileloader_p_cleartiles.txt", "implementation: 0x009577b4", "ARM.exidx end: 0x00957af4"),
        ("disasm_worldtileloader_p_setneedsremoved.txt", "implementation: 0x00957af4", "ARM.exidx end: 0x00957be4"),
        ("disasm_worldtileloader_p_canbreed.txt", "implementation: 0x00957be4", "ARM.exidx end: 0x00957c54"),
        ("disasm_worldtileloader_p_occupiesfg.txt", "implementation: 0x00957c00", "ARM.exidx end: 0x00957c54"),
        ("disasm_worldtileloader_p_tilesabove.txt", "implementation: 0x00957c1c", "ARM.exidx end: 0x00957c54"),
        ("disasm_worldtileloader_p_tilesbelow.txt", "implementation: 0x00957c38", "ARM.exidx end: 0x00957c54"),
    ):
        require(NATIVE / _pb_file, [_pb_imp, _pb_end])
    require(
        NATIVE / "TREE_GROWTH.md",
        [
            "22630",
            "reloadDrawBlockGeometryForTile",
            "seasonForWorldX",
            "tileIsBush",
            "0x9be67c",
        ],
    )
    require(
        NATIVE / "tree_growth.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 2017',
            "update:accurateDT:isSimulation:",
            "updateGrowth:",
        ],
    )
    for _tg_file, _tg_imp, _tg_end in (
        ("disasm_worldtileloader_cf_growth.txt", "implementation: 0x007deca0", "ARM.exidx end: 0x007e0c24"),
        ("disasm_worldtileloader_cf_update.txt", "implementation: 0x007e0c8c", "ARM.exidx end: 0x007e1368"),
        ("disasm_worldtileloader_lt_growth.txt", "implementation: 0x00809db0", "ARM.exidx end: 0x0080bc80"),
        ("disasm_worldtileloader_lt_update.txt", "implementation: 0x0080bc80", "ARM.exidx end: 0x0080c3a8"),
        ("disasm_worldtileloader_at_growth.txt", "implementation: 0x009bd680", "ARM.exidx end: 0x009bf588"),
        ("disasm_worldtileloader_at_update.txt", "implementation: 0x009bf5f0", "ARM.exidx end: 0x009bff14"),
        ("disasm_worldtileloader_ot_growth.txt", "implementation: 0x00a96778", "ARM.exidx end: 0x00a98648"),
        ("disasm_worldtileloader_ot_update.txt", "implementation: 0x00a98648", "ARM.exidx end: 0x00a98d70"),
        ("disasm_worldtileloader_cn_growth.txt", "implementation: 0x00a99b30", "ARM.exidx end: 0x00a9aa30"),
        ("disasm_worldtileloader_cn_update.txt", "implementation: 0x00a9aa30", "ARM.exidx end: 0x00a9b268"),
        ("disasm_worldtileloader_ct_growth.txt", "implementation: 0x00b53a50", "ARM.exidx end: 0x00b54c60"),
        ("disasm_worldtileloader_ct_update.txt", "implementation: 0x00b54c60", "ARM.exidx end: 0x00b5561c"),
        ("disasm_worldtileloader_pt_growth.txt", "implementation: 0x00b652f8", "ARM.exidx end: 0x00b66f40"),
        ("disasm_worldtileloader_pt_update.txt", "implementation: 0x00b66fa8", "ARM.exidx end: 0x00b67a18"),
        ("disasm_worldtileloader_ch_growth.txt", "implementation: 0x00d0e0a0", "ARM.exidx end: 0x00d0fd4c"),
        ("disasm_worldtileloader_ch_update.txt", "implementation: 0x00d0fdb4", "ARM.exidx end: 0x00d1048c"),
        ("disasm_worldtileloader_mg_growth.txt", "implementation: 0x00d4b668", "ARM.exidx end: 0x00d4d314"),
        ("disasm_worldtileloader_mg_update.txt", "implementation: 0x00d4d314", "ARM.exidx end: 0x00d4da38"),
        ("disasm_worldtileloader_mp_growth.txt", "implementation: 0x00db6128", "ARM.exidx end: 0x00db8010"),
        ("disasm_worldtileloader_mp_update.txt", "implementation: 0x00db8078", "ARM.exidx end: 0x00db879c"),
    ):
        require(NATIVE / _tg_file, [_tg_imp, _tg_end])
    require(
        NATIVE / "TREE_CTORS.md",
        [
            "6331",
            "growthVigorForTreeTypeAtPos",
            "0x1869f",
            "0x3fffffff",
            "0x30/31/32",
        ],
    )
    require(
        NATIVE / "tree_ctors.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 730',
            "seasonOffsetNoiseFunction:adultTree:adultMaxAge:",
            "treeDensityNoiseFunction:",
        ],
    )
    for _tc_file, _tc_imp, _tc_end in (
        ("disasm_worldtileloader_cf_ctor.txt", "implementation: 0x007de1c0", "ARM.exidx end: 0x007deb18"),
        ("disasm_worldtileloader_lt_ctor.txt", "implementation: 0x00809278", "ARM.exidx end: 0x00809c2c"),
        ("disasm_worldtileloader_at_ctor.txt", "implementation: 0x009bca70", "ARM.exidx end: 0x009bd3a0"),
        ("disasm_worldtileloader_ot_ctor.txt", "implementation: 0x00a95c40", "ARM.exidx end: 0x00a965f4"),
        ("disasm_worldtileloader_cn_ctor.txt", "implementation: 0x00a990a0", "ARM.exidx end: 0x00a99938"),
        ("disasm_worldtileloader_ct_ctor.txt", "implementation: 0x00b52850", "ARM.exidx end: 0x00b533ac"),
        ("disasm_worldtileloader_pt_ctor.txt", "implementation: 0x00b643d0", "ARM.exidx end: 0x00b64f38"),
        ("disasm_worldtileloader_pt_ctorsave.txt", "implementation: 0x00b64f48", "ARM.exidx end: 0x00b651bc"),
        ("disasm_worldtileloader_ch_ctor.txt", "implementation: 0x00d0d670", "ARM.exidx end: 0x00d0df1c"),
        ("disasm_worldtileloader_mg_ctor.txt", "implementation: 0x00d4ab38", "ARM.exidx end: 0x00d4b4e4"),
        ("disasm_worldtileloader_mp_ctor.txt", "implementation: 0x00db56d0", "ARM.exidx end: 0x00db5fa4"),
    ):
        require(NATIVE / _tc_file, [_tc_imp, _tc_end])
    require(
        NATIVE / "TREE_SMALLS.md",
        [
            "1463",
            "0x1b/0x1c",
            "dmb ish",
            "0x3a",
            "treeType",
        ],
    )
    require(
        NATIVE / "tree_smalls.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 39',
            "fruitShouldFallInSeason:",
            "tileIsKindOfSelf:",
        ],
    )
    for _ts_file, _ts_imp, _ts_end in (
        ("disasm_worldtileloader_cf_objecttype.txt", "implementation: 0x007de158", "ARM.exidx end: 0x007de190"),
        ("disasm_worldtileloader_cf_fruititem.txt", "implementation: 0x007de174", "ARM.exidx end: 0x007de190"),
        ("disasm_worldtileloader_cf_fruitseason.txt", "implementation: 0x007de190", "ARM.exidx end: 0x007de1c0"),
        ("disasm_worldtileloader_cf_getsavedict.txt", "implementation: 0x007dec20", "ARM.exidx end: 0x007deca0"),
        ("disasm_worldtileloader_cf_makedead.txt", "implementation: 0x007e0c24", "ARM.exidx end: 0x007e0c8c"),
        ("disasm_worldtileloader_cf_treetype.txt", "implementation: 0x007e1368", "ARM.exidx end: 0x007e1384"),
        ("disasm_worldtileloader_cf_kindself.txt", "implementation: 0x007e1384", "ARM.exidx end: 0x007e1420"),
        ("disasm_worldtileloader_lt_objecttype.txt", "implementation: 0x00809210", "ARM.exidx end: 0x00809248"),
        ("disasm_worldtileloader_lt_fruititem.txt", "implementation: 0x0080922c", "ARM.exidx end: 0x00809248"),
        ("disasm_worldtileloader_lt_fruitseason.txt", "implementation: 0x00809248", "ARM.exidx end: 0x00809278"),
        ("disasm_worldtileloader_lt_getsavedict.txt", "implementation: 0x00809d34", "ARM.exidx end: 0x00809db0"),
        ("disasm_worldtileloader_lt_makedead.txt", "implementation: 0x0080c3a8", "ARM.exidx end: 0x0080c410"),
        ("disasm_worldtileloader_lt_treetype.txt", "implementation: 0x0080c410", "ARM.exidx end: 0x0080c42c"),
        ("disasm_worldtileloader_lt_kindself.txt", "implementation: 0x0080c42c", "ARM.exidx end: 0x0080c4c8"),
        ("disasm_worldtileloader_at_availfood.txt", "implementation: 0x009bc8fc", "ARM.exidx end: 0x009bc93c"),
        ("disasm_worldtileloader_at_setavailfood.txt", "implementation: 0x009bc93c", "ARM.exidx end: 0x009bca08"),
        ("disasm_worldtileloader_at_fruititem.txt", "implementation: 0x009bca08", "ARM.exidx end: 0x009bca24"),
        ("disasm_worldtileloader_at_fruitseason.txt", "implementation: 0x009bca24", "ARM.exidx end: 0x009bca54"),
        ("disasm_worldtileloader_at_objecttype.txt", "implementation: 0x009bca54", "ARM.exidx end: 0x009bca70"),
        ("disasm_worldtileloader_at_makedead.txt", "implementation: 0x009bf588", "ARM.exidx end: 0x009bf5f0"),
        ("disasm_worldtileloader_at_treetype.txt", "implementation: 0x009bff14", "ARM.exidx end: 0x009bff30"),
        ("disasm_worldtileloader_at_kindself.txt", "implementation: 0x009bff30", "ARM.exidx end: 0x009bffcc"),
        ("disasm_worldtileloader_ot_objecttype.txt", "implementation: 0x00a95bd8", "ARM.exidx end: 0x00a95c10"),
        ("disasm_worldtileloader_ot_fruititem.txt", "implementation: 0x00a95bf4", "ARM.exidx end: 0x00a95c10"),
        ("disasm_worldtileloader_ot_fruitseason.txt", "implementation: 0x00a95c10", "ARM.exidx end: 0x00a95c40"),
        ("disasm_worldtileloader_ot_getsavedict.txt", "implementation: 0x00a966fc", "ARM.exidx end: 0x00a96778"),
        ("disasm_worldtileloader_ot_makedead.txt", "implementation: 0x00a98d70", "ARM.exidx end: 0x00a98dd8"),
        ("disasm_worldtileloader_ot_treetype.txt", "implementation: 0x00a98dd8", "ARM.exidx end: 0x00a98df4"),
        ("disasm_worldtileloader_ot_kindself.txt", "implementation: 0x00a98df4", "ARM.exidx end: 0x00a98e90"),
        ("disasm_worldtileloader_cn_objecttype.txt", "implementation: 0x00a98ff0", "ARM.exidx end: 0x00a99028"),
        ("disasm_worldtileloader_cn_fruititem.txt", "implementation: 0x00a9900c", "ARM.exidx end: 0x00a99028"),
        ("disasm_worldtileloader_cn_fruitseason.txt", "implementation: 0x00a99028", "ARM.exidx end: 0x00a990a0"),
        ("disasm_worldtileloader_cn_getsavedict.txt", "implementation: 0x00a99ab4", "ARM.exidx end: 0x00a99b30"),
        ("disasm_worldtileloader_cn_makedead.txt", "implementation: 0x00a9b268", "ARM.exidx end: 0x00a9b2d0"),
        ("disasm_worldtileloader_cn_kindself.txt", "implementation: 0x00a9b2d0", "ARM.exidx end: 0x00a9b36c"),
        ("disasm_worldtileloader_cn_treetype.txt", "implementation: 0x00a9b36c", "ARM.exidx end: 0x00a9b388"),
        ("disasm_worldtileloader_cn_soiltype.txt", "implementation: 0x00a9b388", "ARM.exidx end: 0x00a9b424"),
        ("disasm_worldtileloader_ct_objecttype.txt", "implementation: 0x00b527e4", "ARM.exidx end: 0x00b5281c"),
        ("disasm_worldtileloader_ct_fruititem.txt", "implementation: 0x00b52800", "ARM.exidx end: 0x00b5281c"),
        ("disasm_worldtileloader_ct_fruitseason.txt", "implementation: 0x00b5281c", "ARM.exidx end: 0x00b52850"),
        ("disasm_worldtileloader_ct_makedead.txt", "implementation: 0x00b5561c", "ARM.exidx end: 0x00b55650"),
        ("disasm_worldtileloader_ct_kindself.txt", "implementation: 0x00b55650", "ARM.exidx end: 0x00b556a4"),
        ("disasm_worldtileloader_ct_treetype.txt", "implementation: 0x00b556a4", "ARM.exidx end: 0x00b556c0"),
        ("disasm_worldtileloader_ct_soiltype.txt", "implementation: 0x00b556c0", "ARM.exidx end: 0x00b5575c"),
        ("disasm_worldtileloader_ct_availfood.txt", "implementation: 0x00b5575c", "ARM.exidx end: 0x00b557f0"),
        ("disasm_worldtileloader_ct_setavailfood.txt", "implementation: 0x00b557a4", "ARM.exidx end: 0x00b557f0"),
        ("disasm_worldtileloader_pt_objecttype.txt", "implementation: 0x00b64378", "ARM.exidx end: 0x00b643d0"),
        ("disasm_worldtileloader_pt_fruititem.txt", "implementation: 0x00b64394", "ARM.exidx end: 0x00b643d0"),
        ("disasm_worldtileloader_pt_fallen.txt", "implementation: 0x00b643b0", "ARM.exidx end: 0x00b643d0"),
        ("disasm_worldtileloader_pt_makedead.txt", "implementation: 0x00b66f40", "ARM.exidx end: 0x00b66fa8"),
        ("disasm_worldtileloader_pt_treetype.txt", "implementation: 0x00b67a18", "ARM.exidx end: 0x00b67a34"),
        ("disasm_worldtileloader_pt_kindself.txt", "implementation: 0x00b67a34", "ARM.exidx end: 0x00b67ad0"),
        ("disasm_worldtileloader_ch_objecttype.txt", "implementation: 0x00d0d604", "ARM.exidx end: 0x00d0d63c"),
        ("disasm_worldtileloader_ch_fruititem.txt", "implementation: 0x00d0d620", "ARM.exidx end: 0x00d0d63c"),
        ("disasm_worldtileloader_ch_fruitseason.txt", "implementation: 0x00d0d63c", "ARM.exidx end: 0x00d0d670"),
        ("disasm_worldtileloader_ch_getsavedict.txt", "implementation: 0x00d0e024", "ARM.exidx end: 0x00d0e0a0"),
        ("disasm_worldtileloader_ch_makedead.txt", "implementation: 0x00d0fd4c", "ARM.exidx end: 0x00d0fdb4"),
        ("disasm_worldtileloader_ch_treetype.txt", "implementation: 0x00d1048c", "ARM.exidx end: 0x00d104a8"),
        ("disasm_worldtileloader_ch_kindself.txt", "implementation: 0x00d104a8", "ARM.exidx end: 0x00d10544"),
        ("disasm_worldtileloader_mg_objecttype.txt", "implementation: 0x00d4aad0", "ARM.exidx end: 0x00d4ab08"),
        ("disasm_worldtileloader_mg_fruititem.txt", "implementation: 0x00d4aaec", "ARM.exidx end: 0x00d4ab08"),
        ("disasm_worldtileloader_mg_fruitseason.txt", "implementation: 0x00d4ab08", "ARM.exidx end: 0x00d4ab38"),
        ("disasm_worldtileloader_mg_getsavedict.txt", "implementation: 0x00d4b5ec", "ARM.exidx end: 0x00d4b668"),
        ("disasm_worldtileloader_mg_makedead.txt", "implementation: 0x00d4da38", "ARM.exidx end: 0x00d4daa0"),
        ("disasm_worldtileloader_mg_treetype.txt", "implementation: 0x00d4daa0", "ARM.exidx end: 0x00d4dabc"),
        ("disasm_worldtileloader_mg_kindself.txt", "implementation: 0x00d4dabc", "ARM.exidx end: 0x00d4db58"),
        ("disasm_worldtileloader_mp_objecttype.txt", "implementation: 0x00db5668", "ARM.exidx end: 0x00db56a0"),
        ("disasm_worldtileloader_mp_fruititem.txt", "implementation: 0x00db5684", "ARM.exidx end: 0x00db56a0"),
        ("disasm_worldtileloader_mp_fruitseason.txt", "implementation: 0x00db56a0", "ARM.exidx end: 0x00db56d0"),
        ("disasm_worldtileloader_mp_getsavedict.txt", "implementation: 0x00db60ac", "ARM.exidx end: 0x00db6128"),
        ("disasm_worldtileloader_mp_makedead.txt", "implementation: 0x00db8010", "ARM.exidx end: 0x00db8078"),
        ("disasm_worldtileloader_mp_treetype.txt", "implementation: 0x00db879c", "ARM.exidx end: 0x00db87b8"),
        ("disasm_worldtileloader_mp_kindself.txt", "implementation: 0x00db87b8", "ARM.exidx end: 0x00db8854"),
    ):
        require(NATIVE / _ts_file, [_ts_imp, _ts_end])
    require(
        NATIVE / "WORKBENCH_FINAL.md",
        [
            "10326",
            "texCoordsForImageIndex",
            "reloadDrawBlockLightGlowQuadsForTile",
            "ceil(remaining / 10)",
            "96/96",
        ],
    )
    require(
        NATIVE / "workbench_final.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 4847',
            "addDrawCubeData:fromIndex:",
            "staticGeometryDrawCubeCount",
        ],
    )
    for _wz_file, _wz_imp, _wz_end in (
        ("disasm_worldtileloader_wz_adddrawquad.txt", "implementation: 0x00b02608", "ARM.exidx end: 0x00b05ec4"),
        ("disasm_worldtileloader_wz_adddrawcube.txt", "implementation: 0x00b05f90", "ARM.exidx end: 0x00b0ab4c"),
        ("disasm_worldtileloader_wz_ctor_placed.txt", "implementation: 0x00ae42c0", "ARM.exidx end: 0x00ae4ed8"),
        ("disasm_worldtileloader_wz_initsubderived.txt", "implementation: 0x00ae3634", "ARM.exidx end: 0x00ae3c5c"),
        ("disasm_worldtileloader_wz_craftableitems.txt", "implementation: 0x00afb128", "ARM.exidx end: 0x00afb164"),
        ("disasm_worldtileloader_wz_hurrycost.txt", "implementation: 0x00b0bc24", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wz_rmmacro.txt", "implementation: 0x00b0aec0", "ARM.exidx end: 0x00b0b25c"),
        ("disasm_worldtileloader_wz_lightpos.txt", "implementation: 0x00b0b51c", "ARM.exidx end: 0x00b0b648"),
        ("disasm_worldtileloader_wz_addartistlight.txt", "implementation: 0x00b0b664", "ARM.exidx end: 0x00b0b6d8"),
        ("disasm_worldtileloader_wz_staticquadcount.txt", "implementation: 0x00b0222c", "ARM.exidx end: 0x00b02608"),
        ("disasm_worldtileloader_wz_staticcubecount.txt", "implementation: 0x00b05ec4", "ARM.exidx end: 0x00b05f90"),
    ):
        require(NATIVE / _wz_file, [_wz_imp, _wz_end])
    require(
        NATIVE / "WORKBENCH_TAIL.md",
        [
            "2324",
            "0x18 (24)",
            "fffff17c",
            "dmb ish",
            "0xb0b958",
        ],
    )
    require(
        NATIVE / "workbench_tail.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 371',
            "numberOfCraftableItemsUpToCurrentLevel",
            "rendersDynamicObjectCubes",
        ],
    )
    for _wt_file, _wt_imp, _wt_end in (
        ("disasm_worldtileloader_wt_destroyitem.txt", "implementation: 0x00b02150", "ARM.exidx end: 0x00b0222c"),
        ("disasm_worldtileloader_wt_fueluipos.txt", "implementation: 0x00b021b4", "ARM.exidx end: 0x00b0222c"),
        ("disasm_worldtileloader_wt_renderquad.txt", "implementation: 0x00b0ab4c", "ARM.exidx end: 0x00b0aec0"),
        ("disasm_worldtileloader_wt_rendercubes.txt", "implementation: 0x00b0ae18", "ARM.exidx end: 0x00b0aec0"),
        ("disasm_worldtileloader_wt_bhunloaded.txt", "implementation: 0x00b0b25c", "ARM.exidx end: 0x00b0b398"),
        ("disasm_worldtileloader_wt_glowquadcount.txt", "implementation: 0x00b0b398", "ARM.exidx end: 0x00b0b51c"),
        ("disasm_worldtileloader_wt_occupiesnormal.txt", "implementation: 0x00b0b648", "ARM.exidx end: 0x00b0b664"),
        ("disasm_worldtileloader_wt_expertuse.txt", "implementation: 0x00b0b6d8", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wt_requiresfuel.txt", "implementation: 0x00b0b738", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wt_upgradename.txt", "implementation: 0x00b0b868", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wt_fueltypescount.txt", "implementation: 0x00b0ba64", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wt_fueltypes.txt", "implementation: 0x00b0baf8", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wt_upgradenamecraft.txt", "implementation: 0x00b0bbd8", "ARM.exidx end: 0x00b0bca4"),
        ("disasm_worldtileloader_wt_numcraftable.txt", "implementation: 0x00b0bca4", "ARM.exidx end: 0x00b0bdd0"),
        ("disasm_worldtileloader_wt_numcraftablelevel.txt", "implementation: 0x00b0bce0", "ARM.exidx end: 0x00b0bdd0"),
        ("disasm_worldtileloader_wt_type.txt", "implementation: 0x00b0bd1c", "ARM.exidx end: 0x00b0bdd0"),
        ("disasm_worldtileloader_wt_level.txt", "implementation: 0x00b0bd58", "ARM.exidx end: 0x00b0bdd0"),
        ("disasm_worldtileloader_wt_selindex.txt", "implementation: 0x00b0bd94", "ARM.exidx end: 0x00b0bdd0"),
        ("disasm_worldtileloader_wt_setselindex.txt", "implementation: 0x00b0bdd0", "ARM.exidx end: 0x00b0be58"),
        ("disasm_worldtileloader_wt_craftobj.txt", "implementation: 0x00b0be14", "ARM.exidx end: 0x00b0be58"),
        ("disasm_worldtileloader_wt_count.txt", "implementation: 0x00b0be58", "ARM.exidx end: 0x00b0bed0"),
        ("disasm_worldtileloader_wt_countleft.txt", "implementation: 0x00b0be94", "ARM.exidx end: 0x00b0bed0"),
        ("disasm_worldtileloader_wt_craftprog.txt", "implementation: 0x00b0bed0", "ARM.exidx end: 0x00b0bfec"),
        ("disasm_worldtileloader_wt_setcraftprog.txt", "implementation: 0x00b0bf14", "ARM.exidx end: 0x00b0bfec"),
        ("disasm_worldtileloader_wt_xscroll.txt", "implementation: 0x00b0bf58", "ARM.exidx end: 0x00b0bfec"),
        ("disasm_worldtileloader_wt_setxscroll.txt", "implementation: 0x00b0bfa0", "ARM.exidx end: 0x00b0bfec"),
    ):
        require(NATIVE / _wt_file, [_wt_imp, _wt_end])
    require(
        NATIVE / "WORKBENCH_GIANTS.md",
        [
            "11150",
            "tileIsBurnable",
            "itemTypeIsPainting",
            "96/96",
        ],
    )
    require(
        NATIVE / "workbench_giants.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 8600',
            "updateQuadBufferTexCoords",
            "fillQuadBuffer",
        ],
    )
    for _wg_file, _wg_imp, _wg_end in (
        ("disasm_worldtileloader_wg_update.txt", "implementation: 0x00aeea18", "ARM.exidx end: 0x00af11f0"),
        ("disasm_worldtileloader_wg_draw.txt", "implementation: 0x00af11f0", "ARM.exidx end: 0x00af9850"),
    ):
        require(NATIVE / _wg_file, [_wg_imp, _wg_end])
    require(
        NATIVE / "WORKBENCH_SMALLS.md",
        [
            "786",
            "0x2d (45)",
            "__wrap_malloc",
            "ffe26678",
        ],
    )
    require(
        NATIVE / "workbench_smalls.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 363',
            "titleForCraftProgressUI",
            "requiresPhysicalBlock",
        ],
    )
    for _ws_file, _ws_imp, _ws_end in (
        ("disasm_worldtileloader_ws_initlevel.txt", "implementation: 0x00ae1acc", "ARM.exidx end: 0x00ae2078"),
        ("disasm_worldtileloader_ws_title.txt", "implementation: 0x00afa7e8", "ARM.exidx end: 0x00afa8b0"),
        ("disasm_worldtileloader_ws_reqphys.txt", "implementation: 0x00afe67c", "ARM.exidx end: 0x00afe968"),
        ("disasm_worldtileloader_ws_fbitem.txt", "implementation: 0x00afd4e8", "ARM.exidx end: 0x00afd54c"),
        ("disasm_worldtileloader_ws_fbsavedict.txt", "implementation: 0x00afd7f0", "ARM.exidx end: 0x00afd83c"),
        ("disasm_worldtileloader_ws_fbdataa.txt", "implementation: 0x00afd83c", "ARM.exidx end: 0x00afd874"),
        ("disasm_worldtileloader_ws_fbdatab.txt", "implementation: 0x00afd858", "ARM.exidx end: 0x00afd874"),
        ("disasm_worldtileloader_ws_objecttype.txt", "implementation: 0x00ae1ab0", "ARM.exidx end: 0x00ae1acc"),
        ("disasm_worldtileloader_ws_actiontitle.txt", "implementation: 0x00b01750", "ARM.exidx end: 0x00b01800"),
        ("disasm_worldtileloader_ws_titlecraft.txt", "implementation: 0x00b0bb8c", "ARM.exidx end: 0x00b0bca4"),
    ):
        require(NATIVE / _ws_file, [_ws_imp, _ws_end])
    require(
        NATIVE / "WORKBENCH_CRAFTING.md",
        [
            "5964",
            "preserveItemDataAInCraftedItem",
            "fff3c074",
            "0x00aebb94",
        ],
    )
    require(
        NATIVE / "workbench_crafting.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1891',
            "blockheadWouldLikeToTakeOwnership:withSaveDict:",
            "abortImmediatelyAndRestoreBlockheadItems",
        ],
    )
    for _wc_file, _wc_imp, _wc_end in (
        ("disasm_worldtileloader_wc_craftcompleted.txt", "implementation: 0x00aeb47c", "ARM.exidx end: 0x00aed208"),
        ("disasm_worldtileloader_wc_craftitem.txt", "implementation: 0x00afb164", "ARM.exidx end: 0x00afc87c"),
        ("disasm_worldtileloader_wc_bhownership.txt", "implementation: 0x00ae7248", "ARM.exidx end: 0x00ae81d0"),
        ("disasm_worldtileloader_wc_abortcraft.txt", "implementation: 0x00ae9b78", "ARM.exidx end: 0x00aeaac4"),
        ("disasm_worldtileloader_wc_abortrestore.txt", "implementation: 0x00aeaac4", "ARM.exidx end: 0x00aeb47c"),
    ):
        require(NATIVE / _wc_file, [_wc_imp, _wc_end])
    require(
        NATIVE / "WORKBENCH_LIFECYCLE.md",
        [
            "7590",
            "reloadDrawBlockLightGlowQuadsForTile",
            "reloadDrawBlockDynamicObjectStaticGeometryForTile",
            "cmn r0, 1",
            "__wrap_free",
        ],
    )
    require(
        NATIVE / "workbench_lifecycle.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1670',
            "upgradeToNextLevel",
            "remoteBlockheadRemovedWithID:",
        ],
    )
    for _wl_file, _wl_imp, _wl_end in (
        ("disasm_worldtileloader_wl_getsavedict.txt", "implementation: 0x00ae81d0", "ARM.exidx end: 0x00ae9510"),
        ("disasm_worldtileloader_wl_worldchanged.txt", "implementation: 0x00afcb38", "ARM.exidx end: 0x00afd4ac"),
        ("disasm_worldtileloader_wl_remove.txt", "implementation: 0x00afd874", "ARM.exidx end: 0x00afdec4"),
        ("disasm_worldtileloader_wl_ctor_save.txt", "implementation: 0x00ae4ed8", "ARM.exidx end: 0x00ae6490"),
        ("disasm_worldtileloader_wl_ctor_net.txt", "implementation: 0x00ae6490", "ARM.exidx end: 0x00ae6c18"),
        ("disasm_worldtileloader_wl_remoteupdate.txt", "implementation: 0x00aff768", "ARM.exidx end: 0x00b01180"),
        ("disasm_worldtileloader_wl_bhloaded.txt", "implementation: 0x00ae6ed8", "ARM.exidx end: 0x00ae7248"),
        ("disasm_worldtileloader_wl_updatenet.txt", "implementation: 0x00ae9510", "ARM.exidx end: 0x00ae99f0"),
        ("disasm_worldtileloader_wl_dealloc.txt", "implementation: 0x00ae6c3c", "ARM.exidx end: 0x00ae6ed8"),
        ("disasm_worldtileloader_wl_upgrade.txt", "implementation: 0x00afeae0", "ARM.exidx end: 0x00aff768"),
        ("disasm_worldtileloader_wl_setneedsremoved.txt", "implementation: 0x00afe4c4", "ARM.exidx end: 0x00afe63c"),
        ("disasm_worldtileloader_wl_setpaused.txt", "implementation: 0x00b02060", "ARM.exidx end: 0x00b02134"),
        ("disasm_worldtileloader_wl_remotebhremoved.txt", "implementation: 0x00b01180", "ARM.exidx end: 0x00b01284"),
        ("disasm_worldtileloader_wl_setlevel.txt", "implementation: 0x00afe968", "ARM.exidx end: 0x00afeae0"),
    ):
        require(NATIVE / _wl_file, [_wl_imp, _wl_end])
    require(
        NATIVE / "WORKBENCH_FUEL.md",
        [
            "1684",
            "0x64",
            "124",
            "fffff1a0",
            "fffff160",
        ],
    )
    require(
        NATIVE / "workbench_fuel.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 428',
            "hurryCompletion:",
            "startManagingFuelWithBlockhead:",
        ],
    )
    for _wf_file, _wf_imp, _wf_end in (
        ("disasm_worldtileloader_wf_updatehasfuel.txt", "implementation: 0x00aedb58", "ARM.exidx end: 0x00aee208"),
        ("disasm_worldtileloader_wf_hurry.txt", "implementation: 0x00aed558", "ARM.exidx end: 0x00aedb58"),
        ("disasm_worldtileloader_wf_addfuel.txt", "implementation: 0x00afdf94", "ARM.exidx end: 0x00afe31c"),
        ("disasm_worldtileloader_wf_addfuelitem.txt", "implementation: 0x00b019c0", "ARM.exidx end: 0x00b01a84"),
        ("disasm_worldtileloader_wf_startfuel.txt", "implementation: 0x00afc87c", "ARM.exidx end: 0x00afcafc"),
        ("disasm_worldtileloader_wf_totalleft.txt", "implementation: 0x00aed318", "ARM.exidx end: 0x00aed558"),
        ("disasm_worldtileloader_wf_fuelitems.txt", "implementation: 0x00b01894", "ARM.exidx end: 0x00b018f8"),
        ("disasm_worldtileloader_wf_crafttype.txt", "implementation: 0x00aed44c", "ARM.exidx end: 0x00aed558"),
        ("disasm_worldtileloader_wf_fuelitemcount.txt", "implementation: 0x00b0179c", "ARM.exidx end: 0x00b01800"),
        ("disasm_worldtileloader_wf_hasreqfuel.txt", "implementation: 0x00afe31c", "ARM.exidx end: 0x00afe40c"),
        ("disasm_worldtileloader_wf_fuelcount.txt", "implementation: 0x00afdec4", "ARM.exidx end: 0x00afdf94"),
        ("disasm_worldtileloader_wf_doubleheight.txt", "implementation: 0x00afe40c", "ARM.exidx end: 0x00afe458"),
        ("disasm_worldtileloader_wf_frac.txt", "implementation: 0x00afe63c", "ARM.exidx end: 0x00afe67c"),
        ("disasm_worldtileloader_wf_reqhuman.txt", "implementation: 0x00afcafc", "ARM.exidx end: 0x00afcb38"),
        ("disasm_worldtileloader_wf_candismiss.txt", "implementation: 0x00b02134", "ARM.exidx end: 0x00b02150"),
        ("disasm_worldtileloader_wf_iobjtype.txt", "implementation: 0x00ae9b5c", "ARM.exidx end: 0x00ae9b78"),
    ):
        require(NATIVE / _wf_file, [_wf_imp, _wf_end])
    require(
        NATIVE / "WORKBENCH_ELECTRICITY.md",
        [
            "1699",
            "8192",
            "tileIsAirOrSnow",
            "powf",
            "(48, 130, 220)",
        ],
    )
    require(
        NATIVE / "workbench_electricity.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 245',
            "subtractElectricty:",
            "usesStoresConductsOrProducesElectricity",
        ],
    )
    for _wbe_file, _wbe_imp, _wbe_end in (
        ("disasm_worldtileloader_wb_avaiablelec.txt", "implementation: 0x00b01284", "ARM.exidx end: 0x00b012c0"),
        ("disasm_worldtileloader_wb_conductelec.txt", "implementation: 0x00b012c0", "ARM.exidx end: 0x00b0137c"),
        ("disasm_worldtileloader_wb_subtractelec.txt", "implementation: 0x00b0137c", "ARM.exidx end: 0x00b01750"),
        ("disasm_worldtileloader_wb_genelectric.txt", "implementation: 0x00b01c24", "ARM.exidx end: 0x00b01ec0"),
        ("disasm_worldtileloader_wb_useselectric.txt", "implementation: 0x00b01cac", "ARM.exidx end: 0x00b01ec0"),
        ("disasm_worldtileloader_wb_energyfrac.txt", "implementation: 0x00b01ec0", "ARM.exidx end: 0x00b02060"),
        ("disasm_worldtileloader_wb_solarlight_full.txt", "implementation: 0x00aee208", "ARM.exidx end: 0x00aee508"),
        ("disasm_worldtileloader_wb_solarlight.txt", "implementation: 0x00aee508", "ARM.exidx end: 0x00aeea18"),
        ("disasm_worldtileloader_wb_getlightrgb.txt", "implementation: 0x00ae3c6c", "ARM.exidx end: 0x00ae3f64"),
        ("disasm_worldtileloader_wb_portallight.txt", "implementation: 0x00ae3f64", "ARM.exidx end: 0x00ae42c0"),
        ("disasm_worldtileloader_wb_storagedev.txt", "implementation: 0x00b01bd4", "ARM.exidx end: 0x00b01c24"),
        ("disasm_worldtileloader_wb_conductelec.txt", "implementation: 0x00b012c0", "ARM.exidx end: 0x00b0137c"),
    ):
        require(NATIVE / _wbe_file, [_wbe_imp, _wbe_end])
    require(
        NATIVE / "STEAMTRAIN_CLOSE.md",
        [
            "18484",
            "drawShaderQuad",
            "fmodf",
            "tileIsWater",
            "205",
        ],
    )
    require(
        NATIVE / "steamtrain_close.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 13137',
            "update:accurateDT:isSimulation:",
            "secondOptionTitle",
        ],
    )
    for _sd_file, _sd_imp, _sd_end in (
        ("disasm_worldtileloader_st4_draw.txt", "implementation: 0x00d20d20", "ARM.exidx end: 0x00d2da64"),
        ("disasm_worldtileloader_st4_update.txt", "implementation: 0x00d1bab8", "ARM.exidx end: 0x00d20620"),
        ("disasm_worldtileloader_st4_ctor_save.txt", "implementation: 0x00d18834", "ARM.exidx end: 0x00d18b04"),
        ("disasm_worldtileloader_st4_getsavedict.txt", "implementation: 0x00d18e84", "ARM.exidx end: 0x00d19188"),
        ("disasm_worldtileloader_st4_title.txt", "implementation: 0x00d2fca8", "ARM.exidx end: 0x00d2fcd8"),
        ("disasm_worldtileloader_st4_actiontitle.txt", "implementation: 0x00d2fad8", "ARM.exidx end: 0x00d2fbc0"),
        ("disasm_worldtileloader_st4_secondtitle.txt", "implementation: 0x00d2fbc0", "ARM.exidx end: 0x00d2fca8"),
        ("disasm_worldtileloader_st4_itemtype.txt", "implementation: 0x00d2f8c8", "ARM.exidx end: 0x00d2f8e4"),
        ("disasm_worldtileloader_st4_objecttype.txt", "implementation: 0x00d17e7c", "ARM.exidx end: 0x00d17e98"),
        ("disasm_worldtileloader_st4_cxx_construct.txt", "implementation: 0x00d31378", "ARM.exidx end: 0x00d31390"),
    ):
        require(NATIVE / _sd_file, [_sd_imp, _sd_end])
    require(
        NATIVE / "PARTICLES.md",
        [
            "6662",
            "ElectrictyParticlePathIndex",
            "0x7fffffff",
            "closestPointOnLineToPoint",
            "dmb ish",
        ],
    )
    require(
        NATIVE / "particles.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 4099',
            "addElectricityParticleWithPath:size:",
            "doAddElectricityParticleWithPath:size:",
        ],
    )
    for _pe_file, _pe_imp, _pe_end in (
        ("disasm_worldtileloader_pe_init.txt", "implementation: 0x00d85f98", "ARM.exidx end: 0x00d86ddc"),
        ("disasm_worldtileloader_pe_instance.txt", "implementation: 0x00d85ecc", "ARM.exidx end: 0x00d85f98"),
        ("disasm_worldtileloader_pe_reset.txt", "implementation: 0x00d86e30", "ARM.exidx end: 0x00d87034"),
        ("disasm_worldtileloader_pe_setworld.txt", "implementation: 0x00d86dec", "ARM.exidx end: 0x00d86e30"),
        ("disasm_worldtileloader_pe_setworldwidth.txt", "implementation: 0x00d8ccf8", "ARM.exidx end: 0x00d8cd3c"),
        ("disasm_worldtileloader_pe_worldwidth.txt", "implementation: 0x00d8ccbc", "ARM.exidx end: 0x00d8ccf8"),
        ("disasm_worldtileloader_pe_setstopall.txt", "implementation: 0x00d8cc78", "ARM.exidx end: 0x00d8ccbc"),
        ("disasm_worldtileloader_pe_stopall.txt", "implementation: 0x00d8cc3c", "ARM.exidx end: 0x00d8cc78"),
        ("disasm_worldtileloader_pe_addparticle.txt", "implementation: 0x00d87034", "ARM.exidx end: 0x00d87268"),
        ("disasm_worldtileloader_pe_addparticle_center.txt", "implementation: 0x00d87268", "ARM.exidx end: 0x00d8753c"),
        ("disasm_worldtileloader_pe_addparticle_goal.txt", "implementation: 0x00d87b8c", "ARM.exidx end: 0x00d88284"),
        ("disasm_worldtileloader_pe_addbonus.txt", "implementation: 0x00d88284", "ARM.exidx end: 0x00d88670"),
        ("disasm_worldtileloader_pe_addelectricity.txt", "implementation: 0x00d8753c", "ARM.exidx end: 0x00d876b0"),
        ("disasm_worldtileloader_pe_doelectricity.txt", "implementation: 0x00d876b0", "ARM.exidx end: 0x00d87b04"),
        ("disasm_worldtileloader_pe_render.txt", "implementation: 0x00d88670", "ARM.exidx end: 0x00d8c67c"),
    ):
        require(NATIVE / _pe_file, [_pe_imp, _pe_end])
    require(
        NATIVE / "TORCH.md",
        [
            "10130",
            "reloadDrawBlockDynamicObjectQuadsForTile",
            "fillQuadBuffer",
            "0x102",
            "dmb ish",
        ],
    )
    require(
        NATIVE / "torch.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 4762',
            "getLightRGB",
            "worldContentsChanged:",
        ],
    )
    for _t_file, _t_imp, _t_end in (
        ("disasm_worldtileloader_t_initsubderived.txt", "implementation: 0x004b4a20", "ARM.exidx end: 0x004b4e98"),
        ("disasm_worldtileloader_t_getlightrgb.txt", "implementation: 0x004b4e98", "ARM.exidx end: 0x004b52ac"),
        ("disasm_worldtileloader_t_ctor_placed.txt", "implementation: 0x004b5300", "ARM.exidx end: 0x004b5c08"),
        ("disasm_worldtileloader_t_objecttype.txt", "implementation: 0x004b5c1c", "ARM.exidx end: 0x004b5c74"),
        ("disasm_worldtileloader_t_fbitemtype.txt", "implementation: 0x004b5c38", "ARM.exidx end: 0x004b5c74"),
        ("disasm_worldtileloader_t_fbsavedict.txt", "implementation: 0x004b5c74", "ARM.exidx end: 0x004b5cc0"),
        ("disasm_worldtileloader_t_fbdataa.txt", "implementation: 0x004b5cc0", "ARM.exidx end: 0x004b5d38"),
        ("disasm_worldtileloader_t_fbdatab.txt", "implementation: 0x004b5cfc", "ARM.exidx end: 0x004b5d38"),
        ("disasm_worldtileloader_t_ctor_save.txt", "implementation: 0x004b5d38", "ARM.exidx end: 0x004b6230"),
        ("disasm_worldtileloader_t_ctor_net.txt", "implementation: 0x004b6230", "ARM.exidx end: 0x004b6594"),
        ("disasm_worldtileloader_t_getsavedict.txt", "implementation: 0x004b65b8", "ARM.exidx end: 0x004b69e0"),
        ("disasm_worldtileloader_t_updatenet.txt", "implementation: 0x004b69e0", "ARM.exidx end: 0x004b6a34"),
        ("disasm_worldtileloader_t_creationdata.txt", "implementation: 0x004b6a34", "ARM.exidx end: 0x004b6d64"),
        ("disasm_worldtileloader_t_dealloc.txt", "implementation: 0x004b6ed0", "ARM.exidx end: 0x004b6ff4"),
        ("disasm_worldtileloader_t_rmmacro.txt", "implementation: 0x004b6ff4", "ARM.exidx end: 0x004b71d8"),
        ("disasm_worldtileloader_t_draw.txt", "implementation: 0x004b71d8", "ARM.exidx end: 0x004b77d0"),
        ("disasm_worldtileloader_t_remoteupdate.txt", "implementation: 0x004b77d0", "ARM.exidx end: 0x004b78bc"),
        ("disasm_worldtileloader_t_waterchanged.txt", "implementation: 0x004b78bc", "ARM.exidx end: 0x004b7bd4"),
        ("disasm_worldtileloader_t_worldcontents.txt", "implementation: 0x004b7bd4", "ARM.exidx end: 0x004b8b50"),
        ("disasm_worldtileloader_t_worldchanged.txt", "implementation: 0x004b8b50", "ARM.exidx end: 0x004b8be8"),
        ("disasm_worldtileloader_t_setneedsremoved.txt", "implementation: 0x004b8be8", "ARM.exidx end: 0x004b8cd0"),
        ("disasm_worldtileloader_t_renderimageidx.txt", "implementation: 0x004b8cd0", "ARM.exidx end: 0x004b8fa8"),
        ("disasm_worldtileloader_t_staticquadcount.txt", "implementation: 0x004b8fa8", "ARM.exidx end: 0x004b8fd0"),
        ("disasm_worldtileloader_t_adddrawquad.txt", "implementation: 0x004b8fd0", "ARM.exidx end: 0x004bda38"),
        ("disasm_worldtileloader_t_lightpos.txt", "implementation: 0x004be0d4", "ARM.exidx end: 0x004bed60"),
        ("disasm_worldtileloader_t_glowquadcount.txt", "implementation: 0x004bed90", "ARM.exidx end: 0x004bedec"),
        ("disasm_worldtileloader_t_isdownlight.txt", "implementation: 0x004bedec", "ARM.exidx end: 0x004beeac"),
        ("disasm_worldtileloader_t_isuplight.txt", "implementation: 0x004bee3c", "ARM.exidx end: 0x004beeac"),
        ("disasm_worldtileloader_t_occupiesfg.txt", "implementation: 0x004bee90", "ARM.exidx end: 0x004beeac"),
        ("disasm_worldtileloader_t_addartistlightcont.txt", "implementation: 0x004beeac", "ARM.exidx end: 0x004bef20"),
        ("disasm_worldtileloader_t_dataa.txt", "implementation: 0x004bef20", "ARM.exidx end: 0x004bef5c"),
        ("disasm_worldtileloader_t_setdataa.txt", "implementation: 0x004bef5c", "ARM.exidx end: 0x004befa4"),
        ("disasm_worldtileloader_t_datab.txt", "implementation: 0x004befa4", "ARM.exidx end: 0x004befe0"),
        ("disasm_worldtileloader_t_setdatab.txt", "implementation: 0x004befe0", "ARM.exidx end: 0x004bf028"),
    ):
        require(NATIVE / _t_file, [_t_imp, _t_end])
    require(
        NATIVE / "WINDOW_SMALLS.md",
        [
            "1185",
            "dmb ish",
            "16-byte frame alignment",
            "4.0f",
            "tileAtWorldPositionLoaded",
        ],
    )
    require(
        NATIVE / "window_smalls.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 169',
            "occupiesBackgroundContents",
            "setNeedsToUpdateChoiceUI:",
        ],
    )
    for _ws_file, _ws_imp, _ws_end in (
        ("disasm_worldtileloader_win_ctor_placed.txt", "# implementation: 0x00c986a0", "# ARM.exidx end: 0x00c98944"),
        ("disasm_worldtileloader_win_ctor_net.txt", "# implementation: 0x00c98b70", "# ARM.exidx end: 0x00c98e5c"),
        ("disasm_worldtileloader_win_creationdata.txt", "# implementation: 0x00c99094", "# ARM.exidx end: 0x00c99338"),
        ("disasm_worldtileloader_win_updatenet.txt", "# implementation: 0x00c99040", "# ARM.exidx end: 0x00c99094"),
        ("disasm_worldtileloader_win_draw.txt", "# implementation: 0x00c99568", "# ARM.exidx end: 0x00c99790"),
        ("disasm_worldtileloader_win_setneedsremoved.txt", "# implementation: 0x00c98538", "# ARM.exidx end: 0x00c986a0"),
        ("disasm_worldtileloader_win_dealloc.txt", "# implementation: 0x00c994a4", "# ARM.exidx end: 0x00c99568"),
        ("disasm_worldtileloader_win_initsubderived.txt", "# implementation: 0x00c984cc", "# ARM.exidx end: 0x00c98538"),
        ("disasm_worldtileloader_win_fbitemtype.txt", "# implementation: 0x00c984fc", "# ARM.exidx end: 0x00c98538"),
        ("disasm_worldtileloader_win_occupiesbg.txt", "# implementation: 0x00c99790", "# ARM.exidx end: 0x00c997ac"),
        ("disasm_worldtileloader_st3_setwbchoice.txt", "# implementation: 0x00d2f8e4", "# ARM.exidx end: 0x00d2fad8"),
        ("disasm_worldtileloader_st3_fuelcount.txt", "# implementation: 0x00d2fcd8", "# ARM.exidx end: 0x00d2fda8"),
        ("disasm_worldtileloader_st3_fuelitemcount.txt", "# implementation: 0x00d2fda8", "# ARM.exidx end: 0x00d2fdf4"),
        ("disasm_worldtileloader_st3_fuelitems.txt", "# implementation: 0x00d2fdc4", "# ARM.exidx end: 0x00d2fdf4"),
        ("disasm_worldtileloader_st3_fueluipos.txt", "# implementation: 0x00d30504", "# ARM.exidx end: 0x00d30580"),
        ("disasm_worldtileloader_st3_needschoice.txt", "# implementation: 0x00d312f8", "# ARM.exidx end: 0x00d31334"),
        ("disasm_worldtileloader_st3_setneedschoice.txt", "# implementation: 0x00d31334", "# ARM.exidx end: 0x00d31378"),
        ("disasm_worldtileloader_st3_candismiss.txt", "# implementation: 0x00d304cc", "# ARM.exidx end: 0x00d30504"),
        ("disasm_worldtileloader_st3_requiresfuel.txt", "# implementation: 0x00d304e8", "# ARM.exidx end: 0x00d30504"),
        ("disasm_worldtileloader_st3_isengine.txt", "# implementation: 0x00d3106c", "# ARM.exidx end: 0x00d31088"),
        ("disasm_worldtileloader_st3_maxriders.txt", "# implementation: 0x00d311dc", "# ARM.exidx end: 0x00d311f8"),
        ("disasm_worldtileloader_st3_settargetvel.txt", "# implementation: 0x00d2f8ac", "# ARM.exidx end: 0x00d2f8c8"),
    ):
        require(NATIVE / _ws_file, [_ws_imp, _ws_end])
    require(
        NATIVE / "STEAM_RIDERS.md",
        [
            "2500",
            "atan2f",
            "0xcd",
            "fffffcc0",
            "ffffcacc",
        ],
    )
    require(
        NATIVE / "steam_riders.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 567',
            "riderBodyMatrixForBlockhead:cameraX:",
            "addToFuelForItem:",
        ],
    )
    for _sr_file, _sr_imp, _sr_end in (
        ("disasm_worldtileloader_st2_riderbody.txt", "# implementation: 0x00d2efd0", "# ARM.exidx end: 0x00d2f8ac"),
        ("disasm_worldtileloader_st2_tapradius.txt", "# implementation: 0x00d307cc", "# ARM.exidx end: 0x00d3106c"),
        ("disasm_worldtileloader_st2_riderpos.txt", "# implementation: 0x00d2eac8", "# ARM.exidx end: 0x00d2efd0"),
        ("disasm_worldtileloader_st2_addfuelitem.txt", "# implementation: 0x00d30030", "# ARM.exidx end: 0x00d304cc"),
        ("disasm_worldtileloader_st2_renderpos.txt", "# implementation: 0x00d2e5b4", "# ARM.exidx end: 0x00d2ea38"),
        ("disasm_worldtileloader_st2_updatehasfuel.txt", "# implementation: 0x00d2fdf4", "# ARM.exidx end: 0x00d30030"),
        ("disasm_worldtileloader_st2_removerider.txt", "# implementation: 0x00d31088", "# ARM.exidx end: 0x00d311dc"),
        ("disasm_worldtileloader_st2_setneedsremoved.txt", "# implementation: 0x00d30580", "# ARM.exidx end: 0x00d306d0"),
        ("disasm_worldtileloader_st2_setpaused.txt", "# implementation: 0x00d306d0", "# ARM.exidx end: 0x00d307cc"),
        ("disasm_worldtileloader_st2_railname.txt", "# implementation: 0x00d311f8", "# ARM.exidx end: 0x00d312f8"),
        ("disasm_worldtileloader_st2_camerapos.txt", "# implementation: 0x00d2ea38", "# ARM.exidx end: 0x00d2eac8"),
    ):
        require(NATIVE / _sr_file, [_sr_imp, _sr_end])
    require(
        NATIVE / "STEAMTRAIN_CORE.md",
        [
            "4243",
            "texCoordsForImageIndex",
            "0x243",
            "0x68",
            "0x62",
            "fffffc8c",
        ],
    )
    require(
        NATIVE / "steamtrain_core.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1371',
            "updateSearchForStations",
            "loadDerivedStuff",
        ],
    )
    for _st_file, _st_imp, _st_end in (
        ("disasm_worldtileloader_st_loadderived.txt", "# implementation: 0x00d170b0", "# ARM.exidx end: 0x00d17e7c"),
        ("disasm_worldtileloader_st_ctor_pos.txt", "# implementation: 0x00d17e98", "# ARM.exidx end: 0x00d18834"),
        ("disasm_worldtileloader_st_ctor_net.txt", "# implementation: 0x00d18b04", "# ARM.exidx end: 0x00d18e60"),
        ("disasm_worldtileloader_st_creationnetdata.txt", "# implementation: 0x00d19188", "# ARM.exidx end: 0x00d1972c"),
        ("disasm_worldtileloader_st_dealloc.txt", "# implementation: 0x00d19898", "# ARM.exidx end: 0x00d19b84"),
        ("disasm_worldtileloader_st_remoteupdate.txt", "# implementation: 0x00d19b84", "# ARM.exidx end: 0x00d1a510"),
        ("disasm_worldtileloader_st_searchstations.txt", "# implementation: 0x00d1a510", "# ARM.exidx end: 0x00d1ba7c"),
    ):
        require(NATIVE / _st_file, [_st_imp, _st_end])
    require(
        NATIVE / "ELECTRIC_LIGHTING.md",
        [
            "2390",
            "ffffef20",
            "reloadDrawBlockLightGlowQuadsForTile",
            "map<int, int>",
            "ffe259f8",
        ],
    )
    require(
        NATIVE / "electric_lighting.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 577',
            "ArtificialLight",
            "GlowBlock",
        ],
    )
    for _el_file, _el_imp, _el_end in (
        ("disasm_worldtileloader_al_ctor_color.txt", "# implementation: 0x00a93744", "# ARM.exidx end: 0x00a93bbc"),
        ("disasm_worldtileloader_al_ctor_save.txt", "# implementation: 0x00a93c64", "# ARM.exidx end: 0x00a942d4"),
        ("disasm_worldtileloader_al_dealloc.txt", "# implementation: 0x00a947ac", "# ARM.exidx end: 0x00a94898"),
        ("disasm_worldtileloader_al_worldchanged.txt", "# implementation: 0x00a94898", "# ARM.exidx end: 0x00a9519c"),
        ("disasm_worldtileloader_al_rmmacro.txt", "# implementation: 0x00a9519c", "# ARM.exidx end: 0x00a95248"),
        ("disasm_worldtileloader_al_cxx_construct.txt", "# implementation: 0x00a958bc", "# ARM.exidx end: 0x00a958d4"),
        ("disasm_worldtileloader_gb_initsubderived.txt", "# implementation: 0x00ca8304", "# ARM.exidx end: 0x00ca8334"),
        ("disasm_worldtileloader_gb_ctor.txt", "# implementation: 0x00ca83d4", "# ARM.exidx end: 0x00ca8920"),
        ("disasm_worldtileloader_gb_dealloc.txt", "# implementation: 0x00ca8e64", "# ARM.exidx end: 0x00ca8f4c"),
        ("disasm_worldtileloader_gb_rmmacro.txt", "# implementation: 0x00ca8f4c", "# ARM.exidx end: 0x00ca90bc"),
        ("disasm_worldtileloader_gb_worldchanged.txt", "# implementation: 0x00ca90bc", "# ARM.exidx end: 0x00ca93ac"),
        ("disasm_worldtileloader_gb_setneedsremoved.txt", "# implementation: 0x00ca93ac", "# ARM.exidx end: 0x00ca9500"),
        ("disasm_worldtileloader_gb_addlightcont.txt", "# implementation: 0x00ca960c", "# ARM.exidx end: 0x00ca9680"),
        ("disasm_worldtileloader_wpc_cxx_destruct.txt", "# implementation: 0x00db5454", "# ARM.exidx end: 0x00db5604"),
        ("disasm_worldtileloader_wpc_cxx_construct.txt", "# implementation: 0x00db549c", "# ARM.exidx end: 0x00db5604"),
        ("disasm_worldtileloader_es_cxx_construct.txt", "# implementation: 0x00cb15a4", "# ARM.exidx end: 0x00cb15bc"),
    ):
        require(NATIVE / _el_file, [_el_imp, _el_end])
    require(
        NATIVE / "CXX_CONSTRUCT.md",
        [
            "866",
            "0x30c",
            "ffffe554",
            "Vector::Vector()",
            "262/262",
            "disasm_dynamicworld_cxx_construct.txt",
        ],
    )
    require(
        NATIVE / "cxx_construct.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 866',
            "OBJC_IVAR_$_DynamicWorld.dynamicObjects",
        ],
    )
    require(
        NATIVE / "disasm_dynamicworld_cxx_construct.txt",
        ["# implementation: 0x00907218", "# ARM.exidx end: 0x00907fa0"],
    )
    require(
        NATIVE / "COMPRESS_STUB.md",
        [
            "5",
            "empty stub",
            "52/52",
            "0x0085475c",
        ],
    )
    require(
        NATIVE / "compress_stub.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 5',
            "compressBlocks",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_compressblocks.txt",
        ["# implementation: 0x0085475c", "# ARM.exidx end: 0x00854770"],
    )
    require(
        NATIVE / "WORLD_LINE_CLOSURE.md",
        [
            "100%",
            "262/262",
            "compressBlocks",
            ".cxx_construct",
            "E65",
            "E66",
        ],
    )
    require(
        NATIVE / "DRAW_COMPOSITE.md",
        [
            "7203",
            "ffe2353c",
            "ffe23538",
            "0x00E4AA3C",
            "structural pass",
            "boundary",
        ],
    )
    require(
        NATIVE / "draw_composite.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 7203',
            "draw:projectionMatrix:",
            "hideUIType:",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_draw_projectionmatrix_modelviewmatrix_ca.txt",
        ["# implementation: 0x008d4ff0", "# ARM.exidx end: 0x008dc07c"],
    )
    require(
        NATIVE / "CLIENTTILELOADER_GETINITIALROCKDIRT.md",
        [
            "0x00947af8",
            "490 ARM words",
            "0x00947cac  A.getX(q + 0.1, 0.5, 3)",
            "*rockHeight = 16 + 32 * (31 * (0.5 + r / 2))",
            "*dirtHeight = 20 + 32 * (31 * (0.5 + r2 / 2))",
            "zero stret reads",
        ],
    )
    require(
        NATIVE / "disasm_clienttileloader_getinitialrockdirt.txt",
        [
            "# ClientTileLoader -[getInitialRockAndDirtHeightforX:rockHeight:dirtHeight:]",
            "# implementation: 0x00947af8",
            "0x009482a0",
        ],
    )
    require(
        NATIVE / "clienttileloader_getinitialrockdirt.json",
        [
            '"verified_words": 490',
            '"blx_calls":',
            '"direct_calls":',
            '"formula":',
            '"elf_sha256": "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"',
        ],
    )
    require(
        NATIVE / "CLIENTTILELOADER_FAULTOFFSET.md",
        [
            "0x00948470",
            "284 ARM words",
            "faultNoiseFunction",
            "0x00948598",
            "0x0094885c",
            "if (width < 512):",
            "result = (int)(512.0f * shaped * band)",
        ],
    )
    require(
        NATIVE / "disasm_clienttileloader_faultoffset.txt",
        [
            "# ClientTileLoader -[faultOffsetForX:y:]",
            "# implementation: 0x00948470",
            "0x009488e0",
        ],
    )
    require(
        NATIVE / "clienttileloader_faultoffset.json",
        [
            '"verified_words": 284',
            '"blx_calls":',
            '"formula":',
            '"elf_sha256": "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7"',
        ],
    )
    require(
        NATIVE / "NOISEFUNCTION_GETXY.md",
        [
            "getX:Y:octaves:",
            "0x00a6324c",
            "grad2",
            "0x2008",
        ],
    )
    require(
        NATIVE / "disasm_worldtileloader_refineterrain.txt",
        [
            "# WorldTileLoader -[refineTerrain]",
            "# implementation: 0x00854c54",
            "# ARM.exidx end: 0x00855ad0",
        ],
    )
    require(
        NATIVE / "worldtileloader_refineterrain.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "\"verified_words\": 927",
            "OBJC_IVAR_$_WorldTileLoader.refineTerrainCount",
            "OBJC_IVAR_$_WorldTileLoader.hasRefinedTerrain",
            "OBJC_CLASS_$_NSAutoreleasePool",
            "tileAtWorldPositionLoaded",
            "makeIntpair",
        ],
    )
    require(
        NATIVE / "STATIC_LIFECYCLE_CONTRACT.md",
        [
            "VerdeApplication",
            "singleTask",
            "context validity",
            "nativeHandleUri",
            "Evidence levels",
        ],
    )
    require(
        ROOT / "tools/extract_original_item_image_map.py",
        [
            "FUNCTION_VA = 0x004D71DC",
            "JUMP_BASE_VA = 0x004D726C",
            "DEFAULT_IMAGE = 32",
            "movw_r0_immediate",
        ],
    )
    require(
        NATIVE / "original_item_image_map.tsv",
        [
            "item_type\timage_dataA0\tcol_from_image_a0\trow_from_image_a0",
            "col=image%32,row=image//32 (derived; TileMap:32x32)",
            "1024\t33\t1\t1\t33\t1\t1\t0x004d73c0",
            "1043\t342\t22\t10\t343\t23\t10\t0x004d74e0",
            "1104\t742\t6\t23\t743\t7\t23\t0x004d7528",
        ],
    )
    require(
        ROOT / "tools/extract_original_tile_item_map.py",
        [
            "FUNCTION_VA = 0x00A18044",
            "TABLE_BASE_VA = 0x00A1868C",
            "LAST_TILE_TYPE = 77",
            "direct_item_type",
        ],
    )
    require(
        ROOT / "tools/recover_gameview_touch_callbacks.py",
        [
            "METHODS = [",
            "\"arm_exidx_end\": hex(end)",
            "selector_references",
            "--check",
        ],
    )
    touch_callbacks = NATIVE / "gameview_touch_callbacks.json"
    require(
        touch_callbacks,
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "static ARM/ObjC evidence; not runtime behavior verification",
            '"selector": "startTouch:withTouch:withEvent:"',
            '"selector": "endSecondaryTouch:"',
            '"implementation": "0x92cdd8"',
        ],
    )
    require(
        ROOT / "tools/verify_font_glyph_content.py",
        [
            "scale_probe",
            "glyphs_with_ink",
            "--check",
        ],
    )
    require(
        NATIVE / "FONT_GLYPH_CONTENT.md",
        [
            "confirmed by pixels",
            "99 / 100",
            "the space character",
        ],
    )
    require(
        NATIVE / "font_glyph_content.json",
        [
            '"glyphs_empty": 51',
            '"glyphs_with_ink_at_scale": 99',
        ],
    )
    require(
        ROOT / "tools/parse_original_fonts.py",
        [
            "BMFont",
            "atlas_size_matches",
            "--check",
        ],
    )
    require(
        NATIVE / "FONT_ASSET_TABLES.md",
        [
            "2048x1024",
            "ASCII 126",
            "Blockheads_64.png",
        ],
    )
    require(
        NATIVE / "font_glyph_tables.json",
        [
            '"fonts": 5',
            '"glyphs": 500',
            '"atlas_size_mismatches": 1',
        ],
    )
    require(
        ROOT / "tools/audit_shader_assets.py",
        [
            "SHADER_SUFFIXES",
            "from string_evidence import classify, contains_token, nul_strings",
            "def sweep_sources",
            "suffix-composition",
        ],
    )
    require(
        NATIVE / "SHADER_ASSET_COVERAGE.md",
        [
            "%@.vsh",
            "whole APK",
            "count of unresolved programs",
            "84",
        ],
    )
    require(
        NATIVE / "shader_asset_coverage.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"ships": 92',
            '"original_suffix_composition": 70',
            '"original_unattributed": 0',
        ],
    )
    require(
        ROOT / "tools/audit_item_display_names.py",
        [
            "classify_context",
            "name-list",
            "name_table_found",
        ],
    )
    require(
        NATIVE / "ITEM_DISPLAY_NAME_SOURCES.md",
        [
            "Why the token search alone is wrong",
            "not extractable from this APK",
            "Clay` only appears inside `Clayton",
        ],
    )
    require(
        NATIVE / "item_display_name_sources.json",
        [
            '"name_table_found": 0',
            '"exact_objc_class_matches": 18',
        ],
    )
    require(
        ROOT / "tools/audit_text_assets.py",
        [
            "sentence_like",
            "PROBE_SYMBOLS",
            "--check",
        ],
    )
    require(
        NATIVE / "TEXT_ASSET_INVENTORY.md",
        [
            "no localization pipeline to consume",
            "InfoPlist.strings",
            "Item display names are not solved here",
        ],
    )
    require(
        NATIVE / "text_asset_inventory.json",
        [
            '"localization_key_value_pairs": 0',
            '"sentence_like_strings": 413',
        ],
    )
    require(
        ROOT / "tools/verify_sprite_cell_content.py",
        [
            "image_domain_in_tilemap",
            "image_domain_in_items",
            "out_of_bounds",
        ],
    )
    require(
        NATIVE / "SPRITE_CELL_CONTENT.md",
        [
            "The pixels decide",
            "image-id domain lives in",
            "the numbers were never wrong, the atlas was",
        ],
    )
    require(
        NATIVE / "sprite_cell_content.json",
        [
            '"image_with_ink_in_tilemap": 82',
            '"image_out_of_bounds_in_items": 11',
        ],
    )
    require(
        ROOT / "tools/verify_atlas_geometry.py",
        [
            "image_id_domain",
            "atlas_attribution",
            "inherited",
            "--check",
        ],
    )
    require(
        NATIVE / "ATLAS_GEOMETRY_CONTRACT.md",
        [
            "wrong attribution in the check",
            "TileMap:32x32",
            "32 x 32 x 64",
        ],
    )
    require(
        NATIVE / "atlas_geometry_contract.json",
        [
            '"item_image_id_violations": 0',
            '"item_formula_violations": 0',
            '"tile_violations": 0',
        ],
    )
    require(
        ROOT / "tools/crosscheck_shader_declarations.py",
        [
            "declared-attribute",
            "undeclared",
            "binding markers",
        ],
    )
    require(
        NATIVE / "SHADER_DECLARATION_CROSSCHECK.md",
        [
            "not a declaration list",
            "ColoredNoTexture",
            "never-claimed attributes",
        ],
    )
    require(
        NATIVE / "shader_declaration_crosscheck.json",
        [
            '"undeclared_binding_markers": 63',
            '"shaders_missing_source": 0',
        ],
    )
    require(
        ROOT / "tools/audit_texture_sets.py",
        [
            "ratio_uniform",
            "identical-duplicate",
            "--check",
        ],
    )
    require(
        NATIVE / "TEXTURE_RESOLUTION_SETS.md",
        [
            "yakNeck.png",
            "32x",
            "HDTex/` membership does not imply a different resolution",
        ],
    )
    require(
        NATIVE / "texture_resolution_sets.json",
        [
            '"sd_hd_pair": 122',
            '"non_uniform_ratio": 1',
            '"8x": 23',
        ],
    )
    require(
        NATIVE / "TILE_CONTENT_RENDER_MAP.md",
        [
            "delegated-dispatch",
            "0x00a22c38",
            "never guesses one",
        ],
    )
    require(
        ROOT / "tools/crosscheck_tile_record_header.py",
        [
            "ACCESSOR_RE",
            "documented_but_unread",
            "size_agrees",
        ],
    )
    require(
        NATIVE / "TILE_RECORD_HEADER_CROSSCHECK.md",
        [
            "backWallType - 1",
            "new",
            "not original source",
        ],
    )
    require(
        NATIVE / "tile_record_header_crosscheck.json",
        [
            '"size_agrees": true',
            '"agreeing_offsets": 2',
        ],
    )
    require(
        ROOT / "tools/extract_grp_identifiers.py",
        [
            "GROUP_PREFIX = \"grp.\"",
            "boundary",
        ],
    )
    require(
        NATIVE / "GRP_IDENTIFIERS.md",
        [
            "Adjacency is not membership",
            "17,209",
            "bird%d.wav",
        ],
    )
    require(
        NATIVE / "grp_identifiers.json",
        [
            '"group_key_count": 117',
            '"audio_names_not_shipped": [\n    "bird%d.wav"\n  ]',
        ],
    )
    require(
        ROOT / "tools/test_live_runtime_ivars.py",
        [
            "EXPECTED_COUNTS",
            "VERIFIED_OFFSETS",
            "527",
        ],
    )
    require(
        NATIVE / "LIVE_RUNTIME_IVARS.md",
        [
            "Live runtime ivar offsets",
            "corrected",
            "Blockhead.headCube",
        ],
    )
    require(
        NATIVE / "live_runtime_ivar_offsets.json",
        [
            '"ivar_count": 527',
            '"Blockhead.headCube": 212',
            '"DynamicWorld.world": 4',
        ],
    )
    require(
        ROOT / "tools/test_live_frame_stack.py",
        [
            "REQUIRED_FRAMES",
            "render:cameraZ:projectionMatrix:pinchScale:",
            "drawForButtonProjectionMatrix:modelViewMatrix:",
        ],
    )
    require(
        NATIVE / "LIVE_FRAME_STACK.md",
        [
            "Live frame stack and dispatch hierarchy",
            "UIKitMain",
            "World render:cameraZ:projectionMatrix:pinchScale:",
        ],
    )
    require(
        NATIVE / "live_frame_stack.json",
        [
            '"thread_name": "UIKitMain"',
            '"root_driver": "World render:cameraZ:projectionMatrix:pinchScale:"',
            '"build_libApplication_sha256"',
        ],
    )
    require(
        ROOT / "tools/probe_live_frame_stack.py",
        [
            "callsite_ok",
            "fn_start_a32",
            "BUILD MISMATCH",
        ],
    )
    require(
        ROOT / "tools/test_probe_live_frame_stack.py",
        [
            "attribute_word",
            "words_from_blob",
        ],
    )
    require(
        NATIVE / "disasm_donkeylike_setupmatrices.txt",
        [
            "DonkeyLike -[setupMatrices:dt:]",
            "bodyMatrix",
            "galloping",
        ],
    )
    require(
        NATIVE / "disasm_blockhead_updateanimation.txt",
        [
            "Blockhead -[updateAnimation]",
            "traverseToKeyFrame",
            "isInJetPackFreeFlightMode",
        ],
    )
    require(
        ROOT / "tools/test_blockhead_clothing_pipeline.py",
        [
            "REQUIRED_SLOTS",
            "JET_TEXTURES",
            "hatPomPomCubes",
        ],
    )
    require(
        NATIVE / "BLOCKHEAD_CLOTHING_PIPELINE.md",
        [
            "Blockhead clothing and accessory mesh pipeline",
            "updateClothingCubes",
            "hatPomPomCubes",
        ],
    )
    require(
        NATIVE / "disasm_blockhead_updateclothingcubes.txt",
        [
            "Blockhead -[updateClothingCubes]",
            "hatPomPomCubes",
            "jet1.png",
        ],
    )
    require(
        ROOT / "tools/probe_live_ivar_offsets.py",
        [
            "OBJC_IVAR_$_",
            "cells_rewritten",
            "BUILD MISMATCH",
        ],
    )
    require(
        NATIVE / "IVAR_OFFSET_READING.md",
        [
            "cross-build misread",
            "instance discovery",
            "live_verified_fields.json",
        ],
    )
    require(
        NATIVE / "live_ivar_offset_divergence.json",
        [
            '"cells_compared": 3793',
            '"cells_identical": 3714',
            '"cells_rewritten": 79',
            '"cells_rewritten": 3735',
        ],
    )
    require(
        ROOT / "tools/find_selector_senders.py",
        [
            "pool_word + PIC_BASE == target address",
            "0x0105FAF4",
            "prologue-verified",
            "objc_msgSend",
            "static_string_args",
            "SEL materialisation",
        ],
    )
    require(
        NATIVE / "SELECTOR_SENDERS.md",
        [
            "reference sites",
            "0x105faf4",
            "settled by the prologue walk-back",
            "noPath.wav",
            "slowdown.wav",
        ],
    )
    require(
        NATIVE / "selector_senders.json",
        [
            '"pic_base": "0x105faf4"',
            '"selector": "soundNamed:"',
            '"slots": [\n        "0xe7de14"',
            '"objc_msgSend_stub": "0x1c281c"',
            '"static_args"',
        ],
    )
    require(
        ROOT / "tools/extract_sound_call_sites.py",
        [
            "LITERAL_WINDOW",
            "prologue-verified",
        ],
    )
    require(
        NATIVE / "audio_call_site_literals.json",
        [
            '"selector": "soundNamed:"',
            '"attribution": "prologue-verified"',
        ],
    )
    require(
        ROOT / "tools/test_audio_call_site_literals.py",
        [
            "EXPECTED_FUNCTIONS",
            "prologue-verified",
        ],
    )
    require(
        ROOT / "tools/probe_objc_send_channel.py",
        [
            "msgrefs_unit_matches",
            "relocation_sections",
            "send_idiom",
        ],
    )
    require(
        NATIVE / "OBJC_SEND_CHANNEL.md",
        [
            "recorded negative result",
            ".rel.dyn",
            "does not transfer here as-is",
            "bl objc_msgSend",
        ],
    )
    require(
        NATIVE / "objc_send_channel.json",
        [
            '"string_va": "0xecf8e2"',
            '"msgrefs_unit_matches": []',
        ],
    )
    require(
        ROOT / "tools/extract_audio_api.py",
        [
            "MJSoundManager",
            "OBJC_IVAR_$_",
            "classes_with_methods",
        ],
    )
    require(
        NATIVE / "AUDIO_API_SURFACE.md",
        [
            "the owner. Loading and lookup",
            "Which game action",
            "reached indirectly",
        ],
    )
    require(
        NATIVE / "audio_api_surface.json",
        [
            '"methods_total": 128',
            '"ivars_total": 85',
        ],
    )
    require(
        ROOT / "tools/extract_item_mapping_functions.py",
        [
            "FUNCTIONS",
            "return_constant",
            "pairs_with_output",
        ],
    )
    require(
        NATIVE / "ITEM_MAPPINGS.md",
        [
            "seed item -> tree type",
            "324-330",
            "not decoded",
        ],
    )
    require(
        NATIVE / "item_mapping_functions.json",
        [
            '"pairs_decoded": 26',
            '"mapped_entries": 14',
        ],
    )
    require(
        ROOT / "tools/extract_item_predicates.py",
        [
            "ITEM_DOMAIN",
            "item_type_count",
            "predicates_naming_item_types",
        ],
    )
    require(
        NATIVE / "ITEM_PREDICATES.md",
        [
            "item attribute matrix",
            "no liquid item",
            "Boundary that matters",
        ],
    )
    require(
        NATIVE / "item_predicates.json",
        [
            '"distinct_item_types_named": 191',
            '"always-constant": 2',
        ],
    )
    require(
        ROOT / "tools/parse_craftable_item_struct.py",
        [
            "CraftableItem",
            "blob_length_from_savedict",
            "sizes_agree",
        ],
    )
    require(
        NATIVE / "CRAFTABLE_ITEM_STRUCT.md",
        [
            "layout from the type encoding",
            "measured twice in",
            "Field meanings",
        ],
    )
    require(
        NATIVE / "craftable_item_struct.json",
        [
            '"packed_size": 124',
            '"int_arrays": 3',
        ],
    )
    require(
        ROOT / "tools/histogram_save_tile_fields.py",
        [
            "blocks_records",
            "nonzero_offset8_states",
            "int16_windows",
        ],
    )
    require(
        NATIVE / "TILE_RECORD_SAVE_DATA.md",
        [
            "zero in every one of the 40,960 tiles",
            "cold-region tiles carrying",
            "One world",
        ],
    )
    require(
        NATIVE / "tile_record_save_data.json",
        [
            '"tiles": 40960',
            '"tiles_per_record": 1024',
        ],
    )
    require(
        ROOT / "tools/extract_tile_record_layout.py",
        [
            "WINDOWS",
            "FIELD_PATTERN",
            "STRIDE_SHIFT",
        ],
    )
    require(
        NATIVE / "TILE_RECORD_LAYOUT.md",
        [
            "candidate reading",
            "loses sync",
            "without a hex prefix",
        ],
    )
    require(
        NATIVE / "tile_record_layout.json",
        [
            '"record_stride": 64',
            '"tail_constant": 69',
        ],
    )
    require(
        ROOT / "tools/join_shared_body_constants.py",
        [
            "writes_to_case_slots",
            "direct_cases_writing_the_compared_slot",
            "--check",
        ],
    )
    require(
        NATIVE / "SHARED_BODY_CONSTANTS.md",
        [
            "Apple, Cherry, Maple",
            "61 / 61",
            "not \"all leaves\"",
        ],
    )
    require(
        NATIVE / "shared_body_constants.json",
        [
            '"constants_with_exactly_one_producer": 6',
            '"direct_cases_writing_the_compared_slot": 61',
        ],
    )
    require(
        ROOT / "tools/crosscheck_draw_value_domains.py",
        [
            "shared_body_vs_sprites",
            "constants_vs_direct_cases",
            "--check",
        ],
    )
    require(
        NATIVE / "DRAW_VALUE_DOMAINS.md",
        [
            "same kind of number",
            "6 / 6",
            "different sub-domain",
        ],
    )
    require(
        NATIVE / "draw_value_domains.json",
        [
            '"shared": 37',
            '"shared": 6',
        ],
    )
    require(
        ROOT / "tools/extract_tile_shared_body.py",
        [
            "decode_movw_imm",
            "register_comparisons",
            "0x00A22ED0",
        ],
    )
    require(
        NATIVE / "TILE_SHARED_BODY_STRUCTURE.md",
        [
            "is a real dispatch",
            "0x112",
            "64-byte stride",
            "branch bodies",
        ],
    )
    require(
        NATIVE / "tile_shared_body_structure.json",
        [
            '"jump_table_entries": 77',
            '"constants_compared": 6',
        ],
    )
    require(
        ROOT / "tools/resolve_tile_sprite_domain.py",
        [
            "itemTypeFromTileIsForegorund",
            "cross_check_mismatches",
            "contents-conditional",
        ],
    )
    require(
        NATIVE / "TILE_SPRITE_DOMAIN.md",
        [
            "tile-map-inline",
            "item-sprite-domain",
            "0** |",
        ],
    )
    require(
        NATIVE / "tile_sprite_domain.json",
        [
            '"tile_types": 77',
            '"cross_check_mismatches": 0',
            '"unresolved": 0',
        ],
    )
    require(
        ROOT / "tools/check_artifact_consumers.py",
        [
            "stale references",
            "LOOKALIKE",
            "artifact_columns",
        ],
    )
    require(
        ROOT / "tools/prepush_gate.py",
        [
            "the four checks that have to pass before a commit goes out",
            "changed_test_names",
            "--changed-only",
        ],
    )
    require(
        ROOT / "tools/run_contract_tests.py",
        [
            "per-test timeout",
            "bounded timeout per test",
            "ThreadPoolExecutor",
        ],
    )
    require(
        ROOT / "tools/lint_evidence_scan.py",
        [
            "no tool may recover a filename by regexing raw binary bytes",
            "BASENAME_RE",
            "violations",
        ],
    )
    require(
        ROOT / "tools/string_evidence.py",
        [
            "def nul_strings",
            "format-string",
            "suffix-composition",
            "def classify",
        ],
    )
    require(
        ROOT / "tools/audit_audio_assets.py",
        [
            "AUDIO_SUFFIXES",
            "from string_evidence import classify, contains_token, nul_strings",
            "def sweep_sources",
        ],
    )
    require(
        NATIVE / "AUDIO_ASSET_COVERAGE.md",
        [
            "original_named_not_in_replacement",
            "OBJC_IVAR_$_KelpPlant.waveTimer",
            "bird%d.wav",
            "whole-APK sweep",
            "136",
        ],
    )
    require(
        NATIVE / "audio_asset_coverage.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"ships": 161',
            '"original_format_string": 14',
            '"original_unattributed": 9',
        ],
    )
    require(
        ROOT / "tools/extract_original_tile_content_render_map.py",
        [
            "TABLE_VA = 0x00A221F4",
            "SHARED_BODY_VA = 0x00A22D70",
            "shared-body",
            "--check",
        ],
    )
    require(
        NATIVE / "tile_content_render_map.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"direct": 61',
            '"shared-body": 59',
            '"delegated-dispatch": 1',
        ],
    )
    require(
        NATIVE / "original_tile_content_render_map.tsv",
        [
            "content_value\tcandidate_name\tdraw_image\tdraw_col\tdraw_row",
            "17\t\t\t\t\t\t\t\tshared-body\t0x00a22d70",
            "46\t\t\t\t\t\t\t\tdelegated-dispatch\t0x00a22b90",
        ],
    )
    require(
        ROOT / "tools/extract_original_item_sprite_map.py",
        [
            "FUNCTION_VA = 0x004D6040",
            "POOL_F64",
            "POOL_F32",
            "--check",
        ],
    )
    require(
        NATIVE / "ITEM_SPRITE_COORDS.md",
        [
            "texCoordsForItemType",
            "0x004d6040",
            "col = type % 32",
            "126/2048",
            "62/2048",
        ],
    )
    require(
        NATIVE / "item_sprite_map.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"formula": 344',
            '"jump_table": 82',
            '"unresolved": 0',
        ],
    )
    require(
        NATIVE / "original_item_sprite_map.tsv",
        [
            "item_type\tatlas\timage\tcol\trow\tu\tv\tu_span\tv_span\tsource",
            "1105\t746\t746\t10\t23",
        ],
    )
    require(
        NATIVE / "WORLD_TIME_DOMAIN.md",
        [
            "getDayNightFractionForX:atWorldTime:",
            "0x00582ad8",
            "900.0",
            "6.283185307179586",
            "worldTime - saveTime > 1800.0",
            "never record a rate without recording the flag",
        ],
    )
    require(
        ROOT / "tools/test_gen_sound_preload_list.py",
        [
            "REFUSING",
            "Membership only",
            "a hand-edited generated header must fail --check",
        ],
    )
    require(
        ROOT / "tools/gen_sound_preload_list.py",
        [
            "REFUSING",
            "check ok: {meta['count']} load-time sounds, all with sha256",
            "shipped flag and asset sha256",
        ],
    )
    require(
        ROOT / "app/src/main/cpp/sound_preload_registry.h",
        [
            "Replacement-side consumer of the GENERATED load-time sound list",
            "NOT part of reconstruction/recovered/",
            "std::size_t pendingWiring() const",
        ],
    )
    require(
        ROOT / "tools/test_sound_preload_registry.py",
        [
            "must bind to kOriginalLoadTimeSoundCount",
            "hard-coded count",
        ],
    )
    require(
        ROOT / "tools/test_sound_preload_registry.cpp",
        [
            "26 of the 32 are still unreferenced",
            "registration is idempotent",
        ],
    )
    require(
        ROOT / "tools/test_sound_preload_list.cpp",
        [
            "26 remain to wire",
            "known load-time names must survive regeneration",
        ],
    )
    require(
        ROOT / "reconstruction/recovered/sound_preload_list.h",
        [
            "GENERATED by tools/gen_sound_preload_list.py",
            "kOriginalLoadTimeSoundCount = 32",
            "yak2.wav",
            "Membership only",
        ],
    )
    require(
        ROOT / "reconstruction/recovered/CMakeLists.txt",
        [
            "test_sound_preload_list",
        ],
    )
    require(
        NATIVE / "AUDIO_WIRING_MAP.md",
        [
            "Audio wiring map: every shipped sound",
            "PIC_BASE",
            "blockheadDie.wav",
            "wiring backlog",
        ],
    )
    require(
        NATIVE / "audio_wiring_map.json",
        [
            '"mapped": 136',
            '"status"',
            '"self_check"',
            "blockheadDie.wav",
        ],
    )
    require(
        ROOT / "tools/test_extract_audio_wiring_map.py",
        [
            "the wrap",
            "SELF_CHECK",
            "wrapped negative offset",
        ],
    )
    require(
        ROOT / "tools/check_workflow_yaml.py",
        [
            "does not parse",
            "has neither run nor uses",
            "workflow yaml:",
        ],
    )
    require(
        ROOT / "tools/test_check_workflow_yaml.py",
        [
            "BROKEN_INDENT",
            "the defect that actually shipped",
        ],
    )
    require(
        ROOT / "tools/extract_audio_wiring_map.py",
        [
            "SELF_CHECK",
            "no_cfstring",
            "PIC_BASE",
        ],
    )
    require(
        NATIVE / "TRACE_RECEIVER_SENSITIVITY.md",
        [
            "Both are inventions",
            "conditional on that fabrication",
            "it is evidence rather than a choice",
        ],
    )
    require(
        NATIVE / "FRAME_LOOP_PROTOCOL.md",
        [
            "one uniform protocol, not a set of lookalikes",
            "never REACHED a send",
            "needs a better receiver than a zeroed page",
        ],
    )
    require(
        NATIVE / "CLOCK_FIELD_WRITE_WATCH.md",
        [
            "the write lives in a callee",
            "Zero, with the indirection hole closed",
        ],
    )
    require(
        NATIVE / "IVAR_ACCESS_CLASSIFIER_FIX.md",
        [
            "tool gap that reads as an",
            "left the world-clock conclusion alone",
        ],
    )
    require(
        NATIVE / "DYNAMICOBJECT_FLAGS.md",
        [
            "the network-sync trigger is a one-byte flag",
            "exactly where a dirty bit belongs",
        ],
    )
    require(
        NATIVE / "MSG_SEND_TRACE.md",
        [
            "The gate the trace's loop kept calling",
            "one-byte ivar on the",
        ],
    )
    require(
        NATIVE / "MSG_SEND_TRACE.md",
        [
            "Executed, with a fabricated receiver and stubbed sends",
            "a send of the method's own selector",
            "This produces structure, not semantics",
        ],
    )
    require(
        NATIVE / "WORLD_METHOD_EXECUTION_CLASSIFICATION.md",
        [
            "it is a statement about",
            "Every decision in this class is in the",
        ],
    )
    require(
        NATIVE / "STRUCT_GETTER_EMULATION.md",
        [
            "does not take self in r0",
            "A control that cannot exist is not evidence of a bug",
            "the symbol cross-check is *unavailable*",
        ],
    )
    require(
        NATIVE / "CLOCK_DOMAIN_LAYOUT.md",
        [
            "so this table cannot drift into a",
            "which is a layout hint the two independent derivations agree on",
            "a window tuned to one getter is a guess",
        ],
    )
    require(
        NATIVE / "FLOAT_GETTER_EMULATION.md",
        [
            "three abstraction classes, and they are not the same abstraction",
            "rejects the `vldr` outright",
            "UC_ARM_REG_R0 == 66",
        ],
    )
    require(
        NATIVE / "WORLD_METHOD_EXECUTION_CLASSIFICATION.md",
        [
            "can be executed under Unicorn",
            "runs as-is with a fabricated receiver",
            "declared live-only",
        ],
    )
    require(
        NATIVE / "world_method_classification.json",
        [
            '"verdict"',
            '"ruled"'.replace('"ruled"', '"rule"'),
            '"unicorn-clean"',
        ],
    )
    require(
        NATIVE / "live_craftable_records.json",
        [
            '"worldTime_per_wall_second"',
            '"classlist_cross_check_agrees"',
            'open discrepancy',
            '"instance_identification_negative"',
            '"static_scan_vs_live_contradiction"',
        ],
    )
    require(
        NATIVE / "struct_census.json",
        [
            '"distinct_structs"',
            '"the net-data family shares one 24-byte header',
        ],
    )
    require(
        NATIVE / "record_build_watch.json",
        [
            '"why_this_is_different"',
            '"interpretation"',
            '"agreements_with_the_static_reading"',
            '"receiver_sensitivity"',
        ],
    )
    require(
        NATIVE / "record_base_tracking_status.json",
        [
            '"rule_sensitivity"',
            '"false_negative"',
            '"false_positive_risk"',
            '"verified_by_hand_elsewhere"',
            '"status_of_the_sealed_condition"',
        ],
    )
    require(
        NATIVE / "WORLDTIME_GETTER_EMULATION.md",
        [
            "executed under Unicorn",
            "UC_ERR_INSN_INVALID",
            "0xFF` | **-1**",
            "runs with no abstraction at all",
            "corrects an earlier claim",
            "returned 42.25",
            "lazy",
        ],
    )
    require(
        NATIVE / "worldtime_getter_emulation.json",
        [
            '"getter_imp": "0x5d99a4"',
            '"passed": true',
            '"equals_value_at_self_plus_cell": true',
        ],
    )
    require(
        ROOT / "tools/emulate_worldtime_getter.py",
        [
            "decoy",
            "lazy trampoline",
        ],
    )
    require(
        NATIVE / "CRAFTABLE_ITEM_BLOB_BOUNDARY.md",
        [
            "CraftableItem blob: proved, and sealed",
            "0xac7a18",
            "passed by value",
            "An empty result covers only the channel that was",
        ],
    )
    require(
        NATIVE / "craftable_item_blob_boundary.json",
        [
            '"struct_is_passed_by_value"',
            '"0xac7ccc',
            '"condition_needed"',
        ],
    )
    require(
        NATIVE / "WORLD_CLOCK_WRITER_BOUNDARY.md",
        [
            "The world-clock writer boundary",
            "Eight mechanisms excluded",
            "0x1c27c0",
            "a name match is not an attribution",
        ],
    )
    require(
        NATIVE / "world_clock_writer_boundary.json",
        [
            '"verdict": "premise holds - the readings are valid"',
            '"mechanism": "a bulk copy into the object (memcpy-family)"',
            "ZERO in World-family methods",
        ],
    )
    require(
        NATIVE / "IVAR_CELL_REFERENCES.md",
        [
            "Every ivar offset cell and who touches it",
            "ITS FILE CONTENTS ARE THE CELL VA",
            "0x105c754",
            "three references, all reads",
            "Do not run the tool without",
            "240 instructions back",
        ],
    )
    require(
        NATIVE / "ivar_cell_references.json",
        [
            '"ivars_with_references": 2003',
            '"sites": 7193',
            '"World.fastForward"',
            '"conclusion"',
        ],
    )
    require(
        ROOT / "tools/extract_ivar_cell_references.py",
        [
            "--self-check",
            "self_check",
            "method_entries_in_range",
        ],
    )
    require(
        ROOT / "tools/test_extract_ivar_cell_references.py",
        [
            "fixture must reproduce the PIC base",
            "the old rd-pinning mask would miss rd=2",
        ],
    )
    require(
        NATIVE / "world_time_domain.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "getDayNightFractionForX:atWorldTime:",
            '"seconds_per_day_divisor"',
            "900.0",
            '"rate_qualifier"',
            '"units_per_real_second": 20.0',
        ],
    )
    require(
        NATIVE / "LIVE_WORLD_CLOCK.md",
        [
            "runs 20 units per real second",
            "a 900-unit day lasts",
            "0x008cdc6c",
            "20.00012",
            "What sets the flag is not located",
        ],
    )
    require(
        NATIVE / "live_world_clock.json",
        [
            '"d09418e9c0865902054a71358dcff3264d47f7b24ede58667cb5ea0e6f269b96"',
            '"build_binding": "ok"',
            '"fastForward_states_seen": [\n   1\n  ]',
            '"fastForward_test_at": "0x008cdc58"',
            '"worldTime": 648',
        ],
    )
    require(
        ROOT / "tools/probe_live_world_clock.py",
        [
            "BUILD MISMATCH",
            "derive_save_dir",
            "find_pid",
            "def decode_ivar_list",
        ],
    )
    require(
        ROOT / "tools/test_probe_live_world_clock.py",
        [
            "decode_ivar_list",
            "degenerate header accepted",
            "unterminated cstring accepted",
        ],
    )
    require(
        ROOT / "tools/extract_world_time_domain.py",
        [
            '"rate_qualifier"',
            "is state-dependent and must be recorded",
        ],
    )
    require(
        NATIVE / "GAMEVIEW_TOUCH_CALLBACKS.md",
        [
            "| endTouch: | 0x0092c3f4..0x0092c638 | 145 | 4 |",
            "| endSecondaryTouch: | 0x0092cdd8..0x0092cfa0 | 113 | 4 |",
            "| cancelSecondaryTouch: | 0x0092cfa0..0x0092d188 | 122 | 3 |",
        ],
    )
    require(
        ROOT / "tools/recover_pickup_dataflow.py",
        [
            "inventory_pickup_dataflow.json",
            "callsite_dataflow",
            "--check",
        ],
    )
    require(
        NATIVE / "inventory_pickup_dataflow.json",
        [
            '"schema": 2',
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"reachable_instructions": 578',
            '"0xc61dd0"',
        ],
    )
    tile_item_map = NATIVE / "original_tile_item_map.tsv"
    tile_item_lines = tile_item_map.read_text(encoding="utf-8").splitlines()
    if len(tile_item_lines) != 78:
        raise SystemExit(f"original TileType map count changed: {len(tile_item_lines) - 1}")
    require(
        tile_item_map,
        [
            "foreground_arg\ttile_type\tresolution\titem_type\timage_dataA0",
            "0\t4\tdirect\t1060\t110\t14\t3\t0x00a18d7c",
            "0\t9\tdirect\t1049\t196\t4\t6\t0x00a18d04",
            "0\t53\tdirect\t1066\t112\t16\t3\t0x00a18cc8",
            "0\t77\tdirect\t1105\t746\t10\t23\t0x00a18c44",
            "0\t2\tconditional",
        ],
    )
    require(
        ROOT / "tools/extract_original_tile_conditional.py",
        [
            "DEFAULT_PATH = 0x00A18DAC",
            "CONTENTS_OFFSET = 3",
            "helper-gated",
            "OriginalTile.contentsType()",
        ],
    )
    require(
        ROOT / "tools/gen_tile_conditional_table.py",
        [
            "original_tile_conditional.json",
            "kConditionalTileSteps",
            "KIND",
        ],
    )
    conditional_tsv = NATIVE / "original_tile_conditional.tsv"
    require(
        conditional_tsv,
        [
            # header must stay aligned with the 8-value rows (the old header
            # declared a `depends_on` column that was never emitted)
            "tile_type\tresolution\tcontents_type\titem_type\thelper\tcase_target\tstep_index\tstatus",
            "1\tcontents\t61\t31\t\t0x00a18b04\t0\tresolved",
            "2\thelper\t\t1049\t0x00a11390\t0x00a187c0\t7\tresolved",
            "6\tcontents\t\t1048\t\t0x00a18a98\t2\tfallback-value",
            "12\tcontents\t\t1028\t\t0x00a18c10\t1\tfallback-value",
        ],
    )
    conditional_lines = conditional_tsv.read_text(encoding="utf-8").splitlines()
    conditional_tiles = sorted({int(line.split("\t")[0]) for line in conditional_lines[1:]})
    map_conditional = sorted(
        int(row.split("\t")[1]) for row in tile_item_lines[1:] if "\tconditional" in row
    )
    if conditional_tiles != map_conditional:
        raise SystemExit(
            "conditional TileType sets disagree: "
            f"resolved {conditional_tiles} vs map {map_conditional}"
        )
    require(
        ROOT / "app/src/main/cpp/original_tile_conditional_table.inc",
        [
            "Generated by tools/gen_tile_conditional_table.py",
            "struct ConditionalTileStep",
            '{2, 96, 0, 178, "0x00a187c0"}',
            "// 0x00a11390",
        ],
    )
    require(
        NATIVE / "ORIGINAL_TILE_CONDITIONAL.md",
        [
            "itemTypeFromTileIsForegorund",
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            "OriginalTile.contentsType()",
            "helper-gated",
        ],
    )
    require(
        ROOT / "tools/extract_original_tile_contents_image_map.py",
        [
            "FUNCTION_VA = 0x00A13E6C",
            "FUNCTION_SIZE = 640",
            "CONTENTS_TABLE_VA = 0x00A13F10",
            "FALLBACK_TABLE_VA = 0x00A14090",
            "direct_image",
        ],
    )
    contents_map = NATIVE / "original_tile_contents_image_map.tsv"
    contents_lines = contents_map.read_text(encoding="utf-8").splitlines()
    if len(contents_lines) != 31:
        raise SystemExit(f"original Tile contents image map count changed: {len(contents_lines) - 1}")
    require(
        contents_map,
        [
            "tile_offset\ttile_value\timage_index\tcol\trow\tcase_target",
            "3\t96\t112\t16\t3\t0x00a140b4",
            "3\t103\t116\t20\t3\t0x00a140c8",
            "11\t67\t239\t15\t7\t0x00a13fa0",
            "11\t124\t446\t30\t13\t0x00a1403c",
            "11\t148\t762\t26\t23\t0x00a13fe8",
        ],
    )
    require(
        ROOT / "tools/extract_original_reload_drawblock_map.py",
        [
            "METHOD_VA = 0x00A1D730",
            "TABLE_VA = 0x00A20EF0",
            "LAST_TILE_TYPE = 77",
            "constant_slot_prefix",
        ],
    )
    drawblock_map = NATIVE / "original_reload_drawblock_map.tsv"
    drawblock_lines = drawblock_map.read_text(encoding="utf-8").splitlines()
    if len(drawblock_lines) != 78:
        raise SystemExit(f"original reloadDrawBlock map count changed: {len(drawblock_lines) - 1}")
    require(
        drawblock_map,
        [
            "tile_type\tresolution\tprimary_image\tprimary_col\tprimary_row",
            "4\tdirect\t110\t14\t3",
            "7\tdirect\t65\t1\t2",
            "9\tdirect\t196\t4\t6",
            "49\tdirect\t98\t2\t3",
            "57\tdirect\t116\t20\t3",
            "77\tdirect\t746\t10\t23",
        ],
    )
    require(
        ROOT / "tools/extract_original_tile_content_render_map.py",
        [
            "TABLE_VA = 0x00A221F4",
            "FIRST_CONTENT = 3",
            "LAST_CONTENT = 123",
            "DRAW_SLOT = 1344",
            "c9bc7eea11ecdefa7de47000bfe70b14be374f3c",
        ],
    )
    content_render_map = NATIVE / "original_tile_content_render_map.tsv"
    content_render_lines = content_render_map.read_text(encoding="utf-8").splitlines()
    # The domain is closed to every value in [3, 123]: 121 rows + the header.
    # The count moved from 62 (direct assignments only) when the map gained
    # explicit shared-body/unresolved rows; a silent change is still an error.
    if len(content_render_lines) != 122:
        raise SystemExit(
            f"original Tile content render map count changed: {len(content_render_lines) - 1}"
        )
    require(
        content_render_map,
        [
            "content_value\tcandidate_name\tdraw_image\tdraw_col\tdraw_row",
            "3\tAppleTreeLeaf\t256\t0\t8",
            "6\tPineTreeLeaf\t237\t13\t7",
            "7\tPineTreeTrunk\t192\t0\t6\t193\t1\t6",
            "43\tCactus\t234\t10\t7",
            "110\tAmethystTreeLeaf\t570\t26\t17",
            "123\tDiamondTreeTrunkLeaf\t606\t30\t18",
        ],
    )

    require(
        NATIVE / "WORLD_INPUT.md",
        [
            "7282",
            "6150",
            "makeIntpair",
            "GLKMathUnproject",
            "linearInterpolate",
            "panBlockingUIDisplayed",
        ],
    )
    require(
        NATIVE / "world_input.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 6150',
            '"verified_words": 309',
            "tap:",
            "OBJC_IVAR_$_World.touchStartTranslation",
        ],
    )
    for _wi_file, _wi_imp, _wi_end in (
        ("disasm_worldtileloader_wi_00.txt", "implementation: 0x005ac3a0", "ARM.exidx end: 0x005b23b8"),
        ("disasm_worldtileloader_wi_01.txt", "implementation: 0x00552e28", "ARM.exidx end: 0x00552ec0"),
        ("disasm_worldtileloader_wi_02.txt", "implementation: 0x00552ec0", "ARM.exidx end: 0x005531d0"),
        ("disasm_worldtileloader_wi_03.txt", "implementation: 0x005531d0", "ARM.exidx end: 0x005536a4"),
        ("disasm_worldtileloader_wi_04.txt", "implementation: 0x005536a4", "ARM.exidx end: 0x005536ec"),
        ("disasm_worldtileloader_wi_05.txt", "implementation: 0x005b30c8", "ARM.exidx end: 0x005b31b8"),
        ("disasm_worldtileloader_wi_06.txt", "implementation: 0x005b3278", "ARM.exidx end: 0x005b3308"),
        ("disasm_worldtileloader_wi_07.txt", "implementation: 0x005b3308", "ARM.exidx end: 0x005b33ac"),
        ("disasm_worldtileloader_wi_08.txt", "implementation: 0x005b33ac", "ARM.exidx end: 0x005b34b4"),
        ("disasm_worldtileloader_wi_09.txt", "implementation: 0x005b3430", "ARM.exidx end: 0x005b34b4"),
        ("disasm_worldtileloader_wi_10.txt", "implementation: 0x005b34b4", "ARM.exidx end: 0x005b3540"),
        ("disasm_worldtileloader_wi_11.txt", "implementation: 0x005bf968", "ARM.exidx end: 0x005bf9f8"),
        ("disasm_worldtileloader_wi_12.txt", "implementation: 0x005bf9f8", "ARM.exidx end: 0x005bfb5c"),
        ("disasm_worldtileloader_wi_13.txt", "implementation: 0x005bf880", "ARM.exidx end: 0x005bf968"),
        ("disasm_worldtileloader_wi_14.txt", "implementation: 0x005bfb5c", "ARM.exidx end: 0x005bfc14"),
        ("disasm_worldtileloader_wi_15.txt", "implementation: 0x005bfc14", "ARM.exidx end: 0x005bfcb0"),
        ("disasm_worldtileloader_wi_16.txt", "implementation: 0x005b3540", "ARM.exidx end: 0x005b3644"),
    ):
        require(NATIVE / _wi_file, [_wi_imp, _wi_end])


    require(
        NATIVE / "WORLD_CRAFT.md",
        [
            "5444",
            "1583",
            "1218",
            "0xc350",
            "CrystalManager",
            "showUIForTappedWorkbench",
        ],
    )
    require(
        NATIVE / "world_craft.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1583',
            '"verified_words": 1218',
            "warpInBlockhead:",
            "OBJC_IVAR_$_World.unableToCraftBlockheadDueToWaitingForServer",
        ],
    )
    for _wc_file, _wc_imp, _wc_end in (
        ("disasm_worldtileloader_cb_00.txt", "implementation: 0x005bbdd0", "ARM.exidx end: 0x005bd68c"),
        ("disasm_worldtileloader_cb_01.txt", "implementation: 0x005b6fa8", "ARM.exidx end: 0x005b82b0"),
        ("disasm_worldtileloader_cb_02.txt", "implementation: 0x005b88f8", "ARM.exidx end: 0x005b902c"),
        ("disasm_worldtileloader_cb_03.txt", "implementation: 0x005b83d0", "ARM.exidx end: 0x005b88f8"),
        ("disasm_worldtileloader_cb_04.txt", "implementation: 0x005b82b0", "ARM.exidx end: 0x005b83d0"),
        ("disasm_worldtileloader_cb_05.txt", "implementation: 0x005bb634", "ARM.exidx end: 0x005bbdd0"),
        ("disasm_worldtileloader_cb_06.txt", "implementation: 0x005b9368", "ARM.exidx end: 0x005b9e10"),
        ("disasm_worldtileloader_cb_07.txt", "implementation: 0x005bd68c", "ARM.exidx end: 0x005bdb14"),
        ("disasm_worldtileloader_cb_08.txt", "implementation: 0x005bdb14", "ARM.exidx end: 0x005bdd70"),
        ("disasm_worldtileloader_cb_09.txt", "implementation: 0x005b90c0", "ARM.exidx end: 0x005b9368"),
    ):
        require(NATIVE / _wc_file, [_wc_imp, _wc_end])


    require(
        NATIVE / "WORLD_LOAD.md",
        [
            "3266",
            "1428",
            "540",
            "SFHFKeychainUtils",
            "globalPrices",
            "checkIfMacroTileCanBeDecommissioned",
        ],
    )
    require(
        NATIVE / "world_load.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1428',
            '"verified_words": 540',
            '"verified_words": 627',
            "initWithWindowInfo:",
            "OBJC_IVAR_$_World.incrementalLoadCount",
        ],
    )
    for _wl_file, _wl_imp, _wl_end in (
        ("disasm_worldtileloader_wl_00.txt", "implementation: 0x00563604", "ARM.exidx end: 0x00564c54"),
        ("disasm_worldtileloader_wl_01.txt", "implementation: 0x005b59f8", "ARM.exidx end: 0x005b5b54"),
        ("disasm_worldtileloader_wl_02.txt", "implementation: 0x005ccc88", "ARM.exidx end: 0x005cd4f8"),
        ("disasm_worldtileloader_wl_03.txt", "implementation: 0x005cc994", "ARM.exidx end: 0x005ccc88"),
        ("disasm_worldtileloader_wl_04.txt", "implementation: 0x005cc864", "ARM.exidx end: 0x005cc994"),
        ("disasm_worldtileloader_wl_05.txt", "implementation: 0x005cc73c", "ARM.exidx end: 0x005cc994"),
        ("disasm_worldtileloader_wl_06.txt", "implementation: 0x005d0d2c", "ARM.exidx end: 0x005d0e54"),
        ("disasm_worldtileloader_wl_07.txt", "implementation: 0x005d3158", "ARM.exidx end: 0x005d3248"),
        ("disasm_worldtileloader_wl_08.txt", "implementation: 0x005c6ef8", "ARM.exidx end: 0x005c78c4"),
        ("disasm_worldtileloader_wl_09.txt", "implementation: 0x005d9ca4", "ARM.exidx end: 0x005d9ce0"),
        ("disasm_worldtileloader_wl_10.txt", "implementation: 0x005d8d3c", "ARM.exidx end: 0x005d8da4"),
        ("disasm_worldtileloader_wl_11.txt", "implementation: 0x005d8da4", "ARM.exidx end: 0x005d8e58"),
        ("disasm_worldtileloader_wl_12.txt", "implementation: 0x005d97c0", "ARM.exidx end: 0x005d9824"),
    ):
        require(NATIVE / _wl_file, [_wl_imp, _wl_end])


    require(
        NATIVE / "WORLD_ZOOM.md",
        [
            "2503",
            "627",
            "583",
            "zoomToPos:pinchZoom:",
            "tileIsLitForClient",
            "calibrationMatrix",
        ],
    )
    require(
        NATIVE / "world_zoom.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 627',
            '"verified_words": 583',
            "zoomToActiveNetBlockheadForPlayer:",
            "OBJC_IVAR_$_World.calibrationMatrix",
        ],
    )
    for _wz_file, _wz_imp, _wz_end in (
        ("disasm_worldtileloader_wz_00.txt", "implementation: 0x005c4c28", "ARM.exidx end: 0x005c55f4"),
        ("disasm_worldtileloader_wz_01.txt", "implementation: 0x005c55f4", "ARM.exidx end: 0x005c5c0c"),
        ("disasm_worldtileloader_wz_02.txt", "implementation: 0x005c8e98", "ARM.exidx end: 0x005c937c"),
        ("disasm_worldtileloader_wz_03.txt", "implementation: 0x005c5c0c", "ARM.exidx end: 0x005c5ce0"),
        ("disasm_worldtileloader_wz_04.txt", "implementation: 0x005c60ac", "ARM.exidx end: 0x005c61d4"),
        ("disasm_worldtileloader_wz_05.txt", "implementation: 0x005be998", "ARM.exidx end: 0x005bf2b4"),
        ("disasm_worldtileloader_wz_06.txt", "implementation: 0x005bf528", "ARM.exidx end: 0x005bf738"),
        ("disasm_worldtileloader_wz_07.txt", "implementation: 0x005bf738", "ARM.exidx end: 0x005bf880"),
        ("disasm_worldtileloader_wz_08.txt", "implementation: 0x005be378", "ARM.exidx end: 0x005be75c"),
    ):
        require(NATIVE / _wz_file, [_wz_imp, _wz_end])


    require(
        NATIVE / "WORLD_TRADE.md",
        [
            "2219",
            "707",
            "453",
            "NSPropertyListSerialization",
            "unsentGlobalTradeTransactions",
            "checkIfCanWarpInSecondBlockhead",
        ],
    )
    require(
        NATIVE / "world_trade.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 707',
            '"verified_words": 453',
            "updateTradePricesIfNeeded",
            "OBJC_IVAR_$_World.unsentGlobalTradeTransactions",
        ],
    )
    for _wt_file, _wt_imp, _wt_end in (
        ("disasm_worldtileloader_wt_00.txt", "implementation: 0x005cbc30", "ARM.exidx end: 0x005cc73c"),
        ("disasm_worldtileloader_wt_01.txt", "implementation: 0x005cd6a8", "ARM.exidx end: 0x005cddbc"),
        ("disasm_worldtileloader_wt_02.txt", "implementation: 0x005ce260", "ARM.exidx end: 0x005ce918"),
        ("disasm_worldtileloader_wt_03.txt", "implementation: 0x005c44a0", "ARM.exidx end: 0x005c47b8"),
        ("disasm_worldtileloader_wt_04.txt", "implementation: 0x005ceb18", "ARM.exidx end: 0x005cedac"),
        ("disasm_worldtileloader_wt_05.txt", "implementation: 0x005c4228", "ARM.exidx end: 0x005c44a0"),
        ("disasm_worldtileloader_wt_06.txt", "implementation: 0x005d32ac", "ARM.exidx end: 0x005d3348"),
        ("disasm_worldtileloader_wt_07.txt", "implementation: 0x005c2858", "ARM.exidx end: 0x005c28e4"),
        ("disasm_worldtileloader_wt_08.txt", "implementation: 0x005da150", "ARM.exidx end: 0x005da194"),
        ("disasm_worldtileloader_wt_09.txt", "implementation: 0x005da10c", "ARM.exidx end: 0x005da194"),
    ):
        require(NATIVE / _wt_file, [_wt_imp, _wt_end])


    require(
        NATIVE / "WORLD_ADMIN.md",
        [
            "2575",
            "440",
            "353",
            "customRulesChanged",
            "BlockAlertView",
            "mutedPlayers",
        ],
    )
    require(
        NATIVE / "world_admin.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 440',
            '"verified_words": 353',
            "verifyClientCustomRulesData:",
            "OBJC_IVAR_$_World.mutedPlayers",
        ],
    )
    for _wa_file, _wa_imp, _wa_end in (
        ("disasm_worldtileloader_wa_00.txt", "implementation: 0x005d70b4", "ARM.exidx end: 0x005d7794"),
        ("disasm_worldtileloader_wa_01.txt", "implementation: 0x005d5b10", "ARM.exidx end: 0x005d5f80"),
        ("disasm_worldtileloader_wa_02.txt", "implementation: 0x005d5710", "ARM.exidx end: 0x005d5b10"),
        ("disasm_worldtileloader_wa_03.txt", "implementation: 0x005d0410", "ARM.exidx end: 0x005d08cc"),
        ("disasm_worldtileloader_wa_04.txt", "implementation: 0x005cfea4", "ARM.exidx end: 0x005d012c"),
        ("disasm_worldtileloader_wa_05.txt", "implementation: 0x005cfa88", "ARM.exidx end: 0x005cfe00"),
        ("disasm_worldtileloader_wa_06.txt", "implementation: 0x005d0e54", "ARM.exidx end: 0x005d13d8"),
        ("disasm_worldtileloader_wa_07.txt", "implementation: 0x005d218c", "ARM.exidx end: 0x005d2548"),
        ("disasm_worldtileloader_wa_08.txt", "implementation: 0x005d1aa4", "ARM.exidx end: 0x005d1f94"),
    ):
        require(NATIVE / _wa_file, [_wa_imp, _wa_end])


    require(
        NATIVE / "WORLD_UI.md",
        [
            "2645",
            "764",
            "517",
            "showTimeCrystalUITapped",
            "ownershipSignPositions",
            "SKPaymentQueue",
        ],
    )
    require(
        NATIVE / "world_ui.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 764',
            '"verified_words": 517',
            "timeCrystalButtonTapped",
            "OBJC_IVAR_$_World.repairMode",
        ],
    )
    for _wu_file, _wu_imp, _wu_end in (
        ("disasm_worldtileloader_wu_00.txt", "implementation: 0x005b5b54", "ARM.exidx end: 0x005b6368"),
        ("disasm_worldtileloader_wu_01.txt", "implementation: 0x005d8f78", "ARM.exidx end: 0x005d971c"),
        ("disasm_worldtileloader_wu_02.txt", "implementation: 0x005d4718", "ARM.exidx end: 0x005d5308"),
        ("disasm_worldtileloader_wu_03.txt", "implementation: 0x005c6898", "ARM.exidx end: 0x005c6eb0"),
        ("disasm_worldtileloader_wu_04.txt", "implementation: 0x005bde9c", "ARM.exidx end: 0x005be2cc"),
        ("disasm_worldtileloader_wu_05.txt", "implementation: 0x005c28e4", "ARM.exidx end: 0x005c29a8"),
        ("disasm_worldtileloader_wu_06.txt", "implementation: 0x005d5308", "ARM.exidx end: 0x005d53b0"),
        ("disasm_worldtileloader_wu_07.txt", "implementation: 0x005d971c", "ARM.exidx end: 0x005d9784"),
        ("disasm_worldtileloader_wu_08.txt", "implementation: 0x005d790c", "ARM.exidx end: 0x005d79c8"),
        ("disasm_worldtileloader_wu_09.txt", "implementation: 0x005ac350", "ARM.exidx end: 0x005ac3a0"),
        ("disasm_worldtileloader_wu_10.txt", "implementation: 0x005d3260", "ARM.exidx end: 0x005d32ac"),
        ("disasm_worldtileloader_wu_11.txt", "implementation: 0x005d9e8c", "ARM.exidx end: 0x005d9ec8"),
        ("disasm_worldtileloader_wu_12.txt", "implementation: 0x005d9784", "ARM.exidx end: 0x005d97c0"),
        ("disasm_worldtileloader_wu_13.txt", "implementation: 0x005d3248", "ARM.exidx end: 0x005d3260"),
    ):
        require(NATIVE / _wu_file, [_wu_imp, _wu_end])


    require(
        NATIVE / "WORLD_OWN.md",
        [
            "1542",
            "527",
            "373",
            "ownershipSignPositions",
            "OwnershipAreaRenderer",
            "loadLightBlockForClientLightBlockIndex",
        ],
    )
    require(
        NATIVE / "world_own.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 527',
            '"verified_words": 373',
            "ownershipSignWasPlacedOrChangedAtPos:",
            "OBJC_IVAR_$_World.ownershipSignPositions",
        ],
    )
    for _wo_file, _wo_imp, _wo_end in (
        ("disasm_worldtileloader_wo_00.txt", "implementation: 0x005d35cc", "ARM.exidx end: 0x005d3e08"),
        ("disasm_worldtileloader_wo_01.txt", "implementation: 0x005d4144", "ARM.exidx end: 0x005d4718"),
        ("disasm_worldtileloader_wo_02.txt", "implementation: 0x005d3e08", "ARM.exidx end: 0x005d4144"),
        ("disasm_worldtileloader_wo_03.txt", "implementation: 0x005d53b0", "ARM.exidx end: 0x005d5534"),
        ("disasm_worldtileloader_wo_04.txt", "implementation: 0x005d3538", "ARM.exidx end: 0x005d35cc"),
        ("disasm_worldtileloader_wo_05.txt", "implementation: 0x005daa14", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wo_06.txt", "implementation: 0x005c88b0", "ARM.exidx end: 0x005c8d28"),
    ):
        require(NATIVE / _wo_file, [_wo_imp, _wo_end])


    require(
        NATIVE / "WORLD_PVP.md",
        [
            "1782",
            "321",
            "305",
            "sufferDamage:isSimulation:recoil:",
            "TipManager",
            "projectileManager",
        ],
    )
    require(
        NATIVE / "world_pvp.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 321',
            '"verified_words": 305',
            "remoteBlockheadDamageRequest:",
            "OBJC_IVAR_$_World.projectileManager",
        ],
    )
    for _wp_file, _wp_imp, _wp_end in (
        ("disasm_worldtileloader_wp_00.txt", "implementation: 0x005c9b54", "ARM.exidx end: 0x005ca058"),
        ("disasm_worldtileloader_wp_01.txt", "implementation: 0x005cb08c", "ARM.exidx end: 0x005cb550"),
        ("disasm_worldtileloader_wp_02.txt", "implementation: 0x005cb550", "ARM.exidx end: 0x005cb930"),
        ("disasm_worldtileloader_wp_03.txt", "implementation: 0x005c97dc", "ARM.exidx end: 0x005c9b54"),
        ("disasm_worldtileloader_wp_04.txt", "implementation: 0x005c937c", "ARM.exidx end: 0x005c96f0"),
        ("disasm_worldtileloader_wp_05.txt", "implementation: 0x005cba90", "ARM.exidx end: 0x005cbc30"),
        ("disasm_worldtileloader_wp_06.txt", "implementation: 0x005cb930", "ARM.exidx end: 0x005cba90"),
        ("disasm_worldtileloader_wp_07.txt", "implementation: 0x005c96f0", "ARM.exidx end: 0x005c97dc"),
        ("disasm_worldtileloader_wp_08.txt", "implementation: 0x005c19b4", "ARM.exidx end: 0x005c1b58"),
        ("disasm_worldtileloader_wp_09.txt", "implementation: 0x005c1b58", "ARM.exidx end: 0x005c1cd0"),
        ("disasm_worldtileloader_wp_10.txt", "implementation: 0x005cf334", "ARM.exidx end: 0x005cf370"),
    ):
        require(NATIVE / _wp_file, [_wp_imp, _wp_end])


    require(
        NATIVE / "WORLD_CXX.md",
        [
            "1346",
            "324",
            "1022",
            "macroTileAtMacroPostion",
            "requestBlockFromServerAtPos",
            "std::__1::__tree",
        ],
    )
    require(
        NATIVE / "world_cxx.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 324',
            '"verified_words": 1022',
            ".cxx_construct",
            "OBJC_IVAR_$_World.usedPhysicalBlocks",
        ],
    )
    for _wc2_file, _wc2_imp, _wc2_end in (
        ("disasm_worldtileloader_wc_00.txt", "implementation: 0x005dab64", "ARM.exidx end: 0x005db074"),
        ("disasm_worldtileloader_wc_01.txt", "implementation: 0x005b4a00", "ARM.exidx end: 0x005b59f8"),
    ):
        require(NATIVE / _wc2_file, [_wc2_imp, _wc2_end])


    require(
        NATIVE / "WORLD_CLOSE1.md",
        [
            "6190",
            "388",
            "344",
            "GKAchievement",
            "std::unordered_set<PhysicalBlock>",
            "__android_log_print",
            "Reachability",
        ],
    )
    require(
        NATIVE / "world_close1.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 388',
            '"verified_words": 344',
            "setCustomSlotAtIndex:",
            "OBJC_IVAR_$_World.foundItemsList",
        ],
    )
    for _wx_file, _wx_imp, _wx_end in (
        ("disasm_worldtileloader_wx_00.txt", "implementation: 0x005d5f80", "ARM.exidx end: 0x005d6590"),
        ("disasm_worldtileloader_wx_01.txt", "implementation: 0x005d7f2c", "ARM.exidx end: 0x005d848c"),
        ("disasm_worldtileloader_wx_02.txt", "implementation: 0x005d2c7c", "ARM.exidx end: 0x005d2cc8"),
        ("disasm_worldtileloader_wx_03.txt", "implementation: 0x005d855c", "ARM.exidx end: 0x005d8974"),
        ("disasm_worldtileloader_wx_04.txt", "implementation: 0x005c47b8", "ARM.exidx end: 0x005c4b08"),
        ("disasm_worldtileloader_wx_05.txt", "implementation: 0x005d6910", "ARM.exidx end: 0x005d6cb8"),
        ("disasm_worldtileloader_wx_06.txt", "implementation: 0x005d6590", "ARM.exidx end: 0x005d6910"),
        ("disasm_worldtileloader_wx_07.txt", "implementation: 0x005c8284", "ARM.exidx end: 0x005c85fc"),
        ("disasm_worldtileloader_wx_08.txt", "implementation: 0x005ab274", "ARM.exidx end: 0x005ab510"),
        ("disasm_worldtileloader_wx_09.txt", "implementation: 0x005d6cb8", "ARM.exidx end: 0x005d6fc8"),
        ("disasm_worldtileloader_wx_10.txt", "implementation: 0x00566948", "ARM.exidx end: 0x00566c14"),
        ("disasm_worldtileloader_wx_11.txt", "implementation: 0x005d179c", "ARM.exidx end: 0x005d1a68"),
        ("disasm_worldtileloader_wx_12.txt", "implementation: 0x005d1484", "ARM.exidx end: 0x005d1724"),
        ("disasm_worldtileloader_wx_13.txt", "implementation: 0x005cf470", "ARM.exidx end: 0x005cf6f0"),
        ("disasm_worldtileloader_wx_14.txt", "implementation: 0x005d8acc", "ARM.exidx end: 0x005d8d3c"),
        ("disasm_worldtileloader_wx_15.txt", "implementation: 0x00566c14", "ARM.exidx end: 0x00566e64"),
        ("disasm_worldtileloader_wx_16.txt", "implementation: 0x005c61d4", "ARM.exidx end: 0x005c6414"),
        ("disasm_worldtileloader_wx_17.txt", "implementation: 0x005cf858", "ARM.exidx end: 0x005cfa4c"),
        ("disasm_worldtileloader_wx_18.txt", "implementation: 0x005c8094", "ARM.exidx end: 0x005c8284"),
        ("disasm_worldtileloader_wx_19.txt", "implementation: 0x005d7d54", "ARM.exidx end: 0x005d7f2c"),
        ("disasm_worldtileloader_wx_20.txt", "implementation: 0x005cdfbc", "ARM.exidx end: 0x005ce174"),
        ("disasm_worldtileloader_wx_21.txt", "implementation: 0x005b6410", "ARM.exidx end: 0x005b65bc"),
        ("disasm_worldtileloader_wx_22.txt", "implementation: 0x005cf010", "ARM.exidx end: 0x005cf1b8"),
        ("disasm_worldtileloader_wx_23.txt", "implementation: 0x005d79c8", "ARM.exidx end: 0x005d7b60"),
        ("disasm_worldtileloader_wx_24.txt", "implementation: 0x005cf1b8", "ARM.exidx end: 0x005cf334"),
        ("disasm_worldtileloader_wx_25.txt", "implementation: 0x005cf6f0", "ARM.exidx end: 0x005cf858"),
        ("disasm_worldtileloader_wx_26.txt", "implementation: 0x005ceebc", "ARM.exidx end: 0x005cf010"),
        ("disasm_worldtileloader_wx_27.txt", "implementation: 0x005d7b9c", "ARM.exidx end: 0x005d7cac"),
        ("disasm_worldtileloader_wx_28.txt", "implementation: 0x005c1cd0", "ARM.exidx end: 0x005c1ddc"),
        ("disasm_worldtileloader_wx_29.txt", "implementation: 0x005c8d90", "ARM.exidx end: 0x005c8e98"),
        ("disasm_worldtileloader_wx_30.txt", "implementation: 0x005cf370", "ARM.exidx end: 0x005cf470"),
        ("disasm_worldtileloader_wx_31.txt", "implementation: 0x005d2098", "ARM.exidx end: 0x005d218c"),
        ("disasm_worldtileloader_wx_32.txt", "implementation: 0x005ce174", "ARM.exidx end: 0x005ce260"),
        ("disasm_worldtileloader_wx_33.txt", "implementation: 0x005d2b90", "ARM.exidx end: 0x005d2c7c"),
        ("disasm_worldtileloader_wx_34.txt", "implementation: 0x005c875c", "ARM.exidx end: 0x005c8844"),
        ("disasm_worldtileloader_wx_35.txt", "implementation: 0x005b65bc", "ARM.exidx end: 0x005b6698"),
        ("disasm_worldtileloader_wx_36.txt", "implementation: 0x005d2ab8", "ARM.exidx end: 0x005d2b90"),
        ("disasm_worldtileloader_wx_37.txt", "implementation: 0x005daa8c", "ARM.exidx end: 0x005dab64"),
        ("disasm_worldtileloader_wx_38.txt", "implementation: 0x00552d58", "ARM.exidx end: 0x00552e28"),
        ("disasm_worldtileloader_wx_39.txt", "implementation: 0x005d848c", "ARM.exidx end: 0x005d855c"),
        ("disasm_worldtileloader_wx_40.txt", "implementation: 0x005ab1ac", "ARM.exidx end: 0x005ab274"),
        ("disasm_worldtileloader_wx_41.txt", "implementation: 0x005d3348", "ARM.exidx end: 0x005d3410"),
        ("disasm_worldtileloader_wx_42.txt", "implementation: 0x005d3474", "ARM.exidx end: 0x005d3538"),
        ("disasm_worldtileloader_wx_43.txt", "implementation: 0x005be2cc", "ARM.exidx end: 0x005be378"),
        ("disasm_worldtileloader_wx_44.txt", "implementation: 0x005d13d8", "ARM.exidx end: 0x005d1484"),
        ("disasm_worldtileloader_wx_45.txt", "implementation: 0x005b6368", "ARM.exidx end: 0x005b6410"),
        ("disasm_worldtileloader_wx_46.txt", "implementation: 0x005cfe00", "ARM.exidx end: 0x005cfea4"),
        ("disasm_worldtileloader_wx_47.txt", "implementation: 0x005bddac", "ARM.exidx end: 0x005bde3c"),
        ("disasm_worldtileloader_wx_48.txt", "implementation: 0x005c8660", "ARM.exidx end: 0x005c86ec"),
        ("disasm_worldtileloader_wx_49.txt", "implementation: 0x005d5684", "ARM.exidx end: 0x005d5710"),
        ("disasm_worldtileloader_wx_50.txt", "implementation: 0x005d89ec", "ARM.exidx end: 0x005d8a68"),
        ("disasm_worldtileloader_wx_51.txt", "implementation: 0x005d560c", "ARM.exidx end: 0x005d5684"),
        ("disasm_worldtileloader_wx_52.txt", "implementation: 0x005d8974", "ARM.exidx end: 0x005d89ec"),
        ("disasm_worldtileloader_wx_53.txt", "implementation: 0x005c86ec", "ARM.exidx end: 0x005c875c"),
        ("disasm_worldtileloader_wx_54.txt", "implementation: 0x005c8844", "ARM.exidx end: 0x005c88b0"),
        ("disasm_worldtileloader_wx_55.txt", "implementation: 0x005cee00", "ARM.exidx end: 0x005cee6c"),
        ("disasm_worldtileloader_wx_56.txt", "implementation: 0x005d7ce8", "ARM.exidx end: 0x005d7d54"),
        ("disasm_worldtileloader_wx_57.txt", "implementation: 0x005d8f0c", "ARM.exidx end: 0x005d8f78"),
        ("disasm_worldtileloader_wx_58.txt", "implementation: 0x005da33c", "ARM.exidx end: 0x005da3a8"),
        ("disasm_worldtileloader_wx_59.txt", "implementation: 0x005c8d28", "ARM.exidx end: 0x005c8d90"),
        ("disasm_worldtileloader_wx_60.txt", "implementation: 0x005d0c5c", "ARM.exidx end: 0x005d0cc4"),
        ("disasm_worldtileloader_wx_61.txt", "implementation: 0x005d0cc4", "ARM.exidx end: 0x005d0d2c"),
        ("disasm_worldtileloader_wx_62.txt", "implementation: 0x005d704c", "ARM.exidx end: 0x005d70b4"),
        ("disasm_worldtileloader_wx_63.txt", "implementation: 0x005c2790", "ARM.exidx end: 0x005c2858"),
        ("disasm_worldtileloader_wx_64.txt", "implementation: 0x005c27f4", "ARM.exidx end: 0x005c2858"),
        ("disasm_worldtileloader_wx_65.txt", "implementation: 0x005c4b60", "ARM.exidx end: 0x005c4c28"),
        ("disasm_worldtileloader_wx_66.txt", "implementation: 0x005c4bc4", "ARM.exidx end: 0x005c4c28"),
        ("disasm_worldtileloader_wx_67.txt", "implementation: 0x005c85fc", "ARM.exidx end: 0x005c8660"),
        ("disasm_worldtileloader_wx_68.txt", "implementation: 0x005d3410", "ARM.exidx end: 0x005d3474"),
        ("disasm_worldtileloader_wx_69.txt", "implementation: 0x005d8a68", "ARM.exidx end: 0x005d8acc"),
    ):
        require(NATIVE / _wx_file, [_wx_imp, _wx_end])


    require(
        NATIVE / "WORLD_CLOSE2.md",
        [
            "1204",
            "objc_copyStruct",
            "windStrength",
            "ldrsb",
            "workbenchProgressBarUIDisplayed",
        ],
    )
    require(
        NATIVE / "world_close2.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 25',
            '"verified_words": 24',
            "pinchScale",
            "OBJC_IVAR_$_World.randomSeed",
        ],
    )
    for _wy_file, _wy_imp, _wy_end in (
        ("disasm_worldtileloader_wy_00.txt", "implementation: 0x005da2d8", "ARM.exidx end: 0x005da33c"),
        ("disasm_worldtileloader_wy_01.txt", "implementation: 0x005bde3c", "ARM.exidx end: 0x005bde9c"),
        ("disasm_worldtileloader_wy_02.txt", "implementation: 0x005d9b88", "ARM.exidx end: 0x005d9be8"),
        ("disasm_worldtileloader_wy_03.txt", "implementation: 0x005d9d24", "ARM.exidx end: 0x005d9d84"),
        ("disasm_worldtileloader_wy_04.txt", "implementation: 0x005da3e4", "ARM.exidx end: 0x005da444"),
        ("disasm_worldtileloader_wy_05.txt", "implementation: 0x005d7970", "ARM.exidx end: 0x005d79c8"),
        ("disasm_worldtileloader_wy_06.txt", "implementation: 0x005cedac", "ARM.exidx end: 0x005cee00"),
        ("disasm_worldtileloader_wy_07.txt", "implementation: 0x005cee6c", "ARM.exidx end: 0x005ceebc"),
        ("disasm_worldtileloader_wy_08.txt", "implementation: 0x005d5584", "ARM.exidx end: 0x005d55d0"),
        ("disasm_worldtileloader_wy_09.txt", "implementation: 0x005c6eb0", "ARM.exidx end: 0x005c6ef8"),
        ("disasm_worldtileloader_wy_10.txt", "implementation: 0x005d9ab0", "ARM.exidx end: 0x005d9b88"),
        ("disasm_worldtileloader_wy_11.txt", "implementation: 0x005d9af8", "ARM.exidx end: 0x005d9b88"),
        ("disasm_worldtileloader_wy_12.txt", "implementation: 0x005d9b40", "ARM.exidx end: 0x005d9b88"),
        ("disasm_worldtileloader_wy_13.txt", "implementation: 0x005d989c", "ARM.exidx end: 0x005d9968"),
        ("disasm_worldtileloader_wy_14.txt", "implementation: 0x005d98e0", "ARM.exidx end: 0x005d9968"),
        ("disasm_worldtileloader_wy_15.txt", "implementation: 0x005d9924", "ARM.exidx end: 0x005d9968"),
        ("disasm_worldtileloader_wy_16.txt", "implementation: 0x005d9c24", "ARM.exidx end: 0x005d9c68"),
        ("disasm_worldtileloader_wy_17.txt", "implementation: 0x005d9ce0", "ARM.exidx end: 0x005d9d24"),
        ("disasm_worldtileloader_wy_18.txt", "implementation: 0x005d9d84", "ARM.exidx end: 0x005d9e50"),
        ("disasm_worldtileloader_wy_19.txt", "implementation: 0x005d9dc8", "ARM.exidx end: 0x005d9e50"),
        ("disasm_worldtileloader_wy_20.txt", "implementation: 0x005d9e0c", "ARM.exidx end: 0x005d9e50"),
        ("disasm_worldtileloader_wy_21.txt", "implementation: 0x005d9ec8", "ARM.exidx end: 0x005d9f0c"),
        ("disasm_worldtileloader_wy_22.txt", "implementation: 0x005d9f48", "ARM.exidx end: 0x005d9f8c"),
        ("disasm_worldtileloader_wy_23.txt", "implementation: 0x005d9fc8", "ARM.exidx end: 0x005da00c"),
        ("disasm_worldtileloader_wy_24.txt", "implementation: 0x005da048", "ARM.exidx end: 0x005da08c"),
        ("disasm_worldtileloader_wy_25.txt", "implementation: 0x005da0c8", "ARM.exidx end: 0x005da194"),
        ("disasm_worldtileloader_wy_26.txt", "implementation: 0x005da1d0", "ARM.exidx end: 0x005da214"),
        ("disasm_worldtileloader_wy_27.txt", "implementation: 0x005da250", "ARM.exidx end: 0x005da2d8"),
        ("disasm_worldtileloader_wy_28.txt", "implementation: 0x005da294", "ARM.exidx end: 0x005da2d8"),
        ("disasm_worldtileloader_wy_29.txt", "implementation: 0x005da480", "ARM.exidx end: 0x005da508"),
        ("disasm_worldtileloader_wy_30.txt", "implementation: 0x005da4c4", "ARM.exidx end: 0x005da508"),
        ("disasm_worldtileloader_wy_31.txt", "implementation: 0x005da544", "ARM.exidx end: 0x005da588"),
        ("disasm_worldtileloader_wy_32.txt", "implementation: 0x005da63c", "ARM.exidx end: 0x005da744"),
        ("disasm_worldtileloader_wy_33.txt", "implementation: 0x005da680", "ARM.exidx end: 0x005da744"),
        ("disasm_worldtileloader_wy_34.txt", "implementation: 0x005d8e90", "ARM.exidx end: 0x005d8f0c"),
        ("disasm_worldtileloader_wy_35.txt", "implementation: 0x005da6c4", "ARM.exidx end: 0x005da744"),
        ("disasm_worldtileloader_wy_36.txt", "implementation: 0x005da704", "ARM.exidx end: 0x005da744"),
        ("disasm_worldtileloader_wy_37.txt", "implementation: 0x005bdd70", "ARM.exidx end: 0x005bddac"),
        ("disasm_worldtileloader_wy_38.txt", "implementation: 0x005cfa4c", "ARM.exidx end: 0x005cfa88"),
        ("disasm_worldtileloader_wy_39.txt", "implementation: 0x005d1724", "ARM.exidx end: 0x005d179c"),
        ("disasm_worldtileloader_wy_40.txt", "implementation: 0x005d1760", "ARM.exidx end: 0x005d179c"),
        ("disasm_worldtileloader_wy_41.txt", "implementation: 0x005d1a68", "ARM.exidx end: 0x005d1aa4"),
        ("disasm_worldtileloader_wy_42.txt", "implementation: 0x005d55d0", "ARM.exidx end: 0x005d560c"),
        ("disasm_worldtileloader_wy_43.txt", "implementation: 0x005d7b60", "ARM.exidx end: 0x005d7b9c"),
        ("disasm_worldtileloader_wy_44.txt", "implementation: 0x005d7cac", "ARM.exidx end: 0x005d7ce8"),
        ("disasm_worldtileloader_wy_45.txt", "implementation: 0x005d8ed0", "ARM.exidx end: 0x005d8f0c"),
        ("disasm_worldtileloader_wy_46.txt", "implementation: 0x005d9860", "ARM.exidx end: 0x005d989c"),
        ("disasm_worldtileloader_wy_47.txt", "implementation: 0x005d9968", "ARM.exidx end: 0x005d99a4"),
        ("disasm_worldtileloader_wy_48.txt", "implementation: 0x005d9f0c", "ARM.exidx end: 0x005d9f48"),
        ("disasm_worldtileloader_wy_49.txt", "implementation: 0x005d9f8c", "ARM.exidx end: 0x005d9fc8"),
        ("disasm_worldtileloader_wy_50.txt", "implementation: 0x005da00c", "ARM.exidx end: 0x005da048"),
        ("disasm_worldtileloader_wy_51.txt", "implementation: 0x005da08c", "ARM.exidx end: 0x005da0c8"),
        ("disasm_worldtileloader_wy_52.txt", "implementation: 0x005da194", "ARM.exidx end: 0x005da1d0"),
        ("disasm_worldtileloader_wy_53.txt", "implementation: 0x005da214", "ARM.exidx end: 0x005da250"),
        ("disasm_worldtileloader_wy_54.txt", "implementation: 0x005da3a8", "ARM.exidx end: 0x005da3e4"),
        ("disasm_worldtileloader_wy_55.txt", "implementation: 0x005da508", "ARM.exidx end: 0x005da544"),
        ("disasm_worldtileloader_wy_56.txt", "implementation: 0x005da588", "ARM.exidx end: 0x005da63c"),
        ("disasm_worldtileloader_wy_57.txt", "implementation: 0x005da5c4", "ARM.exidx end: 0x005da63c"),
        ("disasm_worldtileloader_wy_58.txt", "implementation: 0x005da744", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_59.txt", "implementation: 0x005da780", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_60.txt", "implementation: 0x005da7bc", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_61.txt", "implementation: 0x005da7f8", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_62.txt", "implementation: 0x005da834", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_63.txt", "implementation: 0x005da870", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_64.txt", "implementation: 0x005da8ac", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_65.txt", "implementation: 0x005da8e8", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_66.txt", "implementation: 0x005da924", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_67.txt", "implementation: 0x005da960", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_68.txt", "implementation: 0x005da99c", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_69.txt", "implementation: 0x005da9d8", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_70.txt", "implementation: 0x005daa50", "ARM.exidx end: 0x005daa8c"),
        ("disasm_worldtileloader_wy_71.txt", "implementation: 0x005d8e58", "ARM.exidx end: 0x005d8f0c"),
    ):
        require(NATIVE / _wy_file, [_wy_imp, _wy_end])


    require(
        NATIVE / "DYNAMICOBJECT.md",
        [
            "2523",
            "439",
            "canBeRemovedByBlockhead",
            "getNextDynamicObjectID",
            "cosf",
        ],
    )
    require(
        NATIVE / "dynobj.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 439',
            '"verified_words": 289',
            "updatePosition:",
            "OBJC_IVAR_$_DynamicObject.floatPos",
        ],
    )
    for _dob_file, _dob_imp, _dob_end in (
        ("disasm_worldtileloader_dob_00.txt", "implementation: 0x00839508", "ARM.exidx end: 0x008398d0"),
        ("disasm_worldtileloader_dob_01.txt", "implementation: 0x008398d0", "ARM.exidx end: 0x008399fc"),
        ("disasm_worldtileloader_dob_02.txt", "implementation: 0x00839a18", "ARM.exidx end: 0x00839af8"),
        ("disasm_worldtileloader_dob_03.txt", "implementation: 0x00839af8", "ARM.exidx end: 0x00839f7c"),
        ("disasm_worldtileloader_dob_04.txt", "implementation: 0x0083a3c0", "ARM.exidx end: 0x0083a740"),
        ("disasm_worldtileloader_dob_05.txt", "implementation: 0x0083a740", "ARM.exidx end: 0x0083a7ac"),
        ("disasm_worldtileloader_dob_06.txt", "implementation: 0x0083aabc", "ARM.exidx end: 0x0083ac20"),
        ("disasm_worldtileloader_dob_07.txt", "implementation: 0x0083ac20", "ARM.exidx end: 0x0083ac50"),
        ("disasm_worldtileloader_dob_08.txt", "implementation: 0x0083ae78", "ARM.exidx end: 0x0083b554"),
        ("disasm_worldtileloader_dob_09.txt", "implementation: 0x0083b554", "ARM.exidx end: 0x0083b570"),
        ("disasm_worldtileloader_dob_10.txt", "implementation: 0x0083b570", "ARM.exidx end: 0x0083b588"),
        ("disasm_worldtileloader_dob_11.txt", "implementation: 0x0083b588", "ARM.exidx end: 0x0083b5a4"),
        ("disasm_worldtileloader_dob_12.txt", "implementation: 0x0083b5a4", "ARM.exidx end: 0x0083b64c"),
        ("disasm_worldtileloader_dob_13.txt", "implementation: 0x0083b5f8", "ARM.exidx end: 0x0083b64c"),
        ("disasm_worldtileloader_dob_14.txt", "implementation: 0x0083b64c", "ARM.exidx end: 0x0083b68c"),
        ("disasm_worldtileloader_dob_15.txt", "implementation: 0x0083b66c", "ARM.exidx end: 0x0083b68c"),
        ("disasm_worldtileloader_dob_16.txt", "implementation: 0x0083b68c", "ARM.exidx end: 0x0083b7b0"),
        ("disasm_worldtileloader_dob_17.txt", "implementation: 0x0083b7b0", "ARM.exidx end: 0x0083b8d4"),
        ("disasm_worldtileloader_dob_18.txt", "implementation: 0x0083b8d4", "ARM.exidx end: 0x0083b8f0"),
        ("disasm_worldtileloader_dob_19.txt", "implementation: 0x0083b8f0", "ARM.exidx end: 0x0083b9c4"),
        ("disasm_worldtileloader_dob_20.txt", "implementation: 0x0083b9c4", "ARM.exidx end: 0x0083b9fc"),
        ("disasm_worldtileloader_dob_21.txt", "implementation: 0x0083b9e0", "ARM.exidx end: 0x0083b9fc"),
        ("disasm_worldtileloader_dob_22.txt", "implementation: 0x0083b9fc", "ARM.exidx end: 0x0083ba8c"),
        ("disasm_worldtileloader_dob_23.txt", "implementation: 0x0083ba20", "ARM.exidx end: 0x0083ba8c"),
        ("disasm_worldtileloader_dob_24.txt", "implementation: 0x0083ba44", "ARM.exidx end: 0x0083ba8c"),
        ("disasm_worldtileloader_dob_25.txt", "implementation: 0x0083ba68", "ARM.exidx end: 0x0083ba8c"),
        ("disasm_worldtileloader_dob_26.txt", "implementation: 0x0083ba8c", "ARM.exidx end: 0x0083bafc"),
        ("disasm_worldtileloader_dob_27.txt", "implementation: 0x0083bac4", "ARM.exidx end: 0x0083bafc"),
        ("disasm_worldtileloader_dob_28.txt", "implementation: 0x0083bafc", "ARM.exidx end: 0x0083bb18"),
        ("disasm_worldtileloader_dob_29.txt", "implementation: 0x0083bb18", "ARM.exidx end: 0x0083bb3c"),
        ("disasm_worldtileloader_dob_30.txt", "implementation: 0x0083bb3c", "ARM.exidx end: 0x0083bb74"),
        ("disasm_worldtileloader_dob_31.txt", "implementation: 0x0083bb58", "ARM.exidx end: 0x0083bb74"),
        ("disasm_worldtileloader_dob_32.txt", "implementation: 0x0083bb74", "ARM.exidx end: 0x0083bb98"),
        ("disasm_worldtileloader_dob_33.txt", "implementation: 0x0083bb98", "ARM.exidx end: 0x0083bbb4"),
        ("disasm_worldtileloader_dob_34.txt", "implementation: 0x0083bbb4", "ARM.exidx end: 0x0083bbd8"),
        ("disasm_worldtileloader_dob_35.txt", "implementation: 0x0083bbd8", "ARM.exidx end: 0x0083bbf4"),
        ("disasm_worldtileloader_dob_36.txt", "implementation: 0x0083bbf4", "ARM.exidx end: 0x0083bc18"),
        ("disasm_worldtileloader_dob_37.txt", "implementation: 0x0083c890", "ARM.exidx end: 0x0083c8a8"),
        ("disasm_worldtileloader_dob_38.txt", "implementation: 0x0083c8a8", "ARM.exidx end: 0x0083c8bc"),
        ("disasm_worldtileloader_dob_39.txt", "implementation: 0x0083c960", "ARM.exidx end: 0x0083c998"),
        ("disasm_worldtileloader_dob_40.txt", "implementation: 0x0083c97c", "ARM.exidx end: 0x0083c998"),
        ("disasm_worldtileloader_dob_41.txt", "implementation: 0x0083c9dc", "ARM.exidx end: 0x0083ca98"),
        ("disasm_worldtileloader_dob_42.txt", "implementation: 0x0083ca98", "ARM.exidx end: 0x0083cb7c"),
        ("disasm_worldtileloader_dob_43.txt", "implementation: 0x0083cab4", "ARM.exidx end: 0x0083cb7c"),
        ("disasm_worldtileloader_dob_44.txt", "implementation: 0x0083cad0", "ARM.exidx end: 0x0083cb7c"),
        ("disasm_worldtileloader_dob_45.txt", "implementation: 0x0083caec", "ARM.exidx end: 0x0083cb7c"),
        ("disasm_worldtileloader_dob_46.txt", "implementation: 0x0083cb28", "ARM.exidx end: 0x0083cb7c"),
        ("disasm_worldtileloader_dob_47.txt", "implementation: 0x0083cb7c", "ARM.exidx end: 0x0083ce9c"),
        ("disasm_worldtileloader_dob_48.txt", "implementation: 0x0083ce9c", "ARM.exidx end: 0x0083ceb8"),
        ("disasm_worldtileloader_dob_49.txt", "implementation: 0x0083ceb8", "ARM.exidx end: 0x0083ced4"),
        ("disasm_worldtileloader_dob_50.txt", "implementation: 0x0083ced4", "ARM.exidx end: 0x0083cf5c"),
        ("disasm_worldtileloader_dob_51.txt", "implementation: 0x0083cf5c", "ARM.exidx end: 0x0083cfcc"),
        ("disasm_worldtileloader_dob_52.txt", "implementation: 0x0083cf78", "ARM.exidx end: 0x0083cfcc"),
        ("disasm_worldtileloader_dob_53.txt", "implementation: 0x0083cf94", "ARM.exidx end: 0x0083cfcc"),
        ("disasm_worldtileloader_dob_54.txt", "implementation: 0x0083cfb0", "ARM.exidx end: 0x0083cfcc"),
        ("disasm_worldtileloader_dob_55.txt", "implementation: 0x0083d0f0", "ARM.exidx end: 0x0083d12c"),
        ("disasm_worldtileloader_dob_56.txt", "implementation: 0x0083d12c", "ARM.exidx end: 0x0083d170"),
        ("disasm_worldtileloader_dob_57.txt", "implementation: 0x0083d170", "ARM.exidx end: 0x0083d1ac"),
        ("disasm_worldtileloader_dob_58.txt", "implementation: 0x0083d1ac", "ARM.exidx end: 0x0083d1f0"),
        ("disasm_worldtileloader_dob_59.txt", "implementation: 0x0083d1f0", "ARM.exidx end: 0x0083d22c"),
        ("disasm_worldtileloader_dob_60.txt", "implementation: 0x0083d22c", "ARM.exidx end: 0x0083d270"),
        ("disasm_worldtileloader_dob_61.txt", "implementation: 0x0083d270", "ARM.exidx end: 0x0083d2ac"),
        ("disasm_worldtileloader_dob_62.txt", "implementation: 0x0083d2ac", "ARM.exidx end: 0x0083d2f0"),
        ("disasm_worldtileloader_dob_63.txt", "implementation: 0x0083d2f0", "ARM.exidx end: 0x0083d32c"),
        ("disasm_worldtileloader_dob_64.txt", "implementation: 0x0083d32c", "ARM.exidx end: 0x0083d370"),
        ("disasm_worldtileloader_dob_65.txt", "implementation: 0x0083d370", "ARM.exidx end: 0x0083d490"),
    ):
        require(NATIVE / _dob_file, [_dob_imp, _dob_end])


    require(
        NATIVE / "NPC_CORE.md",
        [
            "11055",
            "1832",
            "1432",
            "tameCountRequirementForNPCType",
            "drawShaderQuadNoTexture",
            "0x6445d8",
        ],
    )
    require(
        NATIVE / "npc_core.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1832',
            '"verified_words": 1432',
            "remoteCreationDataUpdate:",
            "OBJC_IVAR_$_NPC.tamedClientID",
        ],
    )
    for _np_file, _np_imp, _np_end in (
        ("disasm_worldtileloader_np_00.txt", "implementation: 0x006513e4", "ARM.exidx end: 0x0065142c"),
        ("disasm_worldtileloader_np_01.txt", "implementation: 0x0064bf30", "ARM.exidx end: 0x0064dbd0"),
        ("disasm_worldtileloader_np_02.txt", "implementation: 0x00647cf8", "ARM.exidx end: 0x00649358"),
        ("disasm_worldtileloader_np_03.txt", "implementation: 0x006468d0", "ARM.exidx end: 0x00647c84"),
        ("disasm_worldtileloader_np_04.txt", "implementation: 0x00645aac", "ARM.exidx end: 0x00646738"),
        ("disasm_worldtileloader_np_05.txt", "implementation: 0x0064b398", "ARM.exidx end: 0x0064be74"),
        ("disasm_worldtileloader_np_06.txt", "implementation: 0x00650b10", "ARM.exidx end: 0x00651314"),
        ("disasm_worldtileloader_np_07.txt", "implementation: 0x00650218", "ARM.exidx end: 0x0065096c"),
        ("disasm_worldtileloader_np_08.txt", "implementation: 0x00644e94", "ARM.exidx end: 0x006455d4"),
        ("disasm_worldtileloader_np_09.txt", "implementation: 0x0064ad80", "ARM.exidx end: 0x0064b398"),
        ("disasm_worldtileloader_np_10.txt", "implementation: 0x00649894", "ARM.exidx end: 0x00649e20"),
        ("disasm_worldtileloader_np_11.txt", "implementation: 0x00644718", "ARM.exidx end: 0x00644b24"),
        ("disasm_worldtileloader_np_12.txt", "implementation: 0x0064fd60", "ARM.exidx end: 0x006500c0"),
        ("disasm_worldtileloader_np_13.txt", "implementation: 0x0064f124", "ARM.exidx end: 0x0064f444"),
        ("disasm_worldtileloader_np_14.txt", "implementation: 0x0064a9f8", "ARM.exidx end: 0x0064acf8"),
        ("disasm_worldtileloader_np_15.txt", "implementation: 0x0064f6c8", "ARM.exidx end: 0x0064f9a0"),
        ("disasm_worldtileloader_np_16.txt", "implementation: 0x0064e8d8", "ARM.exidx end: 0x0064eb64"),
        ("disasm_worldtileloader_np_17.txt", "implementation: 0x0064f444", "ARM.exidx end: 0x0064f6c8"),
        ("disasm_worldtileloader_np_18.txt", "implementation: 0x0064f9a0", "ARM.exidx end: 0x0064fbf0"),
        ("disasm_worldtileloader_np_19.txt", "implementation: 0x0064eb64", "ARM.exidx end: 0x0064ed9c"),
        ("disasm_worldtileloader_np_20.txt", "implementation: 0x0064567c", "ARM.exidx end: 0x0064589c"),
        ("disasm_worldtileloader_np_21.txt", "implementation: 0x00649fec", "ARM.exidx end: 0x0064a208"),
        ("disasm_worldtileloader_np_22.txt", "implementation: 0x0064e604", "ARM.exidx end: 0x0064e81c"),
        ("disasm_worldtileloader_np_23.txt", "implementation: 0x00649670", "ARM.exidx end: 0x00649880"),
        ("disasm_worldtileloader_np_24.txt", "implementation: 0x0064ef20", "ARM.exidx end: 0x0064f124"),
        ("disasm_worldtileloader_np_25.txt", "implementation: 0x00644ca0", "ARM.exidx end: 0x00644e94"),
        ("disasm_worldtileloader_np_26.txt", "implementation: 0x0064a2f0", "ARM.exidx end: 0x0064a49c"),
        ("disasm_worldtileloader_np_27.txt", "implementation: 0x00646738", "ARM.exidx end: 0x006468d0"),
        ("disasm_worldtileloader_np_28.txt", "implementation: 0x0064448c", "ARM.exidx end: 0x00644704"),
        ("disasm_worldtileloader_np_29.txt", "implementation: 0x0064589c", "ARM.exidx end: 0x006459c0"),
    ):
        require(NATIVE / _np_file, [_np_imp, _np_end])


    require(
        NATIVE / "SNOWLINE.md",
        [
            "5866",
            "iceMeltTimer",
            "fillTile:atPos:withType:",
            "snowChangedAtMacroPos",
            "0x423",
        ],
    )
    require(
        NATIVE / "snowline.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1428',
            '"verified_words": 642',
            "updateSnowContent:tile:",
            "OBJC_IVAR_$_SnowSurfaceBlock.temperature",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_sl_00.txt", "implementation: 0x00d918d8", "ARM.exidx end: 0x00d919a0"),
        ("disasm_worldtileloader_sl_01.txt", "implementation: 0x00d8d9b8", "ARM.exidx end: 0x00d8da7c"),
        ("disasm_worldtileloader_sl_02.txt", "implementation: 0x00d8d5e0", "ARM.exidx end: 0x00d8d89c"),
        ("disasm_worldtileloader_sl_03.txt", "implementation: 0x00d8d89c", "ARM.exidx end: 0x00d8d9b8"),
        ("disasm_worldtileloader_sl_04.txt", "implementation: 0x00d8da7c", "ARM.exidx end: 0x00d8dab8"),
        ("disasm_worldtileloader_sl_05.txt", "implementation: 0x00d8d5c4", "ARM.exidx end: 0x00d8d5e0"),
        ("disasm_worldtileloader_sl_06.txt", "implementation: 0x00d8d4b8", "ARM.exidx end: 0x00d8d5b4"),
        ("disasm_worldtileloader_sl_07.txt", "implementation: 0x00d8dab8", "ARM.exidx end: 0x00d8db28"),
        ("disasm_worldtileloader_sl_08.txt", "implementation: 0x00d8db28", "ARM.exidx end: 0x00d8e530"),
        ("disasm_worldtileloader_sl_09.txt", "implementation: 0x00d8e530", "ARM.exidx end: 0x00d8fb80"),
        ("disasm_worldtileloader_sl_10.txt", "implementation: 0x00d8fb80", "ARM.exidx end: 0x00d903b8"),
        ("disasm_worldtileloader_sl_11.txt", "implementation: 0x00d903b8", "ARM.exidx end: 0x00d90a4c"),
        ("disasm_worldtileloader_sl_12.txt", "implementation: 0x00d90a4c", "ARM.exidx end: 0x00d90e84"),
        ("disasm_worldtileloader_sl_13.txt", "implementation: 0x00d90e84", "ARM.exidx end: 0x00d9119c"),
        ("disasm_worldtileloader_sl_14.txt", "implementation: 0x00d911d8", "ARM.exidx end: 0x00d913d4"),
        ("disasm_worldtileloader_sl_15.txt", "implementation: 0x00d913d4", "ARM.exidx end: 0x00d918d8"),
        ("disasm_worldtileloader_sl_16.txt", "implementation: 0x00d91588", "ARM.exidx end: 0x00d918d8"),
        ("disasm_worldtileloader_sl_17.txt", "implementation: 0x00d919a0", "ARM.exidx end: 0x00d91a34"),
        ("disasm_worldtileloader_sl_18.txt", "implementation: 0x00d919e8", "ARM.exidx end: 0x00d91a34"),
        ("disasm_worldtileloader_sl_19.txt", "implementation: 0x00834210", "ARM.exidx end: 0x00834538"),
        ("disasm_worldtileloader_sl_20.txt", "implementation: 0x00835b60", "ARM.exidx end: 0x00835fa0"),
        ("disasm_worldtileloader_sl_21.txt", "implementation: 0x006cbbe0", "ARM.exidx end: 0x006cc2bc"),
        ("disasm_worldtileloader_sl_22.txt", "implementation: 0x006cdccc", "ARM.exidx end: 0x006ce10c"),
        ("disasm_worldtileloader_sl_23.txt", "implementation: 0x008e1bf0", "ARM.exidx end: 0x008e1f18"),
        ("disasm_worldtileloader_sl_24.txt", "implementation: 0x008e6608", "ARM.exidx end: 0x008e66d4"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "WATERLINE.md",
        [
            "11897",
            "getWeatherFractionForPos",
            "sandFractionForPos",
            "recursivelyFlowOutWaterFromTile",
            "takeAnyWaterFromTileAtPos",
        ],
    )
    require(
        NATIVE / "waterline.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1877',
            '"verified_words": 1101',
            "getWeatherFractionForPos:atWorldTime:ignoreSandFraction:",
            "OBJC_IVAR_$_Weather.windMovement",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_aq_00.txt", "implementation: 0x007e3a28", "ARM.exidx end: 0x007e4b5c"),
        ("disasm_worldtileloader_aq_01.txt", "implementation: 0x007e4b6c", "ARM.exidx end: 0x007e5568"),
        ("disasm_worldtileloader_aq_02.txt", "implementation: 0x007e5568", "ARM.exidx end: 0x007e5b10"),
        ("disasm_worldtileloader_aq_03.txt", "implementation: 0x007e5b10", "ARM.exidx end: 0x007e5eb0"),
        ("disasm_worldtileloader_aq_04.txt", "implementation: 0x007e5eb0", "ARM.exidx end: 0x007e6a70"),
        ("disasm_worldtileloader_aq_05.txt", "implementation: 0x007e6a70", "ARM.exidx end: 0x007e6f48"),
        ("disasm_worldtileloader_aq_06.txt", "implementation: 0x007e6f48", "ARM.exidx end: 0x007e7990"),
        ("disasm_worldtileloader_aq_07.txt", "implementation: 0x007e7990", "ARM.exidx end: 0x007e88a8"),
        ("disasm_worldtileloader_aq_08.txt", "implementation: 0x007e88a8", "ARM.exidx end: 0x007ea5fc"),
        ("disasm_worldtileloader_aq_09.txt", "implementation: 0x007ea820", "ARM.exidx end: 0x007eb4e8"),
        ("disasm_worldtileloader_aq_10.txt", "implementation: 0x007eb4e8", "ARM.exidx end: 0x007eb694"),
        ("disasm_worldtileloader_aq_11.txt", "implementation: 0x007eb694", "ARM.exidx end: 0x007ebee0"),
        ("disasm_worldtileloader_aq_12.txt", "implementation: 0x007ebee0", "ARM.exidx end: 0x007ebf60"),
        ("disasm_worldtileloader_aq_13.txt", "implementation: 0x007ebf60", "ARM.exidx end: 0x007ebff4"),
        ("disasm_worldtileloader_aq_14.txt", "implementation: 0x007ebfa8", "ARM.exidx end: 0x007ebff4"),
        ("disasm_worldtileloader_aq_15.txt", "implementation: 0x007ebff4", "ARM.exidx end: 0x007ec00c"),
        ("disasm_worldtileloader_aq_16.txt", "implementation: 0x00582a50", "ARM.exidx end: 0x00582ad8"),
        ("disasm_worldtileloader_aq_17.txt", "implementation: 0x00582408", "ARM.exidx end: 0x00582488"),
        ("disasm_worldtileloader_aq_18.txt", "implementation: 0x00582488", "ARM.exidx end: 0x00582a14"),
        ("disasm_worldtileloader_aq_19.txt", "implementation: 0x005d9ab0", "ARM.exidx end: 0x005d9b88"),
        ("disasm_worldtileloader_aq_20.txt", "implementation: 0x005d9b40", "ARM.exidx end: 0x005d9b88"),
        ("disasm_worldtileloader_aq_21.txt", "implementation: 0x00578430", "ARM.exidx end: 0x00578a20"),
        ("disasm_worldtileloader_aq_22.txt", "implementation: 0x005c1ddc", "ARM.exidx end: 0x005c2790"),
        ("disasm_worldtileloader_aq_23.txt", "implementation: 0x005da5c4", "ARM.exidx end: 0x005da63c"),
        ("disasm_worldtileloader_aq_24.txt", "implementation: 0x0085c214", "ARM.exidx end: 0x0085c518"),
        ("disasm_worldtileloader_aq_25.txt", "implementation: 0x008e0ad0", "ARM.exidx end: 0x008e1390"),
        ("disasm_worldtileloader_aq_26.txt", "implementation: 0x00812184", "ARM.exidx end: 0x00812228"),
        ("disasm_worldtileloader_aq_27.txt", "implementation: 0x00812228", "ARM.exidx end: 0x00812cf4"),
        ("disasm_worldtileloader_aq_28.txt", "implementation: 0x008144a8", "ARM.exidx end: 0x008148b8"),
        ("disasm_worldtileloader_aq_29.txt", "implementation: 0x0083b5f8", "ARM.exidx end: 0x0083b64c"),
        ("disasm_worldtileloader_aq_30.txt", "implementation: 0x008ee1f0", "ARM.exidx end: 0x008ee3e8"),
        ("disasm_worldtileloader_aq_31.txt", "implementation: 0x00b8ca38", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_aq_32.txt", "implementation: 0x00c8a540", "ARM.exidx end: 0x00c8a588"),
        ("disasm_worldtileloader_aq_33.txt", "implementation: 0x006ba1b4", "ARM.exidx end: 0x006ba1d0"),
        ("disasm_worldtileloader_aq_34.txt", "implementation: 0x006d143c", "ARM.exidx end: 0x006d1458"),
        ("disasm_worldtileloader_aq_35.txt", "implementation: 0x006ffc08", "ARM.exidx end: 0x006ffc24"),
        ("disasm_worldtileloader_aq_36.txt", "implementation: 0x00741978", "ARM.exidx end: 0x00741994"),
        ("disasm_worldtileloader_aq_37.txt", "implementation: 0x00770d2c", "ARM.exidx end: 0x00770d48"),
        ("disasm_worldtileloader_aq_38.txt", "implementation: 0x009bc5f0", "ARM.exidx end: 0x009bc60c"),
        ("disasm_worldtileloader_aq_39.txt", "implementation: 0x00a65554", "ARM.exidx end: 0x00a655c4"),
        ("disasm_worldtileloader_aq_40.txt", "implementation: 0x00b50248", "ARM.exidx end: 0x00b50264"),
        ("disasm_worldtileloader_aq_41.txt", "implementation: 0x00650a48", "ARM.exidx end: 0x00650b10"),
        ("disasm_worldtileloader_aq_42.txt", "implementation: 0x00d85230", "ARM.exidx end: 0x00d85268"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "HEATLINE.md",
        [
            "12812",
            "burnTimer",
            "spreadTimers",
            "placeFireAtPosition",
            "tileIsBurnable",
        ],
    )
    require(
        NATIVE / "heatline.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 2753',
            '"verified_words": 692',
            "customRulesPoleOffset",
            "OBJC_IVAR_$_FireObject.spreadTimers",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_hl_00.txt", "implementation: 0x0067440c", "ARM.exidx end: 0x00674678"),
        ("disasm_worldtileloader_hl_01.txt", "implementation: 0x00674688", "ARM.exidx end: 0x006746a4"),
        ("disasm_worldtileloader_hl_02.txt", "implementation: 0x006746a4", "ARM.exidx end: 0x00674704"),
        ("disasm_worldtileloader_hl_03.txt", "implementation: 0x00674704", "ARM.exidx end: 0x00674af4"),
        ("disasm_worldtileloader_hl_04.txt", "implementation: 0x00674af4", "ARM.exidx end: 0x00674f00"),
        ("disasm_worldtileloader_hl_05.txt", "implementation: 0x00674f00", "ARM.exidx end: 0x0067501c"),
        ("disasm_worldtileloader_hl_06.txt", "implementation: 0x0067501c", "ARM.exidx end: 0x006753ec"),
        ("disasm_worldtileloader_hl_07.txt", "implementation: 0x006753ec", "ARM.exidx end: 0x00675440"),
        ("disasm_worldtileloader_hl_08.txt", "implementation: 0x00675440", "ARM.exidx end: 0x00675560"),
        ("disasm_worldtileloader_hl_09.txt", "implementation: 0x00675560", "ARM.exidx end: 0x00675648"),
        ("disasm_worldtileloader_hl_10.txt", "implementation: 0x00675648", "ARM.exidx end: 0x00675730"),
        ("disasm_worldtileloader_hl_11.txt", "implementation: 0x00675730", "ARM.exidx end: 0x00675cd4"),
        ("disasm_worldtileloader_hl_12.txt", "implementation: 0x00675cd4", "ARM.exidx end: 0x00675d30"),
        ("disasm_worldtileloader_hl_13.txt", "implementation: 0x00675d30", "ARM.exidx end: 0x00676800"),
        ("disasm_worldtileloader_hl_14.txt", "implementation: 0x00676800", "ARM.exidx end: 0x00678b70"),
        ("disasm_worldtileloader_hl_15.txt", "implementation: 0x00679a48", "ARM.exidx end: 0x00679ab4"),
        ("disasm_worldtileloader_hl_16.txt", "implementation: 0x00679ab4", "ARM.exidx end: 0x00679b28"),
        ("disasm_worldtileloader_hl_17.txt", "implementation: 0x00a8f22c", "ARM.exidx end: 0x00a91d30"),
        ("disasm_worldtileloader_hl_18.txt", "implementation: 0x00a92238", "ARM.exidx end: 0x00a93160"),
        ("disasm_worldtileloader_hl_19.txt", "implementation: 0x00a93198", "ARM.exidx end: 0x00a93728"),
        ("disasm_worldtileloader_hl_20.txt", "implementation: 0x00a93728", "ARM.exidx end: 0x00a93744"),
        ("disasm_worldtileloader_hl_21.txt", "implementation: 0x00a93744", "ARM.exidx end: 0x00a93bbc"),
        ("disasm_worldtileloader_hl_22.txt", "implementation: 0x00a93bbc", "ARM.exidx end: 0x00a93c64"),
        ("disasm_worldtileloader_hl_23.txt", "implementation: 0x00a93c64", "ARM.exidx end: 0x00a942d4"),
        ("disasm_worldtileloader_hl_24.txt", "implementation: 0x00a942d4", "ARM.exidx end: 0x00a947ac"),
        ("disasm_worldtileloader_hl_25.txt", "implementation: 0x00a947ac", "ARM.exidx end: 0x00a94898"),
        ("disasm_worldtileloader_hl_26.txt", "implementation: 0x00a94898", "ARM.exidx end: 0x00a9519c"),
        ("disasm_worldtileloader_hl_27.txt", "implementation: 0x00a9519c", "ARM.exidx end: 0x00a95248"),
        ("disasm_worldtileloader_hl_28.txt", "implementation: 0x00a95248", "ARM.exidx end: 0x00a958bc"),
        ("disasm_worldtileloader_hl_29.txt", "implementation: 0x00a958bc", "ARM.exidx end: 0x00a958d4"),
        ("disasm_worldtileloader_hl_30.txt", "implementation: 0x00ca8304", "ARM.exidx end: 0x00ca8334"),
        ("disasm_worldtileloader_hl_31.txt", "implementation: 0x00ca8318", "ARM.exidx end: 0x00ca8334"),
        ("disasm_worldtileloader_hl_32.txt", "implementation: 0x00ca8334", "ARM.exidx end: 0x00ca83d4"),
        ("disasm_worldtileloader_hl_33.txt", "implementation: 0x00ca83d4", "ARM.exidx end: 0x00ca8920"),
        ("disasm_worldtileloader_hl_34.txt", "implementation: 0x00ca8920", "ARM.exidx end: 0x00ca8c78"),
        ("disasm_worldtileloader_hl_35.txt", "implementation: 0x00ca8c78", "ARM.exidx end: 0x00ca8e64"),
        ("disasm_worldtileloader_hl_36.txt", "implementation: 0x00ca8e64", "ARM.exidx end: 0x00ca8f4c"),
        ("disasm_worldtileloader_hl_37.txt", "implementation: 0x00ca8f4c", "ARM.exidx end: 0x00ca90bc"),
        ("disasm_worldtileloader_hl_38.txt", "implementation: 0x00ca90bc", "ARM.exidx end: 0x00ca93ac"),
        ("disasm_worldtileloader_hl_39.txt", "implementation: 0x00ca93ac", "ARM.exidx end: 0x00ca9500"),
        ("disasm_worldtileloader_hl_40.txt", "implementation: 0x00ca9500", "ARM.exidx end: 0x00ca955c"),
        ("disasm_worldtileloader_hl_41.txt", "implementation: 0x00ca955c", "ARM.exidx end: 0x00ca960c"),
        ("disasm_worldtileloader_hl_42.txt", "implementation: 0x00ca960c", "ARM.exidx end: 0x00ca9680"),
        ("disasm_worldtileloader_hl_43.txt", "implementation: 0x00a140ec", "ARM.exidx end: 0x00a14180"),
        ("disasm_worldtileloader_hl_44.txt", "implementation: 0x00a14180", "ARM.exidx end: 0x00a1436c"),
        ("disasm_worldtileloader_hl_45.txt", "implementation: 0x00a14f28", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_hl_46.txt", "implementation: 0x00a15404", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_hl_47.txt", "implementation: 0x00a14ba0", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_hl_48.txt", "implementation: 0x00a14d98", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_hl_49.txt", "implementation: 0x00a14a48", "ARM.exidx end: 0x00a155dc"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "CBASE.md",
        [
            "4059",
            "worldWidthMacro",
            "dynamicObjectTypeForNPCType",
            "fmod(d / 900.0",
            "((y & 31) << 5)",
            "0xe4aa1c",
        ],
    )
    require(
        NATIVE / "cbase.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 126',
            '"verified_words": 226',
            "objectTypeIsNPC",
            "makeIntpair",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_cx_00.txt", "implementation: 0x004bdaac", "ARM.exidx end: 0x004bdac0"),
        ("disasm_worldtileloader_cx_01.txt", "implementation: 0x004b5c08", "ARM.exidx end: 0x004b5c1c"),
        ("disasm_worldtileloader_cx_02.txt", "implementation: 0x004b49fc", "ARM.exidx end: 0x004b4a20"),
        ("disasm_worldtileloader_cx_03.txt", "implementation: 0x004b52ac", "ARM.exidx end: 0x004b5300"),
        ("disasm_worldtileloader_cx_04.txt", "implementation: 0x004d0480", "ARM.exidx end: 0x004d04b4"),
        ("disasm_worldtileloader_cx_05.txt", "implementation: 0x004be068", "ARM.exidx end: 0x004be0d4"),
        ("disasm_worldtileloader_cx_06.txt", "implementation: 0x00582a14", "ARM.exidx end: 0x00582a50"),
        ("disasm_worldtileloader_cx_07.txt", "implementation: 0x004d0418", "ARM.exidx end: 0x004d0480"),
        ("disasm_worldtileloader_cx_08.txt", "implementation: 0x004d0d08", "ARM.exidx end: 0x004d0d60"),
        ("disasm_worldtileloader_cx_09.txt", "implementation: 0x004d0368", "ARM.exidx end: 0x004d0480"),
        ("disasm_worldtileloader_cx_10.txt", "implementation: 0x004c0b70", "ARM.exidx end: 0x004c0bc4"),
        ("disasm_worldtileloader_cx_11.txt", "implementation: 0x004d04b4", "ARM.exidx end: 0x004d0590"),
        ("disasm_worldtileloader_cx_12.txt", "implementation: 0x004bed60", "ARM.exidx end: 0x004bed90"),
        ("disasm_worldtileloader_cx_13.txt", "implementation: 0x004d5170", "ARM.exidx end: 0x004d5198"),
        ("disasm_worldtileloader_cx_14.txt", "implementation: 0x004d6538", "ARM.exidx end: 0x004d65e4"),
        ("disasm_worldtileloader_cx_15.txt", "implementation: 0x005ac12c", "ARM.exidx end: 0x005ac1a4"),
        ("disasm_worldtileloader_cx_16.txt", "implementation: 0x004da9cc", "ARM.exidx end: 0x004dad30"),
        ("disasm_worldtileloader_cx_17.txt", "implementation: 0x00575108", "ARM.exidx end: 0x005751f8"),
        ("disasm_worldtileloader_cx_18.txt", "implementation: 0x005be75c", "ARM.exidx end: 0x005be888"),
        ("disasm_worldtileloader_cx_19.txt", "implementation: 0x0057509c", "ARM.exidx end: 0x005751f8"),
        ("disasm_worldtileloader_cx_20.txt", "implementation: 0x005be888", "ARM.exidx end: 0x005be998"),
        ("disasm_worldtileloader_cx_21.txt", "implementation: 0x005bf2b4", "ARM.exidx end: 0x005bf528"),
        ("disasm_worldtileloader_cx_22.txt", "implementation: 0x005bf378", "ARM.exidx end: 0x005bf528"),
        ("disasm_worldtileloader_cx_23.txt", "implementation: 0x00668924", "ARM.exidx end: 0x006689d0"),
        ("disasm_worldtileloader_cx_24.txt", "implementation: 0x00820690", "ARM.exidx end: 0x008206f8"),
        ("disasm_worldtileloader_cx_25.txt", "implementation: 0x004d03c0", "ARM.exidx end: 0x004d0480"),
        ("disasm_worldtileloader_cx_26.txt", "implementation: 0x00a1179c", "ARM.exidx end: 0x00a118e4"),
        ("disasm_worldtileloader_cx_27.txt", "implementation: 0x00a11690", "ARM.exidx end: 0x00a116dc"),
        ("disasm_worldtileloader_cx_28.txt", "implementation: 0x00a126dc", "ARM.exidx end: 0x00a127cc"),
        ("disasm_worldtileloader_cx_29.txt", "implementation: 0x00a12760", "ARM.exidx end: 0x00a127cc"),
        ("disasm_worldtileloader_cx_30.txt", "implementation: 0x00a13214", "ARM.exidx end: 0x00a13694"),
        ("disasm_worldtileloader_cx_31.txt", "implementation: 0x00a128b0", "ARM.exidx end: 0x00a12bd8"),
        ("disasm_worldtileloader_cx_32.txt", "implementation: 0x00a138fc", "ARM.exidx end: 0x00a13a4c"),
        ("disasm_worldtileloader_cx_33.txt", "implementation: 0x00a12300", "ARM.exidx end: 0x00a12410"),
        ("disasm_worldtileloader_cx_34.txt", "implementation: 0x00a127cc", "ARM.exidx end: 0x00a128b0"),
        ("disasm_worldtileloader_cx_35.txt", "implementation: 0x00a14450", "ARM.exidx end: 0x00a146a0"),
        ("disasm_worldtileloader_cx_36.txt", "implementation: 0x00a13a4c", "ARM.exidx end: 0x00a13e6c"),
        ("disasm_worldtileloader_cx_37.txt", "implementation: 0x00a11390", "ARM.exidx end: 0x00a11690"),
        ("disasm_worldtileloader_cx_38.txt", "implementation: 0x00a12818", "ARM.exidx end: 0x00a128b0"),
        ("disasm_worldtileloader_cx_39.txt", "implementation: 0x00a13ce0", "ARM.exidx end: 0x00a13e6c"),
        ("disasm_worldtileloader_cx_40.txt", "implementation: 0x00a1436c", "ARM.exidx end: 0x00a143d8"),
        ("disasm_worldtileloader_cx_41.txt", "implementation: 0x00a14824", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_cx_42.txt", "implementation: 0x00a11818", "ARM.exidx end: 0x00a118e4"),
        ("disasm_worldtileloader_cx_43.txt", "implementation: 0x00a1234c", "ARM.exidx end: 0x00a12410"),
        ("disasm_worldtileloader_cx_44.txt", "implementation: 0x00a12864", "ARM.exidx end: 0x00a128b0"),
        ("disasm_worldtileloader_cx_45.txt", "implementation: 0x00a146a0", "ARM.exidx end: 0x00a14824"),
        ("disasm_worldtileloader_cx_46.txt", "implementation: 0x00a13694", "ARM.exidx end: 0x00a13778"),
        ("disasm_worldtileloader_cx_47.txt", "implementation: 0x00a12608", "ARM.exidx end: 0x00a126dc"),
        ("disasm_worldtileloader_cx_48.txt", "implementation: 0x00a12410", "ARM.exidx end: 0x00a12434"),
        ("disasm_worldtileloader_cx_49.txt", "implementation: 0x00a13778", "ARM.exidx end: 0x00a137e8"),
        ("disasm_worldtileloader_cx_50.txt", "implementation: 0x00a12f24", "ARM.exidx end: 0x00a13694"),
        ("disasm_worldtileloader_cx_51.txt", "implementation: 0x00a16e68", "ARM.exidx end: 0x00a170b4"),
        ("disasm_worldtileloader_cx_52.txt", "implementation: 0x00a156a8", "ARM.exidx end: 0x00a159c8"),
        ("disasm_worldtileloader_cx_53.txt", "implementation: 0x00a15838", "ARM.exidx end: 0x00a159c8"),
        ("disasm_worldtileloader_cx_54.txt", "implementation: 0x00a16ccc", "ARM.exidx end: 0x00a16e68"),
        ("disasm_worldtileloader_cx_55.txt", "implementation: 0x00a1770c", "ARM.exidx end: 0x00a17a70"),
        ("disasm_worldtileloader_cx_56.txt", "implementation: 0x00a16594", "ARM.exidx end: 0x00a16720"),
        ("disasm_worldtileloader_cx_57.txt", "implementation: 0x00a174a4", "ARM.exidx end: 0x00a17a70"),
        ("disasm_worldtileloader_cx_58.txt", "implementation: 0x00a173c4", "ARM.exidx end: 0x00a174a4"),
        ("disasm_worldtileloader_cx_59.txt", "implementation: 0x00a16944", "ARM.exidx end: 0x00a16ccc"),
        ("disasm_worldtileloader_cx_60.txt", "implementation: 0x00a15518", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_cx_61.txt", "implementation: 0x00a149f8", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_cx_62.txt", "implementation: 0x00a151d0", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_cx_63.txt", "implementation: 0x00a148b0", "ARM.exidx end: 0x00a155dc"),
        ("disasm_worldtileloader_cx_64.txt", "implementation: 0x008bcacc", "ARM.exidx end: 0x008bcb78"),
        ("disasm_worldtileloader_cx_65.txt", "implementation: 0x008b68ac", "ARM.exidx end: 0x008b6ac0"),
        ("disasm_worldtileloader_cx_66.txt", "implementation: 0x008ba904", "ARM.exidx end: 0x008ba928"),
        ("disasm_worldtileloader_cx_67.txt", "implementation: 0x00903420", "ARM.exidx end: 0x00903594"),
        ("disasm_worldtileloader_cx_68.txt", "implementation: 0x008b6a8c", "ARM.exidx end: 0x008b6ac0"),
        ("disasm_worldtileloader_cx_69.txt", "implementation: 0x008bc974", "ARM.exidx end: 0x008bcb78"),
        ("disasm_worldtileloader_cx_70.txt", "implementation: 0x008bca20", "ARM.exidx end: 0x008bcb78"),
        ("disasm_worldtileloader_cx_71.txt", "implementation: 0x008c4b74", "ARM.exidx end: 0x008c4c20"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "CAUX.md",
        [
            "15100",
            "dynamicObjectTypeForInteractionObjectType",
            "tameCountRequirementForNPCType",
            "0x1fe01",
            "GLKMathUnproject",
        ],
    )
    require(
        NATIVE / "caux.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1115',
            '"verified_words": 562',
            "objectType",
            "q_sort",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_cy_00.txt", "implementation: 0x00a1915c", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_01.txt", "implementation: 0x00a19670", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_02.txt", "implementation: 0x00a197b4", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_03.txt", "implementation: 0x00a19598", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_04.txt", "implementation: 0x00a18f68", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_05.txt", "implementation: 0x00a193a4", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_06.txt", "implementation: 0x00d948fc", "ARM.exidx end: 0x00d94c88"),
        ("disasm_worldtileloader_cy_07.txt", "implementation: 0x00d94c88", "ARM.exidx end: 0x00d960cc"),
        ("disasm_worldtileloader_cy_08.txt", "implementation: 0x00d91b30", "ARM.exidx end: 0x00d91c6c"),
        ("disasm_worldtileloader_cy_09.txt", "implementation: 0x00d91c6c", "ARM.exidx end: 0x00d9280c"),
        ("disasm_worldtileloader_cy_10.txt", "implementation: 0x00d96f5c", "ARM.exidx end: 0x00d98190"),
        ("disasm_worldtileloader_cy_11.txt", "implementation: 0x00d98190", "ARM.exidx end: 0x00d98d78"),
        ("disasm_worldtileloader_cy_12.txt", "implementation: 0x007c55e4", "ARM.exidx end: 0x007c59a0"),
        ("disasm_worldtileloader_cy_13.txt", "implementation: 0x007c57ec", "ARM.exidx end: 0x007c59a0"),
        ("disasm_worldtileloader_cy_14.txt", "implementation: 0x007c5238", "ARM.exidx end: 0x007c59a0"),
        ("disasm_worldtileloader_cy_15.txt", "implementation: 0x007c5438", "ARM.exidx end: 0x007c59a0"),
        ("disasm_worldtileloader_cy_16.txt", "implementation: 0x007c43dc", "ARM.exidx end: 0x007c4554"),
        ("disasm_worldtileloader_cy_17.txt", "implementation: 0x007c4790", "ARM.exidx end: 0x007c4860"),
        ("disasm_worldtileloader_cy_18.txt", "implementation: 0x004d6820", "ARM.exidx end: 0x004d71dc"),
        ("disasm_worldtileloader_cy_19.txt", "implementation: 0x004d6040", "ARM.exidx end: 0x004d6128"),
        ("disasm_worldtileloader_cy_20.txt", "implementation: 0x004c0bd4", "ARM.exidx end: 0x004c1e84"),
        ("disasm_worldtileloader_cy_21.txt", "implementation: 0x00854138", "ARM.exidx end: 0x008546e0"),
        ("disasm_worldtileloader_cy_22.txt", "implementation: 0x004c1e84", "ARM.exidx end: 0x004c1f84"),
        ("disasm_worldtileloader_cy_23.txt", "implementation: 0x00b597bc", "ARM.exidx end: 0x00b5aa24"),
        ("disasm_worldtileloader_cy_24.txt", "implementation: 0x005f3f50", "ARM.exidx end: 0x005f4218"),
        ("disasm_worldtileloader_cy_25.txt", "implementation: 0x008bc89c", "ARM.exidx end: 0x008bc974"),
        ("disasm_worldtileloader_cy_26.txt", "implementation: 0x006495a0", "ARM.exidx end: 0x00649670"),
        ("disasm_worldtileloader_cy_27.txt", "implementation: 0x006437e4", "ARM.exidx end: 0x00643a68"),
        ("disasm_worldtileloader_cy_28.txt", "implementation: 0x0064be74", "ARM.exidx end: 0x0064bf30"),
        ("disasm_worldtileloader_cy_29.txt", "implementation: 0x006caf24", "ARM.exidx end: 0x006cb018"),
        ("disasm_worldtileloader_cy_30.txt", "implementation: 0x00580e5c", "ARM.exidx end: 0x00580f24"),
        ("disasm_worldtileloader_cy_31.txt", "implementation: 0x00a653d8", "ARM.exidx end: 0x00a654f4"),
        ("disasm_worldtileloader_cy_32.txt", "implementation: 0x008e4b2c", "ARM.exidx end: 0x008e4c98"),
        ("disasm_worldtileloader_cy_33.txt", "implementation: 0x008e4c98", "ARM.exidx end: 0x008e4e44"),
        ("disasm_worldtileloader_cy_34.txt", "implementation: 0x008c3a88", "ARM.exidx end: 0x008c3c08"),
        ("disasm_worldtileloader_cy_35.txt", "implementation: 0x004ea3cc", "ARM.exidx end: 0x004ea4c0"),
        ("disasm_worldtileloader_cy_36.txt", "implementation: 0x0056871c", "ARM.exidx end: 0x0056884c"),
        ("disasm_worldtileloader_cy_37.txt", "implementation: 0x005b902c", "ARM.exidx end: 0x005b90c0"),
        ("disasm_worldtileloader_cy_38.txt", "implementation: 0x004d6128", "ARM.exidx end: 0x004d6260"),
        ("disasm_worldtileloader_cy_39.txt", "implementation: 0x0057b5e4", "ARM.exidx end: 0x0057b630"),
        ("disasm_worldtileloader_cy_40.txt", "implementation: 0x0057b630", "ARM.exidx end: 0x0057b6bc"),
        ("disasm_worldtileloader_cy_41.txt", "implementation: 0x0057b6bc", "ARM.exidx end: 0x0057b700"),
        ("disasm_worldtileloader_cy_42.txt", "implementation: 0x005b291c", "ARM.exidx end: 0x005b2aa0"),
        ("disasm_worldtileloader_cy_43.txt", "implementation: 0x005b2b0c", "ARM.exidx end: 0x005b2ca0"),
        ("disasm_worldtileloader_cy_44.txt", "implementation: 0x004cc11c", "ARM.exidx end: 0x004cc4a4"),
        ("disasm_worldtileloader_cy_45.txt", "implementation: 0x004daf58", "ARM.exidx end: 0x004db268"),
        ("disasm_worldtileloader_cy_46.txt", "implementation: 0x0057bd18", "ARM.exidx end: 0x0057bd70"),
        ("disasm_worldtileloader_cy_47.txt", "implementation: 0x00580be0", "ARM.exidx end: 0x00580e5c"),
        ("disasm_worldtileloader_cy_48.txt", "implementation: 0x00580c20", "ARM.exidx end: 0x00580e5c"),
        ("disasm_worldtileloader_cy_49.txt", "implementation: 0x00580cdc", "ARM.exidx end: 0x00580e5c"),
        ("disasm_worldtileloader_cy_50.txt", "implementation: 0x00580f24", "ARM.exidx end: 0x00580f88"),
        ("disasm_worldtileloader_cy_51.txt", "implementation: 0x005b23b8", "ARM.exidx end: 0x005b2aa0"),
        ("disasm_worldtileloader_cy_52.txt", "implementation: 0x005b2aa0", "ARM.exidx end: 0x005b2b0c"),
        ("disasm_worldtileloader_cy_53.txt", "implementation: 0x005b2ad4", "ARM.exidx end: 0x005b2b0c"),
        ("disasm_worldtileloader_cy_54.txt", "implementation: 0x005b2ca0", "ARM.exidx end: 0x005b30c8"),
        ("disasm_worldtileloader_cy_55.txt", "implementation: 0x005df794", "ARM.exidx end: 0x005df88c"),
        ("disasm_worldtileloader_cy_56.txt", "implementation: 0x00a118e4", "ARM.exidx end: 0x00a1229c"),
        ("disasm_worldtileloader_cy_57.txt", "implementation: 0x00a15e28", "ARM.exidx end: 0x00a16594"),
        ("disasm_worldtileloader_cy_58.txt", "implementation: 0x00a10a48", "ARM.exidx end: 0x00a11690"),
        ("disasm_worldtileloader_cy_59.txt", "implementation: 0x00a18044", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cy_60.txt", "implementation: 0x004b4444", "ARM.exidx end: 0x004b49fc"),
        ("disasm_worldtileloader_cy_61.txt", "implementation: 0x00db222c", "ARM.exidx end: 0x00db2690"),
        ("disasm_worldtileloader_cy_62.txt", "implementation: 0x00aed208", "ARM.exidx end: 0x00aed318"),
        ("disasm_worldtileloader_cy_63.txt", "implementation: 0x00582e00", "ARM.exidx end: 0x00582eb4"),
        ("disasm_worldtileloader_cy_64.txt", "implementation: 0x00668a34", "ARM.exidx end: 0x00668cc8"),
        ("disasm_worldtileloader_cy_65.txt", "implementation: 0x008546e0", "ARM.exidx end: 0x0085475c"),
        ("disasm_worldtileloader_cy_66.txt", "implementation: 0x00c38b6c", "ARM.exidx end: 0x00c38c4c"),
        ("disasm_worldtileloader_cy_67.txt", "implementation: 0x005aa394", "ARM.exidx end: 0x005aa3b0"),
        ("disasm_worldtileloader_cy_68.txt", "implementation: 0x0058198c", "ARM.exidx end: 0x00581a38"),
        ("disasm_worldtileloader_cy_69.txt", "implementation: 0x0020ca1c", "ARM.exidx end: 0x0020d2e4"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "CZERO.md",
        [
            "34140",
            "blockheadNamesInit",
            "checkCanEnterTile",
            "999999",
            "init_by_array",
            "tileContainsUsableDoor",
        ],
    )
    require(
        NATIVE / "czero.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 17646',
            '"verified_words": 6200',
            "genrand_res53",
            "clearLineOfSightBetweenTiles",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_cz_00.txt", "implementation: 0x00cc7690", "ARM.exidx end: 0x00cd8a48"),
        ("disasm_worldtileloader_cz_01.txt", "implementation: 0x00bde520", "ARM.exidx end: 0x00be4600"),
        ("disasm_worldtileloader_cz_02.txt", "implementation: 0x00b2bba0", "ARM.exidx end: 0x00b2d808"),
        ("disasm_worldtileloader_cz_03.txt", "implementation: 0x005f85a0", "ARM.exidx end: 0x005f9ae4"),
        ("disasm_worldtileloader_cz_04.txt", "implementation: 0x00d92db0", "ARM.exidx end: 0x00d94218"),
        ("disasm_worldtileloader_cz_05.txt", "implementation: 0x00be4600", "ARM.exidx end: 0x00be5420"),
        ("disasm_worldtileloader_cz_06.txt", "implementation: 0x007c4860", "ARM.exidx end: 0x007c4e48"),
        ("disasm_worldtileloader_cz_07.txt", "implementation: 0x00d94218", "ARM.exidx end: 0x00d94700"),
        ("disasm_worldtileloader_cz_08.txt", "implementation: 0x007c4e48", "ARM.exidx end: 0x007c5238"),
        ("disasm_worldtileloader_cz_09.txt", "implementation: 0x006a4b18", "ARM.exidx end: 0x006a4ef0"),
        ("disasm_worldtileloader_cz_10.txt", "implementation: 0x007c3a6c", "ARM.exidx end: 0x007c3e00"),
        ("disasm_worldtileloader_cz_11.txt", "implementation: 0x007c3f18", "ARM.exidx end: 0x007c4290"),
        ("disasm_worldtileloader_cz_12.txt", "implementation: 0x0086915c", "ARM.exidx end: 0x00869520"),
        ("disasm_worldtileloader_cz_13.txt", "implementation: 0x007c37dc", "ARM.exidx end: 0x007c3a6c"),
        ("disasm_worldtileloader_cz_14.txt", "implementation: 0x0096a4e8", "ARM.exidx end: 0x0096a768"),
        ("disasm_worldtileloader_cz_15.txt", "implementation: 0x00c37b58", "ARM.exidx end: 0x00c37d3c"),
        ("disasm_worldtileloader_cz_16.txt", "implementation: 0x00a15a74", "ARM.exidx end: 0x00a15e28"),
        ("disasm_worldtileloader_cz_17.txt", "implementation: 0x00a12434", "ARM.exidx end: 0x00a12608"),
        ("disasm_worldtileloader_cz_18.txt", "implementation: 0x00a15c54", "ARM.exidx end: 0x00a15e28"),
        ("disasm_worldtileloader_cz_19.txt", "implementation: 0x00a178f8", "ARM.exidx end: 0x00a17a70"),
        ("disasm_worldtileloader_cz_20.txt", "implementation: 0x007c4290", "ARM.exidx end: 0x007c4554"),
        ("disasm_worldtileloader_cz_21.txt", "implementation: 0x009176f8", "ARM.exidx end: 0x00917818"),
        ("disasm_worldtileloader_cz_22.txt", "implementation: 0x007c3e00", "ARM.exidx end: 0x007c3f18"),
        ("disasm_worldtileloader_cz_23.txt", "implementation: 0x00a137e8", "ARM.exidx end: 0x00a138fc"),
        ("disasm_worldtileloader_cz_24.txt", "implementation: 0x0096ab6c", "ARM.exidx end: 0x0096ac78"),
        ("disasm_worldtileloader_cz_25.txt", "implementation: 0x005effb8", "ARM.exidx end: 0x005f00c4"),
        ("disasm_worldtileloader_cz_26.txt", "implementation: 0x0096aa6c", "ARM.exidx end: 0x0096ab6c"),
        ("disasm_worldtileloader_cz_27.txt", "implementation: 0x0096ad40", "ARM.exidx end: 0x0096ae78"),
        ("disasm_worldtileloader_cz_28.txt", "implementation: 0x0096ac78", "ARM.exidx end: 0x0096ae78"),
        ("disasm_worldtileloader_cz_29.txt", "implementation: 0x00a7ffd0", "ARM.exidx end: 0x00a80178"),
        ("disasm_worldtileloader_cz_30.txt", "implementation: 0x00a159c8", "ARM.exidx end: 0x00a15a74"),
        ("disasm_worldtileloader_cz_31.txt", "implementation: 0x00a143d8", "ARM.exidx end: 0x00a146a0"),
        ("disasm_worldtileloader_cz_32.txt", "implementation: 0x0096ae10", "ARM.exidx end: 0x0096ae78"),
        ("disasm_worldtileloader_cz_33.txt", "implementation: 0x009fdf50", "ARM.exidx end: 0x009fdf68"),
        ("disasm_worldtileloader_cz_34.txt", "implementation: 0x00663254", "ARM.exidx end: 0x0066326c"),
        ("disasm_worldtileloader_cz_35.txt", "implementation: 0x00a19820", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cz_36.txt", "implementation: 0x00a30e68", "ARM.exidx end: 0x00a31308"),
        ("disasm_worldtileloader_cz_37.txt", "implementation: 0x00a12bd8", "ARM.exidx end: 0x00a12f24"),
        ("disasm_worldtileloader_cz_38.txt", "implementation: 0x007c4554", "ARM.exidx end: 0x007c4790"),
        ("disasm_worldtileloader_cz_39.txt", "implementation: 0x00a1311c", "ARM.exidx end: 0x00a13694"),
        ("disasm_worldtileloader_cz_40.txt", "implementation: 0x00a12b04", "ARM.exidx end: 0x00a12bd8"),
        ("disasm_worldtileloader_cz_41.txt", "implementation: 0x00a31284", "ARM.exidx end: 0x00a31308"),
        ("disasm_worldtileloader_cz_42.txt", "implementation: 0x00a19604", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cz_43.txt", "implementation: 0x00a19748", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cz_44.txt", "implementation: 0x00a196dc", "ARM.exidx end: 0x00a19c0c"),
        ("disasm_worldtileloader_cz_45.txt", "implementation: 0x006689d0", "ARM.exidx end: 0x00668a34"),
        ("disasm_worldtileloader_cz_46.txt", "implementation: 0x00bb4798", "ARM.exidx end: 0x00bb564c"),
        ("disasm_worldtileloader_cz_47.txt", "implementation: 0x00a3124c", "ARM.exidx end: 0x00a31308"),
        ("disasm_worldtileloader_cz_48.txt", "implementation: 0x00ce8dd8", "ARM.exidx end: 0x00ce8dec"),
        ("disasm_worldtileloader_cz_49.txt", "implementation: 0x00a31b44", "ARM.exidx end: 0x00a31da4"),
        ("disasm_worldtileloader_cz_50.txt", "implementation: 0x00a1295c", "ARM.exidx end: 0x00a12bd8"),
        ("disasm_worldtileloader_cz_51.txt", "implementation: 0x00a12a30", "ARM.exidx end: 0x00a12bd8"),
        ("disasm_worldtileloader_cz_52.txt", "implementation: 0x00a116dc", "ARM.exidx end: 0x00a1179c"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "BLOCKHEAD.md",
        [
            "44419",
            "Blockhead",
            "37,886",
            "0x116",
            "checkCanEnterTile",
        ],
    )
    require(
        NATIVE / "blockhead.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 37886',
            '"verified_words": 1092',
            "dpadFindPath",
            "tileIsSolid",
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_hd_00.txt", "implementation: 0x00c7af40", "ARM.exidx end: 0x00c7afc8"),
        ("disasm_worldtileloader_hd_01.txt", "implementation: 0x00bb564c", "ARM.exidx end: 0x00bb5740"),
        ("disasm_worldtileloader_hd_02.txt", "implementation: 0x00bb51c0", "ARM.exidx end: 0x00bb564c"),
        ("disasm_worldtileloader_hd_03.txt", "implementation: 0x00bb4cfc", "ARM.exidx end: 0x00bb564c"),
        ("disasm_worldtileloader_hd_04.txt", "implementation: 0x00b8c850", "ARM.exidx end: 0x00b8c910"),
        ("disasm_worldtileloader_hd_05.txt", "implementation: 0x00bb5740", "ARM.exidx end: 0x00bb63b8"),
        ("disasm_worldtileloader_hd_06.txt", "implementation: 0x00c82a88", "ARM.exidx end: 0x00c82e90"),
        ("disasm_worldtileloader_hd_07.txt", "implementation: 0x00b8caf8", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hd_08.txt", "implementation: 0x00b8c910", "ARM.exidx end: 0x00b8c9b8"),
        ("disasm_worldtileloader_hd_09.txt", "implementation: 0x00b8c8d0", "ARM.exidx end: 0x00b8c910"),
        ("disasm_worldtileloader_hd_10.txt", "implementation: 0x00b8c890", "ARM.exidx end: 0x00b8c910"),
        ("disasm_worldtileloader_hd_11.txt", "implementation: 0x00b8c810", "ARM.exidx end: 0x00b8c910"),
        ("disasm_worldtileloader_hd_12.txt", "implementation: 0x00b8cb38", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hd_13.txt", "implementation: 0x00c82104", "ARM.exidx end: 0x00c8219c"),
        ("disasm_worldtileloader_hd_14.txt", "implementation: 0x00c7afc8", "ARM.exidx end: 0x00c7b054"),
        ("disasm_worldtileloader_hd_15.txt", "implementation: 0x00b8c9b8", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hd_16.txt", "implementation: 0x00bb6e68", "ARM.exidx end: 0x00bb7054"),
        ("disasm_worldtileloader_hd_17.txt", "implementation: 0x00bb6b48", "ARM.exidx end: 0x00bb6e68"),
        ("disasm_worldtileloader_hd_18.txt", "implementation: 0x00bb7054", "ARM.exidx end: 0x00bb7114"),
        ("disasm_worldtileloader_hd_19.txt", "implementation: 0x00c7b15c", "ARM.exidx end: 0x00c7b2d8"),
        ("disasm_worldtileloader_hd_20.txt", "implementation: 0x00c7b054", "ARM.exidx end: 0x00c7b0a0"),
        ("disasm_worldtileloader_hd_21.txt", "implementation: 0x00bec89c", "ARM.exidx end: 0x00bed9ac"),
        ("disasm_worldtileloader_hd_22.txt", "implementation: 0x00c82a2c", "ARM.exidx end: 0x00c82a4c"),
        ("disasm_worldtileloader_hd_23.txt", "implementation: 0x00c8a3c0", "ARM.exidx end: 0x00c8a3fc"),
        ("disasm_worldtileloader_hd_24.txt", "implementation: 0x00c8a3fc", "ARM.exidx end: 0x00c8a484"),
        ("disasm_worldtileloader_hd_25.txt", "implementation: 0x00c7b2d8", "ARM.exidx end: 0x00c7b31c"),
        ("disasm_worldtileloader_hd_26.txt", "implementation: 0x00c7b018", "ARM.exidx end: 0x00c7b054"),
        ("disasm_worldtileloader_hd_27.txt", "implementation: 0x00b8cb90", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hd_28.txt", "implementation: 0x00c81cd8", "ARM.exidx end: 0x00c820e8"),
        ("disasm_worldtileloader_hd_29.txt", "implementation: 0x00c82f18", "ARM.exidx end: 0x00c82fc4"),
        ("disasm_worldtileloader_hd_30.txt", "implementation: 0x00c820e8", "ARM.exidx end: 0x00c82104"),
        ("disasm_worldtileloader_hd_31.txt", "implementation: 0x00bb47d0", "ARM.exidx end: 0x00bb564c"),
        ("disasm_worldtileloader_hd_32.txt", "implementation: 0x00bb63b8", "ARM.exidx end: 0x00bb6b48"),
        ("disasm_worldtileloader_hd_33.txt", "implementation: 0x00c8a588", "ARM.exidx end: 0x00c8a600"),
        ("disasm_worldtileloader_hd_34.txt", "implementation: 0x00bb8fe0", "ARM.exidx end: 0x00bb91a8"),
        ("disasm_worldtileloader_hd_35.txt", "implementation: 0x00c79510", "ARM.exidx end: 0x00c79598"),
        ("disasm_worldtileloader_hd_36.txt", "implementation: 0x00c7b0a0", "ARM.exidx end: 0x00c7b15c"),
        ("disasm_worldtileloader_hd_37.txt", "implementation: 0x00c87bc8", "ARM.exidx end: 0x00c87be8"),
        ("disasm_worldtileloader_hd_38.txt", "implementation: 0x00bb8e54", "ARM.exidx end: 0x00bb8fa4"),
        ("disasm_worldtileloader_hd_39.txt", "implementation: 0x00c7adbc", "ARM.exidx end: 0x00c7af40"),
        ("disasm_worldtileloader_hd_40.txt", "implementation: 0x00c86934", "ARM.exidx end: 0x00c86e4c"),
        ("disasm_worldtileloader_hd_41.txt", "implementation: 0x00b8cbd0", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hd_42.txt", "implementation: 0x00c828c4", "ARM.exidx end: 0x00c82900"),
        ("disasm_worldtileloader_hd_43.txt", "implementation: 0x00c86548", "ARM.exidx end: 0x00c86584"),
        ("disasm_worldtileloader_hd_44.txt", "implementation: 0x00c80de0", "ARM.exidx end: 0x00c80e34"),
        ("disasm_worldtileloader_hd_45.txt", "implementation: 0x00bac054", "ARM.exidx end: 0x00bac0a4"),
        ("disasm_worldtileloader_hd_46.txt", "implementation: 0x00bac004", "ARM.exidx end: 0x00bac0a4"),
        ("disasm_worldtileloader_hd_47.txt", "implementation: 0x00bac624", "ARM.exidx end: 0x00bac674"),
        ("disasm_worldtileloader_hd_48.txt", "implementation: 0x00c8a4c0", "ARM.exidx end: 0x00c8a4fc"),
        ("disasm_worldtileloader_hd_49.txt", "implementation: 0x00c8a4fc", "ARM.exidx end: 0x00c8a588"),
        ("disasm_worldtileloader_hd_50.txt", "implementation: 0x00c69920", "ARM.exidx end: 0x00c6a070"),
        ("disasm_worldtileloader_hd_51.txt", "implementation: 0x00c7c4a8", "ARM.exidx end: 0x00c7c5f0"),
        ("disasm_worldtileloader_hd_52.txt", "implementation: 0x00c805c0", "ARM.exidx end: 0x00c80940"),
        ("disasm_worldtileloader_hd_53.txt", "implementation: 0x00c8a5c4", "ARM.exidx end: 0x00c8a600"),
        ("disasm_worldtileloader_hd_54.txt", "implementation: 0x00c8a600", "ARM.exidx end: 0x00c8a688"),
        ("disasm_worldtileloader_hd_55.txt", "implementation: 0x00c82e90", "ARM.exidx end: 0x00c82f18"),
        ("disasm_worldtileloader_hd_56.txt", "implementation: 0x00c8a090", "ARM.exidx end: 0x00c8a0d4"),
        ("disasm_worldtileloader_hd_57.txt", "implementation: 0x00c86584", "ARM.exidx end: 0x00c867d8"),
        ("disasm_worldtileloader_hd_58.txt", "implementation: 0x00c87b8c", "ARM.exidx end: 0x00c87be8"),
        ("disasm_worldtileloader_hd_59.txt", "implementation: 0x00c87a60", "ARM.exidx end: 0x00c87b8c"),
        ("disasm_worldtileloader_hd_60.txt", "implementation: 0x00bb9238", "ARM.exidx end: 0x00bde230"),
        ("disasm_worldtileloader_hd_61.txt", "implementation: 0x00c8a768", "ARM.exidx end: 0x00c8aa70"),
        ("disasm_worldtileloader_hd_62.txt", "implementation: 0x00c8a6e8", "ARM.exidx end: 0x00c8a768"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "BLOCKHEAD2.md",
        [
            "32709",
                        '28-arm jump table',
            'jetpack',
            '0x4000',
            'toolBreak.wav',
        ],
    )
    require(
        NATIVE / "blockhead2.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 8735',
            '"verified_words": 4047',
            '0x666',
            'interactionTestResult',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_hb_00.txt", "implementation: 0x00c87be8", "ARM.exidx end: 0x00c881f8"),
        ("disasm_worldtileloader_hb_01.txt", "implementation: 0x00c803b8", "ARM.exidx end: 0x00c8041c"),
        ("disasm_worldtileloader_hb_02.txt", "implementation: 0x00c8a644", "ARM.exidx end: 0x00c8a688"),
        ("disasm_worldtileloader_hb_03.txt", "implementation: 0x00c81f74", "ARM.exidx end: 0x00c820e8"),
        ("disasm_worldtileloader_hb_04.txt", "implementation: 0x00c833bc", "ARM.exidx end: 0x00c837b8"),
        ("disasm_worldtileloader_hb_05.txt", "implementation: 0x00ba9d8c", "ARM.exidx end: 0x00baa1dc"),
        ("disasm_worldtileloader_hb_06.txt", "implementation: 0x00c7cde8", "ARM.exidx end: 0x00c7d2b8"),
        ("disasm_worldtileloader_hb_07.txt", "implementation: 0x00c5ec34", "ARM.exidx end: 0x00c5f4c0"),
        ("disasm_worldtileloader_hb_08.txt", "implementation: 0x00c644e4", "ARM.exidx end: 0x00c6455c"),
        ("disasm_worldtileloader_hb_09.txt", "implementation: 0x00c638dc", "ARM.exidx end: 0x00c64428"),
        ("disasm_worldtileloader_hb_10.txt", "implementation: 0x00c73100", "ARM.exidx end: 0x00c731c4"),
        ("disasm_worldtileloader_hb_11.txt", "implementation: 0x00c88c08", "ARM.exidx end: 0x00c89c2c"),
        ("disasm_worldtileloader_hb_12.txt", "implementation: 0x00c89c2c", "ARM.exidx end: 0x00c89c48"),
        ("disasm_worldtileloader_hb_13.txt", "implementation: 0x00bac27c", "ARM.exidx end: 0x00bac528"),
        ("disasm_worldtileloader_hb_14.txt", "implementation: 0x00baa1dc", "ARM.exidx end: 0x00baa364"),
        ("disasm_worldtileloader_hb_15.txt", "implementation: 0x00c8015c", "ARM.exidx end: 0x00c8041c"),
        ("disasm_worldtileloader_hb_16.txt", "implementation: 0x00baa364", "ARM.exidx end: 0x00baa3a0"),
        ("disasm_worldtileloader_hb_17.txt", "implementation: 0x00baa3a0", "ARM.exidx end: 0x00baa488"),
        ("disasm_worldtileloader_hb_18.txt", "implementation: 0x00bb3488", "ARM.exidx end: 0x00bb4798"),
        ("disasm_worldtileloader_hb_19.txt", "implementation: 0x00bac194", "ARM.exidx end: 0x00bac27c"),
        ("disasm_worldtileloader_hb_20.txt", "implementation: 0x00b9ea28", "ARM.exidx end: 0x00b9ffe4"),
        ("disasm_worldtileloader_hb_21.txt", "implementation: 0x00ba097c", "ARM.exidx end: 0x00ba0ed8"),
        ("disasm_worldtileloader_hb_22.txt", "implementation: 0x00bacd0c", "ARM.exidx end: 0x00bae370"),
        ("disasm_worldtileloader_hb_23.txt", "implementation: 0x00c800e4", "ARM.exidx end: 0x00c8041c"),
        ("disasm_worldtileloader_hb_24.txt", "implementation: 0x00c7d2b8", "ARM.exidx end: 0x00c7d590"),
        ("disasm_worldtileloader_hb_25.txt", "implementation: 0x00c74e24", "ARM.exidx end: 0x00c75364"),
        ("disasm_worldtileloader_hb_26.txt", "implementation: 0x00c82628", "ARM.exidx end: 0x00c828c4"),
        ("disasm_worldtileloader_hb_27.txt", "implementation: 0x00c881f8", "ARM.exidx end: 0x00c88c08"),
        ("disasm_worldtileloader_hb_28.txt", "implementation: 0x00c89c48", "ARM.exidx end: 0x00c89e3c"),
        ("disasm_worldtileloader_hb_29.txt", "implementation: 0x00c6dd30", "ARM.exidx end: 0x00c6e54c"),
        ("disasm_worldtileloader_hb_30.txt", "implementation: 0x00c6e6b0", "ARM.exidx end: 0x00c6ebc0"),
        ("disasm_worldtileloader_hb_31.txt", "implementation: 0x00c6cb54", "ARM.exidx end: 0x00c6cd08"),
        ("disasm_worldtileloader_hb_32.txt", "implementation: 0x00c6be48", "ARM.exidx end: 0x00c6becc"),
        ("disasm_worldtileloader_hb_33.txt", "implementation: 0x00c6becc", "ARM.exidx end: 0x00c6cb00"),
        ("disasm_worldtileloader_hb_34.txt", "implementation: 0x00b91e08", "ARM.exidx end: 0x00b95d44"),
        ("disasm_worldtileloader_hb_35.txt", "implementation: 0x00c82a4c", "ARM.exidx end: 0x00c82a88"),
        ("disasm_worldtileloader_hb_36.txt", "implementation: 0x00bac728", "ARM.exidx end: 0x00bac764"),
        ("disasm_worldtileloader_hb_37.txt", "implementation: 0x00ba0fe0", "ARM.exidx end: 0x00ba985c"),
        ("disasm_worldtileloader_hb_38.txt", "implementation: 0x00bac158", "ARM.exidx end: 0x00bac194"),
        ("disasm_worldtileloader_hb_39.txt", "implementation: 0x00c67a58", "ARM.exidx end: 0x00c683c0"),
        ("disasm_worldtileloader_hb_40.txt", "implementation: 0x00c837b8", "ARM.exidx end: 0x00c83864"),
        ("disasm_worldtileloader_hb_41.txt", "implementation: 0x00c82fc4", "ARM.exidx end: 0x00c833bc"),
        ("disasm_worldtileloader_hb_42.txt", "implementation: 0x00b9b6a0", "ARM.exidx end: 0x00b9b86c"),
        ("disasm_worldtileloader_hb_43.txt", "implementation: 0x00c7d680", "ARM.exidx end: 0x00c80034"),
        ("disasm_worldtileloader_hb_44.txt", "implementation: 0x00c7d590", "ARM.exidx end: 0x00c7d680"),
        ("disasm_worldtileloader_hb_45.txt", "implementation: 0x00c74c70", "ARM.exidx end: 0x00c74e24"),
        ("disasm_worldtileloader_hb_46.txt", "implementation: 0x00bac674", "ARM.exidx end: 0x00bac728"),
        ("disasm_worldtileloader_hb_47.txt", "implementation: 0x00bac0a4", "ARM.exidx end: 0x00bac158"),
        ("disasm_worldtileloader_hb_48.txt", "implementation: 0x00c5c9f0", "ARM.exidx end: 0x00c5d748"),
        ("disasm_worldtileloader_hb_49.txt", "implementation: 0x00bb0e70", "ARM.exidx end: 0x00bb2c6c"),
        ("disasm_worldtileloader_hb_50.txt", "implementation: 0x00c80940", "ARM.exidx end: 0x00c80b84"),
        ("disasm_worldtileloader_hb_51.txt", "implementation: 0x00bb2c6c", "ARM.exidx end: 0x00bb3468"),
        ("disasm_worldtileloader_hb_52.txt", "implementation: 0x00c7c320", "ARM.exidx end: 0x00c7c4a8"),
        ("disasm_worldtileloader_hb_53.txt", "implementation: 0x00babab0", "ARM.exidx end: 0x00bac004"),
        ("disasm_worldtileloader_hb_54.txt", "implementation: 0x00bab850", "ARM.exidx end: 0x00bac004"),
        ("disasm_worldtileloader_hb_55.txt", "implementation: 0x00babc70", "ARM.exidx end: 0x00bac004"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "BLOCKHEAD3.md",
        [
            "42091",
                        'inventory model',
            'selectedToolIndex',
            '0xc5eaa8',
            '0xa6',
        ],
    )
    require(
        NATIVE / "blockhead3.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 11170',
            '"verified_words": 4618',
            'totalCash',
            'selectedToolIndex',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_hc_00.txt", "implementation: 0x00c80fec", "ARM.exidx end: 0x00c811e0"),
        ("disasm_worldtileloader_hc_01.txt", "implementation: 0x00b9b86c", "ARM.exidx end: 0x00b9ba78"),
        ("disasm_worldtileloader_hc_02.txt", "implementation: 0x00b9d894", "ARM.exidx end: 0x00b9dedc"),
        ("disasm_worldtileloader_hc_03.txt", "implementation: 0x00c73804", "ARM.exidx end: 0x00c73b38"),
        ("disasm_worldtileloader_hc_04.txt", "implementation: 0x00c73288", "ARM.exidx end: 0x00c73518"),
        ("disasm_worldtileloader_hc_05.txt", "implementation: 0x00c73b38", "ARM.exidx end: 0x00c73d6c"),
        ("disasm_worldtileloader_hc_06.txt", "implementation: 0x00c8a688", "ARM.exidx end: 0x00c8a6e8"),
        ("disasm_worldtileloader_hc_07.txt", "implementation: 0x00c49968", "ARM.exidx end: 0x00c547f0"),
        ("disasm_worldtileloader_hc_08.txt", "implementation: 0x00c71800", "ARM.exidx end: 0x00c71fa0"),
        ("disasm_worldtileloader_hc_09.txt", "implementation: 0x00c80fb0", "ARM.exidx end: 0x00c80fec"),
        ("disasm_worldtileloader_hc_10.txt", "implementation: 0x00c7bb4c", "ARM.exidx end: 0x00c7bd30"),
        ("disasm_worldtileloader_hc_11.txt", "implementation: 0x00bb3468", "ARM.exidx end: 0x00bb3488"),
        ("disasm_worldtileloader_hc_12.txt", "implementation: 0x00c86434", "ARM.exidx end: 0x00c86548"),
        ("disasm_worldtileloader_hc_13.txt", "implementation: 0x00c863e0", "ARM.exidx end: 0x00c86434"),
        ("disasm_worldtileloader_hc_14.txt", "implementation: 0x00c867d8", "ARM.exidx end: 0x00c86e4c"),
        ("disasm_worldtileloader_hc_15.txt", "implementation: 0x00c6cb00", "ARM.exidx end: 0x00c6cb54"),
        ("disasm_worldtileloader_hc_16.txt", "implementation: 0x00c6cd08", "ARM.exidx end: 0x00c6d618"),
        ("disasm_worldtileloader_hc_17.txt", "implementation: 0x00c6d618", "ARM.exidx end: 0x00c6dd30"),
        ("disasm_worldtileloader_hc_18.txt", "implementation: 0x00b95fe4", "ARM.exidx end: 0x00b9a80c"),
        ("disasm_worldtileloader_hc_19.txt", "implementation: 0x00c638a0", "ARM.exidx end: 0x00c638dc"),
        ("disasm_worldtileloader_hc_20.txt", "implementation: 0x00c64ca4", "ARM.exidx end: 0x00c65204"),
        ("disasm_worldtileloader_hc_21.txt", "implementation: 0x00c7156c", "ARM.exidx end: 0x00c7162c"),
        ("disasm_worldtileloader_hc_22.txt", "implementation: 0x00c6ebc0", "ARM.exidx end: 0x00c7156c"),
        ("disasm_worldtileloader_hc_23.txt", "implementation: 0x00bac9e4", "ARM.exidx end: 0x00bacd0c"),
        ("disasm_worldtileloader_hc_24.txt", "implementation: 0x00c6a070", "ARM.exidx end: 0x00c6a4f8"),
        ("disasm_worldtileloader_hc_25.txt", "implementation: 0x00c72628", "ARM.exidx end: 0x00c730d0"),
        ("disasm_worldtileloader_hc_26.txt", "implementation: 0x00c71fa0", "ARM.exidx end: 0x00c722e8"),
        ("disasm_worldtileloader_hc_27.txt", "implementation: 0x00bb8fa4", "ARM.exidx end: 0x00bb8fe0"),
        ("disasm_worldtileloader_hc_28.txt", "implementation: 0x00be91fc", "ARM.exidx end: 0x00bec7ec"),
        ("disasm_worldtileloader_hc_29.txt", "implementation: 0x00bb0a1c", "ARM.exidx end: 0x00bb0e70"),
        ("disasm_worldtileloader_hc_30.txt", "implementation: 0x00be5d40", "ARM.exidx end: 0x00be91fc"),
        ("disasm_worldtileloader_hc_31.txt", "implementation: 0x00c69424", "ARM.exidx end: 0x00c69920"),
        ("disasm_worldtileloader_hc_32.txt", "implementation: 0x00c68f4c", "ARM.exidx end: 0x00c69424"),
        ("disasm_worldtileloader_hc_33.txt", "implementation: 0x00be5854", "ARM.exidx end: 0x00be5d40"),
        ("disasm_worldtileloader_hc_34.txt", "implementation: 0x00bb8d6c", "ARM.exidx end: 0x00bb8fa4"),
        ("disasm_worldtileloader_hc_35.txt", "implementation: 0x00c7ca5c", "ARM.exidx end: 0x00c7cde8"),
        ("disasm_worldtileloader_hc_36.txt", "implementation: 0x00c746d0", "ARM.exidx end: 0x00c74c70"),
        ("disasm_worldtileloader_hc_37.txt", "implementation: 0x00c7c5f0", "ARM.exidx end: 0x00c7ca5c"),
        ("disasm_worldtileloader_hc_38.txt", "implementation: 0x00c722e8", "ARM.exidx end: 0x00c72628"),
        ("disasm_worldtileloader_hc_39.txt", "implementation: 0x00c73d6c", "ARM.exidx end: 0x00c746d0"),
        ("disasm_worldtileloader_hc_40.txt", "implementation: 0x00c8a1b4", "ARM.exidx end: 0x00c8a1f8"),
        ("disasm_worldtileloader_hc_41.txt", "implementation: 0x00c753d4", "ARM.exidx end: 0x00c75410"),
        ("disasm_worldtileloader_hc_42.txt", "implementation: 0x00c73518", "ARM.exidx end: 0x00c73804"),
        ("disasm_worldtileloader_hc_43.txt", "implementation: 0x00c7162c", "ARM.exidx end: 0x00c71800"),
        ("disasm_worldtileloader_hc_44.txt", "implementation: 0x00c75364", "ARM.exidx end: 0x00c753d4"),
        ("disasm_worldtileloader_hc_45.txt", "implementation: 0x00b9be40", "ARM.exidx end: 0x00b9cec0"),
        ("disasm_worldtileloader_hc_46.txt", "implementation: 0x00c68964", "ARM.exidx end: 0x00c68f4c"),
        ("disasm_worldtileloader_hc_47.txt", "implementation: 0x00c683c0", "ARM.exidx end: 0x00c68964"),
        ("disasm_worldtileloader_hc_48.txt", "implementation: 0x00c87060", "ARM.exidx end: 0x00c87a60"),
        ("disasm_worldtileloader_hc_49.txt", "implementation: 0x00c80e34", "ARM.exidx end: 0x00c80fb0"),
        ("disasm_worldtileloader_hc_50.txt", "implementation: 0x00c6595c", "ARM.exidx end: 0x00c67a58"),
        ("disasm_worldtileloader_hc_51.txt", "implementation: 0x00c6a4f8", "ARM.exidx end: 0x00c6a55c"),
        ("disasm_worldtileloader_hc_52.txt", "implementation: 0x00c6a55c", "ARM.exidx end: 0x00c6be48"),
        ("disasm_worldtileloader_hc_53.txt", "implementation: 0x00c65204", "ARM.exidx end: 0x00c6595c"),
        ("disasm_worldtileloader_hc_54.txt", "implementation: 0x00c6455c", "ARM.exidx end: 0x00c64ca4"),
        ("disasm_worldtileloader_hc_55.txt", "implementation: 0x00c79598", "ARM.exidx end: 0x00c7abe8"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "BLOCKHEAD4.md",
        [
            "106952",
                        'preDrawUpdate',
            '55,344',
            '221 ivar',
            'instanceStart',
        ],
    )
    require(
        NATIVE / "blockhead4.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 55344',
            '"verified_words": 17891',
            'preDrawUpdate',
            '221',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_hf_00.txt", "implementation: 0x00c811e0", "ARM.exidx end: 0x00c8122c"),
        ("disasm_worldtileloader_hf_01.txt", "implementation: 0x00c7b990", "ARM.exidx end: 0x00c7bb4c"),
        ("disasm_worldtileloader_hf_02.txt", "implementation: 0x00c86e4c", "ARM.exidx end: 0x00c86e88"),
        ("disasm_worldtileloader_hf_03.txt", "implementation: 0x00c7b5fc", "ARM.exidx end: 0x00c7bb4c"),
        ("disasm_worldtileloader_hf_04.txt", "implementation: 0x00c7b8a0", "ARM.exidx end: 0x00c7bb4c"),
        ("disasm_worldtileloader_hf_05.txt", "implementation: 0x00c81a44", "ARM.exidx end: 0x00c820e8"),
        ("disasm_worldtileloader_hf_06.txt", "implementation: 0x00c8122c", "ARM.exidx end: 0x00c81750"),
        ("disasm_worldtileloader_hf_07.txt", "implementation: 0x00c82900", "ARM.exidx end: 0x00c82a2c"),
        ("disasm_worldtileloader_hf_08.txt", "implementation: 0x00c8a1f8", "ARM.exidx end: 0x00c8a230"),
        ("disasm_worldtileloader_hf_09.txt", "implementation: 0x00c8a27c", "ARM.exidx end: 0x00c8a2b4"),
        ("disasm_worldtileloader_hf_10.txt", "implementation: 0x00c8a300", "ARM.exidx end: 0x00c8a338"),
        ("disasm_worldtileloader_hf_11.txt", "implementation: 0x00bac9a8", "ARM.exidx end: 0x00bac9e4"),
        ("disasm_worldtileloader_hf_12.txt", "implementation: 0x00c89e3c", "ARM.exidx end: 0x00c89eec"),
        ("disasm_worldtileloader_hf_13.txt", "implementation: 0x00c89eec", "ARM.exidx end: 0x00c8a014"),
        ("disasm_worldtileloader_hf_14.txt", "implementation: 0x00c8a014", "ARM.exidx end: 0x00c8a030"),
        ("disasm_worldtileloader_hf_15.txt", "implementation: 0x00b9ffe4", "ARM.exidx end: 0x00ba097c"),
        ("disasm_worldtileloader_hf_16.txt", "implementation: 0x00c86e88", "ARM.exidx end: 0x00c87060"),
        ("disasm_worldtileloader_hf_17.txt", "implementation: 0x00c7c0d0", "ARM.exidx end: 0x00c7c224"),
        ("disasm_worldtileloader_hf_18.txt", "implementation: 0x00c86ae4", "ARM.exidx end: 0x00c86e4c"),
        ("disasm_worldtileloader_hf_19.txt", "implementation: 0x00c38e68", "ARM.exidx end: 0x00c49968"),
        ("disasm_worldtileloader_hf_20.txt", "implementation: 0x00bed9ac", "ARM.exidx end: 0x00bff138"),
        ("disasm_worldtileloader_hf_21.txt", "implementation: 0x00b8c9f8", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hf_22.txt", "implementation: 0x00b8ca78", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hf_23.txt", "implementation: 0x00b8cab8", "ARM.exidx end: 0x00b8cc0c"),
        ("disasm_worldtileloader_hf_24.txt", "implementation: 0x00c80b84", "ARM.exidx end: 0x00c80de0"),
        ("disasm_worldtileloader_hf_25.txt", "implementation: 0x00c83864", "ARM.exidx end: 0x00c83a54"),
        ("disasm_worldtileloader_hf_26.txt", "implementation: 0x00b9e9d4", "ARM.exidx end: 0x00b9ea28"),
        ("disasm_worldtileloader_hf_27.txt", "implementation: 0x00c75410", "ARM.exidx end: 0x00c7922c"),
        ("disasm_worldtileloader_hf_28.txt", "implementation: 0x00b9111c", "ARM.exidx end: 0x00b91ddc"),
        ("disasm_worldtileloader_hf_29.txt", "implementation: 0x00b9d0f8", "ARM.exidx end: 0x00b9d59c"),
        ("disasm_worldtileloader_hf_30.txt", "implementation: 0x00c8a484", "ARM.exidx end: 0x00c8a4fc"),
        ("disasm_worldtileloader_hf_31.txt", "implementation: 0x00bac764", "ARM.exidx end: 0x00bac9a8"),
        ("disasm_worldtileloader_hf_32.txt", "implementation: 0x00c83a54", "ARM.exidx end: 0x00c83a90"),
        ("disasm_worldtileloader_hf_33.txt", "implementation: 0x00c81e80", "ARM.exidx end: 0x00c820e8"),
        ("disasm_worldtileloader_hf_34.txt", "implementation: 0x00c7b4a0", "ARM.exidx end: 0x00c7bb4c"),
        ("disasm_worldtileloader_hf_35.txt", "implementation: 0x00c8a030", "ARM.exidx end: 0x00c8a090"),
        ("disasm_worldtileloader_hf_36.txt", "implementation: 0x00b91dec", "ARM.exidx end: 0x00b91e08"),
        ("disasm_worldtileloader_hf_37.txt", "implementation: 0x00c8a0d4", "ARM.exidx end: 0x00c8a110"),
        ("disasm_worldtileloader_hf_38.txt", "implementation: 0x00c80584", "ARM.exidx end: 0x00c805c0"),
        ("disasm_worldtileloader_hf_39.txt", "implementation: 0x00c01a98", "ARM.exidx end: 0x00c37b58"),
        ("disasm_worldtileloader_hf_40.txt", "implementation: 0x00b9d59c", "ARM.exidx end: 0x00b9d894"),
        ("disasm_worldtileloader_hf_41.txt", "implementation: 0x00bb7114", "ARM.exidx end: 0x00bb8d6c"),
        ("disasm_worldtileloader_hf_42.txt", "implementation: 0x00c8a154", "ARM.exidx end: 0x00c8a1b4"),
        ("disasm_worldtileloader_hf_43.txt", "implementation: 0x00c7bee4", "ARM.exidx end: 0x00c7c224"),
        ("disasm_worldtileloader_hf_44.txt", "implementation: 0x00c731c4", "ARM.exidx end: 0x00c73288"),
        ("disasm_worldtileloader_hf_45.txt", "implementation: 0x00c7c224", "ARM.exidx end: 0x00c7c320"),
        ("disasm_worldtileloader_hf_46.txt", "implementation: 0x00c8a440", "ARM.exidx end: 0x00c8a484"),
        ("disasm_worldtileloader_hf_47.txt", "implementation: 0x00c8a230", "ARM.exidx end: 0x00c8a27c"),
        ("disasm_worldtileloader_hf_48.txt", "implementation: 0x00c8a2b4", "ARM.exidx end: 0x00c8a300"),
        ("disasm_worldtileloader_hf_49.txt", "implementation: 0x00c8a338", "ARM.exidx end: 0x00c8a384"),
        ("disasm_worldtileloader_hf_50.txt", "implementation: 0x00c7b31c", "ARM.exidx end: 0x00c7bb4c"),
        ("disasm_worldtileloader_hf_51.txt", "implementation: 0x00bb91a8", "ARM.exidx end: 0x00bb9238"),
        ("disasm_worldtileloader_hf_52.txt", "implementation: 0x00c79494", "ARM.exidx end: 0x00c79510"),
        ("disasm_worldtileloader_hf_53.txt", "implementation: 0x00c8a110", "ARM.exidx end: 0x00c8a154"),
        ("disasm_worldtileloader_hf_54.txt", "implementation: 0x00c8041c", "ARM.exidx end: 0x00c80584"),
        ("disasm_worldtileloader_hf_55.txt", "implementation: 0x00c7bd30", "ARM.exidx end: 0x00c7bee4"),
        ("disasm_worldtileloader_hf_56.txt", "implementation: 0x00c7922c", "ARM.exidx end: 0x00c79494"),
        ("disasm_worldtileloader_hf_57.txt", "implementation: 0x00c89df0", "ARM.exidx end: 0x00c89e3c"),
        ("disasm_worldtileloader_hf_58.txt", "implementation: 0x00bb01f0", "ARM.exidx end: 0x00bb0a1c"),
        ("disasm_worldtileloader_hf_59.txt", "implementation: 0x00c7b560", "ARM.exidx end: 0x00c7bb4c"),
        ("disasm_worldtileloader_hf_60.txt", "implementation: 0x00c8219c", "ARM.exidx end: 0x00c82628"),
        ("disasm_worldtileloader_hf_61.txt", "implementation: 0x00c81750", "ARM.exidx end: 0x00c81a44"),
        ("disasm_worldtileloader_hf_62.txt", "implementation: 0x00ba0ed8", "ARM.exidx end: 0x00ba0fe0"),
        ("disasm_worldtileloader_hf_63.txt", "implementation: 0x00c83a90", "ARM.exidx end: 0x00c863e0"),
        ("disasm_worldtileloader_hf_64.txt", "implementation: 0x00b9dedc", "ARM.exidx end: 0x00b9e9d4"),
        ("disasm_worldtileloader_hf_65.txt", "implementation: 0x00baa488", "ARM.exidx end: 0x00bab850"),
        ("disasm_worldtileloader_hf_66.txt", "implementation: 0x00c8a384", "ARM.exidx end: 0x00c8a3fc"),
        ("disasm_worldtileloader_hf_67.txt", "implementation: 0x00c81da4", "ARM.exidx end: 0x00c820e8"),
        ("disasm_worldtileloader_hf_68.txt", "implementation: 0x00c794d4", "ARM.exidx end: 0x00c79510"),
        ("disasm_worldtileloader_hf_69.txt", "implementation: 0x00c730d0", "ARM.exidx end: 0x00c73100"),
        ("disasm_worldtileloader_hf_70.txt", "implementation: 0x00c730e8", "ARM.exidx end: 0x00c73100"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "NPC2.md",
        [
            "1440",
                        'RIDE',
            'SET FREE',
            'CRITTER',
            'fullnessFraction',
        ],
    )
    require(
        NATIVE / "npc2.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 72',
            '"verified_words": 65',
            'RIDE',
            'fullnessFraction',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_nq_00.txt", "implementation: 0x0064a78c", "ARM.exidx end: 0x0064a7e4"),
        ("disasm_worldtileloader_nq_01.txt", "implementation: 0x0064fd44", "ARM.exidx end: 0x0064fd60"),
        ("disasm_worldtileloader_nq_02.txt", "implementation: 0x00651314", "ARM.exidx end: 0x006513a8"),
        ("disasm_worldtileloader_nq_03.txt", "implementation: 0x0064ed9c", "ARM.exidx end: 0x0064ee04"),
        ("disasm_worldtileloader_nq_04.txt", "implementation: 0x00649fc8", "ARM.exidx end: 0x00649fec"),
        ("disasm_worldtileloader_nq_05.txt", "implementation: 0x0064ee04", "ARM.exidx end: 0x0064ee48"),
        ("disasm_worldtileloader_nq_06.txt", "implementation: 0x006513a8", "ARM.exidx end: 0x006513e4"),
        ("disasm_worldtileloader_nq_07.txt", "implementation: 0x0064ad30", "ARM.exidx end: 0x0064ad80"),
        ("disasm_worldtileloader_nq_08.txt", "implementation: 0x0064fc64", "ARM.exidx end: 0x0064fcf0"),
        ("disasm_worldtileloader_nq_09.txt", "implementation: 0x0064a744", "ARM.exidx end: 0x0064a78c"),
        ("disasm_worldtileloader_nq_10.txt", "implementation: 0x0064a554", "ARM.exidx end: 0x0064a574"),
        ("disasm_worldtileloader_nq_11.txt", "implementation: 0x0064a7e4", "ARM.exidx end: 0x0064a83c"),
        ("disasm_worldtileloader_nq_12.txt", "implementation: 0x0064a64c", "ARM.exidx end: 0x0064a66c"),
        ("disasm_worldtileloader_nq_13.txt", "implementation: 0x0064ee48", "ARM.exidx end: 0x0064ef20"),
        ("disasm_worldtileloader_nq_14.txt", "implementation: 0x0064a768", "ARM.exidx end: 0x0064a78c"),
        ("disasm_worldtileloader_nq_15.txt", "implementation: 0x0064a49c", "ARM.exidx end: 0x0064a554"),
        ("disasm_worldtileloader_nq_16.txt", "implementation: 0x0064a574", "ARM.exidx end: 0x0064a62c"),
        ("disasm_worldtileloader_nq_17.txt", "implementation: 0x0064a66c", "ARM.exidx end: 0x0064a724"),
        ("disasm_worldtileloader_nq_18.txt", "implementation: 0x0064a2d0", "ARM.exidx end: 0x0064a2f0"),
        ("disasm_worldtileloader_nq_19.txt", "implementation: 0x0064a2b4", "ARM.exidx end: 0x0064a2f0"),
        ("disasm_worldtileloader_nq_20.txt", "implementation: 0x00649f04", "ARM.exidx end: 0x00649f8c"),
        ("disasm_worldtileloader_nq_21.txt", "implementation: 0x00650a80", "ARM.exidx end: 0x00650b10"),
        ("disasm_worldtileloader_nq_22.txt", "implementation: 0x00644704", "ARM.exidx end: 0x00644718"),
        ("disasm_worldtileloader_nq_23.txt", "implementation: 0x00649358", "ARM.exidx end: 0x00649390"),
        ("disasm_worldtileloader_nq_24.txt", "implementation: 0x00643b04", "ARM.exidx end: 0x00643b20"),
        ("disasm_worldtileloader_nq_25.txt", "implementation: 0x00643ab4", "ARM.exidx end: 0x00643ad0"),
        ("disasm_worldtileloader_nq_26.txt", "implementation: 0x0064a298", "ARM.exidx end: 0x0064a2f0"),
        ("disasm_worldtileloader_nq_27.txt", "implementation: 0x00649428", "ARM.exidx end: 0x0064952c"),
        ("disasm_worldtileloader_nq_28.txt", "implementation: 0x0064acf8", "ARM.exidx end: 0x0064ad30"),
        ("disasm_worldtileloader_nq_29.txt", "implementation: 0x0064ad14", "ARM.exidx end: 0x0064ad30"),
        ("disasm_worldtileloader_nq_30.txt", "implementation: 0x00649390", "ARM.exidx end: 0x0064952c"),
        ("disasm_worldtileloader_nq_31.txt", "implementation: 0x0064a208", "ARM.exidx end: 0x0064a268"),
        ("disasm_worldtileloader_nq_32.txt", "implementation: 0x0064a7c8", "ARM.exidx end: 0x0064a7e4"),
        ("disasm_worldtileloader_nq_33.txt", "implementation: 0x00649f8c", "ARM.exidx end: 0x00649fc8"),
        ("disasm_worldtileloader_nq_34.txt", "implementation: 0x0064fcf0", "ARM.exidx end: 0x0064fd60"),
        ("disasm_worldtileloader_nq_35.txt", "implementation: 0x00643a84", "ARM.exidx end: 0x00643ab4"),
        ("disasm_worldtileloader_nq_36.txt", "implementation: 0x00649374", "ARM.exidx end: 0x00649390"),
        ("disasm_worldtileloader_nq_37.txt", "implementation: 0x0064a62c", "ARM.exidx end: 0x0064a66c"),
        ("disasm_worldtileloader_nq_38.txt", "implementation: 0x00643ad0", "ARM.exidx end: 0x00643b04"),
        ("disasm_worldtileloader_nq_39.txt", "implementation: 0x0064a83c", "ARM.exidx end: 0x0064a86c"),
        ("disasm_worldtileloader_nq_40.txt", "implementation: 0x0064e5c8", "ARM.exidx end: 0x0064e604"),
        ("disasm_worldtileloader_nq_41.txt", "implementation: 0x00650980", "ARM.exidx end: 0x00650a2c"),
        ("disasm_worldtileloader_nq_42.txt", "implementation: 0x00643a68", "ARM.exidx end: 0x00643a84"),
        ("disasm_worldtileloader_nq_43.txt", "implementation: 0x006455d4", "ARM.exidx end: 0x0064567c"),
        ("disasm_worldtileloader_nq_44.txt", "implementation: 0x00649550", "ARM.exidx end: 0x006495a0"),
        ("disasm_worldtileloader_nq_45.txt", "implementation: 0x0065096c", "ARM.exidx end: 0x00650980"),
        ("disasm_worldtileloader_nq_46.txt", "implementation: 0x00649880", "ARM.exidx end: 0x00649894"),
        ("disasm_worldtileloader_nq_47.txt", "implementation: 0x00647c84", "ARM.exidx end: 0x00647cf8"),
        ("disasm_worldtileloader_nq_48.txt", "implementation: 0x0064a9bc", "ARM.exidx end: 0x0064a9f8"),
        ("disasm_worldtileloader_nq_49.txt", "implementation: 0x0064a98c", "ARM.exidx end: 0x0064a9f8"),
        ("disasm_worldtileloader_nq_50.txt", "implementation: 0x00649ebc", "ARM.exidx end: 0x00649f04"),
        ("disasm_worldtileloader_nq_51.txt", "implementation: 0x0064fd28", "ARM.exidx end: 0x0064fd60"),
        ("disasm_worldtileloader_nq_52.txt", "implementation: 0x006501b8", "ARM.exidx end: 0x00650218"),
        ("disasm_worldtileloader_nq_53.txt", "implementation: 0x00650a64", "ARM.exidx end: 0x00650b10"),
        ("disasm_worldtileloader_nq_54.txt", "implementation: 0x0064fd0c", "ARM.exidx end: 0x0064fd60"),
        ("disasm_worldtileloader_nq_55.txt", "implementation: 0x0064fc04", "ARM.exidx end: 0x0064fc64"),
        ("disasm_worldtileloader_nq_56.txt", "implementation: 0x0064fc34", "ARM.exidx end: 0x0064fc64"),
        ("disasm_worldtileloader_nq_57.txt", "implementation: 0x00650a2c", "ARM.exidx end: 0x00650b10"),
        ("disasm_worldtileloader_nq_58.txt", "implementation: 0x0065019c", "ARM.exidx end: 0x006501b8"),
        ("disasm_worldtileloader_nq_59.txt", "implementation: 0x006500c0", "ARM.exidx end: 0x00650180"),
        ("disasm_worldtileloader_nq_60.txt", "implementation: 0x0064a9d8", "ARM.exidx end: 0x0064a9f8"),
        ("disasm_worldtileloader_nq_61.txt", "implementation: 0x0064a86c", "ARM.exidx end: 0x0064a98c"),
        ("disasm_worldtileloader_nq_62.txt", "implementation: 0x0065135c", "ARM.exidx end: 0x006513a8"),
        ("disasm_worldtileloader_nq_63.txt", "implementation: 0x006445e8", "ARM.exidx end: 0x00644704"),
        ("disasm_worldtileloader_nq_64.txt", "implementation: 0x00650180", "ARM.exidx end: 0x0065019c"),
        ("disasm_worldtileloader_nq_65.txt", "implementation: 0x0064a724", "ARM.exidx end: 0x0064a744"),
        ("disasm_worldtileloader_nq_66.txt", "implementation: 0x00650abc", "ARM.exidx end: 0x00650b10"),
        ("disasm_worldtileloader_nq_67.txt", "implementation: 0x0064a268", "ARM.exidx end: 0x0064a2f0"),
        ("disasm_worldtileloader_nq_68.txt", "implementation: 0x0064fbf0", "ARM.exidx end: 0x0064fc04"),
        ("disasm_worldtileloader_nq_69.txt", "implementation: 0x0064e81c", "ARM.exidx end: 0x0064e8d8"),
        ("disasm_worldtileloader_nq_70.txt", "implementation: 0x0064952c", "ARM.exidx end: 0x00649550"),
        ("disasm_worldtileloader_nq_71.txt", "implementation: 0x006459c0", "ARM.exidx end: 0x00645aac"),
        ("disasm_worldtileloader_nq_72.txt", "implementation: 0x00649e20", "ARM.exidx end: 0x00649ebc"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "CAVETROLL.md",
        [
            "49828",
                        'CAVE TROLL',
            'Trollface',
            'npcType = 6',
            'recoilTimer',
        ],
    )
    require(
        NATIVE / "cavetroll.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 30803',
            '"verified_words": 9034',
            'CAVE TROLL',
            'recoilTimer',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_cw_00.txt", "implementation: 0x00d853c0", "ARM.exidx end: 0x00d8574c"),
        ("disasm_worldtileloader_cw_01.txt", "implementation: 0x00d84ee8", "ARM.exidx end: 0x00d84fe8"),
        ("disasm_worldtileloader_cw_02.txt", "implementation: 0x00d850f4", "ARM.exidx end: 0x00d851dc"),
        ("disasm_worldtileloader_cw_03.txt", "implementation: 0x00d846a8", "ARM.exidx end: 0x00d8487c"),
        ("disasm_worldtileloader_cw_04.txt", "implementation: 0x00d84ccc", "ARM.exidx end: 0x00d84d58"),
        ("disasm_worldtileloader_cw_05.txt", "implementation: 0x00d84898", "ARM.exidx end: 0x00d848bc"),
        ("disasm_worldtileloader_cw_06.txt", "implementation: 0x00d84080", "ARM.exidx end: 0x00d8409c"),
        ("disasm_worldtileloader_cw_07.txt", "implementation: 0x00d8487c", "ARM.exidx end: 0x00d84898"),
        ("disasm_worldtileloader_cw_08.txt", "implementation: 0x00d848bc", "ARM.exidx end: 0x00d849a0"),
        ("disasm_worldtileloader_cw_09.txt", "implementation: 0x00d52c24", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_10.txt", "implementation: 0x00d54378", "ARM.exidx end: 0x00d54604"),
        ("disasm_worldtileloader_cw_11.txt", "implementation: 0x00d56338", "ARM.exidx end: 0x00d56460"),
        ("disasm_worldtileloader_cw_12.txt", "implementation: 0x00d54908", "ARM.exidx end: 0x00d54924"),
        ("disasm_worldtileloader_cw_13.txt", "implementation: 0x00d54604", "ARM.exidx end: 0x00d5481c"),
        ("disasm_worldtileloader_cw_14.txt", "implementation: 0x00d83ae0", "ARM.exidx end: 0x00d83b68"),
        ("disasm_worldtileloader_cw_15.txt", "implementation: 0x00d52ae4", "ARM.exidx end: 0x00d52b20"),
        ("disasm_worldtileloader_cw_16.txt", "implementation: 0x00d55038", "ARM.exidx end: 0x00d55074"),
        ("disasm_worldtileloader_cw_17.txt", "implementation: 0x00d552b8", "ARM.exidx end: 0x00d552f4"),
        ("disasm_worldtileloader_cw_18.txt", "implementation: 0x00d54e2c", "ARM.exidx end: 0x00d55038"),
        ("disasm_worldtileloader_cw_19.txt", "implementation: 0x00d56190", "ARM.exidx end: 0x00d56338"),
        ("disasm_worldtileloader_cw_20.txt", "implementation: 0x00d52b70", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_21.txt", "implementation: 0x00d52b54", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_22.txt", "implementation: 0x00d55720", "ARM.exidx end: 0x00d55bcc"),
        ("disasm_worldtileloader_cw_23.txt", "implementation: 0x00d7e358", "ARM.exidx end: 0x00d8270c"),
        ("disasm_worldtileloader_cw_24.txt", "implementation: 0x00d83b68", "ARM.exidx end: 0x00d83c24"),
        ("disasm_worldtileloader_cw_25.txt", "implementation: 0x00d52bbc", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_26.txt", "implementation: 0x00d52bd8", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_27.txt", "implementation: 0x00d52c08", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_28.txt", "implementation: 0x00d842ac", "ARM.exidx end: 0x00d846a8"),
        ("disasm_worldtileloader_cw_29.txt", "implementation: 0x00d83320", "ARM.exidx end: 0x00d839f0"),
        ("disasm_worldtileloader_cw_30.txt", "implementation: 0x00d52c40", "ARM.exidx end: 0x00d535cc"),
        ("disasm_worldtileloader_cw_31.txt", "implementation: 0x00d535f8", "ARM.exidx end: 0x00d538cc"),
        ("disasm_worldtileloader_cw_32.txt", "implementation: 0x00d53f2c", "ARM.exidx end: 0x00d54378"),
        ("disasm_worldtileloader_cw_33.txt", "implementation: 0x00d55074", "ARM.exidx end: 0x00d552b8"),
        ("disasm_worldtileloader_cw_34.txt", "implementation: 0x00d851dc", "ARM.exidx end: 0x00d85268"),
        ("disasm_worldtileloader_cw_35.txt", "implementation: 0x00d52b20", "ARM.exidx end: 0x00d52b54"),
        ("disasm_worldtileloader_cw_36.txt", "implementation: 0x00d83c24", "ARM.exidx end: 0x00d83c40"),
        ("disasm_worldtileloader_cw_37.txt", "implementation: 0x00d849a0", "ARM.exidx end: 0x00d84a4c"),
        ("disasm_worldtileloader_cw_38.txt", "implementation: 0x00d85268", "ARM.exidx end: 0x00d852c8"),
        ("disasm_worldtileloader_cw_39.txt", "implementation: 0x00d535dc", "ARM.exidx end: 0x00d535f8"),
        ("disasm_worldtileloader_cw_40.txt", "implementation: 0x00d852c8", "ARM.exidx end: 0x00d85304"),
        ("disasm_worldtileloader_cw_41.txt", "implementation: 0x00d5f4b8", "ARM.exidx end: 0x00d7d604"),
        ("disasm_worldtileloader_cw_42.txt", "implementation: 0x00d84a4c", "ARM.exidx end: 0x00d84c6c"),
        ("disasm_worldtileloader_cw_43.txt", "implementation: 0x00d84118", "ARM.exidx end: 0x00d842ac"),
        ("disasm_worldtileloader_cw_44.txt", "implementation: 0x00d55ef4", "ARM.exidx end: 0x00d560f8"),
        ("disasm_worldtileloader_cw_45.txt", "implementation: 0x00d55bcc", "ARM.exidx end: 0x00d55ef4"),
        ("disasm_worldtileloader_cw_46.txt", "implementation: 0x00d84fe8", "ARM.exidx end: 0x00d850f4"),
        ("disasm_worldtileloader_cw_47.txt", "implementation: 0x00d8409c", "ARM.exidx end: 0x00d84118"),
        ("disasm_worldtileloader_cw_48.txt", "implementation: 0x00d84df0", "ARM.exidx end: 0x00d84ee8"),
        ("disasm_worldtileloader_cw_49.txt", "implementation: 0x00d84d58", "ARM.exidx end: 0x00d84d9c"),
        ("disasm_worldtileloader_cw_50.txt", "implementation: 0x00d85214", "ARM.exidx end: 0x00d85268"),
        ("disasm_worldtileloader_cw_51.txt", "implementation: 0x00d8524c", "ARM.exidx end: 0x00d85268"),
        ("disasm_worldtileloader_cw_52.txt", "implementation: 0x00d84c6c", "ARM.exidx end: 0x00d84ccc"),
        ("disasm_worldtileloader_cw_53.txt", "implementation: 0x00d851f8", "ARM.exidx end: 0x00d85268"),
        ("disasm_worldtileloader_cw_54.txt", "implementation: 0x00d85348", "ARM.exidx end: 0x00d85380"),
        ("disasm_worldtileloader_cw_55.txt", "implementation: 0x00d83a64", "ARM.exidx end: 0x00d83ae0"),
        ("disasm_worldtileloader_cw_56.txt", "implementation: 0x00d82ccc", "ARM.exidx end: 0x00d832f0"),
        ("disasm_worldtileloader_cw_57.txt", "implementation: 0x00d85304", "ARM.exidx end: 0x00d85348"),
        ("disasm_worldtileloader_cw_58.txt", "implementation: 0x00d85380", "ARM.exidx end: 0x00d853c0"),
        ("disasm_worldtileloader_cw_59.txt", "implementation: 0x00d84d9c", "ARM.exidx end: 0x00d84df0"),
        ("disasm_worldtileloader_cw_60.txt", "implementation: 0x00d839f0", "ARM.exidx end: 0x00d83a64"),
        ("disasm_worldtileloader_cw_61.txt", "implementation: 0x00d52b8c", "ARM.exidx end: 0x00d52c40"),
        ("disasm_worldtileloader_cw_62.txt", "implementation: 0x00d552f4", "ARM.exidx end: 0x00d55518"),
        ("disasm_worldtileloader_cw_63.txt", "implementation: 0x00d55518", "ARM.exidx end: 0x00d55720"),
        ("disasm_worldtileloader_cw_64.txt", "implementation: 0x00d83c40", "ARM.exidx end: 0x00d84080"),
        ("disasm_worldtileloader_cw_65.txt", "implementation: 0x00d56160", "ARM.exidx end: 0x00d56190"),
        ("disasm_worldtileloader_cw_66.txt", "implementation: 0x00d56460", "ARM.exidx end: 0x00d5f188"),
        ("disasm_worldtileloader_cw_67.txt", "implementation: 0x00d560f8", "ARM.exidx end: 0x00d56160"),
        ("disasm_worldtileloader_cw_68.txt", "implementation: 0x00d5481c", "ARM.exidx end: 0x00d54908"),
        ("disasm_worldtileloader_cw_69.txt", "implementation: 0x00d83aa4", "ARM.exidx end: 0x00d83ae0"),
        ("disasm_worldtileloader_cw_70.txt", "implementation: 0x00d832f0", "ARM.exidx end: 0x00d83320"),
        ("disasm_worldtileloader_cw_71.txt", "implementation: 0x00d83308", "ARM.exidx end: 0x00d83320"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "UIMANAGER.md",
        [
            "21484",
            'UIManager',
            'button',
            'alert',
        ],
    )
    require(
        NATIVE / "uimanager.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 3277',
            '"verified_words": 50',
            '0xade6c4',
            '"um_64"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_um_00.txt", "implementation: 0x00ade688", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_01.txt", "implementation: 0x00ade7dc", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_02.txt", "implementation: 0x00ad0e70", "ARM.exidx end: 0x00ad19d0"),
        ("disasm_worldtileloader_um_03.txt", "implementation: 0x00ad94f4", "ARM.exidx end: 0x00ad9558"),
        ("disasm_worldtileloader_um_04.txt", "implementation: 0x00acccdc", "ARM.exidx end: 0x00acd22c"),
        ("disasm_worldtileloader_um_05.txt", "implementation: 0x00ad0560", "ARM.exidx end: 0x00ad065c"),
        ("disasm_worldtileloader_um_06.txt", "implementation: 0x00ad065c", "ARM.exidx end: 0x00ad0878"),
        ("disasm_worldtileloader_um_07.txt", "implementation: 0x00ade754", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_08.txt", "implementation: 0x00ad9558", "ARM.exidx end: 0x00ad9668"),
        ("disasm_worldtileloader_um_09.txt", "implementation: 0x00ade9b8", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_10.txt", "implementation: 0x00adc3d8", "ARM.exidx end: 0x00adc470"),
        ("disasm_worldtileloader_um_11.txt", "implementation: 0x00ade014", "ARM.exidx end: 0x00ade07c"),
        ("disasm_worldtileloader_um_12.txt", "implementation: 0x00ade710", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_13.txt", "implementation: 0x00ade798", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_14.txt", "implementation: 0x00ade4f8", "ARM.exidx end: 0x00ade608"),
        ("disasm_worldtileloader_um_15.txt", "implementation: 0x00ade370", "ARM.exidx end: 0x00ade3ac"),
        ("disasm_worldtileloader_um_16.txt", "implementation: 0x00ade2f0", "ARM.exidx end: 0x00ade32c"),
        ("disasm_worldtileloader_um_17.txt", "implementation: 0x00adebd8", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_18.txt", "implementation: 0x00aca3c8", "ARM.exidx end: 0x00acac40"),
        ("disasm_worldtileloader_um_19.txt", "implementation: 0x00ad1a3c", "ARM.exidx end: 0x00ad1bc4"),
        ("disasm_worldtileloader_um_20.txt", "implementation: 0x00addd4c", "ARM.exidx end: 0x00adddb8"),
        ("disasm_worldtileloader_um_21.txt", "implementation: 0x00ad0ac8", "ARM.exidx end: 0x00ad0e70"),
        ("disasm_worldtileloader_um_22.txt", "implementation: 0x00ad0878", "ARM.exidx end: 0x00ad0ac8"),
        ("disasm_worldtileloader_um_23.txt", "implementation: 0x00ad53a0", "ARM.exidx end: 0x00ad5504"),
        ("disasm_worldtileloader_um_24.txt", "implementation: 0x00adb6f4", "ARM.exidx end: 0x00adb848"),
        ("disasm_worldtileloader_um_25.txt", "implementation: 0x00ad9284", "ARM.exidx end: 0x00ad944c"),
        ("disasm_worldtileloader_um_26.txt", "implementation: 0x00adbd18", "ARM.exidx end: 0x00adbf4c"),
        ("disasm_worldtileloader_um_27.txt", "implementation: 0x00ad5504", "ARM.exidx end: 0x00ad5968"),
        ("disasm_worldtileloader_um_28.txt", "implementation: 0x00adb8b4", "ARM.exidx end: 0x00adbae8"),
        ("disasm_worldtileloader_um_29.txt", "implementation: 0x00ade470", "ARM.exidx end: 0x00ade608"),
        ("disasm_worldtileloader_um_30.txt", "implementation: 0x00adddb8", "ARM.exidx end: 0x00ade014"),
        ("disasm_worldtileloader_um_31.txt", "implementation: 0x00ad8644", "ARM.exidx end: 0x00ad8cb0"),
        ("disasm_worldtileloader_um_32.txt", "implementation: 0x00adc2dc", "ARM.exidx end: 0x00adc3d8"),
        ("disasm_worldtileloader_um_33.txt", "implementation: 0x00ad91bc", "ARM.exidx end: 0x00ad9284"),
        ("disasm_worldtileloader_um_34.txt", "implementation: 0x00ad5e60", "ARM.exidx end: 0x00ad6254"),
        ("disasm_worldtileloader_um_35.txt", "implementation: 0x00ad6254", "ARM.exidx end: 0x00ad657c"),
        ("disasm_worldtileloader_um_36.txt", "implementation: 0x00ad657c", "ARM.exidx end: 0x00ad6b84"),
        ("disasm_worldtileloader_um_37.txt", "implementation: 0x00adb848", "ARM.exidx end: 0x00adb8b4"),
        ("disasm_worldtileloader_um_38.txt", "implementation: 0x00ade1f0", "ARM.exidx end: 0x00ade22c"),
        ("disasm_worldtileloader_um_39.txt", "implementation: 0x00ad944c", "ARM.exidx end: 0x00ad94f4"),
        ("disasm_worldtileloader_um_40.txt", "implementation: 0x00adbf4c", "ARM.exidx end: 0x00adc17c"),
        ("disasm_worldtileloader_um_41.txt", "implementation: 0x00adbae8", "ARM.exidx end: 0x00adbd18"),
        ("disasm_worldtileloader_um_42.txt", "implementation: 0x00ade8ec", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_43.txt", "implementation: 0x00ade11c", "ARM.exidx end: 0x00ade1f0"),
        ("disasm_worldtileloader_um_44.txt", "implementation: 0x00ade07c", "ARM.exidx end: 0x00ade11c"),
        ("disasm_worldtileloader_um_45.txt", "implementation: 0x00ac8480", "ARM.exidx end: 0x00aca3c8"),
        ("disasm_worldtileloader_um_46.txt", "implementation: 0x00ad3968", "ARM.exidx end: 0x00ad3cb8"),
        ("disasm_worldtileloader_um_47.txt", "implementation: 0x00ad2c0c", "ARM.exidx end: 0x00ad3450"),
        ("disasm_worldtileloader_um_48.txt", "implementation: 0x00ade974", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_49.txt", "implementation: 0x00add6c8", "ARM.exidx end: 0x00add7ec"),
        ("disasm_worldtileloader_um_50.txt", "implementation: 0x00ade820", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_51.txt", "implementation: 0x00ade270", "ARM.exidx end: 0x00ade2ac"),
        ("disasm_worldtileloader_um_52.txt", "implementation: 0x00ade580", "ARM.exidx end: 0x00ade608"),
        ("disasm_worldtileloader_um_53.txt", "implementation: 0x00ad8048", "ARM.exidx end: 0x00ad8644"),
        ("disasm_worldtileloader_um_54.txt", "implementation: 0x00adea84", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_55.txt", "implementation: 0x00ad3cb8", "ARM.exidx end: 0x00ad4330"),
        ("disasm_worldtileloader_um_56.txt", "implementation: 0x00ad9128", "ARM.exidx end: 0x00ad9284"),
        ("disasm_worldtileloader_um_57.txt", "implementation: 0x00ade53c", "ARM.exidx end: 0x00ade608"),
        ("disasm_worldtileloader_um_58.txt", "implementation: 0x00adeb94", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_59.txt", "implementation: 0x00ad4330", "ARM.exidx end: 0x00ad43ec"),
        ("disasm_worldtileloader_um_60.txt", "implementation: 0x00ade8a8", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_61.txt", "implementation: 0x00adc17c", "ARM.exidx end: 0x00adc2dc"),
        ("disasm_worldtileloader_um_62.txt", "implementation: 0x00acac40", "ARM.exidx end: 0x00acc908"),
        ("disasm_worldtileloader_um_63.txt", "implementation: 0x00ad3450", "ARM.exidx end: 0x00ad3968"),
        ("disasm_worldtileloader_um_64.txt", "implementation: 0x00acd22c", "ARM.exidx end: 0x00ad0560"),
        ("disasm_worldtileloader_um_65.txt", "implementation: 0x00ad4514", "ARM.exidx end: 0x00ad45a8"),
        ("disasm_worldtileloader_um_66.txt", "implementation: 0x00ade3ac", "ARM.exidx end: 0x00ade3f0"),
        ("disasm_worldtileloader_um_67.txt", "implementation: 0x00ade32c", "ARM.exidx end: 0x00ade370"),
        ("disasm_worldtileloader_um_68.txt", "implementation: 0x00adca90", "ARM.exidx end: 0x00adcc60"),
        ("disasm_worldtileloader_um_69.txt", "implementation: 0x00ade22c", "ARM.exidx end: 0x00ade270"),
        ("disasm_worldtileloader_um_70.txt", "implementation: 0x00ad1bc4", "ARM.exidx end: 0x00ad1c40"),
        ("disasm_worldtileloader_um_71.txt", "implementation: 0x00ade2ac", "ARM.exidx end: 0x00ade2f0"),
        ("disasm_worldtileloader_um_72.txt", "implementation: 0x00ad19d0", "ARM.exidx end: 0x00ad1a3c"),
        ("disasm_worldtileloader_um_73.txt", "implementation: 0x00adca50", "ARM.exidx end: 0x00adca90"),
        ("disasm_worldtileloader_um_74.txt", "implementation: 0x00addb7c", "ARM.exidx end: 0x00addd4c"),
        ("disasm_worldtileloader_um_75.txt", "implementation: 0x00ad43ec", "ARM.exidx end: 0x00ad4514"),
        ("disasm_worldtileloader_um_76.txt", "implementation: 0x00adc9ec", "ARM.exidx end: 0x00adca50"),
        ("disasm_worldtileloader_um_77.txt", "implementation: 0x00adc4dc", "ARM.exidx end: 0x00adc5ac"),
        ("disasm_worldtileloader_um_78.txt", "implementation: 0x00adc5ac", "ARM.exidx end: 0x00adc838"),
        ("disasm_worldtileloader_um_79.txt", "implementation: 0x00ad9668", "ARM.exidx end: 0x00adb0f4"),
        ("disasm_worldtileloader_um_80.txt", "implementation: 0x00adb0f4", "ARM.exidx end: 0x00adb6f4"),
        ("disasm_worldtileloader_um_81.txt", "implementation: 0x00adec1c", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_82.txt", "implementation: 0x00ade864", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_83.txt", "implementation: 0x00ad6b84", "ARM.exidx end: 0x00ad7300"),
        ("disasm_worldtileloader_um_84.txt", "implementation: 0x00ade5c4", "ARM.exidx end: 0x00ade608"),
        ("disasm_worldtileloader_um_85.txt", "implementation: 0x00ade608", "ARM.exidx end: 0x00ade644"),
        ("disasm_worldtileloader_um_86.txt", "implementation: 0x00adc470", "ARM.exidx end: 0x00adc4dc"),
        ("disasm_worldtileloader_um_87.txt", "implementation: 0x00ad45a8", "ARM.exidx end: 0x00ad4f5c"),
        ("disasm_worldtileloader_um_88.txt", "implementation: 0x00ad7300", "ARM.exidx end: 0x00ad7748"),
        ("disasm_worldtileloader_um_89.txt", "implementation: 0x00adeb50", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_90.txt", "implementation: 0x00adeb0c", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_91.txt", "implementation: 0x00adea40", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_92.txt", "implementation: 0x00ade9fc", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_93.txt", "implementation: 0x00adda78", "ARM.exidx end: 0x00addb7c"),
        ("disasm_worldtileloader_um_94.txt", "implementation: 0x00add7ec", "ARM.exidx end: 0x00adda78"),
        ("disasm_worldtileloader_um_95.txt", "implementation: 0x00add260", "ARM.exidx end: 0x00add6c8"),
        ("disasm_worldtileloader_um_96.txt", "implementation: 0x00adcf34", "ARM.exidx end: 0x00add260"),
        ("disasm_worldtileloader_um_97.txt", "implementation: 0x00adcc60", "ARM.exidx end: 0x00adcf34"),
        ("disasm_worldtileloader_um_98.txt", "implementation: 0x00ade930", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_99.txt", "implementation: 0x00ad8cb0", "ARM.exidx end: 0x00ad9128"),
        ("disasm_worldtileloader_um_100.txt", "implementation: 0x00ade644", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_101.txt", "implementation: 0x00adeac8", "ARM.exidx end: 0x00adecf4"),
        ("disasm_worldtileloader_um_102.txt", "implementation: 0x00ad1c40", "ARM.exidx end: 0x00ad2bd0"),
        ("disasm_worldtileloader_um_103.txt", "implementation: 0x00ade4b4", "ARM.exidx end: 0x00ade608"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "BHSERVER.md",
        [
            "35474",
            'BHServer',
            'server',
            'connection',
        ],
    )
    require(
        NATIVE / "bhserver.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 11490',
            '"verified_words": 133',
            '0x00533cbc',
            '"bs_29"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_bs_00.txt", "implementation: 0x00533cbc", "ARM.exidx end: 0x00534188"),
        ("disasm_worldtileloader_bs_01.txt", "implementation: 0x00551938", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_02.txt", "implementation: 0x005518b0", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_03.txt", "implementation: 0x00531d90", "ARM.exidx end: 0x005322f4"),
        ("disasm_worldtileloader_bs_04.txt", "implementation: 0x005317e0", "ARM.exidx end: 0x005319f4"),
        ("disasm_worldtileloader_bs_05.txt", "implementation: 0x005322f4", "ARM.exidx end: 0x0053294c"),
        ("disasm_worldtileloader_bs_06.txt", "implementation: 0x005336cc", "ARM.exidx end: 0x00533a58"),
        ("disasm_worldtileloader_bs_07.txt", "implementation: 0x00547acc", "ARM.exidx end: 0x00547ee0"),
        ("disasm_worldtileloader_bs_08.txt", "implementation: 0x00531370", "ARM.exidx end: 0x00531444"),
        ("disasm_worldtileloader_bs_09.txt", "implementation: 0x00543a4c", "ARM.exidx end: 0x00543d40"),
        ("disasm_worldtileloader_bs_10.txt", "implementation: 0x00551a48", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_11.txt", "implementation: 0x00550088", "ARM.exidx end: 0x00550154"),
        ("disasm_worldtileloader_bs_12.txt", "implementation: 0x00532cb8", "ARM.exidx end: 0x00533064"),
        ("disasm_worldtileloader_bs_13.txt", "implementation: 0x00531444", "ARM.exidx end: 0x005317e0"),
        ("disasm_worldtileloader_bs_14.txt", "implementation: 0x005319f4", "ARM.exidx end: 0x00531d90"),
        ("disasm_worldtileloader_bs_15.txt", "implementation: 0x00544c00", "ARM.exidx end: 0x005450e4"),
        ("disasm_worldtileloader_bs_16.txt", "implementation: 0x005517fc", "ARM.exidx end: 0x0055186c"),
        ("disasm_worldtileloader_bs_17.txt", "implementation: 0x00551794", "ARM.exidx end: 0x0055186c"),
        ("disasm_worldtileloader_bs_18.txt", "implementation: 0x00534ec0", "ARM.exidx end: 0x00535014"),
        ("disasm_worldtileloader_bs_19.txt", "implementation: 0x00535014", "ARM.exidx end: 0x00535720"),
        ("disasm_worldtileloader_bs_20.txt", "implementation: 0x0054fe7c", "ARM.exidx end: 0x00550020"),
        ("disasm_worldtileloader_bs_21.txt", "implementation: 0x00550664", "ARM.exidx end: 0x00551100"),
        ("disasm_worldtileloader_bs_22.txt", "implementation: 0x0054a448", "ARM.exidx end: 0x0054fe7c"),
        ("disasm_worldtileloader_bs_23.txt", "implementation: 0x00535720", "ARM.exidx end: 0x00535808"),
        ("disasm_worldtileloader_bs_24.txt", "implementation: 0x0052eb80", "ARM.exidx end: 0x00531088"),
        ("disasm_worldtileloader_bs_25.txt", "implementation: 0x00550020", "ARM.exidx end: 0x00550154"),
        ("disasm_worldtileloader_bs_26.txt", "implementation: 0x005505e4", "ARM.exidx end: 0x00550600"),
        ("disasm_worldtileloader_bs_27.txt", "implementation: 0x00533a58", "ARM.exidx end: 0x00533cbc"),
        ("disasm_worldtileloader_bs_28.txt", "implementation: 0x00533678", "ARM.exidx end: 0x005336cc"),
        ("disasm_worldtileloader_bs_29.txt", "implementation: 0x005379e8", "ARM.exidx end: 0x00542d70"),
        ("disasm_worldtileloader_bs_30.txt", "implementation: 0x00534188", "ARM.exidx end: 0x00534ec0"),
        ("disasm_worldtileloader_bs_31.txt", "implementation: 0x00542f3c", "ARM.exidx end: 0x00542f60"),
        ("disasm_worldtileloader_bs_32.txt", "implementation: 0x0055197c", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_33.txt", "implementation: 0x00547ee0", "ARM.exidx end: 0x00547f74"),
        ("disasm_worldtileloader_bs_34.txt", "implementation: 0x00547f74", "ARM.exidx end: 0x00549af0"),
        ("disasm_worldtileloader_bs_35.txt", "implementation: 0x00537044", "ARM.exidx end: 0x00537304"),
        ("disasm_worldtileloader_bs_36.txt", "implementation: 0x00536f68", "ARM.exidx end: 0x00537044"),
        ("disasm_worldtileloader_bs_37.txt", "implementation: 0x00536160", "ARM.exidx end: 0x00536538"),
        ("disasm_worldtileloader_bs_38.txt", "implementation: 0x00535808", "ARM.exidx end: 0x00535d90"),
        ("disasm_worldtileloader_bs_39.txt", "implementation: 0x00536ae4", "ARM.exidx end: 0x00536d40"),
        ("disasm_worldtileloader_bs_40.txt", "implementation: 0x00536d40", "ARM.exidx end: 0x00536f68"),
        ("disasm_worldtileloader_bs_41.txt", "implementation: 0x0053788c", "ARM.exidx end: 0x005379e8"),
        ("disasm_worldtileloader_bs_42.txt", "implementation: 0x00537304", "ARM.exidx end: 0x00537560"),
        ("disasm_worldtileloader_bs_43.txt", "implementation: 0x00536930", "ARM.exidx end: 0x00536ae4"),
        ("disasm_worldtileloader_bs_44.txt", "implementation: 0x0053655c", "ARM.exidx end: 0x00536930"),
        ("disasm_worldtileloader_bs_45.txt", "implementation: 0x00543d40", "ARM.exidx end: 0x00544964"),
        ("disasm_worldtileloader_bs_46.txt", "implementation: 0x00550258", "ARM.exidx end: 0x005503e4"),
        ("disasm_worldtileloader_bs_47.txt", "implementation: 0x005519c0", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_48.txt", "implementation: 0x00550430", "ARM.exidx end: 0x005505e4"),
        ("disasm_worldtileloader_bs_49.txt", "implementation: 0x0055186c", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_50.txt", "implementation: 0x005450e4", "ARM.exidx end: 0x00547acc"),
        ("disasm_worldtileloader_bs_51.txt", "implementation: 0x0054a0a4", "ARM.exidx end: 0x0054a448"),
        ("disasm_worldtileloader_bs_52.txt", "implementation: 0x00549af0", "ARM.exidx end: 0x0054a0a4"),
        ("disasm_worldtileloader_bs_53.txt", "implementation: 0x0053294c", "ARM.exidx end: 0x00532a18"),
        ("disasm_worldtileloader_bs_54.txt", "implementation: 0x00532a18", "ARM.exidx end: 0x00532cb8"),
        ("disasm_worldtileloader_bs_55.txt", "implementation: 0x00535d90", "ARM.exidx end: 0x00536160"),
        ("disasm_worldtileloader_bs_56.txt", "implementation: 0x00542f60", "ARM.exidx end: 0x00543a4c"),
        ("disasm_worldtileloader_bs_57.txt", "implementation: 0x00544964", "ARM.exidx end: 0x00544b70"),
        ("disasm_worldtileloader_bs_58.txt", "implementation: 0x00542d70", "ARM.exidx end: 0x00542f3c"),
        ("disasm_worldtileloader_bs_59.txt", "implementation: 0x00550600", "ARM.exidx end: 0x00550664"),
        ("disasm_worldtileloader_bs_60.txt", "implementation: 0x005512b8", "ARM.exidx end: 0x0055172c"),
        ("disasm_worldtileloader_bs_61.txt", "implementation: 0x00544b70", "ARM.exidx end: 0x00544c00"),
        ("disasm_worldtileloader_bs_62.txt", "implementation: 0x00551a04", "ARM.exidx end: 0x00551a8c"),
        ("disasm_worldtileloader_bs_63.txt", "implementation: 0x005503e4", "ARM.exidx end: 0x00550430"),
        ("disasm_worldtileloader_bs_64.txt", "implementation: 0x00533064", "ARM.exidx end: 0x00533678"),
        ("disasm_worldtileloader_bs_65.txt", "implementation: 0x0055172c", "ARM.exidx end: 0x0055186c"),
        ("disasm_worldtileloader_bs_66.txt", "implementation: 0x00550154", "ARM.exidx end: 0x00550258"),
        ("disasm_worldtileloader_bs_67.txt", "implementation: 0x00537560", "ARM.exidx end: 0x00537614"),
        ("disasm_worldtileloader_bs_68.txt", "implementation: 0x00537614", "ARM.exidx end: 0x0053788c"),
        ("disasm_worldtileloader_bs_69.txt", "implementation: 0x005518f4", "ARM.exidx end: 0x00551a8c"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "MAINMENU.md",
        [
            "22053",
            'MainMenuUI',
            'menu',
            'save',
        ],
    )
    require(
        NATIVE / "mainmenu.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 10738',
            '"verified_words": 45',
            '0x88',
            '"mm_51"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_mm_00.txt", "implementation: 0x00a10360", "ARM.exidx end: 0x00a104a0"),
        ("disasm_worldtileloader_mm_01.txt", "implementation: 0x00a0fdd0", "ARM.exidx end: 0x00a0fee0"),
        ("disasm_worldtileloader_mm_02.txt", "implementation: 0x00a0fee0", "ARM.exidx end: 0x00a0ff44"),
        ("disasm_worldtileloader_mm_03.txt", "implementation: 0x00a101d8", "ARM.exidx end: 0x00a10250"),
        ("disasm_worldtileloader_mm_04.txt", "implementation: 0x00a0fc64", "ARM.exidx end: 0x00a0fd68"),
        ("disasm_worldtileloader_mm_05.txt", "implementation: 0x00a0ff44", "ARM.exidx end: 0x00a0ff80"),
        ("disasm_worldtileloader_mm_06.txt", "implementation: 0x009f90cc", "ARM.exidx end: 0x009f91a8"),
        ("disasm_worldtileloader_mm_07.txt", "implementation: 0x00a0fc4c", "ARM.exidx end: 0x00a0fc64"),
        ("disasm_worldtileloader_mm_08.txt", "implementation: 0x00a0fc30", "ARM.exidx end: 0x00a0fc64"),
        ("disasm_worldtileloader_mm_09.txt", "implementation: 0x00a0f314", "ARM.exidx end: 0x00a0f3fc"),
        ("disasm_worldtileloader_mm_10.txt", "implementation: 0x009f7620", "ARM.exidx end: 0x009f76e0"),
        ("disasm_worldtileloader_mm_11.txt", "implementation: 0x00a0f288", "ARM.exidx end: 0x00a0f314"),
        ("disasm_worldtileloader_mm_12.txt", "implementation: 0x00a0c7f0", "ARM.exidx end: 0x00a0c9e4"),
        ("disasm_worldtileloader_mm_13.txt", "implementation: 0x00a10294", "ARM.exidx end: 0x00a10360"),
        ("disasm_worldtileloader_mm_14.txt", "implementation: 0x00a0e40c", "ARM.exidx end: 0x00a0ef0c"),
        ("disasm_worldtileloader_mm_15.txt", "implementation: 0x00a10214", "ARM.exidx end: 0x00a10250"),
        ("disasm_worldtileloader_mm_16.txt", "implementation: 0x009fc874", "ARM.exidx end: 0x009fcf64"),
        ("disasm_worldtileloader_mm_17.txt", "implementation: 0x009f76e0", "ARM.exidx end: 0x009f7710"),
        ("disasm_worldtileloader_mm_18.txt", "implementation: 0x00a0cfe0", "ARM.exidx end: 0x00a0d060"),
        ("disasm_worldtileloader_mm_19.txt", "implementation: 0x009fc3f4", "ARM.exidx end: 0x009fc510"),
        ("disasm_worldtileloader_mm_20.txt", "implementation: 0x00a0e2b0", "ARM.exidx end: 0x00a0e2c4"),
        ("disasm_worldtileloader_mm_21.txt", "implementation: 0x00a0fbd4", "ARM.exidx end: 0x00a0fc30"),
        ("disasm_worldtileloader_mm_22.txt", "implementation: 0x009fc610", "ARM.exidx end: 0x009fc874"),
        ("disasm_worldtileloader_mm_23.txt", "implementation: 0x00a10070", "ARM.exidx end: 0x00a100b0"),
        ("disasm_worldtileloader_mm_24.txt", "implementation: 0x00a100b0", "ARM.exidx end: 0x00a10174"),
        ("disasm_worldtileloader_mm_25.txt", "implementation: 0x00a0ff80", "ARM.exidx end: 0x00a10070"),
        ("disasm_worldtileloader_mm_26.txt", "implementation: 0x00a0de90", "ARM.exidx end: 0x00a0e080"),
        ("disasm_worldtileloader_mm_27.txt", "implementation: 0x00a0dca0", "ARM.exidx end: 0x00a0de90"),
        ("disasm_worldtileloader_mm_28.txt", "implementation: 0x009f91a8", "ARM.exidx end: 0x009f93a8"),
        ("disasm_worldtileloader_mm_29.txt", "implementation: 0x00a0fd68", "ARM.exidx end: 0x00a0fdd0"),
        ("disasm_worldtileloader_mm_30.txt", "implementation: 0x00a0d1e4", "ARM.exidx end: 0x00a0d488"),
        ("disasm_worldtileloader_mm_31.txt", "implementation: 0x00a0ef70", "ARM.exidx end: 0x00a0f024"),
        ("disasm_worldtileloader_mm_32.txt", "implementation: 0x00a0f024", "ARM.exidx end: 0x00a0f088"),
        ("disasm_worldtileloader_mm_33.txt", "implementation: 0x00a0ef0c", "ARM.exidx end: 0x00a0ef70"),
        ("disasm_worldtileloader_mm_34.txt", "implementation: 0x00a0f12c", "ARM.exidx end: 0x00a0f1a8"),
        ("disasm_worldtileloader_mm_35.txt", "implementation: 0x009f93a8", "ARM.exidx end: 0x009fc108"),
        ("disasm_worldtileloader_mm_36.txt", "implementation: 0x00a0d9c8", "ARM.exidx end: 0x00a0da04"),
        ("disasm_worldtileloader_mm_37.txt", "implementation: 0x00a0fc14", "ARM.exidx end: 0x00a0fc30"),
        ("disasm_worldtileloader_mm_38.txt", "implementation: 0x00a0cf30", "ARM.exidx end: 0x00a0cfe0"),
        ("disasm_worldtileloader_mm_39.txt", "implementation: 0x00a0ca4c", "ARM.exidx end: 0x00a0cbd0"),
        ("disasm_worldtileloader_mm_40.txt", "implementation: 0x00a0cbd0", "ARM.exidx end: 0x00a0cf30"),
        ("disasm_worldtileloader_mm_41.txt", "implementation: 0x00a102d8", "ARM.exidx end: 0x00a10360"),
        ("disasm_worldtileloader_mm_42.txt", "implementation: 0x00a0c3c8", "ARM.exidx end: 0x00a0c7f0"),
        ("disasm_worldtileloader_mm_43.txt", "implementation: 0x00a10250", "ARM.exidx end: 0x00a10360"),
        ("disasm_worldtileloader_mm_44.txt", "implementation: 0x00a0d060", "ARM.exidx end: 0x00a0d0e0"),
        ("disasm_worldtileloader_mm_45.txt", "implementation: 0x00a0e218", "ARM.exidx end: 0x00a0e29c"),
        ("disasm_worldtileloader_mm_46.txt", "implementation: 0x00a0a4c4", "ARM.exidx end: 0x00a0ae10"),
        ("disasm_worldtileloader_mm_47.txt", "implementation: 0x00a0da84", "ARM.exidx end: 0x00a0dac4"),
        ("disasm_worldtileloader_mm_48.txt", "implementation: 0x009fc510", "ARM.exidx end: 0x009fc610"),
        ("disasm_worldtileloader_mm_49.txt", "implementation: 0x00a0f4c8", "ARM.exidx end: 0x00a0f744"),
        ("disasm_worldtileloader_mm_50.txt", "implementation: 0x00a0d0e0", "ARM.exidx end: 0x00a0d1e4"),
        ("disasm_worldtileloader_mm_51.txt", "implementation: 0x009fdf68", "ARM.exidx end: 0x00a08730"),
        ("disasm_worldtileloader_mm_52.txt", "implementation: 0x009f8294", "ARM.exidx end: 0x009f82a8"),
        ("disasm_worldtileloader_mm_53.txt", "implementation: 0x009f824c", "ARM.exidx end: 0x009f8294"),
        ("disasm_worldtileloader_mm_54.txt", "implementation: 0x009f7ee4", "ARM.exidx end: 0x009f824c"),
        ("disasm_worldtileloader_mm_55.txt", "implementation: 0x00a0dac4", "ARM.exidx end: 0x00a0dca0"),
        ("disasm_worldtileloader_mm_56.txt", "implementation: 0x00a0c014", "ARM.exidx end: 0x00a0c3c8"),
        ("disasm_worldtileloader_mm_57.txt", "implementation: 0x009f7710", "ARM.exidx end: 0x009f7e7c"),
        ("disasm_worldtileloader_mm_58.txt", "implementation: 0x00a0da04", "ARM.exidx end: 0x00a0da84"),
        ("disasm_worldtileloader_mm_59.txt", "implementation: 0x00a0e0d8", "ARM.exidx end: 0x00a0e218"),
        ("disasm_worldtileloader_mm_60.txt", "implementation: 0x00a0f3fc", "ARM.exidx end: 0x00a0f4c8"),
        ("disasm_worldtileloader_mm_61.txt", "implementation: 0x009f7ec8", "ARM.exidx end: 0x009f7ee4"),
        ("disasm_worldtileloader_mm_62.txt", "implementation: 0x00a10174", "ARM.exidx end: 0x00a101d8"),
        ("disasm_worldtileloader_mm_63.txt", "implementation: 0x00a0e2c4", "ARM.exidx end: 0x00a0e40c"),
        ("disasm_worldtileloader_mm_64.txt", "implementation: 0x00a0c9e4", "ARM.exidx end: 0x00a0ca4c"),
        ("disasm_worldtileloader_mm_65.txt", "implementation: 0x00a0f1a8", "ARM.exidx end: 0x00a0f288"),
        ("disasm_worldtileloader_mm_66.txt", "implementation: 0x00a0f0c8", "ARM.exidx end: 0x00a0f12c"),
        ("disasm_worldtileloader_mm_67.txt", "implementation: 0x009f8bf4", "ARM.exidx end: 0x009f90cc"),
        ("disasm_worldtileloader_mm_68.txt", "implementation: 0x00a0d488", "ARM.exidx end: 0x00a0d9c8"),
        ("disasm_worldtileloader_mm_69.txt", "implementation: 0x00a1031c", "ARM.exidx end: 0x00a10360"),
        ("disasm_worldtileloader_mm_70.txt", "implementation: 0x00a0e080", "ARM.exidx end: 0x00a0e0d8"),
        ("disasm_worldtileloader_mm_71.txt", "implementation: 0x00a0f088", "ARM.exidx end: 0x00a0f0c8"),
        ("disasm_worldtileloader_mm_72.txt", "implementation: 0x00a09d70", "ARM.exidx end: 0x00a09df0"),
        ("disasm_worldtileloader_mm_73.txt", "implementation: 0x009f8be0", "ARM.exidx end: 0x009f8bf4"),
        ("disasm_worldtileloader_mm_74.txt", "implementation: 0x009f82a8", "ARM.exidx end: 0x009f8b68"),
        ("disasm_worldtileloader_mm_75.txt", "implementation: 0x009fc270", "ARM.exidx end: 0x009fc3f4"),
        ("disasm_worldtileloader_mm_76.txt", "implementation: 0x00a0e29c", "ARM.exidx end: 0x00a0e2c4"),
        ("disasm_worldtileloader_mm_77.txt", "implementation: 0x009fcf64", "ARM.exidx end: 0x009fdf50"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "WORLDUI2.md",
        [
            "28977",
            'WorldUI',
            'inventory',
            'button',
        ],
    )
    require(
        NATIVE / "worldui2.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 4431',
            '"verified_words": 160',
            '0xce1cac',
            '"wv_34"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_wv_00.txt", "implementation: 0x00cffd68", "ARM.exidx end: 0x00cffd80"),
        ("disasm_worldtileloader_wv_01.txt", "implementation: 0x00cff838", "ARM.exidx end: 0x00cffaf8"),
        ("disasm_worldtileloader_wv_02.txt", "implementation: 0x00cf9258", "ARM.exidx end: 0x00cf9fd4"),
        ("disasm_worldtileloader_wv_03.txt", "implementation: 0x00cebc7c", "ARM.exidx end: 0x00cebf78"),
        ("disasm_worldtileloader_wv_04.txt", "implementation: 0x00cfcf34", "ARM.exidx end: 0x00cfd298"),
        ("disasm_worldtileloader_wv_05.txt", "implementation: 0x00ce1930", "ARM.exidx end: 0x00ce1f94"),
        ("disasm_worldtileloader_wv_06.txt", "implementation: 0x00cff074", "ARM.exidx end: 0x00cff30c"),
        ("disasm_worldtileloader_wv_07.txt", "implementation: 0x00cfb644", "ARM.exidx end: 0x00cfcc1c"),
        ("disasm_worldtileloader_wv_08.txt", "implementation: 0x00cf2e2c", "ARM.exidx end: 0x00cf380c"),
        ("disasm_worldtileloader_wv_09.txt", "implementation: 0x00cfec68", "ARM.exidx end: 0x00cfed38"),
        ("disasm_worldtileloader_wv_10.txt", "implementation: 0x00cf9fd4", "ARM.exidx end: 0x00cfa448"),
        ("disasm_worldtileloader_wv_11.txt", "implementation: 0x00cfb310", "ARM.exidx end: 0x00cfb378"),
        ("disasm_worldtileloader_wv_12.txt", "implementation: 0x00cffaf8", "ARM.exidx end: 0x00cffb60"),
        ("disasm_worldtileloader_wv_13.txt", "implementation: 0x00cffb60", "ARM.exidx end: 0x00cffc70"),
        ("disasm_worldtileloader_wv_14.txt", "implementation: 0x00cf5594", "ARM.exidx end: 0x00cf5874"),
        ("disasm_worldtileloader_wv_15.txt", "implementation: 0x00cfd938", "ARM.exidx end: 0x00cfe704"),
        ("disasm_worldtileloader_wv_16.txt", "implementation: 0x00ce1584", "ARM.exidx end: 0x00ce1930"),
        ("disasm_worldtileloader_wv_17.txt", "implementation: 0x00cfec20", "ARM.exidx end: 0x00cfec68"),
        ("disasm_worldtileloader_wv_18.txt", "implementation: 0x00cffc70", "ARM.exidx end: 0x00cffd24"),
        ("disasm_worldtileloader_wv_19.txt", "implementation: 0x00cffcac", "ARM.exidx end: 0x00cffd24"),
        ("disasm_worldtileloader_wv_20.txt", "implementation: 0x00cf3998", "ARM.exidx end: 0x00cf4d70"),
        ("disasm_worldtileloader_wv_21.txt", "implementation: 0x00cfa448", "ARM.exidx end: 0x00cfb310"),
        ("disasm_worldtileloader_wv_22.txt", "implementation: 0x00cf61d8", "ARM.exidx end: 0x00cf6270"),
        ("disasm_worldtileloader_wv_23.txt", "implementation: 0x00cfe9d0", "ARM.exidx end: 0x00cfec20"),
        ("disasm_worldtileloader_wv_24.txt", "implementation: 0x00cddc10", "ARM.exidx end: 0x00ce123c"),
        ("disasm_worldtileloader_wv_25.txt", "implementation: 0x00ce1f94", "ARM.exidx end: 0x00ce20e8"),
        ("disasm_worldtileloader_wv_26.txt", "implementation: 0x00cf6154", "ARM.exidx end: 0x00cf61d8"),
        ("disasm_worldtileloader_wv_27.txt", "implementation: 0x00cf6de8", "ARM.exidx end: 0x00cf8430"),
        ("disasm_worldtileloader_wv_28.txt", "implementation: 0x00cff700", "ARM.exidx end: 0x00cff78c"),
        ("disasm_worldtileloader_wv_29.txt", "implementation: 0x00cff30c", "ARM.exidx end: 0x00cff698"),
        ("disasm_worldtileloader_wv_30.txt", "implementation: 0x00cfd298", "ARM.exidx end: 0x00cfd2b0"),
        ("disasm_worldtileloader_wv_31.txt", "implementation: 0x00cfcc84", "ARM.exidx end: 0x00cfccec"),
        ("disasm_worldtileloader_wv_32.txt", "implementation: 0x00cffce8", "ARM.exidx end: 0x00cffd24"),
        ("disasm_worldtileloader_wv_33.txt", "implementation: 0x00cfed38", "ARM.exidx end: 0x00cff074"),
        ("disasm_worldtileloader_wv_34.txt", "implementation: 0x00ce3e68", "ARM.exidx end: 0x00ce83a4"),
        ("disasm_worldtileloader_wv_35.txt", "implementation: 0x00ce90f8", "ARM.exidx end: 0x00ceb020"),
        ("disasm_worldtileloader_wv_36.txt", "implementation: 0x00ceb020", "ARM.exidx end: 0x00ceb5a0"),
        ("disasm_worldtileloader_wv_37.txt", "implementation: 0x00ceb5a0", "ARM.exidx end: 0x00cebb04"),
        ("disasm_worldtileloader_wv_38.txt", "implementation: 0x00cff78c", "ARM.exidx end: 0x00cff7d4"),
        ("disasm_worldtileloader_wv_39.txt", "implementation: 0x00cfccec", "ARM.exidx end: 0x00cfcf34"),
        ("disasm_worldtileloader_wv_40.txt", "implementation: 0x00cfb378", "ARM.exidx end: 0x00cfb618"),
        ("disasm_worldtileloader_wv_41.txt", "implementation: 0x00cebb04", "ARM.exidx end: 0x00cebc7c"),
        ("disasm_worldtileloader_wv_42.txt", "implementation: 0x00cff7d4", "ARM.exidx end: 0x00cff838"),
        ("disasm_worldtileloader_wv_43.txt", "implementation: 0x00cfd3f8", "ARM.exidx end: 0x00cfd938"),
        ("disasm_worldtileloader_wv_44.txt", "implementation: 0x00cfe704", "ARM.exidx end: 0x00cfe9d0"),
        ("disasm_worldtileloader_wv_45.txt", "implementation: 0x00cf1468", "ARM.exidx end: 0x00cf1554"),
        ("disasm_worldtileloader_wv_46.txt", "implementation: 0x00cffba4", "ARM.exidx end: 0x00cffc70"),
        ("disasm_worldtileloader_wv_47.txt", "implementation: 0x00cffd24", "ARM.exidx end: 0x00cffd68"),
        ("disasm_worldtileloader_wv_48.txt", "implementation: 0x00ce1458", "ARM.exidx end: 0x00ce1584"),
        ("disasm_worldtileloader_wv_49.txt", "implementation: 0x00cffc2c", "ARM.exidx end: 0x00cffc70"),
        ("disasm_worldtileloader_wv_50.txt", "implementation: 0x00cf2114", "ARM.exidx end: 0x00cf2e2c"),
        ("disasm_worldtileloader_wv_51.txt", "implementation: 0x00cf60bc", "ARM.exidx end: 0x00cf6154"),
        ("disasm_worldtileloader_wv_52.txt", "implementation: 0x00cf6270", "ARM.exidx end: 0x00cf6de8"),
        ("disasm_worldtileloader_wv_53.txt", "implementation: 0x00cf5874", "ARM.exidx end: 0x00cf60bc"),
        ("disasm_worldtileloader_wv_54.txt", "implementation: 0x00cfd2b0", "ARM.exidx end: 0x00cfd310"),
        ("disasm_worldtileloader_wv_55.txt", "implementation: 0x00cfcc1c", "ARM.exidx end: 0x00cfcc84"),
        ("disasm_worldtileloader_wv_56.txt", "implementation: 0x00cf4d70", "ARM.exidx end: 0x00cf5594"),
        ("disasm_worldtileloader_wv_57.txt", "implementation: 0x00cffbe8", "ARM.exidx end: 0x00cffc70"),
        ("disasm_worldtileloader_wv_58.txt", "implementation: 0x00ce3cd4", "ARM.exidx end: 0x00ce3e68"),
        ("disasm_worldtileloader_wv_59.txt", "implementation: 0x00cebf78", "ARM.exidx end: 0x00cec248"),
        ("disasm_worldtileloader_wv_60.txt", "implementation: 0x00cec248", "ARM.exidx end: 0x00cec8e4"),
        ("disasm_worldtileloader_wv_61.txt", "implementation: 0x00cf1d98", "ARM.exidx end: 0x00cf1e94"),
        ("disasm_worldtileloader_wv_62.txt", "implementation: 0x00cf1c38", "ARM.exidx end: 0x00cf1d98"),
        ("disasm_worldtileloader_wv_63.txt", "implementation: 0x00cf1e94", "ARM.exidx end: 0x00cf2114"),
        ("disasm_worldtileloader_wv_64.txt", "implementation: 0x00cf1554", "ARM.exidx end: 0x00cf1c38"),
        ("disasm_worldtileloader_wv_65.txt", "implementation: 0x00cf8430", "ARM.exidx end: 0x00cf9258"),
        ("disasm_worldtileloader_wv_66.txt", "implementation: 0x00cff698", "ARM.exidx end: 0x00cff700"),
        ("disasm_worldtileloader_wv_67.txt", "implementation: 0x00ce20e8", "ARM.exidx end: 0x00ce3cd4"),
        ("disasm_worldtileloader_wv_68.txt", "implementation: 0x00cfd310", "ARM.exidx end: 0x00cfd3f8"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "GVIEWA.md",
        [
            "15107",
            'Game Center',
            'cloud',
            'chat',
        ],
    )
    require(
        NATIVE / "gviewa.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 1355',
            '"verified_words": 94',
            'auth',
            '"gx_34"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_gx_00.txt", "implementation: 0x00944c64", "ARM.exidx end: 0x00944da8"),
        ("disasm_worldtileloader_gx_01.txt", "implementation: 0x0092bc24", "ARM.exidx end: 0x0092bc54"),
        ("disasm_worldtileloader_gx_02.txt", "implementation: 0x0093c6c8", "ARM.exidx end: 0x0093c740"),
        ("disasm_worldtileloader_gx_03.txt", "implementation: 0x0093c420", "ARM.exidx end: 0x0093c6c8"),
        ("disasm_worldtileloader_gx_04.txt", "implementation: 0x00923d68", "ARM.exidx end: 0x00923f78"),
        ("disasm_worldtileloader_gx_05.txt", "implementation: 0x00931aec", "ARM.exidx end: 0x00932670"),
        ("disasm_worldtileloader_gx_06.txt", "implementation: 0x00944558", "ARM.exidx end: 0x009447c8"),
        ("disasm_worldtileloader_gx_07.txt", "implementation: 0x00939c3c", "ARM.exidx end: 0x0093a3b0"),
        ("disasm_worldtileloader_gx_08.txt", "implementation: 0x0093c7d8", "ARM.exidx end: 0x0093c874"),
        ("disasm_worldtileloader_gx_09.txt", "implementation: 0x00938dac", "ARM.exidx end: 0x00938f48"),
        ("disasm_worldtileloader_gx_10.txt", "implementation: 0x0094491c", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gx_11.txt", "implementation: 0x00944960", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gx_12.txt", "implementation: 0x00921064", "ARM.exidx end: 0x00921270"),
        ("disasm_worldtileloader_gx_13.txt", "implementation: 0x00939580", "ARM.exidx end: 0x00939614"),
        ("disasm_worldtileloader_gx_14.txt", "implementation: 0x00917d20", "ARM.exidx end: 0x00917db8"),
        ("disasm_worldtileloader_gx_15.txt", "implementation: 0x00942178", "ARM.exidx end: 0x00942274"),
        ("disasm_worldtileloader_gx_16.txt", "implementation: 0x00944b68", "ARM.exidx end: 0x00944ba4"),
        ("disasm_worldtileloader_gx_17.txt", "implementation: 0x0093fb3c", "ARM.exidx end: 0x0093feb4"),
        ("disasm_worldtileloader_gx_18.txt", "implementation: 0x0093f8c4", "ARM.exidx end: 0x0093fb3c"),
        ("disasm_worldtileloader_gx_19.txt", "implementation: 0x0093f7d8", "ARM.exidx end: 0x0093f8c4"),
        ("disasm_worldtileloader_gx_20.txt", "implementation: 0x0093f770", "ARM.exidx end: 0x0093f7d8"),
        ("disasm_worldtileloader_gx_21.txt", "implementation: 0x0091b500", "ARM.exidx end: 0x0091bce8"),
        ("disasm_worldtileloader_gx_22.txt", "implementation: 0x009352ac", "ARM.exidx end: 0x009353f0"),
        ("disasm_worldtileloader_gx_23.txt", "implementation: 0x0093feb4", "ARM.exidx end: 0x0093fff0"),
        ("disasm_worldtileloader_gx_24.txt", "implementation: 0x0092f8dc", "ARM.exidx end: 0x0092f964"),
        ("disasm_worldtileloader_gx_25.txt", "implementation: 0x0091bce8", "ARM.exidx end: 0x0091c1dc"),
        ("disasm_worldtileloader_gx_26.txt", "implementation: 0x0091c1dc", "ARM.exidx end: 0x0091c5e8"),
        ("disasm_worldtileloader_gx_27.txt", "implementation: 0x00940e88", "ARM.exidx end: 0x00940f24"),
        ("disasm_worldtileloader_gx_28.txt", "implementation: 0x00942c04", "ARM.exidx end: 0x009439d4"),
        ("disasm_worldtileloader_gx_29.txt", "implementation: 0x00922110", "ARM.exidx end: 0x0092352c"),
        ("disasm_worldtileloader_gx_30.txt", "implementation: 0x00936348", "ARM.exidx end: 0x0093687c"),
        ("disasm_worldtileloader_gx_31.txt", "implementation: 0x009390c8", "ARM.exidx end: 0x00939580"),
        ("disasm_worldtileloader_gx_32.txt", "implementation: 0x00938f48", "ARM.exidx end: 0x009390c8"),
        ("disasm_worldtileloader_gx_33.txt", "implementation: 0x00939614", "ARM.exidx end: 0x00939c3c"),
        ("disasm_worldtileloader_gx_34.txt", "implementation: 0x0093687c", "ARM.exidx end: 0x00937da8"),
        ("disasm_worldtileloader_gx_35.txt", "implementation: 0x00920374", "ARM.exidx end: 0x0092059c"),
        ("disasm_worldtileloader_gx_36.txt", "implementation: 0x00940284", "ARM.exidx end: 0x00940dc4"),
        ("disasm_worldtileloader_gx_37.txt", "implementation: 0x00932e80", "ARM.exidx end: 0x00933214"),
        ("disasm_worldtileloader_gx_38.txt", "implementation: 0x00933214", "ARM.exidx end: 0x00933e7c"),
        ("disasm_worldtileloader_gx_39.txt", "implementation: 0x0092f964", "ARM.exidx end: 0x00930bb4"),
        ("disasm_worldtileloader_gx_40.txt", "implementation: 0x0093c008", "ARM.exidx end: 0x0093c10c"),
        ("disasm_worldtileloader_gx_41.txt", "implementation: 0x00930bb4", "ARM.exidx end: 0x00931204"),
        ("disasm_worldtileloader_gx_42.txt", "implementation: 0x0093bf58", "ARM.exidx end: 0x0093c008"),
        ("disasm_worldtileloader_gx_43.txt", "implementation: 0x0093bdb8", "ARM.exidx end: 0x0093bf58"),
        ("disasm_worldtileloader_gx_44.txt", "implementation: 0x0093c10c", "ARM.exidx end: 0x0093c420"),
        ("disasm_worldtileloader_gx_45.txt", "implementation: 0x0093bc40", "ARM.exidx end: 0x0093bdb8"),
        ("disasm_worldtileloader_gx_46.txt", "implementation: 0x00934d78", "ARM.exidx end: 0x00934f7c"),
        ("disasm_worldtileloader_gx_47.txt", "implementation: 0x00932670", "ARM.exidx end: 0x00932cec"),
        ("disasm_worldtileloader_gx_48.txt", "implementation: 0x0092edac", "ARM.exidx end: 0x0092ee80"),
        ("disasm_worldtileloader_gx_49.txt", "implementation: 0x00932cec", "ARM.exidx end: 0x00932e80"),
        ("disasm_worldtileloader_gx_50.txt", "implementation: 0x009253bc", "ARM.exidx end: 0x0092564c"),
        ("disasm_worldtileloader_gx_51.txt", "implementation: 0x009207e0", "ARM.exidx end: 0x0092085c"),
        ("disasm_worldtileloader_gx_52.txt", "implementation: 0x0093c740", "ARM.exidx end: 0x0093c7b8"),
        ("disasm_worldtileloader_gx_53.txt", "implementation: 0x009448d8", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gx_54.txt", "implementation: 0x0093a718", "ARM.exidx end: 0x0093a8f8"),
        ("disasm_worldtileloader_gx_55.txt", "implementation: 0x00944be4", "ARM.exidx end: 0x00944c64"),
        ("disasm_worldtileloader_gx_56.txt", "implementation: 0x0091b268", "ARM.exidx end: 0x0091b500"),
        ("disasm_worldtileloader_gx_57.txt", "implementation: 0x00944850", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gx_58.txt", "implementation: 0x00940dc4", "ARM.exidx end: 0x00940e88"),
        ("disasm_worldtileloader_gx_59.txt", "implementation: 0x00940ff0", "ARM.exidx end: 0x00941128"),
        ("disasm_worldtileloader_gx_60.txt", "implementation: 0x00920f28", "ARM.exidx end: 0x00920fb8"),
        ("disasm_worldtileloader_gx_61.txt", "implementation: 0x00920fb8", "ARM.exidx end: 0x00921064"),
        ("disasm_worldtileloader_gx_62.txt", "implementation: 0x0093f70c", "ARM.exidx end: 0x0093f7d8"),
        ("disasm_worldtileloader_gx_63.txt", "implementation: 0x00923778", "ARM.exidx end: 0x00923860"),
        ("disasm_worldtileloader_gx_64.txt", "implementation: 0x00923698", "ARM.exidx end: 0x00923778"),
        ("disasm_worldtileloader_gx_65.txt", "implementation: 0x00923860", "ARM.exidx end: 0x00923918"),
        ("disasm_worldtileloader_gx_66.txt", "implementation: 0x00924378", "ARM.exidx end: 0x00924748"),
        ("disasm_worldtileloader_gx_67.txt", "implementation: 0x00924748", "ARM.exidx end: 0x00924b10"),
        ("disasm_worldtileloader_gx_68.txt", "implementation: 0x0092085c", "ARM.exidx end: 0x00920b98"),
        ("disasm_worldtileloader_gx_69.txt", "implementation: 0x0093c9cc", "ARM.exidx end: 0x0093cd28"),
        ("disasm_worldtileloader_gx_70.txt", "implementation: 0x00944a2c", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gx_71.txt", "implementation: 0x0093cd28", "ARM.exidx end: 0x0093ce48"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "GVIEWB.md",
        [
            "16513",
            'panGesture',
            'loadWorld',
            'timer',
        ],
    )
    require(
        NATIVE / "gviewb.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 3166',
            '"verified_words": 130',
            'loadWorld',
            '"gy_17"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_gy_00.txt", "implementation: 0x009347e4", "ARM.exidx end: 0x00934d78"),
        ("disasm_worldtileloader_gy_01.txt", "implementation: 0x0093a55c", "ARM.exidx end: 0x0093a718"),
        ("disasm_worldtileloader_gy_02.txt", "implementation: 0x009449e8", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gy_03.txt", "implementation: 0x0092059c", "ARM.exidx end: 0x009207e0"),
        ("disasm_worldtileloader_gy_04.txt", "implementation: 0x0093c7b8", "ARM.exidx end: 0x0093c7d8"),
        ("disasm_worldtileloader_gy_05.txt", "implementation: 0x009345fc", "ARM.exidx end: 0x009347e4"),
        ("disasm_worldtileloader_gy_06.txt", "implementation: 0x0092cba8", "ARM.exidx end: 0x0092d188"),
        ("disasm_worldtileloader_gy_07.txt", "implementation: 0x009357b4", "ARM.exidx end: 0x00935c3c"),
        ("disasm_worldtileloader_gy_08.txt", "implementation: 0x00935f2c", "ARM.exidx end: 0x00936348"),
        ("disasm_worldtileloader_gy_09.txt", "implementation: 0x0092ded0", "ARM.exidx end: 0x0092eba4"),
        ("disasm_worldtileloader_gy_10.txt", "implementation: 0x0092564c", "ARM.exidx end: 0x009258c4"),
        ("disasm_worldtileloader_gy_11.txt", "implementation: 0x00921e64", "ARM.exidx end: 0x00922110"),
        ("disasm_worldtileloader_gy_12.txt", "implementation: 0x009258c4", "ARM.exidx end: 0x00925914"),
        ("disasm_worldtileloader_gy_13.txt", "implementation: 0x00944a70", "ARM.exidx end: 0x00944aac"),
        ("disasm_worldtileloader_gy_14.txt", "implementation: 0x009312dc", "ARM.exidx end: 0x00931aec"),
        ("disasm_worldtileloader_gy_15.txt", "implementation: 0x0093ff8c", "ARM.exidx end: 0x0093fff0"),
        ("disasm_worldtileloader_gy_16.txt", "implementation: 0x00924b10", "ARM.exidx end: 0x00924cf4"),
        ("disasm_worldtileloader_gy_17.txt", "implementation: 0x009180cc", "ARM.exidx end: 0x0091b244"),
        ("disasm_worldtileloader_gy_18.txt", "implementation: 0x00923918", "ARM.exidx end: 0x00923d68"),
        ("disasm_worldtileloader_gy_19.txt", "implementation: 0x0093c874", "ARM.exidx end: 0x0093c9cc"),
        ("disasm_worldtileloader_gy_20.txt", "implementation: 0x0093a8f8", "ARM.exidx end: 0x0093ae50"),
        ("disasm_worldtileloader_gy_21.txt", "implementation: 0x0093b008", "ARM.exidx end: 0x0093b568"),
        ("disasm_worldtileloader_gy_22.txt", "implementation: 0x00942288", "ARM.exidx end: 0x009422c4"),
        ("disasm_worldtileloader_gy_23.txt", "implementation: 0x00928bc4", "ARM.exidx end: 0x009290b0"),
        ("disasm_worldtileloader_gy_24.txt", "implementation: 0x0093a3b0", "ARM.exidx end: 0x0093a55c"),
        ("disasm_worldtileloader_gy_25.txt", "implementation: 0x0092f298", "ARM.exidx end: 0x0092f6ac"),
        ("disasm_worldtileloader_gy_26.txt", "implementation: 0x00924cf4", "ARM.exidx end: 0x009253bc"),
        ("disasm_worldtileloader_gy_27.txt", "implementation: 0x0094135c", "ARM.exidx end: 0x00941eb0"),
        ("disasm_worldtileloader_gy_28.txt", "implementation: 0x0092d188", "ARM.exidx end: 0x0092d1c4"),
        ("disasm_worldtileloader_gy_29.txt", "implementation: 0x0093f928", "ARM.exidx end: 0x0093fb3c"),
        ("disasm_worldtileloader_gy_30.txt", "implementation: 0x00944ba4", "ARM.exidx end: 0x00944c64"),
        ("disasm_worldtileloader_gy_31.txt", "implementation: 0x00944c24", "ARM.exidx end: 0x00944c64"),
        ("disasm_worldtileloader_gy_32.txt", "implementation: 0x00944894", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gy_33.txt", "implementation: 0x009439d4", "ARM.exidx end: 0x00943a40"),
        ("disasm_worldtileloader_gy_34.txt", "implementation: 0x00938c58", "ARM.exidx end: 0x00938f48"),
        ("disasm_worldtileloader_gy_35.txt", "implementation: 0x00944aac", "ARM.exidx end: 0x00944aec"),
        ("disasm_worldtileloader_gy_36.txt", "implementation: 0x0094480c", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gy_37.txt", "implementation: 0x00944b28", "ARM.exidx end: 0x00944b68"),
        ("disasm_worldtileloader_gy_38.txt", "implementation: 0x0093b6c8", "ARM.exidx end: 0x0093bc40"),
        ("disasm_worldtileloader_gy_39.txt", "implementation: 0x00944348", "ARM.exidx end: 0x009443b0"),
        ("disasm_worldtileloader_gy_40.txt", "implementation: 0x0093ec54", "ARM.exidx end: 0x0093f130"),
        ("disasm_worldtileloader_gy_41.txt", "implementation: 0x0093f538", "ARM.exidx end: 0x0093f70c"),
        ("disasm_worldtileloader_gy_42.txt", "implementation: 0x009422c4", "ARM.exidx end: 0x009427b0"),
        ("disasm_worldtileloader_gy_43.txt", "implementation: 0x0093ce48", "ARM.exidx end: 0x0093d4b0"),
        ("disasm_worldtileloader_gy_44.txt", "implementation: 0x009443b0", "ARM.exidx end: 0x00944558"),
        ("disasm_worldtileloader_gy_45.txt", "implementation: 0x00943a40", "ARM.exidx end: 0x00943fd0"),
        ("disasm_worldtileloader_gy_46.txt", "implementation: 0x0093dcf4", "ARM.exidx end: 0x0093e0fc"),
        ("disasm_worldtileloader_gy_47.txt", "implementation: 0x0093d818", "ARM.exidx end: 0x0093db60"),
        ("disasm_worldtileloader_gy_48.txt", "implementation: 0x00925914", "ARM.exidx end: 0x00925954"),
        ("disasm_worldtileloader_gy_49.txt", "implementation: 0x00934f7c", "ARM.exidx end: 0x009352ac"),
        ("disasm_worldtileloader_gy_50.txt", "implementation: 0x00923f78", "ARM.exidx end: 0x0092432c"),
        ("disasm_worldtileloader_gy_51.txt", "implementation: 0x00941128", "ARM.exidx end: 0x0094135c"),
        ("disasm_worldtileloader_gy_52.txt", "implementation: 0x009353f0", "ARM.exidx end: 0x009357b4"),
        ("disasm_worldtileloader_gy_53.txt", "implementation: 0x0092c89c", "ARM.exidx end: 0x0092cba8"),
        ("disasm_worldtileloader_gy_54.txt", "implementation: 0x00917818", "ARM.exidx end: 0x00917a20"),
        ("disasm_worldtileloader_gy_55.txt", "implementation: 0x00920b98", "ARM.exidx end: 0x00920f28"),
        ("disasm_worldtileloader_gy_56.txt", "implementation: 0x00942274", "ARM.exidx end: 0x009422c4"),
        ("disasm_worldtileloader_gy_57.txt", "implementation: 0x0092ee80", "ARM.exidx end: 0x0092f298"),
        ("disasm_worldtileloader_gy_58.txt", "implementation: 0x0092eba4", "ARM.exidx end: 0x0092edac"),
        ("disasm_worldtileloader_gy_59.txt", "implementation: 0x0093fff0", "ARM.exidx end: 0x00940284"),
        ("disasm_worldtileloader_gy_60.txt", "implementation: 0x00917db8", "ARM.exidx end: 0x00917f40"),
        ("disasm_worldtileloader_gy_61.txt", "implementation: 0x0093ff18", "ARM.exidx end: 0x0093fff0"),
        ("disasm_worldtileloader_gy_62.txt", "implementation: 0x00933e7c", "ARM.exidx end: 0x009345fc"),
        ("disasm_worldtileloader_gy_63.txt", "implementation: 0x0092de5c", "ARM.exidx end: 0x0092ded0"),
        ("disasm_worldtileloader_gy_64.txt", "implementation: 0x00928030", "ARM.exidx end: 0x00928bc4"),
        ("disasm_worldtileloader_gy_65.txt", "implementation: 0x009447c8", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gy_66.txt", "implementation: 0x00937da8", "ARM.exidx end: 0x00938c58"),
        ("disasm_worldtileloader_gy_67.txt", "implementation: 0x00944aec", "ARM.exidx end: 0x00944b28"),
        ("disasm_worldtileloader_gy_68.txt", "implementation: 0x00931204", "ARM.exidx end: 0x009312dc"),
        ("disasm_worldtileloader_gy_69.txt", "implementation: 0x0092f6ac", "ARM.exidx end: 0x0092f8dc"),
        ("disasm_worldtileloader_gy_70.txt", "implementation: 0x009449a4", "ARM.exidx end: 0x00944a70"),
        ("disasm_worldtileloader_gy_71.txt", "implementation: 0x00925954", "ARM.exidx end: 0x009259c0"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "CREATEWORLDUI.md",
        [
            "36355",
            'cloud',
            'receipt',
            'worldSize',
        ],
    )
    require(
        NATIVE / "createworldui.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 12536',
            '"verified_words": 139',
            '0xcc',
            '"cwu_24"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_cwu_00.txt", "implementation: 0x00b1f6fc", "ARM.exidx end: 0x00b1f7c0"),
        ("disasm_worldtileloader_cwu_01.txt", "implementation: 0x00b30dfc", "ARM.exidx end: 0x00b313c0"),
        ("disasm_worldtileloader_cwu_02.txt", "implementation: 0x00b32ddc", "ARM.exidx end: 0x00b32e40"),
        ("disasm_worldtileloader_cwu_03.txt", "implementation: 0x00b32d70", "ARM.exidx end: 0x00b32ddc"),
        ("disasm_worldtileloader_cwu_04.txt", "implementation: 0x00b32e40", "ARM.exidx end: 0x00b32f10"),
        ("disasm_worldtileloader_cwu_05.txt", "implementation: 0x00b32d0c", "ARM.exidx end: 0x00b32d70"),
        ("disasm_worldtileloader_cwu_06.txt", "implementation: 0x00b32bc8", "ARM.exidx end: 0x00b32d0c"),
        ("disasm_worldtileloader_cwu_07.txt", "implementation: 0x00b3299c", "ARM.exidx end: 0x00b32bc8"),
        ("disasm_worldtileloader_cwu_08.txt", "implementation: 0x00b32858", "ARM.exidx end: 0x00b3299c"),
        ("disasm_worldtileloader_cwu_09.txt", "implementation: 0x00b326d8", "ARM.exidx end: 0x00b32858"),
        ("disasm_worldtileloader_cwu_10.txt", "implementation: 0x00b32280", "ARM.exidx end: 0x00b3265c"),
        ("disasm_worldtileloader_cwu_11.txt", "implementation: 0x00b1f354", "ARM.exidx end: 0x00b1f6fc"),
        ("disasm_worldtileloader_cwu_12.txt", "implementation: 0x00b32fc0", "ARM.exidx end: 0x00b330d0"),
        ("disasm_worldtileloader_cwu_13.txt", "implementation: 0x00b3308c", "ARM.exidx end: 0x00b330d0"),
        ("disasm_worldtileloader_cwu_14.txt", "implementation: 0x00b32f10", "ARM.exidx end: 0x00b32fc0"),
        ("disasm_worldtileloader_cwu_15.txt", "implementation: 0x00b2dd6c", "ARM.exidx end: 0x00b2defc"),
        ("disasm_worldtileloader_cwu_16.txt", "implementation: 0x00b2ea30", "ARM.exidx end: 0x00b2ecb8"),
        ("disasm_worldtileloader_cwu_17.txt", "implementation: 0x00b11088", "ARM.exidx end: 0x00b11750"),
        ("disasm_worldtileloader_cwu_18.txt", "implementation: 0x00b32680", "ARM.exidx end: 0x00b326d8"),
        ("disasm_worldtileloader_cwu_19.txt", "implementation: 0x00b10d08", "ARM.exidx end: 0x00b11088"),
        ("disasm_worldtileloader_cwu_20.txt", "implementation: 0x00b3029c", "ARM.exidx end: 0x00b30b68"),
        ("disasm_worldtileloader_cwu_21.txt", "implementation: 0x00b2defc", "ARM.exidx end: 0x00b2df78"),
        ("disasm_worldtileloader_cwu_22.txt", "implementation: 0x00b33148", "ARM.exidx end: 0x00b331c0"),
        ("disasm_worldtileloader_cwu_23.txt", "implementation: 0x00b1aae8", "ARM.exidx end: 0x00b1e22c"),
        ("disasm_worldtileloader_cwu_24.txt", "implementation: 0x00b1f7c0", "ARM.exidx end: 0x00b2bba0"),
        ("disasm_worldtileloader_cwu_25.txt", "implementation: 0x00b31e20", "ARM.exidx end: 0x00b32280"),
        ("disasm_worldtileloader_cwu_26.txt", "implementation: 0x00b31c50", "ARM.exidx end: 0x00b31e20"),
        ("disasm_worldtileloader_cwu_27.txt", "implementation: 0x00b0cc48", "ARM.exidx end: 0x00b0ec14"),
        ("disasm_worldtileloader_cwu_28.txt", "implementation: 0x00b2e6a4", "ARM.exidx end: 0x00b2e92c"),
        ("disasm_worldtileloader_cwu_29.txt", "implementation: 0x00b2f9d0", "ARM.exidx end: 0x00b3029c"),
        ("disasm_worldtileloader_cwu_30.txt", "implementation: 0x00b317f0", "ARM.exidx end: 0x00b31b10"),
        ("disasm_worldtileloader_cwu_31.txt", "implementation: 0x00b31b10", "ARM.exidx end: 0x00b31c50"),
        ("disasm_worldtileloader_cwu_32.txt", "implementation: 0x00b2dc74", "ARM.exidx end: 0x00b2dcf0"),
        ("disasm_worldtileloader_cwu_33.txt", "implementation: 0x00b2df78", "ARM.exidx end: 0x00b2e200"),
        ("disasm_worldtileloader_cwu_34.txt", "implementation: 0x00b330d0", "ARM.exidx end: 0x00b331c0"),
        ("disasm_worldtileloader_cwu_35.txt", "implementation: 0x00b0f5cc", "ARM.exidx end: 0x00b0fac0"),
        ("disasm_worldtileloader_cwu_36.txt", "implementation: 0x00b17148", "ARM.exidx end: 0x00b1aae8"),
        ("disasm_worldtileloader_cwu_37.txt", "implementation: 0x00b1e614", "ARM.exidx end: 0x00b1e9c4"),
        ("disasm_worldtileloader_cwu_38.txt", "implementation: 0x00b0fac0", "ARM.exidx end: 0x00b10d08"),
        ("disasm_worldtileloader_cwu_39.txt", "implementation: 0x00b2edbc", "ARM.exidx end: 0x00b2f9d0"),
        ("disasm_worldtileloader_cwu_40.txt", "implementation: 0x00b33184", "ARM.exidx end: 0x00b331c0"),
        ("disasm_worldtileloader_cwu_41.txt", "implementation: 0x00b30b68", "ARM.exidx end: 0x00b30dfc"),
        ("disasm_worldtileloader_cwu_42.txt", "implementation: 0x00b313c0", "ARM.exidx end: 0x00b31444"),
        ("disasm_worldtileloader_cwu_43.txt", "implementation: 0x00b2dcf0", "ARM.exidx end: 0x00b2dd6c"),
        ("disasm_worldtileloader_cwu_44.txt", "implementation: 0x00b2e304", "ARM.exidx end: 0x00b2e5a0"),
        ("disasm_worldtileloader_cwu_45.txt", "implementation: 0x00b3310c", "ARM.exidx end: 0x00b331c0"),
        ("disasm_worldtileloader_cwu_46.txt", "implementation: 0x00b0eca4", "ARM.exidx end: 0x00b0f5a0"),
        ("disasm_worldtileloader_cwu_47.txt", "implementation: 0x00b33004", "ARM.exidx end: 0x00b330d0"),
        ("disasm_worldtileloader_cwu_48.txt", "implementation: 0x00b33048", "ARM.exidx end: 0x00b330d0"),
        ("disasm_worldtileloader_cwu_49.txt", "implementation: 0x00b1e22c", "ARM.exidx end: 0x00b1e614"),
        ("disasm_worldtileloader_cwu_50.txt", "implementation: 0x00b11750", "ARM.exidx end: 0x00b17148"),
        ("disasm_worldtileloader_cwu_51.txt", "implementation: 0x00b31444", "ARM.exidx end: 0x00b317f0"),
        ("disasm_worldtileloader_cwu_52.txt", "implementation: 0x00b2da8c", "ARM.exidx end: 0x00b2dc74"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "ITEM_DISPLAY_NAMES.md",
        [
            "0x004db268",
            "0x004db2bc",
            "0x004db840",
            "0x004ddb8c",
            "0x004ddb9c",
            "UNKNOWN",
            "425",
        ],
    )
    require(
        NATIVE / "item_display_names.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"item_type_count": 425',
            '"entries": 343',
            '"entries": 82',
            '"name": "DIAMOND STAIRS"',
        ],
    )


    require(
        NATIVE / "JOINWORLDUI.md",
        [
            "36441",
            'server',
            'world',
        ],
    )
    require(
        NATIVE / "joinworldui.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 6576',
            '"verified_words": 190',
            '0x61c66c',
            '"jw_32"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_jw_00.txt", "implementation: 0x0061b710", "ARM.exidx end: 0x0061c704"),
        ("disasm_worldtileloader_jw_01.txt", "implementation: 0x0061c704", "ARM.exidx end: 0x0061c74c"),
        ("disasm_worldtileloader_jw_02.txt", "implementation: 0x0061c74c", "ARM.exidx end: 0x0061c8c0"),
        ("disasm_worldtileloader_jw_03.txt", "implementation: 0x0061c8c0", "ARM.exidx end: 0x0061e398"),
        ("disasm_worldtileloader_jw_04.txt", "implementation: 0x0061fd00", "ARM.exidx end: 0x0062191c"),
        ("disasm_worldtileloader_jw_05.txt", "implementation: 0x0061e914", "ARM.exidx end: 0x0061f1d8"),
        ("disasm_worldtileloader_jw_06.txt", "implementation: 0x006221fc", "ARM.exidx end: 0x00622260"),
        ("disasm_worldtileloader_jw_07.txt", "implementation: 0x00622018", "ARM.exidx end: 0x006221fc"),
        ("disasm_worldtileloader_jw_08.txt", "implementation: 0x00622260", "ARM.exidx end: 0x00622330"),
        ("disasm_worldtileloader_jw_09.txt", "implementation: 0x006188d4", "ARM.exidx end: 0x00618a64"),
        ("disasm_worldtileloader_jw_10.txt", "implementation: 0x00625498", "ARM.exidx end: 0x00625520"),
        ("disasm_worldtileloader_jw_11.txt", "implementation: 0x0061f580", "ARM.exidx end: 0x0061f940"),
        ("disasm_worldtileloader_jw_12.txt", "implementation: 0x006254dc", "ARM.exidx end: 0x00625520"),
        ("disasm_worldtileloader_jw_13.txt", "implementation: 0x0061f940", "ARM.exidx end: 0x0061fd00"),
        ("disasm_worldtileloader_jw_14.txt", "implementation: 0x00603b38", "ARM.exidx end: 0x00604210"),
        ("disasm_worldtileloader_jw_15.txt", "implementation: 0x00603b24", "ARM.exidx end: 0x00603b38"),
        ("disasm_worldtileloader_jw_16.txt", "implementation: 0x00624918", "ARM.exidx end: 0x00625410"),
        ("disasm_worldtileloader_jw_17.txt", "implementation: 0x00618a64", "ARM.exidx end: 0x00618bf4"),
        ("disasm_worldtileloader_jw_18.txt", "implementation: 0x00618bf4", "ARM.exidx end: 0x006194e4"),
        ("disasm_worldtileloader_jw_19.txt", "implementation: 0x006194e4", "ARM.exidx end: 0x00619bc8"),
        ("disasm_worldtileloader_jw_20.txt", "implementation: 0x00603134", "ARM.exidx end: 0x006034e4"),
        ("disasm_worldtileloader_jw_21.txt", "implementation: 0x00602fac", "ARM.exidx end: 0x00603134"),
        ("disasm_worldtileloader_jw_22.txt", "implementation: 0x0062279c", "ARM.exidx end: 0x00622bfc"),
        ("disasm_worldtileloader_jw_23.txt", "implementation: 0x006225cc", "ARM.exidx end: 0x0062279c"),
        ("disasm_worldtileloader_jw_24.txt", "implementation: 0x00610e58", "ARM.exidx end: 0x00611bec"),
        ("disasm_worldtileloader_jw_25.txt", "implementation: 0x00611bec", "ARM.exidx end: 0x0061499c"),
        ("disasm_worldtileloader_jw_26.txt", "implementation: 0x00601af0", "ARM.exidx end: 0x00602ed0"),
        ("disasm_worldtileloader_jw_27.txt", "implementation: 0x0061499c", "ARM.exidx end: 0x00615360"),
        ("disasm_worldtileloader_jw_28.txt", "implementation: 0x00623e20", "ARM.exidx end: 0x00625410"),
        ("disasm_worldtileloader_jw_29.txt", "implementation: 0x0061f25c", "ARM.exidx end: 0x0061f580"),
        ("disasm_worldtileloader_jw_30.txt", "implementation: 0x00622460", "ARM.exidx end: 0x006225a0"),
        ("disasm_worldtileloader_jw_31.txt", "implementation: 0x00618744", "ARM.exidx end: 0x006188d4"),
        ("disasm_worldtileloader_jw_32.txt", "implementation: 0x0060a798", "ARM.exidx end: 0x00610e58"),
        ("disasm_worldtileloader_jw_33.txt", "implementation: 0x0062191c", "ARM.exidx end: 0x00621ccc"),
        ("disasm_worldtileloader_jw_34.txt", "implementation: 0x00622430", "ARM.exidx end: 0x00622460"),
        ("disasm_worldtileloader_jw_35.txt", "implementation: 0x00622330", "ARM.exidx end: 0x00622430"),
        ("disasm_worldtileloader_jw_36.txt", "implementation: 0x00615360", "ARM.exidx end: 0x00618744"),
        ("disasm_worldtileloader_jw_37.txt", "implementation: 0x00621da4", "ARM.exidx end: 0x00622018"),
        ("disasm_worldtileloader_jw_38.txt", "implementation: 0x00621ccc", "ARM.exidx end: 0x00621da4"),
        ("disasm_worldtileloader_jw_39.txt", "implementation: 0x00619bc8", "ARM.exidx end: 0x0061b710"),
        ("disasm_worldtileloader_jw_40.txt", "implementation: 0x00622444", "ARM.exidx end: 0x00622460"),
        ("disasm_worldtileloader_jw_41.txt", "implementation: 0x006034e4", "ARM.exidx end: 0x00603b24"),
        ("disasm_worldtileloader_jw_42.txt", "implementation: 0x0061e690", "ARM.exidx end: 0x0061e914"),
        ("disasm_worldtileloader_jw_43.txt", "implementation: 0x00622bfc", "ARM.exidx end: 0x00623e20"),
        ("disasm_worldtileloader_jw_44.txt", "implementation: 0x00625520", "ARM.exidx end: 0x0062555c"),
        ("disasm_worldtileloader_jw_45.txt", "implementation: 0x0061e398", "ARM.exidx end: 0x0061e690"),
        ("disasm_worldtileloader_jw_46.txt", "implementation: 0x0061f1d8", "ARM.exidx end: 0x0061f25c"),
        ("disasm_worldtileloader_jw_47.txt", "implementation: 0x00625410", "ARM.exidx end: 0x00625520"),
        ("disasm_worldtileloader_jw_48.txt", "implementation: 0x00625454", "ARM.exidx end: 0x00625520"),
        ("disasm_worldtileloader_jw_49.txt", "implementation: 0x00604210", "ARM.exidx end: 0x0060a798"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])


    require(
        NATIVE / "MJBUTTON.md",
        [
            "6259",
            'render',
            'E138',
        ],
    )
    require(
        NATIVE / "mjbutton.json",
        [
            "733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7",
            '"verified_words": 2581',
            '"verified_words": 21',
            '0xd17034',
            '"mj_17"',
        ],
    )
    for _sl_file, _sl_imp, _sl_end in (
        ("disasm_worldtileloader_mj_00.txt", "implementation: 0x00d17034", "ARM.exidx end: 0x00d1704c"),
        ("disasm_worldtileloader_mj_01.txt", "implementation: 0x00d16a7c", "ARM.exidx end: 0x00d16ab8"),
        ("disasm_worldtileloader_mj_02.txt", "implementation: 0x00d169f4", "ARM.exidx end: 0x00d16a30"),
        ("disasm_worldtileloader_mj_03.txt", "implementation: 0x00d1696c", "ARM.exidx end: 0x00d169a8"),
        ("disasm_worldtileloader_mj_04.txt", "implementation: 0x00d168e4", "ARM.exidx end: 0x00d16920"),
        ("disasm_worldtileloader_mj_05.txt", "implementation: 0x00d1611c", "ARM.exidx end: 0x00d16498"),
        ("disasm_worldtileloader_mj_06.txt", "implementation: 0x00d10640", "ARM.exidx end: 0x00d109bc"),
        ("disasm_worldtileloader_mj_07.txt", "implementation: 0x00d1232c", "ARM.exidx end: 0x00d1257c"),
        ("disasm_worldtileloader_mj_08.txt", "implementation: 0x00d16e54", "ARM.exidx end: 0x00d16e90"),
        ("disasm_worldtileloader_mj_09.txt", "implementation: 0x00d16ed4", "ARM.exidx end: 0x00d16f34"),
        ("disasm_worldtileloader_mj_10.txt", "implementation: 0x00d16c94", "ARM.exidx end: 0x00d16cf4"),
        ("disasm_worldtileloader_mj_11.txt", "implementation: 0x00d16d74", "ARM.exidx end: 0x00d16dd4"),
        ("disasm_worldtileloader_mj_12.txt", "implementation: 0x00d16b04", "ARM.exidx end: 0x00d16b40"),
        ("disasm_worldtileloader_mj_13.txt", "implementation: 0x00d16b8c", "ARM.exidx end: 0x00d16bc8"),
        ("disasm_worldtileloader_mj_14.txt", "implementation: 0x00d16c14", "ARM.exidx end: 0x00d16c50"),
        ("disasm_worldtileloader_mj_15.txt", "implementation: 0x00d11768", "ARM.exidx end: 0x00d11d7c"),
        ("disasm_worldtileloader_mj_16.txt", "implementation: 0x00d11d7c", "ARM.exidx end: 0x00d1232c"),
        ("disasm_worldtileloader_mj_17.txt", "implementation: 0x00d12700", "ARM.exidx end: 0x00d14f54"),
        ("disasm_worldtileloader_mj_18.txt", "implementation: 0x00d16ab8", "ARM.exidx end: 0x00d16b04"),
        ("disasm_worldtileloader_mj_19.txt", "implementation: 0x00d16a30", "ARM.exidx end: 0x00d16a7c"),
        ("disasm_worldtileloader_mj_20.txt", "implementation: 0x00d169a8", "ARM.exidx end: 0x00d169f4"),
        ("disasm_worldtileloader_mj_21.txt", "implementation: 0x00d16920", "ARM.exidx end: 0x00d1696c"),
        ("disasm_worldtileloader_mj_22.txt", "implementation: 0x00d1138c", "ARM.exidx end: 0x00d11768"),
        ("disasm_worldtileloader_mj_23.txt", "implementation: 0x00d16e90", "ARM.exidx end: 0x00d16ed4"),
        ("disasm_worldtileloader_mj_24.txt", "implementation: 0x00d10fc4", "ARM.exidx end: 0x00d1138c"),
        ("disasm_worldtileloader_mj_25.txt", "implementation: 0x00d15ae4", "ARM.exidx end: 0x00d15f88"),
        ("disasm_worldtileloader_mj_26.txt", "implementation: 0x00d16f34", "ARM.exidx end: 0x00d16fb4"),
        ("disasm_worldtileloader_mj_27.txt", "implementation: 0x00d16cf4", "ARM.exidx end: 0x00d16d74"),
        ("disasm_worldtileloader_mj_28.txt", "implementation: 0x00d16dd4", "ARM.exidx end: 0x00d16e54"),
        ("disasm_worldtileloader_mj_29.txt", "implementation: 0x00d16b40", "ARM.exidx end: 0x00d16b8c"),
        ("disasm_worldtileloader_mj_30.txt", "implementation: 0x00d15784", "ARM.exidx end: 0x00d15934"),
        ("disasm_worldtileloader_mj_31.txt", "implementation: 0x00d16bc8", "ARM.exidx end: 0x00d16c14"),
        ("disasm_worldtileloader_mj_32.txt", "implementation: 0x00d15934", "ARM.exidx end: 0x00d15ae4"),
        ("disasm_worldtileloader_mj_33.txt", "implementation: 0x00d12674", "ARM.exidx end: 0x00d12700"),
        ("disasm_worldtileloader_mj_34.txt", "implementation: 0x00d15740", "ARM.exidx end: 0x00d15784"),
        ("disasm_worldtileloader_mj_35.txt", "implementation: 0x00d16c50", "ARM.exidx end: 0x00d16c94"),
        ("disasm_worldtileloader_mj_36.txt", "implementation: 0x00d156fc", "ARM.exidx end: 0x00d15784"),
        ("disasm_worldtileloader_mj_37.txt", "implementation: 0x00d16ff0", "ARM.exidx end: 0x00d17034"),
        ("disasm_worldtileloader_mj_38.txt", "implementation: 0x00d1257c", "ARM.exidx end: 0x00d12674"),
        ("disasm_worldtileloader_mj_39.txt", "implementation: 0x00d10c30", "ARM.exidx end: 0x00d10f88"),
        ("disasm_worldtileloader_mj_40.txt", "implementation: 0x00d10a08", "ARM.exidx end: 0x00d10be4"),
        ("disasm_worldtileloader_mj_41.txt", "implementation: 0x00d16748", "ARM.exidx end: 0x00d16890"),
        ("disasm_worldtileloader_mj_42.txt", "implementation: 0x00d16498", "ARM.exidx end: 0x00d1670c"),
        ("disasm_worldtileloader_mj_43.txt", "implementation: 0x00d15f88", "ARM.exidx end: 0x00d15fdc"),
        ("disasm_worldtileloader_mj_44.txt", "implementation: 0x00d16890", "ARM.exidx end: 0x00d168e4"),
        ("disasm_worldtileloader_mj_45.txt", "implementation: 0x00d16fb4", "ARM.exidx end: 0x00d16ff0"),
        ("disasm_worldtileloader_mj_46.txt", "implementation: 0x00d10f88", "ARM.exidx end: 0x00d10fc4"),
        ("disasm_worldtileloader_mj_47.txt", "implementation: 0x00d1670c", "ARM.exidx end: 0x00d16748"),
        ("disasm_worldtileloader_mj_48.txt", "implementation: 0x00d15fdc", "ARM.exidx end: 0x00d1607c"),
        ("disasm_worldtileloader_mj_49.txt", "implementation: 0x00d1607c", "ARM.exidx end: 0x00d1611c"),
    ):
        require(NATIVE / _sl_file, [_sl_imp, _sl_end])

    print("reverse-evidence-contract: PASS")


if __name__ == "__main__":
    main()
