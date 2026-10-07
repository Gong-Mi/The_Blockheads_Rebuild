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
    print("reverse-evidence-contract: PASS")


if __name__ == "__main__":
    main()
