#!/usr/bin/env python3
"""Validate checked-in reverse-v3 evidence without requiring the copyrighted APK."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "reconstruction" / "reverse-v3" / "native"


def require(path: Path, needles: list[str]) -> None:
    if not path.is_file():
        raise SystemExit(f"missing evidence file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(
            f"{path.relative_to(ROOT)} is missing required evidence: {missing}"
        )


def main() -> None:
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
        ],
    )
    require(
        NATIVE / "SELECTOR_SENDERS.md",
        [
            "reference sites",
            "0x105faf4",
            "settled by the prologue walk-back",
            "noPath.wav",
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
        NATIVE / "WORLDTIME_GETTER_EMULATION.md",
        [
            "executed under Unicorn",
            "UC_ERR_INSN_INVALID",
            "0xFF` | **-1**",
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
