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
            "item_type\timage_dataA0\tcol_dataA0\trow_dataA0",
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
    if len(content_render_lines) != 62:
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
