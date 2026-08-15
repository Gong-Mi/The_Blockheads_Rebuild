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
    print("reverse-evidence-contract: PASS")


if __name__ == "__main__":
    main()
