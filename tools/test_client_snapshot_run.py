#!/usr/bin/env python3
"""Standalone reverse-pipeline run test: assemble a snapshot, run the loader.

    test_client_snapshot_run.py <client_app_skeleton_cli>

Builds a fixture snapshot that mirrors the shapes of the real
reverse-probe-001 save (one dynamic record for each of the ten recovered
type ids: 1 AppleTree, 4 PineTree, 7 OrangeTree, 11 SunflowerPlant,
12 CornPlant, 13 Dodo, 28 Donkey, 45 Workbench, 59 TulipPlant,
62 TomatoPlant; plus one physical block and the main/worldv2 domain
carrying worldTime), runs the recovered loader over it through the CLI,
and asserts the full report.

This test depends on NOTHING but the CLI binary and python3: no APK, no
Gradle, no device, no ELF/Unicorn. It is the "does the reverse pipeline
actually run" gate, fit for plain `ctest`.

Failure modes are loud: a mismatch prints the offending key and the CLI's
full output.
"""
import hashlib
import json
import re
import subprocess
import struct
import sys
import tempfile
from pathlib import Path

BLOCK_PAYLOAD_SIZE = 65541

# ---- fixture records ---------------------------------------------------------
# Keys and values are copied from the real reverse-probe-001 records so the
# fixture exercises the same shapes; treeFruit stays EMPTY because the Tree
# stage-1 executed differential covers the empty-array domain only.
TYPED_RECORDS = {
    1: ("AppleTree", 39, 114, 526, dict(
        floatPos=[114.5, 526.0], age=1422.129, availableFood=279.3271,
        dead=False, growthCounter=0.4282283, growthRate=0.2343903,
        growthRateGene=235, height=1, maxAge=26853.88, maxHeight=7,
        maxHeightGene=211, maxHeightReached=1, removeCheckCount=0.0,
        saveTime=900.0, timeDied=0.0, treeFruit=[], treeSeasonOffset=0,
    )),
    4: ("PineTree", 116, 159, 537, dict(
        floatPos=[159.5, 537.0], age=4185.872, availableFood=0.7251471,
        dead=False, growthCounter=0.3934377, growthRate=0.9490196,
        growthRateGene=191, height=10, maxAge=20143.46, maxHeight=25,
        maxHeightGene=228, maxHeightReached=10, removeCheckCount=0.0,
        saveTime=900.0, timeDied=0.0, treeFruit=[], treeSeasonOffset=-1,
    )),
    7: ("OrangeTree", 115, 157, 537, dict(
        floatPos=[157.5, 537.0], age=1968.187, dead=False,
        growthCounter=0.4034734, growthRate=0.3541177, growthRateGene=207,
        height=2, maxAge=23757.2, maxHeight=10, maxHeightGene=215,
        maxHeightReached=2, removeCheckCount=0.0, saveTime=900.0,
        timeDied=0.0, treeFruit=[], treeSeasonOffset=160,
    )),
    11: ("SunflowerPlant", 80, 181, 531, dict(
        floatPos=[181.5, 531.0], age=10254.91, availableFood=951.9518,
        flowering=False, frozen=False, gatherProgress=0,
        growthRate=0.8588235, growthRateGene=168,
        hasFloweredThisSeason=False, maxAge=14256.0, maxAgeGene=153,
        saveTime=900.0, seasonOffset=9,
    )),
    12: ("CornPlant", 78, 173, 534, dict(
        floatPos=[173.5, 534.0], age=3438.549, availableFood=711.1219,
        flowering=False, frozen=False, gatherProgress=0,
        growthRate=0.8352941, growthRateGene=162,
        hasFloweredThisSeason=False, maxAge=15221.65, maxAgeGene=172,
        saveTime=900.0, seasonOffset=11,
    )),
    13: ("Dodo", 38, 110, 525, dict(
        floatPos=[110.5, 525.0], age=3432.53, breed=0, damage=0,
        fullness=1623.233, hasBeenFedByBlockheadOrChest=False,
        hasBred=False, layCooldownTimer=82.93232, layTimer=0.0,
        mateBreed=0, mateCooldownTimer=0.0, saveTime=900.0,
        tameCooldownTimer=0.0,
    )),
    28: ("Donkey", 114, 153, 535, dict(
        floatPos=[153.5, 535.0], age=509.2054, breed=0, damage=0,
        fullness=1337.967, hasBeenFedByBlockheadOrChest=False,
        hasBred=False, layCooldownTimer=625.7209, layTimer=0.0,
        mateBreed=0, mateCooldownTimer=0.0, saveTime=900.0,
        tameCooldownTimer=0.0,
    )),
    45: ("Workbench", 154, 143, 532, dict(
        floatPos=[143.5, 532.0], availableElectricity=0,
        craftProgressCount=0.0, fireSpreadTimer=0.0, flipped=False,
        fuelFraction=0.0, hasFuel=False, hurryCost=0, hurrySeconds=0.0,
        hurryTimer=0.0, hurrying=False, interactionObjectType=1,
        isInUse=False, lastWorldTime=900.0, level=0,
        lightDict={"contributionGridOrigin.x": 131},
        paintColor=0, saveTime=900.0, selectedIndex=0, workbenchType=1,
        xScroll=0.0,
    )),
    59: ("TulipPlant", 74, 160, 537, dict(
        floatPos=[160.5, 537.0], age=1366.412, availableFood=119.3827,
        colorGenes=13364, flowering=False, frozen=False, gatherProgress=0,
        growthRate=0.2039216, growthRateGene=1,
        hasFloweredThisSeason=False, mateColorGenes=13364,
        maxAge=99999.0, maxAgeGene=255, mixGenes=0, saveTime=900.0,
        seasonOffset=0,
    )),
    62: ("TomatoPlant", 76, 162, 537, dict(
        floatPos=[162.5, 537.0], age=7642.733, availableFood=879.7785,
        flowering=False, frozen=False, gatherProgress=0,
        growthRate=0.8392157, growthRateGene=163,
        hasFloweredThisSeason=False, maxAge=15729.88, maxAgeGene=182,
        saveTime=900.0, seasonOffset=-4,
    )),
    # --- family expansion (2026-09-28) ---------------------------------------
    # ClownFish/Shark/Scorpion share the forwarder5 zero-own-state body with
    # Dodo, so their records carry the NPC key set exactly.
    35: ("ClownFish", 121, 90, 520, dict(
        floatPos=[90.5, 520.0], age=800.0, breed=0, damage=0,
        fullness=400.0, hasBeenFedByBlockheadOrChest=False, hasBred=False,
        layCooldownTimer=10.0, layTimer=0.0, mateBreed=0,
        mateCooldownTimer=0.0, saveTime=900.0, tameCooldownTimer=0.0,
    )),
    36: ("Shark", 122, 91, 520, dict(
        floatPos=[91.5, 520.0], age=900.0, breed=0, damage=0,
        fullness=500.0, hasBeenFedByBlockheadOrChest=False, hasBred=False,
        layCooldownTimer=11.0, layTimer=0.0, mateBreed=0,
        mateCooldownTimer=0.0, saveTime=900.0, tameCooldownTimer=0.0,
    )),
    51: ("Scorpion", 123, 92, 520, dict(
        floatPos=[92.5, 520.0], age=1000.0, breed=0, damage=0,
        fullness=600.0, hasBeenFedByBlockheadOrChest=False, hasBred=False,
        layCooldownTimer=12.0, layTimer=0.0, mateBreed=0,
        mateCooldownTimer=0.0, saveTime=900.0, tameCooldownTimer=0.0,
    )),
    # Yak = the NPC chain + ownkey5 own keys milk/hair (executed).
    63: ("Yak", 124, 93, 520, dict(
        floatPos=[93.5, 520.0], age=1100.0, breed=0, damage=0,
        fullness=700.0, hasBeenFedByBlockheadOrChest=False, hasBred=False,
        layCooldownTimer=13.0, layTimer=0.0, mateBreed=0,
        mateCooldownTimer=0.0, saveTime=900.0, tameCooldownTimer=0.0,
        milk=2.5, hair=12.0,
    )),
    # CoconutTree: the Tree chain is its whole record (b3b: own keys empty).
    6: ("CoconutTree", 125, 94, 521, dict(
        floatPos=[94.5, 521.0], age=2000.0, dead=False,
        growthCounter=0.1, growthRate=0.2, growthRateGene=200, height=3,
        maxAge=20000.0, maxHeight=12, maxHeightGene=210,
        maxHeightReached=3, removeCheckCount=0.0, saveTime=900.0,
        timeDied=0.0, treeFruit=[], treeSeasonOffset=0,
    )),
    # CactusTree: Tree + b3b own keys (super then own; availableFood@148).
    5: ("CactusTree", 126, 95, 521, dict(
        floatPos=[95.5, 521.0], age=2100.0, dead=False,
        growthCounter=0.11, growthRate=0.21, growthRateGene=201, height=4,
        maxAge=21000.0, maxHeight=13, maxHeightGene=211,
        maxHeightReached=4, removeCheckCount=0.0, saveTime=900.0,
        timeDied=0.0, treeFruit=[], treeSeasonOffset=1,
        splitHeightA=3, splitHeightB=4, splitDirection=True,
        availableFood=12.5,
    )),
    # The five pure trees: Tree chain only (TREEFAMILY9_PURE_TREES.md).
    2: ("MapleTree", 150, 70, 510, dict(
        floatPos=[70.5, 510.0], age=500.0, dead=False, growthCounter=0.2,
        growthRate=0.3, growthRateGene=180, height=6, maxAge=18000.0,
        maxHeight=16, maxHeightGene=190, maxHeightReached=6,
        removeCheckCount=0.0, saveTime=900.0, timeDied=0.0, treeFruit=[],
        treeSeasonOffset=3,
    )),
    3: ("MangoTree", 151, 71, 510, dict(
        floatPos=[71.5, 510.0], age=600.0, dead=False, growthCounter=0.21,
        height=7, treeFruit=[], treeSeasonOffset=4,
    )),
    8: ("CherryTree", 152, 72, 510, dict(
        floatPos=[72.5, 510.0], age=700.0, dead=False, growthCounter=0.22,
        height=8, treeFruit=[], treeSeasonOffset=5,
    )),
    9: ("CoffeeTree", 153, 73, 510, dict(
        floatPos=[73.5, 510.0], age=800.0, dead=False, growthCounter=0.23,
        height=9, treeFruit=[], treeSeasonOffset=6,
    )),
    37: ("LimeTree", 155, 74, 510, dict(
        floatPos=[74.5, 510.0], age=900.0, dead=False, growthCounter=0.24,
        height=10, treeFruit=[], treeSeasonOffset=7,
    )),
    # Mid-tier static family: the nine table-driven classes.
    31: ("Window", 260, 99, 524, dict(itemType=5, ownerID="c")),
    40: ("Rail", 261, 100, 524, dict(configuration=3, ownedByStation=True, itemType=8)),
    32: ("Boat", 262, 101, 524, dict(currentBlockheadIndex=4, ownerID="c")),
    19: ("Ladder", 263, 102, 524, dict(itemType=6, ownerID="c", paintColor=70000)),
    30: ("Egg", 264, 103, 524, dict(breed=70000, genesDict={"g": 1}, hatchTimer=1.5)),
    53: ("Column", 265, 104, 524, dict(configuration=2, itemType=7, ownerID="c", paintColor=3)),
    54: ("Stairs", 266, 105, 524, dict(configuration=2, itemType=7, ownerID="c", paintColor=3)),
    20: ("Door", 267, 106, 524, dict(blocked=True, ironPlaceClientID="x", itemType=4, ownerID="c")),
    38: ("Wire", 268, 107, 524, dict(configuration=1, itemType=2, solidConfiguration=3, ownerID="c")),
    # forwarder5b zeros: base-only record domains.
    22: ("SurfaceBlock", 280, 112, 527, dict(itemType=1)),
    29: ("SnowSurfaceBlock", 281, 113, 527, dict()),
    # Painting / OwnershipSign: listing-decoded own keys.
    52: ("Painting", 272, 110, 526, dict(
        itemType=9, ownerID="c", ownerName="bob",
        hasVerifiedImageData=True, outputImageData="blob",
    )),
    60: ("OwnershipSign", 273, 111, 526, dict(
        text="mine", connectionType=1, offsetType=2, landOwnerID="c",
        landOwnerName="bob", w=5, h=6,
    )),
    # Elevator pair (mid-tier tables).
    55: ("ElevatorMotor", 270, 108, 525, dict(
        itemType=3, ownerID="c", availableElectricity=70000, minY=1, maxY=2,
    )),
    56: ("ElevatorShaft", 271, 109, 525, dict(
        itemType=3, ownerID="c", **{"lastKnownMotorPos.x": 10,
                                     "lastKnownMotorPos.y": 20},
        paintColor=70000,
    )),
    # FireObject / Torch: base + listing-decoded own keys.
    16: ("FireObject", 250, 97, 523, dict(
        floatPos=[97.5, 523.0], burnTimer=0.75, spreadTimer_0=1.0,
        spreadTimer_1=2.0, spreadTimer_2=3.0, spreadTimer_3=4.0,
        lightDict={"radius": 2},
    )),
    17: ("Torch", 251, 98, 523, dict(
        floatPos=[98.5, 523.0], itemType=9, connectionType=1, dataA=70000,
        dataB=2, ownerID="c-7", lightDict={"radius": 4},
    )),
    # GlowBlock: base + listing-decoded own keys.
    18: ("GlowBlock", 240, 96, 522, dict(
        floatPos=[96.5, 522.0], tileType=7, lightDict={"radius": 3},
    )),
    # Bed / Sign: executed InteractionObject super + listing-decoded own keys.
    23: ("Bed", 230, 94, 521, dict(
        floatPos=[94.5, 521.0], isInUse=True, beddingColor=70000, itemType=2,
    )),
    47: ("Sign", 231, 95, 521, dict(
        floatPos=[95.5, 521.0], text="hello", connectionType=3,
        offsetType=1,
    )),
    # InteractionObject family: the executed 352w mid-chain init.
    15: ("InteractionObject", 220, 92, 520, dict(
        floatPos=[92.5, 520.0], isInUse=True, flipped=False,
        paintColor=70000, currentBlockheadIndex=5, ownerID="c-1",
    )),
    64: ("Mirror", 221, 93, 520, dict(
        floatPos=[93.5, 520.0], isInUse=False, flipped=True, paintColor=2,
    )),
    # TradePortal: static own keys + the executed b4i clamp hook.
    50: ("TradePortal", 200, 89, 519, dict(
        floatPos=[89.5, 519.0], level=1,
        localPriceOffsets={"wood": 0.25, "stone": 3.5},
    )),
    # TradingPost: static own keys + the executed sellSlot hook (counts only).
    48: ("TradingPost", 201, 90, 519, dict(
        floatPos=[90.5, 519.0], coinCount=12, priceTier=2,
        sellerClientID="client-9", sellerClientName="seller",
        sellSlot=[{"itemType": 1}, {"itemType": 11}],
    )),
    # FreeBlock: b4p executed save surface (12 keys, subItems counts).
    14: ("FreeBlock", 190, 87, 518, dict(
        floatPos=[87.5, 518.0], bounceTimer=0.1, fallSpeed=0.2,
        creationTime=100.0, **{"floatPos[VX]": 87.5, "floatPos[VY]": 518.0},
        hovers=True, itemType=3, dataA=1, dataB=2,
        subItems=[[{"itemType": 1}], []],
        dynamicObjectSaveDict={"seed": 1}, priorityBlockheadUinqueID=0,
    )),
    # Chest: b4m executed surface (chestType / slots counts / shelf_0..3).
    46: ("Chest", 180, 86, 517, dict(
        floatPos=[86.5, 517.0], chestType=2,
        saveItemSlots=[[{"itemType": 1, "uid": 1}], [], [], []],
        shelfRenderItems_0=1, shelfItemDataBs_0=2,
    )),
    # TrainStation: ownkey5 own key {text} + InteractionObject static boundary.
    49: ("TrainStation", 170, 85, 516, dict(
        floatPos=[85.5, 516.0], text="Depot A",
    )),
    # Crop plants: Plant chain only (constant-accessor classes).
    10: ("FlaxPlant", 160, 80, 515, dict(
        floatPos=[80.5, 515.0], seasonOffset=1, age=100.0, maxAgeGene=140,
        growthRateGene=150, saveTime=900.0,
    )),
    27: ("CarrotPlant", 161, 81, 515, dict(
        floatPos=[81.5, 515.0], seasonOffset=2, age=200.0, maxAgeGene=141,
        growthRateGene=151, saveTime=900.0,
    )),
    33: ("ChilliPlant", 162, 82, 515, dict(
        floatPos=[82.5, 515.0], seasonOffset=3, age=300.0, maxAgeGene=142,
        growthRateGene=152, saveTime=900.0,
    )),
    61: ("WheatPlant", 163, 83, 515, dict(
        floatPos=[83.5, 515.0], seasonOffset=4, age=400.0, maxAgeGene=143,
        growthRateGene=153, saveTime=900.0,
    )),
    # KelpPlant / VinePlant: the executed b4o/b4n twin chains.
    34: ("KelpPlant", 140, 60, 500, dict(
        floatPos=[60.5, 500.0], seasonOffset=5, age=300.0,
        maxAgeGene=150, growthRateGene=160, saveTime=900.0,
        numberOfOccupiedTilesAbove=6, growthTimer=1.25,
        availableFood=55.5,
    )),
    58: ("VinePlant", 141, 61, 500, dict(
        floatPos=[61.5, 500.0], seasonOffset=6, age=400.0,
        maxAgeGene=151, growthRateGene=161, saveTime=900.0,
        numberOfOccupiedTilesBelow=9, growthTimer=2.5,
        availableFood=66.0,
    )),
    # GatherBlock: base + ownkey5 executed own keys (the full key set).
    26: ("GatherBlock", 130, 98, 521, dict(
        floatPos=[98.5, 521.0], timer=0.5, lastKnownGatherValue=42,
    )),
    # GemTree: Tree + b3b own keys (own then super; gemTreeType/fruitYear).
    57: ("GemTree", 127, 96, 521, dict(
        floatPos=[96.5, 521.0], age=2200.0, dead=False,
        growthCounter=0.12, growthRate=0.22, growthRateGene=202, height=5,
        maxAge=22000.0, maxHeight=14, maxHeightGene=212,
        maxHeightReached=5, removeCheckCount=0.0, saveTime=900.0,
        timeDied=0.0, treeFruit=[], treeSeasonOffset=2,
        gemTreeType=2, fruitYear=3,
    )),
}

WORLD_TIME = 900.0


def plist_value(value) -> str:
    if isinstance(value, bool):
        return "<true/>" if value else "<false/>"
    if isinstance(value, int):
        return f"<integer>{value}</integer>"
    if isinstance(value, float):
        return f"<real>{value!r}</real>"
    if isinstance(value, str):
        return f"<string>{value}</string>"
    if isinstance(value, list):
        return "<array>" + "".join(plist_value(v) for v in value) + "</array>"
    if isinstance(value, dict):
        return ("<dict>" + "".join(
            f"<key>{k}</key>{plist_value(v)}" for k, v in value.items()
        ) + "</dict>")
    raise TypeError(f"unsupported plist value: {type(value)!r}")


def plist_record(event: dict) -> str:
    return ('<?xml version="1.0"?>\n<plist version="1.0"><dict>'
            '<key>dynamicObjects</key><array>' + plist_value(event) +
            '</array></dict></plist>\n')


def write(path: Path, data) -> None:
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def build_snapshot(root: Path) -> None:
    (root / "blocks").mkdir(parents=True)
    (root / "dynamic").mkdir()
    (root / "main").mkdir()

    # one physical block, key "0_0"
    block = bytearray(BLOCK_PAYLOAD_SIZE)
    block[0] = 3
    block = bytes(block)
    write(root / "blocks/0_0.raw", block)
    write(root / "blocks/index.tsv",
          "key_hex\tx\ty\tfile\traw_sha256\tbytes\n"
          "305f30\t0\t0\tblocks/0_0.raw\t"
          f"{hashlib.sha256(block).hexdigest()}\t{len(block)}\n")

    # one dynamic record per recovered type
    rows = ["key_hex\tx\ty\tfile\traw_sha256\tbytes"]
    for order, (type_id, (name, uid, x, y, fields)) in enumerate(
            sorted(TYPED_RECORDS.items())):
        event = {"uniqueID": uid, "pos_x": x, "pos_y": y}
        event.update(fields)
        payload = plist_record(event)
        rel = f"dynamic/rec{order:02d}_{name}.plist"
        write(root / rel, payload)
        key_hex = f"{x}_{y}/{type_id}".encode().hex()
        rows.append(f"{key_hex}\t{x}\t{y}\t{rel}\t"
                    f"{hashlib.sha256(payload.encode()).hexdigest()}\t"
                    f"{len(payload.encode())}")
    write(root / "dynamic/index.tsv", "\n".join(rows) + "\n")

    # main/worldv2: the saveTime gate's other input
    worldv2 = ('<?xml version="1.0"?>\n<plist version="1.0"><dict>'
               f'<key>worldTime</key><real>{WORLD_TIME!r}</real>'
               '<key>saveVersion</key><integer>1100</integer>'
               '</dict></plist>\n')
    write(root / "main/worldv2.plist", worldv2)
    write(root / "main/index.tsv",
          "key_hex\tfile\traw_sha256\tbytes\n"
          "776f726c647632\tmain/worldv2.plist\t"
          f"{hashlib.sha256(worldv2.encode()).hexdigest()}\t"
          f"{len(worldv2.encode())}\n")


# Evidence-level honesty pins: the reason string of each type must name the
# evidence grade of its chain (executed batch or static table). This keeps
# the "state what is executed vs static" discipline load-bearing in the run.
EXPECT_REASON = {
    63: "ownkey5",       # Yak own keys, executed
    35: "b4f",           # forwarder5 zero-own-state + b4f NPC chain
    36: "b4f",
    51: "b4f",
    5: "b3b",            # CactusTree own-key read-back table (static)
    6: "b3b",            # CoconutTree (own keys empty)
    57: "b3b",           # GemTree own keys
    1: "b4d",            # tree stage-1 executed differential
    59: "Plant loadSaveDictValues",
    13: "b3g",           # NPC init executed
    45: "b4q",           # workbench executed differential
    26: "ownkey5",       # GatherBlock own keys, executed
    34: "b4n",           # KelpPlant twin loader executed
    58: "b4o",           # VinePlant twin loader executed
    2: "b4d",            # pure trees: Tree stage-1 executed
    3: "b4d",
    8: "b4d",
    9: "b4d",
    37: "b4d",
    10: "Plant loadSaveDictValues",   # crops: inherited Plant chain
    27: "Plant loadSaveDictValues",
    33: "Plant loadSaveDictValues",
    61: "Plant loadSaveDictValues",
    49: "ownkey5",        # TrainStation own key {text} executed
    46: "b4m",            # Chest executed read-back
    14: "b4p",            # FreeBlock executed read-back
    50: "b4i",            # TradePortal clamp hook executed
    48: "sellSlot",       # TradingPost slot hook executed
    15: "executed 352w",  # InteractionObject executed differential
    64: "zero-own-key",   # Mirror zero-own-key forwarder over the same chain
    23: "beddingColor@104-strh",  # Bed own keys (listing decode)
    47: "connectionType@112",      # Sign own keys (listing decode)
    18: "tileType@60",             # GlowBlock own key (listing decode)
    16: "burnTimer@56",            # FireObject own keys (listing decode)
    17: "dataA@80-strh",           # Torch own keys (listing decode)
    31: "key table",               # mid-tier: Window
    40: "key table",               # mid-tier: Rail
    32: "key table",               # mid-tier: Boat
    19: "key table",               # mid-tier: Ladder
    30: "key table",               # mid-tier: Egg
    53: "key table",               # mid-tier: Column
    54: "key table",               # mid-tier: Stairs
    20: "key table",               # mid-tier: Door
    38: "key table",               # mid-tier: Wire
    55: "key table",               # mid-tier: ElevatorMotor
    56: "key table",               # mid-tier: ElevatorShaft
    52: "outputImageData@60",      # Painting own keys (listing decode)
    60: "landOwnerID@124",         # OwnershipSign own keys (listing decode)
    22: "zero-own-key",            # forwarder5b: SurfaceBlock
    29: "zero-own-key",            # forwarder5b: SnowSurfaceBlock
}


def registered_type_ids() -> set:
    """Every registerFactory id in the app registry source — the fixture
    must cover them, so a new registration cannot land without run cover."""
    app = (Path(__file__).resolve().parents[1] /
           "app/src/main/cpp/original_client_app.cpp").read_text()
    return {int(m) for m in re.findall(r"registerFactory\(\s*(\d+),", app)}


def field(text: str, label: str) -> int:
    m = re.search(rf"{re.escape(label)}:?\s+(\d+)", text)
    if m is None:
        raise AssertionError(f"CLI output misses '{label}':\n{text}")
    return int(m.group(1))


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test_client_snapshot_run.py <client_app_skeleton_cli>")
        return 2
    cli = Path(sys.argv[1])
    if not cli.is_file():
        print(f"CLI binary not found: {cli}")
        return 2

    missing_cover = registered_type_ids() - set(TYPED_RECORDS)
    if missing_cover:
        print(f"registered types missing from the run fixture: "
              f"{sorted(missing_cover)} — extend TYPED_RECORDS")
        return 1

    with tempfile.TemporaryDirectory(prefix="bh-reverse-run-") as tmp:
        root = Path(tmp) / "snapshot"
        build_snapshot(root)

        proc = subprocess.run([str(cli), str(root)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"CLI failed (rc={proc.returncode}):\n{proc.stdout}\n"
                  f"{proc.stderr}")
            return 1
        out = proc.stdout

        try:
            assert field(out, "blocks") == 1, out
            assert field(out, "dynamic records") == len(TYPED_RECORDS), out
            assert field(out, "dynamic objects") == len(TYPED_RECORDS), out
            assert field(out, "stub objects") == 0, out
            assert field(out, "recovered objects") == len(TYPED_RECORDS), out
            assert field(out, "unidentified objects") == 0, out
            assert field(out, "out-of-range types") == 0, out
            assert field(out, "opaque records") == 0, out
            assert field(out, "malformed records") == 0, out
            m = re.search(r"worldTime \(main/worldv2\):\s+([\d.]+)", out)
            assert m is not None, out
            assert float(m.group(1)) == WORLD_TIME, out
            for type_id in TYPED_RECORDS:
                assert re.search(rf"type {type_id}: 1 object\(s\)", out), \
                    (type_id, out)
        except AssertionError as exc:
            print(f"report assertion failed: {exc}\n---- CLI output ----\n{out}")
            return 1

        # same run through --json: exact statuses, ids and class names
        proc = subprocess.run([str(cli), str(root), "--json"],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"CLI --json failed (rc={proc.returncode}):\n{proc.stderr}")
            return 1
        report = json.loads(proc.stdout)
        expected_ids = {type_id: rec[1]
                        for type_id, rec in TYPED_RECORDS.items()}
        expected_names = {type_id: rec[0]
                          for type_id, rec in TYPED_RECORDS.items()}
        errors = []
        if report["recovered_objects"] != len(TYPED_RECORDS):
            errors.append(f"recovered={report['recovered_objects']}")
        if report["stub_objects"] != 0:
            errors.append(f"stub={report['stub_objects']}")
        if report["per_type"] != {str(t): 1 for t in TYPED_RECORDS}:
            errors.append(f"per_type={report['per_type']}")
        for obj in report["objects"]:
            t = obj["type_id"]
            if obj["status"] != "recovered":
                errors.append(f"type {t}: status {obj['status']}")
            if obj["class_name"] != expected_names[t]:
                errors.append(f"type {t}: class {obj['class_name']}")
            if obj["unique_id"] != expected_ids[t]:
                errors.append(f"type {t}: uid {obj['unique_id']}")
            needle = EXPECT_REASON.get(t)
            if needle and needle not in obj.get("reason", ""):
                errors.append(
                    f"type {t}: reason misses evidence grade '{needle}' "
                    f"(got: {obj.get('reason', '')})")
        if errors:
            print("json assertions failed: " + "; ".join(errors))
            print(json.dumps(report, indent=2)[:4000])
            return 1

    n = len(TYPED_RECORDS)
    print(f"client-snapshot-run: PASS ({n}/{n} recovered through the CLI)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
