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
            assert field(out, "dynamic records") == 10, out
            assert field(out, "dynamic objects") == 10, out
            assert field(out, "stub objects") == 0, out
            assert field(out, "recovered objects") == 10, out
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
        if report["recovered_objects"] != 10:
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
        if errors:
            print("json assertions failed: " + "; ".join(errors))
            print(json.dumps(report, indent=2)[:4000])
            return 1

    print("client-snapshot-run: PASS (10/10 recovered through the CLI)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
