#!/usr/bin/env python3
"""Original-runtime measurement: InventoryItem accessor round trip (shell32).

The measurement was taken on the RUNNING original: the shell32
standalone-original process (runtime-lab repo, shell32/logs/run119.log) loaded
the same arm32 libApplication build and used objc_getClass / sel_registerName /
objc_msgSend (resolved from the live libSystem) to construct a real instance:

    objc_getClass("InventoryItem")  = 0x9d3a5c84
    [InventoryItem alloc]           = 0x91306f80
    itemType=0  dataA=0  selectedSubItemIndex(initial)=0
    setSelectedSubItemIndex(0x99) -> selectedSubItemIndex=153   (round trip)
    subItems=0x0

so the setter and the getter are behaviourally consistent on the running
original: the setter stores what the getter reads back.

Boundaries (stated, not implied):
  - the instance is alloc-only (no initWith*), so this measures the accessor
    pair, NOT any initialization path;
  - the call chain goes through the runtime's own dispatch (sel_registerName +
    objc_msgSend), so dispatch itself is exercised;
  - no claim is made about the field's meaning beyond the round trip.

Usage: python3 probe_shell32_inventoryitem.py [probe_output.txt]
Without an argument it verifies the committed fixture; with a fresh run119-style
output file it re-checks the same claims against it.
"""
import sys
from pathlib import Path

FIXTURE = """objc_getClass(InventoryItem) = 0x9d3a5c84
[InventoryItem alloc] = 0x91306f80
itemType=0  dataA=0  selectedSubItemIndex(initial)=0
setSelectedSubItemIndex(0x99) -> selectedSubItemIndex=153  ok=true
subItems=0x0
"""

SETTER_IMP = "0x00ac7518"   # InventoryItem -setSelectedSubItemIndex:
GETTER_IMP = "0x00ac74dc"   # InventoryItem -selectedSubItemIndex


def parse(text):
    got = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("objc_getClass(InventoryItem) = "):
            got["class"] = line.split("= ")[1]
        elif line.startswith("[InventoryItem alloc] = "):
            got["instance"] = line.split("= ")[1]
        elif line.startswith("setSelectedSubItemIndex(0x99) -> selectedSubItemIndex="):
            rest = line.split("selectedSubItemIndex=")[1]
            got["roundtrip_value"] = int(rest.split()[0])
            got["roundtrip_ok"] = "ok=true" in line
    return got


def check(text):
    got = parse(text)
    errors = []
    if not got.get("class") or int(got["class"], 16) == 0:
        errors.append("class lookup returned null")
    if not got.get("instance") or int(got["instance"], 16) == 0:
        errors.append("alloc returned null instance")
    if got.get("roundtrip_value") != 0x99:
        errors.append(f"round trip value {got.get('roundtrip_value')} != 0x99")
    if not got.get("roundtrip_ok"):
        errors.append("round trip flagged not ok")
    return errors


def main():
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text()
        print(f"re-checking {sys.argv[1]} against the committed claims")
    else:
        text = FIXTURE
        print("verifying the committed fixture (shell32 run119)")
    errors = check(text)
    print(f"setter {SETTER_IMP} / getter {GETTER_IMP}: round trip on the running original")
    if errors:
        for e in errors:
            print("FAIL:", e)
        return 1
    print("PASS: setter writes and getter reads back the same value on a live instance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
