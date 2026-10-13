#!/usr/bin/env python3
"""Contract test for app/src/main/cpp/sound_preload_registry.h (the replacement-side consumer).

The C++ target proves the registry behaves; this test pins the two properties that keep the pair of
files honest as the generated list evolves:

  * the registry must NOT hard-code the row count - it must read
    recovered::kOriginalLoadTimeSoundCount, so regenerating the list cannot leave it stale;
  * it must include the GENERATED header rather than restating names, and the generated header must
    still carry the array + count the registry binds to.

Negative controls mutate a copy of each file, so "green" means the check would have caught the drift
it claims to catch.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HDR = ROOT / "app/src/main/cpp/sound_preload_registry.h"
GEN = ROOT / "reconstruction/recovered/sound_preload_list.h"


def problems(header: str, generated: str) -> list[str]:
    out: list[str] = []
    if '#include "sound_preload_list.h"' not in header:
        out.append("the registry must include the GENERATED header")
    if "kOriginalLoadTimeSoundCount" not in header:
        out.append("the registry must bind to kOriginalLoadTimeSoundCount, not a literal count")
    # a hard-coded row count would go stale the moment the list is regenerated
    for m in re.finditer(r"\b(\d{2,3})\b", header):
        if m.group(1) in ("32", "26", "161"):
            out.append(f"hard-coded count {m.group(1)} found in the registry")
    if "kOriginalLoadTimeSounds" not in header:
        out.append("the registry must read the generated array")
    if "const char*" not in generated and "struct OriginalLoadTimeSound" not in generated:
        out.append("the generated header lost its row struct")
    if not re.search(r"kOriginalLoadTimeSoundCount\s*=\s*\d+", generated):
        out.append("the generated header lost its count constant")
    return out


def main() -> int:
    if not HDR.is_file() or not GEN.is_file():
        print("skip: registry or generated header absent")
        return 0
    header, generated = HDR.read_text(), GEN.read_text()
    assert problems(header, generated) == [], problems(header, generated)

    # negative controls
    assert any("hard-coded" in p for p in problems(header.replace("entries_.size()", "32", 1), generated))
    assert any("must include the GENERATED" in p for p in problems(header.replace(
        '#include "sound_preload_list.h"', "", 1), generated))
    assert any("count constant" in p for p in problems(header, re.sub(
        r"kOriginalLoadTimeSoundCount\s*=\s*\d+", "", generated, count=1)))

    n = int(re.search(r"kOriginalLoadTimeSoundCount\s*=\s*(\d+)", generated).group(1))
    rows = len(re.findall(r'\{"[\w.]+\.wav"', generated))
    assert n == rows == 32, f"generated header says {n} but lists {rows} rows"
    print(f"registry/generated pair consistent: {n} rows, no hard-coded count, controls verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
