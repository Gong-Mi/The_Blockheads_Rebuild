#!/usr/bin/env python3
"""Guard: the APK build must compile every recovered module the app uses.

A real CI break (the npc_full batch) happened exactly here: app socket code
included a recovered module header and called its factory, but the APK-side
CMakeLists did not list the .cpp, so ld.lld failed with an undefined symbol
only on the Gradle build — host CI was green before that because the host
target had its own source list.

Rule enforced:
  1. every "#include \"X.h\"" in app/src/main/cpp that resolves to
     reconstruction/recovered/X.h must have its X.cpp (when one exists)
     listed in app/src/main/cpp/CMakeLists.txt;
  2. every reconstruction/recovered/*.cpp path named in that CMakeLists must
     exist on disk (no stale entries);
  3. the recovered include directory must be on the app include path.

Runs on plain python3, no build, no device — fit for ctest in any job.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "app/src/main/cpp"
REC_DIR = ROOT / "reconstruction/recovered"
APP_CMAKE = APP_DIR / "CMakeLists.txt"


def main() -> int:
    cmake = APP_CMAKE.read_text()
    errors = []

    # 3. include path present
    if "reconstruction/recovered)" not in cmake:
        errors.append("app CMakeLists misses the recovery include directory")

    # 1. every recovered header the app includes must have its module listed
    sources = sorted(APP_DIR.glob("*.cpp")) + sorted(APP_DIR.glob("*.h"))
    seen = set()
    for src in sources:
        for m in re.finditer(r'#include\s+"([^"]+)"', src.read_text(errors="ignore")):
            inc = m.group(1)
            if inc in seen:
                continue
            seen.add(inc)
            if not (REC_DIR / inc).is_file():
                continue  # not a recovered-dir module
            module = inc[:-2] + ".cpp" if inc.endswith(".h") else inc
            if not (REC_DIR / module).is_file():
                continue  # header-only module (e.g. sha256_util.h) — nothing to link
            if module not in cmake:
                errors.append(
                    f"{src.name} includes {inc} but {module} is not in the "
                    f"APK source list (ld.lld would fail on the Gradle build)")

    # 2. no stale entries: every recovered path named must exist
    for m in re.finditer(r"reconstruction/recovered/([\w.]+\.cpp)", cmake):
        if not (REC_DIR / m.group(1)).is_file():
            errors.append(f"APK source list names missing file: {m.group(1)}")

    if errors:
        print("apk-source-sync: FAIL")
        for e in errors:
            print(" -", e)
        return 1
    print("apk-source-sync: PASS (every app-used recovered module is compiled "
          "into the APK; no stale entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
