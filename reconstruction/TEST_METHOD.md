# Rebuild-v2 test method

This project has three separate acceptance layers. A green Gradle build is only
the first one.

## 1. Source/asset contract (local and CI)

Run from the repository root:

```sh
python3 tools/validate_render_contract.py
python3 tools/asset_audit.py \
  --apk /path/to/original.apk \
  --assets app/src/main/assets \
  --repo . \
  --json reconstruction/asset_comparison.json
```

The first command checks shader selection, UV units, unknown-ID rejection,
texture filtering, the world tick wakeup, and case-sensitive asset names.
The second command compares every referenced asset by full path and reports
missing files and dimension mismatches.

## 2. Packaged APK contract (CI or after downloading the artifact)

```sh
python3 tools/validate_apk.py app-debug.apk
```

This checks that the built APK contains the shader pair, item atlases,
hotbar selection asset, corrected animal asset, manifest, and at least one
`native-lib` ABI payload. It does not claim the APK renders correctly.

## 3. Device smoke test (real Android device)

Connect a test device with USB debugging and verify `adb devices` first.
Install and launch explicitly:

```sh
python3 tools/device_smoke_test.py \
  --apk app-debug.apk \
  --install \
  --out-dir reconstruction/device-smoke
```

Without `--install`, the script tests the currently installed package:

```sh
python3 tools/device_smoke_test.py
```

The result must include:

- a live package PID after launch;
- `reconstruction/device-smoke/logcat.txt`;
- `reconstruction/device-smoke/screen.png`.

Review the screenshot manually for the main menu, hotbar highlight, atlas
orientation, black/transparent textures, and native crash symptoms. Then
launch the game through the menu and repeat the capture after entering the
world. Device smoke is not protocol, save-format, or gameplay-equivalence
acceptance; those require separate scenario tests.

## Required scenario evidence before calling a feature verified

- Cold launch from stopped process.
- Main menu -> new world -> world render.
- Hotbar selection changes visually.
- Pan and pinch do not move the UI overlay with world coordinates.
- Place/break one known block and capture logcat plus screenshot.
- Save, force-stop, relaunch, and verify the same world state.
- Open inventory and exercise one swap.

Report each scenario as `施工` (code path exists) and `验收` (device evidence
exists). CI build success alone belongs only to construction/packaging.
