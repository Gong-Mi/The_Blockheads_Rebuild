# Blockheads Rebuild v2

This branch deliberately does not extend the previous prototype in place.
The previous implementation remains in Git history as the legacy baseline.

## Why v2 exists

The old prototype mixed four unverified assumptions into the runtime:

- numeric item IDs were treated as direct 32-column atlas coordinates;
- native shader input layout was copied without an independent vertex-contract test;
- world generation, lighting, fluids, and temperature were updated from one
  worker loop with guessed constants;
- Android widgets were used as a second UI renderer while the GL renderer owned
  world coordinates, causing two unsynchronised coordinate systems.

Those choices explain why adding content did not converge: an apparently valid
feature could still use the wrong texture, wrong tile identity, or wrong screen
position.

## v2 boundaries

The rebuild is split into contracts before gameplay features:

1. `asset-contract`: APK/extracted-resource inventory, PNG dimensions, shader
   inputs, atlas metadata and stable content IDs.
2. `world-model`: deterministic tick/update commands with no Android or GL
   dependency. Every state mutation is an explicit command and can be replayed.
3. `render-model`: immutable render snapshots. The renderer never reads mutable
   simulation state and never invents item coordinates.
4. `ui-model`: one coordinate space and one event stream. Android only supplies
   surface/input/audio services; it does not maintain a parallel gameplay UI.
5. `android-runner`: lifecycle, EGL/GLES and packaging only.

## First gate

Run:

```sh
python3 tools/asset_audit.py \
  --apk /storage/emulated/0/Download/com.noodlecake.blockheads_1.7.6-1564553369_minAPI12\(armeabi-v7a\)\(nodpi\)_apkmirror.com.apk \
  --repo . \
  --json reconstruction/apk_asset_catalog.json
```

The command must pass before renderer changes are accepted. A missing asset is a
build error, not a runtime fallback.

## Known legacy defects recorded from source

- `SelectionBox40.png` is referenced but absent from both APK and repository.
- `dropbearBody.png`, `dropbearHead.png`, and `yakLeg.png` are referenced but
  absent; the APK uses other names/parts (`yakLegs.png`, etc.).
- `loadTex()` always calls `glGenerateMipmap()` and selects a mipmapped min
  filter, even for small/non-atlas textures. This is not the original shader
  contract and can produce incomplete-texture failures on GLES paths.
- `pushBlock()` falls back to `(type - 1) % 32` / `/ 32`, although the original
  block shader consumes a separate atlas index plus 0..255 local pixel
  coordinates. Numeric item ID and atlas position are different concepts.
- JNI calls are guarded by one recursive global mutex while rendering and
  simulation share global objects. v2 will replace this with a command queue and
  immutable snapshots.

The asset comparison must preserve APK paths because the package contains both
the normal and `HDTex` copies of many files. The normal `TileMap`,
`TileDestruct`, and `Items` dimensions match the corresponding old-project
assets; the comparison currently identifies the character skin files as
32x16-vs-256x128 mismatches. The earlier basename-only comparison that called
the core atlases mismatched was invalid and is not used anymore.

These are evidence-backed starting points, not gameplay guesses.

## First implementation landed

The renderer now has a separate item path using the APK's `Item.vsh` and
`Item.fsh` pair. Dropped items resolve through `ItemManager` and convert the
explicit item-table cell to normalized coordinates for `Items.png`; they no
longer use `Block.fsh` or `(itemId - 1) % 32`. Unknown IDs are rejected instead
of being rendered at a guessed location. Texture upload also uses a complete
non-mipmapped GLES2 contract, and the known yak leg filename is corrected to
`yakLegs.png`.
