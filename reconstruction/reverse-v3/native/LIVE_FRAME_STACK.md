# Live frame stack and dispatch hierarchy from running Android process

Captured directly from the `UIKitMain` thread (TID 11438) of live running process `com.noodlecake.blockheads` (armeabi-v7a) on Android 16/HyperOS translator. **Build not recorded at capture — see Provenance and corrections.**

## Background and Methodology

Static disassembly of `World -render:` (8640w) and `DynamicWorld -draw:` (7203w) revealed extensive dispatch candidate sets, but joining the exact call sequence required live execution evidence.

By reading `/proc/<pid>/mem` at the top of the `UIKitMain` thread stack (`[anon:stack_and_tls:11438]`), we extracted all active return addresses pointing into `libApplication.so` (`.text` range `0x001c4480..0x00db8950`). Correlating these return addresses with the 10,478 indexed methods in `libApplication_objc_methods.tsv` reconstructs the active frame hierarchy of a live running world frame.

## Reconstructed Call Stack (17 recorded frames; names build-unbound)

```text
UIApplication run (+0x2f0)
└── World render:cameraZ:projectionMatrix:pinchScale: (+0x1d250)
    ├── UIManager render:projectionMatrix:cameraZ:cameraMinXWorld:...:mapAlpha: (+0x1350)
    │   └── WorldUI render:translation:pinchScale:paused: (+0x4630)
    │       ├── DPad render: (+0x328)
    │       ├── SleepProgressUI render:translation:pinchScale: (+0x1b98)
    │       ├── Tutorial render:translation:pinchScale: (+0x32bc)
    │       ├── MJButton renderFrame:projectionMatrix: (+0x2b0)
    │       ├── MJView renderFrame:projectionMatrix: (+0x314)
    │       ├── MJTextView setColor: (+0x1c)
    │       └── BitmapString renderWithProjectionMatrix:modelViewMatrix: (+0x92c)
    ├── DonkeyLike draw:projectionMatrix:modelViewMatrix:cameraMinXWorld:... (+0x150)
    │   ├── DonkeyLike setupMatrices:dt: (+0x1954)
    │   └── Donkey drawSubClassStuff:projectionMatrix:modelViewMatrix: (+0x2ec8)
    ├── Blockhead drawForButtonProjectionMatrix:modelViewMatrix: (+0x118c0)
    │   └── DrawCube cubeDebugDescription (+0x13c)
    └── CraftUI craftButton: (+0x5e4)
```

## Key Architectural Findings

1. **World Frame Orchestration**:
   - `World -[render:cameraZ:projectionMatrix:pinchScale:]` is confirmed as the root world frame driver.
   - It divides each frame into:
     * UI master layer (`UIManager` -> `WorldUI` -> sub-panels and controls).
     * Entity / Animal layer (`DonkeyLike` family rendering with dynamic matrix setup).
     * Character button / portrait previews (`Blockhead -drawForButtonProjectionMatrix:modelViewMatrix:`).

2. **NPC / Animal Rendering Model**:
   - `DonkeyLike` decomposes rendering into:
     * `setupMatrices:dt:` (0x00ab9df8): computes bone matrices (`bodyMatrix`, `headMatrix`, `neckMatrix`, `leftArmMatrix`, `rightArmMatrix`, `leftLegMatrix`, `rightLegMatrix`) from `walkTimer` and `headDownFraction`.
     * `draw:projectionMatrix:...` (0x00abc508): draws common animal geometry.
     * `drawSubClassStuff:projectionMatrix:modelViewMatrix:` (0x00ac2d08): draws species-specific meshes (e.g. donkey vs yak features).

3. **HUD and UI Delegation**:
   - HUD elements (`DPad`, `SleepProgressUI`, `Tutorial`) are direct child renders of `WorldUI`, which delegates text and glyph draws to `BitmapString` and `MJTextView`.

## Provenance and corrections (2026-10-02)

- **Count corrected**: an earlier revision declared 21 frames while the `frames` array holds
  **17**; `frame_count` now equals the recorded data and the contract test enforces that
  equality (a declared count without matching data must fail).
- **Build binding missing**: this capture did not record the running `libApplication.so`
  sha256, and the frame names were aligned against the pinned **1.7.6** method table (10478).
  A same-night live measurement on this device proved a **1.7.5** process, so these names are
  **build-unbound** — treat the hierarchy as a clue, not as a verified runtime dispatch tree,
  until re-captured with the build hash recorded (same discipline as the ivar-offset line;
  see `IVAR_OFFSET_READING.md`).
- **No raw evidence retained**: the artifact stores names/roles only — no return addresses or
  stack offsets — so independent re-verification requires a fresh capture that keeps the raw
  return-address words alongside the aligned names.

## Pinned Artifacts

- Document: `native/LIVE_FRAME_STACK.md`
- JSON frame map: `native/live_frame_stack.json`
- Contract test: `tools/test_live_frame_stack.py`
