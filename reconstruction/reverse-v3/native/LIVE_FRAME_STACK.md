# Live frame stack and dispatch hierarchy from running Android process

**Build-bound recapture (2026-10-02).** Captured from the `UIKitMain` thread (TID 10943) of the
live `com.noodlecake.blockheads` process (PID 10853) on Android 16/HyperOS binary translator.
The running `libApplication.so` is pinned by sha256 (the device runs the 1.7.5 build), and frame
names are aligned against a method table generated from that same library — this supersedes the
earlier build-unbound 2026-10-01 capture (see Provenance and corrections).

## Background and Methodology

Static disassembly of `World -render:` and `DynamicWorld -draw:` revealed extensive dispatch
candidate sets, but joining the exact call sequence required live execution evidence.

Two verification steps gate every frame — both enforced by the capture probe, which also carries
an inlined calibration block (2 known frames must resolve to their imps; 2 byte-verified non-calls
must stay non-calls; 1 known unnamed region must stay unnamed) and refuses to report if any check fails:

1. **Call-site check** — a `bl`/`blx` instruction must end exactly at the candidate address (ARM
   and Thumb modes both tried). Stack words that merely look like code pointers (saved constants,
   shim values) fail this and are excluded from `frames` (they remain in `stack_words` with
   `callsite: false`).
2. **Enclosing-function check** — the enclosing function start is found by walking back (A32,
   4-byte steps) to the nearest `push {…, lr}` prologue; for a call-return address this is the
   containing non-leaf function. A frame is credited to an Objective-C method **only** when that
   start exactly equals a method-table imp; otherwise it is recorded as an unnamed function by its
   raw start address.

## Reconstructed Call Stack (20 call-site-verified frames, stack order root → leaf)

- unnamed function @ 0x00496058 — return_addr 0x64a2d0f8, file_va 0x004960f8
- unnamed function @ 0x0024065c — return_addr 0x647d773c, file_va 0x0024073c
- unnamed function @ 0x009c538c — return_addr 0x64f5c4ec, file_va 0x009c54ec
- unnamed function @ 0x00240814 — return_addr 0x647d7c34, file_va 0x00240c34
- `UIApplication run (+0x270)` — fn_start 0x00242470, return_addr 0x647d96e0
- `World render:cameraZ:projectionMatrix:pinchScale: (+0x1d0f8)` — fn_start 0x0058c950, return_addr 0x64b40a48
- `UIManager render:projectionMatrix:cameraZ:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:hideUIType:pinchScale:mapAlpha: (+0x11f8)` — fn_start 0x00acad98, return_addr 0x65062f90
- `SleepProgressUI render:translation:pinchScale: (+0x1a40)` — fn_start 0x00b34b48, return_addr 0x650cd588
- `Tutorial render:translation:pinchScale: (+0x3164)` — fn_start 0x007241dc, return_addr 0x64cbe340
- `WorldUI render:translation:pinchScale:paused: (+0x44d8)` — fn_start 0x00ce3fc0, return_addr 0x6527f498
- `MJTextView renderFrame:projectionMatrix: (+0x5bc)` — fn_start 0x00526970, return_addr 0x64abdf2c
- `MJButton renderFrame:projectionMatrix: (+0x27cc)` — fn_start 0x00d12858, return_addr 0x652ac024
- `MJView renderFrame:projectionMatrix: (+0x1bc)` — fn_start 0x00660fd4, return_addr 0x64bf8190
- `BitmapString renderWithProjectionMatrix:modelViewMatrix: (+0x7d4)` — fn_start 0x009e2f54, return_addr 0x64f7a728
- `MJButton renderFrame:projectionMatrix: (+0x158)` — fn_start 0x00d12858, return_addr 0x652a99b0
- `Blockhead drawForButtonProjectionMatrix:modelViewMatrix: (+0x11768)` — fn_start 0x00bedb04, return_addr 0x6519626c
- `World customRules (+0x3c)` — fn_start 0x005d56dc, return_addr 0x64b6c718
- unnamed function @ 0x00c38638 — return_addr 0x651cf9c8, file_va 0x00c389c8
- `NoiseFunction getX:Y:octaves: (+0xbc)` — fn_start 0x00a633a4, return_addr 0x64ffa460
- unnamed function @ 0x00a63478 — return_addr 0x64ffa5b4, file_va 0x00a635b4

Full per-frame evidence (`stack_addr`, `return_addr`, `file_va`, call-site instruction) and the
raw stack-word table are in `live_frame_stack.json`.

## Key Architectural Findings

1. **World frame orchestration.** `World -[render:cameraZ:projectionMatrix:pinchScale:]` is a
   single giant function — its next method-table entry is `0x1ddd0` later in **both** 1.7.5 and
   1.7.6 — so verified frames legitimately appear at offsets like `+0x1d0f8`. Large offsets alone
   are not misattribution evidence; naive nearest-below naming without prologue verification is.
2. **Delegation chain in this snapshot**: `UIApplication run` → `World render` → `UIManager render` →
   `WorldUI render` with HUD children (`SleepProgressUI`, `Tutorial`), `MJ*` view/text/button
   `renderFrame:` layers down to `BitmapString` text geometry, plus the `Blockhead` portrait path
   (`drawForButtonProjectionMatrix:modelViewMatrix:`) and `World customRules` → `NoiseFunction`
   terrain queries.
3. **Unnamed functions inside the chain** (not present in the ObjC method table; recorded by start
   address): `0x00496058` (Verde main-thread driver region), `0x0024065c` / `0x00240814`
   (Apportable/UIKit shim region), `0x009c538c`, `0x00c38638` (Blockhead `preDrawUpdate:` region),
   `0x00a63478` (NoiseFunction region).
4. **Scene-state variance.** The live stack differs between moments: three same-day captures of
   this tid yielded 34/64/33 candidate words, and which frames appear depends on what the world is
   doing (the earlier capture caught `DonkeyLike` entity draws; this one does not show them).
   Absence in one snapshot is not contradiction.

## Provenance and corrections (2026-10-02)

- The 2026-10-01 capture declared 21 frames against 17 recorded entries (fixed in commit c2ec381),
  had no build binding, and kept no raw addresses; it is superseded by this build-bound recapture.
- Stack words inside known methods that fail the call-site check are **not** listed as frames —
  e.g. `0x00242744` (inside `UIApplication run`); they stay in `stack_words` with `callsite: false`.
- Earlier name+offset tables that were produced without call-site and prologue verification are
  superseded for frames where the two disagree (this file and `live_frame_stack.json` are the
  current authority).

## Pinned Artifacts

- Document: `native/LIVE_FRAME_STACK.md`
- JSON frame map: `native/live_frame_stack.json`
- Contract test: `tools/test_live_frame_stack.py`
