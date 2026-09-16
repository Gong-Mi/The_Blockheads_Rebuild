# GameView -[startTouch:withTouch:withEvent:] static control-flow map

Original ELF SHA-256 `733d8210…b94c7`; types `v24@0:4{CGPoint=ff}8@16@20`
(CGPoint by value in r2/r3, withTouch at fp+8, withEvent at fp+12).
IMP `0x0092be2c`, ARM.exidx end `0x0092c148` (199 words including the literal
pool), verified against the pinned bytes
(`tools/recover_gameview_starttouch.py --check`). PIC base `0x0105faf4` —
the same compilation-unit family as -[init] and -[touchIsInUI:].

This closes the primary-touch producer `startTouch:withTouch:withEvent:` from
`GAMEVIEW_INPUT.md`/`GAME_ADAPTER_BOUNDARY.md`; move/end/cancel producers and
`init` remain pending. The withEvent argument is spilled at entry
(`str lr,[fp,#-0x30]`@0x0092be7c) and NEVER read again.

## Dispatch sites (all seven, with receiver provenance)

| site | route | selector | receiver route (reviewed loads) |
|---|---|---|---|
| 0x0092bf2c `bl #0x1c281c` | msgSend@plt | `tapCount` | withTouch (fp-0x2c, first stack arg); menu path only |
| 0x0092bf50 `bl #0x1c281c` | msgSend@plt | `startTouch:tapCount:` | mainMenuUI reloaded 0x0092bee4..0x0092befc; menu path iff mainMenuUI != nil AND world == nil |
| 0x0092bf98 `blx r2` | GOT `objc_msgSend` (GLOB_DAT 0x0105b7a0) | `loadComplete` | world reloaded 0x0092bf70..0x0092bf84; world path (mainMenuUI==nil OR world!=nil) |
| 0x0092bfe4 `blx r2` | GOT `objc_msgSend` (same slot) | `isSimulating` | world reloaded 0x0092bfbc..0x0092bfd0; reached when loadComplete (sxtb) != 0 |
| 0x0092c03c `bl #0x1c281c` | msgSend@plt | `tapCount` | withTouch reloaded fp-0x2c; re-sent AFTER the world gates |
| 0x0092c068 `bl #0x1c281c` | msgSend@plt | `startTouch:tapCount:index:` | world reloaded 0x0092bff4..0x0092c00c; stack args [tapCount, 0] (index literal 0 via `movw lr,#0`@0x0092c058) |
| 0x0092c0a8 `bl #0x1c281c` | msgSend@plt | `touchIsInUI:` | world kept from the 0x0092c00c load; reached when isSimulating (sxtb) == 0 |

The four `bl` sites share the msgSend PLT stub `0x001c281c`
(`R_ARM_JUMP_SLOT objc_msgSend`, GOT slot 0x0105fb18). The two `blx r2` sites
load the dispatch target from GOT slot `0x0105b7a0`, which carries a
`R_ARM_GLOB_DAT` relocation against `objc_msgSend` (file value 0; resolved
through the relocation table, not the zero file content). Same receiver,
selector-in-r1 ABI as the plain stub.

Ivar cells (symbol-resolved via __objc_ivar entries, offsets re-checked):

| ivar | cell | offset |
|---|---|---:|
| `OBJC_IVAR_$_GameView.mainMenuUI` | 0x0092c10c | 20 |
| `OBJC_IVAR_$_GameView.world` | 0x0092c118 | 24 |
| `OBJC_IVAR_$_GameView.primaryTouchIsActiveInUI` | 0x0092c110 | 496 |
| `OBJC_IVAR_$_GameView.startTouchHasntMoved` | 0x0092c114 | 486 |
| `OBJC_IVAR_$_GameView.startTouchPos` | 0x0092c140 | 488 |

Selector cells: `tapCount` 0x0092c120, `startTouch:tapCount:` 0x0092c124,
`startTouch:tapCount:index:` 0x0092c138, `touchIsInUI:` 0x0092c13c,
`loadComplete` 0x0092c12c, `isSimulating` 0x0092c130 (all through selrefs).

## Decision logic (static CFG, exact branch sites)

```text
self->startTouchHasntMoved = 0        # strb @0x0092be8c, unconditional
self->primaryTouchIsActiveInUI = 0    # strb @0x0092be9c, unconditional
if self->mainMenuUI != nil (beq 0x0092bf5c) AND self->world == nil (bne 0x0092bf5c):
    # menu path
    [mainMenuUI startTouch:point tapCount:[withTouch tapCount]]
    return
# world path — runs even when world == nil (nil dispatch yields 0/false)
if [world loadComplete] (sxtb) == 0 (beq 0x0092c100): return
if [world isSimulating] (sxtb) != 0 (bne 0x0092c100): return
tapCount = [withTouch tapCount]                       # re-sent, not reused
self->primaryTouchIsActiveInUI = low byte of
    [world startTouch:point tapCount:tapCount index:0] # strb @0x0092c080, NO sxtb
if [world touchIsInUI:point] (sxtb) == 0 (bne 0x0092c0fc):
    self->startTouchHasntMoved = 1                     # strb @0x0092c0dc
    self->startTouchPos = point                        # two full-word str @0x0092c0f0/0x0092c0f8
```

Notable byte-level facts, all pinned:

- The gate order matches -[touchIsInUI:] (menu iff `mainMenuUI != nil AND
  world == nil`); the two producers route consistently.
- GameView performs NO `sxtb` of its own on the World `startTouch:` result;
  `strb`@0x0092c080 keeps only the low byte (the World method itself sign-
  extends its own result — see WORLD_STARTTOUCH.md).
- `tapCount` is dispatched twice on the world path (once only in the menu
  path); the value is re-obtained after the gates rather than cached.
- The `startTouchPos` write is a full-word CGPoint copy (two `str`), while
  `startTouchHasntMoved` is a single byte store — mixing them would be wrong.
- The world receiver is reloaded from the ivar before EVERY world send
  (0x0092bf78..0x0092bf84, 0x0092bfc4..0x0092bfd0, 0x0092bff4..0x0092c00c);
  callbacks that nil the world mid-flight leave subsequent sends as
  nil-dispatch no-ops with zero results — the final stores then DO execute.

## Recovered behavior

Executable snapshot: `reconstruction/recovered/gameview_starttouch.{h,cpp}`
in `blockheads_recovered_view`, sharing the one `GameViewState` plus a paired
`GameViewStartTouchState` (three added ivars). Mandatory external interfaces:
`StartTouchMenuUI::startTouch` (mainMenuUI), `GameViewStartTouchRuntime::
touchTapCount` (UITouch dispatch), and the two new `FrameWorld` selectors
(`startTouch:tapCount:index:` returning the signed byte, `touchIsInUI:`).
UIManager `startTouch:tapCount:` internals, UITouch `tapCount` internals and
the World callees' own bodies are NOT declared recovered.

## Bounds of the claim

Static bounded-body map plus a typed host snapshot: no runtime receiver
identity, no nil-`withTouch`/`mainMenuUI` dispatch proof (nil models the
ObjC zero), no UIManager/World side-effect proof, no original-runtime
differential, no Android device execution. This is single-owner synchronous
dispatch; producers for move/end/cancel, `init` window construction and the
game-loop adapter remain pending.

## Reproduce (local acceptance layer, requires original ELF)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_starttouch.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
```

CI runs the dependency-free compiled contract instead: the
`gameview_starttouch` ctest target builds from
`tools/test_gameview_starttouch.cpp` at O0/O2.
