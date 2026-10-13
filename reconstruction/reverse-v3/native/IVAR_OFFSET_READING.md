# Ivar-offset cells: corrected reading and the completed object-graph verification

**(Corrected 2026-10-02.)** An earlier revision of this file — "the file and the process
disagree" — reported that 3735 of 3793 ivar storage cells differ between the ELF and the
running process, leaving "which reading is the runtime offset" open. That measurement was a
**cross-build misread** and is invalid. This revision keeps it as a record, gives the
corrected same-build reading, and records the object-graph verification that closes the
question for the sampled fields.

## The prior measurement and why it was invalid

`tools/probe_live_ivar_offsets.py` had compared, for every `OBJC_IVAR_$_<Class>.<ivar>`
symbol, the ELF file content of its 4-byte storage cell with the process content read at
`base_rw + (symbol_vma - 0xe32000)` (pid 18779, `rw-p` base `0x653fc000`), and printed:

```
compared 3793 ivar storage cells: 58 identical, 3735 rewritten   (98.5% differ)
```

Correction evidence (reproduced 2026-10-02 against the same device):

1. the process that was measured ran a *different build* than the ELF whose symbols supplied
   the addresses: reading today's process at the prior measurement's exact relative addresses
   reproduces **all 3793** prior "live" values — the prior process was the same 1.7.5 build
   the device still runs, while the addresses came from the pinned 1.7.6 ELF;
2. `va176 - va175 == +0x50` for **all 3793** ivar symbols (uniform shift of the ivar-symbol
   area between the two builds);
3. neighbor closure: every prior "live" value equals the cell value of the symbol sitting
   0x50 later — e.g. prior `Blockhead.state` 728 == `Blockhead.skinOptions` cell,
   `bodyCube` 516 == `prevFromSquare`, `floatPos` 36 == `FishingRod.hookPos`.

So the prior table is a record of neighboring cells, not of realized offsets.

## Corrected same-build reading

Same build on both sides (live libApplication `d09418e9…`, audited 2026-10-02):

- compared 3793; **identical 3714; rewritten 79 (2.1%)**;
- the 79 rewrites concentrate in UIKit-inherited classes whose realized layout differs:
  `EAGLView` family +144, `UIView` +4, `UISegment` family +196, `UIStoryboardPopoverSegue`
  +16, `UIImageNibPlaceholder` +68, `UIButtonTitle` +224, … Full list:
  `live_ivar_offset_divergence.json` → `corrected_same_build.rewritten_list`.
- **no `World` / `DynamicWorld` / `Blockhead` / `DynamicObject` cell is in the list**: for
  the game classes the file-content number **is** the runtime offset.

## The completed object-graph verification

The prior revision defined a "next method" (walk a real object graph; every hop's header
word must equal the runtime-resolved class pointer; cross-check a terminal field against an
independent file). It has now been **run** on the live process (2026-10-02):

1. runtime class objects resolved from the ELF's ObjC classlist; live values read from the
   process (relocated pointer == file va, delta 0 for all 536 libApplication classes; 82
   libCoreFoundation classes resolved the same way and used for `__NSCF*` names);
2. instances anchored without signature assumptions: World / DynamicWorld / Blockhead /
   GameView / EAGLView located by full-region class-pointer scans whose candidates must
   satisfy a structural signature (e.g. a GameView candidate must have +24 pointing at the
   found World) — a 4-byte class-pointer hit is still not instance discovery by itself, and
   the signature requirement is what the earlier revision identified as missing;
3. every hop requires the header word to equal the runtime class pointer; the verified chain:

```
World+416 -> DynamicWorld+44 -> __NSCFArray (blockheads container)
          -> store+12 -> Blockhead
Blockhead+4 -> World (DynamicObject.world), +8 -> DynamicWorld (DynamicObject.dynamicWorld)
DynamicWorld+4 -> World (back-reference)
GameView+24 -> World;  EAGLView+176 -> GameView;  EvolutionViewController+176 -> GameView
```

4. external cross-check: `World.saveID` (+436) is an `__NSCFString` whose bytes contain
   `a8124d2b4dea3347ddef22a1550a78c6` — exactly the save directory the process has open via
   `/proc/<pid>/fd`;
5. field census: every counted field must have its storage-cell value equal the empirically
   observed offset AND its target instantiate the named class. Result: **153 fields
   verified** (World 48, DynamicWorld 14, Blockhead 28 + DynamicObject base 2, GameView 12,
   UIManager 29, WorldUI 22). Machine artifact: `live_verified_fields.json`.

Status for the game classes: the fields in `live_verified_fields.json` are **verified**;
other cell values are **candidate runtime offsets** backed by the same-build identity
(3714/3793), with the 79-cell exception list applying to UIKit-inherited classes only.

## Boundaries

- The live audit binds to the installed original **1.7.5** build (`libApplication.so` sha256
  `d09418e9…`); the repository static baseline remains the pinned **1.7.6** APK (`733d8210…`).
  All 527 four-class cell values compared **equal** across the two builds
  (`live_runtime_ivar_offsets.json` → `values_equal_across_builds`); the 79-cell rewrite list
  is build-specific and a same-build 1.7.6 audit is pending.
- The live walk was read-only forensics on a user-provided foreground process: no injection,
  no screenshots, no interaction.
- `tools/probe_live_ivar_offsets.py` now hashes the libApplication mapped in the process and
  **refuses to measure when it does not match the ELF passed in** ("BUILD MISMATCH"), which
  is the check whose absence produced the invalid table above.
