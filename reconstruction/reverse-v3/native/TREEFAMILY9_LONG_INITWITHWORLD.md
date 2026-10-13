# Tree-family long-variant forwarders (batch b3i)

Scope: the nine `-[initWithWorld:dynamicWorld:saveDict:cache:
treeDensityNoiseFunction:seasonOffsetNoiseFunction:]` implementations — the
LONG 6-argument variant of the loader selector — in `libApplication.so`
(sha256 `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

    CactusTree   0x00b533bc    CherryTree  0x00d0df2c    CoconutTree 0x00a99948
    CoffeeTree   0x007deb28    GemTree     0x00529134    LimeTree    0x00809c3c
    MangoTree    0x00d4b4f4    MapleTree   0x00db5fb4    OrangeTree  0x00a96604

62 words each, 558 words total.

Evidence level: **static (level-A)** — word-gated decode of the original
instruction stream, no execution in this batch (b4-style execution of the
shared body is future work; the body is byte-identical so one harness covers
all nine).

## Finding

All nine bodies are ONE byte-identical shared skeleton (words 0..58,
sha256 `0e8602818e17…` over the little-endian body words, gated per class);
the per-class tail words 59–61 only select each class's own superref /
selector / PIC cells. Pairwise comparison confirmed 59/62 words identical
before gating; the three differing words per pair are exactly the tail.

Decoded semantics of the shared body:

```text
prologue          spill all six incoming arguments
                  (self, _cmd, world, dynamicWorld, saveDict, cache,
                   treeDensityNoiseFunction, seasonOffsetNoiseFunction —
                   last two arrive on the stack, @32…@28 type encoding)
                  into the outgoing call frame
call              objc_msgSendSuper2 with the own-class superref, forwarding
                  ALL SIX arguments to [super initWithWorld:dynamicWorld:
                  saveDict:cache:treeDensityNoiseFunction:
                  seasonOffsetNoiseFunction:]
nil guard         cmp r1,r0; bne → if the super result is nil, return nil
epilogue          otherwise return the super result (return self)
own state         NONE: no CFString key is read, no ivar is written,
                  no post-init hook is called (contrast b3f's loadDerivedStuff
                  and b3h's initSubDerivedItems shapes)
```

All nine runtime superclasses resolve in-file to **Tree** — so this batch
completes the tree family's loader front: every tree subclass forwards to
`Tree`'s own loader, which is where the save-dict reading happens.

## Census after b3i (selector front, both variants)

```text
exact 4-arg variant   43 methods / 10,976 words total (map scope)
long 6-arg variant     17 methods /  2,844 words total
covered after b3f+g+h+i 20 methods (11 forwarders + 9 tree-family)
remaining (exact)       23 methods / 9,634 words
largest remaining       Workbench 1,390w, FreeBlock 1,347w, Chest 760w
```

## Negative controls

6/6 mutations detected with the correct failing site:

- body word mutations report their own class + word index
  (CactusTree w42 super call, CherryTree w48 nil guard, GemTree w0 push,
   LimeTree w57 pop)
- a mid-body word with no explicit gate is caught by the shared-body sha256
  check naming the class (MangoTree w30)
- a tail-literal mutation is caught by the per-class tail gates
  (CoconutTree w60)

Gate-ordering lesson (recorded in the skill): run the word-index gates BEFORE
the shared-body hash check — a checksum must never swallow the site-specific
failure message.

## Artifacts

- `tools/recover_treefamily9_long_initwithworld.py` — recovery tool
  (`--check` / `--self-test`).
- `reconstruction/reverse-v3/native/treefamily9_long_initwithworld.json` —
  gated evidence (per-class IMP/boundary/superref/GOT cells, body sha256).
- `tools/test_treefamily9_long_initwithworld_evidence.py` — dual-mode guard.
- This document.
