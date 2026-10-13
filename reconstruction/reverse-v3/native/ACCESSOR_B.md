# DynamicWorld structure-part accessor family B — E37

The second typed-accessor batch, four structure-part triplets: each at-position
lookup (ffe235f0), each add (ffe23624 with the type immediate) and each removal
(ffe23600 + the per-type cell). **12 bodies, 456 verified words**, from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_acc2.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/accessor_b.json`.

| body | imp | words | content |
|---|---|---:|---|
| addLadderAtPos:ofType:saveDict:placedByClient: | 0x008eb4d8 | 41 | ladder add |
| addColumnAtPos:ofType:saveDict:placedByClient: | 0x008eb6a0 | 41 | column add |
| addStairsAtPos:ofType:saveDict:placedByClient: | 0x008eb868 | 41 | stairs add |
| addElevatorShaftAtPos:ofType:saveDict:placedByClient: | 0x008ebbf8 | 41 | shaft add |
| removeLadderAtPos: | 0x008eb57c | 45 | ladder removal |
| removeColumnAtPos: | 0x008eb744 | 45 | column removal |
| removeStairsAtPos: | 0x008eb90c | 45 | stairs removal |
| removeElevatorShaftAtPos: | 0x008ebc9c | 45 | shaft removal |
| ladderAtPos: | 0x008eb468 | 28 | ladder accessor |
| columnAtPos: | 0x008eb630 | 28 | column accessor |
| stairsAtPos: | 0x008eb7f8 | 28 | stairs accessor |
| elevatorShaftAtPos: | 0x008ebb88 | 28 | shaft accessor |

## Load-bearing findings

- **Type codes pinned**: ladder = **0x13 (19)**, column = **0x35 (53)**,
  stairs = **0x36 (54)**, elevator shaft = **0x38 (56)**.
- **Regular triplets**: every `XAtPos:` is the type immediate + the ffe235f0
  lookup; every `addX...` packs the four arguments (ofType/saveDict/placedByClient
  + the type head `mov r1, <type>`) into the ffe23624 call frame; every
  `removeXAtPos:` is the ffe23600 gate + its per-type remove cell
  (ffe23628 ladder / ffe2355c column / ffe23560 stairs / ffe2362c shaft).
- The triplet shape matches E36's torch/egg/painting family — the same three
  dispatch cells recur across both batches (ffe235f0 / ffe23624 / ffe23600).

## Boundaries (honest)

- All cells pinned by cell address; type codes read from immediates; the
  4-argument frame layout read from the stack stores; all 16 uncl cells resolve
  as PIC base anchors (clean). Note: the elevator-shaft method names hit the
  22-char slug truncation in the listing filenames (addelevatorshaftatpos_oftype_savedict_pl / removeelevatorshaftatpos_), recorded verbatim in the pins.
