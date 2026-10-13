# DynamicWorld last smalls — E43

The last smalls: the elevator sound/motor triplet, the rail accessor/remover,
the 11-family tree resolver and the painting sender.
**8 bodies, 536 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_lastsm.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/last_smalls.json`.

| body | imp | words | content |
|---|---|---:|---|
| sendPaintingDataForPaintingWithID:toClient: | 0x009016c0 | 186 | painting sender |
| openElevatorAtPos: | 0x008ebd50 | 96 | elevator sound |
| removeRailAtPos: | 0x008ed2c4 | 56 | rail removal |
| treeAtPos: | 0x008ef618 | 56 | 11-family tree resolver |
| removeElevatorMotorAtPos: | 0x008ecdf0 | 45 | motor removal |
| addElevatorMotorAtPos:ofType:saveDict:placedByClient: | 0x008ecd4c | 41 | motor add |
| elevatorMotorAtPos: | 0x008ebed0 | 28 | motor accessor |
| getRailAtPos: | 0x008ed254 | 28 | rail accessor |

## Load-bearing findings

- **Type codes pinned**: elevator motor = **0x37 (55)**, rail = **0x28 (40)**.
  The motor triplet repeats the E36/E37/E38 family shape (ffe235f0 /
  ffe23624 / ffe23600 + **ffe23640**, the same cell E23's
  elevatorMotorForShaftAtPos: hits — pair confirmed).
- **Rail pair**: `getRailAtPos:` type 40 via ffe235f0; `removeRailAtPos:` =
  the **ffe235e0 check** (shared with E34's railOrStationNameChanged) + the
  ffe23600 gate + the **ffe23648** remove cell.
- **treeAtPos:** — the `arg >= 0xb` gate (**11 tree classes**) + the
  **0x00E4AA64 jump table** (11 arms) probing each family via the ffe235f0
  lookup in a loop — the table sits adjacent to E23's 0xE4AA60 life-fraction
  table (the tree-family table cluster at 0xE4AA60-0xE4AA64).
- **openElevatorAtPos:** — class **ffe2af10** + ffe232c8 (shared with E42's
  crystal player) + the **0xfff34174 sound string** + the vcvt position maths
  + the ffe23630 call.
- **sendPaintingDataForPaintingWithID:toClient:** — the ffe23788/ffe2378c
  resolve checks + the **ffe23348 8-byte data accessor** — the sender half of
  the E32 painting pair (requestPaintingDataForPainting: /
  paintingDataRecievedFromServer:) with the same 8-byte convention.

## Boundaries (honest)

- Cells pinned by cell address; type codes read from immediates; the 0xE4AA64
  adjacency to E23's table is observed; 12 of 13 uncl cells resolve as PIC base
  anchors, the last is the 0xE4AA64 table base; the parse tails continue in the
  listings. Remaining uncovered after this batch: the 7203-word
  `draw:...:hideUIType:` composite (boundary artifact for a final batch).
