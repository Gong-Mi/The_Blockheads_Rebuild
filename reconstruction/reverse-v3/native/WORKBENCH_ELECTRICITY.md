# Workbench electricity system — E75 (electricity line)

The Workbench's electricity war: the u16 charge store, the drain, the
generator/storage/use type tables, the 8192 capacity constant, the solar
panels and the portal/electric light colors.
**12 bodies, 1699 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_wbelectric.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/workbench_electricity.json`.

| body | imp | words | content |
|---|---|---:|---|
| wb_subtractelec | 0x00b0137c | 245 | the electricity drain |
| wb_getlightrgb | 0x00ae3c6c | 190 | light colors (electric blue) |
| wb_storagedev | 0x00b01bd4 | 20 | storage test |
| wb_energyfrac | 0x00b01ec0 | 104 | fraction (8192) |
| wb_genelectric | 0x00b01c24 | 167 | generator types |
| wb_useselectric | 0x00b01cac | 133 | use-set enumeration |
| wb_solarlight | 0x00aee508 | 324 | solar (normal) |
| wb_solarlight_full | 0x00aee208 | 192 | solar (full-sun) |
| wb_portallight | 0x00ae3f64 | 215 | portal light |
| wb_conductelec | 0x00b012c0 | 47 | conductivity cascade |
| wb_avaiablelec | 0x00b01284 | 15 | u16 charge read |

## Load-bearing findings

- **The charge store**: `availableElectricity` is a **u16** (`ldrh` via the
  **fffff150** cell); `subtractElectricty:` keeps the amount as a halfword,
  guards (`cmp; bgt` = not enough exits), does the **`sub`/`strh` write-back**
  and sets its dirty byte + the ffffc8d8/c8b4/c89c propagation chain.
- **The capacity constant**: `energyFraction` type **0x15 (21)** computes
  **stored / 0x2000 (8192)** (`movw r0, 0x2000`); type 0x14 (20) reads and
  clamps its live level; other types return 0.
- **The type tables**: generate = {**0xf (15), 0x14 (20)**}; storage =
  {**0x15 (21)**}; the use-set enumeration (9 compares) covers
  **0xf/0x14/0x15/0x11/0x10/0x1b/...** - the workbench variants wired to the
  electricity system.
- **The solar panels**: `tileIsAirOrSnow` (**snow blocks the panel**) + the
  tile byte +3 == **0x2e ('.')** check; the falloff runs through
  **`__wrap_powf`** over the height fraction; the sunlight triplet is the
  sum of the halfwords at +0xe/+0x10/+0x12 compared via `vcmpe`.
- **The light colors**: `getLightRGB`'s flag arm returns **(48, 130, 220)**
  - the electric blue-cyan glow; type 3 → (4, 0x32, 0x40).
- `conductsElectricity` = the double-delegate cascade (ffe26670/74).

## Boundaries (honest)

- uncl 17/17 resolve as PIC base anchors (clean).
- The ffe26xxx/ffe264xx call-chain identities stay opaque; the workbench
  type codes are pinned by the compares but their display names are not
  asserted; the solar curve's exact exponent reads from powf's inputs in the
  listing (documented structurally).
