# getSaveDict key pairings — batch 2f (Column, Stairs, Door, Wire)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2f.py` →
`subclass_savedict_keys_b2f.json`. Listings:
`disasm_column_getsavedict.txt` (188w), `disasm_stairs_getsavedict.txt`
(188w), `disasm_door_getsavedict.txt` (185w),
`disasm_wire_getsavedict.txt` (189w).
Table generator: `tools/gen_b2f_table.py` (mechanical extraction from the
listings + freeblock simulator; every address in the recovery tool passed
through it first).

```text
Column  [super] + itemType @56 int (0x8351d4/0x8351f8)
              + configuration @64 int  <- Column.currentConfiguration (0x835234/0x835258)
              + paintColor @60 UNSIGNED (0x835294/0x8352b8)
              + ownerID direct (inherited DynamicObject.ownerID @36; set 0x835330)
Stairs  [super] + itemType @56 int; configuration <- currentConfiguration @60;
              paintColor @64 UNSIGNED; ownerID direct  (same template)
Door    [super] + itemType @64 int; blocked @68 int; ironPlaceClientID @72
              direct object; ownerID direct
Wire    [super] + itemType @56 int; configuration <- currentConfiguration @60;
              solidConfiguration <- currentSolidConfiguration @64; ownerID direct
```

Template-family facts:

- Key names and ivar names diverge: `configuration` serialises
  `currentConfiguration`, `solidConfiguration` serialises
  `currentSolidConfiguration`. The replacement schema must keep the key
  spelling, not the ivar spelling.
- `paintColor` is boxed with `numberWithUnsignedInt:` (Column, Stairs)
  while every other int uses `numberWithInt:` — signedness matters in the
  plist value domain.
- All four classes add `itemType` and the inherited `ownerID` directly;
  `ironPlaceClientID` (Door @72) is also stored as a raw object (NSNumber
  from elsewhere).
- Stairs/Column differ in paintColor offset (@64 vs @60) — same key name,
  different struct layout; never infer one class's offset table from
  another's.

Process: extraction-first pipeline (`gen_b2f_table.py`) produced this
batch's table; every gate passed on the first run, and the two extraction
bugs the dry-run surfaced (selector regex swallowing the trailing colon,
`currentX` candidate naming) were fixed in the generator, not hand-patched
in the table.

Static level-A only; **25 overrides remain** (exact set, word sizes):
Workbench 1232, Tree 818, TrainCar 557, InteractionObject 514, Action 510,
Plant 456, TradingPost 327, CaveTroll 322, DropBear 318, ArtificialLight
310, Boat 271, Torch 266, FireObject 244, Painting 242, ElevatorMotor 223,
ElevatorShaft 223, Sign 216, OwnershipSign 202, CactusTree 202, TulipPlant
193, SteamTrain 193, Egg 171, VinePlant 160, KelpPlant 160, Rail 159 —
plus the read-back sides and save/roundtrip behavior. Programmatic tally
(inventory + b2c/2d/2e/2f + tree/item JSONs) confirms 38/63 covered.
