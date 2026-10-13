# getSaveDict key pairings — batch 2h (TulipPlant, SteamTrain, OwnershipSign, CactusTree)

Original ELF SHA-256:
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
Recovery: `tools/recover_subclass_savedict_keys_b2h.py` →
`subclass_savedict_keys_b2h.json`. Listings:
`disasm_tulipplant_getsavedict.txt` (193w),
`disasm_steamtrain_getsavedict.txt` (193w),
`disasm_ownershipsign_getsavedict.txt` (202w),
`disasm_cactustree_getsavedict.txt` (202w).

```text
TulipPlant  [super] + availableFood@100 float (0x9a19c0/0x9a19e4)
                  + colorGenes@112 / mixGenes@114 / mateColorGenes@116 int
SteamTrain  [super] + fuelFraction@260 float (0xd18ff0/0xd19014)
                  + hasFuel@268 / goingRight@252 / stopped@325 bool
OwnershipSign [super] + landOwnerID@124 DIRECT OBJECT (set 0xa35a04, blx lr)
                    + landOwnerName@128 direct object (set 0xa35a3c)
                    + w<-widthRadius@132 int (0xa35ad8/0xa35afc)
                    + h<-heightRadius@136 int (0xa35b98/0xa35bbc)
CactusTree  [super] + splitHeightA@136 / splitHeightB@140 int
                  + splitDirection@144 bool + availableFood@148 float
```

Facts:

- **OwnershipSign.landOwnerID is stored as a raw object** (NSNumber
  allocated upstream, inserted without any boxing selector in this body —
  the first direct-object *numeric-role* key; compare NPC.tamedClientID).
  Keys `w`/`h` are one-character CFStrings mapping to widthRadius/
  heightRadius — shortest key names on the wire, must survive verbatim in
  any replacement encoder.
- **SteamTrain.stopped @325** confirms the deep TrainCar-family struct:
  bool fields live at 252/268/325 (three separate cache lines of ivars).
- TulipPlant's gene trio sits at 112/114/116 (16-bit-sized gaps) —
  half-word state fields boxed as ints.

Process note: the ownership-sign listing was initially emitted under a
mis-suffixed name; renamed to the `disasm_<class>_getsavedict.txt`
convention before committing, and the table addresses all came from the
mechanical extraction pass.

Static level-A only; 17 overrides remain (Sign 216w … Workbench 1232w),
read-back/roundtrip unresolved.
